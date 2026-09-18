<div align="center">

# Architecture

</div>

---

## Overview

RunSafety consists of two components:

1. **runsafety-agent** - Background daemon that monitors AI coding tools
2. **runsafety** - TUI dashboard client (optional)

```
┌─────────────────────────────────────────────────────────────┐
│                      runsafety-agent                         │
├─────────────────────────────────────────────────────────────┤
│  Discovery  →  Monitors  →  Rule Engine  →  Alert Sender   │
│      ↓              ↓             ↓              ↓          │
│  /proc/WMI    File/Net/Proc   Correlation   Notifications  │
│      ↓              ↓             ↓              ↓          │
│              Event Bus (tokio broadcast)                    │
│                       ↓                                     │
│              Audit Logger (SQLite/JSONL)                    │
│                       ↓                                     │
│              IPC Server (Unix socket / Named pipe)          │
└─────────────────────────────────────────────────────────────┘
                              ↕
┌─────────────────────────────────────────────────────────────┐
│                      runsafety (TUI)                        │
├─────────────────────────────────────────────────────────────┤
│  Sessions View  |  Resources View  |  Security View         │
└─────────────────────────────────────────────────────────────┘
```

---

## Crate Structure

```
crates/
├── shared/          # Shared types and protocol
│   ├── types.rs     # CliType, Session, Signal, Severity
│   ├── config.rs    # AgentConfig, GovernorConfig, SecurityConfig
│   └── protocol.rs  # JSON-RPC protocol for IPC
│
├── agent/           # Background daemon
│   ├── main.rs      # Entry point, task orchestration
│   ├── daemon.rs    # PID file, daemonize, signals
│   ├── config.rs    # Config loading, path resolution
│   ├── discovery/   # Process scanning
│   │   ├── mod.rs   # Scanner trait, pattern matching
│   │   ├── linux.rs # /proc scanning
│   │   ├── macos.rs # libproc scanning
│   │   └── windows.rs # WMI scanning
│   ├── security/    # Threat detection
│   │   ├── mod.rs   # Security monitor loop
│   │   ├── file_monitor.rs   # Sensitive file access
│   │   ├── net_monitor.rs    # Network connections
│   │   ├── process_monitor.rs # Child processes
│   │   ├── proc_connector.rs  # Process events
│   │   └── rules.rs          # Rule engine
│   ├── governor/    # Resource enforcement
│   │   ├── mod.rs   # Resource monitor loop
│   │   ├── cgroups.rs     # Linux cgroups v2
│   │   ├── ulimit.rs      # Unix ulimit fallback
│   │   ├── macos_enforcer.rs  # macOS limits
│   │   ├── macos_monitor.rs   # macOS RSS
│   │   └── windows_monitor.rs # Windows RSS
│   ├── audit.rs     # JSONL audit logger
│   ├── audit_sqlite.rs  # SQLite audit logger
│   ├── alert.rs     # Desktop notifications
│   └── ipc.rs       # IPC server
│
└── cli/             # TUI client
    ├── main.rs      # Entry point
    ├── cli.rs       # CLI commands
    ├── ipc.rs       # IPC client
    ├── proc_info.rs # Process info
    └── tui/
        ├── mod.rs   # TUI state management
        └── render.rs # Rendering
```

---

## Event Bus

All components communicate through a tokio broadcast channel.

```rust
// Signal types
pub enum Signal {
    // Session lifecycle
    SessionDiscovered(Session),
    SessionExited { id, pid, cli_type },
    
    // Memory events
    MemoryWarning { session_id, pid, rss_bytes, high_bytes },
    MemoryUrgent { session_id, pid, rss_bytes, high_bytes },
    LeakDetected { session_id, pid, rss_bytes, duration_secs },
    OomKill { session_id, pid, peak_rss_bytes },
    
    // Security events
    SensitiveFileAccess { session_id, pid, path, rule_name, severity },
    BoundaryViolation { session_id, pid, path, project_dir },
    UnexpectedNetwork { session_id, pid, remote_addr, remote_port },
    DangerousCommand { session_id, pid, rule_name, matched_text, severity },
    SuspiciousChild { session_id, pid, child_pid, child_cmdline },
    ExfilAttempt { session_id, pid, file_path, remote_addr },
}
```

---

## Process Discovery

### Linux (`/proc`)

```
/proc/*/cmdline → Parse arguments → Match patterns → Register session
```

1. Scan `/proc` for numeric directories (PIDs)
2. Read `/proc/<pid>/cmdline` for process arguments
3. Match against configured patterns
4. Check parent PID to avoid registering children

### macOS (`libproc`)

```
libproc::pidpath() → Get executable path → Match patterns
```

1. Use libproc to enumerate processes
2. Get executable path for each PID
3. Match against configured patterns

### Windows (`WMI`)

```
wmic process get → Parse CSV → Match patterns
```

1. Execute `wmic process get ProcessId,CommandLine,ExecutablePath`
2. Parse CSV output
3. Match against configured patterns

---

## Security Monitoring

### File Monitor

```
/proc/<pid>/fd/* → Read symlinks → Check against rules
```

- Reads `/proc/<pid>/fd/` to get open file descriptors
- Resolves symlinks to actual paths
- Matches against sensitive file rules
- Uses inotify for real-time directory watching

### Network Monitor

```
/proc/<pid>/net/tcp → Parse connections → Match against allowlist
```

- Reads `/proc/<pid>/net/tcp` for TCP connections
- Matches socket inodes to file descriptors
- Compares remote addresses against allowlist

### Process Monitor

```
/proc/<pid>/task/<tid>/children → Recursive scan → Command patterns
```

- Scans child processes recursively
- Checks command patterns for dangerous commands
- Detects reverse shells, privilege escalation, etc.

### Correlation Engine

```
File Access + Network Connection (within 10s) = Exfiltration Alert
```

- Tracks file access events
- Tracks network connection events
- If sensitive file read followed by network connection → alert

---

## Resource Governor

### Cgroups v2 (Linux)

```
/sys/fs/cgroup/user.slice/user-<uid>.slice/
└── runsafety/
    ├── <session-id>/
    │   ├── memory.high  (soft limit)
    │   └── memory.max   (hard limit)
    └── ...
```

1. Create `runsafety` cgroup subtree
2. Create per-session cgroup
3. Set `memory.high` for soft limit (throttle)
4. Set `memory.max` for hard limit (kill)
5. Monitor `memory.events` for OOM kills

### Ulimit Fallback

```rust
// If cgroups unavailable, use setrlimit
setrlimit(RLIMIT_AS, memory_high, memory_max)
```

### Memory Monitoring

```
/proc/<pid>/stat → field 24 (rss) → RSS in pages
```

- Read RSS from `/proc/<pid>/stat`
- Convert pages to bytes (pages × page_size)
- Track history for leak detection

---

## IPC Protocol

### Unix Socket (Linux/macOS)

```
~/.local/share/runsafety/agent.sock
```

### Named Pipe (Windows)

```
\\.\pipe\runsafety-agent
```

### JSON-RPC Methods

| Method | Request | Response |
|--------|---------|----------|
| `ListSessions` | `{}` | `[{id, pid, cli_type, status, memory, ...}]` |
| `GetEvents` | `{session_id?, severity?, limit}` | `[{timestamp, signal}]` |
| `Subscribe` | `{session_id?, min_severity?}` | Stream of events |
| `InjectSession` | `{session, rss_bytes?}` | `{injected: true}` |
| `InjectEvent` | `{signal, rss_update?}` | `{injected: true}` |

---

## Audit Storage

### JSONL Format

```json
{"timestamp":1234567890,"event":{"SessionDiscovered":{"id":1,"pid":12345,...}}}
{"timestamp":1234567891,"event":{"MemoryWarning":{"session_id":1,"pid":12345,...}}}
```

- One file per day: `~/.local/share/runsafety/audit/2024-01-15.jsonl`
- Easy to parse with `jq` or scripts
- No external dependencies

### SQLite Format

```sql
CREATE TABLE audit_entries (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    event_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

- Single file: `~/.local/share/runsafety/audit/audit.db`
- Indexed for fast queries
- Query API for filtering by time, session, severity
