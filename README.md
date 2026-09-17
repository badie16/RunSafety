# RunSafety

Runtime security monitor for AI coding agents.

## The Problem

AI coding tools run commands on your machine with broad permissions. They read files, make network connections, spawn child processes. npm postinstall scripts, piped curl commands, credential file reads: it all happens in the background with no visibility.

## What RunSafety Does

- **Watches file access.** Detects reads of SSH keys, AWS credentials, .env files, GPG keys, and 30+ other sensitive paths.
- **Monitors network connections.** Flags connections to hosts not on the allowlist.
- **Detects dangerous commands.** Reverse shells, `curl | sh`, `chmod 777`, crontab edits, cloud metadata access.
- **Correlates signals.** Sensitive file read followed by a network connection within 10 seconds triggers a data exfiltration alert.
- **Enforces memory limits.** Cgroups v2 prevents AI tools from freezing your machine. Tiered warnings before throttle or kill.
- **Sends desktop notifications.** You see alerts without checking a dashboard.

No wrappers. No proxies. You keep using Claude Code, Codex, Cursor, Gemini CLI, Aider, or any other tool normally. RunSafety watches from the background.

## How It Works

The `runsafety-agent` daemon runs as a user service (systemd on Linux, launchd on macOS). It scans `/proc` every 5 seconds to discover AI coding tool processes by matching command-line patterns. Once a session is found, five monitors activate:

- **FileMonitor:** scans `/proc/pid/fd` and watches sensitive directories with inotify
- **NetworkMonitor:** parses `/proc/pid/net/tcp` and matches socket inodes
- **ProcessMonitor:** tracks child process trees recursively
- **ResourceMonitor:** reads RSS from `/proc/pid/stat`, detects memory leaks
- **OutputMonitor:** watches command output for suspicious patterns

All signals flow through a tokio broadcast channel to consumers: the rule engine, audit logger, alert sender, cgroup governor, and IPC server.

```
runsafety-agent (daemon, always running)
|
|-- Discovery         /proc/*/cmdline scanning, pattern matching
|-- File Monitor      /proc/pid/fd + inotify on sensitive dirs
|-- Network Monitor   /proc/pid/net/tcp, socket inode matching
|-- Process Monitor   recursive child scanning, command patterns
|-- Resource Governor  cgroups v2 memory limits, leak detection
|-- Correlation        file access + network = exfil alert
|-- Audit Logger       JSON Lines to ~/.local/share/runsafety/audit/
|-- IPC Server         Unix socket, JSON-RPC (ListSessions, GetEvents, Subscribe)
|
|-- Config: ~/.config/runsafety/agent.toml
|-- Rules:  ~/.config/runsafety/security-rules.toml
|-- Socket: ~/.local/share/runsafety/agent.sock
```

The optional `runsafety` TUI client connects to the daemon over a Unix socket for a live dashboard with session, resource, and security views.

## Supported AI Tools

| Tool        | Detection Patterns                                |
| ----------- | ------------------------------------------------- |
| Claude Code | `claude`, `claude-code`, `@anthropic/claude-code` |
| Codex       | `codex`, `openai-codex`                           |
| Gemini CLI  | `gemini`, `gemini-cli`                            |
| Cursor      | `cursor-agent`, `cursor`                          |
| Aider       | `aider`                                           |
| OpenCode    | `opencode`, `open-code`                           |
| Custom      | Configurable patterns in `agent.toml`             |

## Detection Rules

| Threat                       | How                                     | OWASP ASI |
| ---------------------------- | --------------------------------------- | --------- |
| SSH/AWS/GPG key access       | FD scanning + inotify                   | ASI-02    |
| Writes outside project dir   | Boundary detection                      | ASI-01    |
| Unknown network connections  | TCP parsing + allowlist                 | ASI-05    |
| Data exfiltration            | File + network correlation (10s window) | ASI-08    |
| `curl \| sh`, reverse shells | Command pattern matching                | ASI-10    |
| Suspicious child processes   | Recursive /proc/children scan           | ASI-10    |
| Memory leaks                 | Monotonic RSS growth detection          | -         |
| OOM kills                    | cgroup memory.events monitoring         | -         |

## Resource Governor

Three modes for memory enforcement via cgroups v2:

| Mode       | memory.high | memory.max | Effect                                   |
| ---------- | ----------- | ---------- | ---------------------------------------- |
| `warn`     | -           | -          | Desktop notifications only               |
| `throttle` | set         | -          | Kernel throttles at soft limit (default) |
| `kill`     | set         | set        | Hard OOM kill at max limit               |

Per-CLI defaults: Claude Code 3GB/4GB, Codex 1.5GB/2GB, Gemini CLI 2GB/3GB, Cursor 3GB/4GB.

Tiered alerts: 85% warning, 95% urgent ("save your work"), 100% throttled, OOM killed.

## Configuration

### agent.toml

```toml
[discovery]
scan_interval_secs = 5

[governor]
enabled = true
action = "throttle"       # warn | throttle | kill
warn_threshold = 0.85
urgent_threshold = 0.95

[governor.defaults]
memory_high = "2GB"
memory_max = "3GB"

[governor.cli.ClaudeCode]
memory_high = "3GB"
memory_max = "4GB"

[security]
enabled = true
scan_interval_secs = 3
exfil_window_secs = 10
```

### security-rules.toml

Defines sensitive file paths, network allowlists, and dangerous command patterns. See [`config/security-rules.toml`](config/security-rules.toml) for the full default ruleset.

## Install

Download and install (Linux and macOS):

```bash
curl -sSf https://raw.githubusercontent.com/badie16/runsafety/main/dist/install.sh | sh
```

This installs both the daemon and the TUI, starts the background service, and adds default config files.

After install, open the dashboard:

```bash
runsafety
```

Try the demo to see alerts in action:

```bash
runsafety demo
```

### Build from source

```bash
git clone https://github.com/badie16/runsafety.git
cd runsafety
cargo build --release
cp target/release/runsafety-agent target/release/runsafety ~/.local/bin/
mkdir -p ~/.config/runsafety
cp config/agent.toml config/security-rules.toml ~/.config/runsafety/
```

## Platform Support

| Platform              | Status                                     |
| --------------------- | ------------------------------------------ |
| Linux (x86_64)        | Full support, primary development platform |
| Linux (aarch64)       | Full support                               |
| macOS (Intel)         | Works, CI tested                           |
| macOS (Apple Silicon) | Works, CI tested                           |
| Windows               | In development                             |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
