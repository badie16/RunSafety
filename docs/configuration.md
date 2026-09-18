<div align="center">

# Configuration Guide

</div>

---

## Config Files

| File | Location | Purpose |
|------|----------|---------|
| `agent.toml` | `~/.config/runsafety/agent.toml` | Main configuration |
| `security-rules.toml` | `~/.config/runsafety/security-rules.toml` | Detection rules |

---

## agent.toml

### Discovery Section

Controls how RunSafety scans for AI coding tools.

```toml
[discovery]
# How often to scan for new processes (seconds)
scan_interval_secs = 5
```

### CLI Patterns

Define which processes to monitor.

```toml
[[discovery.cli]]
name = "claude"
type = "ClaudeCode"
patterns = ["claude", "claude-code", "@anthropic/claude-code"]

[[discovery.cli]]
name = "codex"
type = "Codex"
patterns = ["codex", "openai-codex"]

[[discovery.cli]]
name = "gemini"
type = "GeminiCli"
patterns = ["gemini", "gemini-cli"]

[[discovery.cli]]
name = "cursor"
type = "Cursor"
patterns = ["cursor-agent", "cursor"]

[[discovery.cli]]
name = "aider"
type = "Aider"
patterns = ["aider"]

[[discovery.cli]]
name = "opencode"
type = "OpenCode"
patterns = ["opencode", "open-code"]
```

### Adding Custom CLI Tools

```toml
[[discovery.cli]]
name = "my-tool"
type = "MyTool"
patterns = ["my-tool", "mytool", "my-tool-cli"]
```

### Governor Section

Controls memory limits and enforcement.

```toml
[governor]
# Enable memory enforcement
enabled = true

# Enforcement mode:
#   "warn"     - notifications only, no limits
#   "throttle" - kernel throttles at soft limit (default)
#   "kill"     - hard OOM kill at max limit
action = "throttle"

# Memory threshold percentages
warn_threshold = 0.85      # 85% = warning
urgent_threshold = 0.95    # 95% = urgent

# Monitoring interval
monitor_interval_secs = 2

# Leak detection
leak_window_secs = 60      # Window to detect leaks
leak_min_growth = "100MB"  # Minimum growth to flag

# Auto-restart on OOM kill
auto_restart = false
```

### Governor Defaults

Default memory limits for all CLI tools.

```toml
[governor.defaults]
memory_high = "2GB"    # Soft limit (throttle)
memory_max = "3GB"     # Hard limit (kill)
```

### Per-CLI Governor Limits

Override defaults for specific tools.

```toml
[governor.cli.ClaudeCode]
memory_high = "3GB"
memory_max = "4GB"
leak_min_growth = "500MB"

[governor.cli.Codex]
memory_high = "1.5GB"
memory_max = "2GB"

[governor.cli.GeminiCli]
memory_high = "2GB"
memory_max = "3GB"

[governor.cli.Cursor]
memory_high = "3GB"
memory_max = "4GB"

[governor.cli.OpenCode]
memory_high = "2GB"
memory_max = "3GB"
```

### Security Section

Controls security monitoring.

```toml
[security]
# Enable security monitoring
enabled = true

# How often to scan (seconds)
scan_interval_secs = 3

# Fast scan interval (milliseconds) for high-priority checks
fast_scan_interval_ms = 500

# Exfiltration detection window (seconds)
# If a sensitive file is read AND network activity happens within this window,
# it triggers an exfiltration alert
exfil_window_secs = 10

# Deduplication window (seconds)
# Don't alert for the same event within this window
dedup_window_secs = 300

# Minimum severity for desktop notifications
# Options: "Info", "Warning", "Critical"
notify_min_severity = "Critical"
```

### Audit Section

Controls audit logging.

```toml
[audit]
# Enable audit logging
enabled = true

# Storage backend:
#   "jsonl"  - JSON Lines files (one per day)
#   "sqlite" - SQLite database (default)
storage = "sqlite"

# How long to keep audit logs (days)
retention_days = 90
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUNSAFETY_CONFIG` | `~/.config/runsafety` | Config directory |
| `RUNSAFETY_DATA` | `~/.local/share/runsafety` | Data directory |
| `RUNSAFETY_LOG` | `info` | Log level (trace, debug, info, warn, error) |

---

## Config Locations by Platform

| Platform | Config Path | Data Path |
|----------|-------------|-----------|
| Linux | `~/.config/runsafety/` | `~/.local/share/runsafety/` |
| macOS | `~/Library/Application Support/runsafety/` | `~/Library/Application Support/runsafety/` |
| Windows | `%APPDATA%\runsafety\` | `%LOCALAPPDATA%\runsafety\` |

---

## Example Configurations

### Minimal Setup

```toml
[discovery]
scan_interval_secs = 10

[governor]
enabled = false

[security]
enabled = true
```

### Maximum Security

```toml
[discovery]
scan_interval_secs = 2

[governor]
enabled = true
action = "kill"
warn_threshold = 0.75
urgent_threshold = 0.90

[governor.defaults]
memory_high = "1GB"
memory_max = "2GB"

[security]
enabled = true
scan_interval_secs = 1
exfil_window_secs = 5
notify_min_severity = "Info"

[audit]
enabled = true
storage = "sqlite"
retention_days = 365
```

### Development Mode

```toml
[discovery]
scan_interval_secs = 5

[governor]
enabled = true
action = "warn"  # Only notify, don't throttle

[security]
enabled = true
notify_min_severity = "Warning"

[audit]
enabled = true
storage = "jsonl"
retention_days = 30
```
