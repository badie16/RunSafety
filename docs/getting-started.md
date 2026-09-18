<div align="center">

# Getting Started

</div>

---

## Installation

### Linux / macOS

```bash
curl -sSf https://raw.githubusercontent.com/badie16/runsafety/main/dist/install.sh | sh
```

### Windows (WSL)

```bash
# In WSL Ubuntu
sudo apt update && sudo apt install build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

git clone https://github.com/badie16/runsafety.git
cd runsafety
cargo build --release
cp target/release/runsafety-agent target/release/runsafety ~/.local/bin/
```

### Build from Source

```bash
# Prerequisites
# - Rust 1.70+ (https://rustup.rs)
# - Linux: no extra deps
# - macOS: Xcode Command Line Tools

git clone https://github.com/badie16/runsafety.git
cd runsafety
cargo build --release

# Install binaries
mkdir -p ~/.local/bin
cp target/release/runsafety-agent ~/.local/bin/
cp target/release/runsafety ~/.local/bin/

# Install config
mkdir -p ~/.config/runsafety
cp config/agent.toml ~/.config/runsafety/
cp config/security-rules.toml ~/.config/runsafety/

# Create data directory
mkdir -p ~/.local/share/runsafety/audit
```

---

## Quick Start

### 1. Start the Daemon

```bash
# Start in foreground (for testing)
runsafety-agent

# Start as background service
runsafety-agent --daemon
```

### 2. Open the Dashboard

```bash
runsafety
```

### 3. Try the Demo

```bash
runsafety demo
```

---

## First Run

When you start RunSafety for the first time:

1. **Daemon starts** and begins scanning for AI coding tools
2. **Dashboard opens** showing the Sessions view
3. **Launch your AI tool** (Claude Code, Codex, etc.)
4. **RunSafety detects** the process and starts monitoring

---

## What You'll See

### Sessions View
Shows all monitored AI coding tool sessions with PID, CLI type, status, and memory usage.

### Security View
Displays security alerts with severity levels (Critical, Warning, Info) and event details.

### Resources View
Memory usage graphs for each session with historical data.

---

## Configuration

Edit `~/.config/runsafety/agent.toml` to customize:

```toml
[discovery]
scan_interval_secs = 5  # How often to scan for processes

[governor]
enabled = true
action = "throttle"     # warn | throttle | kill

[security]
enabled = true
scan_interval_secs = 3  # How often to check security

[audit]
enabled = true
storage = "sqlite"      # jsonl | sqlite
```

See [Configuration Guide](configuration.md) for all options.

---

## Troubleshooting

### Daemon not starting

```bash
# Check if already running
ps aux | grep runsafety-agent

# Check logs
journalctl --user -u runsafety-agent

# Run in foreground for debugging
runsafety-agent
```

### Dashboard can't connect

```bash
# Check if daemon is running
runsafety status

# Check socket exists
ls -la ~/.local/share/runsafety/agent.sock

# Restart daemon
systemctl --user restart runsafety-agent
```

### Permission denied

```bash
# Fix permissions
chmod 755 ~/.local/bin/runsafety-agent
chmod 755 ~/.local/bin/runsafety
chmod -R 755 ~/.config/runsafety/
chmod -R 755 ~/.local/share/runsafety/
```

---

## Next Steps

- [Configuration Guide](configuration.md) - All config options
- [Architecture](architecture.md) - How RunSafety works
- [Security Rules](security-rules.md) - Custom detection rules
- [CLI Reference](cli-reference.md) - All commands
