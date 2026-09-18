<div align="center">

# CLI Reference

</div>

---

## runsafety-agent

Background daemon that monitors AI coding tools.

### Usage

```bash
runsafety-agent [OPTIONS]
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--daemon` | `-d` | Run as background daemon |
| `--config <PATH>` | `-c` | Config file path |
| `--help` | `-h` | Print help |
| `--version` | `-V` | Print version |

### Examples

```bash
# Run in foreground (for debugging)
runsafety-agent

# Run as daemon
runsafety-agent --daemon

# Use custom config
runsafety-agent --config /path/to/agent.toml
```

### Service Management

```bash
# Start service (systemd)
systemctl --user start runsafety-agent

# Stop service
systemctl --user stop runsafety-agent

# Restart service
systemctl --user restart runsafety-agent

# Check status
systemctl --user status runsafety-agent

# View logs
journalctl --user -u runsafety-agent
```

---

## runsafety

TUI dashboard client for monitoring AI coding tools.

### Usage

```bash
runsafety [COMMAND] [OPTIONS]
```

### Commands

| Command | Description |
|---------|-------------|
| (default) | Open the TUI dashboard |
| `status` | Check if daemon is running |
| `list` | List active sessions |
| `events` | Show security events |
| `kill <ID>` | Kill a session by ID |
| `config` | Configuration management |
| `plugin` | Plugin management |
| `analytics` | Analytics and statistics |
| `test-alert` | Send test notification |
| `demo` | Run demo to see alerts in action |
| `help` | Print help |

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--config <PATH>` | `-c` | Config file path |
| `--help` | `-h` | Print help |
| `--version` | `-V` | Print version |

### Examples

```bash
# Open dashboard
runsafety

# Check daemon status
runsafety status

# List active sessions
runsafety list

# Show security events
runsafety events --severity Warning --limit 20

# Kill a session
runsafety kill 1

# Export configuration
runsafety config export --output backup.json

# Import configuration
runsafety config import --input backup.json

# Validate configuration
runsafety config validate

# List plugins
runsafety plugin list

# Show analytics summary
runsafety analytics summary

# Show memory statistics
runsafety analytics memory --session 1

# Export analytics
runsafety analytics export --output analytics.json

# Run demo
runsafety demo
```

---

## TUI Navigation

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Tab` | Switch between views |
| `Shift+Tab` | Switch to previous view |
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `Enter` | Select item |
| `Esc` | Deselect / Go back |
| `q` | Quit |
| `?` | Show help |

### Views

#### Sessions View
- Shows all monitored AI coding tool sessions
- Display PID, CLI type, status, memory usage
- Select a session to see details

#### Resources View
- Memory usage graphs for each session
- CPU usage (if available)
- Historical data

#### Security View
- Security alerts and events
- Filter by severity (Info, Warning, Critical)
- Filter by session

#### Tasks View
- Command history
- Child process tree
- Network connections

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUNSAFETY_CONFIG` | `~/.config/runsafety` | Config directory |
| `RUNSAFETY_DATA` | `~/.local/share/runsafety` | Data directory |
| `RUNSAFETY_LOG` | `info` | Log level |

### Log Levels

```bash
# Set log level
RUNSAFETY_LOG=debug runsafety-agent

# Trace (very verbose)
RUNSAFETY_LOG=trace runsafety-agent

# Quiet (errors only)
RUNSAFETY_LOG=error runsafety-agent
```

---

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `1` | General error |
| `2` | Invalid arguments |
| `3` | Config file not found |
| `4` | Daemon already running |
| `5` | Permission denied |

---

## Examples

### Monitor a Specific Session

```bash
# Start daemon
runsafety-agent --daemon

# Open dashboard
runsafety

# Use keyboard to select a session
# Press Enter to see details
```

### Debug Mode

```bash
# Run daemon in foreground with debug logging
RUNSAFETY_LOG=debug runsafety-agent

# In another terminal, open dashboard
runsafety
```

### Custom Config

```bash
# Use custom config
runsafety-agent --config /etc/runsafety/agent.toml

# Open dashboard with same config
runsafety --config /etc/runsafety/agent.toml
```

---

## IPC Protocol

For advanced usage, you can communicate with the daemon directly via IPC.

### Unix Socket (Linux/macOS)

```bash
# Send JSON-RPC request
echo '{"jsonrpc":"2.0","method":"ListSessions","params":{},"id":1}' | \
  socat - UNIX-CONNECT:$HOME/.local/share/runsafety/agent.sock
```

### Named Pipe (Windows)

```powershell
# PowerShell
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "runsafety-agent")
$pipe.Connect()
$writer = New-Object System.IO.StreamWriter($pipe)
$writer.WriteLine('{"jsonrpc":"2.0","method":"ListSessions","params":{},"id":1}')
$writer.Flush()
```

### Available Methods

| Method | Description |
|--------|-------------|
| `ListSessions` | Get all active sessions |
| `GetEvents` | Get buffered events |
| `Subscribe` | Stream events in real-time |
| `InjectSession` | Inject a test session |
| `InjectEvent` | Inject a test event |
