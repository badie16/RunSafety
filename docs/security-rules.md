<div align="center">

# Security Rules

</div>

---

## Overview

Security rules define what RunSafety monitors and alerts on. Rules are defined in `~/.config/runsafety/security-rules.toml`.

---

## Rule Types

### 1. File Access Rules

Monitor access to sensitive files and directories.

```toml
[[file_access]]
name = "SSH private keys"
paths = ["~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa"]
severity = "Warning"
```

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable rule name |
| `paths` | Yes | List of paths to monitor (supports globs) |
| `severity` | No | `Info`, `Warning`, or `Critical` (default: `Warning`) |
| `known_safe` | No | Explanation shown when this is expected behavior |
| `known_safe_for` | No | List of CLI types where this is expected |

**Example with known_safe:**

```toml
[[file_access]]
name = "SSH config"
paths = ["~/.ssh/config", "~/.ssh/known_hosts"]
severity = "Info"
known_safe = "Normal: SSH client reads config during connections."
```

**Example with known_safe_for:**

```toml
[[file_access]]
name = "AWS credentials"
paths = ["~/.aws/credentials", "~/.aws/config"]
severity = "Critical"
known_safe_for = ["ClaudeCode", "Codex", "Cursor"]
```

---

### 2. Network Allowlist

Define trusted hosts for network connections.

```toml
[[network_allow]]
name = "AI APIs"
hosts = [
    "api.anthropic.com",
    "claude.ai",
    "api.openai.com",
    "generativelanguage.googleapis.com",
]
```

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable group name |
| `hosts` | Yes | List of allowed hostnames |

**Example groups:**

```toml
[[network_allow]]
name = "Package registries"
hosts = [
    "registry.npmjs.org",
    "pypi.org",
    "crates.io",
]

[[network_allow]]
name = "Code hosting"
hosts = [
    "github.com",
    "api.github.com",
    "gitlab.com",
]

[[network_allow]]
name = "CDN"
hosts = [
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
]
```

---

### 3. Command Patterns

Detect dangerous commands using regex patterns.

```toml
[[command_pattern]]
name = "Curl pipe shell"
pattern = "(curl|wget).*\\|.*(sh|bash|zsh)"
severity = "Critical"
```

**Fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable rule name |
| `pattern` | Yes | Regex pattern to match |
| `severity` | No | `Info`, `Warning`, or `Critical` (default: `Warning`) |

**Common Patterns:**

```toml
# Reverse shells
[[command_pattern]]
name = "Reverse shell"
pattern = "(nc\\s+-[a-zA-Z]*e|bash\\s+-i|/dev/tcp/|mkfifo.*nc)"
severity = "Critical"

# Privilege escalation
[[command_pattern]]
name = "Privilege escalation"
pattern = "(sudo|su\\s+-|pkexec|doas)"
severity = "Critical"

# Dangerous delete
[[command_pattern]]
name = "Dangerous delete"
pattern = "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*\\s+)?/"
severity = "Critical"

# World writable permissions
[[command_pattern]]
name = "World writable"
pattern = "chmod\\s+(777|a\\+w)"
severity = "Warning"

# Crontab modification
[[command_pattern]]
name = "Crontab modification"
pattern = "crontab"
severity = "Critical"

# Cloud metadata access
[[command_pattern]]
name = "Cloud metadata access"
pattern = "(curl|wget).*(169\\.254\\.169\\.254|metadata\\.google\\.internal)"
severity = "Critical"

# Script execution from /tmp
[[command_pattern]]
name = "Script from /tmp"
pattern = "(bash|sh|python|node|perl|ruby)\\s+/tmp/"
severity = "Critical"
```

---

## Severity Levels

| Level | Desktop Notification | TUI Display | Description |
|-------|---------------------|-------------|-------------|
| `Info` | No (by default) | Blue | Informational, expected behavior |
| `Warning` | Yes | Yellow | Suspicious, worth investigating |
| `Critical` | Yes | Red | Dangerous, immediate attention |

---

## Path Patterns

### Home Directory

Use `~` for the user's home directory:

```toml
paths = ["~/.ssh/id_rsa", "~/.aws/credentials"]
```

### Glob Patterns

Use `*` for wildcards:

```toml
paths = ["*.tfstate", "*.pem", "*.key"]
```

### System Paths

Absolute paths work too:

```toml
paths = ["/etc/shadow", "/etc/passwd"]
```

---

## Writing Custom Rules

### Example 1: Monitor Terraform State

```toml
[[file_access]]
name = "Terraform state"
paths = ["*.tfstate", "*.tfstate.backup", ".terraform/"]
severity = "Critical"
```

### Example 2: Monitor Docker Config

```toml
[[file_access]]
name = "Docker config"
paths = ["~/.docker/config.json", "docker-compose.yml"]
severity = "Warning"
```

### Example 3: Custom Network Allowlist

```toml
[[network_allow]]
name = "My API"
hosts = ["api.mycompany.com", "internal.mycompany.com"]
```

### Example 4: Custom Command Pattern

```toml
[[command_pattern]]
name = "Suspicious download"
pattern = "wget.*-O\\s+/tmp/"
severity = "Warning"
```

---

## Rule Processing Order

1. **File Access Rules** - Checked when a file is opened
2. **Network Allowlist** - Checked when a connection is made
3. **Command Patterns** - Checked when a child process is spawned
4. **Correlation** - File + Network within 10s = Exfiltration alert

---

## Default Rules

See [`config/security-rules.toml`](../config/security-rules.toml) for the complete default ruleset including:

- SSH keys and config
- AWS credentials
- GPG keys
- Kubernetes config
- Environment files
- Docker config
- System passwords
- Git credentials
- Package manager tokens
- And more...
