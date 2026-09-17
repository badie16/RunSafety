use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Warning => write!(f, "Warning"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

impl Severity {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "warning" => Self::Warning,
            _ => Self::Info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CliType {
    ClaudeCode,
    Codex,
    GeminiCli,
    Cursor,
    Aider,
    OpenCode,
    Custom(String),
}

impl CliType {
    pub fn from_config_str(s: &str) -> Self {
        match s {
            "ClaudeCode" => Self::ClaudeCode,
            "Codex" => Self::Codex,
            "GeminiCli" => Self::GeminiCli,
            "Cursor" => Self::Cursor,
            "Aider" => Self::Aider,
            "OpenCode" => Self::OpenCode,
            other => Self::Custom(other.to_string()),
        }
    }

    pub fn config_key(&self) -> &str {
        match self {
            Self::ClaudeCode => "ClaudeCode",
            Self::Codex => "Codex",
            Self::GeminiCli => "GeminiCli",
            Self::Cursor => "Cursor",
            Self::Aider => "Aider",
            Self::OpenCode => "OpenCode",
            Self::Custom(s) => s,
        }
    }
}

impl fmt::Display for CliType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaudeCode => write!(f, "Claude Code"),
            Self::Codex => write!(f, "Codex"),
            Self::GeminiCli => write!(f, "Gemini CLI"),
            Self::Cursor => write!(f, "Cursor"),
            Self::Aider => write!(f, "Aider"),
            Self::OpenCode => write!(f, "OpenCode"),
            Self::Custom(name) => write!(f, "{name}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Running,
    Idle,
    HighMemory,
    Leaking,
    Restarting,
    Exited { code: Option<i32> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: u64,
    pub pid: u32,
    pub cli_type: CliType,
    pub status: SessionStatus,
    pub working_dir: PathBuf,
    pub started_at: u64,
    #[serde(default)]
    pub memory_high: Option<u64>,
    #[serde(default)]
    pub memory_max: Option<u64>,
    #[serde(default)]
    pub cmdline: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signal {
    SessionDiscovered(Session),
    SessionExited {
        id: u64,
        pid: u32,
        cli_type: CliType,
    },
    MemoryWarning {
        session_id: u64,
        pid: u32,
        cli_type: CliType,
        rss_bytes: u64,
        high_bytes: u64,
    },
    MemoryUrgent {
        session_id: u64,
        pid: u32,
        cli_type: CliType,
        rss_bytes: u64,
        high_bytes: u64,
    },
    LeakDetected {
        session_id: u64,
        pid: u32,
        cli_type: CliType,
        rss_bytes: u64,
        duration_secs: u64,
    },
    OomKill {
        session_id: u64,
        pid: u32,
        cli_type: CliType,
        peak_rss_bytes: u64,
    },
    // Security signals (Sprint 3)
    SensitiveFileAccess {
        session_id: u64,
        pid: u32,
        cli_type: CliType,
        path: PathBuf,
        rule_name: String,
        severity: Severity,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        known_safe: Option<String>,
    },
    BoundaryViolation {
        session_id: u64,
        pid: u32,
        cli_type: CliType,
        path: PathBuf,
        project_dir: PathBuf,
    },
    UnexpectedNetwork {
        session_id: u64,
        pid: u32,
        cli_type: CliType,
        remote_addr: String,
        remote_port: u16,
    },
    DangerousCommand {
        session_id: u64,
        pid: u32,
        cli_type: CliType,
        rule_name: String,
        matched_text: String,
        severity: Severity,
    },
    SuspiciousChild {
        session_id: u64,
        pid: u32,
        cli_type: CliType,
        child_pid: u32,
        child_cmdline: String,
    },
    ExfilAttempt {
        session_id: u64,
        pid: u32,
        cli_type: CliType,
        file_path: PathBuf,
        remote_addr: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub event: Signal,
}
