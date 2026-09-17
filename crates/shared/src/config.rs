use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliPattern {
    pub name: String,
    #[serde(rename = "type")]
    pub cli_type: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub memory_limit: Option<String>, // Legacy field, ignored by governor
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    #[serde(default = "default_scan_interval")]
    pub scan_interval_secs: u64,
    #[serde(default)]
    pub cli: Vec<CliPattern>,
}

fn default_scan_interval() -> u64 {
    5
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GovernorAction {
    Warn,
    Throttle,
    Kill,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryLimits {
    pub memory_high: Option<String>,
    pub memory_max: Option<String>,
    pub leak_min_growth: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_action")]
    pub action: GovernorAction,
    #[serde(default = "default_warn_threshold")]
    pub warn_threshold: f32,
    #[serde(default = "default_urgent_threshold")]
    pub urgent_threshold: f32,
    #[serde(default = "default_monitor_interval")]
    pub monitor_interval_secs: u64,
    #[serde(default = "default_leak_window")]
    pub leak_window_secs: u64,
    #[serde(default = "default_leak_min_growth")]
    pub leak_min_growth: String,
    #[serde(default)]
    pub auto_restart: bool,
    #[serde(default)]
    pub defaults: MemoryLimits,
    #[serde(default)]
    pub cli: HashMap<String, MemoryLimits>,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: default_action(),
            warn_threshold: default_warn_threshold(),
            urgent_threshold: default_urgent_threshold(),
            monitor_interval_secs: default_monitor_interval(),
            leak_window_secs: default_leak_window(),
            leak_min_growth: default_leak_min_growth(),
            auto_restart: false,
            defaults: MemoryLimits::default(),
            cli: HashMap::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_action() -> GovernorAction {
    GovernorAction::Throttle
}

fn default_warn_threshold() -> f32 {
    0.85
}

fn default_urgent_threshold() -> f32 {
    0.95
}

fn default_monitor_interval() -> u64 {
    2
}

fn default_leak_window() -> u64 {
    60
}

fn default_leak_min_growth() -> String {
    "100MB".to_string()
}

// --- Security config (in agent.toml [security] section) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_security_scan_interval")]
    pub scan_interval_secs: u64,
    #[serde(default = "default_fast_scan_interval_ms")]
    pub fast_scan_interval_ms: u64,
    #[serde(default = "default_exfil_window")]
    pub exfil_window_secs: u64,
    #[serde(default = "default_dedup_window")]
    pub dedup_window_secs: u64,
    /// Minimum severity for desktop notifications. Events below this still
    /// appear in the TUI and audit log, just no desktop popup.
    /// Values: "Info", "Warning", "Critical". Default: "Warning".
    #[serde(default = "default_notify_min_severity")]
    pub notify_min_severity: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_secs: default_security_scan_interval(),
            fast_scan_interval_ms: default_fast_scan_interval_ms(),
            exfil_window_secs: default_exfil_window(),
            dedup_window_secs: default_dedup_window(),
            notify_min_severity: default_notify_min_severity(),
        }
    }
}

fn default_security_scan_interval() -> u64 {
    3
}

fn default_fast_scan_interval_ms() -> u64 {
    500
}

fn default_exfil_window() -> u64 {
    10
}

fn default_dedup_window() -> u64 {
    300
}

fn default_notify_min_severity() -> String {
    "Warning".to_string()
}

// --- Security rules (from security-rules.toml) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessRule {
    pub name: String,
    pub paths: Vec<String>,
    #[serde(default = "default_severity_warning")]
    pub severity: String,
    /// Short explanation shown in TUI when this is expected behavior.
    #[serde(default)]
    pub known_safe: Option<String>,
    /// When a tracked session whose CLI type is in this list reads a
    /// matching path, the event severity is downgraded to Info. Unknown
    /// readers, children of tracked sessions, and unattributed inotify
    /// fallbacks keep the original severity.
    #[serde(default)]
    pub known_safe_for: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAllowEntry {
    pub name: String,
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPatternRule {
    pub name: String,
    pub pattern: String,
    #[serde(default = "default_severity_warning")]
    pub severity: String,
}

fn default_severity_warning() -> String {
    "Warning".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityRulesConfig {
    #[serde(default)]
    pub file_access: Vec<FileAccessRule>,
    #[serde(default)]
    pub network_allow: Vec<NetworkAllowEntry>,
    #[serde(default)]
    pub command_pattern: Vec<CommandPatternRule>,
}

// --- Audit config ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditStorage {
    Jsonl,
    Sqlite,
}

impl Default for AuditStorage {
    fn default() -> Self {
        Self::Sqlite
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub storage: AuditStorage,
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            storage: AuditStorage::default(),
            retention_days: default_audit_retention_days(),
        }
    }
}

fn default_audit_retention_days() -> u64 {
    90
}

// --- Top-level agent config ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub discovery: DiscoveryConfig,
    #[serde(default)]
    pub governor: GovernorConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub audit: AuditConfig,
}
