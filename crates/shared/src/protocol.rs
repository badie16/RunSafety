use serde::{Deserialize, Serialize};

use crate::types::{Session, Severity, Signal};

// --- JSON-RPC envelope ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Option<serde_json::Value>, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(JsonRpcError { code, message }),
            id,
        }
    }
}

// --- JSON-RPC notification (server -> client, no id) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
}

impl JsonRpcNotification {
    pub fn new(method: &str, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
        }
    }
}

// --- Method-specific types ---

/// Response for ListSessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: u64,
    pub pid: u32,
    pub cli_type: String,
    pub status: String,
    pub working_dir: String,
    pub started_at: u64,
    pub rss_bytes: Option<u64>,
    pub memory_high: Option<u64>,
    pub memory_max: Option<u64>,
}

impl SessionInfo {
    pub fn from_session(session: &Session, rss_bytes: Option<u64>) -> Self {
        Self {
            id: session.id,
            pid: session.pid,
            cli_type: format!("{}", session.cli_type),
            status: format!("{:?}", session.status),
            working_dir: session.working_dir.display().to_string(),
            started_at: session.started_at,
            rss_bytes,
            memory_high: session.memory_high,
            memory_max: session.memory_max,
        }
    }
}

/// Params for GetEvents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEventsParams {
    #[serde(default)]
    pub session_id: Option<u64>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

/// Params for Subscribe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeParams {
    #[serde(default)]
    pub session_id: Option<u64>,
    #[serde(default)]
    pub min_severity: Option<String>,
}

/// A streamed event sent to subscribed clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventNotification {
    pub timestamp: u64,
    pub signal: Signal,
}

// --- Error codes ---

pub const PARSE_ERROR: i32 = -32700;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;

// --- Subscription filter ---

pub struct SubscriptionFilter {
    pub session_id: Option<u64>,
    pub min_severity: Option<Severity>,
}

impl SubscriptionFilter {
    pub fn from_params(params: &SubscribeParams) -> Self {
        Self {
            session_id: params.session_id,
            min_severity: params.min_severity.as_ref().map(|s| Severity::parse(s)),
        }
    }

    pub fn matches(&self, signal: &Signal) -> bool {
        if let Some(sid) = self.session_id {
            if signal_session_id(signal) != Some(sid) {
                return false;
            }
        }
        if let Some(ref min) = self.min_severity {
            let sig_severity = signal_severity(signal);
            if !severity_at_least(&sig_severity, min) {
                return false;
            }
        }
        true
    }
}

fn signal_session_id(signal: &Signal) -> Option<u64> {
    match signal {
        Signal::SessionDiscovered(s) => Some(s.id),
        Signal::SessionExited { id, .. } => Some(*id),
        Signal::MemoryWarning { session_id, .. }
        | Signal::MemoryUrgent { session_id, .. }
        | Signal::LeakDetected { session_id, .. }
        | Signal::OomKill { session_id, .. }
        | Signal::SensitiveFileAccess { session_id, .. }
        | Signal::BoundaryViolation { session_id, .. }
        | Signal::UnexpectedNetwork { session_id, .. }
        | Signal::DangerousCommand { session_id, .. }
        | Signal::SuspiciousChild { session_id, .. }
        | Signal::ExfilAttempt { session_id, .. } => Some(*session_id),
    }
}

fn signal_severity(signal: &Signal) -> Severity {
    match signal {
        Signal::SessionDiscovered(_) | Signal::SessionExited { .. } => Severity::Info,
        Signal::MemoryWarning { .. } => Severity::Warning,
        Signal::MemoryUrgent { .. } | Signal::LeakDetected { .. } => Severity::Warning,
        Signal::OomKill { .. } => Severity::Critical,
        Signal::SensitiveFileAccess { severity, .. }
        | Signal::DangerousCommand { severity, .. } => severity.clone(),
        Signal::BoundaryViolation { .. }
        | Signal::UnexpectedNetwork { .. }
        | Signal::SuspiciousChild { .. } => Severity::Warning,
        Signal::ExfilAttempt { .. } => Severity::Critical,
    }
}

fn severity_at_least(actual: &Severity, min: &Severity) -> bool {
    severity_rank(actual) >= severity_rank(min)
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CliType;

    #[test]
    fn response_success_serializes() {
        let resp = JsonRpcResponse::success(
            Some(serde_json::json!(1)),
            serde_json::json!({"sessions": []}),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"sessions\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn response_error_serializes() {
        let resp = JsonRpcResponse::error(
            Some(serde_json::json!(1)),
            METHOD_NOT_FOUND,
            "not found".into(),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("-32601"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn filter_matches_all_when_empty() {
        let filter = SubscriptionFilter {
            session_id: None,
            min_severity: None,
        };
        let signal = Signal::MemoryWarning {
            session_id: 1,
            pid: 100,
            cli_type: CliType::ClaudeCode,
            rss_bytes: 1024,
            high_bytes: 2048,
        };
        assert!(filter.matches(&signal));
    }

    #[test]
    fn filter_by_session_id() {
        let filter = SubscriptionFilter {
            session_id: Some(42),
            min_severity: None,
        };
        let yes = Signal::MemoryWarning {
            session_id: 42,
            pid: 100,
            cli_type: CliType::ClaudeCode,
            rss_bytes: 1024,
            high_bytes: 2048,
        };
        let no = Signal::MemoryWarning {
            session_id: 99,
            pid: 100,
            cli_type: CliType::ClaudeCode,
            rss_bytes: 1024,
            high_bytes: 2048,
        };
        assert!(filter.matches(&yes));
        assert!(!filter.matches(&no));
    }

    #[test]
    fn filter_by_severity() {
        let filter = SubscriptionFilter {
            session_id: None,
            min_severity: Some(Severity::Critical),
        };
        let warning = Signal::MemoryWarning {
            session_id: 1,
            pid: 100,
            cli_type: CliType::ClaudeCode,
            rss_bytes: 1024,
            high_bytes: 2048,
        };
        let critical = Signal::OomKill {
            session_id: 1,
            pid: 100,
            cli_type: CliType::ClaudeCode,
            peak_rss_bytes: 4096,
        };
        assert!(!filter.matches(&warning));
        assert!(filter.matches(&critical));
    }

    #[test]
    fn notification_serializes() {
        let notif = JsonRpcNotification::new("event", serde_json::json!({"signal": "test"}));
        let json = serde_json::to_string(&notif).unwrap();
        assert!(json.contains("\"method\":\"event\""));
    }
}
