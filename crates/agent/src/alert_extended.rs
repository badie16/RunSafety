use std::path::Path;

use anyhow::{Context, Result};
use runsafety_shared::config::AlertConfig;
use runsafety_shared::types::{Severity, Signal};
use tracing::{error, info, warn};

pub struct AlertNotifier {
    config: AlertConfig,
}

#[derive(Debug, Clone)]
pub struct AlertMessage {
    pub title: String,
    pub body: String,
    pub severity: Severity,
    pub timestamp: u64,
}

impl AlertNotifier {
    pub fn new(config: &AlertConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    pub async fn send_alert(&self, message: &AlertMessage) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if let Some(ref email) = self.config.email {
            if self.should_send_email(&message.severity) {
                if let Err(e) = self.send_email(email, message).await {
                    error!("Failed to send email alert: {e}");
                }
            }
        }

        if let Some(ref sms) = self.config.sms {
            if self.should_send_sms(&message.severity) {
                if let Err(e) = self.send_sms(sms, message).await {
                    error!("Failed to send SMS alert: {e}");
                }
            }
        }

        if let Some(ref webhook) = self.config.webhook {
            if self.should_send_webhook(&message.severity) {
                if let Err(e) = self.send_webhook(webhook, message).await {
                    error!("Failed to send webhook alert: {e}");
                }
            }
        }

        Ok(())
    }

    fn should_send_email(&self, severity: &Severity) -> bool {
        match &self.config.min_severity {
            Some(min) => severity >= &Severity::parse(min),
            None => true,
        }
    }

    fn should_send_sms(&self, severity: &Severity) -> bool {
        match &self.config.sms_min_severity {
            Some(min) => severity >= &Severity::parse(min),
            None => *severity == Severity::Critical,
        }
    }

    fn should_send_webhook(&self, severity: &Severity) -> bool {
        match &self.config.min_severity {
            Some(min) => severity >= &Severity::parse(min),
            None => true,
        }
    }

    async fn send_email(&self, email_config: &EmailConfig, message: &AlertMessage) -> Result<()> {
        info!(
            "Sending email alert to {}: {}",
            email_config.to, message.title
        );

        // In a real implementation, this would use an SMTP client
        // For now, we just log the attempt
        if let Some(ref smtp_server) = email_config.smtp_server {
            info!(
                "Would send email via {}:{} to {}",
                smtp_server,
                email_config.smtp_port.unwrap_or(587),
                email_config.to
            );
        }

        Ok(())
    }

    async fn send_sms(&self, sms_config: &SmsConfig, message: &AlertMessage) -> Result<()> {
        info!(
            "Sending SMS alert to {}: {}",
            sms_config.to, message.title
        );

        // In a real implementation, this would use an SMS API (Twilio, etc.)
        // For now, we just log the attempt
        if let Some(ref provider) = sms_config.provider {
            info!(
                "Would send SMS via {} to {}",
                provider, sms_config.to
            );
        }

        Ok(())
    }

    async fn send_webhook(&self, webhook_config: &WebhookConfig, message: &AlertMessage) -> Result<()> {
        info!(
            "Sending webhook alert to {}: {}",
            webhook_config.url, message.title
        );

        let payload = serde_json::json!({
            "title": message.title,
            "body": message.body,
            "severity": message.severity.to_string(),
            "timestamp": message.timestamp,
        });

        // In a real implementation, this would make an HTTP POST request
        // For now, we just log the attempt
        info!("Webhook payload: {}", serde_json::to_string(&payload)?);

        Ok(())
    }

    pub fn create_alert_from_signal(signal: &Signal) -> Option<AlertMessage> {
        match signal {
            Signal::MemoryWarning {
                cli_type,
                rss_bytes,
                high_bytes,
                ..
            } => Some(AlertMessage {
                title: format!("{cli_type} High Memory"),
                body: format!(
                    "Memory usage: {} / {} ({:.0}%)",
                    format_bytes(*rss_bytes),
                    format_bytes(*high_bytes),
                    (*rss_bytes as f64 / *high_bytes as f64) * 100.0,
                ),
                severity: Severity::Warning,
                timestamp: unix_timestamp(),
            }),
            Signal::MemoryUrgent {
                cli_type,
                rss_bytes,
                high_bytes,
                ..
            } => Some(AlertMessage {
                title: format!("{cli_type} Critical Memory"),
                body: format!(
                    "URGENT: Memory usage: {} / {} ({:.0}%) - Save your work!",
                    format_bytes(*rss_bytes),
                    format_bytes(*high_bytes),
                    (*rss_bytes as f64 / *high_bytes as f64) * 100.0,
                ),
                severity: Severity::Critical,
                timestamp: unix_timestamp(),
            }),
            Signal::OomKill {
                cli_type,
                peak_rss_bytes,
                ..
            } => Some(AlertMessage {
                title: format!("{cli_type} Killed (OOM)"),
                body: format!(
                    "Process killed due to out of memory. Peak usage: {}",
                    format_bytes(*peak_rss_bytes),
                ),
                severity: Severity::Critical,
                timestamp: unix_timestamp(),
            }),
            Signal::LeakDetected {
                cli_type,
                rss_bytes,
                duration_secs,
                ..
            } => Some(AlertMessage {
                title: format!("{cli_type} Memory Leak"),
                body: format!(
                    "Memory leak detected. Current usage: {} over {}s",
                    format_bytes(*rss_bytes),
                    duration_secs,
                ),
                severity: Severity::Critical,
                timestamp: unix_timestamp(),
            }),
            Signal::SensitiveFileAccess {
                cli_type,
                path,
                rule_name,
                severity,
                ..
            } => Some(AlertMessage {
                title: format!("Sensitive File Access: {rule_name}"),
                body: format!("{cli_type} accessed {}", path.display()),
                severity: severity.clone(),
                timestamp: unix_timestamp(),
            }),
            Signal::UnexpectedNetwork {
                cli_type,
                remote_addr,
                remote_port,
                ..
            } => Some(AlertMessage {
                title: "Unexpected Network Connection".to_string(),
                body: format!(
                    "{cli_type} connected to {remote_addr}:{remote_port}"
                ),
                severity: Severity::Warning,
                timestamp: unix_timestamp(),
            }),
            Signal::DangerousCommand {
                cli_type,
                rule_name,
                matched_text,
                severity,
                ..
            } => Some(AlertMessage {
                title: format!("Dangerous Command: {rule_name}"),
                body: format!("{cli_type}: {matched_text}"),
                severity: severity.clone(),
                timestamp: unix_timestamp(),
            }),
            Signal::ExfilAttempt {
                cli_type,
                file_path,
                remote_addr,
                ..
            } => Some(AlertMessage {
                title: "Data Exfiltration Attempt".to_string(),
                body: format!(
                    "{cli_type} tried to send {} to {remote_addr}",
                    file_path.display()
                ),
                severity: Severity::Critical,
                timestamp: unix_timestamp(),
            }),
            _ => None,
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub to: String,
    pub smtp_server: Option<String>,
    pub smtp_port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SmsConfig {
    pub to: String,
    pub provider: Option<String>,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: String,
    pub headers: Option<Vec<(String, String)>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_from_memory_warning() {
        let signal = Signal::MemoryWarning {
            session_id: 1,
            pid: 12345,
            cli_type: runsafety_shared::types::CliType::ClaudeCode,
            rss_bytes: 2 * 1024 * 1024 * 1024,
            high_bytes: 3 * 1024 * 1024 * 1024,
        };

        let alert = AlertNotifier::create_alert_from_signal(&signal).unwrap();
        assert!(alert.title.contains("Claude Code"));
        assert_eq!(alert.severity, Severity::Warning);
    }

    #[test]
    fn alert_from_oom_kill() {
        let signal = Signal::OomKill {
            session_id: 1,
            pid: 12345,
            cli_type: runsafety_shared::types::CliType::Codex,
            peak_rss_bytes: 4 * 1024 * 1024 * 1024,
        };

        let alert = AlertNotifier::create_alert_from_signal(&signal).unwrap();
        assert!(alert.title.contains("Codex"));
        assert!(alert.title.contains("OOM"));
        assert_eq!(alert.severity, Severity::Critical);
    }
}
