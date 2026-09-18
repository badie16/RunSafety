use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use runsafety_shared::types::{CliType, Severity};
use tracing::info;

pub struct AnalyticsDashboard {
    #[allow(dead_code)]
    db_path: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalyticsSummary {
    pub total_sessions: u64,
    pub active_sessions: u64,
    pub total_events: u64,
    pub events_by_severity: HashMap<String, u64>,
    pub events_by_cli: HashMap<String, u64>,
    pub events_by_hour: HashMap<u32, u64>,
    pub top_sensitive_files: Vec<(String, u64)>,
    pub top_network_hosts: Vec<(String, u64)>,
    pub top_dangerous_commands: Vec<(String, u64)>,
    pub memory_stats: MemoryStats,
    pub security_stats: SecurityStats,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryStats {
    pub avg_memory_usage: f64,
    pub max_memory_usage: u64,
    pub total_oom_kills: u64,
    pub total_leaks_detected: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SecurityStats {
    pub total_file_access_alerts: u64,
    pub total_network_alerts: u64,
    pub total_command_alerts: u64,
    pub total_exfil_attempts: u64,
    pub critical_alerts_today: u64,
}

#[derive(Debug, Clone)]
pub struct TimeSeriesData {
    pub timestamps: Vec<u64>,
    pub values: Vec<f64>,
}

impl AnalyticsDashboard {
    pub fn new(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).context("creating analytics directory")?;
        let db_path = dir.join("analytics.db");
        let conn = Connection::open(&db_path)
            .with_context(|| format!("opening analytics database {}", db_path.display()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY,
                pid INTEGER NOT NULL,
                cli_type TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                peak_memory INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                session_id INTEGER,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );
            CREATE TABLE IF NOT EXISTS memory_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                rss_bytes INTEGER NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_memory_session ON memory_history(session_id);
            ",
        )?;

        Ok(Self {
            db_path,
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub async fn record_session_start(&self, session_id: u64, pid: u32, cli_type: &CliType) -> Result<()> {
        let conn = self.conn.clone();
        let cli_str = cli_type.to_string();
        let ts = chrono_now();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO sessions (id, pid, cli_type, started_at) VALUES (?1, ?2, ?3, ?4)",
                params![session_id, pid, cli_str, ts],
            )
        })
        .await?
        .context("recording session start")?;
        Ok(())
    }

    pub async fn record_session_end(&self, session_id: u64, peak_memory: u64) -> Result<()> {
        let conn = self.conn.clone();
        let ts = chrono_now();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE sessions SET ended_at = ?1, peak_memory = ?2 WHERE id = ?3",
                params![ts, peak_memory, session_id],
            )
        })
        .await?
        .context("recording session end")?;
        Ok(())
    }

    pub async fn record_event(
        &self,
        session_id: Option<u64>,
        event_type: &str,
        severity: &Severity,
        details: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.clone();
        let event_type = event_type.to_string();
        let severity_str = severity.to_string();
        let details = details.map(|s| s.to_string());
        let ts = chrono_now();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO events (timestamp, session_id, event_type, severity, details) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ts, session_id, event_type, severity_str, details],
            )
        })
        .await?
        .context("recording event")?;
        Ok(())
    }

    pub async fn record_memory_usage(&self, session_id: u64, rss_bytes: u64) -> Result<()> {
        let conn = self.conn.clone();
        let ts = chrono_now();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO memory_history (timestamp, session_id, rss_bytes) VALUES (?1, ?2, ?3)",
                params![ts, session_id, rss_bytes],
            )
        })
        .await?
        .context("recording memory usage")?;
        Ok(())
    }

    pub async fn get_summary(&self) -> Result<AnalyticsSummary> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();

            let total_sessions: u64 = conn.query_row(
                "SELECT COUNT(*) FROM sessions",
                [],
                |row| row.get(0),
            )?;

            let active_sessions: u64 = conn.query_row(
                "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL",
                [],
                |row| row.get(0),
            )?;

            let total_events: u64 = conn.query_row(
                "SELECT COUNT(*) FROM events",
                [],
                |row| row.get(0),
            )?;

            let mut events_by_severity = HashMap::new();
            let mut stmt = conn.prepare(
                "SELECT severity, COUNT(*) FROM events GROUP BY severity"
            )?;
            for row in stmt.query_map([], |row| {
                let severity: String = row.get(0)?;
                let count: u64 = row.get(1)?;
                Ok((severity, count))
            })? {
                let (severity, count) = row?;
                events_by_severity.insert(severity, count);
            }

            let mut events_by_cli = HashMap::new();
            let mut stmt = conn.prepare(
                "SELECT s.cli_type, COUNT(*) FROM events e JOIN sessions s ON e.session_id = s.id GROUP BY s.cli_type"
            )?;
            for row in stmt.query_map([], |row| {
                let cli_type: String = row.get(0)?;
                let count: u64 = row.get(1)?;
                Ok((cli_type, count))
            })? {
                let (cli_type, count) = row?;
                events_by_cli.insert(cli_type, count);
            }

            let mut events_by_hour = HashMap::new();
            let mut stmt = conn.prepare(
                "SELECT (timestamp % 86400) / 3600 as hour, COUNT(*) FROM events GROUP BY hour"
            )?;
            for row in stmt.query_map([], |row| {
                let hour: u32 = row.get(0)?;
                let count: u64 = row.get(1)?;
                Ok((hour, count))
            })? {
                let (hour, count) = row?;
                events_by_hour.insert(hour, count);
            }

            let mut top_sensitive_files = Vec::new();
            let mut stmt = conn.prepare(
                "SELECT details, COUNT(*) FROM events WHERE event_type = 'SensitiveFileAccess' GROUP BY details ORDER BY COUNT(*) DESC LIMIT 10"
            )?;
            for row in stmt.query_map([], |row| {
                let file: String = row.get(0).unwrap_or_default();
                let count: u64 = row.get(1)?;
                Ok((file, count))
            })? {
                top_sensitive_files.push(row?);
            }

            let mut top_network_hosts = Vec::new();
            let mut stmt = conn.prepare(
                "SELECT details, COUNT(*) FROM events WHERE event_type = 'UnexpectedNetwork' GROUP BY details ORDER BY COUNT(*) DESC LIMIT 10"
            )?;
            for row in stmt.query_map([], |row| {
                let host: String = row.get(0).unwrap_or_default();
                let count: u64 = row.get(1)?;
                Ok((host, count))
            })? {
                top_network_hosts.push(row?);
            }

            let mut top_dangerous_commands = Vec::new();
            let mut stmt = conn.prepare(
                "SELECT details, COUNT(*) FROM events WHERE event_type = 'DangerousCommand' GROUP BY details ORDER BY COUNT(*) DESC LIMIT 10"
            )?;
            for row in stmt.query_map([], |row| {
                let cmd: String = row.get(0).unwrap_or_default();
                let count: u64 = row.get(1)?;
                Ok((cmd, count))
            })? {
                top_dangerous_commands.push(row?);
            }

            let avg_memory_usage: f64 = conn.query_row(
                "SELECT COALESCE(AVG(rss_bytes), 0) FROM memory_history",
                [],
                |row| row.get(0),
            )?;

            let max_memory_usage: u64 = conn.query_row(
                "SELECT COALESCE(MAX(rss_bytes), 0) FROM memory_history",
                [],
                |row| row.get(0),
            )?;

            let total_oom_kills: u64 = conn.query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'OomKill'",
                [],
                |row| row.get(0),
            )?;

            let total_leaks_detected: u64 = conn.query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'LeakDetected'",
                [],
                |row| row.get(0),
            )?;

            let total_file_access_alerts: u64 = conn.query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'SensitiveFileAccess'",
                [],
                |row| row.get(0),
            )?;

            let total_network_alerts: u64 = conn.query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'UnexpectedNetwork'",
                [],
                |row| row.get(0),
            )?;

            let total_command_alerts: u64 = conn.query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'DangerousCommand'",
                [],
                |row| row.get(0),
            )?;

            let total_exfil_attempts: u64 = conn.query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'ExfilAttempt'",
                [],
                |row| row.get(0),
            )?;

            let today_start = chrono_now() - (chrono_now() % 86400);
            let critical_alerts_today: u64 = conn.query_row(
                "SELECT COUNT(*) FROM events WHERE severity = 'Critical' AND timestamp >= ?1",
                params![today_start],
                |row| row.get(0),
            )?;

            Ok(AnalyticsSummary {
                total_sessions,
                active_sessions,
                total_events,
                events_by_severity,
                events_by_cli,
                events_by_hour,
                top_sensitive_files,
                top_network_hosts,
                top_dangerous_commands,
                memory_stats: MemoryStats {
                    avg_memory_usage,
                    max_memory_usage,
                    total_oom_kills,
                    total_leaks_detected,
                },
                security_stats: SecurityStats {
                    total_file_access_alerts,
                    total_network_alerts,
                    total_command_alerts,
                    total_exfil_attempts,
                    critical_alerts_today,
                },
            })
        })
        .await?
    }

    pub async fn get_memory_timeseries(&self, session_id: u64, hours: u64) -> Result<TimeSeriesData> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let start_time = chrono_now() - (hours * 3600);

            let mut timestamps = Vec::new();
            let mut values = Vec::new();

            let mut stmt = conn.prepare(
                "SELECT timestamp, rss_bytes FROM memory_history WHERE session_id = ?1 AND timestamp >= ?2 ORDER BY timestamp"
            )?;

            for row in stmt.query_map(params![session_id, start_time], |row| {
                let ts: u64 = row.get(0)?;
                let rss: u64 = row.get(1)?;
                Ok((ts, rss as f64))
            })? {
                let (ts, rss) = row?;
                timestamps.push(ts);
                values.push(rss);
            }

            Ok(TimeSeriesData { timestamps, values })
        })
        .await?
    }

    pub async fn get_events_timeline(&self, hours: u64) -> Result<TimeSeriesData> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let start_time = chrono_now() - (hours * 3600);

            let mut timestamps = Vec::new();
            let mut values = Vec::new();

            let mut stmt = conn.prepare(
                "SELECT (timestamp / 3600) * 3600 as hour, COUNT(*) FROM events WHERE timestamp >= ?1 GROUP BY hour ORDER BY hour"
            )?;

            for row in stmt.query_map(params![start_time], |row| {
                let ts: u64 = row.get(0)?;
                let count: u64 = row.get(1)?;
                Ok((ts, count as f64))
            })? {
                let (ts, count) = row?;
                timestamps.push(ts);
                values.push(count);
            }

            Ok(TimeSeriesData { timestamps, values })
        })
        .await?
    }

    pub async fn export_analytics(&self, output_path: &Path) -> Result<()> {
        let summary = self.get_summary().await?;
        let json = serde_json::to_string_pretty(&summary)?;
        tokio::fs::write(output_path, json).await?;
        info!("Analytics exported to {}", output_path.display());
        Ok(())
    }
}

fn chrono_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn analytics_dashboard_creation() {
        let dir = std::env::temp_dir().join("runsafety-test-analytics");
        let _ = std::fs::remove_dir_all(&dir);
        let dashboard = AnalyticsDashboard::new(&dir).unwrap();

        dashboard.record_session_start(1, 12345, &CliType::ClaudeCode).await.unwrap();
        dashboard.record_event(Some(1), "TestEvent", &Severity::Info, Some("test")).await.unwrap();
        dashboard.record_session_end(1, 1024).await.unwrap();

        let summary = dashboard.get_summary().await.unwrap();
        assert_eq!(summary.total_sessions, 1);
        assert_eq!(summary.total_events, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
