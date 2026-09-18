#![allow(dead_code)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use runsafety_shared::types::{AuditEntry, Signal};

pub struct SqliteAuditLogger {
    db_path: PathBuf,
    conn: Option<Connection>,
}

impl SqliteAuditLogger {
    pub fn new(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).context("creating audit directory")?;
        let db_path = dir.join("audit.db");
        let mut logger = Self {
            db_path,
            conn: None,
        };
        logger.init_database()?;
        Ok(logger)
    }

    fn init_database(&mut self) -> Result<()> {
        let conn = Connection::open(&self.db_path)
            .with_context(|| format!("opening SQLite database {}", self.db_path.display()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_entries(event_json);
        ",
        )?;

        self.conn = Some(conn);
        Ok(())
    }

    pub fn log_signal(&mut self, signal: &Signal) -> Result<()> {
        let entry = AuditEntry {
            timestamp: unix_timestamp(),
            event: signal.clone(),
        };
        let json = serde_json::to_string(&entry)?;

        if let Some(conn) = &self.conn {
            conn.execute(
                "INSERT INTO audit_entries (timestamp, event_json) VALUES (?1, ?2)",
                params![entry.timestamp, json],
            )
            .context("inserting audit entry")?;
        }

        Ok(())
    }

    pub fn query_entries(
        &self,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<AuditEntry>> {
        let conn = self
            .conn
            .as_ref()
            .context("database not initialized")?;

        let mut sql = String::from("SELECT event_json FROM audit_entries WHERE 1=1");
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(start) = start_time {
            sql.push_str(" AND timestamp >= ?1");
            params.push(Box::new(start));
        }

        if let Some(end) = end_time {
            sql.push_str(" AND timestamp <= ?2");
            params.push(Box::new(end));
        }

        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(lim) = limit {
            sql.push_str(&format!(" LIMIT {lim}"));
        }

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let json = row?;
            let entry: AuditEntry = serde_json::from_str(&json)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    pub fn get_stats(&self) -> Result<AuditStats> {
        let conn = self
            .conn
            .as_ref()
            .context("database not initialized")?;

        let total_entries: u64 =
            conn.query_row("SELECT COUNT(*) FROM audit_entries", [], |row| {
                row.get(0)
            })?;

        let oldest_entry: Option<u64> = conn
            .query_row(
                "SELECT MIN(timestamp) FROM audit_entries",
                [],
                |row| row.get(0),
            )
            .unwrap_or(None);

        let newest_entry: Option<u64> = conn
            .query_row(
                "SELECT MAX(timestamp) FROM audit_entries",
                [],
                |row| row.get(0),
            )
            .unwrap_or(None);

        Ok(AuditStats {
            total_entries,
            oldest_entry,
            newest_entry,
            db_path: self.db_path.clone(),
        })
    }
}

#[derive(Debug)]
pub struct AuditStats {
    pub total_entries: u64,
    pub oldest_entry: Option<u64>,
    pub newest_entry: Option<u64>,
    pub db_path: PathBuf,
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use runsafety_shared::types::{CliType, Session, SessionStatus};

    #[test]
    fn sqlite_audit_writes_entries() {
        let dir = std::env::temp_dir().join("runsafety-test-sqlite-audit");
        let _ = std::fs::remove_dir_all(&dir);
        let mut logger = SqliteAuditLogger::new(&dir).unwrap();

        let signal = Signal::SessionDiscovered(Session {
            id: 1,
            pid: 12345,
            cli_type: CliType::ClaudeCode,
            status: SessionStatus::Running,
            working_dir: "/tmp".into(),
            started_at: 0,
            memory_high: None,
            memory_max: None,
            cmdline: vec!["claude".into()],
        });

        logger.log_signal(&signal).unwrap();

        let entries = logger.query_entries(None, None, Some(10)).unwrap();
        assert_eq!(entries.len(), 1);

        let stats = logger.get_stats().unwrap();
        assert_eq!(stats.total_entries, 1);
        assert!(stats.oldest_entry.is_some());
        assert!(stats.newest_entry.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
