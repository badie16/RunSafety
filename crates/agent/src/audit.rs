use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use runsafety_shared::types::{AuditEntry, Signal};

pub struct AuditLogger {
    dir: PathBuf,
}

impl AuditLogger {
    pub fn new(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).context("creating audit directory")?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn log_signal(&self, signal: &Signal) -> Result<()> {
        let entry = AuditEntry {
            timestamp: unix_timestamp(),
            event: signal.clone(),
        };
        let path = self.dir.join(format!("{}.jsonl", today_string()));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening audit file {}", path.display()))?;
        let json = serde_json::to_string(&entry)?;
        writeln!(file, "{json}")?;
        Ok(())
    }
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn today_string() -> String {
    let secs = unix_timestamp() as i64;
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&secs as *const i64 as *const libc::time_t, &mut tm);
        format!(
            "{:04}-{:02}-{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn today_string_looks_like_date() {
        let s = today_string();
        assert_eq!(s.len(), 10);
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
    }

    #[test]
    fn audit_writes_jsonl() {
        let dir = std::env::temp_dir().join("runsafety-test-audit");
        let _ = fs::remove_dir_all(&dir);
        let logger = AuditLogger::new(&dir).unwrap();

        let signal = Signal::SessionDiscovered(runsafety_shared::types::Session {
            id: 1,
            pid: 12345,
            cli_type: runsafety_shared::types::CliType::ClaudeCode,
            status: runsafety_shared::types::SessionStatus::Running,
            working_dir: "/tmp".into(),
            started_at: 0,
            memory_high: None,
            memory_max: None,
            cmdline: vec!["claude".into()],
        });

        logger.log_signal(&signal).unwrap();

        let file_path = dir.join(format!("{}.jsonl", today_string()));
        let content = fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("SessionDiscovered"));
        assert!(content.contains("12345"));

        let _ = fs::remove_dir_all(&dir);
    }
}
