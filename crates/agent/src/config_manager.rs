#![allow(dead_code)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use runsafety_shared::config::{AgentConfig, SecurityRulesConfig};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigBackup {
    pub version: String,
    pub timestamp: u64,
    pub agent_config: AgentConfig,
    pub security_rules: SecurityRulesConfig,
    pub metadata: BackupMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub hostname: String,
    pub username: String,
    pub platform: String,
    pub runsafety_version: String,
}

pub struct ConfigManager {
    config_dir: PathBuf,
}

impl ConfigManager {
    pub fn new(config_dir: &Path) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
        }
    }

    pub fn export_config(&self, output_path: &Path) -> Result<()> {
        let agent_config = self.load_agent_config()?;
        let security_rules = self.load_security_rules()?;

        let backup = ConfigBackup {
            version: "1.0.0".to_string(),
            timestamp: unix_timestamp(),
            agent_config,
            security_rules,
            metadata: BackupMetadata {
                hostname: hostname::get()
                    .map(|h| h.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".to_string()),
                username: whoami::username(),
                platform: std::env::consts::OS.to_string(),
                runsafety_version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };

        let json = serde_json::to_string_pretty(&backup)?;
        std::fs::write(output_path, json)
            .with_context(|| format!("writing config to {}", output_path.display()))?;

        info!("Configuration exported to {}", output_path.display());
        Ok(())
    }

    pub fn import_config(&self, input_path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(input_path)
            .with_context(|| format!("reading config from {}", input_path.display()))?;

        let backup: ConfigBackup =
            serde_json::from_str(&content).context("parsing config backup")?;

        info!(
            "Importing configuration from {} (created {})",
            input_path.display(),
            backup.metadata.runsafety_version
        );

        // Validate the backup
        if backup.version != "1.0.0" {
            error!("Unsupported backup version: {}", backup.version);
            anyhow::bail!("Unsupported backup version: {}", backup.version);
        }

        // Backup current config
        let backup_dir = self.config_dir.join("backups");
        std::fs::create_dir_all(&backup_dir)?;
        let backup_file = backup_dir.join(format!(
            "backup-{}.json",
            chrono_now()
        ));
        self.export_config(&backup_file)?;
        info!("Current config backed up to {}", backup_file.display());

        // Write new config
        let agent_config_path = self.config_dir.join("agent.toml");
        let agent_config_toml = toml::to_string_pretty(&backup.agent_config)?;
        std::fs::write(&agent_config_path, agent_config_toml)?;

        let security_rules_path = self.config_dir.join("security-rules.toml");
        let security_rules_toml = toml::to_string_pretty(&backup.security_rules)?;
        std::fs::write(&security_rules_path, security_rules_toml)?;

        info!("Configuration imported successfully");
        Ok(())
    }

    pub fn list_backups(&self) -> Result<Vec<BackupInfo>> {
        let backup_dir = self.config_dir.join("backups");
        if !backup_dir.exists() {
            return Ok(Vec::new());
        }

        let mut backups = Vec::new();
        for entry in std::fs::read_dir(&backup_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(backup) = serde_json::from_str::<ConfigBackup>(&content) {
                        backups.push(BackupInfo {
                            path,
                            timestamp: backup.timestamp,
                            version: backup.metadata.runsafety_version,
                            hostname: backup.metadata.hostname,
                        });
                    }
                }
            }
        }

        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(backups)
    }

    pub fn restore_backup(&self, backup_path: &Path) -> Result<()> {
        self.import_config(backup_path)
    }

    pub fn validate_config(&self) -> Result<Vec<String>> {
        let mut warnings = Vec::new();

        let agent_config_path = self.config_dir.join("agent.toml");
        if !agent_config_path.exists() {
            warnings.push("agent.toml not found, using defaults".to_string());
        } else if let Ok(content) = std::fs::read_to_string(&agent_config_path) {
            if let Err(e) = toml::from_str::<AgentConfig>(&content) {
                warnings.push(format!("Invalid agent.toml: {e}"));
            }
        }

        let security_rules_path = self.config_dir.join("security-rules.toml");
        if !security_rules_path.exists() {
            warnings.push("security-rules.toml not found, using defaults".to_string());
        } else if let Ok(content) = std::fs::read_to_string(&security_rules_path) {
            if let Err(e) = toml::from_str::<SecurityRulesConfig>(&content) {
                warnings.push(format!("Invalid security-rules.toml: {e}"));
            }
        }

        Ok(warnings)
    }

    fn load_agent_config(&self) -> Result<AgentConfig> {
        let path = self.config_dir.join("agent.toml");
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            Ok(toml::from_str(&content)?)
        } else {
            Ok(AgentConfig::default())
        }
    }

    fn load_security_rules(&self) -> Result<SecurityRulesConfig> {
        let path = self.config_dir.join("security-rules.toml");
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            Ok(toml::from_str(&content)?)
        } else {
            Ok(SecurityRulesConfig::default())
        }
    }
}

#[derive(Debug)]
pub struct BackupInfo {
    pub path: PathBuf,
    pub timestamp: u64,
    pub version: String,
    pub hostname: String,
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn chrono_now() -> u64 {
    unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_export_import() {
        let dir = std::env::temp_dir().join("runsafety-test-config");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let manager = ConfigManager::new(&dir);

        // Export
        let export_path = dir.join("backup.json");
        manager.export_config(&export_path).unwrap();
        assert!(export_path.exists());

        // Import
        manager.import_config(&export_path).unwrap();

        // Validate
        let warnings = manager.validate_config().unwrap();
        assert!(warnings.is_empty() || warnings.iter().any(|w| w.contains("not found")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_backups_empty() {
        let dir = std::env::temp_dir().join("runsafety-test-backups");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let manager = ConfigManager::new(&dir);
        let backups = manager.list_backups().unwrap();
        assert!(backups.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
