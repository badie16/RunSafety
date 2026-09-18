use std::path::{Path, PathBuf};

use anyhow::Context;
use tracing::info;

use runsafety_shared::config::{AgentConfig, SecurityRulesConfig};

pub struct DaemonPaths {
    pub audit_dir: PathBuf,
    pub analytics_dir: PathBuf,
    pub config_dir: PathBuf,
    pub pid_file: PathBuf,
    #[cfg(not(target_os = "windows"))]
    pub socket_path: PathBuf,
    #[cfg(target_os = "windows")]
    pub pipe_name: String,
}

impl DaemonPaths {
    pub fn new() -> Self {
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("runsafety");
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/etc"))
            .join("runsafety");
        Self {
            audit_dir: data_dir.join("audit"),
            analytics_dir: data_dir.join("analytics"),
            config_dir,
            pid_file: data_dir.join("agent.pid"),
            #[cfg(not(target_os = "windows"))]
            socket_path: data_dir.join("agent.sock"),
            #[cfg(target_os = "windows")]
            pipe_name: r"\\.\pipe\runsafety-agent".to_string(),
        }
    }
}

pub fn load(path: Option<&Path>) -> anyhow::Result<AgentConfig> {
    if let Some(p) = path {
        let content = std::fs::read_to_string(p)
            .with_context(|| format!("reading config from {}", p.display()))?;
        return Ok(toml::from_str(&content)?);
    }

    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/etc"))
        .join("runsafety");
    let default_path = config_dir.join("agent.toml");

    if default_path.exists() {
        let content = std::fs::read_to_string(&default_path)
            .with_context(|| format!("reading config from {}", default_path.display()))?;
        return Ok(toml::from_str(&content)?);
    }

    Ok(default_config())
}

fn default_config() -> AgentConfig {
    toml::from_str(include_str!("../../../config/agent.toml"))
        .expect("built-in config is valid TOML")
}

/// Load security rules from security-rules.toml.
/// Search order: same directory as agent.toml, then ~/.config/runsafety/, then built-in default.
pub fn load_security_rules(
    agent_config_path: Option<&Path>,
) -> anyhow::Result<SecurityRulesConfig> {
    // Check next to the agent config file
    if let Some(p) = agent_config_path {
        if let Some(dir) = p.parent() {
            let rules_path = dir.join("security-rules.toml");
            if rules_path.exists() {
                info!("Loading security rules from {}", rules_path.display());
                let content = std::fs::read_to_string(&rules_path)
                    .with_context(|| format!("reading {}", rules_path.display()))?;
                return Ok(toml::from_str(&content)?);
            }
        }
    }

    // Check default config dir
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/etc"))
        .join("runsafety");
    let default_path = config_dir.join("security-rules.toml");

    if default_path.exists() {
        info!("Loading security rules from {}", default_path.display());
        let content = std::fs::read_to_string(&default_path)
            .with_context(|| format!("reading {}", default_path.display()))?;
        return Ok(toml::from_str(&content)?);
    }

    // Fall back to built-in default
    info!("Using built-in default security rules");
    Ok(default_security_rules())
}

fn default_security_rules() -> SecurityRulesConfig {
    toml::from_str(include_str!("../../../config/security-rules.toml"))
        .expect("built-in security rules are valid TOML")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_config_parses() {
        let config = default_config();
        assert!(config.discovery.scan_interval_secs > 0);
        assert!(!config.discovery.cli.is_empty());
    }

    #[test]
    fn builtin_security_rules_parse() {
        let rules = default_security_rules();
        assert!(
            !rules.file_access.is_empty(),
            "should have file access rules"
        );
        assert!(
            !rules.network_allow.is_empty(),
            "should have network allow rules"
        );
        assert!(
            !rules.command_pattern.is_empty(),
            "should have command patterns"
        );
    }

    #[test]
    fn builtin_config_has_security_section() {
        let config = default_config();
        assert!(config.security.enabled);
        assert_eq!(config.security.scan_interval_secs, 3);
        assert_eq!(config.security.fast_scan_interval_ms, 500);
        assert_eq!(config.security.exfil_window_secs, 10);
        assert_eq!(config.security.dedup_window_secs, 300);
    }

    #[test]
    fn load_security_rules_defaults() {
        let rules = load_security_rules(None).unwrap();
        assert!(!rules.file_access.is_empty());

        // Verify SSH private key rule exists with Warning severity
        let ssh_rule = rules
            .file_access
            .iter()
            .find(|r| r.name == "SSH private keys");
        assert!(ssh_rule.is_some());
        assert_eq!(ssh_rule.unwrap().severity, "Warning");
    }
}
