use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use runsafety_shared::types::{CliType, Signal};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
    fn on_session_discovered(&self, session: &runsafety_shared::types::Session) -> Option<Signal> {
        None
    }
    fn on_signal(&self, signal: &Signal) -> Option<Signal> {
        None
    }
    fn on_config_loaded(&self, config: &HashMap<String, String>) {}
    fn cleanup(&self) {}
}

pub struct PluginManager {
    plugins: Arc<RwLock<Vec<Box<dyn Plugin>>>>,
    config_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub enabled: bool,
}

impl PluginManager {
    pub fn new(config_dir: &Path) -> Self {
        Self {
            plugins: Arc::new(RwLock::new(Vec::new())),
            config_dir: config_dir.to_path_buf(),
        }
    }

    pub async fn load_plugins(&self) -> Result<()> {
        let plugins_dir = self.config_dir.join("plugins");
        if !plugins_dir.exists() {
            std::fs::create_dir_all(&plugins_dir)?;
            return Ok(());
        }

        info!("Loading plugins from {}", plugins_dir.display());

        // In a real implementation, this would:
        // 1. Scan the plugins directory for .toml config files
        // 2. Load shared libraries (.so, .dylib, .dll) based on config
        // 3. Instantiate plugin objects and add to the list

        Ok(())
    }

    pub async fn register_plugin(&self, plugin: Box<dyn Plugin>) {
        info!(
            "Registering plugin: {} v{}",
            plugin.name(),
            plugin.version()
        );
        self.plugins.write().await.push(plugin);
    }

    pub async fn notify_session_discovered(
        &self,
        session: &runsafety_shared::types::Session,
    ) -> Vec<Signal> {
        let plugins = self.plugins.read().await;
        let mut signals = Vec::new();

        for plugin in plugins.iter() {
            if let Some(signal) = plugin.on_session_discovered(session) {
                signals.push(signal);
            }
        }

        signals
    }

    pub async fn notify_signal(&self, signal: &Signal) -> Vec<Signal> {
        let plugins = self.plugins.read().await;
        let mut new_signals = Vec::new();

        for plugin in plugins.iter() {
            if let Some(new_signal) = plugin.on_signal(signal) {
                new_signals.push(new_signal);
            }
        }

        new_signals
    }

    pub async fn list_plugins(&self) -> Vec<PluginInfo> {
        let plugins = self.plugins.read().await;
        plugins
            .iter()
            .map(|p| PluginInfo {
                name: p.name().to_string(),
                version: p.version().to_string(),
                description: p.description().to_string(),
                enabled: true,
            })
            .collect()
    }

    pub async fn cleanup(&self) {
        let plugins = self.plugins.read().await;
        for plugin in plugins.iter() {
            plugin.cleanup();
        }
    }
}

pub struct BuiltInPlugin {
    name: String,
    version: String,
    description: String,
}

impl BuiltInPlugin {
    pub fn new(name: &str, version: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            description: description.to_string(),
        }
    }
}

impl Plugin for BuiltInPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> &str {
        &self.description
    }
}

pub struct SecurityPlugin {
    name: String,
    version: String,
    description: String,
    rules: Vec<CustomRule>,
}

#[derive(Debug, Clone)]
pub struct CustomRule {
    pub name: String,
    pub pattern: String,
    pub action: String,
}

impl SecurityPlugin {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: "Custom security rules plugin".to_string(),
            rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: CustomRule) {
        self.rules.push(rule);
    }
}

impl Plugin for SecurityPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn on_signal(&self, signal: &Signal) -> Option<Signal> {
        // Check if the signal matches any custom rules
        match signal {
            Signal::DangerousCommand {
                matched_text,
                ..
            } => {
                for rule in &self.rules {
                    if matched_text.contains(&rule.pattern) {
                        info!(
                            "Custom rule '{}' triggered by: {}",
                            rule.name, matched_text
                        );
                        // Could create a custom signal here
                    }
                }
                None
            }
            _ => None,
        }
    }
}

pub struct AnalyticsPlugin {
    name: String,
    version: String,
    description: String,
    event_count: Arc<RwLock<u64>>,
}

impl AnalyticsPlugin {
    pub fn new() -> Self {
        Self {
            name: "analytics".to_string(),
            version: "1.0.0".to_string(),
            description: "Analytics and metrics plugin".to_string(),
            event_count: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn get_event_count(&self) -> u64 {
        *self.event_count.read().await
    }
}

impl Plugin for AnalyticsPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn on_signal(&self, _signal: &Signal) -> Option<Signal> {
        // Increment event count (would need async in real implementation)
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plugin_manager_creation() {
        let dir = std::env::temp_dir().join("runsafety-test-plugins");
        let _ = std::fs::remove_dir_all(&dir);
        let manager = PluginManager::new(&dir);

        let plugin = BuiltInPlugin::new("test", "1.0.0", "Test plugin");
        manager.register_plugin(Box::new(plugin)).await;

        let plugins = manager.list_plugins().await;
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "test");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn security_plugin_triggers() {
        let mut plugin = SecurityPlugin::new("test-security");
        plugin.add_rule(CustomRule {
            name: "test-rule".to_string(),
            pattern: "dangerous".to_string(),
            action: "alert".to_string(),
        });

        let signal = Signal::DangerousCommand {
            session_id: 1,
            pid: 12345,
            cli_type: runsafety_shared::types::CliType::ClaudeCode,
            rule_name: "test".to_string(),
            matched_text: "this is dangerous command".to_string(),
            severity: runsafety_shared::types::Severity::Warning,
        };

        // The plugin should trigger but we can't easily test the log output
        let _ = plugin.on_signal(&signal);
    }
}
