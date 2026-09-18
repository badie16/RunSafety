use std::path::PathBuf;

use runsafety_agent::analytics::AnalyticsDashboard;
use runsafety_agent::config_manager::ConfigManager;
use runsafety_agent::plugin::{BuiltInPlugin, PluginManager, SecurityPlugin, CustomRule};
use runsafety_shared::types::{CliType, Severity, Signal};

#[tokio::test]
async fn test_analytics_dashboard_full_workflow() {
    let dir = std::env::temp_dir().join("runsafety-test-analytics-full");
    let _ = std::fs::remove_dir_all(&dir);

    let dashboard = AnalyticsDashboard::new(&dir).unwrap();

    // Record session start
    dashboard
        .record_session_start(1, 12345, &CliType::ClaudeCode)
        .await
        .unwrap();

    // Record events
    dashboard
        .record_event(
            Some(1),
            "TestEvent",
            &Severity::Info,
            Some("test details"),
        )
        .await
        .unwrap();

    dashboard
        .record_event(
            Some(1),
            "SensitiveFileAccess",
            &Severity::Warning,
            Some("/home/user/.ssh/id_rsa"),
        )
        .await
        .unwrap();

    dashboard
        .record_event(
            Some(1),
            "UnexpectedNetwork",
            &Severity::Warning,
            Some("192.168.1.100"),
        )
        .await
        .unwrap();

    // Record memory usage
    dashboard.record_memory_usage(1, 1024 * 1024).await.unwrap();
    dashboard.record_memory_usage(1, 2 * 1024 * 1024).await.unwrap();
    dashboard.record_memory_usage(1, 1500 * 1024).await.unwrap();

    // Record session end
    dashboard.record_session_end(1, 2 * 1024 * 1024).await.unwrap();

    // Get summary
    let summary = dashboard.get_summary().await.unwrap();
    assert_eq!(summary.total_sessions, 1);
    assert_eq!(summary.total_events, 3);
    assert!(summary.memory_stats.avg_memory_usage > 0.0);
    assert!(summary.memory_stats.max_memory_usage > 0);
    assert_eq!(summary.security_stats.total_file_access_alerts, 1);
    assert_eq!(summary.security_stats.total_network_alerts, 1);

    // Get memory timeseries
    let timeseries = dashboard.get_memory_timeseries(1, 1).await.unwrap();
    assert_eq!(timeseries.values.len(), 3);

    // Get events timeline
    let timeline = dashboard.get_events_timeline(1).await.unwrap();
    assert!(!timeline.timestamps.is_empty());

    // Export analytics
    let export_path = dir.join("export.json");
    dashboard.export_analytics(&export_path).await.unwrap();
    assert!(export_path.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_analytics_multiple_sessions() {
    let dir = std::env::temp_dir().join("runsafety-test-analytics-multi");
    let _ = std::fs::remove_dir_all(&dir);

    let dashboard = AnalyticsDashboard::new(&dir).unwrap();

    // Record multiple sessions
    for i in 1..=5 {
        dashboard
            .record_session_start(i, 10000 + i as u32, &CliType::Codex)
            .await
            .unwrap();

        dashboard
            .record_event(Some(i), "TestEvent", &Severity::Info, None)
            .await
            .unwrap();

        dashboard.record_session_end(i, 1024 * 1024).await.unwrap();
    }

    let summary = dashboard.get_summary().await.unwrap();
    assert_eq!(summary.total_sessions, 5);
    assert_eq!(summary.total_events, 5);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_config_manager_export_import() {
    let dir = std::env::temp_dir().join("runsafety-test-config-manager");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let manager = ConfigManager::new(&dir);

    // Export config
    let export_path = dir.join("backup.json");
    manager.export_config(&export_path).unwrap();
    assert!(export_path.exists());

    // Read and verify export
    let content = std::fs::read_to_string(&export_path).unwrap();
    assert!(content.contains("1.0.0"));
    assert!(content.contains("runsafety"));

    // Import config
    manager.import_config(&export_path).unwrap();

    // Verify config files were created
    assert!(dir.join("agent.toml").exists());
    assert!(dir.join("security-rules.toml").exists());

    // Validate config
    let warnings = manager.validate_config().unwrap();
    assert!(warnings.is_empty());

    // List backups
    let backups = manager.list_backups().unwrap();
    assert!(!backups.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_config_manager_backup_restore() {
    let dir = std::env::temp_dir().join("runsafety-test-config-backup");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let manager = ConfigManager::new(&dir);

    // Create initial config
    let export_path = dir.join("initial.json");
    manager.export_config(&export_path).unwrap();

    // Import (creates config files)
    manager.import_config(&export_path).unwrap();

    // Create backup
    let backup_path = dir.join("backup.json");
    manager.export_config(&backup_path).unwrap();

    // Restore backup
    manager.restore_backup(&backup_path).unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_plugin_manager_builtin_plugins() {
    let dir = std::env::temp_dir().join("runsafety-test-plugins-builtin");
    let _ = std::fs::remove_dir_all(&dir);

    let manager = PluginManager::new(&dir);

    // Register built-in plugins
    manager
        .register_plugin(Box::new(BuiltInPlugin::new(
            "test-plugin",
            "1.0.0",
            "Test plugin description",
        )))
        .await;

    manager
        .register_plugin(Box::new(BuiltInPlugin::new(
            "test-plugin-2",
            "2.0.0",
            "Another test plugin",
        )))
        .await;

    // List plugins
    let plugins = manager.list_plugins().await;
    assert_eq!(plugins.len(), 2);
    assert_eq!(plugins[0].name, "test-plugin");
    assert_eq!(plugins[1].name, "test-plugin-2");
    assert!(plugins[0].enabled);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_plugin_session_notification() {
    let dir = std::env::temp_dir().join("runsafety-test-plugins-notification");
    let _ = std::fs::remove_dir_all(&dir);

    let manager = PluginManager::new(&dir);

    // Create a session
    let session = runsafety_shared::types::Session {
        id: 1,
        pid: 12345,
        cli_type: CliType::ClaudeCode,
        status: runsafety_shared::types::SessionStatus::Running,
        working_dir: PathBuf::from("/tmp"),
        started_at: 1234567890,
        memory_high: None,
        memory_max: None,
        cmdline: vec!["claude-code".to_string()],
    };

    // Notify plugins (no plugins registered, should return empty)
    let signals = manager.notify_session_discovered(&session).await;
    assert!(signals.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_security_plugin_custom_rules() {
    let dir = std::env::temp_dir().join("runsafety-test-security-plugin");
    let _ = std::fs::remove_dir_all(&dir);

    let mut plugin = SecurityPlugin::new("test-security");

    // Add custom rules
    plugin.add_rule(CustomRule {
        name: "block-curl".to_string(),
        pattern: "curl".to_string(),
        action: "alert".to_string(),
    });

    plugin.add_rule(CustomRule {
        name: "block-wget".to_string(),
        pattern: "wget".to_string(),
        action: "alert".to_string(),
    });

    // Test signal processing
    let signal = Signal::DangerousCommand {
        session_id: 1,
        pid: 12345,
        cli_type: CliType::ClaudeCode,
        rule_name: "test".to_string(),
        matched_text: "curl http://evil.com".to_string(),
        severity: Severity::Warning,
    };

    // Plugin should process the signal
    let result = plugin.on_signal(&signal);
    assert!(result.is_none()); // No new signal generated

    // Test with non-matching command
    let signal2 = Signal::DangerousCommand {
        session_id: 1,
        pid: 12345,
        cli_type: CliType::ClaudeCode,
        rule_name: "test".to_string(),
        matched_text: "ls -la".to_string(),
        severity: Severity::Warning,
    };

    let result2 = plugin.on_signal(&signal2);
    assert!(result2.is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_analytics_summary_format() {
    let dir = std::env::temp_dir().join("runsafety-test-analytics-format");
    let _ = std::fs::remove_dir_all(&dir);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let dashboard = AnalyticsDashboard::new(&dir).unwrap();

        dashboard
            .record_session_start(1, 12345, &CliType::ClaudeCode)
            .await
            .unwrap();

        let summary = dashboard.get_summary().await.unwrap();

        // Verify summary structure
        assert!(summary.total_sessions > 0);
        assert!(summary.memory_stats.avg_memory_usage >= 0.0);
        assert!(summary.memory_stats.max_memory_usage >= 0);

        let _ = std::fs::remove_dir_all(&dir);
    });
}

#[test]
fn test_config_validation_warnings() {
    let dir = std::env::temp_dir().join("runsafety-test-config-validation");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let manager = ConfigManager::new(&dir);

    // Validate empty config dir
    let warnings = manager.validate_config().unwrap();
    assert!(!warnings.is_empty()); // Should have warnings about missing files

    // Check warning messages
    assert!(warnings.iter().any(|w| w.contains("agent.toml")));
    assert!(warnings.iter().any(|w| w.contains("security-rules.toml")));

    let _ = std::fs::remove_dir_all(&dir);
}
