mod alert;
mod alert_extended;
mod analytics;
mod audit;
mod audit_sqlite;
mod config;
mod config_manager;
mod daemon;
mod discovery;
mod governor;
mod ipc;
mod plugin;
mod security;

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use runsafety_shared::config::AgentConfig;
use runsafety_shared::types::{Session, SessionStatus, Severity, Signal};

#[cfg(target_os = "linux")]
use crate::discovery::{match_cli_type, LinuxScanner, ProcessScanner};
#[cfg(target_os = "macos")]
use crate::discovery::{match_cli_type, MacosScanner, ProcessScanner};
#[cfg(target_os = "windows")]
use crate::discovery::{match_cli_type, WindowsScanner, ProcessScanner};

#[derive(Parser)]
#[command(name = "runsafety-agent", about = "Guardian daemon for AI coding CLIs")]
struct Args {
    /// Run as background daemon
    #[arg(short, long)]
    daemon: bool,

    /// Config file path
    #[arg(short, long)]
    config: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let agent_config = config::load(args.config.as_deref())?;
    let paths = config::DaemonPaths::new();

    if daemon::check_running(&paths.pid_file)? {
        anyhow::bail!(
            "runsafety-agent already running (see {})",
            paths.pid_file.display()
        );
    }

    if args.daemon {
        daemon::daemonize()?;
    }

    daemon::write_pid_file(&paths.pid_file)?;

    tracing_subscriber::fmt().with_target(false).init();

    info!("runsafety-agent v{} starting", env!("CARGO_PKG_VERSION"));

    let rt = tokio::runtime::Runtime::new()?;
    let pid_file = paths.pid_file.clone();
    let result = rt.block_on(run(agent_config, paths));

    daemon::remove_pid_file(&pid_file);
    info!("runsafety-agent stopped");

    result
}

async fn run(config: AgentConfig, paths: config::DaemonPaths) -> Result<()> {
    let (tx, _rx) = broadcast::channel::<Signal>(1024);

    // Initialize analytics dashboard
    let analytics = Arc::new(analytics::AnalyticsDashboard::new(&paths.analytics_dir)?);
    info!("Analytics dashboard: {}", paths.analytics_dir.display());

    // Initialize plugin manager
    let plugin_manager = Arc::new(plugin::PluginManager::new(&paths.config_dir));
    plugin_manager.load_plugins().await?;
    let plugins = plugin_manager.list_plugins().await;
    info!("Loaded {} plugins", plugins.len());

    // Initialize config manager
    let _config_manager = config_manager::ConfigManager::new(&paths.config_dir);

    // Initialize alert notifier
    let alert_config = config.alerts.clone();
    let alert_notifier = Arc::new(alert_extended::AlertNotifier::new(&alert_config));

    // Spawn audit logger consumer (based on config storage type)
    let mut audit_rx = tx.subscribe();
    let audit_handle = match config.audit.storage {
        runsafety_shared::config::AuditStorage::Sqlite => {
            let mut audit_logger = audit_sqlite::SqliteAuditLogger::new(&paths.audit_dir)?;
            tokio::spawn(async move {
                loop {
                    match audit_rx.recv().await {
                        Ok(signal) => {
                            if let Err(e) = audit_logger.log_signal(&signal) {
                                error!("Audit log error: {e}");
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Audit logger lagged {n} events");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
        }
        runsafety_shared::config::AuditStorage::Jsonl => {
            let audit_logger = audit::AuditLogger::new(&paths.audit_dir)?;
            tokio::spawn(async move {
                loop {
                    match audit_rx.recv().await {
                        Ok(signal) => {
                            if let Err(e) = audit_logger.log_signal(&signal) {
                                error!("Audit log error: {e}");
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Audit logger lagged {n} events");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
        }
    };

    // Spawn analytics consumer (records all events)
    let mut analytics_rx = tx.subscribe();
    let analytics_clone = analytics.clone();
    let analytics_handle = tokio::spawn(async move {
        loop {
            match analytics_rx.recv().await {
                Ok(signal) => {
                    let (event_type, severity, details) = match &signal {
                        Signal::SessionDiscovered(s) => {
                            ("SessionDiscovered", Severity::Info, Some(format!("{} PID {}", s.cli_type, s.pid)))
                        }
                        Signal::SessionExited { cli_type, pid, .. } => {
                            ("SessionExited", Severity::Info, Some(format!("{cli_type} PID {pid}")))
                        }
                        Signal::MemoryWarning { cli_type, rss_bytes, .. } => {
                            ("MemoryWarning", Severity::Warning, Some(format!("{cli_type} {rss_bytes} bytes")))
                        }
                        Signal::MemoryUrgent { cli_type, rss_bytes, .. } => {
                            ("MemoryUrgent", Severity::Critical, Some(format!("{cli_type} {rss_bytes} bytes")))
                        }
                        Signal::OomKill { cli_type, .. } => {
                            ("OomKill", Severity::Critical, Some(format!("{cli_type} killed")))
                        }
                        Signal::LeakDetected { cli_type, rss_bytes, .. } => {
                            ("LeakDetected", Severity::Critical, Some(format!("{cli_type} {rss_bytes} bytes")))
                        }
                        Signal::SensitiveFileAccess { path, rule_name, severity, .. } => {
                            ("SensitiveFileAccess", severity.clone(), Some(format!("{rule_name}: {}", path.display())))
                        }
                        Signal::UnexpectedNetwork { remote_addr, remote_port, .. } => {
                            ("UnexpectedNetwork", Severity::Warning, Some(format!("{remote_addr}:{remote_port}")))
                        }
                        Signal::DangerousCommand { rule_name, matched_text, severity, .. } => {
                            ("DangerousCommand", severity.clone(), Some(format!("{rule_name}: {matched_text}")))
                        }
                        Signal::ExfilAttempt { file_path, remote_addr, .. } => {
                            ("ExfilAttempt", Severity::Critical, Some(format!("{} -> {remote_addr}", file_path.display())))
                        }
                        _ => continue,
                    };
                    if let Err(e) = analytics_clone.record_event(None, event_type, &severity, details.as_deref()).await {
                        error!("Analytics record error: {e}");
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Analytics lagged {n} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Spawn alert consumer (sends alerts for critical events)
    let mut alert_rx = tx.subscribe();
    let alert_notifier_clone = alert_notifier.clone();
    let alert_handle = tokio::spawn(async move {
        loop {
            match alert_rx.recv().await {
                Ok(signal) => {
                    if let Some(alert_msg) = alert_extended::AlertNotifier::create_alert_from_signal(&signal) {
                        if let Err(e) = alert_notifier_clone.send_alert(&alert_msg).await {
                            error!("Alert send error: {e}");
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Alert notifier lagged {n} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Spawn plugin consumer (notifies plugins of all signals)
    let mut plugin_rx = tx.subscribe();
    let plugin_manager_clone = plugin_manager.clone();
    let plugin_handle = tokio::spawn(async move {
        loop {
            match plugin_rx.recv().await {
                Ok(signal) => {
                    let _new_signals = plugin_manager_clone.notify_signal(&signal).await;
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Plugin manager lagged {n} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Spawn resource monitor (consumer + producer)
    let resource_rx = tx.subscribe();
    let resource_tx = tx.clone();
    let governor_config = config.governor.clone();
    let resource_handle = tokio::spawn(async move {
        governor::resource_monitor_loop(resource_rx, resource_tx, governor_config).await;
    });

    // Spawn security monitor (consumer + producer)
    let security_handle = if config.security.enabled {
        let rules_config = config::load_security_rules(None)?;
        let rules = security::rules::SecurityRules::load(&rules_config);
        let security_rx = tx.subscribe();
        let security_tx = tx.clone();
        let security_config = config.security.clone();
        info!(
            "Security monitor: scanning every {}s, exfil window {}s",
            security_config.scan_interval_secs, security_config.exfil_window_secs,
        );
        Some(tokio::spawn(async move {
            security::security_monitor_loop(security_rx, security_tx, security_config, rules).await;
        }))
    } else {
        info!("Security monitor: disabled");
        None
    };

    // Spawn IPC server
    let ipc_rx = tx.subscribe();
    #[cfg(not(target_os = "windows"))]
    let socket_path = paths.socket_path.clone();
    #[cfg(target_os = "windows")]
    let pipe_name = paths.pipe_name.clone();
    let ipc_handle = tokio::spawn(async move {
        #[cfg(not(target_os = "windows"))]
        if let Err(e) = ipc::ipc_server(&socket_path, ipc_rx).await {
            error!("IPC server error: {e}");
        }
        #[cfg(target_os = "windows")]
        if let Err(e) = ipc::ipc_server_named_pipe(&pipe_name, ipc_rx).await {
            error!("IPC server error: {e}");
        }
    });

    // Spawn discovery loop producer
    let discovery_tx = tx.clone();
    let discovery_config = config.discovery.clone();
    let governor_config_for_discovery = config.governor.clone();
    let discovery_handle = tokio::spawn(async move {
        discovery_loop(
            discovery_config,
            governor_config_for_discovery,
            discovery_tx,
        )
        .await;
    });

    info!(
        "Scanning for AI CLI processes every {}s",
        config.discovery.scan_interval_secs
    );
    info!(
        "Resource governor: mode={}, monitoring every {}s",
        match config.governor.action {
            runsafety_shared::config::GovernorAction::Warn => "warn",
            runsafety_shared::config::GovernorAction::Throttle => "throttle",
            runsafety_shared::config::GovernorAction::Kill => "kill",
        },
        config.governor.monitor_interval_secs,
    );
    info!("Audit log: {}", paths.audit_dir.display());
    #[cfg(not(target_os = "windows"))]
    info!("IPC socket: {}", paths.socket_path.display());
    #[cfg(target_os = "windows")]
    info!("IPC pipe: {}", paths.pipe_name);

    // Wait for shutdown or task failure
    tokio::select! {
        _ = daemon::shutdown_signal() => {
            info!("Shutdown signal received");
        }
        result = audit_handle => {
            error!("Audit logger exited unexpectedly: {result:?}");
        }
        result = analytics_handle => {
            error!("Analytics logger exited unexpectedly: {result:?}");
        }
        result = alert_handle => {
            error!("Alert notifier exited unexpectedly: {result:?}");
        }
        result = plugin_handle => {
            error!("Plugin manager exited unexpectedly: {result:?}");
        }
        result = resource_handle => {
            error!("Resource monitor exited unexpectedly: {result:?}");
        }
        result = discovery_handle => {
            error!("Discovery loop exited unexpectedly: {result:?}");
        }
        result = ipc_handle => {
            error!("IPC server exited unexpectedly: {result:?}");
        }
        result = async {
            match security_handle {
                Some(h) => h.await,
                None => std::future::pending().await,
            }
        } => {
            error!("Security monitor exited unexpectedly: {result:?}");
        }
    }

    // Cleanup on shutdown
    plugin_manager.cleanup().await;
    let export_path = paths.analytics_dir.join("export.json");
    if let Err(e) = analytics.export_analytics(&export_path).await {
        error!("Failed to export analytics on shutdown: {e}");
    }
    info!("Analytics exported to {}", export_path.display());

    Ok(())
}

async fn discovery_loop(
    config: runsafety_shared::config::DiscoveryConfig,
    governor_config: runsafety_shared::config::GovernorConfig,
    tx: broadcast::Sender<Signal>,
) {
    #[cfg(target_os = "linux")]
    let scanner = LinuxScanner;
    #[cfg(target_os = "macos")]
    let scanner = MacosScanner;
    #[cfg(target_os = "windows")]
    let scanner = WindowsScanner;
    let patterns = &config.cli;
    let my_pid = std::process::id();
    let mut known: HashMap<u32, Session> = HashMap::new();
    let mut next_id: u64 = 1;

    let mut interval = tokio::time::interval(Duration::from_secs(config.scan_interval_secs));

    loop {
        interval.tick().await;

        let processes = match scanner.scan() {
            Ok(p) => p,
            Err(e) => {
                error!("Discovery scan failed: {e}");
                continue;
            }
        };

        let mut matches: Vec<(u32, runsafety_shared::types::CliType, PathBuf, Vec<String>)> =
            Vec::new();
        for proc in &processes {
            if proc.pid == my_pid || known.contains_key(&proc.pid) {
                continue;
            }
            if let Some(cli_type) = match_cli_type(&proc.cmdline_args, patterns) {
                matches.push((
                    proc.pid,
                    cli_type,
                    proc.cwd.clone(),
                    proc.cmdline_args.clone(),
                ));
            }
        }
        matches.sort_by_key(|(pid, _, _, _)| *pid);

        for (pid, cli_type, cwd, cmdline_args) in matches {
            if is_child_of_tracked(pid, &known) {
                continue;
            }
            let limits = governor::resolve_limits(&cli_type, &governor_config);
            let session = Session {
                id: next_id,
                pid,
                cli_type: cli_type.clone(),
                status: SessionStatus::Running,
                working_dir: cwd.clone(),
                started_at: unix_timestamp(),
                memory_high: Some(limits.memory_high),
                memory_max: limits.memory_max,
                cmdline: cmdline_args,
            };
            next_id += 1;

            info!(
                "Discovered: {} (PID {}) in {}",
                cli_type,
                pid,
                cwd.display()
            );
            let _ = tx.send(Signal::SessionDiscovered(session.clone()));
            known.insert(pid, session);
        }

        let exited_pids: Vec<u32> = known
            .keys()
            .filter(|pid| !is_process_alive(**pid))
            .copied()
            .collect();

        for pid in exited_pids {
            if let Some(session) = known.remove(&pid) {
                info!("Session exited: {} (PID {})", session.cli_type, pid);
                let _ = tx.send(Signal::SessionExited {
                    id: session.id,
                    pid,
                    cli_type: session.cli_type,
                });
            }
        }
    }
}

/// Walk up the process tree to check if `pid` is a descendant of any tracked session.
fn is_child_of_tracked(pid: u32, known: &HashMap<u32, Session>) -> bool {
    let mut current = pid;
    for _ in 0..32 {
        match security::process_monitor::read_ppid(current) {
            Some(ppid) if ppid > 1 => {
                if known.contains_key(&ppid) {
                    return true;
                }
                current = ppid;
            }
            _ => return false,
        }
    }
    false
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(target_os = "linux")]
fn is_process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(target_os = "macos")]
fn is_process_alive(pid: u32) -> bool {
    use nix::errno::Errno;
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None) {
        Ok(()) => true,
        Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}
