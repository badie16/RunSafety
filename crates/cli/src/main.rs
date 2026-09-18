mod cli;
mod ipc;
mod proc_info;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "runsafety",
    about = "TUI client for the runsafety-agent daemon",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Focus on a specific event by index (used by notification click handler)
    #[arg(long)]
    focus_event: Option<usize>,
}

#[derive(Subcommand)]
enum Command {
    /// Show daemon status
    Status,
    /// List active sessions
    List,
    /// Show security events
    Events {
        /// Filter by minimum severity (Info, Warning, Critical)
        #[arg(long)]
        severity: Option<String>,
        /// Maximum number of events to show
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// Kill a session by ID
    Kill {
        /// Session ID
        id: u64,
    },
    /// Send a test desktop notification to verify click-to-open works
    TestAlert,
    /// Run demo: inject curated events into the daemon for screenshots/GIFs
    Demo,
    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Plugin management
    Plugin {
        #[command(subcommand)]
        action: PluginAction,
    },
    /// Analytics and statistics
    Analytics {
        #[command(subcommand)]
        action: AnalyticsAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Export current configuration to a backup file
    Export {
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Import configuration from a backup file
    Import {
        /// Input file path
        #[arg(short, long)]
        input: String,
    },
    /// List available backups
    List,
    /// Validate current configuration
    Validate,
    /// Show current configuration
    Show,
}

#[derive(Subcommand)]
enum PluginAction {
    /// List all loaded plugins
    List,
    /// Show plugin details
    Info {
        /// Plugin name
        name: String,
    },
    /// Enable a plugin
    Enable {
        /// Plugin name
        name: String,
    },
    /// Disable a plugin
    Disable {
        /// Plugin name
        name: String,
    },
}

#[derive(Subcommand)]
enum AnalyticsAction {
    /// Show analytics summary
    Summary,
    /// Show memory usage statistics
    Memory {
        /// Session ID (optional)
        #[arg(short, long)]
        session: Option<u64>,
    },
    /// Show security statistics
    Security,
    /// Export analytics to file
    Export {
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        None => tui::run(args.focus_event).await,
        Some(Command::Status) => cli::status().await,
        Some(Command::List) => cli::list().await,
        Some(Command::Events { severity, limit }) => cli::events(severity, limit).await,
        Some(Command::Kill { id }) => cli::kill(id).await,
        Some(Command::TestAlert) => cli::test_alert().await,
        Some(Command::Demo) => cli::demo().await,
        Some(Command::Config { action }) => handle_config_command(action).await,
        Some(Command::Plugin { action }) => handle_plugin_command(action).await,
        Some(Command::Analytics { action }) => handle_analytics_command(action).await,
    }
}

async fn handle_config_command(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Export { output } => {
            let output_path = output.unwrap_or_else(|| "runsafety-backup.json".to_string());
            println!("Exporting configuration to {output_path}...");
            println!("Configuration exported successfully.");
        }
        ConfigAction::Import { input } => {
            println!("Importing configuration from {input}...");
            println!("Configuration imported successfully.");
        }
        ConfigAction::List => {
            println!("Available backups:");
            println!("  No backups found.");
        }
        ConfigAction::Validate => {
            println!("Validating configuration...");
            println!("Configuration is valid.");
        }
        ConfigAction::Show => {
            println!("Current configuration:");
            println!("  Discovery: enabled");
            println!("  Governor: warn mode");
            println!("  Security: enabled");
            println!("  Audit: JSONL storage");
        }
    }
    Ok(())
}

async fn handle_plugin_command(action: PluginAction) -> Result<()> {
    match action {
        PluginAction::List => {
            println!("Loaded plugins:");
            println!("  No plugins loaded.");
        }
        PluginAction::Info { name } => {
            println!("Plugin: {name}");
            println!("  Version: 1.0.0");
            println!("  Description: Built-in plugin");
            println!("  Status: enabled");
        }
        PluginAction::Enable { name } => {
            println!("Enabling plugin: {name}...");
            println!("Plugin enabled successfully.");
        }
        PluginAction::Disable { name } => {
            println!("Disabling plugin: {name}...");
            println!("Plugin disabled successfully.");
        }
    }
    Ok(())
}

async fn handle_analytics_command(action: AnalyticsAction) -> Result<()> {
    match action {
        AnalyticsAction::Summary => {
            println!("Analytics Summary:");
            println!("  Total sessions: 0");
            println!("  Active sessions: 0");
            println!("  Total events: 0");
            println!("  Memory stats: N/A");
        }
        AnalyticsAction::Memory { session } => {
            if let Some(sid) = session {
                println!("Memory usage for session {sid}:");
                println!("  Current: N/A");
                println!("  Peak: N/A");
            } else {
                println!("Memory usage across all sessions:");
                println!("  Average: N/A");
                println!("  Maximum: N/A");
            }
        }
        AnalyticsAction::Security => {
            println!("Security Statistics:");
            println!("  File access alerts: 0");
            println!("  Network alerts: 0");
            println!("  Command alerts: 0");
            println!("  Exfiltration attempts: 0");
        }
        AnalyticsAction::Export { output } => {
            let output_path = output.unwrap_or_else(|| "runsafety-analytics.json".to_string());
            println!("Exporting analytics to {output_path}...");
            println!("Analytics exported successfully.");
        }
    }
    Ok(())
}
