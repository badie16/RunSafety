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
    }
}
