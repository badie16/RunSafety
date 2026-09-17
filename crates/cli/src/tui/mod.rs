mod render;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEvent, KeyModifiers,
    MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::Terminal;
use tokio::sync::mpsc;

use runsafety_shared::config::{AgentConfig, SecurityRulesConfig};
use runsafety_shared::protocol::{EventNotification, SessionInfo};
use runsafety_shared::types::Signal;

use crate::ipc::IpcClient;
use crate::proc_info;

const HISTORY_CAP: usize = 60;
const ENDED_SESSION_TTL: Duration = Duration::from_secs(3600); // 1 hour
const MAX_ENDED_SESSIONS: usize = 20;

pub struct EndedSession {
    pub info: SessionInfo,
    pub ended_at: Instant,
}

/// Items returned by `filtered_sessions_with_ended` for rendering.
pub enum SessionItem<'a> {
    Active(&'a SessionInfo),
    Separator,
    Ended(&'a SessionInfo),
}

#[derive(Clone, Copy, PartialEq)]
pub enum DetailTab {
    Events,
    Resources,
    Info,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ActivePane {
    Sessions,
    Events,
    EventDetail,
}

pub struct App {
    pub detail_tab: DetailTab,
    pub sessions: Vec<SessionInfo>,
    pub events: Vec<EventEntry>,
    pub selected: usize,
    pub event_scroll: usize,
    pub filter_text: String,
    pub editing_filter: bool,
    pub show_help: bool,
    pub show_settings: bool,
    pub confirm_kill: Option<u64>,
    pub status_msg: Option<(String, Instant)>,
    pub cpu_tracker: CpuTracker,
    pub cpu_percents: HashMap<u32, f32>,
    pub first_seen: HashMap<u64, Instant>, // session_id -> when TUI first saw it
    pub rss_history: HashMap<u32, VecDeque<u64>>,
    pub cpu_history: HashMap<u32, VecDeque<u64>>,
    pub connected_at: Instant,
    pub ended_sessions: Vec<EndedSession>,
    pub agent_config: Option<AgentConfig>,
    pub security_rules: Option<SecurityRulesConfig>,
    pub quit: bool,
    // Settings editor state
    pub settings_cursor: usize,
    pub settings_editing: bool,
    pub settings_edit_buf: String,
    pub settings_fields: Vec<SettingsField>,
    pub daemon_pid: Option<u32>,
    // Event detail panel
    pub event_detail: Option<EventDetail>,
    // Which pane has focus (for border highlighting and key routing)
    pub active_pane: ActivePane,
    // Layout areas for mouse hit-testing (set each frame by render)
    pub layout: LayoutAreas,
}

/// Stores layout rectangles from the last render for mouse hit-testing.
#[derive(Default, Clone)]
pub struct LayoutAreas {
    pub session_list: Rect,
    pub detail_pane: Rect,
    pub events_list_area: Rect,
    pub event_detail_pane: Rect,
    pub header: Rect,
    // Tab label positions in header (x-start, x-end, tab)
    pub tab_regions: Vec<(u16, u16, DetailTab)>,
    // Action button positions in event detail (x-start, x-end, row, action_index)
    pub action_buttons: Vec<(u16, u16, u16, usize)>,
}

pub struct EventDetail {
    pub event_idx: usize,
    pub explanation: String,
    pub extra_info: Vec<(String, String)>, // label, value pairs
    pub selected_action: usize,
    pub dns_result: Option<String>,
}

#[derive(Clone)]
pub struct SettingsField {
    pub label: String,
    pub value: String,
    pub kind: SettingsFieldKind,
}

#[derive(Clone, PartialEq)]
pub enum SettingsFieldKind {
    GovernorMode,        // cycle: warn/throttle/kill
    Threshold,           // float 0.0-1.0
    MemorySize,          // string like "3GB"
    NetworkEntry(usize), // index into network_allow
    ReadOnly,
}

pub struct EventEntry {
    pub timestamp: u64,
    pub severity: EventSeverity,
    pub cli_type: String,
    pub pid: u32,
    pub session_id: u64,
    pub description: String,
    // Raw data for detail panel
    pub raw_signal: SignalSummary,
}

/// Extracted fields from Signal for the detail panel, avoiding lifetime issues.
#[derive(Clone)]
pub enum SignalSummary {
    SessionStarted {
        working_dir: String,
    },
    SessionExited,
    MemoryWarning {
        rss_bytes: u64,
        high_bytes: u64,
    },
    MemoryUrgent {
        rss_bytes: u64,
        high_bytes: u64,
    },
    LeakDetected {
        rss_bytes: u64,
        duration_secs: u64,
    },
    OomKill {
        peak_rss_bytes: u64,
    },
    SensitiveFileAccess {
        path: String,
        known_safe: Option<String>,
    },
    BoundaryViolation {
        path: String,
    },
    UnexpectedNetwork {
        remote_addr: String,
        remote_port: u16,
    },
    DangerousCommand {
        matched_text: String,
    },
    SuspiciousChild {
        child_cmdline: String,
    },
    ExfilAttempt {
        file_path: String,
        remote_addr: String,
    },
}

#[derive(Clone, Copy, PartialEq)]
pub enum EventSeverity {
    Info,
    Warning,
    Critical,
}

pub struct CpuTracker {
    prev: HashMap<u32, (u64, Instant)>,
}

impl CpuTracker {
    fn new() -> Self {
        Self {
            prev: HashMap::new(),
        }
    }

    fn update(&mut self, pid: u32) -> Option<f32> {
        let ticks = proc_info::read_cpu_ticks(pid)?;
        let now = Instant::now();
        let result = if let Some((prev_ticks, prev_time)) = self.prev.get(&pid) {
            let elapsed = now.duration_since(*prev_time).as_secs_f32();
            if elapsed > 0.5 {
                let delta = ticks.saturating_sub(*prev_ticks) as f32;
                Some((delta / (elapsed * 100.0)) * 100.0) // CLK_TCK=100
            } else {
                None
            }
        } else {
            None
        };
        self.prev.insert(pid, (ticks, now));
        result
    }

    fn remove_stale(&mut self, active_pids: &[u32]) {
        self.prev.retain(|pid, _| active_pids.contains(pid));
    }
}

impl App {
    fn new() -> Self {
        let (agent_config, security_rules) = load_display_config();
        let settings_fields = build_settings_fields(&agent_config, &security_rules);
        let daemon_pid = find_daemon_pid();
        Self {
            detail_tab: DetailTab::Events,
            sessions: Vec::new(),
            events: Vec::new(),
            selected: 0,
            event_scroll: 0,
            filter_text: String::new(),
            editing_filter: false,
            show_help: false,
            show_settings: false,
            confirm_kill: None,
            status_msg: None,
            cpu_tracker: CpuTracker::new(),
            cpu_percents: HashMap::new(),
            first_seen: HashMap::new(),
            rss_history: HashMap::new(),
            cpu_history: HashMap::new(),
            connected_at: Instant::now(),
            ended_sessions: Vec::new(),
            agent_config,
            security_rules,
            quit: false,
            settings_cursor: 0,
            settings_editing: false,
            settings_edit_buf: String::new(),
            settings_fields,
            daemon_pid,
            event_detail: None,
            active_pane: ActivePane::Sessions,
            layout: LayoutAreas::default(),
        }
    }

    pub fn filtered_sessions(&self) -> Vec<&SessionInfo> {
        if self.filter_text.is_empty() {
            self.sessions.iter().collect()
        } else {
            let f = self.filter_text.to_lowercase();
            self.sessions
                .iter()
                .filter(|s| {
                    s.cli_type.to_lowercase().contains(&f)
                        || s.working_dir.to_lowercase().contains(&f)
                })
                .collect()
        }
    }

    /// Active sessions + separator + ended sessions for rendering.
    pub fn session_items(&self) -> Vec<SessionItem<'_>> {
        let f = self.filter_text.to_lowercase();
        let active: Vec<&SessionInfo> = if f.is_empty() {
            self.sessions.iter().collect()
        } else {
            self.sessions
                .iter()
                .filter(|s| {
                    s.cli_type.to_lowercase().contains(&f)
                        || s.working_dir.to_lowercase().contains(&f)
                })
                .collect()
        };
        let ended: Vec<&SessionInfo> = if f.is_empty() {
            self.ended_sessions.iter().map(|e| &e.info).collect()
        } else {
            self.ended_sessions
                .iter()
                .filter(|e| {
                    e.info.cli_type.to_lowercase().contains(&f)
                        || e.info.working_dir.to_lowercase().contains(&f)
                })
                .map(|e| &e.info)
                .collect()
        };

        let mut items: Vec<SessionItem<'_>> = Vec::new();
        for s in &active {
            items.push(SessionItem::Active(s));
        }
        if !ended.is_empty() {
            items.push(SessionItem::Separator);
            for s in &ended {
                items.push(SessionItem::Ended(s));
            }
        }
        items
    }

    /// Total number of selectable sessions (active + ended, excluding separator).
    pub fn selectable_count(&self) -> usize {
        let active = self.filtered_sessions().len();
        let ended_f: usize = if self.filter_text.is_empty() {
            self.ended_sessions.len()
        } else {
            let f = self.filter_text.to_lowercase();
            self.ended_sessions
                .iter()
                .filter(|e| {
                    e.info.cli_type.to_lowercase().contains(&f)
                        || e.info.working_dir.to_lowercase().contains(&f)
                })
                .count()
        };
        active + ended_f
    }

    /// Get the SessionInfo at the given selectable index (active first, then ended).
    pub fn session_at(&self, idx: usize) -> Option<&SessionInfo> {
        let active = self.filtered_sessions();
        if idx < active.len() {
            return Some(active[idx]);
        }
        let ended_idx = idx - active.len();
        let ended: Vec<&SessionInfo> = if self.filter_text.is_empty() {
            self.ended_sessions.iter().map(|e| &e.info).collect()
        } else {
            let f = self.filter_text.to_lowercase();
            self.ended_sessions
                .iter()
                .filter(|e| {
                    e.info.cli_type.to_lowercase().contains(&f)
                        || e.info.working_dir.to_lowercase().contains(&f)
                })
                .map(|e| &e.info)
                .collect()
        };
        ended.get(ended_idx).copied()
    }

    /// Events for the currently selected session.
    pub fn selected_session_events(&self) -> Vec<&EventEntry> {
        let sid = self.session_at(self.selected).map(|s| s.id);
        match sid {
            Some(id) => self.events.iter().filter(|e| e.session_id == id).collect(),
            None => Vec::new(),
        }
    }

    /// The currently selected session, if any.
    pub fn selected_session(&self) -> Option<&SessionInfo> {
        self.session_at(self.selected)
    }

    /// Returns true if this session was discovered less than 5 seconds ago.
    pub fn is_measuring(&self, session_id: u64) -> bool {
        self.first_seen
            .get(&session_id)
            .map(|t| t.elapsed() < Duration::from_secs(5))
            .unwrap_or(false)
    }

    fn set_status(&mut self, msg: String) {
        self.status_msg = Some((msg, Instant::now()));
    }

    fn open_event_detail(&mut self) {
        let events = self.selected_session_events();
        if events.is_empty() {
            return;
        }
        // Toggle: if detail is already open, close it
        if self.event_detail.is_some() {
            self.event_detail = None;
            return;
        }
        self.refresh_event_detail();
    }

    /// Rebuild event detail from current event_scroll position without toggling.
    fn refresh_event_detail(&mut self) {
        let events = self.selected_session_events();
        if events.is_empty() {
            self.event_detail = None;
            return;
        }
        // Events are displayed reversed, so map scroll position
        let rev_idx = self.event_scroll;
        let actual_idx = events.len().saturating_sub(1).saturating_sub(rev_idx);
        if let Some(event) = events.get(actual_idx) {
            let (explanation, extra_info) = build_event_explanation(event);
            let dns_result = try_reverse_dns(&event.raw_signal);
            self.event_detail = Some(EventDetail {
                event_idx: actual_idx,
                explanation,
                extra_info,
                selected_action: 0,
                dns_result,
            });
        }
    }
}

// --- Event detail helpers ---

const EVENT_ACTIONS: &[(&str, &str)] = &[
    ("a", "Allow"),
    ("b", "Block"),
    ("i", "Investigate"),
    ("l", "View log"),
    ("c", "Copy"),
    ("x", "Close detail"),
];

fn build_event_explanation(event: &EventEntry) -> (String, Vec<(String, String)>) {
    let mut info = vec![
        ("Tool".to_string(), event.cli_type.clone()),
        ("Process ID".to_string(), event.pid.to_string()),
        (
            "Time".to_string(),
            crate::cli::format_timestamp(event.timestamp),
        ),
    ];

    let explanation = match &event.raw_signal {
        SignalSummary::SessionStarted { working_dir } => {
            info.push(("Directory".to_string(), working_dir.clone()));
            "A new AI coding session was detected and is now being monitored.".to_string()
        }
        SignalSummary::SessionExited => "The AI coding session ended normally.".to_string(),
        SignalSummary::MemoryWarning {
            rss_bytes,
            high_bytes,
        } => {
            info.push((
                "Current memory".to_string(),
                crate::cli::format_bytes(Some(*rss_bytes)),
            ));
            info.push((
                "Soft limit".to_string(),
                crate::cli::format_bytes(Some(*high_bytes)),
            ));
            let pct = (*rss_bytes as f64 / *high_bytes as f64 * 100.0) as u64;
            format!(
                "Memory usage is at {pct}% of the soft limit. \
                 The tool is using more memory than expected. \
                 If it keeps growing, the system will start throttling it."
            )
        }
        SignalSummary::MemoryUrgent {
            rss_bytes,
            high_bytes,
        } => {
            info.push((
                "Current memory".to_string(),
                crate::cli::format_bytes(Some(*rss_bytes)),
            ));
            info.push((
                "Soft limit".to_string(),
                crate::cli::format_bytes(Some(*high_bytes)),
            ));
            "Memory usage is critically high. The system is actively throttling this tool. \
             Save your work - the tool may become slow or unresponsive."
                .to_string()
        }
        SignalSummary::LeakDetected {
            rss_bytes,
            duration_secs,
        } => {
            info.push((
                "Current memory".to_string(),
                crate::cli::format_bytes(Some(*rss_bytes)),
            ));
            info.push(("Growing for".to_string(), format!("{duration_secs}s")));
            "Memory has been steadily increasing, which usually means a memory leak. \
             The tool is not releasing memory it no longer needs. \
             Consider restarting it before it consumes too much."
                .to_string()
        }
        SignalSummary::OomKill { peak_rss_bytes } => {
            info.push((
                "Peak memory".to_string(),
                crate::cli::format_bytes(Some(*peak_rss_bytes)),
            ));
            "The tool was killed by the system because it exceeded its hard memory limit. \
             Your work should be saved, but the tool needs to be restarted."
                .to_string()
        }
        SignalSummary::SensitiveFileAccess { path, known_safe } => {
            info.push(("File".to_string(), path.clone()));
            if let Some(safe_msg) = known_safe {
                safe_msg.clone()
            } else {
                format!(
                    "The tool accessed a sensitive file. This might be expected (reading config) \
                     or suspicious (reading credentials). Check whether {} is something this \
                     tool needs for its current task.",
                    path
                )
            }
        }
        SignalSummary::BoundaryViolation { path } => {
            info.push(("Path".to_string(), path.clone()));
            "The tool tried to access a file outside its allowed working directory. \
             This is often a sign the tool is trying to read or modify something it shouldn't."
                .to_string()
        }
        SignalSummary::UnexpectedNetwork {
            remote_addr,
            remote_port,
        } => {
            info.push(("Address".to_string(), remote_addr.clone()));
            info.push(("Port".to_string(), port_context(*remote_port)));
            format!(
                "The tool connected to {remote_addr} on port {remote_port}. \
                 {} \
                 If this address is not in your allowlist, it could be API traffic \
                 that Runsafety doesn't recognize, or something unexpected.",
                port_explanation(*remote_port)
            )
        }
        SignalSummary::DangerousCommand { matched_text } => {
            info.push(("Command".to_string(), matched_text.clone()));
            "A command matching a dangerous pattern was detected. \
             This could be a legitimate build step or something harmful. \
             Review what the tool was trying to do."
                .to_string()
        }
        SignalSummary::SuspiciousChild { child_cmdline } => {
            info.push(("Child process".to_string(), child_cmdline.clone()));
            "The tool spawned a child process that looks unusual. \
             AI coding tools sometimes run shells or compilers, but unexpected \
             processes could indicate the tool is doing something unintended."
                .to_string()
        }
        SignalSummary::ExfilAttempt {
            file_path,
            remote_addr,
        } => {
            info.push(("File".to_string(), file_path.clone()));
            info.push(("Destination".to_string(), remote_addr.clone()));
            format!(
                "A file was read shortly before a network connection was made to {remote_addr}. \
                 This pattern can indicate data exfiltration - the tool may be sending \
                 the contents of {} to an external server. Investigate immediately.",
                file_path
            )
        }
    };

    (explanation, info)
}

fn port_context(port: u16) -> String {
    let label = match port {
        22 => "SSH (remote shell)",
        80 => "HTTP (unencrypted web)",
        443 => "HTTPS (encrypted web/API)",
        8080 | 8443 => "HTTP alt (dev server or proxy)",
        53 => "DNS (name resolution)",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        _ => return format!("{port} (unknown service)"),
    };
    format!("{port} ({label})")
}

fn port_explanation(port: u16) -> String {
    match port {
        443 => "Port 443 is HTTPS, likely API traffic.".to_string(),
        80 => "Port 80 is unencrypted HTTP, which is unusual for API calls.".to_string(),
        22 => "Port 22 is SSH. The tool should not be making SSH connections.".to_string(),
        _ => format!("Port {port} is not a standard web port."),
    }
}

fn try_reverse_dns(signal: &SignalSummary) -> Option<String> {
    let addr = match signal {
        SignalSummary::UnexpectedNetwork {
            remote_addr,
            remote_port,
        } => {
            format!("{remote_addr}:{remote_port}")
        }
        SignalSummary::ExfilAttempt { remote_addr, .. } => {
            format!("{remote_addr}:443")
        }
        _ => return None,
    };
    // Best-effort reverse DNS
    match addr.to_socket_addrs() {
        Ok(_) => {
            // to_socket_addrs doesn't do reverse DNS. Use std::net for forward check.
            // For actual reverse DNS we'd need dns-lookup crate. Show the raw IP.
            None
        }
        Err(_) => None,
    }
}

fn execute_event_action(app: &mut App, action_key: &str) {
    let detail = match &app.event_detail {
        Some(d) => d,
        None => return,
    };

    let events = app.selected_session_events();
    let event = match events.get(detail.event_idx) {
        Some(e) => *e,
        None => return,
    };

    match action_key {
        "a" => {
            // Allow: add to allowlist
            match &event.raw_signal {
                SignalSummary::UnexpectedNetwork { remote_addr, .. } => {
                    if add_to_network_allowlist(remote_addr) {
                        app.set_status(format!("Added {remote_addr} to network allowlist"));
                        signal_daemon_reload(app.daemon_pid);
                    } else {
                        app.set_status("Failed to update allowlist".into());
                    }
                }
                SignalSummary::SensitiveFileAccess { path, .. }
                | SignalSummary::BoundaryViolation { path } => {
                    app.set_status(format!(
                        "Would add {path} to file allowlist (not yet implemented)"
                    ));
                }
                _ => {
                    app.set_status("Allow not applicable for this event type".into());
                }
            }
            app.event_detail = None;
        }
        "b" => {
            // Block: kill the connection/process
            if let Some(session) = app.sessions.iter().find(|s| s.pid == event.pid) {
                let pid = nix::unistd::Pid::from_raw(session.pid as i32);
                match nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM) {
                    Ok(_) => app.set_status(format!(
                        "Sent stop signal to {} (PID {})",
                        event.cli_type, event.pid
                    )),
                    Err(e) => app.set_status(format!("Block failed: {e}")),
                }
            }
            app.event_detail = None;
        }
        "i" => {
            // Investigate: launch AI CLI with context prompt
            investigate_event(event);
            app.set_status("Launched investigation in new terminal".into());
            app.event_detail = None;
        }
        "l" => {
            // View log: open audit log
            view_audit_log();
            app.set_status("Opened audit log".into());
            app.event_detail = None;
        }
        "c" => {
            // Copy event text to clipboard
            let detail = match &app.event_detail {
                Some(d) => d,
                None => return,
            };
            let mut text = format!("{}\n\n{}\n", event.description, detail.explanation);
            for (label, value) in &detail.extra_info {
                text.push_str(&format!("{label}: {value}\n"));
            }
            copy_to_clipboard(&text);
            app.set_status("Event copied to clipboard".into());
        }
        "x" => {
            app.event_detail = None;
        }
        _ => {}
    }
}

fn add_to_network_allowlist(addr: &str) -> bool {
    let config_dir = match dirs::config_dir() {
        Some(d) => d.join("runsafety"),
        None => return false,
    };
    let rules_path = config_dir.join("security-rules.toml");
    let mut rules: SecurityRulesConfig = std::fs::read_to_string(&rules_path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default();

    // Add to "User allowed" group or create it
    let group = rules
        .network_allow
        .iter_mut()
        .find(|g| g.name == "User allowed");
    if let Some(group) = group {
        if !group.hosts.contains(&addr.to_string()) {
            group.hosts.push(addr.to_string());
        }
    } else {
        rules
            .network_allow
            .push(runsafety_shared::config::NetworkAllowEntry {
                name: "User allowed".to_string(),
                hosts: vec![addr.to_string()],
            });
    }

    match toml::to_string_pretty(&rules) {
        Ok(s) => std::fs::write(&rules_path, s).is_ok(),
        Err(_) => false,
    }
}

fn investigate_event(event: &EventEntry) {
    let ts = crate::cli::format_timestamp(event.timestamp);
    // Sanitize description: collapse newlines and control chars to spaces
    let clean_desc = event
        .description
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>();
    let clean_desc = clean_desc.split_whitespace().collect::<Vec<_>>().join(" ");

    let prompt = format!(
        "Runsafety detected: {clean_desc} from {} (PID {}) at {ts}. \
         Is this expected? What should I do?",
        event.cli_type, event.pid
    );

    // Try each AI CLI with full path resolution.
    // Use interactive mode so the user can follow up. Add "read" fallback
    // so the terminal stays open if the CLI exits immediately.
    let cli_specs: &[(&str, &[&str])] = &[("claude", &[]), ("codex", &[]), ("gemini", &[])];

    let shell_safe_prompt = prompt.replace('\'', "'\\''");

    for (name, extra_args) in cli_specs {
        if let Some(bin_path) = find_cli_binary(name) {
            let mut cmd = format!("'{bin_path}'");
            for arg in *extra_args {
                cmd.push_str(&format!(" '{arg}'"));
            }
            cmd.push_str(&format!(" '{shell_safe_prompt}'"));
            // Keep terminal open after CLI exits
            cmd.push_str("; echo; read -p 'Press Enter to close'");
            spawn_in_terminal(&cmd);
            return;
        }
    }

    // Fallback: just open a shell with the prompt printed
    spawn_in_terminal(&format!(
        "echo '{shell_safe_prompt}'; echo; read -p 'Press Enter to close'"
    ));
}

/// Find a CLI binary by checking common install paths, then falling back to
/// `which`. AI coding tools often install to user-local paths that aren't in
/// the daemon's PATH.
fn find_cli_binary(name: &str) -> Option<String> {
    let home = std::env::var("HOME").unwrap_or_default();

    // Common install locations for AI coding CLIs
    let candidate_dirs = [
        format!("{home}/.local/bin"),
        format!("{home}/.claude/local"),
        format!("{home}/.nvm/versions/node"), // npm global, checked below
        "/usr/local/bin".to_string(),
        "/usr/bin".to_string(),
    ];

    for dir in &candidate_dirs {
        let path = format!("{dir}/{name}");
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }

    // Check npm global bin (nvm installs vary)
    if let Ok(output) = std::process::Command::new("bash")
        .args(["-lc", &format!("which {name}")])
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() && std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }
    }

    // Plain which (may not find user-local installs)
    if which_exists(name) {
        return Some(name.to_string());
    }

    None
}

#[allow(clippy::needless_return)]
fn copy_to_clipboard(text: &str) {
    // macOS: use pbcopy
    #[cfg(target_os = "macos")]
    {
        if let Ok(mut child) = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(stdin) = child.stdin.as_mut() {
                use std::io::Write;
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
            return;
        }
    }

    // Linux: try wl-copy (Wayland) first, then xclip (X11)
    #[cfg(not(target_os = "macos"))]
    {
        let wayland = std::env::var("WAYLAND_DISPLAY").is_ok();
        if wayland {
            if let Ok(mut child) = std::process::Command::new("wl-copy")
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                if let Some(stdin) = child.stdin.as_mut() {
                    use std::io::Write;
                    let _ = stdin.write_all(text.as_bytes());
                }
                let _ = child.wait();
                return;
            }
        }
        if let Ok(mut child) = std::process::Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(stdin) = child.stdin.as_mut() {
                use std::io::Write;
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }
}

fn which_exists(name: &str) -> bool {
    std::process::Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Detected terminal emulator with its capabilities.
struct TerminalInfo {
    name: String,
    /// Whether this terminal supports opening a new tab in an existing instance.
    supports_tab_reuse: bool,
}

fn detect_terminal() -> TerminalInfo {
    // Prefer the terminal the user is actually running (TERM_PROGRAM env var)
    if let Ok(term_prog) = std::env::var("TERM_PROGRAM") {
        let lower = term_prog.to_lowercase();
        if lower.contains("ghostty") && which_exists("ghostty") {
            return TerminalInfo {
                name: "ghostty".to_string(),
                supports_tab_reuse: true,
            };
        }
        // Map other common TERM_PROGRAM values
        let known = [
            ("kitty", "kitty"),
            ("alacritty", "alacritty"),
            ("wezterm", "wezterm"),
        ];
        for (pattern, bin) in known {
            if lower.contains(pattern) && which_exists(bin) {
                return TerminalInfo {
                    name: bin.to_string(),
                    supports_tab_reuse: false,
                };
            }
        }
    }

    // Fallback: probe installed terminals, prefer ghostty
    for term in [
        "ghostty",
        "kitty",
        "alacritty",
        "wezterm",
        "gnome-terminal",
        "konsole",
        "xterm",
    ] {
        if which_exists(term) {
            return TerminalInfo {
                name: term.to_string(),
                supports_tab_reuse: term == "ghostty",
            };
        }
    }
    TerminalInfo {
        name: "xterm".to_string(),
        supports_tab_reuse: false,
    }
}

/// Spawn a shell command in the user's terminal.
/// For ghostty: uses --gtk-single-instance=true to open as a new tab in
/// the existing window instead of spawning a separate window.
fn spawn_in_terminal(shell_cmd: &str) {
    let term = detect_terminal();
    if term.supports_tab_reuse && term.name == "ghostty" {
        let _ = std::process::Command::new(&term.name)
            .arg("--gtk-single-instance=true")
            .arg("-e")
            .arg("bash")
            .arg("-c")
            .arg(shell_cmd)
            .spawn();
    } else {
        let _ = std::process::Command::new(&term.name)
            .arg("-e")
            .arg("bash")
            .arg("-c")
            .arg(shell_cmd)
            .spawn();
    }
}

/// Spawn a direct command (no shell wrapper) in the user's terminal.
fn spawn_direct_in_terminal(args: &[&str]) {
    let term = detect_terminal();
    let mut cmd = std::process::Command::new(&term.name);
    if term.supports_tab_reuse && term.name == "ghostty" {
        cmd.arg("--gtk-single-instance=true");
    }
    cmd.arg("-e");
    for arg in args {
        cmd.arg(arg);
    }
    let _ = cmd.spawn();
}

fn view_audit_log() {
    let data_dir = dirs::data_dir().unwrap_or_default().join("runsafety/audit");
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "less".to_string());

    // Find today's log file
    let today = chrono_free_today();
    let log_file = data_dir.join(format!("{today}.jsonl"));
    let path = if log_file.exists() {
        log_file
    } else {
        data_dir
    };

    let path_str = path.to_string_lossy().to_string();
    spawn_direct_in_terminal(&[&editor, &path_str]);
}

fn chrono_free_today() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    // Simple date calculation
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let year_days = if is_leap(y) { 366 } else { 365 };
        if remaining < year_days {
            break;
        }
        remaining -= year_days;
        y += 1;
    }
    let month_days = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md {
            m = i;
            break;
        }
        remaining -= md;
    }
    format!("{y:04}-{:02}-{:02}", m + 1, remaining + 1)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// --- Settings helpers ---

fn build_settings_fields(
    agent_config: &Option<AgentConfig>,
    security_rules: &Option<SecurityRulesConfig>,
) -> Vec<SettingsField> {
    let mut fields = Vec::new();

    if let Some(cfg) = agent_config {
        let mode_str = match cfg.governor.action {
            runsafety_shared::config::GovernorAction::Warn => "warn",
            runsafety_shared::config::GovernorAction::Throttle => "throttle",
            runsafety_shared::config::GovernorAction::Kill => "kill",
        };
        fields.push(SettingsField {
            label: "Governor Mode".into(),
            value: mode_str.into(),
            kind: SettingsFieldKind::GovernorMode,
        });
        fields.push(SettingsField {
            label: "Warn Threshold".into(),
            value: format!("{:.0}%", cfg.governor.warn_threshold * 100.0),
            kind: SettingsFieldKind::Threshold,
        });
        fields.push(SettingsField {
            label: "Urgent Threshold".into(),
            value: format!("{:.0}%", cfg.governor.urgent_threshold * 100.0),
            kind: SettingsFieldKind::Threshold,
        });

        for (cli, limits) in &cfg.governor.cli {
            fields.push(SettingsField {
                label: format!("{cli} memory_high"),
                value: limits.memory_high.clone().unwrap_or_else(|| "--".into()),
                kind: SettingsFieldKind::MemorySize,
            });
            fields.push(SettingsField {
                label: format!("{cli} memory_max"),
                value: limits.memory_max.clone().unwrap_or_else(|| "--".into()),
                kind: SettingsFieldKind::MemorySize,
            });
        }
    } else {
        fields.push(SettingsField {
            label: "Governor Mode".into(),
            value: "throttle".into(),
            kind: SettingsFieldKind::GovernorMode,
        });
        fields.push(SettingsField {
            label: "Warn Threshold".into(),
            value: "85%".into(),
            kind: SettingsFieldKind::Threshold,
        });
        fields.push(SettingsField {
            label: "Urgent Threshold".into(),
            value: "95%".into(),
            kind: SettingsFieldKind::Threshold,
        });
    }

    if let Some(rules) = security_rules {
        for (i, entry) in rules.network_allow.iter().enumerate() {
            fields.push(SettingsField {
                label: format!("Network: {}", entry.name),
                value: entry.hosts.join(", "),
                kind: SettingsFieldKind::NetworkEntry(i),
            });
        }
    }

    fields
}

fn find_daemon_pid() -> Option<u32> {
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_str()?;
        if name_str.chars().all(|c| c.is_ascii_digit()) {
            let cmdline_path = entry.path().join("cmdline");
            if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                if cmdline.contains("runsafety-agent") {
                    return name_str.parse().ok();
                }
            }
        }
    }
    None
}

fn save_settings(app: &App) -> Result<()> {
    use runsafety_shared::config::*;

    let config_dir = dirs::config_dir()
        .context("Cannot determine config directory")?
        .join("runsafety");
    std::fs::create_dir_all(&config_dir)?;

    let mut governor = app
        .agent_config
        .as_ref()
        .map(|c| c.governor.clone())
        .unwrap_or_default();

    for field in &app.settings_fields {
        match (&field.kind, field.label.as_str()) {
            (SettingsFieldKind::GovernorMode, _) => {
                governor.action = match field.value.as_str() {
                    "warn" => GovernorAction::Warn,
                    "kill" => GovernorAction::Kill,
                    _ => GovernorAction::Throttle,
                };
            }
            (SettingsFieldKind::Threshold, "Warn Threshold") => {
                if let Some(v) = parse_pct(&field.value) {
                    governor.warn_threshold = v;
                }
            }
            (SettingsFieldKind::Threshold, "Urgent Threshold") => {
                if let Some(v) = parse_pct(&field.value) {
                    governor.urgent_threshold = v;
                }
            }
            (SettingsFieldKind::MemorySize, label) => {
                if let Some((cli, mem_field)) = label.rsplit_once(' ') {
                    let limits = governor.cli.entry(cli.to_string()).or_default();
                    let val = if field.value == "--" {
                        None
                    } else {
                        Some(field.value.clone())
                    };
                    if mem_field == "memory_high" {
                        limits.memory_high = val;
                    } else if mem_field == "memory_max" {
                        limits.memory_max = val;
                    }
                }
            }
            _ => {}
        }
    }

    let config_path = config_dir.join("agent.toml");
    let builtin: AgentConfig = toml::from_str(include_str!("../../../../config/agent.toml"))
        .context("built-in config is invalid")?;

    let mut config = if let Ok(existing) = std::fs::read_to_string(&config_path) {
        toml::from_str::<AgentConfig>(&existing).unwrap_or(builtin.clone())
    } else {
        builtin.clone()
    };

    // Only update governor settings; preserve discovery and security
    config.governor = governor;

    // If discovery patterns are empty (broken by previous save), restore from built-in
    if config.discovery.cli.is_empty() {
        config.discovery.cli = builtin.discovery.cli;
    }

    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&config_path, toml_str)?;

    Ok(())
}

fn parse_pct(s: &str) -> Option<f32> {
    let s = s.trim_end_matches('%').trim();
    s.parse::<f32>().ok().map(|v| v / 100.0)
}

fn signal_daemon_reload(pid: Option<u32>) -> bool {
    if let Some(pid) = pid {
        let p = nix::unistd::Pid::from_raw(pid as i32);
        nix::sys::signal::kill(p, nix::sys::signal::Signal::SIGHUP).is_ok()
    } else {
        false
    }
}

fn load_display_config() -> (Option<AgentConfig>, Option<SecurityRulesConfig>) {
    let config_dir = dirs::config_dir().unwrap_or_default().join("runsafety");

    let agent: Option<AgentConfig> = std::fs::read_to_string(config_dir.join("agent.toml"))
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .or_else(|| {
            std::fs::read_to_string("config/agent.toml")
                .ok()
                .and_then(|s| toml::from_str(&s).ok())
        });

    let rules: Option<SecurityRulesConfig> =
        std::fs::read_to_string(config_dir.join("security-rules.toml"))
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .or_else(|| {
                std::fs::read_to_string("config/security-rules.toml")
                    .ok()
                    .and_then(|s| toml::from_str(&s).ok())
            });

    (agent, rules)
}

// --- Main loop ---

pub async fn run(focus_event: Option<usize>) -> Result<()> {
    let mut poll_client = match IpcClient::connect().await {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Daemon not running - start with: runsafety-agent");
            eprintln!();
            eprintln!("  Or use systemd:");
            eprintln!("  systemctl --user start runsafety-agent");
            std::process::exit(1);
        }
    };

    let sessions = poll_client.list_sessions().await.unwrap_or_default();
    let mut app = App::new();
    let now = Instant::now();
    for s in &sessions {
        app.first_seen.entry(s.id).or_insert(now);
    }
    app.sessions = sessions;

    // Load historical events from daemon buffer
    if let Ok(historical) = poll_client.get_events(None, None, 500).await {
        let active_ids: std::collections::HashSet<u64> =
            app.sessions.iter().map(|s| s.id).collect();

        for en in &historical {
            // Reconstruct ended sessions from SessionDiscovered signals
            if let Signal::SessionDiscovered(session) = &en.signal {
                if !active_ids.contains(&session.id)
                    && !app.ended_sessions.iter().any(|e| e.info.id == session.id)
                {
                    let mut info = SessionInfo::from_session(session, None);
                    info.status = "Exited".to_string();
                    app.ended_sessions.push(EndedSession {
                        info,
                        ended_at: Instant::now(),
                    });
                }
            }
        }

        for en in historical {
            let entry = signal_to_entry(&en.signal, en.timestamp);
            app.events.push(entry);
        }
    }

    // Handle --focus-event: switch to events tab and open detail
    if let Some(idx) = focus_event {
        app.detail_tab = DetailTab::Events;
        app.event_scroll = idx;
        // Detail will be opened after first render when events are loaded
    }

    // Spawn subscription listener
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<EventNotification>();
    tokio::spawn(async move {
        if let Ok(mut sub_client) = IpcClient::connect().await {
            if sub_client.subscribe(None, None).await.is_ok() {
                while let Ok(Some(notif)) = sub_client.next_notification().await {
                    if notif.method == "event" {
                        if let Ok(en) = serde_json::from_value::<EventNotification>(notif.params) {
                            if event_tx.send(en).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    stdout.execute(EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut event_stream = EventStream::new();
    let mut poll_interval = tokio::time::interval(Duration::from_secs(2));
    poll_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // If focus_event was set, open detail after first event load
    let mut pending_focus = focus_event.is_some();
    // Track whether mouse capture is temporarily released (Shift held)
    let mut mouse_released = false;

    while !app.quit {
        terminal.draw(|f| render::render(f, &mut app))?;

        // Open event detail after first render if --focus-event was passed
        if pending_focus && !app.events.is_empty() {
            app.open_event_detail();
            pending_focus = false;
        }

        tokio::select! {
            maybe_event = event_stream.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) => {
                        // Shift key: release mouse capture so terminal native
                        // text selection works. Re-enable on release.
                        if key.modifiers.contains(KeyModifiers::SHIFT)
                            && !mouse_released
                        {
                            let _ = io::stdout().execute(DisableMouseCapture);
                            mouse_released = true;
                        }
                        handle_input(&mut app, key);
                    }
                    Some(Ok(Event::Mouse(mouse))) => {
                        // If mouse was released for Shift selection, re-enable
                        if mouse_released {
                            let _ = io::stdout().execute(EnableMouseCapture);
                            mouse_released = false;
                        }
                        handle_mouse(&mut app, mouse);
                    }
                    _ => {
                        // Re-enable mouse on any other event if released
                        if mouse_released {
                            let _ = io::stdout().execute(EnableMouseCapture);
                            mouse_released = false;
                        }
                    }
                }
            }
            _ = poll_interval.tick() => {
                refresh_sessions(&mut app, &mut poll_client).await;
            }
            Some(en) = event_rx.recv() => {
                handle_stream_event(&mut app, en);
            }
        }

        if let Some((_, when)) = &app.status_msg {
            if when.elapsed() > Duration::from_secs(3) {
                app.status_msg = None;
            }
        }
    }

    terminal::disable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(DisableMouseCapture)?;
    stdout.execute(LeaveAlternateScreen)?;
    Ok(())
}

async fn refresh_sessions(app: &mut App, client: &mut IpcClient) {
    if let Ok(sessions) = client.list_sessions().await {
        let active_ids: Vec<u64> = sessions.iter().map(|s| s.id).collect();

        // Detect sessions that disappeared: move to ended_sessions
        for old in &app.sessions {
            if !active_ids.contains(&old.id) {
                // Don't add duplicates
                if !app.ended_sessions.iter().any(|e| e.info.id == old.id) {
                    let mut ended_info = old.clone();
                    ended_info.status = "Exited".to_string();
                    app.ended_sessions.push(EndedSession {
                        info: ended_info,
                        ended_at: Instant::now(),
                    });
                }
            }
        }

        // Expire old ended sessions (>1hr or >20)
        app.ended_sessions
            .retain(|e| e.ended_at.elapsed() < ENDED_SESSION_TTL);
        while app.ended_sessions.len() > MAX_ENDED_SESSIONS {
            app.ended_sessions.remove(0);
        }

        let active_pids: Vec<u32> = sessions.iter().map(|s| s.pid).collect();
        for s in &sessions {
            if let Some(pct) = app.cpu_tracker.update(s.pid) {
                app.cpu_percents.insert(s.pid, pct);
                push_history(&mut app.cpu_history, s.pid, (pct * 10.0) as u64);
            }
            if let Some(rss) = s.rss_bytes {
                push_history(&mut app.rss_history, s.pid, rss / (1024 * 1024));
            }
        }
        app.cpu_tracker.remove_stale(&active_pids);
        app.cpu_percents.retain(|pid, _| active_pids.contains(pid));
        app.rss_history.retain(|pid, _| active_pids.contains(pid));
        app.cpu_history.retain(|pid, _| active_pids.contains(pid));
        let now = Instant::now();
        let active_ids: std::collections::HashSet<u64> = sessions.iter().map(|s| s.id).collect();
        for s in &sessions {
            app.first_seen.entry(s.id).or_insert(now);
        }
        app.first_seen.retain(|id, _| active_ids.contains(id));
        app.sessions = sessions;

        let len = app.selectable_count();
        if app.selected >= len && len > 0 {
            app.selected = len - 1;
        }
    }
}

fn push_history(map: &mut HashMap<u32, VecDeque<u64>>, pid: u32, val: u64) {
    let hist = map
        .entry(pid)
        .or_insert_with(|| VecDeque::with_capacity(HISTORY_CAP));
    if hist.len() >= HISTORY_CAP {
        hist.pop_front();
    }
    hist.push_back(val);
}

fn handle_stream_event(app: &mut App, en: EventNotification) {
    let entry = signal_to_entry(&en.signal, en.timestamp);
    app.events.push(entry);
    if app.events.len() > 500 {
        app.events.remove(0);
    }
}

// --- Mouse handling ---

fn handle_mouse(app: &mut App, mouse: MouseEvent) {
    let col = mouse.column;
    let row = mouse.row;

    // Event detail pane: handle button clicks and scroll
    if app.event_detail.is_some() {
        let edp = app.layout.event_detail_pane;
        if col >= edp.x && col < edp.x + edp.width && row >= edp.y && row < edp.y + edp.height {
            match mouse.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    // Check if click is on an action button
                    for &(x_start, x_end, btn_row, action_idx) in &app.layout.action_buttons {
                        if row == btn_row && col >= x_start && col < x_end {
                            app.active_pane = ActivePane::EventDetail;
                            let action_key = EVENT_ACTIONS[action_idx].0;
                            execute_event_action(app, action_key);
                            return;
                        }
                    }
                    // Click elsewhere in detail pane just focuses it
                    app.active_pane = ActivePane::EventDetail;
                    return;
                }
                MouseEventKind::ScrollUp => {
                    if let Some(ref mut detail) = app.event_detail {
                        detail.selected_action = detail.selected_action.saturating_sub(1);
                    }
                    return;
                }
                MouseEventKind::ScrollDown => {
                    if let Some(ref mut detail) = app.event_detail {
                        detail.selected_action =
                            (detail.selected_action + 1).min(EVENT_ACTIONS.len() - 1);
                    }
                    return;
                }
                _ => {}
            }
        }
    }

    // Settings overlay mouse handling
    if app.show_settings {
        return;
    }

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            // Check header tab clicks
            for &(x_start, x_end, tab) in &app.layout.tab_regions {
                if row == app.layout.header.y && col >= x_start && col < x_end {
                    app.detail_tab = tab;
                    app.event_scroll = 0;
                    return;
                }
            }

            // Check session list click
            let sl = app.layout.session_list;
            if col >= sl.x && col < sl.x + sl.width && row >= sl.y && row < sl.y + sl.height {
                app.active_pane = ActivePane::Sessions;
                // Account for border (1 row top)
                let clicked_row = (row - sl.y).saturating_sub(1) as usize;
                if let Some(sel_idx) = visual_row_to_selectable(app, clicked_row) {
                    app.selected = sel_idx;
                    app.event_scroll = 0;
                }
                return;
            }

            // Check detail pane click
            let dp = app.layout.detail_pane;
            if col >= dp.x && col < dp.x + dp.width && row >= dp.y && row < dp.y + dp.height {
                if app.detail_tab == DetailTab::Events {
                    // Use stored events_list_area for precise hit-testing
                    let ela = app.layout.events_list_area;
                    let edp = app.layout.event_detail_pane;
                    if ela.height > 0
                        && col >= ela.x
                        && col < ela.x + ela.width
                        && row >= ela.y
                        && row < ela.y + ela.height
                    {
                        // Click in events list area
                        app.active_pane = ActivePane::Events;
                        let clicked_row = (row - ela.y).saturating_sub(1) as usize;
                        // Each event takes 2 visual rows (header + description)
                        let event_idx = clicked_row / 2;
                        let events = app.selected_session_events();
                        if event_idx < events.len() {
                            app.event_scroll = event_idx;
                            app.refresh_event_detail();
                        }
                    } else if edp.height > 0
                        && col >= edp.x
                        && col < edp.x + edp.width
                        && row >= edp.y
                        && row < edp.y + edp.height
                    {
                        // Click in event detail area
                        app.active_pane = ActivePane::EventDetail;
                    } else {
                        // Click in events area but no events yet
                        app.active_pane = ActivePane::Events;
                    }
                } else {
                    // Resources or Info tab - just focus the detail pane
                    app.active_pane = ActivePane::Events;
                }
            }
        }
        MouseEventKind::ScrollUp => {
            let sl = app.layout.session_list;
            let dp = app.layout.detail_pane;
            if col >= sl.x && col < sl.x + sl.width && row >= sl.y && row < sl.y + sl.height {
                app.selected = app.selected.saturating_sub(1);
                app.event_scroll = 0;
            } else if col >= dp.x
                && col < dp.x + dp.width
                && row >= dp.y
                && row < dp.y + dp.height
                && app.detail_tab == DetailTab::Events
            {
                app.event_scroll = app.event_scroll.saturating_sub(1);
                if app.event_detail.is_some() {
                    app.refresh_event_detail();
                }
            }
        }
        MouseEventKind::ScrollDown => {
            let sl = app.layout.session_list;
            let dp = app.layout.detail_pane;
            if col >= sl.x && col < sl.x + sl.width && row >= sl.y && row < sl.y + sl.height {
                let len = app.selectable_count();
                if len > 0 {
                    app.selected = (app.selected + 1).min(len - 1);
                    app.event_scroll = 0;
                }
            } else if col >= dp.x
                && col < dp.x + dp.width
                && row >= dp.y
                && row < dp.y + dp.height
                && app.detail_tab == DetailTab::Events
            {
                let len = app.selected_session_events().len();
                if len > 0 {
                    app.event_scroll = (app.event_scroll + 1).min(len - 1);
                    if app.event_detail.is_some() {
                        app.refresh_event_detail();
                    }
                }
            }
        }
        MouseEventKind::Drag(MouseButton::Left) => {
            // Click-and-drag on session list to select
            let sl = app.layout.session_list;
            if col >= sl.x && col < sl.x + sl.width && row >= sl.y && row < sl.y + sl.height {
                let clicked_row = (row - sl.y).saturating_sub(1) as usize;
                if let Some(sel_idx) = visual_row_to_selectable(app, clicked_row) {
                    app.selected = sel_idx;
                }
            }
        }
        _ => {}
    }
}

/// Convert a visual row index in the session list to a selectable index.
/// Returns None if the clicked row is the separator or out of bounds.
fn visual_row_to_selectable(app: &App, visual_row: usize) -> Option<usize> {
    let items = app.session_items();
    let item = items.get(visual_row)?;
    match item {
        SessionItem::Separator => None,
        SessionItem::Active(_) => Some(visual_row),
        SessionItem::Ended(_) => {
            // Count how many separators came before this row
            let seps_before = items[..visual_row]
                .iter()
                .filter(|i| matches!(i, SessionItem::Separator))
                .count();
            Some(visual_row - seps_before)
        }
    }
}

// --- Keyboard handling ---

fn handle_input(app: &mut App, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.quit = true;
        return;
    }

    // Global keys that work from any context
    match key.code {
        KeyCode::Char('q') if !app.editing_filter && !app.settings_editing => {
            app.quit = true;
            return;
        }
        KeyCode::Char('?') if !app.editing_filter && !app.settings_editing => {
            app.show_help = true;
            return;
        }
        KeyCode::Char('S') | KeyCode::F(3)
            if !app.editing_filter && !app.settings_editing && !app.show_settings =>
        {
            app.show_settings = true;
            return;
        }
        _ => {}
    }

    // Overlays take priority over event detail
    if app.show_help {
        app.show_help = false;
        return;
    }

    if app.show_settings {
        handle_settings_input(app, key);
        return;
    }

    // Event detail panel
    if app.event_detail.is_some() {
        handle_event_detail_input(app, key);
        return;
    }

    if app.editing_filter {
        handle_filter_input(app, key);
        return;
    }

    if let Some(sid) = app.confirm_kill {
        match key.code {
            KeyCode::Char('D') | KeyCode::Char('y') | KeyCode::Char('Y') => {
                do_kill(app, sid);
                app.confirm_kill = None;
            }
            _ => {
                app.confirm_kill = None;
                app.set_status("Kill cancelled".into());
            }
        }
        return;
    }

    match key.code {
        KeyCode::Char('/') => {
            app.editing_filter = true;
            app.filter_text.clear();
        }
        KeyCode::Tab => {
            // Tab cycles: Sessions -> Events -> (EventDetail if open) -> Sessions
            app.active_pane = match app.active_pane {
                ActivePane::Sessions => ActivePane::Events,
                ActivePane::Events => {
                    if app.event_detail.is_some() && app.detail_tab == DetailTab::Events {
                        ActivePane::EventDetail
                    } else {
                        ActivePane::Sessions
                    }
                }
                ActivePane::EventDetail => ActivePane::Sessions,
            };
        }
        KeyCode::BackTab => {
            // Shift-Tab cycles detail tabs: Events -> Resources -> Info
            app.detail_tab = match app.detail_tab {
                DetailTab::Events => DetailTab::Resources,
                DetailTab::Resources => DetailTab::Info,
                DetailTab::Info => DetailTab::Events,
            };
            app.event_scroll = 0;
            app.active_pane = ActivePane::Events;
        }
        KeyCode::Esc => {
            if !app.filter_text.is_empty() {
                app.filter_text.clear();
            } else if app.active_pane != ActivePane::Sessions {
                app.active_pane = ActivePane::Sessions;
            }
        }
        // Open event detail
        KeyCode::Enter => {
            if app.detail_tab == DetailTab::Events && app.active_pane == ActivePane::Events {
                app.open_event_detail();
                if app.event_detail.is_some() {
                    app.active_pane = ActivePane::EventDetail;
                }
            }
        }
        // j/k navigation is pane-aware
        KeyCode::Char('j') | KeyCode::Down => match app.active_pane {
            ActivePane::Sessions => {
                let len = app.selectable_count();
                if len > 0 {
                    app.selected = (app.selected + 1).min(len - 1);
                    app.event_scroll = 0;
                }
            }
            ActivePane::Events | ActivePane::EventDetail => {
                if app.detail_tab == DetailTab::Events {
                    let len = app.selected_session_events().len();
                    if len > 0 {
                        app.event_scroll = (app.event_scroll + 1).min(len - 1);
                        if app.event_detail.is_some() {
                            app.refresh_event_detail();
                        }
                    }
                }
            }
        },
        KeyCode::Char('k') | KeyCode::Up => match app.active_pane {
            ActivePane::Sessions => {
                app.selected = app.selected.saturating_sub(1);
                app.event_scroll = 0;
            }
            ActivePane::Events | ActivePane::EventDetail => {
                if app.detail_tab == DetailTab::Events {
                    app.event_scroll = app.event_scroll.saturating_sub(1);
                    if app.event_detail.is_some() {
                        app.refresh_event_detail();
                    }
                }
            }
        },
        KeyCode::Char('g') | KeyCode::Home => {
            if app.active_pane == ActivePane::Sessions {
                app.selected = 0;
                app.event_scroll = 0;
            } else {
                app.event_scroll = 0;
                if app.event_detail.is_some() {
                    app.refresh_event_detail();
                }
            }
        }
        KeyCode::Char('G') | KeyCode::End => {
            if app.active_pane == ActivePane::Sessions {
                let len = app.selectable_count();
                if len > 0 {
                    app.selected = len - 1;
                    app.event_scroll = 0;
                }
            } else {
                let len = app.selected_session_events().len();
                if len > 0 {
                    app.event_scroll = len - 1;
                    if app.event_detail.is_some() {
                        app.refresh_event_detail();
                    }
                }
            }
        }
        // Kill
        KeyCode::Char('D') => {
            let sid = app.filtered_sessions().get(app.selected).map(|s| s.id);
            if let Some(sid) = sid {
                app.confirm_kill = Some(sid);
                app.set_status(format!(
                    "Kill session {sid}? Press D/y to confirm, any key to cancel",
                ));
            }
        }
        // J/K also scroll events (legacy, works from any pane)
        KeyCode::Char('J') | KeyCode::PageDown => {
            if app.detail_tab == DetailTab::Events {
                let len = app.selected_session_events().len();
                if len > 0 {
                    app.event_scroll = (app.event_scroll + 1).min(len - 1);
                    if app.event_detail.is_some() {
                        app.refresh_event_detail();
                    }
                }
            }
        }
        KeyCode::Char('K') | KeyCode::PageUp => {
            if app.detail_tab == DetailTab::Events {
                app.event_scroll = app.event_scroll.saturating_sub(1);
                if app.event_detail.is_some() {
                    app.refresh_event_detail();
                }
            }
        }
        _ => {}
    }
}

fn handle_event_detail_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('x') => {
            app.event_detail = None;
            app.active_pane = ActivePane::Events;
        }
        KeyCode::Char('a') => execute_event_action(app, "a"),
        KeyCode::Char('b') => execute_event_action(app, "b"),
        KeyCode::Char('i') => execute_event_action(app, "i"),
        KeyCode::Char('l') => execute_event_action(app, "l"),
        KeyCode::Char('c') => execute_event_action(app, "c"),
        // Navigate events (j/k scrolls through events, updates detail live)
        KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Down | KeyCode::PageDown => {
            let len = app.selected_session_events().len();
            if len > 0 {
                app.event_scroll = (app.event_scroll + 1).min(len - 1);
                app.refresh_event_detail();
            }
        }
        KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Up | KeyCode::PageUp => {
            app.event_scroll = app.event_scroll.saturating_sub(1);
            app.refresh_event_detail();
        }
        KeyCode::Enter => {
            if let Some(detail) = &app.event_detail {
                let action_key = EVENT_ACTIONS[detail.selected_action].0;
                execute_event_action(app, action_key);
            }
        }
        // Left/right to move between action buttons
        KeyCode::Left => {
            if let Some(ref mut detail) = app.event_detail {
                detail.selected_action = detail.selected_action.saturating_sub(1);
            }
        }
        KeyCode::Right => {
            if let Some(ref mut detail) = app.event_detail {
                detail.selected_action = (detail.selected_action + 1).min(EVENT_ACTIONS.len() - 1);
            }
        }
        _ => {}
    }
}

fn handle_filter_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter | KeyCode::Esc => {
            app.editing_filter = false;
            if key.code == KeyCode::Esc {
                app.filter_text.clear();
            }
        }
        KeyCode::Char(c) => app.filter_text.push(c),
        KeyCode::Backspace => {
            app.filter_text.pop();
        }
        _ => {}
    }
}

fn handle_settings_input(app: &mut App, key: KeyEvent) {
    if app.settings_editing {
        let field_kind = app
            .settings_fields
            .get(app.settings_cursor)
            .map(|f| f.kind.clone());
        match key.code {
            KeyCode::Esc => {
                app.settings_editing = false;
                app.settings_edit_buf.clear();
            }
            KeyCode::Enter => {
                if let Some(field) = app.settings_fields.get_mut(app.settings_cursor) {
                    if !app.settings_edit_buf.is_empty() {
                        field.value = format_field_value(&app.settings_edit_buf, &field.kind);
                    }
                }
                app.settings_editing = false;
                app.settings_edit_buf.clear();
            }
            KeyCode::Up => {
                nudge_edit_buf(&mut app.settings_edit_buf, &field_kind, 1);
            }
            KeyCode::Down => {
                nudge_edit_buf(&mut app.settings_edit_buf, &field_kind, -1);
            }
            KeyCode::Char(c) => {
                let allow = match &field_kind {
                    Some(SettingsFieldKind::Threshold) => c.is_ascii_digit(),
                    Some(SettingsFieldKind::MemorySize) => {
                        c.is_ascii_digit()
                            || c == '.'
                            || c == 'G'
                            || c == 'M'
                            || c == 'K'
                            || c == 'B'
                            || c == 'g'
                            || c == 'm'
                            || c == 'k'
                            || c == 'b'
                    }
                    _ => true,
                };
                if allow {
                    app.settings_edit_buf.push(c);
                }
            }
            KeyCode::Backspace => {
                app.settings_edit_buf.pop();
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.show_settings = false;
            app.settings_cursor = 0;
        }
        KeyCode::Char('S') | KeyCode::F(3) => {
            app.show_settings = false;
            app.settings_cursor = 0;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if !app.settings_fields.is_empty() {
                app.settings_cursor = (app.settings_cursor + 1).min(app.settings_fields.len() - 1);
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.settings_cursor = app.settings_cursor.saturating_sub(1);
        }
        KeyCode::Left | KeyCode::Right => {
            if let Some(field) = app.settings_fields.get_mut(app.settings_cursor) {
                match field.kind {
                    SettingsFieldKind::GovernorMode => {
                        let modes = ["warn", "throttle", "kill"];
                        let cur = modes.iter().position(|m| *m == field.value).unwrap_or(1);
                        let next = if key.code == KeyCode::Right {
                            (cur + 1) % modes.len()
                        } else {
                            (cur + modes.len() - 1) % modes.len()
                        };
                        field.value = modes[next].to_string();
                    }
                    SettingsFieldKind::Threshold => {
                        let delta: i32 = if key.code == KeyCode::Right { 5 } else { -5 };
                        nudge_field_value(field, delta);
                    }
                    SettingsFieldKind::MemorySize => {
                        nudge_memory_field(field, key.code == KeyCode::Right);
                    }
                    _ => {}
                }
            }
        }
        KeyCode::Enter => {
            if let Some(field) = app.settings_fields.get(app.settings_cursor) {
                if field.kind != SettingsFieldKind::ReadOnly {
                    if field.kind == SettingsFieldKind::GovernorMode {
                        return;
                    }
                    app.settings_editing = true;
                    app.settings_edit_buf = strip_field_suffix(&field.value, &field.kind);
                }
            }
        }
        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            match save_settings(app) {
                Ok(()) => {
                    let reloaded = signal_daemon_reload(app.daemon_pid);
                    if reloaded {
                        app.set_status("Settings saved, daemon reloaded".into());
                    } else {
                        app.set_status(
                            "Settings saved (daemon not found, restart to apply)".into(),
                        );
                    }
                    let (cfg, rules) = load_display_config();
                    app.agent_config = cfg;
                    app.security_rules = rules;
                }
                Err(e) => {
                    app.set_status(format!("Save failed: {e}"));
                }
            }
        }
        _ => {}
    }
}

// --- Settings field helpers ---

fn strip_field_suffix(value: &str, kind: &SettingsFieldKind) -> String {
    match kind {
        SettingsFieldKind::Threshold => value.trim_end_matches('%').to_string(),
        _ => value.to_string(),
    }
}

fn format_field_value(raw: &str, kind: &SettingsFieldKind) -> String {
    match kind {
        SettingsFieldKind::Threshold => {
            let n: u32 = raw.parse().unwrap_or(0);
            let clamped = n.min(100);
            format!("{clamped}%")
        }
        SettingsFieldKind::MemorySize => {
            let s = raw.trim();
            if s.is_empty() {
                "--".to_string()
            } else {
                s.to_uppercase()
            }
        }
        _ => raw.to_string(),
    }
}

fn nudge_edit_buf(buf: &mut String, kind: &Option<SettingsFieldKind>, delta: i32) {
    match kind {
        Some(SettingsFieldKind::Threshold) => {
            let cur: i32 = buf.parse().unwrap_or(0);
            let next = (cur + delta).clamp(0, 100);
            *buf = next.to_string();
        }
        Some(SettingsFieldKind::MemorySize) => {
            let (num_str, suffix) = split_mem_value(buf);
            if let Ok(cur) = num_str.parse::<f64>() {
                let step = if suffix == "GB" || suffix == "G" {
                    0.5
                } else {
                    100.0
                };
                let next = (cur + delta as f64 * step).max(0.0);
                if next == next.floor() {
                    *buf = format!("{}{}", next as u64, suffix);
                } else {
                    *buf = format!("{:.1}{}", next, suffix);
                }
            }
        }
        _ => {}
    }
}

fn nudge_field_value(field: &mut SettingsField, delta: i32) {
    let raw = field.value.trim_end_matches('%');
    let cur: i32 = raw.parse().unwrap_or(0);
    let next = (cur + delta).clamp(0, 100);
    field.value = format!("{next}%");
}

fn nudge_memory_field(field: &mut SettingsField, up: bool) {
    let (num_str, suffix) = split_mem_value(&field.value);
    let suffix = if suffix.is_empty() { "GB" } else { &suffix };
    if let Ok(cur) = num_str.parse::<f64>() {
        let step = if suffix.starts_with('G') || suffix.starts_with('g') {
            0.5
        } else {
            256.0
        };
        let delta = if up { step } else { -step };
        let next = (cur + delta).max(0.0);
        if next == next.floor() {
            field.value = format!("{}{}", next as u64, suffix);
        } else {
            field.value = format!("{:.1}{}", next, suffix);
        }
    }
}

fn split_mem_value(s: &str) -> (String, String) {
    let s = s.trim();
    let num_end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    (s[..num_end].to_string(), s[num_end..].to_string())
}

fn do_kill(app: &mut App, session_id: u64) {
    if let Some(session) = app.sessions.iter().find(|s| s.id == session_id) {
        let pid = nix::unistd::Pid::from_raw(session.pid as i32);
        match nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM) {
            Ok(_) => app.set_status(format!(
                "Sent SIGTERM to session {} (PID {})",
                session_id, session.pid
            )),
            Err(e) => app.set_status(format!("Kill failed: {e}")),
        }
    }
}

// --- Signal to EventEntry conversion ---

pub fn signal_to_entry(signal: &Signal, timestamp: u64) -> EventEntry {
    let (severity, cli_type, pid, session_id, description, raw_signal) = match signal {
        Signal::SessionDiscovered(s) => (
            EventSeverity::Info,
            format!("{}", s.cli_type),
            s.pid,
            s.id,
            format!("Session started in {}", s.working_dir.display()),
            SignalSummary::SessionStarted {
                working_dir: s.working_dir.display().to_string(),
            },
        ),
        Signal::SessionExited { id, pid, cli_type } => (
            EventSeverity::Info,
            format!("{cli_type}"),
            *pid,
            *id,
            "Session exited".into(),
            SignalSummary::SessionExited,
        ),
        Signal::MemoryWarning {
            session_id,
            pid,
            cli_type,
            rss_bytes,
            high_bytes,
        } => (
            EventSeverity::Warning,
            format!("{cli_type}"),
            *pid,
            *session_id,
            format!(
                "Memory warning: {}",
                crate::cli::format_bytes(Some(*rss_bytes))
            ),
            SignalSummary::MemoryWarning {
                rss_bytes: *rss_bytes,
                high_bytes: *high_bytes,
            },
        ),
        Signal::MemoryUrgent {
            session_id,
            pid,
            cli_type,
            rss_bytes,
            high_bytes,
        } => (
            EventSeverity::Warning,
            format!("{cli_type}"),
            *pid,
            *session_id,
            format!(
                "Memory URGENT: {}",
                crate::cli::format_bytes(Some(*rss_bytes))
            ),
            SignalSummary::MemoryUrgent {
                rss_bytes: *rss_bytes,
                high_bytes: *high_bytes,
            },
        ),
        Signal::LeakDetected {
            session_id,
            pid,
            cli_type,
            rss_bytes,
            duration_secs,
        } => (
            EventSeverity::Warning,
            format!("{cli_type}"),
            *pid,
            *session_id,
            format!(
                "Leak detected: {} over {duration_secs}s",
                crate::cli::format_bytes(Some(*rss_bytes))
            ),
            SignalSummary::LeakDetected {
                rss_bytes: *rss_bytes,
                duration_secs: *duration_secs,
            },
        ),
        Signal::OomKill {
            session_id,
            pid,
            cli_type,
            peak_rss_bytes,
        } => (
            EventSeverity::Critical,
            format!("{cli_type}"),
            *pid,
            *session_id,
            "OOM killed".into(),
            SignalSummary::OomKill {
                peak_rss_bytes: *peak_rss_bytes,
            },
        ),
        Signal::SensitiveFileAccess {
            session_id,
            pid,
            cli_type,
            path,
            severity,
            known_safe,
            ..
        } => (
            match severity {
                runsafety_shared::types::Severity::Critical => EventSeverity::Critical,
                runsafety_shared::types::Severity::Warning => EventSeverity::Warning,
                runsafety_shared::types::Severity::Info => EventSeverity::Info,
            },
            format!("{cli_type}"),
            *pid,
            *session_id,
            format!("Accessed {}", path.display()),
            SignalSummary::SensitiveFileAccess {
                path: path.display().to_string(),
                known_safe: known_safe.clone(),
            },
        ),
        Signal::BoundaryViolation {
            session_id,
            pid,
            cli_type,
            path,
            ..
        } => (
            EventSeverity::Warning,
            format!("{cli_type}"),
            *pid,
            *session_id,
            format!("Boundary violation: {}", path.display()),
            SignalSummary::BoundaryViolation {
                path: path.display().to_string(),
            },
        ),
        Signal::UnexpectedNetwork {
            session_id,
            pid,
            cli_type,
            remote_addr,
            remote_port,
            ..
        } => (
            EventSeverity::Warning,
            format!("{cli_type}"),
            *pid,
            *session_id,
            format!("Unexpected connection: {remote_addr}:{remote_port}"),
            SignalSummary::UnexpectedNetwork {
                remote_addr: remote_addr.clone(),
                remote_port: *remote_port,
            },
        ),
        Signal::DangerousCommand {
            session_id,
            pid,
            cli_type,
            matched_text,
            severity,
            ..
        } => (
            match severity {
                runsafety_shared::types::Severity::Critical => EventSeverity::Critical,
                runsafety_shared::types::Severity::Warning => EventSeverity::Warning,
                runsafety_shared::types::Severity::Info => EventSeverity::Info,
            },
            format!("{cli_type}"),
            *pid,
            *session_id,
            format!("Dangerous command: {matched_text}"),
            SignalSummary::DangerousCommand {
                matched_text: matched_text.clone(),
            },
        ),
        Signal::SuspiciousChild {
            session_id,
            pid,
            cli_type,
            child_cmdline,
            ..
        } => (
            EventSeverity::Warning,
            format!("{cli_type}"),
            *pid,
            *session_id,
            format!("Suspicious child: {child_cmdline}"),
            SignalSummary::SuspiciousChild {
                child_cmdline: child_cmdline.clone(),
            },
        ),
        Signal::ExfilAttempt {
            session_id,
            pid,
            cli_type,
            file_path,
            remote_addr,
        } => (
            EventSeverity::Critical,
            format!("{cli_type}"),
            *pid,
            *session_id,
            format!("Exfil attempt: {} -> {remote_addr}", file_path.display()),
            SignalSummary::ExfilAttempt {
                file_path: file_path.display().to_string(),
                remote_addr: remote_addr.clone(),
            },
        ),
    };

    EventEntry {
        timestamp,
        severity,
        cli_type,
        pid,
        session_id,
        description,
        raw_signal,
    }
}

// --- Utility functions ---

pub fn format_uptime(started_at: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_duration(now.saturating_sub(started_at))
}

pub fn format_duration(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    } else if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

pub fn dir_basename(path: &str) -> &str {
    path.rsplit('/').find(|s| !s.is_empty()).unwrap_or(path)
}
