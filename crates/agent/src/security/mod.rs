pub mod file_monitor;
pub mod net_monitor;
#[cfg(target_os = "linux")]
pub mod proc_connector;
pub mod process_monitor;
pub mod rules;

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;
use tracing::{info, warn};

use runsafety_shared::config::SecurityConfig;
use runsafety_shared::types::{CliType, Session, Severity, Signal};

use crate::alert;
use rules::SecurityRules;

/// Per-session security tracking state with time-windowed dedup.
struct TrackedSecuritySession {
    session: Session,
    seen_files: HashMap<PathBuf, Instant>,
    seen_connections: HashMap<(IpAddr, u16), Instant>,
    seen_children: HashMap<u32, Instant>,
    /// When this session started being tracked. During the warmup period,
    /// signals are logged/audited but desktop notifications are suppressed
    /// to avoid flooding on initial scan of pre-existing state.
    tracked_since: Instant,
}

/// How long to suppress desktop notifications after a session is first discovered.
/// Signals still flow to audit log and event bus during warmup.
const SESSION_WARMUP_SECS: u64 = 10;

/// A recorded file access event for cross-signal correlation.
struct FileAccessRecord {
    session_id: u64,
    path: PathBuf,
    timestamp: Instant,
}

/// Correlation engine: detects exfiltration patterns.
/// Pattern: sensitive file read + network connection within N seconds = Critical.
struct CorrelationTracker {
    file_accesses: VecDeque<FileAccessRecord>,
    exfil_window: Duration,
    reported: HashMap<(u64, PathBuf, String), Instant>,
    dedup_window: Duration,
}

impl CorrelationTracker {
    fn new(window_secs: u64, dedup_window: Duration) -> Self {
        Self {
            file_accesses: VecDeque::new(),
            exfil_window: Duration::from_secs(window_secs),
            reported: HashMap::new(),
            dedup_window,
        }
    }

    fn record_file_access(&mut self, session_id: u64, path: &Path) {
        self.file_accesses.push_back(FileAccessRecord {
            session_id,
            path: path.to_path_buf(),
            timestamp: Instant::now(),
        });
        self.prune();
    }

    /// Check if a network event correlates with a recent file access.
    fn check_exfil(
        &mut self,
        session_id: u64,
        pid: u32,
        cli_type: &CliType,
        remote_addr: &str,
    ) -> Option<Signal> {
        let now = Instant::now();
        self.prune();

        for record in &self.file_accesses {
            if record.session_id != session_id {
                continue;
            }
            if now.duration_since(record.timestamp) > self.exfil_window {
                continue;
            }

            let key = (session_id, record.path.clone(), remote_addr.to_string());
            if let Some(&seen_at) = self.reported.get(&key) {
                if seen_at.elapsed() < self.dedup_window {
                    continue;
                }
            }

            self.reported.insert(key, Instant::now());
            return Some(Signal::ExfilAttempt {
                session_id,
                pid,
                cli_type: cli_type.clone(),
                file_path: record.path.clone(),
                remote_addr: remote_addr.to_string(),
            });
        }

        None
    }

    fn prune(&mut self) {
        let cutoff = Instant::now() - self.exfil_window * 2;
        while let Some(front) = self.file_accesses.front() {
            if front.timestamp < cutoff {
                self.file_accesses.pop_front();
            } else {
                break;
            }
        }
        // Prune expired dedup entries
        self.reported
            .retain(|_, seen_at| seen_at.elapsed() < self.dedup_window);
    }

    fn remove_session(&mut self, session_id: u64) {
        self.file_accesses.retain(|r| r.session_id != session_id);
        self.reported.retain(|(sid, _, _), _| *sid != session_id);
    }
}

/// Time-windowed notification dedup with rate limiting for desktop alerts.
struct NotificationDedup {
    seen: HashMap<String, Instant>,
    window: Duration,
    /// Recent notification timestamps for rate limiting.
    recent: VecDeque<Instant>,
    /// Max notifications per rate window.
    rate_limit: usize,
    /// Rate window duration.
    rate_window: Duration,
}

const RATE_LIMIT: usize = 10;
const RATE_WINDOW_SECS: u64 = 30;

impl NotificationDedup {
    fn new(window: Duration) -> Self {
        Self {
            seen: HashMap::new(),
            window,
            recent: VecDeque::new(),
            rate_limit: RATE_LIMIT,
            rate_window: Duration::from_secs(RATE_WINDOW_SECS),
        }
    }

    /// Returns true if this event should trigger a notification.
    /// Enforces both per-key dedup and global rate limit.
    fn should_notify(&mut self, key: &str) -> bool {
        // Per-key dedup
        if let Some(&seen_at) = self.seen.get(key) {
            if seen_at.elapsed() < self.window {
                return false;
            }
        }

        // Global rate limit: max 10 notifications per 30 seconds
        let now = Instant::now();
        self.recent
            .retain(|&t| now.duration_since(t) < self.rate_window);
        if self.recent.len() >= self.rate_limit {
            return false;
        }

        self.seen.insert(key.to_string(), now);
        self.recent.push_back(now);
        true
    }

    fn prune(&mut self) {
        self.seen
            .retain(|_, seen_at| seen_at.elapsed() < self.window);
    }
}

/// Walk up the process tree to find if `pid` is a descendant of any tracked PID.
/// Returns the tracked PID if found.
fn find_ancestor_session(pid: u32, tracked: &HashMap<u32, TrackedSecuritySession>) -> Option<u32> {
    let mut current = pid;
    for _ in 0..32 {
        let ppid = process_monitor::read_ppid(current)?;
        if ppid <= 1 {
            return None;
        }
        if tracked.contains_key(&ppid) {
            return Some(ppid);
        }
        current = ppid;
    }
    None
}

/// Main security monitoring loop.
/// Subscribes to SessionDiscovered/Exited, runs multi-speed scanning:
/// - Full scan (FD enumeration): every scan_interval_secs (default 3s)
/// - Fast scan (network + process + inotify): every fast_scan_interval_ms (default 500ms)
/// - Proc connector events (Linux): instant via netlink
pub async fn security_monitor_loop(
    mut rx: broadcast::Receiver<Signal>,
    tx: broadcast::Sender<Signal>,
    config: SecurityConfig,
    rules: SecurityRules,
) {
    let full_scan_interval = Duration::from_secs(config.scan_interval_secs);
    let fast_scan_interval = Duration::from_millis(config.fast_scan_interval_ms);
    let dedup_window = Duration::from_secs(config.dedup_window_secs);
    let notify_min_severity = Severity::parse(&config.notify_min_severity);

    let mut tracked: HashMap<u32, TrackedSecuritySession> = HashMap::new();
    let mut correlation = CorrelationTracker::new(config.exfil_window_secs, dedup_window);
    let mut notif_dedup = NotificationDedup::new(dedup_window);
    // Dedup for inotify/kqueue events: (path) -> last seen.
    // Prevents flooding when a file is accessed many times per second.
    let mut inotify_seen: HashMap<PathBuf, Instant> = HashMap::new();

    let mut full_interval = tokio::time::interval(full_scan_interval);
    let mut fast_interval = tokio::time::interval(fast_scan_interval);

    // Set up file watches on sensitive directories and individual files
    #[cfg(target_os = "linux")]
    let mut inotify_state = {
        let watch_dirs = rules.inotify_watch_dirs();
        let watch_files = rules.inotify_watch_files();
        if !watch_dirs.is_empty() || !watch_files.is_empty() {
            info!(
                "Setting up inotify on {} dirs + {} files",
                watch_dirs.len(),
                watch_files.len(),
            );
        }
        file_monitor::setup_inotify(&watch_dirs, &watch_files)
    };

    #[cfg(target_os = "macos")]
    let mut kqueue_state = {
        let watch_dirs = rules.inotify_watch_dirs();
        if !watch_dirs.is_empty() {
            info!(
                "Setting up kqueue on {} sensitive directories",
                watch_dirs.len()
            );
        }
        file_monitor::setup_kqueue(&watch_dirs)
    };

    // Set up proc connector for instant process event detection.
    // Channel always exists; on non-Linux it never receives (sender dropped immediately).
    let (proc_tx, mut proc_rx) = tokio::sync::mpsc::channel::<u32>(512);

    #[cfg(target_os = "linux")]
    let has_proc_connector = {
        match proc_connector::ProcConnector::new() {
            Ok(connector) => {
                info!("Proc connector active: instant process event detection");
                let ptx = proc_tx.clone();
                tokio::spawn(async move {
                    loop {
                        match connector.recv_event().await {
                            Ok(Some(proc_connector::ProcEvent::Exec(e))) => {
                                let _ = ptx.send(e.process_pid).await;
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!("Proc connector error: {e}");
                                break;
                            }
                        }
                    }
                });
                true
            }
            Err(e) => {
                info!("Proc connector unavailable ({e}), using 500ms polling fallback");
                false
            }
        }
    };

    #[cfg(not(target_os = "linux"))]
    let _has_proc_connector = false;

    // Drop the extra sender so recv returns None when the spawned task ends
    drop(proc_tx);

    loop {
        tokio::select! {
            // --- Bus events: session discovery/exit ---
            result = rx.recv() => {
                match result {
                    Ok(Signal::SessionDiscovered(session)) => {
                        info!(
                            "Security monitor tracking: {} (PID {})",
                            session.cli_type, session.pid,
                        );
                        tracked.insert(session.pid, TrackedSecuritySession {
                            session,
                            seen_files: HashMap::new(),
                            seen_connections: HashMap::new(),
                            seen_children: HashMap::new(),
                            tracked_since: Instant::now(),
                        });
                    }
                    Ok(Signal::SessionExited { pid, id, .. }) => {
                        tracked.remove(&pid);
                        correlation.remove_session(id);
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Security monitor lagged {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            // --- Full scan: FD enumeration (every 3s) ---
            _ = full_interval.tick() => {
                if tracked.is_empty() {
                    continue;
                }

                let mut signals: Vec<Signal> = Vec::new();

                for (&pid, ts) in &mut tracked {
                    let file_signals = file_monitor::scan_fds(
                        pid,
                        ts.session.id,
                        &ts.session.cli_type,
                        &ts.session.working_dir,
                        &rules,
                        &mut ts.seen_files,
                        dedup_window,
                    );
                    // Correlation uses the rule's raw severity via
                    // is_exfil_relevant, not the signal's effective
                    // severity. That way downgrades for known-safe
                    // CLIs silence individual alerts without breaking
                    // exfil detection for the same files.
                    for sig in &file_signals {
                        if let Signal::SensitiveFileAccess { path, .. } = sig {
                            if rules.is_exfil_relevant(path) {
                                correlation.record_file_access(ts.session.id, path);
                            }
                        }
                    }
                    signals.extend(file_signals);
                }

                // Periodic dedup pruning
                notif_dedup.prune();

                dispatch_signals(
                    &signals, &mut correlation, &mut notif_dedup, &tx, &tracked, &notify_min_severity,
                );
            }

            // --- Fast scan: network + process + inotify (every 500ms) ---
            _ = fast_interval.tick() => {
                if tracked.is_empty() {
                    continue;
                }

                let mut signals: Vec<Signal> = Vec::new();

                for (&pid, ts) in &mut tracked {
                    // Network connection scanning
                    let net_signals = net_monitor::scan_connections(
                        pid,
                        ts.session.id,
                        &ts.session.cli_type,
                        &rules,
                        &mut ts.seen_connections,
                        dedup_window,
                    );
                    signals.extend(net_signals);

                    // Child process scanning (fallback when no proc connector)
                    #[cfg(target_os = "linux")]
                    let do_poll_children = !has_proc_connector;
                    #[cfg(target_os = "macos")]
                    let do_poll_children = true;

                    if do_poll_children {
                        let child_signals = process_monitor::scan_children(
                            pid,
                            ts.session.id,
                            &ts.session.cli_type,
                            &rules,
                            &mut ts.seen_children,
                            dedup_window,
                        );
                        signals.extend(child_signals);
                    }
                }

                // Process inotify events (Linux)
                #[cfg(target_os = "linux")]
                if let Some(ref mut iw) = inotify_state {
                    process_inotify_events(
                        iw,
                        &tracked,
                        &rules,
                        &mut correlation,
                        &mut inotify_seen,
                        dedup_window,
                        &mut signals,
                    );
                }

                // Process kqueue events (macOS)
                #[cfg(target_os = "macos")]
                if let Some((ref mut watcher, ref watched_dirs)) = kqueue_state {
                    process_kqueue_events(
                        watcher,
                        watched_dirs,
                        &tracked,
                        &rules,
                        &mut inotify_seen,
                        dedup_window,
                        &mut signals,
                    );
                }

                dispatch_signals(
                    &signals, &mut correlation, &mut notif_dedup, &tx, &tracked, &notify_min_severity,
                );
            }

            // --- Proc connector: instant process event detection (Linux) ---
            Some(event_pid) = proc_rx.recv() => {
                if tracked.is_empty() {
                    continue;
                }

                if let Some(tracked_pid) = find_ancestor_session(event_pid, &tracked) {
                    if let Some(ts) = tracked.get(&tracked_pid) {
                        let signals = process_monitor::check_single_exec(
                            event_pid,
                            tracked_pid,
                            ts.session.id,
                            &ts.session.cli_type,
                            &rules,
                        );
                        dispatch_signals(
                            &signals,
                            &mut correlation,
                            &mut notif_dedup,
                            &tx,
                            &tracked,
                            &notify_min_severity,
                        );
                    }
                }
            }
        }
    }
}

/// Read and process inotify events from both directory and file watches.
/// Deduplicates by path: same file won't generate signals more than once per dedup_window.
#[cfg(target_os = "linux")]
fn process_inotify_events(
    iw: &mut file_monitor::InotifyWatches,
    tracked: &HashMap<u32, TrackedSecuritySession>,
    rules: &SecurityRules,
    correlation: &mut CorrelationTracker,
    seen: &mut HashMap<PathBuf, Instant>,
    dedup_window: Duration,
    signals: &mut Vec<Signal>,
) {
    let tracked_pids: Vec<(u32, u64, CliType)> = tracked
        .values()
        .map(|ts| (ts.session.pid, ts.session.id, ts.session.cli_type.clone()))
        .collect();

    let mut buf = [0u8; 4096];
    if let Ok(events) = iw.inotify.read_events(&mut buf) {
        for event in events {
            // File watches: WD identifies the file directly (no name field)
            let mut matched_file = false;
            for (wd, file_path) in &iw.file_watches {
                if event.wd == *wd {
                    if is_inotify_dedup(file_path, seen, dedup_window) {
                        matched_file = true;
                        break;
                    }
                    let inotify_signals =
                        file_monitor::check_inotify_access(file_path, &tracked_pids, rules);
                    record_file_correlations(&inotify_signals, correlation, rules);
                    signals.extend(inotify_signals);
                    matched_file = true;
                    break;
                }
            }

            // Directory watches: event.name identifies the file within the dir
            if !matched_file {
                if let Some(name) = event.name {
                    for (wd, dir) in &iw.dir_watches {
                        if event.wd == *wd {
                            let full_path = dir.join(name);
                            if is_inotify_dedup(&full_path, seen, dedup_window) {
                                break;
                            }
                            let inotify_signals = file_monitor::check_inotify_access(
                                &full_path,
                                &tracked_pids,
                                rules,
                            );
                            record_file_correlations(&inotify_signals, correlation, rules);
                            signals.extend(inotify_signals);
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Process kqueue events for macOS.
#[cfg(target_os = "macos")]
fn process_kqueue_events(
    watcher: &mut kqueue::Watcher,
    watched_dirs: &[PathBuf],
    tracked: &HashMap<u32, TrackedSecuritySession>,
    rules: &SecurityRules,
    seen: &mut HashMap<PathBuf, Instant>,
    dedup_window: Duration,
    signals: &mut Vec<Signal>,
) {
    if let Some(_event) = watcher.poll(None) {
        let tracked_pids: Vec<(u32, u64, CliType)> = tracked
            .values()
            .map(|ts| (ts.session.pid, ts.session.id, ts.session.cli_type.clone()))
            .collect();
        for dir in watched_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if is_inotify_dedup(&path, seen, dedup_window) {
                        continue;
                    }
                    let kq_signals =
                        file_monitor::check_inotify_access(&path, &tracked_pids, rules);
                    signals.extend(kq_signals);
                }
            }
        }
    }
}

/// Check if a path was already seen within the dedup window.
/// Returns true (skip) if already seen, false (process) if new.
fn is_inotify_dedup(
    path: &Path,
    seen: &mut HashMap<PathBuf, Instant>,
    dedup_window: Duration,
) -> bool {
    if let Some(&seen_at) = seen.get(path) {
        if seen_at.elapsed() < dedup_window {
            return true;
        }
    }
    seen.insert(path.to_path_buf(), Instant::now());
    // Periodic cleanup: drop expired entries
    if seen.len() > 100 {
        seen.retain(|_, t| t.elapsed() < dedup_window);
    }
    false
}

/// Record file accesses from signals into the correlation tracker.
/// Uses `rules.is_exfil_relevant(path)` rather than the signal's own
/// severity so that per-CLI downgrades (Info) don't drop the file
/// access from exfil correlation — the raw rule severity is what
/// determines credential-grade relevance, not the effective severity
/// after accessor attribution.
#[cfg(target_os = "linux")]
fn record_file_correlations(
    signals: &[Signal],
    correlation: &mut CorrelationTracker,
    rules: &SecurityRules,
) {
    for sig in signals {
        if let Signal::SensitiveFileAccess {
            path, session_id, ..
        } = sig
        {
            if rules.is_exfil_relevant(path) {
                correlation.record_file_access(*session_id, path);
            }
        }
    }
}

/// Dispatch signals: run correlation checks, send notifications, and broadcast.
fn dispatch_signals(
    signals: &[Signal],
    correlation: &mut CorrelationTracker,
    notif_dedup: &mut NotificationDedup,
    tx: &broadcast::Sender<Signal>,
    tracked: &HashMap<u32, TrackedSecuritySession>,
    notify_min_severity: &Severity,
) {
    let mut extra_signals: Vec<Signal> = Vec::new();

    // Check for exfil correlations on network signals
    for sig in signals {
        if let Signal::UnexpectedNetwork {
            session_id,
            pid,
            cli_type,
            remote_addr,
            ..
        } = sig
        {
            if let Some(exfil) = correlation.check_exfil(*session_id, *pid, cli_type, remote_addr) {
                extra_signals.push(exfil);
            }
        }
    }

    // Send all signals with time-windowed notification dedup.
    // Desktop notifications are suppressed when:
    // - Signal severity is below notify_min_severity (configurable in agent.toml)
    // - Session is in warmup period (first 10s after discovery, avoids
    //   flooding when initial scan finds all pre-existing open files/connections)
    // Events always flow to audit log, TUI, and IPC regardless of this filter.
    let warmup = Duration::from_secs(SESSION_WARMUP_SECS);
    for sig in signals.iter().chain(extra_signals.iter()) {
        let sig_severity = signal_severity(sig);
        let below_threshold = sig_severity.is_some_and(|sev| sev < notify_min_severity);
        let in_warmup = signal_session_pid(sig)
            .and_then(|pid| tracked.get(&pid))
            .is_some_and(|ts| ts.tracked_since.elapsed() < warmup);
        if !below_threshold && !in_warmup {
            let dedup_key = make_dedup_key(sig, tracked);
            if notif_dedup.should_notify(&dedup_key) {
                notify_security_event(sig);
            }
        }
        let _ = tx.send(sig.clone());
    }
}

/// Extract the PID from a security signal (used for warmup checks).
fn signal_session_pid(signal: &Signal) -> Option<u32> {
    match signal {
        Signal::SensitiveFileAccess { pid, .. }
        | Signal::BoundaryViolation { pid, .. }
        | Signal::UnexpectedNetwork { pid, .. }
        | Signal::DangerousCommand { pid, .. }
        | Signal::SuspiciousChild { pid, .. }
        | Signal::ExfilAttempt { pid, .. } => Some(*pid),
        _ => None,
    }
}

/// Extract the severity from a security signal (used for notification filtering).
/// Signals without an explicit severity field are assigned a default level.
fn signal_severity(signal: &Signal) -> Option<&Severity> {
    // Keep a static ref for signals that need a default severity.
    static WARNING: Severity = Severity::Warning;
    static CRITICAL: Severity = Severity::Critical;
    match signal {
        Signal::SensitiveFileAccess { severity, .. }
        | Signal::DangerousCommand { severity, .. } => Some(severity),
        Signal::ExfilAttempt { .. } => Some(&CRITICAL),
        Signal::UnexpectedNetwork { .. }
        | Signal::BoundaryViolation { .. }
        | Signal::SuspiciousChild { .. } => Some(&WARNING),
        _ => None,
    }
}

/// Create a dedup key for notification throttling.
/// Includes session_id so different sessions always get their own notifications.
fn make_dedup_key(signal: &Signal, _tracked: &HashMap<u32, TrackedSecuritySession>) -> String {
    match signal {
        Signal::UnexpectedNetwork {
            session_id,
            remote_addr,
            remote_port,
            ..
        } => format!("net:{session_id}:{remote_addr}:{remote_port}"),
        Signal::SensitiveFileAccess {
            session_id, path, ..
        } => format!("file:{session_id}:{}", path.display()),
        Signal::BoundaryViolation {
            session_id, path, ..
        } => format!("boundary:{session_id}:{}", path.display()),
        Signal::DangerousCommand {
            session_id,
            matched_text,
            ..
        } => format!("cmd:{session_id}:{matched_text}"),
        Signal::SuspiciousChild {
            session_id,
            child_pid,
            ..
        } => format!("child:{session_id}:{child_pid}"),
        Signal::ExfilAttempt {
            session_id,
            file_path,
            remote_addr,
            ..
        } => format!("exfil:{session_id}:{}:{remote_addr}", file_path.display()),
        _ => format!("other:{signal:?}"),
    }
}

/// Send desktop notification for security events.
fn notify_security_event(signal: &Signal) {
    match signal {
        Signal::SensitiveFileAccess {
            cli_type,
            pid,
            path,
            rule_name,
            severity,
            ..
        } => {
            let urgency = severity_to_urgency(severity);
            alert::notify_resource(
                &format!("{cli_type}: {rule_name}"),
                &format!("PID {pid} accessed {}", path.display()),
                urgency,
            );
        }

        Signal::BoundaryViolation {
            cli_type,
            pid,
            path,
            project_dir,
            ..
        } => {
            alert::notify_resource(
                &format!("{cli_type}: boundary violation"),
                &format!(
                    "PID {pid} writing outside project: {} (project: {})",
                    path.display(),
                    project_dir.display(),
                ),
                "normal",
            );
        }

        Signal::UnexpectedNetwork {
            cli_type,
            pid,
            remote_addr,
            remote_port,
            ..
        } => {
            alert::notify_resource(
                &format!("{cli_type}: unknown connection"),
                &format!("PID {pid} connected to {remote_addr}:{remote_port}"),
                "normal",
            );
        }

        Signal::DangerousCommand {
            cli_type,
            pid,
            rule_name,
            matched_text,
            severity,
            ..
        } => {
            let urgency = severity_to_urgency(severity);
            alert::notify_resource(
                &format!("{cli_type}: {rule_name}"),
                &format!("PID {pid}: {matched_text}"),
                urgency,
            );
        }

        Signal::SuspiciousChild {
            cli_type,
            pid,
            child_pid,
            child_cmdline,
            ..
        } => {
            alert::notify_resource(
                &format!("{cli_type}: suspicious child process"),
                &format!("PID {pid} spawned {child_pid}: {child_cmdline}"),
                "normal",
            );
        }

        Signal::ExfilAttempt {
            cli_type,
            pid,
            file_path,
            remote_addr,
            ..
        } => {
            alert::notify_resource(
                &format!("{cli_type}: EXFILTRATION ATTEMPT"),
                &format!(
                    "PID {pid} read {} then connected to {remote_addr}",
                    file_path.display(),
                ),
                "critical",
            );
        }

        _ => {}
    }
}

fn severity_to_urgency(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::Warning => "normal",
        Severity::Info => "low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_detects_exfil_pattern() {
        let dedup = Duration::from_secs(300);
        let mut tracker = CorrelationTracker::new(10, dedup);
        let cli = CliType::ClaudeCode;
        let path = PathBuf::from("/home/user/.ssh/id_rsa");

        tracker.record_file_access(1, &path);

        let result = tracker.check_exfil(1, 100, &cli, "8.8.8.8");
        assert!(result.is_some());
        match result.unwrap() {
            Signal::ExfilAttempt {
                session_id,
                file_path,
                remote_addr,
                ..
            } => {
                assert_eq!(session_id, 1);
                assert_eq!(file_path, path);
                assert_eq!(remote_addr, "8.8.8.8");
            }
            _ => panic!("Expected ExfilAttempt signal"),
        }
    }

    #[test]
    fn correlation_dedup_within_window() {
        let dedup = Duration::from_secs(300);
        let mut tracker = CorrelationTracker::new(10, dedup);
        let cli = CliType::ClaudeCode;
        let path = PathBuf::from("/home/user/.ssh/id_rsa");

        tracker.record_file_access(1, &path);

        let r1 = tracker.check_exfil(1, 100, &cli, "8.8.8.8");
        assert!(r1.is_some());

        let r2 = tracker.check_exfil(1, 100, &cli, "8.8.8.8");
        assert!(r2.is_none(), "Should not duplicate within dedup window");
    }

    #[test]
    fn correlation_different_session_no_match() {
        let dedup = Duration::from_secs(300);
        let mut tracker = CorrelationTracker::new(10, dedup);
        let cli = CliType::ClaudeCode;
        let path = PathBuf::from("/home/user/.ssh/id_rsa");

        tracker.record_file_access(1, &path);

        let result = tracker.check_exfil(2, 200, &cli, "8.8.8.8");
        assert!(result.is_none(), "Different session should not correlate");
    }

    #[test]
    fn correlation_cleanup_on_session_exit() {
        let dedup = Duration::from_secs(300);
        let mut tracker = CorrelationTracker::new(10, dedup);
        let cli = CliType::ClaudeCode;
        let path = PathBuf::from("/home/user/.ssh/id_rsa");

        tracker.record_file_access(1, &path);
        tracker.remove_session(1);

        let result = tracker.check_exfil(1, 100, &cli, "8.8.8.8");
        assert!(result.is_none(), "Removed session should not correlate");
    }

    #[test]
    fn severity_to_urgency_mapping() {
        assert_eq!(severity_to_urgency(&Severity::Critical), "critical");
        assert_eq!(severity_to_urgency(&Severity::Warning), "normal");
        assert_eq!(severity_to_urgency(&Severity::Info), "low");
    }

    #[test]
    fn notification_dedup_within_window() {
        let mut dedup = NotificationDedup::new(Duration::from_secs(300));
        assert!(dedup.should_notify("test:key"));
        assert!(!dedup.should_notify("test:key"));
        assert!(dedup.should_notify("different:key"));
    }

    #[test]
    fn dedup_key_includes_session() {
        let tracked = HashMap::new();
        let sig1 = Signal::UnexpectedNetwork {
            session_id: 1,
            pid: 100,
            cli_type: CliType::ClaudeCode,
            remote_addr: "8.8.8.8".into(),
            remote_port: 443,
        };
        let sig2 = Signal::UnexpectedNetwork {
            session_id: 2,
            pid: 200,
            cli_type: CliType::ClaudeCode,
            remote_addr: "8.8.8.8".into(),
            remote_port: 443,
        };
        let key1 = make_dedup_key(&sig1, &tracked);
        let key2 = make_dedup_key(&sig2, &tracked);
        assert_ne!(
            key1, key2,
            "Different sessions must produce different dedup keys"
        );
    }

    #[test]
    fn is_exfil_relevant_survives_known_safe_for_downgrade() {
        // A Critical rule with known_safe_for populated must still be
        // exfil-relevant: downgrading an individual file-read alert
        // for a whitelisted CLI should NOT suppress the cross-signal
        // exfil correlation.
        use crate::security::rules::{FileRule, SecurityRules};
        use std::collections::HashSet;

        let target = PathBuf::from("/home/test/.aws/credentials");
        let rules = SecurityRules {
            file_rules: vec![FileRule {
                name: "AWS credentials".into(),
                paths: vec![target.clone()],
                severity: Severity::Critical,
                known_safe: None,
                known_safe_for: Some(vec![CliType::ClaudeCode]),
            }],
            allowed_ips: HashSet::new(),
            command_rules: Vec::new(),
        };

        assert!(
            rules.is_exfil_relevant(&target),
            "downgrade-eligible Critical rule must stay exfil-relevant"
        );

        // And an actual correlation + check_exfil round still fires.
        let mut tracker = CorrelationTracker::new(10, Duration::from_secs(300));
        tracker.record_file_access(1, &target);
        let result = tracker.check_exfil(1, 100, &CliType::ClaudeCode, "8.8.8.8");
        assert!(
            result.is_some(),
            "exfil correlation must fire even when individual alert would be downgraded"
        );
    }
}
