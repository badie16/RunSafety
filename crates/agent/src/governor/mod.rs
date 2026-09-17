#[cfg(target_os = "linux")]
pub mod cgroups;
#[cfg(target_os = "linux")]
pub mod monitor;
#[cfg(target_os = "linux")]
pub mod ulimit;

#[cfg(target_os = "macos")]
pub mod macos_enforcer;
#[cfg(target_os = "macos")]
pub mod macos_monitor;

#[cfg(target_os = "windows")]
pub mod windows_monitor;

use std::collections::HashMap;
#[cfg(not(target_os = "windows"))]
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use tokio::sync::broadcast;
use tracing::{info, warn};

use runsafety_shared::config::{GovernorAction, GovernorConfig};
use runsafety_shared::types::{CliType, Session, SessionStatus, Signal};

use crate::alert;
#[cfg(target_os = "linux")]
use cgroups::CgroupGovernor;
#[cfg(target_os = "macos")]
use macos_enforcer::MacosEnforcer;
#[cfg(target_os = "macos")]
use macos_monitor::{read_cpu_ticks, read_rss};
#[cfg(target_os = "linux")]
use monitor::{read_cpu_ticks, read_rss};
#[cfg(target_os = "linux")]
use ulimit::UlimitGovernor;
#[cfg(target_os = "windows")]
use windows_monitor::read_rss;

// --- Public types ---

/// Resolved memory limits for one session.
pub struct SessionLimits {
    pub memory_high: u64,
    pub memory_max: Option<u64>, // None in warn/throttle mode
    pub leak_min_growth_bytes: u64,
}

/// Strategy for enforcing memory limits on discovered processes.
pub trait LimitEnforcer: Send {
    fn apply(&self, pid: u32, session_id: u64, limits: &SessionLimits) -> anyhow::Result<()>;
    fn cleanup(&self, session_id: u64);
    fn check_oom(&self, session_id: u64) -> bool;
    fn name(&self) -> &str;
}

/// No-op enforcer for warn mode: monitor only, no cgroups.
struct NoopEnforcer;

impl LimitEnforcer for NoopEnforcer {
    fn apply(&self, _: u32, _: u64, _: &SessionLimits) -> anyhow::Result<()> {
        Ok(())
    }
    fn cleanup(&self, _: u64) {}
    fn check_oom(&self, _: u64) -> bool {
        false
    }
    fn name(&self) -> &str {
        "warn-only"
    }
}

// --- Ring buffer ---

#[derive(Debug, Clone, Copy)]
pub(crate) struct ResourceReading {
    rss_bytes: u64,
}

pub struct RingBuffer {
    buf: Vec<ResourceReading>,
    capacity: usize,
    write_idx: usize,
    count: usize,
}

impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            capacity,
            write_idx: 0,
            count: 0,
        }
    }

    pub fn push(&mut self, reading: ResourceReading) {
        if self.buf.len() < self.capacity {
            self.buf.push(reading);
        } else {
            self.buf[self.write_idx] = reading;
        }
        self.write_idx = (self.write_idx + 1) % self.capacity;
        if self.count < self.capacity {
            self.count += 1;
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.count
    }

    fn ordered(&self) -> Vec<ResourceReading> {
        if self.count < self.capacity {
            self.buf[..self.count].to_vec()
        } else {
            let mut out = Vec::with_capacity(self.capacity);
            out.extend_from_slice(&self.buf[self.write_idx..]);
            out.extend_from_slice(&self.buf[..self.write_idx]);
            out
        }
    }

    /// Detect monotonic RSS growth over the most recent `min_readings` samples.
    /// `min_growth` is the minimum total growth in bytes to qualify as a leak.
    pub fn detect_leak(&self, min_readings: usize, min_growth: u64) -> Option<u64> {
        if self.count < min_readings || min_readings < 2 {
            return None;
        }
        let all = self.ordered();
        let window = &all[all.len() - min_readings..];

        for pair in window.windows(2) {
            if pair[1].rss_bytes < pair[0].rss_bytes {
                return None;
            }
        }

        let growth = window.last()?.rss_bytes.saturating_sub(window[0].rss_bytes);
        if growth >= min_growth {
            Some(growth)
        } else {
            None
        }
    }

    pub fn peak_rss(&self) -> u64 {
        self.buf.iter().map(|r| r.rss_bytes).max().unwrap_or(0)
    }
}

// --- Helpers ---

/// Parse human-readable size ("2GB", "1.5GB", "512MB") to bytes.
pub fn parse_memory_limit(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num_str, mult) = if let Some(n) = s.strip_suffix("GB").or_else(|| s.strip_suffix("gb")) {
        (n, 1024u64 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("MB").or_else(|| s.strip_suffix("mb")) {
        (n, 1024u64 * 1024)
    } else if let Some(n) = s.strip_suffix("KB").or_else(|| s.strip_suffix("kb")) {
        (n, 1024u64)
    } else {
        (s, 1u64)
    };
    let num: f64 = num_str.trim().parse().ok()?;
    if num < 0.0 {
        return None;
    }
    Some((num * mult as f64) as u64)
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

const DEFAULT_HIGH: u64 = 2 * 1024 * 1024 * 1024; // 2 GB
const DEFAULT_MAX: u64 = 3 * 1024 * 1024 * 1024; // 3 GB

/// Resolve memory limits for a CLI type from governor config.
/// Lookup order: [governor.cli.<type>] -> [governor.defaults] -> hardcoded fallback.
const DEFAULT_LEAK_MIN_GROWTH: u64 = 100 * 1024 * 1024; // 100 MB

pub fn resolve_limits(cli_type: &CliType, config: &GovernorConfig) -> SessionLimits {
    let cli_cfg = config.cli.get(cli_type.config_key());

    let high_str = cli_cfg
        .and_then(|c| c.memory_high.as_deref())
        .or(config.defaults.memory_high.as_deref());
    let max_str = cli_cfg
        .and_then(|c| c.memory_max.as_deref())
        .or(config.defaults.memory_max.as_deref());
    let leak_str = cli_cfg
        .and_then(|c| c.leak_min_growth.as_deref())
        .or(config.defaults.leak_min_growth.as_deref());

    let memory_high = high_str
        .and_then(parse_memory_limit)
        .unwrap_or(DEFAULT_HIGH);

    let memory_max = if config.action == GovernorAction::Kill {
        Some(max_str.and_then(parse_memory_limit).unwrap_or(DEFAULT_MAX))
    } else {
        None
    };

    let leak_min_growth_bytes = leak_str
        .and_then(parse_memory_limit)
        .or_else(|| parse_memory_limit(&config.leak_min_growth))
        .unwrap_or(DEFAULT_LEAK_MIN_GROWTH);

    SessionLimits {
        memory_high,
        memory_max,
        leak_min_growth_bytes,
    }
}

// --- Internal tracking ---

struct TrackedSession {
    session: Session,
    rss_history: RingBuffer,
    prev_cpu_ticks: Option<u64>,
    prev_cpu_time: Option<Instant>,
    limits: SessionLimits,
    warn_notified: bool,
    urgent_notified: bool,
    leak_notified: bool,
}

fn restart_process(ts: &TrackedSession) -> Option<u32> {
    if ts.session.cmdline.is_empty() {
        return None;
    }
    let mut cmd = Command::new(&ts.session.cmdline[0]);
    if ts.session.cmdline.len() > 1 {
        cmd.args(&ts.session.cmdline[1..]);
    }
    cmd.current_dir(&ts.session.working_dir);
    #[cfg(not(target_os = "windows"))]
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    match cmd.spawn() {
        Ok(child) => {
            let pid = child.id();
            info!("Restarted {} as PID {pid}", ts.session.cli_type);
            Some(pid)
        }
        Err(e) => {
            warn!("Restart failed for {}: {e}", ts.session.cli_type);
            None
        }
    }
}

// --- Main loop ---

pub async fn resource_monitor_loop(
    mut rx: broadcast::Receiver<Signal>,
    tx: broadcast::Sender<Signal>,
    config: GovernorConfig,
) {
    // Select enforcer based on action mode
    let enforcer: Box<dyn LimitEnforcer> = match config.action {
        GovernorAction::Warn => {
            info!("Resource governor: warn-only (monitoring)");
            Box::new(NoopEnforcer)
        }
        GovernorAction::Throttle | GovernorAction::Kill => {
            #[cfg(target_os = "linux")]
            {
                match CgroupGovernor::new() {
                    Some(cg) => {
                        info!(
                            "Resource governor: {} via cgroups v2 ({})",
                            config.action_label(),
                            cg.base_path().display(),
                        );
                        Box::new(cg)
                    }
                    None => {
                        warn!("cgroups v2 unavailable, falling back to ulimit");
                        Box::new(UlimitGovernor)
                    }
                }
            }
            #[cfg(target_os = "macos")]
            {
                info!("Resource governor: {} via setrlimit", config.action_label(),);
                Box::new(MacosEnforcer)
            }
            #[cfg(target_os = "windows")]
            {
                warn!("No enforcer available on Windows, using warn-only");
                Box::new(NoopEnforcer)
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            {
                warn!("No enforcer available on this platform, using warn-only");
                Box::new(NoopEnforcer)
            }
        }
    };

    let monitor_interval = Duration::from_secs(config.monitor_interval_secs);
    let leak_readings = (config.leak_window_secs / config.monitor_interval_secs.max(1)) as usize;
    let ring_capacity = leak_readings.max(60);

    let mut tracked: HashMap<u32, TrackedSession> = HashMap::new();
    let mut interval = tokio::time::interval(monitor_interval);

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(Signal::SessionDiscovered(session)) => {
                        let pid = session.pid;
                        let limits = resolve_limits(&session.cli_type, &config);

                        // Apply cgroup/ulimit (no-op in warn mode)
                        match enforcer.apply(pid, session.id, &limits) {
                            Ok(()) => {
                                let mode_desc = match (&config.action, limits.memory_max) {
                                    (GovernorAction::Warn, _) => "monitoring".to_string(),
                                    (_, Some(max)) => format!(
                                        "high={} max={}",
                                        format_bytes(limits.memory_high),
                                        format_bytes(max),
                                    ),
                                    (_, None) => format!(
                                        "high={} (throttle)",
                                        format_bytes(limits.memory_high),
                                    ),
                                };
                                info!(
                                    "{} {} (PID {pid}): {mode_desc}",
                                    enforcer.name(),
                                    session.cli_type,
                                );
                            }
                            Err(e) => warn!(
                                "Failed to apply limit for {} (PID {pid}): {e}",
                                session.cli_type,
                            ),
                        }

                        tracked.insert(pid, TrackedSession {
                            session: Session {
                                memory_high: Some(limits.memory_high),
                                memory_max: limits.memory_max,
                                ..session
                            },
                            rss_history: RingBuffer::new(ring_capacity),
                            prev_cpu_ticks: None,
                            prev_cpu_time: None,
                            limits,
                            warn_notified: false,
                            urgent_notified: false,
                            leak_notified: false,
                        });
                    }

                    Ok(Signal::SessionExited { id, pid, ref cli_type }) => {
                        if let Some(ts) = tracked.remove(&pid) {
                            let was_oom = enforcer.check_oom(id);
                            let was_stressed = matches!(
                                ts.session.status,
                                SessionStatus::HighMemory | SessionStatus::Leaking
                            );

                            if was_oom || was_stressed {
                                let peak = ts.rss_history.peak_rss();
                                info!(
                                    "OOM: {} (PID {pid}), peak {}",
                                    cli_type, format_bytes(peak),
                                );
                                let _ = tx.send(Signal::OomKill {
                                    session_id: id,
                                    pid,
                                    cli_type: cli_type.clone(),
                                    peak_rss_bytes: peak,
                                });
                                alert::notify_resource(
                                    &format!("{cli_type} killed (OOM)"),
                                    &format!(
                                        "PID {pid} died. Peak RSS: {}",
                                        format_bytes(peak),
                                    ),
                                    "critical",
                                );
                                if config.auto_restart {
                                    if let Some(new_pid) = restart_process(&ts) {
                                        alert::notify_resource(
                                            &format!("{cli_type} restarted"),
                                            &format!("New PID: {new_pid}"),
                                            "normal",
                                        );
                                    }
                                }
                            }
                            enforcer.cleanup(id);
                        }
                    }

                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Resource monitor lagged {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            _ = interval.tick() => {
                let mut signals: Vec<Signal> = Vec::new();

                for (&pid, ts) in &mut tracked {
                    let rss = match read_rss(pid) {
                        Some(r) => r,
                        None => continue,
                    };

                    // CPU tracking
                    let cpu_ticks = read_cpu_ticks(pid);
                    let _cpu_pct = match (ts.prev_cpu_ticks, ts.prev_cpu_time, cpu_ticks) {
                        (Some(prev), Some(prev_t), Some(now)) => {
                            let elapsed = prev_t.elapsed().as_secs_f32();
                            if elapsed > 0.0 {
                                let delta = now.saturating_sub(prev) as f32;
                                (delta / 100.0 / elapsed) * 100.0
                            } else { 0.0 }
                        }
                        _ => 0.0,
                    };
                    if let Some(t) = cpu_ticks {
                        ts.prev_cpu_ticks = Some(t);
                        ts.prev_cpu_time = Some(Instant::now());
                    }

                    ts.rss_history.push(ResourceReading { rss_bytes: rss });

                    // --- Tiered memory thresholds ---
                    let high = ts.limits.memory_high;
                    let warn_at = (high as f64 * config.warn_threshold as f64) as u64;
                    let urgent_at = (high as f64 * config.urgent_threshold as f64) as u64;

                    if rss > urgent_at {
                        if ts.session.status != SessionStatus::Leaking {
                            ts.session.status = SessionStatus::HighMemory;
                        }
                        if !ts.urgent_notified {
                            ts.urgent_notified = true;
                            ts.warn_notified = true; // skip warning if we jumped straight to urgent
                            info!(
                                "URGENT: {} (PID {pid}) {} / {} high",
                                ts.session.cli_type,
                                format_bytes(rss), format_bytes(high),
                            );
                            signals.push(Signal::MemoryUrgent {
                                session_id: ts.session.id,
                                pid,
                                cli_type: ts.session.cli_type.clone(),
                                rss_bytes: rss,
                                high_bytes: high,
                            });
                            alert::notify_resource(
                                &format!("{}: save your work", ts.session.cli_type),
                                &format!(
                                    "PID {pid}: {} / {} soft limit — throttling imminent",
                                    format_bytes(rss), format_bytes(high),
                                ),
                                "critical",
                            );
                        }
                    } else if rss > warn_at {
                        if ts.session.status != SessionStatus::Leaking {
                            ts.session.status = SessionStatus::HighMemory;
                        }
                        if !ts.warn_notified {
                            ts.warn_notified = true;
                            info!(
                                "High memory: {} (PID {pid}) {} / {} high",
                                ts.session.cli_type,
                                format_bytes(rss), format_bytes(high),
                            );
                            signals.push(Signal::MemoryWarning {
                                session_id: ts.session.id,
                                pid,
                                cli_type: ts.session.cli_type.clone(),
                                rss_bytes: rss,
                                high_bytes: high,
                            });
                            alert::notify_resource(
                                &format!("{} high memory", ts.session.cli_type),
                                &format!(
                                    "PID {pid}: {} / {} soft limit",
                                    format_bytes(rss), format_bytes(high),
                                ),
                                "normal",
                            );
                        }
                    } else if ts.session.status == SessionStatus::HighMemory {
                        // Memory dropped back below warning threshold
                        ts.session.status = SessionStatus::Running;
                        ts.warn_notified = false;
                        ts.urgent_notified = false;
                    }

                    // --- Leak detection ---
                    if let Some(growth) = ts.rss_history.detect_leak(leak_readings, ts.limits.leak_min_growth_bytes) {
                        ts.session.status = SessionStatus::Leaking;
                        if !ts.leak_notified {
                            ts.leak_notified = true;
                            info!(
                                "Leak: {} (PID {pid}) grew {} over {}s",
                                ts.session.cli_type,
                                format_bytes(growth),
                                config.leak_window_secs,
                            );
                            signals.push(Signal::LeakDetected {
                                session_id: ts.session.id,
                                pid,
                                cli_type: ts.session.cli_type.clone(),
                                rss_bytes: rss,
                                duration_secs: config.leak_window_secs,
                            });
                            alert::notify_resource(
                                &format!("{} memory leak", ts.session.cli_type),
                                &format!(
                                    "PID {pid}: grew {} over {}s, now {}",
                                    format_bytes(growth),
                                    config.leak_window_secs,
                                    format_bytes(rss),
                                ),
                                "critical",
                            );
                            if config.auto_restart {
                                info!("Killing leaking {} (PID {pid})", ts.session.cli_type);
                                #[cfg(not(target_os = "windows"))]
                                {
                                    let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
                                    let _ = nix::sys::signal::kill(
                                        nix_pid,
                                        nix::sys::signal::Signal::SIGTERM,
                                    );
                                }
                                #[cfg(target_os = "windows")]
                                {
                                    // On Windows, we can't easily kill a process by PID
                                    // without using the Windows API. For now, we just log it.
                                    warn!("Auto-restart not implemented on Windows");
                                }
                            }
                        }
                    }
                }

                for sig in signals {
                    let _ = tx.send(sig);
                }
            }
        }
    }
}

// Helper on GovernorConfig (avoids putting it in shared just for logging)
trait GovernorConfigExt {
    fn action_label(&self) -> &str;
}

impl GovernorConfigExt for GovernorConfig {
    fn action_label(&self) -> &str {
        match self.action {
            GovernorAction::Warn => "warn",
            GovernorAction::Throttle => "throttle",
            GovernorAction::Kill => "kill",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runsafety_shared::config::MemoryLimits;

    #[test]
    fn ring_buffer_basic() {
        let mut rb = RingBuffer::new(3);
        assert_eq!(rb.len(), 0);
        rb.push(ResourceReading { rss_bytes: 100 });
        rb.push(ResourceReading { rss_bytes: 200 });
        assert_eq!(rb.len(), 2);
        let ordered = rb.ordered();
        assert_eq!(ordered[0].rss_bytes, 100);
        assert_eq!(ordered[1].rss_bytes, 200);
    }

    #[test]
    fn ring_buffer_wraps() {
        let mut rb = RingBuffer::new(3);
        rb.push(ResourceReading { rss_bytes: 1 });
        rb.push(ResourceReading { rss_bytes: 2 });
        rb.push(ResourceReading { rss_bytes: 3 });
        rb.push(ResourceReading { rss_bytes: 4 });
        assert_eq!(rb.len(), 3);
        let ordered = rb.ordered();
        assert_eq!(ordered[0].rss_bytes, 2);
        assert_eq!(ordered[1].rss_bytes, 3);
        assert_eq!(ordered[2].rss_bytes, 4);
    }

    #[test]
    fn leak_detected_monotonic_growth() {
        let mut rb = RingBuffer::new(10);
        let base = 100 * 1024 * 1024;
        for i in 0..5 {
            rb.push(ResourceReading {
                rss_bytes: base + i * 1024 * 1024,
            });
        }
        // 4MB growth, threshold 1MB → detected
        let result = rb.detect_leak(5, 1024 * 1024);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 4 * 1024 * 1024);
    }

    #[test]
    fn leak_not_detected_below_threshold() {
        let mut rb = RingBuffer::new(10);
        let base = 100 * 1024 * 1024;
        for i in 0..5 {
            rb.push(ResourceReading {
                rss_bytes: base + i * 1024 * 1024,
            });
        }
        // 4MB growth, threshold 100MB → not detected
        assert!(rb.detect_leak(5, 100 * 1024 * 1024).is_none());
    }

    #[test]
    fn leak_not_detected_non_monotonic() {
        let mut rb = RingBuffer::new(10);
        rb.push(ResourceReading {
            rss_bytes: 100_000_000,
        });
        rb.push(ResourceReading {
            rss_bytes: 110_000_000,
        });
        rb.push(ResourceReading {
            rss_bytes: 105_000_000,
        });
        rb.push(ResourceReading {
            rss_bytes: 115_000_000,
        });
        rb.push(ResourceReading {
            rss_bytes: 120_000_000,
        });
        assert!(rb.detect_leak(5, 1024 * 1024).is_none());
    }

    #[test]
    fn leak_not_detected_stable_memory() {
        let mut rb = RingBuffer::new(10);
        for _ in 0..5 {
            rb.push(ResourceReading {
                rss_bytes: 500_000_000,
            });
        }
        assert!(rb.detect_leak(5, 1024 * 1024).is_none());
    }

    #[test]
    fn leak_not_detected_insufficient_readings() {
        let mut rb = RingBuffer::new(10);
        rb.push(ResourceReading {
            rss_bytes: 100_000_000,
        });
        rb.push(ResourceReading {
            rss_bytes: 200_000_000,
        });
        assert!(rb.detect_leak(5, 1024 * 1024).is_none());
    }

    #[test]
    fn peak_rss_tracks_maximum() {
        let mut rb = RingBuffer::new(5);
        rb.push(ResourceReading { rss_bytes: 100 });
        rb.push(ResourceReading { rss_bytes: 500 });
        rb.push(ResourceReading { rss_bytes: 300 });
        assert_eq!(rb.peak_rss(), 500);
    }

    #[test]
    fn parse_limit_integer_gb() {
        assert_eq!(parse_memory_limit("2GB"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_memory_limit("1gb"), Some(1024 * 1024 * 1024));
    }

    #[test]
    fn parse_limit_float_gb() {
        assert_eq!(parse_memory_limit("1.5GB"), Some(1_610_612_736));
    }

    #[test]
    fn parse_limit_mb() {
        assert_eq!(parse_memory_limit("512MB"), Some(512 * 1024 * 1024));
    }

    #[test]
    fn parse_limit_kb() {
        assert_eq!(parse_memory_limit("1024KB"), Some(1024 * 1024));
    }

    #[test]
    fn parse_limit_bytes() {
        assert_eq!(parse_memory_limit("4096"), Some(4096));
    }

    #[test]
    fn parse_limit_invalid() {
        assert_eq!(parse_memory_limit("abc"), None);
        assert_eq!(parse_memory_limit(""), None);
        assert_eq!(parse_memory_limit("-1GB"), None);
    }

    #[test]
    fn format_bytes_display() {
        assert_eq!(format_bytes(500), "500B");
        assert_eq!(format_bytes(2048), "2.0KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0MB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.0GB");
    }

    fn test_config(action: GovernorAction) -> GovernorConfig {
        let mut cli = HashMap::new();
        cli.insert(
            "ClaudeCode".to_string(),
            MemoryLimits {
                memory_high: Some("3GB".to_string()),
                memory_max: Some("4GB".to_string()),
                leak_min_growth: Some("500MB".to_string()),
            },
        );
        GovernorConfig {
            action,
            defaults: MemoryLimits {
                memory_high: Some("2GB".to_string()),
                memory_max: Some("3GB".to_string()),
                leak_min_growth: None,
            },
            cli,
            ..GovernorConfig::default()
        }
    }

    #[test]
    fn resolve_limits_cli_override() {
        let config = test_config(GovernorAction::Kill);
        let limits = resolve_limits(&CliType::ClaudeCode, &config);
        assert_eq!(limits.memory_high, 3 * 1024 * 1024 * 1024);
        assert_eq!(limits.memory_max, Some(4 * 1024 * 1024 * 1024));
    }

    #[test]
    fn resolve_limits_fallback_to_defaults() {
        let config = test_config(GovernorAction::Kill);
        let limits = resolve_limits(&CliType::Aider, &config);
        assert_eq!(limits.memory_high, 2 * 1024 * 1024 * 1024);
        assert_eq!(limits.memory_max, Some(3 * 1024 * 1024 * 1024));
    }

    #[test]
    fn resolve_limits_throttle_no_max() {
        let config = test_config(GovernorAction::Throttle);
        let limits = resolve_limits(&CliType::ClaudeCode, &config);
        assert_eq!(limits.memory_high, 3 * 1024 * 1024 * 1024);
        assert!(limits.memory_max.is_none());
    }

    #[test]
    fn resolve_limits_warn_no_max() {
        let config = test_config(GovernorAction::Warn);
        let limits = resolve_limits(&CliType::ClaudeCode, &config);
        assert_eq!(limits.memory_high, 3 * 1024 * 1024 * 1024);
        assert!(limits.memory_max.is_none());
    }
}
