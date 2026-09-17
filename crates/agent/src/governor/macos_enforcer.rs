use anyhow::Result;
use tracing::{debug, info};

use super::{format_bytes, LimitEnforcer, SessionLimits};

/// macOS enforcer using setrlimit(RLIMIT_RSS) for soft limiting
/// and SIGTERM for kill mode.
///
/// macOS does not have cgroups. RLIMIT_RSS is advisory on modern macOS
/// but signals intent. For kill mode, we monitor and send SIGTERM when
/// the process exceeds memory_max.
pub struct MacosEnforcer;

impl LimitEnforcer for MacosEnforcer {
    #[allow(clippy::unnecessary_cast)]
    fn apply(&self, pid: u32, _session_id: u64, limits: &SessionLimits) -> Result<()> {
        // Set RLIMIT_RSS as soft limit (advisory on macOS)
        let soft = limits.memory_high;
        let hard = limits.memory_max.unwrap_or(libc::RLIM_INFINITY as u64);
        let rlim = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        let ret = unsafe {
            // macOS does not have prlimit; we cannot set rlimit on another process
            // directly. We use setrlimit which only works on the current process.
            // For cross-process limiting, we rely on the monitoring loop to
            // send SIGTERM when memory_max is exceeded.
            //
            // Log the intended limit for monitoring purposes.
            libc::setrlimit(libc::RLIMIT_RSS, &rlim)
        };
        if ret != 0 {
            debug!(
                "setrlimit(RLIMIT_RSS) returned {}: {} (advisory, continuing)",
                ret,
                std::io::Error::last_os_error()
            );
        }

        info!(
            "macOS limits for PID {pid}: soft={}, hard={}",
            format_bytes(soft),
            if hard == libc::RLIM_INFINITY as u64 {
                "unlimited".to_string()
            } else {
                format_bytes(hard)
            }
        );
        Ok(())
    }

    fn cleanup(&self, _session_id: u64) {
        // No cgroup directories to clean up on macOS
    }

    fn check_oom(&self, _session_id: u64) -> bool {
        // macOS does not have cgroup OOM events.
        // OOM detection is handled by the monitoring loop checking if the
        // process disappeared while in HighMemory state.
        false
    }

    fn name(&self) -> &str {
        "macOS setrlimit"
    }
}
