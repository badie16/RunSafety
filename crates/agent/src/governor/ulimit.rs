use anyhow::Result;
use tracing::debug;

use super::{LimitEnforcer, SessionLimits};

/// Fallback governor using prlimit(RLIMIT_AS) when cgroups are unavailable.
/// Less precise than cgroups: limits virtual address space, not RSS.
pub struct UlimitGovernor;

impl LimitEnforcer for UlimitGovernor {
    fn apply(&self, pid: u32, _session_id: u64, limits: &SessionLimits) -> Result<()> {
        // Use memory_max if set (kill mode), otherwise memory_high
        let limit = limits.memory_max.unwrap_or(limits.memory_high);
        let rlim = libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit,
        };
        let ret = unsafe {
            libc::prlimit(
                pid as libc::pid_t,
                libc::RLIMIT_AS,
                &rlim,
                std::ptr::null_mut(),
            )
        };
        if ret != 0 {
            anyhow::bail!(
                "prlimit({pid}, RLIMIT_AS, {limit}): {}",
                std::io::Error::last_os_error()
            );
        }
        debug!("Set RLIMIT_AS={limit} for PID {pid}");
        Ok(())
    }

    fn cleanup(&self, _session_id: u64) {}

    fn check_oom(&self, _session_id: u64) -> bool {
        false
    }

    fn name(&self) -> &str {
        "ulimit"
    }
}
