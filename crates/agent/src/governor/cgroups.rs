use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::{debug, warn};

use super::{LimitEnforcer, SessionLimits};

pub struct CgroupGovernor {
    base: PathBuf,
}

impl CgroupGovernor {
    /// Detect cgroups v2 and set up the runsafety subtree.
    /// Returns None if cgroups v2 is unavailable or we lack permission.
    pub fn new() -> Option<Self> {
        if !PathBuf::from("/sys/fs/cgroup/cgroup.controllers").exists() {
            debug!("cgroups v2 not available");
            return None;
        }

        let parent = Self::find_parent()?;
        let base = parent.join("runsafety");

        if let Err(e) = fs::create_dir_all(&base) {
            debug!("Cannot create cgroup dir {}: {e}", base.display());
            return None;
        }

        // Enable memory controller in the parent so child groups can use it
        let parent_ctrl = parent.join("cgroup.subtree_control");
        let _ = fs::write(&parent_ctrl, "+memory");

        // Enable memory controller in our runsafety group for per-session children
        let base_ctrl = base.join("cgroup.subtree_control");
        let _ = fs::write(&base_ctrl, "+memory");

        // Verify memory controller is actually available
        let controllers = fs::read_to_string(base.join("cgroup.controllers")).ok()?;
        if !controllers.contains("memory") {
            warn!("Memory controller not delegated in {}", base.display());
            return None;
        }

        Some(Self { base })
    }

    fn find_parent() -> Option<PathBuf> {
        let content = fs::read_to_string("/proc/self/cgroup").ok()?;
        let rel_path = content.lines().next()?.strip_prefix("0::")?.trim();
        let our_cgroup = PathBuf::from("/sys/fs/cgroup").join(rel_path.trim_start_matches('/'));

        if let Some(parent) = our_cgroup.parent() {
            if parent.join("cgroup.subtree_control").exists() {
                return Some(parent.to_path_buf());
            }
        }

        let root = PathBuf::from("/sys/fs/cgroup");
        if root.join("cgroup.subtree_control").exists() {
            return Some(root);
        }

        None
    }

    pub fn base_path(&self) -> &PathBuf {
        &self.base
    }

    fn session_path(&self, session_id: u64) -> PathBuf {
        self.base.join(format!("session-{session_id}"))
    }
}

impl LimitEnforcer for CgroupGovernor {
    fn apply(&self, pid: u32, session_id: u64, limits: &SessionLimits) -> Result<()> {
        let path = self.session_path(session_id);
        fs::create_dir_all(&path).with_context(|| format!("creating cgroup {}", path.display()))?;

        // Soft limit (kernel throttles when hit)
        fs::write(path.join("memory.high"), limits.memory_high.to_string())
            .context("writing memory.high")?;

        // Hard limit: set to explicit value (kill mode) or unlimited (throttle mode)
        match limits.memory_max {
            Some(max) => {
                fs::write(path.join("memory.max"), max.to_string())
                    .context("writing memory.max")?;
            }
            None => {
                fs::write(path.join("memory.max"), "max").context("writing memory.max=max")?;
            }
        }

        // Move process into this cgroup
        fs::write(path.join("cgroup.procs"), pid.to_string())
            .with_context(|| format!("moving PID {pid} into cgroup"))?;

        Ok(())
    }

    fn cleanup(&self, session_id: u64) {
        let path = self.session_path(session_id);
        if let Err(e) = fs::remove_dir(&path) {
            debug!("Cgroup cleanup session-{session_id}: {e}");
        }
    }

    fn check_oom(&self, session_id: u64) -> bool {
        let events_path = self.session_path(session_id).join("memory.events");
        if let Ok(content) = fs::read_to_string(events_path) {
            for line in content.lines() {
                if let Some(count_str) = line.strip_prefix("oom_kill ") {
                    if let Ok(count) = count_str.trim().parse::<u64>() {
                        return count > 0;
                    }
                }
            }
        }
        false
    }

    fn name(&self) -> &str {
        "cgroups v2"
    }
}
