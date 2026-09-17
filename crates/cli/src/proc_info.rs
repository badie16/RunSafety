/// Read RSS for a process. Returns bytes.
#[allow(dead_code)]
pub fn read_rss(pid: u32) -> Option<u64> {
    platform::read_rss(pid)
}

/// Read CPU ticks for a process. Returns total CPU time units.
pub fn read_cpu_ticks(pid: u32) -> Option<u64> {
    platform::read_cpu_ticks(pid)
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;

    pub fn read_rss(pid: u32) -> Option<u64> {
        let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("VmRSS:") {
                let kb_str = val.trim().strip_suffix(" kB")?;
                let kb: u64 = kb_str.trim().parse().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }

    pub fn read_cpu_ticks(pid: u32) -> Option<u64> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after_comm = stat.rfind(')')? + 2;
        if after_comm >= stat.len() {
            return None;
        }
        let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
        let utime: u64 = fields.get(11)?.parse().ok()?;
        let stime: u64 = fields.get(12)?.parse().ok()?;
        let cutime: u64 = fields.get(13)?.parse().ok()?;
        let cstime: u64 = fields.get(14)?.parse().ok()?;
        Some(utime + stime + cutime + cstime)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use libproc::libproc::pid_rusage::{pidrusage, RUsageInfoV2};
    use libproc::libproc::proc_pid;
    use libproc::libproc::task_info::TaskAllInfo;

    pub fn read_rss(pid: u32) -> Option<u64> {
        let info: TaskAllInfo = proc_pid::pidinfo(pid as i32, 0).ok()?;
        Some(info.ptinfo.pti_resident_size)
    }

    pub fn read_cpu_ticks(pid: u32) -> Option<u64> {
        let usage: RUsageInfoV2 = pidrusage(pid as i32).ok()?;
        Some(usage.ri_user_time.saturating_add(usage.ri_system_time))
    }
}
