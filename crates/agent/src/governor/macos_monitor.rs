use libproc::libproc::pid_rusage::{pidrusage, RUsageInfoV2};
use libproc::libproc::proc_pid;
use libproc::libproc::task_info::TaskAllInfo;

/// Read RSS from task_info. Returns bytes.
pub fn read_rss(pid: u32) -> Option<u64> {
    let info: TaskAllInfo = proc_pid::pidinfo(pid as i32, 0).ok()?;
    Some(info.ptinfo.pti_resident_size)
}

/// Read user + system CPU time from rusage. Returns total CPU ticks (nanoseconds).
/// We return nanoseconds and the caller converts to a rate, matching the Linux
/// interface where ticks are clock_t units. The tick-to-seconds conversion in
/// the main loop handles the unit difference.
pub fn read_cpu_ticks(pid: u32) -> Option<u64> {
    let usage: RUsageInfoV2 = pidrusage(pid as i32).ok()?;
    // ri_user_time and ri_system_time are in nanoseconds
    Some(usage.ri_user_time.saturating_add(usage.ri_system_time))
}
