use std::fs;

/// Read VmRSS from /proc/<pid>/status. Returns bytes.
pub fn read_rss(pid: u32) -> Option<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(val) = line.strip_prefix("VmRSS:") {
            let val = val.trim();
            let kb_str = val.strip_suffix(" kB")?;
            let kb: u64 = kb_str.trim().parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Read utime + stime from /proc/<pid>/stat. Returns total CPU ticks.
pub fn read_cpu_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm field (field 2) is in parens and can contain spaces.
    // Everything after the closing ')' is safe to split.
    let after_comm = stat.find(')')? + 2;
    if after_comm >= stat.len() {
        return None;
    }
    let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
    // After ") ": state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5)
    //   flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12)
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_own_rss() {
        let rss = read_rss(std::process::id());
        assert!(rss.is_some(), "should read own process RSS");
        assert!(rss.unwrap() > 0, "RSS should be non-zero");
    }

    #[test]
    fn read_own_cpu_ticks() {
        let ticks = read_cpu_ticks(std::process::id());
        assert!(ticks.is_some(), "should read own process CPU ticks");
    }

    #[test]
    fn read_nonexistent_pid() {
        assert!(read_rss(999_999_999).is_none());
        assert!(read_cpu_ticks(999_999_999).is_none());
    }
}
