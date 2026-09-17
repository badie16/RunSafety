use std::collections::HashMap;
use std::time::{Duration, Instant};

use runsafety_shared::types::{CliType, Signal};

use super::rules::SecurityRules;

/// Suspicious child process patterns (binary names that should not be spawned by AI CLIs).
const SUSPICIOUS_BINARIES: &[&str] = &[
    "nc", "ncat", "netcat", "socat", "python", "python3", "perl", "ruby", "ssh", "scp", "sftp",
    "nmap", "masscan", "dig", "nslookup", "host",
];

/// Path patterns in child cmdlines that are known-safe (AI CLI hooks, plugins).
/// If the cmdline contains any of these, skip the suspicious binary check.
const SAFE_CHILD_PATTERNS: &[&str] = &[
    "/.claude/",
    "/.codex/",
    "/.gemini/",
    "/.cursor/",
    "/node_modules/.bin/",
    "GIT_PROTOCOL", // ssh spawned by git (git push/pull/fetch)
    "git-upload-pack",
    "git-receive-pack",
];

/// Scan child processes of a PID recursively.
/// Checks children's cmdlines against dangerous command patterns and suspicious binary names.
/// Uses time-windowed dedup: same child PID re-alerts after `dedup_window` expires.
pub fn scan_children(
    pid: u32,
    session_id: u64,
    cli_type: &CliType,
    rules: &SecurityRules,
    seen_children: &mut HashMap<u32, Instant>,
    dedup_window: Duration,
) -> Vec<Signal> {
    let mut signals = Vec::new();
    let children = get_all_descendants(pid);

    for child_pid in children {
        if let Some(&seen_at) = seen_children.get(&child_pid) {
            if seen_at.elapsed() < dedup_window {
                continue;
            }
        }

        let cmdline = match read_cmdline(child_pid) {
            Some(c) if !c.is_empty() => c,
            _ => continue,
        };

        // Check against dangerous command patterns
        if let Some((rule_name, severity)) = rules.match_command(&cmdline) {
            seen_children.insert(child_pid, Instant::now());
            signals.push(Signal::DangerousCommand {
                session_id,
                pid,
                cli_type: cli_type.clone(),
                rule_name: rule_name.to_string(),
                matched_text: truncate(&cmdline, 200),
                severity: severity.clone(),
            });
            continue;
        }

        // Check for suspicious binary names (skip known-safe paths like CLI hooks)
        if let Some(binary) = extract_binary_name(&cmdline) {
            if SUSPICIOUS_BINARIES.iter().any(|s| binary == *s) && !is_safe_child(&cmdline) {
                seen_children.insert(child_pid, Instant::now());
                signals.push(Signal::SuspiciousChild {
                    session_id,
                    pid,
                    cli_type: cli_type.clone(),
                    child_pid,
                    child_cmdline: truncate(&cmdline, 200),
                });
            }
        }
    }

    signals
}

/// Check a single PID's command line against security rules.
/// Used by the proc connector for instant exec event checking.
pub fn check_single_exec(
    child_pid: u32,
    parent_pid: u32,
    session_id: u64,
    cli_type: &CliType,
    rules: &SecurityRules,
) -> Vec<Signal> {
    let mut signals = Vec::new();
    let cmdline = match read_cmdline(child_pid) {
        Some(c) if !c.is_empty() => c,
        _ => return signals,
    };

    if let Some((rule_name, severity)) = rules.match_command(&cmdline) {
        signals.push(Signal::DangerousCommand {
            session_id,
            pid: parent_pid,
            cli_type: cli_type.clone(),
            rule_name: rule_name.to_string(),
            matched_text: truncate(&cmdline, 200),
            severity: severity.clone(),
        });
        return signals;
    }

    if let Some(binary) = extract_binary_name(&cmdline) {
        if SUSPICIOUS_BINARIES.iter().any(|s| binary == *s) && !is_safe_child(&cmdline) {
            signals.push(Signal::SuspiciousChild {
                session_id,
                pid: parent_pid,
                cli_type: cli_type.clone(),
                child_pid,
                child_cmdline: truncate(&cmdline, 200),
            });
        }
    }

    signals
}

/// Check if a child process cmdline matches a known-safe path pattern.
fn is_safe_child(cmdline: &str) -> bool {
    SAFE_CHILD_PATTERNS.iter().any(|p| cmdline.contains(p))
}

/// Extract the binary name from a cmdline (basename of first argument).
fn extract_binary_name(cmdline: &str) -> Option<String> {
    let first_arg = cmdline.split_whitespace().next()?;
    let binary = first_arg.rsplit('/').next()?;
    Some(binary.to_string())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

// --- Linux implementation ---

#[cfg(target_os = "linux")]
fn get_all_descendants(pid: u32) -> Vec<u32> {
    let mut descendants = Vec::new();
    let mut queue = vec![pid];

    while let Some(current) = queue.pop() {
        let children = read_children_linux(current);
        for child in &children {
            descendants.push(*child);
            queue.push(*child);
        }
    }

    descendants
}

#[cfg(target_os = "linux")]
fn read_children_linux(pid: u32) -> Vec<u32> {
    let path = format!("/proc/{pid}/task/{pid}/children");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
        .collect()
}

#[cfg(target_os = "linux")]
fn read_cmdline(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/cmdline");
    let bytes = std::fs::read(&path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let cmdline = bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    if cmdline.is_empty() {
        None
    } else {
        Some(cmdline)
    }
}

/// Read the parent PID of a process from /proc/pid/status.
#[cfg(target_os = "linux")]
pub fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(ppid_str) = line.strip_prefix("PPid:\t") {
            return ppid_str.trim().parse().ok();
        }
    }
    None
}

// --- macOS implementation ---

/// Get all descendant PIDs using sysctl KERN_PROC to find processes whose ppid matches.
#[cfg(target_os = "macos")]
fn get_all_descendants(pid: u32) -> Vec<u32> {
    use libproc::libproc::proc_pid;
    use libproc::processes;

    let mut descendants = Vec::new();
    let mut queue = vec![pid];

    // Get all PIDs once, then filter by ppid
    let all_pids = match processes::pids_by_type(processes::ProcFilter::All) {
        Ok(pids) => pids,
        Err(_) => return descendants,
    };

    while let Some(current) = queue.pop() {
        for &candidate in &all_pids {
            if candidate == 0 {
                continue;
            }
            if let Ok(info) =
                proc_pid::pidinfo::<libproc::libproc::bsd_info::BSDInfo>(candidate as i32, 0)
            {
                if info.pbi_ppid == current {
                    descendants.push(candidate);
                    queue.push(candidate);
                }
            }
        }
    }

    descendants
}

/// Read cmdline of a PID using KERN_PROCARGS2 sysctl (macOS).
#[cfg(target_os = "macos")]
fn read_cmdline(pid: u32) -> Option<String> {
    use std::mem;

    let pid_i32 = pid as i32;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid_i32];
    let mut size: libc::size_t = 0;

    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return None;
    }

    let mut buf = vec![0u8; size];
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return None;
    }
    buf.truncate(size);

    if buf.len() < mem::size_of::<i32>() {
        return None;
    }

    let argc = i32::from_ne_bytes(buf[..4].try_into().ok()?) as usize;
    let mut pos = 4;

    // Skip exec_path
    while pos < buf.len() && buf[pos] != 0 {
        pos += 1;
    }
    while pos < buf.len() && buf[pos] == 0 {
        pos += 1;
    }

    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        if pos >= buf.len() {
            break;
        }
        let start = pos;
        while pos < buf.len() && buf[pos] != 0 {
            pos += 1;
        }
        if let Ok(s) = std::str::from_utf8(&buf[start..pos]) {
            args.push(s.to_string());
        }
        pos += 1;
    }

    let cmdline = args.join(" ");
    if cmdline.is_empty() {
        None
    } else {
        Some(cmdline)
    }
}

/// Read the parent PID of a process (macOS).
#[cfg(target_os = "macos")]
pub fn read_ppid(pid: u32) -> Option<u32> {
    use libproc::libproc::proc_pid;
    let info = proc_pid::pidinfo::<libproc::libproc::bsd_info::BSDInfo>(pid as i32, 0).ok()?;
    Some(info.pbi_ppid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_binary_from_path() {
        assert_eq!(
            extract_binary_name("/usr/bin/python3 script.py"),
            Some("python3".into())
        );
        assert_eq!(extract_binary_name("nc -e /bin/bash"), Some("nc".into()));
        assert_eq!(extract_binary_name("ls -la"), Some("ls".into()));
    }

    #[test]
    fn get_own_descendants() {
        let descendants = get_all_descendants(std::process::id());
        assert!(descendants.len() < 10000);
    }

    #[test]
    fn read_own_cmdline() {
        let cmdline = read_cmdline(std::process::id());
        assert!(cmdline.is_some());
    }

    #[test]
    fn read_nonexistent_cmdline() {
        assert!(read_cmdline(999_999_999).is_none());
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is long", 7), "this is...");
    }

    #[test]
    fn suspicious_binary_check() {
        let suspicious = SUSPICIOUS_BINARIES;
        assert!(suspicious.contains(&"nc"));
        assert!(suspicious.contains(&"python3"));
        assert!(!suspicious.contains(&"cargo"));
    }
}
