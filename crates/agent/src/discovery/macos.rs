use std::path::PathBuf;

use anyhow::Result;
use libproc::libproc::proc_pid;
use libproc::processes;

use super::{DiscoveredProcess, ProcessScanner};

pub struct MacosScanner;

impl ProcessScanner for MacosScanner {
    fn scan(&self) -> Result<Vec<DiscoveredProcess>> {
        let mut results = Vec::new();

        let pids = processes::pids_by_type(processes::ProcFilter::All)
            .map_err(|e| anyhow::anyhow!("pids_by_type failed: {e}"))?;

        for pid in pids {
            let pid_i32 = pid as i32;
            if pid == 0 {
                continue;
            }

            // Get the binary path
            let path = match proc_pid::pidpath(pid_i32) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Get cmdline args via procargs
            let cmdline_args = match get_proc_args(pid_i32) {
                Some(args) if !args.is_empty() => args,
                _ => vec![path.clone()],
            };

            // Get cwd from BSD info (vnode of current directory)
            let cwd = get_cwd(pid_i32).unwrap_or_default();

            results.push(DiscoveredProcess {
                pid,
                cmdline_args,
                cwd,
            });
        }

        Ok(results)
    }
}

/// Read process arguments via KERN_PROCARGS2 sysctl.
/// Returns None if the process cannot be inspected (permission denied, zombie, etc).
fn get_proc_args(pid: i32) -> Option<Vec<String>> {
    // sysctl kern.procargs2 returns:
    //   argc (4 bytes, int32)
    //   exec_path (null-terminated)
    //   padding nulls
    //   argv[0] (null-terminated)
    //   argv[1] (null-terminated)
    //   ...
    use std::mem;

    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;

    // First call: get buffer size
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

    // Read argc
    let argc = i32::from_ne_bytes(buf[..4].try_into().ok()?) as usize;
    let mut pos = 4;

    // Skip exec_path (null-terminated)
    while pos < buf.len() && buf[pos] != 0 {
        pos += 1;
    }
    // Skip trailing nulls after exec_path
    while pos < buf.len() && buf[pos] == 0 {
        pos += 1;
    }

    // Read argc arguments
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
        pos += 1; // skip null terminator
    }

    Some(args)
}

/// Get the current working directory of a process.
/// Uses proc_pidinfo with PROC_PIDVNODEPATHINFO.
fn get_cwd(pid: i32) -> Option<PathBuf> {
    proc_pid::pidcwd(pid).ok()
}
