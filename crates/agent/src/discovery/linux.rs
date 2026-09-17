use std::fs;
use std::path::PathBuf;

use anyhow::Result;

use super::{DiscoveredProcess, ProcessScanner};

pub struct LinuxScanner;

impl ProcessScanner for LinuxScanner {
    fn scan(&self) -> Result<Vec<DiscoveredProcess>> {
        let mut results = Vec::new();

        let proc_entries = fs::read_dir("/proc")?;
        for entry in proc_entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only numeric directories (PIDs)
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let proc_dir = entry.path();

            // Read cmdline (null-byte separated arguments)
            let cmdline_path = proc_dir.join("cmdline");
            let cmdline_bytes = match fs::read(&cmdline_path) {
                Ok(b) if !b.is_empty() => b,
                _ => continue, // Exited process or kernel thread
            };

            let cmdline_args: Vec<String> = cmdline_bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();

            if cmdline_args.is_empty() {
                continue;
            }

            // Read cwd symlink
            let cwd = fs::read_link(proc_dir.join("cwd")).unwrap_or_else(|_| PathBuf::new());

            results.push(DiscoveredProcess {
                pid,
                cmdline_args,
                cwd,
            });
        }

        Ok(results)
    }
}
