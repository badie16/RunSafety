use std::path::PathBuf;

use anyhow::{Context, Result};
use runsafety_shared::types::CliType;

use super::{DiscoveredProcess, ProcessScanner};

pub struct WindowsScanner;

impl ProcessScanner for WindowsScanner {
    fn scan(&self) -> Result<Vec<DiscoveredProcess>> {
        let mut processes = Vec::new();

        // Use WMI to query running processes
        let output = std::process::Command::new("wmic")
            .args(["process", "get", "ProcessId,CommandLine,ExecutablePath", "/format:csv"])
            .output()
            .context("failed to execute wmic")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                let pid_str = parts[0].trim();
                let cmdline = parts[1].trim();
                let _exe_path = parts[2].trim();

                if let Ok(pid) = pid_str.parse::<u32>() {
                    if pid > 0 && !cmdline.is_empty() {
                        let cmdline_args: Vec<String> =
                            cmdline.split_whitespace().map(String::from).collect();
                        let cwd = get_process_cwd(pid).unwrap_or_else(|| PathBuf::from("."));

                        processes.push(DiscoveredProcess {
                            pid,
                            cmdline_args,
                            cwd,
                        });
                    }
                }
            }
        }

        Ok(processes)
    }
}

fn get_process_cwd(pid: u32) -> Option<PathBuf> {
    // On Windows, we can try to get the current directory using PowerShell
    let output = std::process::Command::new("powershell")
        .args([
            "-Command",
            &format!("Get-Process -Id {pid} | Select-Object -ExpandProperty Path"),
        ])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let path = stdout.trim();
    if !path.is_empty() {
        Some(PathBuf::from(path).parent()?.to_path_buf())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runsafety_shared::config::CliPattern;

    fn test_patterns() -> Vec<CliPattern> {
        vec![
            CliPattern {
                name: "claude".into(),
                cli_type: "ClaudeCode".into(),
                patterns: vec![
                    "claude".into(),
                    "claude-code".into(),
                    "@anthropic/claude-code".into(),
                ],
                memory_limit: None,
            },
            CliPattern {
                name: "codex".into(),
                cli_type: "Codex".into(),
                patterns: vec!["codex".into(), "openai-codex".into()],
                memory_limit: None,
            },
        ]
    }

    #[test]
    fn windows_scanner_can_scan() {
        let scanner = WindowsScanner;
        // This test will only pass on Windows
        if cfg!(target_os = "windows") {
            let result = scanner.scan();
            assert!(result.is_ok());
        }
    }
}
