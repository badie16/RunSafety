use anyhow::Result;
use runsafety_shared::types::Signal;

pub fn read_rss(pid: u32) -> Option<u64> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, TRUE};
        use windows_sys::Win32::System::Threading::{
            GetProcessMemoryInfo, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };
        use windows_sys::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS;

        unsafe {
            let process_handle: HANDLE = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pid,
            );

            if process_handle == 0 {
                return None;
            }

            let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;

            let result = GetProcessMemoryInfo(
                process_handle,
                &mut counters,
                std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            );

            CloseHandle(process_handle);

            if result == TRUE {
                Some(counters.WorkingSetSize as u64)
            } else {
                None
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

pub async fn resource_monitor_loop(
    mut rx: tokio::sync::broadcast::Receiver<Signal>,
    tx: tokio::sync::broadcast::Sender<Signal>,
    config: runsafety_shared::config::GovernorConfig,
) {
    use tracing::{debug, warn};

    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(config.monitor_interval_secs));
    let mut sessions: std::collections::HashMap<u32, SessionTracker> =
        std::collections::HashMap::new();

    loop {
        interval.tick().await;

        // Collect signals
        loop {
            match rx.try_recv() {
                Ok(signal) => match &signal {
                    Signal::SessionDiscovered(session) => {
                        sessions.insert(
                            session.pid,
                            SessionTracker {
                                session_id: session.id,
                                cli_type: session.cli_type.clone(),
                                memory_high: session.memory_high.unwrap_or(0),
                                memory_max: session.memory_max.unwrap_or(0),
                                last_rss: 0,
                                leak_start: None,
                            },
                        );
                    }
                    Signal::SessionExited { pid, .. } => {
                        sessions.remove(pid);
                    }
                    _ => {}
                },
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                    warn!("Resource monitor lagged {n} events");
                }
                Err(_) => break,
            }
        }

        // Monitor memory usage
        for (pid, tracker) in &sessions {
            if let Some(rss) = read_rss(*pid) {
                // Check memory thresholds
                if tracker.memory_high > 0 {
                    let usage_percent = rss as f64 / tracker.memory_high as f64;

                    if usage_percent >= config.urgent_threshold {
                        let _ = tx.send(Signal::MemoryUrgent {
                            session_id: tracker.session_id,
                            pid: *pid,
                            cli_type: tracker.cli_type.clone(),
                            rss_bytes: rss,
                            high_bytes: tracker.memory_high,
                        });
                    } else if usage_percent >= config.warn_threshold {
                        let _ = tx.send(Signal::MemoryWarning {
                            session_id: tracker.session_id,
                            pid: *pid,
                            cli_type: tracker.cli_type.clone(),
                            rss_bytes: rss,
                            high_bytes: tracker.memory_high,
                        });
                    }
                }

                // Detect memory leaks (monotonic growth)
                if rss > tracker.last_rss + 10_000_000 {
                    // 10MB growth
                    if tracker.leak_start.is_none() {
                        debug!("Potential memory leak started for PID {}", pid);
                    }
                }

                debug!("PID {}: RSS = {} bytes", pid, rss);
            }
        }
    }
}

struct SessionTracker {
    session_id: u64,
    cli_type: runsafety_shared::types::CliType,
    memory_high: u64,
    memory_max: u64,
    last_rss: u64,
    leak_start: Option<u64>,
}
