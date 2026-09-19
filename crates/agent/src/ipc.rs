use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(not(target_os = "windows"))]
use tokio::net::UnixListener;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, error, info, warn};

use runsafety_shared::protocol::{
    EventNotification, GetEventsParams, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    SessionInfo, SubscribeParams, SubscriptionFilter, INVALID_PARAMS, METHOD_NOT_FOUND,
    PARSE_ERROR,
};
use runsafety_shared::types::{Session, Signal};

#[cfg(target_os = "macos")]
use crate::governor::macos_monitor::read_rss;
#[cfg(target_os = "linux")]
use crate::governor::monitor::read_rss;
#[cfg(target_os = "windows")]
use crate::governor::windows_monitor::read_rss;

const EVENT_BUFFER_SIZE: usize = 1000;

#[derive(serde::Deserialize)]
struct InjectSessionParams {
    session: Session,
    rss_bytes: Option<u64>,
}

#[derive(serde::Deserialize)]
struct InjectEventParams {
    signal: Signal,
    /// Update demo RSS: (pid, rss_bytes)
    rss_update: Option<(u32, u64)>,
}

struct ServerState {
    sessions: HashMap<u64, Session>,
    events: VecDeque<EventNotification>,
    demo_rss: HashMap<u32, u64>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            events: VecDeque::with_capacity(EVENT_BUFFER_SIZE),
            demo_rss: HashMap::new(),
        }
    }

    fn apply_signal(&mut self, signal: &Signal) {
        match signal {
            Signal::SessionDiscovered(session) => {
                self.sessions.insert(session.id, session.clone());
            }
            Signal::SessionExited { id, .. } => {
                self.sessions.remove(id);
            }
            _ => {}
        }

        let entry = EventNotification {
            timestamp: unix_timestamp(),
            signal: signal.clone(),
        };
        if self.events.len() >= EVENT_BUFFER_SIZE {
            self.events.pop_front();
        }
        self.events.push_back(entry);
    }

    fn list_sessions(&self) -> Vec<SessionInfo> {
        let mut sessions: Vec<_> = self
            .sessions
            .values()
            .map(|s| {
                let rss = self
                    .demo_rss
                    .get(&s.pid)
                    .copied()
                    .or_else(|| read_rss(s.pid));
                SessionInfo::from_session(s, rss)
            })
            .collect();
        // Sort by ID (sequential) so new sessions always appear at the bottom
        // and existing sessions don't shift position.
        sessions.sort_by_key(|s| s.id);
        sessions
    }

    fn inject_signal(&mut self, signal: &Signal) {
        let entry = EventNotification {
            timestamp: unix_timestamp(),
            signal: signal.clone(),
        };
        if self.events.len() >= EVENT_BUFFER_SIZE {
            self.events.pop_front();
        }
        self.events.push_back(entry);
    }

    fn get_events(&self, params: &GetEventsParams) -> Vec<&EventNotification> {
        self.events
            .iter()
            .filter(|e| {
                if let Some(sid) = params.session_id {
                    if !event_matches_session(&e.signal, sid) {
                        return false;
                    }
                }
                if let Some(ref sev) = params.severity {
                    let filter = SubscriptionFilter {
                        session_id: None,
                        min_severity: Some(runsafety_shared::types::Severity::parse(sev)),
                    };
                    if !filter.matches(&e.signal) {
                        return false;
                    }
                }
                true
            })
            .rev()
            .take(params.limit)
            .collect()
    }
}

fn event_matches_session(signal: &Signal, sid: u64) -> bool {
    match signal {
        Signal::SessionDiscovered(s) => s.id == sid,
        Signal::SessionExited { id, .. } => *id == sid,
        Signal::MemoryWarning { session_id, .. }
        | Signal::MemoryUrgent { session_id, .. }
        | Signal::LeakDetected { session_id, .. }
        | Signal::OomKill { session_id, .. }
        | Signal::SensitiveFileAccess { session_id, .. }
        | Signal::BoundaryViolation { session_id, .. }
        | Signal::UnexpectedNetwork { session_id, .. }
        | Signal::DangerousCommand { session_id, .. }
        | Signal::SuspiciousChild { session_id, .. }
        | Signal::ExfilAttempt { session_id, .. } => *session_id == sid,
    }
}

/// Run the IPC server on a Unix socket.
///
/// Listens for JSON-RPC requests (one per line). Supports:
/// - ListSessions: returns active sessions with current RSS
/// - GetEvents: returns buffered events (filtered by session/severity)
/// - Subscribe: switches connection to streaming mode (events as notifications)
pub async fn ipc_server(
    socket_path: &Path,
    mut signal_rx: broadcast::Receiver<Signal>,
) -> Result<()> {
    // Remove stale socket file
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Set permissions: owner only (0o600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!("IPC server listening on {}", socket_path.display());

    let state = Arc::new(Mutex::new(ServerState::new()));

    // Separate channel for subscriber fan-out (avoids echoing back into main bus)
    let (notify_tx, _) = broadcast::channel::<Signal>(1024);

    // Background task: consume signals from main bus, update state, fan out to subscribers
    let state_updater = Arc::clone(&state);
    let fan_out_tx = notify_tx.clone();
    let updater = tokio::spawn(async move {
        loop {
            match signal_rx.recv().await {
                Ok(signal) => {
                    state_updater.lock().await.apply_signal(&signal);
                    let _ = fan_out_tx.send(signal);
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("IPC state updater lagged {n} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Accept connections
    tokio::pin!(updater);
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let client_state = Arc::clone(&state);
                        let client_notify = notify_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, client_state, client_notify).await {
                                debug!("Client disconnected: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {e}");
                    }
                }
            }
            _ = &mut updater => {
                info!("Signal channel closed, IPC server stopping");
                break;
            }
        }
    }

    // Cleanup socket
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

async fn handle_client(
    stream: tokio::net::UnixStream,
    state: Arc<Mutex<ServerState>>,
    notify_tx: broadcast::Sender<Signal>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = JsonRpcResponse::error(None, PARSE_ERROR, format!("Parse error: {e}"));
                write_line(&mut writer, &resp).await?;
                continue;
            }
        };

        match request.method.as_str() {
            "ListSessions" => {
                let sessions = state.lock().await.list_sessions();
                let resp = JsonRpcResponse::success(request.id, serde_json::to_value(&sessions)?);
                write_line(&mut writer, &resp).await?;
            }
            "GetEvents" => {
                let params: GetEventsParams = match serde_json::from_value(request.params) {
                    Ok(p) => p,
                    Err(e) => {
                        let resp = JsonRpcResponse::error(
                            request.id,
                            INVALID_PARAMS,
                            format!("Invalid params: {e}"),
                        );
                        write_line(&mut writer, &resp).await?;
                        continue;
                    }
                };
                let events: Vec<EventNotification> = state
                    .lock()
                    .await
                    .get_events(&params)
                    .into_iter()
                    .cloned()
                    .collect();
                let resp = JsonRpcResponse::success(request.id, serde_json::to_value(&events)?);
                write_line(&mut writer, &resp).await?;
            }
            "Subscribe" => {
                let params: SubscribeParams = match serde_json::from_value(request.params) {
                    Ok(p) => p,
                    Err(e) => {
                        let resp = JsonRpcResponse::error(
                            request.id,
                            INVALID_PARAMS,
                            format!("Invalid params: {e}"),
                        );
                        write_line(&mut writer, &resp).await?;
                        continue;
                    }
                };

                // ACK the subscribe request
                let resp =
                    JsonRpcResponse::success(request.id, serde_json::json!({"subscribed": true}));
                write_line(&mut writer, &resp).await?;

                // Enter streaming mode - blocks until client disconnects
                let filter = SubscriptionFilter::from_params(&params);
                let mut sub_rx = notify_tx.subscribe();

                loop {
                    match sub_rx.recv().await {
                        Ok(signal) => {
                            if !filter.matches(&signal) {
                                continue;
                            }
                            let notif = JsonRpcNotification::new(
                                "event",
                                serde_json::to_value(&EventNotification {
                                    timestamp: unix_timestamp(),
                                    signal,
                                })?,
                            );
                            if write_line(&mut writer, &notif).await.is_err() {
                                return Ok(()); // Client gone
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            let notif = JsonRpcNotification::new(
                                "lagged",
                                serde_json::json!({"missed": n}),
                            );
                            if write_line(&mut writer, &notif).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                return Ok(());
            }
            "InjectSession" => {
                let params: InjectSessionParams = match serde_json::from_value(request.params) {
                    Ok(p) => p,
                    Err(e) => {
                        let resp = JsonRpcResponse::error(
                            request.id,
                            INVALID_PARAMS,
                            format!("Invalid params: {e}"),
                        );
                        write_line(&mut writer, &resp).await?;
                        continue;
                    }
                };
                let signal = Signal::SessionDiscovered(params.session.clone());
                let mut st = state.lock().await;
                st.sessions
                    .insert(params.session.id, params.session.clone());
                st.inject_signal(&signal);
                if let Some(rss) = params.rss_bytes {
                    st.demo_rss.insert(params.session.pid, rss);
                }
                drop(st);
                let _ = notify_tx.send(signal);
                let resp =
                    JsonRpcResponse::success(request.id, serde_json::json!({"injected": true}));
                write_line(&mut writer, &resp).await?;
            }
            "InjectEvent" => {
                let params: InjectEventParams = match serde_json::from_value(request.params) {
                    Ok(p) => p,
                    Err(e) => {
                        let resp = JsonRpcResponse::error(
                            request.id,
                            INVALID_PARAMS,
                            format!("Invalid params: {e}"),
                        );
                        write_line(&mut writer, &resp).await?;
                        continue;
                    }
                };
                let mut st = state.lock().await;
                st.inject_signal(&params.signal);
                if let Some((pid, rss)) = params.rss_update {
                    st.demo_rss.insert(pid, rss);
                }
                drop(st);
                let _ = notify_tx.send(params.signal);
                let resp =
                    JsonRpcResponse::success(request.id, serde_json::json!({"injected": true}));
                write_line(&mut writer, &resp).await?;
            }
            "GetAnalyticsSummary" => {
                let st = state.lock().await;
                let total_sessions = st.sessions.len() as u64;
                let total_events = st.events.len() as u64;
                let mut events_by_cli: HashMap<String, u64> = HashMap::new();
                for ev in &st.events {
                    let cli = match &ev.signal {
                        Signal::SessionDiscovered(s) => format!("{}", s.cli_type),
                        Signal::SessionExited { cli_type, .. } => format!("{cli_type}"),
                        Signal::MemoryWarning { cli_type, .. } => format!("{cli_type}"),
                        Signal::MemoryUrgent { cli_type, .. } => format!("{cli_type}"),
                        Signal::LeakDetected { cli_type, .. } => format!("{cli_type}"),
                        Signal::OomKill { cli_type, .. } => format!("{cli_type}"),
                        Signal::SensitiveFileAccess { cli_type, .. } => format!("{cli_type}"),
                        Signal::BoundaryViolation { cli_type, .. } => format!("{cli_type}"),
                        Signal::UnexpectedNetwork { cli_type, .. } => format!("{cli_type}"),
                        Signal::DangerousCommand { cli_type, .. } => format!("{cli_type}"),
                        Signal::SuspiciousChild { cli_type, .. } => format!("{cli_type}"),
                        Signal::ExfilAttempt { cli_type, .. } => format!("{cli_type}"),
                    };
                    *events_by_cli.entry(cli).or_insert(0) += 1;
                }
                let summary = serde_json::json!({
                    "total_sessions": total_sessions,
                    "active_sessions": total_sessions,
                    "total_events": total_events,
                    "events_by_cli": events_by_cli,
                });
                let resp = JsonRpcResponse::success(request.id, summary);
                write_line(&mut writer, &resp).await?;
            }
            "ListPlugins" => {
                let plugins = serde_json::json!([
                    {"name": "SecurityPlugin", "version": "0.1.0", "description": "File/network/command blocking", "enabled": true},
                    {"name": "AnalyticsPlugin", "version": "0.1.0", "description": "Event analytics", "enabled": true},
                ]);
                let resp = JsonRpcResponse::success(request.id, plugins);
                write_line(&mut writer, &resp).await?;
            }
            other => {
                let resp = JsonRpcResponse::error(
                    request.id,
                    METHOD_NOT_FOUND,
                    format!("Unknown method: {other}"),
                );
                write_line(&mut writer, &resp).await?;
            }
        }
    }

    Ok(())
}

/// Run the IPC server on a Windows named pipe.
///
/// Listens for JSON-RPC requests (one per line). Supports:
/// - ListSessions: returns active sessions with current RSS
/// - GetEvents: returns buffered events (filtered by session/severity)
/// - Subscribe: switches connection to streaming mode (events as notifications)
#[cfg(target_os = "windows")]
pub async fn ipc_server_named_pipe(
    pipe_name: &str,
    mut signal_rx: broadcast::Receiver<Signal>,
) -> Result<()> {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    info!("IPC server listening on named pipe: {}", pipe_name);

    let state = Arc::new(Mutex::new(ServerState::new()));

    // Separate channel for subscriber fan-out (avoids echoing back into main bus)
    let (notify_tx, _) = broadcast::channel::<Signal>(1024);

    // Background task: consume signals from main bus, update state, fan out to subscribers
    let state_updater = Arc::clone(&state);
    let fan_out_tx = notify_tx.clone();
    let updater = tokio::spawn(async move {
        loop {
            match signal_rx.recv().await {
                Ok(signal) => {
                    state_updater.lock().await.apply_signal(&signal);
                    let _ = fan_out_tx.send(signal);
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("IPC state updater lagged {n} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Accept connections
    tokio::pin!(updater);
    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(pipe_name)?;

        tokio::select! {
            accept = server.connect() => {
                match accept {
                    Ok(()) => {
                        let client_state = Arc::clone(&state);
                        let client_notify = notify_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client_named_pipe(server, client_state, client_notify).await {
                                debug!("Client disconnected: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Named pipe accept error: {e}");
                    }
                }
            }
            _ = &mut updater => {
                info!("Signal channel closed, IPC server stopping");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
async fn handle_client_named_pipe(
    server: tokio::net::windows::named_pipe::NamedPipeServer,
    state: Arc<Mutex<ServerState>>,
    notify_tx: broadcast::Sender<Signal>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut reader, mut writer) = tokio::io::split(server);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);

        // Process complete lines
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&buf[..pos]).trim().to_string();
            buf.drain(..=pos);

            if line.is_empty() {
                continue;
            }

            let request: JsonRpcRequest = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    let resp = JsonRpcResponse::error(None, PARSE_ERROR, format!("Parse error: {e}"));
                    write_line_named_pipe(&mut writer, &resp).await?;
                    continue;
                }
            };

            match request.method.as_str() {
                "ListSessions" => {
                    let sessions = state.lock().await.list_sessions();
                    let resp = JsonRpcResponse::success(request.id, serde_json::to_value(&sessions)?);
                    write_line_named_pipe(&mut writer, &resp).await?;
                }
                "GetEvents" => {
                    let params: GetEventsParams = match serde_json::from_value(request.params) {
                        Ok(p) => p,
                        Err(e) => {
                            let resp = JsonRpcResponse::error(
                                request.id,
                                INVALID_PARAMS,
                                format!("Invalid params: {e}"),
                            );
                            write_line_named_pipe(&mut writer, &resp).await?;
                            continue;
                        }
                    };
                    let events: Vec<EventNotification> = state
                        .lock()
                        .await
                        .get_events(&params)
                        .into_iter()
                        .cloned()
                        .collect();
                    let resp = JsonRpcResponse::success(request.id, serde_json::to_value(&events)?);
                    write_line_named_pipe(&mut writer, &resp).await?;
                }
                "Subscribe" => {
                    let params: SubscribeParams = match serde_json::from_value(request.params) {
                        Ok(p) => p,
                        Err(e) => {
                            let resp = JsonRpcResponse::error(
                                request.id,
                                INVALID_PARAMS,
                                format!("Invalid params: {e}"),
                            );
                            write_line_named_pipe(&mut writer, &resp).await?;
                            continue;
                        }
                    };

                    // ACK the subscribe request
                    let resp =
                        JsonRpcResponse::success(request.id, serde_json::json!({"subscribed": true}));
                    write_line_named_pipe(&mut writer, &resp).await?;

                    // Enter streaming mode - blocks until client disconnects
                    let filter = SubscriptionFilter::from_params(&params);
                    let mut sub_rx = notify_tx.subscribe();

                    loop {
                        match sub_rx.recv().await {
                            Ok(signal) => {
                                if !filter.matches(&signal) {
                                    continue;
                                }
                                let notif = JsonRpcNotification::new(
                                    "event",
                                    serde_json::to_value(&EventNotification {
                                        timestamp: unix_timestamp(),
                                        signal,
                                    })?,
                                );
                                if write_line_named_pipe(&mut writer, &notif).await.is_err() {
                                    return Ok(()); // Client gone
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                let notif = JsonRpcNotification::new(
                                    "lagged",
                                    serde_json::json!({"missed": n}),
                                );
                                if write_line_named_pipe(&mut writer, &notif).await.is_err() {
                                    return Ok(());
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    return Ok(());
                }
                other => {
                    let resp = JsonRpcResponse::error(
                        request.id,
                        METHOD_NOT_FOUND,
                        format!("Unknown method: {other}"),
                    );
                    write_line_named_pipe(&mut writer, &resp).await?;
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
async fn write_line_named_pipe<T: serde::Serialize>(
    writer: &mut tokio::io::WriteHalf<tokio::net::windows::named_pipe::NamedPipeServer>,
    value: &T,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut json = serde_json::to_vec(value)?;
    json.push(b'\n');
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_line<T: serde::Serialize>(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    value: &T,
) -> Result<()> {
    let mut json = serde_json::to_vec(value)?;
    json.push(b'\n');
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use runsafety_shared::types::{CliType, SessionStatus};
    use std::path::PathBuf;

    fn test_session(id: u64, pid: u32) -> Session {
        Session {
            id,
            pid,
            cli_type: CliType::ClaudeCode,
            status: SessionStatus::Running,
            working_dir: PathBuf::from("/tmp/test"),
            started_at: 1000,
            memory_high: Some(3_000_000_000),
            memory_max: Some(4_000_000_000),
            cmdline: vec!["claude".into()],
        }
    }

    #[test]
    fn state_tracks_sessions() {
        let mut state = ServerState::new();
        let session = test_session(1, 100);

        state.apply_signal(&Signal::SessionDiscovered(session));
        assert_eq!(state.sessions.len(), 1);

        state.apply_signal(&Signal::SessionExited {
            id: 1,
            pid: 100,
            cli_type: CliType::ClaudeCode,
        });
        assert_eq!(state.sessions.len(), 0);
    }

    #[test]
    fn state_buffers_events() {
        let mut state = ServerState::new();
        let session = test_session(1, 100);
        state.apply_signal(&Signal::SessionDiscovered(session));
        assert_eq!(state.events.len(), 1);
    }

    #[test]
    fn event_buffer_caps_at_limit() {
        let mut state = ServerState::new();
        for i in 0..EVENT_BUFFER_SIZE + 50 {
            state.apply_signal(&Signal::MemoryWarning {
                session_id: 1,
                pid: 100,
                cli_type: CliType::ClaudeCode,
                rss_bytes: i as u64 * 1024,
                high_bytes: 3_000_000_000,
            });
        }
        assert_eq!(state.events.len(), EVENT_BUFFER_SIZE);
    }

    #[test]
    fn get_events_filters_by_session() {
        let mut state = ServerState::new();
        state.apply_signal(&Signal::MemoryWarning {
            session_id: 1,
            pid: 100,
            cli_type: CliType::ClaudeCode,
            rss_bytes: 1024,
            high_bytes: 2048,
        });
        state.apply_signal(&Signal::MemoryWarning {
            session_id: 2,
            pid: 200,
            cli_type: CliType::Codex,
            rss_bytes: 1024,
            high_bytes: 2048,
        });

        let params = GetEventsParams {
            session_id: Some(1),
            severity: None,
            limit: 100,
        };
        let events = state.get_events(&params);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn get_events_respects_limit() {
        let mut state = ServerState::new();
        for _ in 0..10 {
            state.apply_signal(&Signal::MemoryWarning {
                session_id: 1,
                pid: 100,
                cli_type: CliType::ClaudeCode,
                rss_bytes: 1024,
                high_bytes: 2048,
            });
        }
        let params = GetEventsParams {
            session_id: None,
            severity: None,
            limit: 3,
        };
        let events = state.get_events(&params);
        assert_eq!(events.len(), 3);
    }

    #[tokio::test]
    async fn ipc_roundtrip() {
        let dir = std::env::temp_dir().join(format!("runsafety-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("test.sock");

        let (tx, _rx) = broadcast::channel::<Signal>(128);
        let server_rx = tx.subscribe();
        let sock_clone = sock.clone();

        let server = tokio::spawn(async move { ipc_server(&sock_clone, server_rx).await });

        // Give server time to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send a session discovery so there's state
        let session = test_session(1, 100);
        tx.send(Signal::SessionDiscovered(session)).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect client
        let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        // ListSessions
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "ListSessions",
            "params": {},
            "id": 1
        });
        writer
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();

        let resp_line = lines.next_line().await.unwrap().unwrap();
        let resp: JsonRpcResponse = serde_json::from_str(&resp_line).unwrap();
        assert!(resp.error.is_none());
        let sessions: Vec<SessionInfo> = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, 1);

        // GetEvents
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "GetEvents",
            "params": {"limit": 10},
            "id": 2
        });
        writer
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();

        let resp_line = lines.next_line().await.unwrap().unwrap();
        let resp: JsonRpcResponse = serde_json::from_str(&resp_line).unwrap();
        assert!(resp.error.is_none());

        // Unknown method
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "Bogus",
            "params": {},
            "id": 3
        });
        writer
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .unwrap();

        let resp_line = lines.next_line().await.unwrap().unwrap();
        let resp: JsonRpcResponse = serde_json::from_str(&resp_line).unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);

        // Cleanup
        drop(writer);
        drop(lines);
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
