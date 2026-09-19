use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::UnixStream;

use runsafety_shared::protocol::{
    EventNotification, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, SessionInfo,
};
use runsafety_shared::types::{Session, Signal};

pub struct IpcClient {
    reader: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    writer: OwnedWriteHalf,
    next_id: u64,
}

impl IpcClient {
    pub async fn connect() -> Result<Self> {
        let socket_path = socket_path()?;
        let stream = UnixStream::connect(&socket_path)
            .await
            .with_context(|| format!("Cannot connect to daemon at {}", socket_path.display()))?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(reader).lines(),
            writer,
            next_id: 1,
        })
    }

    pub async fn list_sessions(&mut self) -> Result<Vec<SessionInfo>> {
        let resp = self.request("ListSessions", serde_json::json!({})).await?;
        let result = resp.result.context("No result in response")?;
        Ok(serde_json::from_value(result)?)
    }

    pub async fn get_events(
        &mut self,
        session_id: Option<u64>,
        severity: Option<String>,
        limit: usize,
    ) -> Result<Vec<EventNotification>> {
        let resp = self
            .request(
                "GetEvents",
                serde_json::json!({
                    "session_id": session_id,
                    "severity": severity,
                    "limit": limit,
                }),
            )
            .await?;
        let result = resp.result.context("No result in response")?;
        Ok(serde_json::from_value(result)?)
    }

    pub async fn subscribe(
        &mut self,
        session_id: Option<u64>,
        min_severity: Option<String>,
    ) -> Result<()> {
        let _resp = self
            .request(
                "Subscribe",
                serde_json::json!({
                    "session_id": session_id,
                    "min_severity": min_severity,
                }),
            )
            .await?;
        Ok(())
    }

    pub async fn inject_session(
        &mut self,
        session: &Session,
        rss_bytes: Option<u64>,
    ) -> Result<()> {
        let _resp = self
            .request(
                "InjectSession",
                serde_json::json!({
                    "session": session,
                    "rss_bytes": rss_bytes,
                }),
            )
            .await?;
        Ok(())
    }

    pub async fn inject_event(
        &mut self,
        signal: &Signal,
        rss_update: Option<(u32, u64)>,
    ) -> Result<()> {
        let _resp = self
            .request(
                "InjectEvent",
                serde_json::json!({
                    "signal": signal,
                    "rss_update": rss_update,
                }),
            )
            .await?;
        Ok(())
    }

    pub async fn get_analytics_summary(&mut self) -> Result<serde_json::Value> {
        let resp = self.request("GetAnalyticsSummary", serde_json::json!({})).await?;
        let result = resp.result.context("No result in response")?;
        Ok(result)
    }

    pub async fn list_plugins(&mut self) -> Result<Vec<super::tui::PluginInfo>> {
        let resp = self.request("ListPlugins", serde_json::json!({})).await?;
        let result = resp.result.context("No result in response")?;
        Ok(serde_json::from_value(result)?)
    }

    /// Read next line from the connection (used for subscription notifications).
    pub async fn next_notification(&mut self) -> Result<Option<JsonRpcNotification>> {
        match self.reader.next_line().await? {
            Some(line) => Ok(Some(serde_json::from_str(&line)?)),
            None => Ok(None),
        }
    }

    async fn request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<JsonRpcResponse> {
        let id = self.next_id;
        self.next_id += 1;
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id: Some(serde_json::json!(id)),
        };
        let mut json = serde_json::to_vec(&req)?;
        json.push(b'\n');
        self.writer.write_all(&json).await?;
        self.writer.flush().await?;

        let line = self
            .reader
            .next_line()
            .await?
            .context("Daemon closed connection")?;
        let resp: JsonRpcResponse = serde_json::from_str(&line)?;
        if let Some(err) = &resp.error {
            anyhow::bail!("RPC error {}: {}", err.code, err.message);
        }
        Ok(resp)
    }
}

pub fn socket_path() -> Result<std::path::PathBuf> {
    let data_dir = dirs::data_dir().context("Cannot determine XDG data directory")?;
    Ok(data_dir.join("runsafety").join("agent.sock"))
}
