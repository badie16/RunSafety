use std::process::Command;

use tracing::{debug, warn};

/// Send a desktop notification.
/// Urgency: "low", "normal", "critical"
pub fn notify_resource(title: &str, body: &str, urgency: &str) {
    debug!("Notification [{urgency}]: {title} - {body}");
    if let Err(e) = send(title, body, urgency, None) {
        warn!("Desktop notification failed: {e}");
    }
}

/// Send a notification with an event index for clickable action.
#[allow(dead_code)]
pub fn notify_event(title: &str, body: &str, urgency: &str, event_idx: usize) {
    debug!("Notification [{urgency}]: {title} - {body} (event {event_idx})");
    if let Err(e) = send(title, body, urgency, Some(event_idx)) {
        warn!("Desktop notification failed: {e}");
    }
}

#[cfg(target_os = "linux")]
fn send(title: &str, body: &str, urgency: &str, event_idx: Option<usize>) -> anyhow::Result<()> {
    let mut cmd = Command::new("notify-send");
    cmd.arg("--app-name=runsafety")
        .arg(format!("--urgency={urgency}"))
        .arg("--icon=dialog-warning");

    if let Some(idx) = event_idx {
        cmd.arg("--action=open=Open in Runsafety");
        cmd.arg(format!("--hint=int:event-idx:{idx}"));
    }

    cmd.arg(title).arg(body).spawn()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn send(title: &str, body: &str, _urgency: &str, _event_idx: Option<usize>) -> anyhow::Result<()> {
    // Use osascript to display a macOS notification
    let script = format!(
        "display notification \"{}\" with title \"{}\" subtitle \"runsafety\"",
        body.replace('\\', "\\\\").replace('"', "\\\""),
        title.replace('\\', "\\\\").replace('"', "\\\""),
    );

    Command::new("osascript").arg("-e").arg(&script).spawn()?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn send(title: &str, body: &str, urgency: &str, _event_idx: Option<usize>) -> anyhow::Result<()> {
    debug!("No notification backend: [{urgency}] {title} - {body}");
    Ok(())
}
