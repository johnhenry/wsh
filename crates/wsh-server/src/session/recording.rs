//! Structured session recording.
//!
//! Records timestamped events (input, output, resize, etc.) to a file
//! for later replay. Format is newline-delimited JSON for simplicity.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error};

/// Event types that can appear in a session recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RecordingEvent {
    /// PTY output (bytes sent to the client).
    Output(Vec<u8>),
    /// Client input (bytes received from the client).
    Input(Vec<u8>),
    /// Terminal resize event.
    Resize { cols: u16, rows: u16 },
    /// Session started with a given command.
    Start { command: String },
    /// Session ended with an exit code.
    Exit { code: i32 },
    /// Snapshot marker.
    Snapshot { label: String },
}

/// A single timestamped entry in the recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingEntry {
    /// Milliseconds since recording start.
    pub timestamp_ms: u64,
    /// The event.
    pub event: RecordingEvent,
}

/// Session recorder that writes events to a file.
pub struct SessionRecorder {
    path: PathBuf,
    start_time: std::time::Instant,
    /// Whether recording is active.
    active: bool,
}

impl SessionRecorder {
    /// Create a new recorder writing to the given path.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            start_time: std::time::Instant::now(),
            active: true,
        }
    }

    /// Get the recording file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record an event. Errors are logged but do not propagate — recording
    /// is best-effort and must not block the session.
    pub async fn record(&self, event: RecordingEvent) {
        if !self.active {
            return;
        }

        let entry = RecordingEntry {
            timestamp_ms: self.start_time.elapsed().as_millis() as u64,
            event,
        };

        match serde_json::to_string(&entry) {
            Ok(mut line) => {
                line.push('\n');
                if let Err(e) = self.append_line(&line).await {
                    error!(path = %self.path.display(), error = %e, "failed to write recording");
                }
            }
            Err(e) => {
                error!(error = %e, "failed to serialize recording event");
            }
        }
    }

    /// Stop recording.
    pub fn stop(&mut self) {
        self.active = false;
        debug!(path = %self.path.display(), "recording stopped");
    }

    async fn append_line(&self, line: &str) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }
}

/// Load a recording from file (for replay).
pub async fn load_recording(path: &Path) -> std::io::Result<Vec<RecordingEntry>> {
    let content = tokio::fs::read_to_string(path).await?;
    let mut entries = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<RecordingEntry>(line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                error!(error = %e, "skipping malformed recording line");
            }
        }
    }
    Ok(entries)
}
