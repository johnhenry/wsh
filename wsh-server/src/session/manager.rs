//! Session lifecycle management.
//!
//! Tracks all active sessions, handles creation, attachment, detachment,
//! and garbage collection of expired/idle sessions.

use super::pty::PtyHandle;
use super::recording::{RecordingEvent, SessionRecorder};
use super::ring_buffer::RingBuffer;
use crate::auth::permissions::KeyPermissions;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use wsh_core::{WshError, WshResult};

/// Default ring buffer size for replay (256 KiB).
const DEFAULT_RING_BUFFER_SIZE: usize = 256 * 1024;

/// Metadata about a single session.
pub struct Session {
    /// Unique session identifier.
    pub id: String,
    /// Human-readable session name.
    pub name: Option<String>,
    /// Username that owns this session.
    pub username: String,
    /// Key fingerprint used to authenticate.
    pub fingerprint: String,
    /// Permissions granted to this session.
    pub permissions: KeyPermissions,
    /// The PTY backing this session.
    pub pty: PtyHandle,
    /// Ring buffer for output replay on reattach.
    pub ring_buffer: RingBuffer,
    /// Session recorder (writes to disk).
    pub recorder: Option<SessionRecorder>,
    /// When the session was created.
    pub created_at: Instant,
    /// Last activity timestamp (for idle timeout).
    pub last_activity: Instant,
    /// Number of currently attached clients.
    pub attached_count: u32,
    /// Session TTL in seconds.
    pub ttl_secs: u64,
    /// Idle timeout in seconds.
    pub idle_timeout_secs: u64,
}

/// Information returned when listing sessions.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub name: Option<String>,
    pub username: String,
    pub fingerprint_short: String,
    pub created_at_secs: u64,
    pub idle_secs: u64,
    pub attached_count: u32,
}

/// Manages all active sessions.
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    max_sessions: usize,
    default_ttl: u64,
    default_idle_timeout: u64,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(max_sessions: usize, default_ttl: u64, default_idle_timeout: u64) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_sessions,
            default_ttl,
            default_idle_timeout,
        }
    }

    /// Create a new session with a PTY.
    pub async fn create(
        &self,
        username: String,
        fingerprint: String,
        permissions: KeyPermissions,
        command: Option<&str>,
        cols: u16,
        rows: u16,
        env: Option<&std::collections::HashMap<String, String>>,
        recording_dir: Option<&std::path::Path>,
    ) -> WshResult<String> {
        // Pre-check with read lock (fast rejection for common case)
        {
            let sessions = self.sessions.read().await;
            if sessions.len() >= self.max_sessions {
                return Err(WshError::Other(format!(
                    "max sessions ({}) reached",
                    self.max_sessions
                )));
            }
        }

        // Spawn PTY and prepare session (outside lock)
        let session_id = generate_session_id();
        let pty = PtyHandle::spawn(command, cols, rows, env)?;

        let recorder = if let Some(dir) = recording_dir {
            let path = dir.join(format!("{session_id}.jsonl"));
            let recorder = SessionRecorder::new(path);
            let cmd_str = command.unwrap_or("(default shell)").to_string();
            recorder
                .record(RecordingEvent::Start { command: cmd_str })
                .await;
            Some(recorder)
        } else {
            None
        };

        let now = Instant::now();
        let session = Session {
            id: session_id.clone(),
            name: None,
            username,
            fingerprint,
            permissions,
            pty,
            ring_buffer: RingBuffer::new(DEFAULT_RING_BUFFER_SIZE),
            recorder,
            created_at: now,
            last_activity: now,
            attached_count: 1,
            ttl_secs: self.default_ttl,
            idle_timeout_secs: self.default_idle_timeout,
        };

        // Re-check under write lock to prevent TOCTOU race
        let mut sessions = self.sessions.write().await;
        if sessions.len() >= self.max_sessions {
            // Another concurrent create slipped in between our read and write
            return Err(WshError::Other(format!(
                "max sessions ({}) reached",
                self.max_sessions
            )));
        }
        info!(session_id = %session_id, "session created");
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    /// List all active sessions.
    pub async fn list(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .map(|s| {
                let idle = s.last_activity.elapsed().as_secs();
                let created = s.created_at.elapsed().as_secs();
                // Use first 8 chars of fingerprint as short version
                let fp_short = if s.fingerprint.len() >= 8 {
                    s.fingerprint[..8].to_string()
                } else {
                    s.fingerprint.clone()
                };
                SessionInfo {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    username: s.username.clone(),
                    fingerprint_short: fp_short,
                    created_at_secs: created,
                    idle_secs: idle,
                    attached_count: s.attached_count,
                }
            })
            .collect()
    }

    /// Attach to an existing session (increment attached count, touch activity).
    pub async fn attach(&self, session_id: &str) -> WshResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| WshError::SessionNotFound(session_id.to_string()))?;
        session.attached_count += 1;
        session.last_activity = Instant::now();
        info!(
            session_id,
            attached = session.attached_count,
            "client attached"
        );
        Ok(())
    }

    /// Detach from a session (decrement attached count).
    pub async fn detach(&self, session_id: &str) -> WshResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| WshError::SessionNotFound(session_id.to_string()))?;
        session.attached_count = session.attached_count.saturating_sub(1);
        session.last_activity = Instant::now();
        info!(
            session_id,
            attached = session.attached_count,
            "client detached"
        );
        Ok(())
    }

    /// Touch a session's activity timestamp.
    pub async fn touch(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = Instant::now();
        }
    }

    /// Rename a session.
    pub async fn rename(&self, session_id: &str, name: String) -> WshResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| WshError::SessionNotFound(session_id.to_string()))?;
        session.name = Some(name);
        Ok(())
    }

    /// Remove a session (called after process exits or forced cleanup).
    pub async fn remove(&self, session_id: &str) -> WshResult<()> {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(session_id).is_some() {
            info!(session_id, "session removed");
            Ok(())
        } else {
            Err(WshError::SessionNotFound(session_id.to_string()))
        }
    }

    /// Access a session mutably via a callback (holds write lock).
    pub async fn with_session_mut<F, R>(&self, session_id: &str, f: F) -> WshResult<R>
    where
        F: FnOnce(&mut Session) -> WshResult<R>,
    {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| WshError::SessionNotFound(session_id.to_string()))?;
        f(session)
    }

    /// Access a session immutably via a callback (holds read lock).
    pub async fn with_session<F, R>(&self, session_id: &str, f: F) -> WshResult<R>
    where
        F: FnOnce(&Session) -> WshResult<R>,
    {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| WshError::SessionNotFound(session_id.to_string()))?;
        f(session)
    }

    /// Garbage-collect expired and idle sessions.
    ///
    /// Returns the IDs of sessions that were removed.
    pub async fn gc(&self) -> Vec<String> {
        let mut sessions = self.sessions.write().await;
        let mut removed = Vec::new();

        sessions.retain(|id, session| {
            let age = session.created_at.elapsed().as_secs();
            let idle = session.last_activity.elapsed().as_secs();

            // TTL exceeded
            if age > session.ttl_secs {
                warn!(session_id = %id, age_secs = age, "session expired (TTL)");
                removed.push(id.clone());
                return false;
            }

            // Idle timeout (only if no one is attached)
            if session.attached_count == 0 && idle > session.idle_timeout_secs {
                warn!(session_id = %id, idle_secs = idle, "session expired (idle)");
                removed.push(id.clone());
                return false;
            }

            true
        });

        if !removed.is_empty() {
            debug!(count = removed.len(), "GC removed sessions");
        }

        removed
    }

    /// Get the number of active sessions.
    pub async fn count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Count active sessions for a specific key fingerprint.
    pub async fn count_for_fingerprint(&self, fingerprint: &str) -> usize {
        self.sessions
            .read()
            .await
            .values()
            .filter(|s| s.fingerprint == fingerprint)
            .count()
    }

    /// Get the default idle timeout in seconds.
    pub async fn idle_timeout(&self) -> u64 {
        self.default_idle_timeout
    }
}

/// Generate a random session ID (hex-encoded, 16 bytes = 32 hex chars).
fn generate_session_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    hex::encode(bytes)
}
