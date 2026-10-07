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
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};
use wsh_core::messages::*;
use wsh_core::{WshError, WshResult};

/// Default ring buffer size for replay (256 KiB).
const DEFAULT_RING_BUFFER_SIZE: usize = 256 * 1024;

/// Replay is sent in chunks of at most this many bytes.
const REPLAY_CHUNK_BYTES: usize = 16 * 1024;

/// One connection's attachment to a session.
///
/// Everything destined for that connection about this session (the reply to
/// the Open/Attach/Resume, replayed output, live output, Presence, Exit and
/// Close) goes through `tx`, one ordered queue, so a replay is never overtaken
/// by live output. A task per attachment forwards the queue to the
/// connection's own sender; when that connection goes away the queue closes
/// and the next push prunes the attachment.
#[derive(Debug, Clone)]
pub struct Attachment {
    /// Connection id (`None` only for a connection that never registered one).
    pub conn_id: Option<u64>,
    /// Channel assigned on that connection.
    pub channel_id: u32,
    /// `"control"` or `"readonly"`.
    pub mode: String,
    pub username: String,
    pub tx: mpsc::UnboundedSender<Envelope>,
}

/// What an Attach/Resume found.
#[derive(Debug)]
pub enum AttachError {
    /// No such session.
    NotFound,
    /// `last_seq` is older than the retained output or newer than produced.
    Gap(String),
}

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
    /// Connections attached to this session (the opener included). Output is
    /// fanned out to all of them; the session keeps running, and keeps
    /// filling `ring_buffer`, with none.
    pub attachments: Vec<Attachment>,
    /// Set once the process has ended while nobody was attached: the record
    /// lingers so a later Attach/Resume still hears the replay and the exit.
    pub exit_code: Option<i32>,
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
            attachments: Vec::new(),
            exit_code: None,
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
                    attached_count: s.attachments.len() as u32,
                }
            })
            .collect()
    }

    /// Register the attachment of the connection that just opened `session_id`.
    ///
    /// Call before the output pump starts so the opener sees the output from
    /// byte 0.
    pub async fn add_attachment(&self, session_id: &str, att: Attachment) -> WshResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| WshError::SessionNotFound(session_id.to_string()))?;
        session.attachments.push(att);
        session.last_activity = Instant::now();
        Ok(())
    }

    /// Attach (`from: None`, the retained output) or resume (`from: Some(last_seq)`,
    /// only the bytes after it) a connection to a session.
    ///
    /// Queues, in order, on `tx`: the Presence that answers the request (the
    /// caller's own entry carries the assigned `channel_id` and the `seq` of the
    /// first byte that will arrive on it), the replay as `SessionData`, and
    /// then either the exit (if the process already ended) or nothing more
    /// until live output; the attachment is registered in the same critical
    /// section, so no live byte can slip between the replay and the stream.
    ///
    /// `seq` is the cumulative number of session output bytes (spec
    /// `Resume.last_seq`): a `last_seq` older than the ring still holds, or
    /// newer than the session produced, is refused with a `Gap` naming it.
    pub async fn attach_with_replay(
        &self,
        session_id: &str,
        att: Attachment,
        from: Option<u64>,
    ) -> Result<u64, AttachError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id).ok_or(AttachError::NotFound)?;
        let start = session.ring_buffer.start_seq();
        let end = session.ring_buffer.total_written();
        let from = match from {
            None => start,
            Some(last) if last > end => {
                return Err(AttachError::Gap(format!(
                    "last_seq {last} is ahead of the session (it has produced {end} bytes)"
                )))
            }
            Some(last) if last < start => {
                return Err(AttachError::Gap(format!(
                    "output gap: this session's retained output starts at seq {start} but last_seq is {last}; attach for the retained output instead"
                )))
            }
            Some(last) => last,
        };

        let mut roster = vec![AttachmentInfo {
            session_id: session_id.to_string(),
            mode: att.mode.clone(),
            username: Some(att.username.clone()),
            channel_id: Some(att.channel_id),
            seq: Some(from),
        }];
        roster.extend(session.attachments.iter().map(roster_entry(session_id)));
        let _ = att.tx.send(Envelope {
            msg_type: MsgType::Presence,
            payload: Payload::Presence(PresencePayload {
                attachments: roster,
            }),
        });
        for chunk in session
            .ring_buffer
            .read_from(from)
            .chunks(REPLAY_CHUNK_BYTES)
        {
            let _ = att.tx.send(session_data(att.channel_id, chunk));
        }
        session.last_activity = Instant::now();

        if let Some(code) = session.exit_code {
            // The process ended while nobody was attached: this is the
            // exit they missed, after which the record has served its purpose.
            let _ = att.tx.send(exit_envelope(att.channel_id, code));
            let _ = att.tx.send(close_envelope(att.channel_id));
            sessions.remove(session_id);
            return Ok(from);
        }

        session.attachments.push(att);
        broadcast_presence(session, session_id, Some(session.attachments.len() - 1));
        info!(
            session_id,
            attached = session.attachments.len(),
            from,
            "client attached"
        );
        Ok(from)
    }

    /// Whether `conn_id`'s channel may write to the session's input (a
    /// read-only attachment may not, and neither may a connection that is
    /// not attached at all).
    pub async fn may_write(&self, session_id: &str, conn_id: Option<u64>, channel_id: u32) -> bool {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).is_some_and(|s| {
            s.attachments
                .iter()
                .any(|a| a.conn_id == conn_id && a.channel_id == channel_id && a.mode == "control")
        })
    }

    /// Remove one channel's attachment (the client closed it). The session
    /// itself keeps running.
    pub async fn detach_channel(
        &self,
        session_id: &str,
        conn_id: Option<u64>,
        channel_id: u32,
    ) -> WshResult<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| WshError::SessionNotFound(session_id.to_string()))?;
        session
            .attachments
            .retain(|a| !(a.conn_id == conn_id && a.channel_id == channel_id));
        session.last_activity = Instant::now();
        broadcast_presence(session, session_id, None);
        info!(
            session_id,
            attached = session.attachments.len(),
            "client detached"
        );
        Ok(())
    }

    /// Remove every attachment `conn_id` holds on `session_id` (a client's
    /// `Detach`). Returns how many it held; the session keeps running.
    pub async fn detach_session(&self, session_id: &str, conn_id: Option<u64>) -> WshResult<usize> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| WshError::SessionNotFound(session_id.to_string()))?;
        let before = session.attachments.len();
        session.attachments.retain(|a| a.conn_id != conn_id);
        let held = before - session.attachments.len();
        session.last_activity = Instant::now();
        if held > 0 {
            broadcast_presence(session, session_id, None);
        }
        Ok(held)
    }

    /// A connection went away: it no longer holds any attachment. Sessions
    /// it was attached to keep running and keep filling their ring buffers.
    pub async fn detach_connection(&self, conn_id: u64) {
        let mut sessions = self.sessions.write().await;
        for (id, session) in sessions.iter_mut() {
            let before = session.attachments.len();
            session.attachments.retain(|a| a.conn_id != Some(conn_id));
            if session.attachments.len() != before {
                session.last_activity = Instant::now();
                broadcast_presence(session, id, None);
                debug!(session_id = %id, conn_id, "connection dropped; session detached");
            }
        }
    }

    /// Output from the process: retained in the ring buffer (which defines
    /// `seq`) and delivered to every attached channel. Returns `false` once
    /// the session no longer exists.
    pub async fn push_output(&self, session_id: &str, data: &[u8]) -> bool {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return false;
        };
        session.last_activity = Instant::now();
        session.ring_buffer.write(data);
        // A closed queue means that connection is gone: prune it.
        session
            .attachments
            .retain(|a| a.tx.send(session_data(a.channel_id, data)).is_ok());
        true
    }

    /// The process ended. Everyone attached hears Exit + Close and the record
    /// is dropped; if nobody is attached it lingers (with the exit code) so a
    /// later Attach/Resume can still replay the output and report the exit.
    pub async fn finish(&self, session_id: &str, code: i32) {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return;
        };
        session.last_activity = Instant::now();
        let mut heard = false;
        for a in session.attachments.drain(..) {
            heard |= a.tx.send(exit_envelope(a.channel_id, code)).is_ok();
            let _ = a.tx.send(close_envelope(a.channel_id));
        }
        if heard {
            sessions.remove(session_id);
        } else {
            session.exit_code = Some(code);
        }
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
            if session.attachments.is_empty() && idle > session.idle_timeout_secs {
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
            .filter(|s| s.fingerprint == fingerprint && s.exit_code.is_none())
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

fn roster_entry(session_id: &str) -> impl Fn(&Attachment) -> AttachmentInfo + '_ {
    move |a| AttachmentInfo {
        session_id: session_id.to_string(),
        mode: a.mode.clone(),
        username: Some(a.username.clone()),
        channel_id: None,
        seq: None,
    }
}

/// Tell every attachment (except the one at `except`) who is attached now.
fn broadcast_presence(session: &Session, session_id: &str, except: Option<usize>) {
    if session.attachments.is_empty() {
        return;
    }
    let roster: Vec<AttachmentInfo> = session
        .attachments
        .iter()
        .map(roster_entry(session_id))
        .collect();
    for (i, a) in session.attachments.iter().enumerate() {
        if Some(i) == except {
            continue;
        }
        let _ = a.tx.send(Envelope {
            msg_type: MsgType::Presence,
            payload: Payload::Presence(PresencePayload {
                attachments: roster.clone(),
            }),
        });
    }
}

fn session_data(channel_id: u32, data: &[u8]) -> Envelope {
    Envelope {
        msg_type: MsgType::SessionData,
        payload: Payload::SessionData(SessionDataPayload {
            channel_id,
            data: data.to_vec(),
        }),
    }
}

fn exit_envelope(channel_id: u32, code: i32) -> Envelope {
    Envelope {
        msg_type: MsgType::Exit,
        payload: Payload::Exit(ExitPayload { channel_id, code }),
    }
}

fn close_envelope(channel_id: u32) -> Envelope {
    Envelope {
        msg_type: MsgType::Close,
        payload: Payload::Close(ClosePayload { channel_id }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn session_with_output(mgr: &SessionManager, output: &[u8]) -> String {
        let id = mgr
            .create(
                "alice".into(),
                "fp".into(),
                KeyPermissions::from_options("fp".into(), None),
                Some("sleep 30"),
                80,
                24,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(mgr.push_output(&id, output).await);
        id
    }

    fn attachment(channel_id: u32, mode: &str) -> (Attachment, mpsc::UnboundedReceiver<Envelope>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Attachment {
                conn_id: Some(7),
                channel_id,
                mode: mode.into(),
                username: "alice".into(),
                tx,
            },
            rx,
        )
    }

    /// Drain what is queued: (own Presence entry, replayed bytes, other messages).
    fn drain(
        rx: &mut mpsc::UnboundedReceiver<Envelope>,
    ) -> (Option<AttachmentInfo>, Vec<u8>, Vec<MsgType>) {
        let (mut own, mut data, mut rest) = (None, Vec::new(), Vec::new());
        while let Ok(env) = rx.try_recv() {
            match env.payload {
                Payload::Presence(p) => {
                    if own.is_none() {
                        own = p.attachments.into_iter().find(|a| a.channel_id.is_some());
                    }
                }
                Payload::SessionData(d) => data.extend(d.data),
                _ => rest.push(env.msg_type),
            }
        }
        (own, data, rest)
    }

    #[tokio::test]
    async fn resume_replays_only_bytes_after_last_seq() {
        let mgr = SessionManager::new(8, 3600, 3600);
        let id = session_with_output(&mgr, b"hello world").await;

        let (att, mut rx) = attachment(5, "control");
        let from = mgr.attach_with_replay(&id, att, Some(6)).await.unwrap();
        assert_eq!(from, 6);
        let (own, data, _) = drain(&mut rx);
        let own = own.expect("the caller's Presence entry");
        assert_eq!(own.channel_id, Some(5));
        assert_eq!(own.seq, Some(6), "seq of the first replayed byte");
        assert_eq!(data, b"world");

        // Live output follows on the same queue, after the replay.
        assert!(mgr.push_output(&id, b"!").await);
        let (_, live, _) = drain(&mut rx);
        assert_eq!(live, b"!");
    }

    #[tokio::test]
    async fn last_seq_zero_and_at_the_end() {
        let mgr = SessionManager::new(8, 3600, 3600);
        let id = session_with_output(&mgr, b"abc").await;
        let (att, mut rx) = attachment(1, "control");
        mgr.attach_with_replay(&id, att, Some(0)).await.unwrap();
        assert_eq!(drain(&mut rx).1, b"abc");
        let (att, mut rx) = attachment(2, "control");
        mgr.attach_with_replay(&id, att, Some(3)).await.unwrap();
        assert_eq!(drain(&mut rx).1, b"");
    }

    #[tokio::test]
    async fn gaps_are_refused_with_the_positions_named() {
        let mgr = SessionManager::new(8, 3600, 3600);
        let id = session_with_output(&mgr, b"abc").await;
        let (att, _rx) = attachment(1, "control");
        match mgr.attach_with_replay(&id, att, Some(10)).await {
            Err(AttachError::Gap(m)) => assert!(m.contains("ahead of the session"), "{m}"),
            other => panic!("expected a gap, got {other:?}"),
        }
        // Overflow the 256 KiB ring so the start moves past 0.
        assert!(
            mgr.push_output(&id, &vec![b'x'; DEFAULT_RING_BUFFER_SIZE])
                .await
        );
        let (att, _rx) = attachment(2, "control");
        match mgr.attach_with_replay(&id, att, Some(1)).await {
            Err(AttachError::Gap(m)) => {
                assert!(m.contains("starts at seq 3"), "{m}");
                assert!(m.contains("last_seq is 1"), "{m}");
            }
            other => panic!("expected a gap, got {other:?}"),
        }
        // Attach (no last_seq) still gets the retained tail, from its start.
        let (att, mut rx) = attachment(3, "control");
        assert_eq!(mgr.attach_with_replay(&id, att, None).await.unwrap(), 3);
        assert_eq!(drain(&mut rx).1.len(), DEFAULT_RING_BUFFER_SIZE);
    }

    #[tokio::test]
    async fn unknown_session_is_not_found() {
        let mgr = SessionManager::new(8, 3600, 3600);
        let (att, _rx) = attachment(1, "control");
        assert!(matches!(
            mgr.attach_with_replay("nope", att, None).await,
            Err(AttachError::NotFound)
        ));
    }

    #[tokio::test]
    async fn dropped_connections_are_pruned_and_the_ring_keeps_filling() {
        let mgr = SessionManager::new(8, 3600, 3600);
        let id = session_with_output(&mgr, b"a").await;
        let (att, rx) = attachment(1, "control");
        mgr.add_attachment(&id, att).await.unwrap();
        assert_eq!(mgr.list().await[0].attached_count, 1);
        drop(rx); // the connection's forwarder ended
        assert!(mgr.push_output(&id, b"b").await);
        assert_eq!(
            mgr.list().await[0].attached_count,
            0,
            "pruned on the next push"
        );
        // ...but the output was retained for a later resume.
        let (att, mut rx) = attachment(2, "control");
        mgr.attach_with_replay(&id, att, Some(1)).await.unwrap();
        assert_eq!(drain(&mut rx).1, b"b");
    }

    #[tokio::test]
    async fn only_a_control_attachment_of_the_same_connection_may_write() {
        let mgr = SessionManager::new(8, 3600, 3600);
        let id = session_with_output(&mgr, b"").await;
        let (control, _a) = attachment(1, "control");
        let (viewer, _b) = attachment(2, "readonly");
        mgr.add_attachment(&id, control).await.unwrap();
        mgr.add_attachment(&id, viewer).await.unwrap();
        assert!(mgr.may_write(&id, Some(7), 1).await);
        assert!(!mgr.may_write(&id, Some(7), 2).await, "read-only");
        assert!(
            !mgr.may_write(&id, Some(8), 1).await,
            "another connection's channel"
        );
        assert!(!mgr.may_write(&id, Some(7), 99).await, "no such channel");
    }

    #[tokio::test]
    async fn exit_while_detached_lingers_until_the_next_attach_hears_it() {
        let mgr = SessionManager::new(8, 3600, 3600);
        let id = session_with_output(&mgr, b"bye").await;
        mgr.finish(&id, 3).await;
        assert_eq!(mgr.count().await, 1, "kept: nobody heard the exit");
        assert_eq!(
            mgr.count_for_fingerprint("fp").await,
            0,
            "but it no longer counts against the key's cap"
        );

        let (att, mut rx) = attachment(9, "control");
        mgr.attach_with_replay(&id, att, Some(0)).await.unwrap();
        let (_, data, rest) = drain(&mut rx);
        assert_eq!(data, b"bye");
        assert_eq!(rest, vec![MsgType::Exit, MsgType::Close]);
        assert_eq!(mgr.count().await, 0, "dropped once the exit was delivered");
    }

    #[tokio::test]
    async fn exit_with_someone_attached_removes_the_session() {
        let mgr = SessionManager::new(8, 3600, 3600);
        let id = session_with_output(&mgr, b"").await;
        let (att, mut rx) = attachment(1, "control");
        mgr.add_attachment(&id, att).await.unwrap();
        mgr.finish(&id, 0).await;
        assert_eq!(drain(&mut rx).2, vec![MsgType::Exit, MsgType::Close]);
        assert_eq!(mgr.count().await, 0);
    }

    #[tokio::test]
    async fn detach_connection_removes_only_that_connections_attachments() {
        let mgr = SessionManager::new(8, 3600, 3600);
        let id = session_with_output(&mgr, b"").await;
        let (mine, _a) = attachment(1, "control");
        let (tx, _rx) = mpsc::unbounded_channel();
        let other = Attachment {
            conn_id: Some(8),
            channel_id: 2,
            mode: "control".into(),
            username: "bob".into(),
            tx,
        };
        mgr.add_attachment(&id, mine).await.unwrap();
        mgr.add_attachment(&id, other).await.unwrap();
        mgr.detach_connection(7).await;
        assert_eq!(mgr.list().await[0].attached_count, 1);
        assert!(mgr.may_write(&id, Some(8), 2).await);
    }
}
