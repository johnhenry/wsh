//! Client-side wsh session.
//!
//! A `WshSession` wraps either a transport byte stream or a virtual-session
//! message queue and provides read/write/resize/signal/close operations on a
//! single channel.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::Mutex;
use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::{
    ChannelKind, EchoAckPayload, EchoStatePayload, Envelope, Payload, SessionDataMode,
    TermDiffPayload, TermSyncPayload,
};
use wsh_core::transport::ByteStream;

use crate::e2e_frame::{self, RoleTag};
use crate::stream_frame::{self, ChunkAccumulator, CoalesceOverride, WriteCoalescer};
use crate::virtual_session::VirtualSessionBackend;

/// Boxed flush callback for a stream-mode session's [`WriteCoalescer`] --
/// seals + frames the merged bytes and writes them to the underlying
/// `ByteStream`. Boxed (rather than a bare generic) so `WshSession` can
/// name a concrete field type without threading a type parameter through
/// the whole struct.
type StreamFlushFn =
    Box<dyn Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send>> + Send + Sync>;

/// The state of a session channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// The channel is open and active.
    Open,
    /// The channel is closing (sent close, waiting for confirmation).
    Closing,
    /// The channel is fully closed.
    Closed,
}

/// Options for opening a new session.
#[derive(Debug, Clone)]
pub struct SessionOpts {
    /// Channel kind (pty, exec, meta, file).
    pub kind: ChannelKind,
    /// Command to execute (for exec channels).
    pub command: Option<String>,
    /// Terminal columns (for pty channels).
    pub cols: Option<u16>,
    /// Terminal rows (for pty channels).
    pub rows: Option<u16>,
    /// Environment variables to set.
    pub env: Option<std::collections::HashMap<String, String>>,
}

impl Default for SessionOpts {
    fn default() -> Self {
        Self {
            kind: ChannelKind::Pty,
            command: None,
            cols: Some(80),
            rows: Some(24),
            env: None,
        }
    }
}

/// Information about an existing session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session identifier.
    pub session_id: String,
    /// Channel ID.
    pub channel_id: u32,
    /// Channel kind.
    pub kind: ChannelKind,
    /// Current state.
    pub state: SessionState,
    /// Human-readable name (if set).
    pub name: Option<String>,
}

/// A client-side wsh session wrapping a data stream.
///
/// Provides buffered read/write operations plus control actions
/// (resize, signal, close) that are dispatched via the control channel.
pub struct WshSession {
    /// Channel ID assigned by the server.
    channel_id: u32,
    /// Channel kind.
    kind: ChannelKind,
    /// Session data mode negotiated in `OpenOk`.
    data_mode: SessionDataMode,
    /// Server-advertised capabilities for this session.
    capabilities: Vec<String>,
    /// The server-assigned session_id this channel belongs to, from
    /// `OpenOk` (clawser #48). `None` for channel kinds without
    /// Attach/Resume-able sessions (e.g. file channels).
    session_id: Option<String>,
    /// The session-scoped HMAC token minted by the server at Open time
    /// (clawser #48), also from `OpenOk`. Pass it to `resume_session` (or
    /// optionally to `attach_session`) from a later connection to reclaim
    /// this exact session. `None` alongside `session_id`.
    resume_token: Option<Vec<u8>>,
    /// Current state.
    state: Arc<Mutex<SessionState>>,
    /// Last known remote exit code, when available.
    exit_code: Arc<Mutex<Option<i32>>>,
    /// The session backend for stream-backed or virtual-backed data.
    backend: SessionBackend,
    /// Sender for control messages (resize, signal, close) — sent to the client's
    /// control dispatch loop.
    control_tx: tokio::sync::mpsc::Sender<ControlAction>,
    /// End-to-end encryption state (wsh #19 / clawser E2E PR 2), set by
    /// `enable_e2e`. `None` means E2E is not active and `write()`/
    /// `handle_control` use plaintext `SessionData` as before.
    e2e: Mutex<Option<E2eState>>,
    /// Stream-mode E2E chunk reassembly buffer (wsh #22 / clawser E2E PR
    /// 3): reassembles the raw stdout byte stream into complete sealed
    /// chunks. `Some` only while E2E is enabled on a stream-mode session;
    /// reset to a fresh accumulator on every `enable_e2e` call.
    stream_accumulator: Mutex<Option<ChunkAccumulator>>,
    /// Decrypted plaintext bytes queued for delivery via `read()`, drained
    /// FIFO. Mirrors `VirtualSessionBackend`'s "pending" byte-queue pattern
    /// for the "queue decrypted plaintext, deliver into a possibly-smaller
    /// caller buffer" problem.
    stream_read_pending: Mutex<VecDeque<u8>>,
    /// Write coalescer for a stream-mode E2E session (wsh #22). `None`
    /// while E2E is disabled, or while enabled with coalescing turned off
    /// (`CoalesceOverride::Disabled`) -- either way `write()` seals+frames
    /// each call immediately in that case.
    stream_coalescer: Mutex<Option<Arc<WriteCoalescer<StreamFlushFn>>>>,
}

/// Per-session E2E state set by `WshSession::enable_e2e`. Connection-scoped,
/// not session-scoped -- see `enable_e2e`'s doc comment for why this must
/// never be reused across a Resume/Attach onto a new connection.
struct E2eState {
    /// The AES-256-GCM key derived from `WshClient::initiate_e2e`.
    key: [u8; 32],
    /// This channel's server-assigned session_id, bound as AAD. Cached here
    /// (rather than re-reading `WshSession::session_id`) so `enable_e2e`
    /// can fail fast once and every subsequent seal/open just uses it.
    session_id: String,
    /// This side's nonce role tag for frames it sends.
    send_role: RoleTag,
    /// The peer's nonce role tag, expected on frames this side receives.
    /// Not currently read back anywhere (open_frame derives the counter
    /// straight from the nonce bytes and doesn't re-derive/verify the role
    /// tag portion) -- kept for symmetry with `send_role`/the JS side's
    /// `#e2eRecvRoleTag` and as a hook for future stricter validation.
    #[allow(dead_code)]
    recv_role: RoleTag,
    /// Next monotonic send counter (0, 1, 2, ...). Incremented by
    /// `write()` on every seal. `Arc`-wrapped (rather than a bare
    /// `AtomicU64`) so a stream-mode session's `WriteCoalescer` flush
    /// closure -- which can't borrow `&self` (see `StreamFlushFn`) -- can
    /// share the exact same counter instance the direct/non-coalesced path
    /// uses.
    send_counter: Arc<AtomicU64>,
    /// Next monotonic receive counter this side expects from the peer.
    /// Incremented by `handle_control` on every `EncryptedFrame` regardless
    /// of whether it successfully opens, mirroring the JS side's
    /// `#e2eRecvCounter++` (a rejected frame still consumes the expected
    /// slot -- v1's strict-next-counter semantics don't retry).
    recv_counter: AtomicU64,
}

enum SessionBackend {
    Stream(Arc<Mutex<Box<dyn ByteStream>>>),
    Virtual(Arc<VirtualSessionBackend>),
}

/// Internal control actions that the session sends to the client dispatch loop.
#[derive(Debug)]
pub enum ControlAction {
    Data {
        channel_id: u32,
        data: Vec<u8>,
    },
    /// A sealed `EncryptedFrame` (wsh #19 / clawser E2E PR 2), sent instead
    /// of `Data` once `WshSession::enable_e2e` has been called. `nonce`
    /// and `ciphertext` are already-sealed bytes from
    /// `crate::e2e_frame::seal_frame`.
    EncryptedData {
        channel_id: u32,
        session_id: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    Resize {
        channel_id: u32,
        cols: u16,
        rows: u16,
    },
    Signal {
        channel_id: u32,
        signal: String,
    },
    Close {
        channel_id: u32,
    },
}

/// Seal one stream-mode chunk and write it to the underlying `ByteStream`.
/// Used directly by `WshSession::write` when coalescing is disabled, and as
/// the flush callback for a session's `stream_coalescer` otherwise. A free
/// function (not a `WshSession` method) so the `WriteCoalescer` flush
/// closure can capture only the specific `Arc`s it needs rather than a
/// whole `Arc<WshSession>` -- avoids a reference cycle between the session
/// (which owns the coalescer) and the coalescer's flush closure.
async fn seal_and_write_stream_chunk(
    stream: &Arc<Mutex<Box<dyn ByteStream>>>,
    key: &[u8; 32],
    session_id: &str,
    role: RoleTag,
    counter: &AtomicU64,
    bytes: &[u8],
) -> WshResult<()> {
    let counter_value = counter.fetch_add(1, Ordering::SeqCst);
    let (nonce, ciphertext) = e2e_frame::seal_frame(key, session_id, role, counter_value, bytes)?;
    let wire = stream_frame::encode_chunk(&nonce, &ciphertext)?;
    let mut stream = stream.lock().await;
    stream.write_all(&wire).await
}

impl WshSession {
    /// Create a new stream-backed session.
    pub(crate) fn new_stream(
        channel_id: u32,
        kind: ChannelKind,
        stream: Box<dyn ByteStream>,
        control_tx: tokio::sync::mpsc::Sender<ControlAction>,
        capabilities: Vec<String>,
    ) -> Self {
        Self {
            channel_id,
            kind,
            data_mode: SessionDataMode::Stream,
            capabilities,
            session_id: None,
            resume_token: None,
            state: Arc::new(Mutex::new(SessionState::Open)),
            exit_code: Arc::new(Mutex::new(None)),
            backend: SessionBackend::Stream(Arc::new(Mutex::new(stream))),
            control_tx,
            e2e: Mutex::new(None),
            stream_accumulator: Mutex::new(None),
            stream_read_pending: Mutex::new(VecDeque::new()),
            stream_coalescer: Mutex::new(None),
        }
    }

    /// Create a new virtual-session-backed session.
    pub(crate) fn new_virtual(
        channel_id: u32,
        kind: ChannelKind,
        control_tx: tokio::sync::mpsc::Sender<ControlAction>,
        capabilities: Vec<String>,
    ) -> Self {
        Self {
            channel_id,
            kind,
            data_mode: SessionDataMode::Virtual,
            capabilities,
            session_id: None,
            resume_token: None,
            state: Arc::new(Mutex::new(SessionState::Open)),
            exit_code: Arc::new(Mutex::new(None)),
            backend: SessionBackend::Virtual(Arc::new(VirtualSessionBackend::new())),
            control_tx,
            e2e: Mutex::new(None),
            stream_accumulator: Mutex::new(None),
            stream_read_pending: Mutex::new(VecDeque::new()),
            stream_coalescer: Mutex::new(None),
        }
    }

    /// Attach the server-provided session_id/token from `OpenOk` (clawser
    /// #48). Builder-style; call once right after construction, before the
    /// session is wrapped in `Arc` (the fields never change afterward).
    /// `None`/`None` for channel kinds without an Attach/Resume-able
    /// session (e.g. file channels), matching `OpenOk`'s own optionality.
    #[must_use]
    pub(crate) fn with_session_credentials(
        mut self,
        session_id: Option<String>,
        resume_token: Option<Vec<u8>>,
    ) -> Self {
        self.session_id = session_id;
        self.resume_token = resume_token;
        self
    }

    /// The channel ID assigned by the server.
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    /// The server-assigned session_id this channel belongs to, if any
    /// (clawser #48; `None` for channel kinds with no Attach/Resume-able
    /// session, e.g. file channels).
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// The session-scoped resume token minted at Open time, if any
    /// (clawser #48). Pass it to `WshClient::resume_session` from a later
    /// connection to reclaim this exact session, proving you're the same
    /// credentialed opener rather than merely an authorized principal.
    pub fn resume_token(&self) -> Option<&[u8]> {
        self.resume_token.as_deref()
    }

    /// The kind of this channel.
    pub fn kind(&self) -> &ChannelKind {
        &self.kind
    }

    /// The negotiated data mode for this session.
    pub fn data_mode(&self) -> &SessionDataMode {
        &self.data_mode
    }

    /// Server-advertised capabilities for this session.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Current session state.
    pub async fn state(&self) -> SessionState {
        *self.state.lock().await
    }

    /// Last known remote process exit code, if one has been reported.
    pub async fn exit_code(&self) -> Option<i32> {
        *self.exit_code.lock().await
    }

    /// Last echo acknowledgement received for this session, if available.
    pub async fn last_echo_ack(&self) -> Option<EchoAckPayload> {
        match &self.backend {
            SessionBackend::Virtual(backend) => backend.last_echo_ack().await,
            SessionBackend::Stream(_) => None,
        }
    }

    /// Last echo state received for this session, if available.
    pub async fn last_echo_state(&self) -> Option<EchoStatePayload> {
        match &self.backend {
            SessionBackend::Virtual(backend) => backend.last_echo_state().await,
            SessionBackend::Stream(_) => None,
        }
    }

    /// Last terminal sync hash received for this session, if available.
    pub async fn last_term_sync(&self) -> Option<TermSyncPayload> {
        match &self.backend {
            SessionBackend::Virtual(backend) => backend.last_term_sync().await,
            SessionBackend::Stream(_) => None,
        }
    }

    /// Last terminal diff received for this session, if available.
    pub async fn last_term_diff(&self) -> Option<TermDiffPayload> {
        match &self.backend {
            SessionBackend::Virtual(backend) => backend.last_term_diff().await,
            SessionBackend::Stream(_) => None,
        }
    }

    /// Whether `enable_e2e` has been called and E2E sealing is active for
    /// this session.
    pub async fn e2e_enabled(&self) -> bool {
        self.e2e.lock().await.is_some()
    }

    /// Opt in to end-to-end encryption for this session's data plane.
    /// Works for both virtual-mode and stream-mode sessions (wsh #22
    /// generalized this from virtual-mode-only, #19).
    ///
    /// Virtual-mode: after this call, `write()` seals outgoing data into
    /// `EncryptedFrame` messages instead of plaintext `SessionData`, and
    /// incoming `EncryptedFrame` messages are opened and delivered via the
    /// same path `SessionData` uses today.
    ///
    /// Stream-mode: outgoing bytes are sealed and framed inline in the raw
    /// byte stream (`crate::stream_frame`'s `[len][nonce][ciphertext]`
    /// chunk format, reusing the same `seal_frame`/`open_frame`
    /// primitives) -- invisible to the control-message spec, no new
    /// message type. Small writes are batched before sealing per
    /// `coalesce` (see [`crate::stream_frame::CoalesceOverride`]);
    /// incoming bytes are reassembled via a `ChunkAccumulator` and opened
    /// per-chunk before reaching `read()`. `coalesce` is ignored for
    /// virtual-mode sessions (each `write()` is already one
    /// `EncryptedFrame`).
    ///
    /// Mirrors `@johnhenry/wsh`'s `WshSession.enableE2E` (`src/session.mjs`)
    /// API shape and semantics exactly.
    ///
    /// IMPORTANT -- key lifetime: `shared_secret` must come from a *fresh*
    /// `WshClient::initiate_e2e` call on the *current* connection. E2E
    /// state here is connection-scoped, not session-scoped: if this session
    /// is later detached and Resumed/Attached on a new connection, callers
    /// MUST run `initiate_e2e` again and call `enable_e2e` again with the
    /// new key -- never persist or reuse a `shared_secret` (or its
    /// counters) across a resume. Calling `enable_e2e` again on an
    /// already-enabled session is fine and resets counters cleanly (a fresh
    /// key naturally means fresh counters, and a fresh `ChunkAccumulator`
    /// for stream-mode), but the caller is responsible for actually
    /// supplying a fresh key when doing so.
    ///
    /// `role` is which side of the `KeyExchange` this session was; it
    /// determines this side's nonce role tag. The two peers of one session
    /// MUST pick opposite roles, or their nonces can collide.
    pub async fn enable_e2e(
        &self,
        shared_secret: [u8; 32],
        role: RoleTag,
        coalesce: CoalesceOverride,
    ) -> WshResult<()> {
        let session_id = self.session_id.clone().ok_or_else(|| {
            WshError::Channel(
                "enable_e2e: session has no server-assigned session_id to bind as AAD -- was OpenOk missing session_id?"
                    .into(),
            )
        })?;

        let send_counter = Arc::new(AtomicU64::new(0));
        {
            let mut e2e = self.e2e.lock().await;
            *e2e = Some(E2eState {
                key: shared_secret,
                session_id: session_id.clone(),
                send_role: role,
                recv_role: role.peer(),
                send_counter: send_counter.clone(),
                recv_counter: AtomicU64::new(0),
            });
        }

        if matches!(self.data_mode, SessionDataMode::Stream) {
            let SessionBackend::Stream(stream) = &self.backend else {
                unreachable!("data_mode Stream implies a Stream backend");
            };
            *self.stream_accumulator.lock().await = Some(ChunkAccumulator::new());
            self.stream_read_pending.lock().await.clear();

            let coalescer = stream_frame::resolve_coalesce_options(&self.kind, coalesce).map(
                |options| {
                    let stream = stream.clone();
                    let key = shared_secret;
                    let sealed_session_id = session_id.clone();
                    let counter = send_counter.clone();
                    let flush: StreamFlushFn = Box::new(move |bytes: Vec<u8>| {
                        let stream = stream.clone();
                        let sealed_session_id = sealed_session_id.clone();
                        let counter = counter.clone();
                        Box::pin(async move {
                            seal_and_write_stream_chunk(
                                &stream,
                                &key,
                                &sealed_session_id,
                                role,
                                &counter,
                                &bytes,
                            )
                            .await
                        })
                    });
                    Arc::new(WriteCoalescer::new(options, flush))
                },
            );
            *self.stream_coalescer.lock().await = coalescer;
        } else {
            *self.stream_accumulator.lock().await = None;
            *self.stream_coalescer.lock().await = None;
        }

        Ok(())
    }

    /// Write data to the session's data stream.
    pub async fn write(&self, data: &[u8]) -> WshResult<()> {
        let state = self.state.lock().await;
        if *state != SessionState::Open {
            return Err(WshError::Channel(format!(
                "channel {} is not open (state: {:?})",
                self.channel_id, *state
            )));
        }
        drop(state);

        match &self.backend {
            SessionBackend::Stream(stream) => {
                let e2e_guard = self.e2e.lock().await;
                let Some(e2e) = e2e_guard.as_ref() else {
                    drop(e2e_guard);
                    let mut s = stream.lock().await;
                    return s.write_all(data).await;
                };
                let key = e2e.key;
                let session_id = e2e.session_id.clone();
                let role = e2e.send_role;
                let counter = e2e.send_counter.clone();
                drop(e2e_guard);

                let coalescer_guard = self.stream_coalescer.lock().await;
                if let Some(coalescer) = coalescer_guard.as_ref() {
                    let coalescer = coalescer.clone();
                    drop(coalescer_guard);
                    coalescer.write(data).await
                } else {
                    drop(coalescer_guard);
                    seal_and_write_stream_chunk(stream, &key, &session_id, role, &counter, data)
                        .await
                }
            }
            SessionBackend::Virtual(_) => {
                let e2e_guard = self.e2e.lock().await;
                if let Some(e2e) = e2e_guard.as_ref() {
                    let counter = e2e.send_counter.fetch_add(1, Ordering::SeqCst);
                    let (nonce, ciphertext) = e2e_frame::seal_frame(
                        &e2e.key,
                        &e2e.session_id,
                        e2e.send_role,
                        counter,
                        data,
                    )?;
                    let session_id = e2e.session_id.clone();
                    drop(e2e_guard);
                    self.control_tx
                        .send(ControlAction::EncryptedData {
                            channel_id: self.channel_id,
                            session_id,
                            nonce,
                            ciphertext,
                        })
                        .await
                        .map_err(|_| WshError::Channel("control channel closed".into()))
                } else {
                    drop(e2e_guard);
                    self.control_tx
                        .send(ControlAction::Data {
                            channel_id: self.channel_id,
                            data: data.to_vec(),
                        })
                        .await
                        .map_err(|_| WshError::Channel("control channel closed".into()))
                }
            }
        }
    }

    /// Read data from the session's data stream.
    ///
    /// Returns the number of bytes read. Returns 0 on EOF.
    pub async fn read(&self, buf: &mut [u8]) -> WshResult<usize> {
        match &self.backend {
            SessionBackend::Stream(stream) => {
                let e2e_enabled = self.e2e.lock().await.is_some();
                if e2e_enabled {
                    self.read_stream_e2e(stream, buf).await
                } else {
                    let mut stream = stream.lock().await;
                    stream.read(buf).await
                }
            }
            SessionBackend::Virtual(backend) => backend.read(buf).await,
        }
    }

    /// Stream-mode E2E read path: pull decrypted plaintext already queued
    /// from a previous call, or -- if none is queued -- read more raw bytes
    /// from the underlying stream, feed them through the `ChunkAccumulator`,
    /// open every complete chunk it yields, and queue the results before
    /// looping back to serve `buf`. Mirrors `session.mjs`'s
    /// `_pumpDataStream`/`#openStreamChunks`, adapted from a push-driven
    /// background pump to a pull-driven `read()` (this crate has no
    /// standing read-loop task per session).
    async fn read_stream_e2e(
        &self,
        stream: &Arc<Mutex<Box<dyn ByteStream>>>,
        buf: &mut [u8],
    ) -> WshResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            {
                let mut pending = self.stream_read_pending.lock().await;
                if !pending.is_empty() {
                    let to_copy = pending.len().min(buf.len());
                    for slot in buf.iter_mut().take(to_copy) {
                        *slot = pending.pop_front().expect("checked non-empty above");
                    }
                    return Ok(to_copy);
                }
            }

            let mut raw = vec![0_u8; stream_frame::CHUNK_HARD_CAP_BYTES];
            let n = {
                let mut s = stream.lock().await;
                s.read(&mut raw).await?
            };

            if n == 0 {
                // Clean EOF: catch a torn (truncated) chunk left in the E2E
                // accumulator, if any -- per the design, no partial-chunk
                // plaintext is ever released, so this is purely
                // diagnostic (the stream is ending either way).
                if let Some(accumulator) = self.stream_accumulator.lock().await.as_ref() {
                    if let Err(err) = accumulator.finish() {
                        tracing::error!(
                            "[wsh:session] stream E2E torn chunk at stream end: {err}"
                        );
                    }
                }
                return Ok(0);
            }
            raw.truncate(n);

            let wire_chunks = {
                let mut accumulator_guard = self.stream_accumulator.lock().await;
                let accumulator = accumulator_guard
                    .as_mut()
                    .expect("stream_accumulator set while E2E is enabled on a stream session");
                accumulator.feed(&raw)?
            };
            if wire_chunks.is_empty() {
                continue;
            }

            let mut opened_chunks = Vec::with_capacity(wire_chunks.len());
            {
                let e2e_guard = self.e2e.lock().await;
                let e2e = e2e_guard.as_ref().ok_or_else(|| {
                    WshError::Channel(
                        "stream E2E chunk arrived but E2E was disabled mid-read".into(),
                    )
                })?;
                for (nonce, ciphertext) in wire_chunks {
                    let counter = e2e.recv_counter.fetch_add(1, Ordering::SeqCst);
                    let plaintext =
                        e2e_frame::open_frame(&e2e.key, &e2e.session_id, counter, &nonce, &ciphertext)?;
                    opened_chunks.push(plaintext);
                }
            }

            let mut pending = self.stream_read_pending.lock().await;
            for plaintext in opened_chunks {
                pending.extend(plaintext);
            }
        }
    }

    /// Resize the terminal (for pty sessions).
    pub async fn resize(&self, cols: u16, rows: u16) -> WshResult<()> {
        self.control_tx
            .send(ControlAction::Resize {
                channel_id: self.channel_id,
                cols,
                rows,
            })
            .await
            .map_err(|_| WshError::Channel("control channel closed".into()))
    }

    /// Send a signal to the session process.
    pub async fn signal(&self, sig: &str) -> WshResult<()> {
        self.control_tx
            .send(ControlAction::Signal {
                channel_id: self.channel_id,
                signal: sig.to_string(),
            })
            .await
            .map_err(|_| WshError::Channel("control channel closed".into()))
    }

    /// Close this session.
    pub async fn close(&self) -> WshResult<()> {
        {
            let mut state = self.state.lock().await;
            if *state == SessionState::Closed {
                return Ok(());
            }
            *state = SessionState::Closing;
        }

        self.control_tx
            .send(ControlAction::Close {
                channel_id: self.channel_id,
            })
            .await
            .map_err(|_| WshError::Channel("control channel closed".into()))?;

        match &self.backend {
            SessionBackend::Stream(stream) => {
                // Flush any bytes still buffered by the write coalescer
                // before closing the stream, mirroring `session.mjs`'s
                // close(): coalescing must not silently drop trailing
                // bytes that never hit the byte/timer threshold.
                let coalescer = self.stream_coalescer.lock().await.clone();
                if let Some(coalescer) = coalescer {
                    if let Err(err) = coalescer.flush().await {
                        tracing::error!(
                            "[wsh:session] failed to flush coalesced stream E2E writes on close: {err}"
                        );
                    }
                }
                let mut stream = stream.lock().await;
                stream.close().await?;
            }
            SessionBackend::Virtual(backend) => {
                backend.close().await;
            }
        }

        {
            let mut state = self.state.lock().await;
            *state = SessionState::Closed;
        }

        Ok(())
    }

    /// Mark this session as closed (called externally when an Exit message is received).
    pub(crate) async fn mark_closed(&self) {
        if let SessionBackend::Virtual(backend) = &self.backend {
            backend.close().await;
        }
        let mut state = self.state.lock().await;
        *state = SessionState::Closed;
    }

    /// Mark this session closed with a known remote exit code.
    pub(crate) async fn mark_exited(&self, code: i32) {
        {
            let mut exit = self.exit_code.lock().await;
            *exit = Some(code);
        }
        self.mark_closed().await;
    }

    /// Mark this session as open (called when transitioning from a connecting state).
    #[allow(dead_code)]
    pub(crate) async fn mark_open(&self) {
        let mut state = self.state.lock().await;
        *state = SessionState::Open;
    }

    /// Handle a session-specific control message from the server.
    pub(crate) async fn handle_control(&self, envelope: &Envelope) -> WshResult<()> {
        match &envelope.payload {
            Payload::SessionData(data) => match &self.backend {
                SessionBackend::Virtual(backend) => backend.push_data(data.data.clone()).await,
                SessionBackend::Stream(_) => Ok(()),
            },
            Payload::EncryptedFrame(frame) => {
                let e2e_guard = self.e2e.lock().await;
                let e2e = e2e_guard.as_ref().ok_or_else(|| {
                    WshError::Channel(format!(
                        "received EncryptedFrame on channel {} but E2E is not enabled on this session",
                        self.channel_id
                    ))
                })?;
                if frame.session_id != e2e.session_id {
                    return Err(WshError::Channel(
                        "EncryptedFrame session_id mismatch -- possible splice attempt".into(),
                    ));
                }
                // Mirrors the JS side: the expected counter is consumed
                // (incremented) regardless of whether open_frame below
                // succeeds -- v1's strict-next-counter semantics don't
                // retry a rejected frame.
                let counter = e2e.recv_counter.fetch_add(1, Ordering::SeqCst);
                let plaintext = e2e_frame::open_frame(
                    &e2e.key,
                    &e2e.session_id,
                    counter,
                    &frame.nonce,
                    &frame.ciphertext,
                )?;
                drop(e2e_guard);
                match &self.backend {
                    SessionBackend::Virtual(backend) => backend.push_data(plaintext).await,
                    SessionBackend::Stream(_) => Ok(()),
                }
            }
            Payload::Close(_) => {
                self.mark_closed().await;
                Ok(())
            }
            Payload::Exit(exit) => {
                self.mark_exited(exit.code).await;
                Ok(())
            }
            Payload::EchoAck(payload) => {
                if let SessionBackend::Virtual(backend) = &self.backend {
                    backend.record_echo_ack(payload.clone()).await;
                }
                Ok(())
            }
            Payload::EchoState(payload) => {
                if let SessionBackend::Virtual(backend) = &self.backend {
                    backend.record_echo_state(payload.clone()).await;
                }
                Ok(())
            }
            Payload::TermSync(payload) => {
                if let SessionBackend::Virtual(backend) = &self.backend {
                    backend.record_term_sync(payload.clone()).await;
                }
                Ok(())
            }
            Payload::TermDiff(payload) => {
                if let SessionBackend::Virtual(backend) = &self.backend {
                    backend.record_term_diff(payload.clone()).await;
                }
                Ok(())
            }
            _ => Err(WshError::InvalidMessage(format!(
                "unsupported session control payload for channel {}",
                self.channel_id
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;
    use wsh_core::messages::{
        ChannelKind, ClosePayload, EchoAckPayload, EchoStatePayload, Envelope, ExitPayload,
        MsgType, Payload, TermDiffPayload, TermSyncPayload,
    };

    use super::{ControlAction, SessionState, WshSession};

    #[tokio::test]
    async fn virtual_session_write_sends_session_data_action() {
        let (control_tx, mut control_rx) = mpsc::channel(4);
        let session = WshSession::new_virtual(7, ChannelKind::Pty, control_tx, vec![]);

        session.write(b"pwd\n").await.unwrap();

        let action = control_rx.recv().await.unwrap();
        assert!(matches!(
            action,
            ControlAction::Data { channel_id, data } if channel_id == 7 && data == b"pwd\n"
        ));
    }

    #[tokio::test]
    async fn virtual_session_reads_incoming_session_data() {
        let (control_tx, _control_rx) = mpsc::channel(4);
        let session = WshSession::new_virtual(8, ChannelKind::Pty, control_tx, vec![]);
        let envelope = Envelope {
            msg_type: MsgType::SessionData,
            payload: Payload::SessionData(wsh_core::messages::SessionDataPayload {
                channel_id: 8,
                data: b"ls\n".to_vec(),
            }),
        };

        session.handle_control(&envelope).await.unwrap();

        let mut buf = [0_u8; 8];
        let n = session.read(&mut buf).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..n], b"ls\n");
    }

    #[tokio::test]
    async fn close_payload_marks_virtual_session_closed() {
        let (control_tx, _control_rx) = mpsc::channel(4);
        let session = WshSession::new_virtual(9, ChannelKind::Pty, control_tx, vec![]);
        let envelope = Envelope {
            msg_type: MsgType::Close,
            payload: Payload::Close(ClosePayload { channel_id: 9 }),
        };

        session.handle_control(&envelope).await.unwrap();

        assert_eq!(session.state().await, SessionState::Closed);
        let mut buf = [0_u8; 1];
        assert_eq!(session.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn exit_payload_tracks_remote_exit_code() {
        let (control_tx, _control_rx) = mpsc::channel(4);
        let session = WshSession::new_virtual(10, ChannelKind::Exec, control_tx, vec![]);
        let envelope = Envelope {
            msg_type: MsgType::Exit,
            payload: Payload::Exit(ExitPayload {
                channel_id: 10,
                code: 17,
            }),
        };

        session.handle_control(&envelope).await.unwrap();

        assert_eq!(session.exit_code().await, Some(17));
        assert_eq!(session.state().await, SessionState::Closed);
    }

    #[tokio::test]
    async fn virtual_session_tracks_echo_and_terminal_metadata() {
        let (control_tx, _control_rx) = mpsc::channel(4);
        let session = WshSession::new_virtual(11, ChannelKind::Pty, control_tx, vec![]);

        session
            .handle_control(&Envelope {
                msg_type: MsgType::EchoAck,
                payload: Payload::EchoAck(EchoAckPayload {
                    channel_id: 11,
                    echo_seq: 9,
                }),
            })
            .await
            .unwrap();
        session
            .handle_control(&Envelope {
                msg_type: MsgType::EchoState,
                payload: Payload::EchoState(EchoStatePayload {
                    channel_id: 11,
                    echo_seq: 9,
                    cursor_x: 2,
                    cursor_y: 1,
                    pending: 0,
                }),
            })
            .await
            .unwrap();
        session
            .handle_control(&Envelope {
                msg_type: MsgType::TermSync,
                payload: Payload::TermSync(TermSyncPayload {
                    channel_id: 11,
                    frame_seq: 4,
                    state_hash: vec![1, 2, 3],
                }),
            })
            .await
            .unwrap();
        session
            .handle_control(&Envelope {
                msg_type: MsgType::TermDiff,
                payload: Payload::TermDiff(TermDiffPayload {
                    channel_id: 11,
                    frame_seq: 4,
                    base_seq: 3,
                    patch: vec![4, 5],
                }),
            })
            .await
            .unwrap();

        assert_eq!(session.last_echo_ack().await.unwrap().echo_seq, 9);
        assert_eq!(session.last_echo_state().await.unwrap().cursor_y, 1);
        assert_eq!(session.last_term_sync().await.unwrap().frame_seq, 4);
        assert_eq!(session.last_term_diff().await.unwrap().base_seq, 3);
    }
}
