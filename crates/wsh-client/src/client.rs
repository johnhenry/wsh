//! The main wsh client.
//!
//! `WshClient` manages the connection lifecycle: transport selection, handshake,
//! authentication, session management, and keepalive.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use ml_kem::{Decapsulate, Encapsulate, EncapsulationKey, Kem, KeyExport, MlKem768, TryKeyInit};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use wsh_core::codec::{decode_envelope, frame_encode};
use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::*;

use crate::auth;
use crate::e2e::{combine_hybrid_secret, E2eKeyExchange, ALGORITHM_HYBRID};
use crate::known_hosts::{HostStatus, KnownHosts};
use crate::session::{ControlAction, SessionInfo, SessionOpts, WshSession};
use crate::transport::{self, AnyTransport};

/// Configuration for connecting to a wsh server.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    /// Username for authentication.
    pub username: String,
    /// Name of the key to use from the keystore (for pubkey auth).
    pub key_name: Option<String>,
    /// Password (for password auth).
    pub password: Option<String>,
    /// Whether to verify the host key (TOFU).
    pub verify_host: bool,
    /// Ping interval in seconds (0 = disabled).
    pub ping_interval_secs: u64,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            username: whoami(),
            key_name: None,
            password: None,
            verify_host: true,
            ping_interval_secs: 30,
            timeout_secs: 10,
        }
    }
}

/// Get the current system username as a default.
fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// The main wsh client.
/// One pending request-response wait.
///
/// `matcher` is what makes correlation possible. Without it, waiters were
/// keyed on message type alone and dispatch took whichever one it found, so
/// two concurrent requests expecting the same response type received each
/// other's replies. A waiter with no matcher accepts any envelope of its
/// type, which is the historical behaviour and still correct for the many
/// call sites that only ever have one request in flight.
struct Waiter {
    tx: oneshot::Sender<Envelope>,
    #[allow(clippy::type_complexity)]
    matcher: Option<Box<dyn Fn(&Envelope) -> bool + Send + Sync>>,
}

/// SERVER_HELLO feature advertising that McpResult echoes McpCall's call_id.
pub const MCP_CALL_ID_FEATURE: &str = "mcp-call-id";

/// Remove and return the first waiter that claims `envelope`.
///
/// FIFO, and matcher-aware. Dispatch used `Vec::pop()`, which is LIFO: with
/// two requests of the same response type in flight the SECOND caller
/// received the FIRST reply, so the swap happened even when replies arrived
/// in call order. Extracted so the selection can be tested directly -- the
/// dispatch loop it lives in needs a whole client to drive.
fn take_matching_waiter(waiters: &mut Vec<Waiter>, envelope: &Envelope) -> Option<Waiter> {
    let idx = waiters
        .iter()
        .position(|w| w.matcher.as_ref().is_none_or(|m| m(envelope)))?;
    Some(waiters.remove(idx))
}

pub struct WshClient {
    /// The underlying transport session (enum dispatch, not dyn).
    transport: Arc<Mutex<AnyTransport>>,
    /// The authenticated session ID from the server.
    session_id: Option<String>,
    /// The session token for re-attachment.
    token: Option<Vec<u8>>,
    /// Active sessions, keyed by channel ID.
    sessions: Arc<Mutex<HashMap<u32, Arc<WshSession>>>>,
    /// Sender for outgoing control actions from sessions.
    control_action_tx: mpsc::Sender<ControlAction>,
    /// Handle for the control message dispatch task.
    dispatch_handle: Option<tokio::task::JoinHandle<()>>,
    /// Handle for the keepalive task.
    keepalive_handle: Option<tokio::task::JoinHandle<()>>,
    /// Sender for outgoing control messages (used by dispatch + keepalive).
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    /// Channel for receiving specific response types (request-response pattern).
    response_tx: Arc<Mutex<HashMap<u8, Vec<Waiter>>>>,
    /// Features the server advertised in SERVER_HELLO.
    server_features: Arc<Mutex<Vec<String>>>,
    /// Whether the client is connected.
    connected: Arc<Mutex<bool>>,
    /// Receiver for incoming ReverseConnect notifications (take-once).
    reverse_connect_rx: Arc<Mutex<Option<mpsc::Receiver<Envelope>>>>,
    /// Receiver for relay-forwarded control/data messages (take-once).
    relay_message_rx: Arc<Mutex<Option<mpsc::Receiver<Envelope>>>>,
    /// Fingerprints of reverse-connect peers this client has accepted a
    /// bridge with. RelayForward-wrapped messages are only unwrapped and
    /// delivered if their from_fingerprint is in this set -- populated by
    /// app code via `trust_relay_peer` once it decides to accept/establish
    /// a given peer (see `ReverseConnectPayload.from_fingerprint`).
    accepted_relay_peers: Arc<Mutex<HashSet<String>>>,
}

/// Server-provided session summary from `SessionList`.
#[derive(Debug, Clone)]
pub struct RemoteSessionInfo {
    pub session_id: String,
    pub name: Option<String>,
    pub username: String,
    pub fingerprint_short: String,
    pub created_at_secs: u64,
    pub idle_secs: u64,
    pub attached_count: u32,
}

impl WshClient {
    /// Connect to a wsh server, perform the handshake, and authenticate.
    ///
    /// Returns the server-assigned session ID on success.
    pub async fn connect(url: &str, config: ConnectConfig) -> WshResult<Self> {
        let known_host = known_host_label(url)?;
        let timeout = Duration::from_secs(config.timeout_secs);

        // Auto-select and connect transport within the configured connection timeout.
        let transport = match time::timeout(timeout, transport::auto_connect(url)).await {
            Ok(Ok(transport)) => transport,
            Ok(Err(err)) => return Err(err),
            Err(_) => return Err(WshError::Timeout),
        };
        let transport = Arc::new(Mutex::new(transport));

        let (control_action_tx, control_action_rx) = mpsc::channel::<ControlAction>(256);
        let (outgoing_tx, outgoing_rx) = mpsc::channel::<Vec<u8>>(256);
        let response_tx: Arc<Mutex<HashMap<u8, Vec<Waiter>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let sessions: Arc<Mutex<HashMap<u32, Arc<WshSession>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let connected = Arc::new(Mutex::new(true));

        // Channel for unsolicited incoming ReverseConnect messages
        let (rc_tx, rc_rx) = mpsc::channel::<Envelope>(16);
        let reverse_connect_rx = Arc::new(Mutex::new(Some(rc_rx)));
        let (relay_tx, relay_rx) = mpsc::channel::<Envelope>(128);
        let relay_message_rx = Arc::new(Mutex::new(Some(relay_rx)));
        let accepted_relay_peers: Arc<Mutex<HashSet<String>>> =
            Arc::new(Mutex::new(HashSet::new()));

        let mut client = Self {
            transport: transport.clone(),
            session_id: None,
            token: None,
            sessions: sessions.clone(),
            control_action_tx,
            dispatch_handle: None,
            keepalive_handle: None,
            outgoing_tx: outgoing_tx.clone(),
            response_tx: response_tx.clone(),
            server_features: Arc::new(Mutex::new(Vec::new())),
            connected: connected.clone(),
            reverse_connect_rx,
            relay_message_rx,
            accepted_relay_peers: accepted_relay_peers.clone(),
        };

        // Perform handshake with timeout
        let handshake_result = time::timeout(timeout, client.handshake(&config, &known_host)).await;

        match handshake_result {
            Ok(Ok(session_id)) => {
                client.session_id = Some(session_id);
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(WshError::Timeout),
        }

        // Spawn the control dispatch loop
        let dispatch_handle = {
            let transport = transport.clone();
            let response_tx = response_tx.clone();
            let sessions = sessions.clone();
            let connected = connected.clone();
            let outgoing_tx_clone = outgoing_tx.clone();
            let accepted_relay_peers = accepted_relay_peers.clone();

            tokio::spawn(async move {
                Self::dispatch_loop(
                    transport,
                    outgoing_rx,
                    control_action_rx,
                    response_tx,
                    sessions,
                    connected,
                    outgoing_tx_clone,
                    Some(rc_tx),
                    Some(relay_tx),
                    accepted_relay_peers,
                )
                .await;
            })
        };
        client.dispatch_handle = Some(dispatch_handle);

        // Spawn keepalive if configured
        if config.ping_interval_secs > 0 {
            let interval = Duration::from_secs(config.ping_interval_secs);
            let outgoing = outgoing_tx.clone();
            let connected = client.connected.clone();

            let keepalive_handle = tokio::spawn(async move {
                let mut ping_id: u64 = 0;
                let mut ticker = time::interval(interval);
                ticker.tick().await; // skip first immediate tick

                loop {
                    ticker.tick().await;

                    let is_connected = {
                        let c = connected.lock().await;
                        *c
                    };
                    if !is_connected {
                        break;
                    }

                    ping_id += 1;
                    let envelope = Envelope {
                        msg_type: MsgType::Ping,
                        payload: Payload::PingPong(PingPongPayload { id: ping_id }),
                    };

                    match frame_encode(&envelope) {
                        Ok(frame) => {
                            if outgoing.send(frame).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("failed to encode ping: {}", e);
                        }
                    }
                }

                tracing::debug!("keepalive loop ended");
            });
            client.keepalive_handle = Some(keepalive_handle);
        }

        Ok(client)
    }

    /// The server-assigned session ID (available after successful connect).
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// The session token (for re-attachment).
    pub fn token(&self) -> Option<&[u8]> {
        self.token.as_deref()
    }

    /// Whether the client is currently connected.
    pub async fn is_connected(&self) -> bool {
        *self.connected.lock().await
    }

    /// Take the reverse-connect receiver for handling incoming connections.
    ///
    /// Can only be called once (moves the receiver out). Returns `None` on
    /// subsequent calls.
    pub async fn take_reverse_connect_rx(&self) -> Option<mpsc::Receiver<Envelope>> {
        self.reverse_connect_rx.lock().await.take()
    }

    /// Take the relay-message receiver for handling forwarded control/data messages.
    ///
    /// Can only be called once.
    pub async fn take_relay_message_rx(&self) -> Option<mpsc::Receiver<Envelope>> {
        self.relay_message_rx.lock().await.take()
    }

    /// Mark a peer fingerprint as an accepted reverse-connect bridge partner.
    ///
    /// Call this once a `ReverseConnect` has been accepted (either side):
    /// the target after sending `ReverseAccept` in response to an incoming
    /// request, or the operator after receiving `ReverseAccept` for a
    /// request it sent. Only `RelayForward`-wrapped messages whose
    /// `from_fingerprint` is trusted this way are unwrapped and delivered.
    pub async fn trust_relay_peer(&self, fingerprint: String) {
        self.accepted_relay_peers.lock().await.insert(fingerprint);
    }

    /// Stop trusting a peer as a relay-forward bridge partner (e.g. on
    /// session end).
    pub async fn untrust_relay_peer(&self, fingerprint: &str) {
        self.accepted_relay_peers.lock().await.remove(fingerprint);
    }

    /// Send a control message without waiting for any response (fire-and-forget).
    ///
    /// Unlike `send_and_wait_public`, this does not register a response listener
    /// and returns immediately after the message is queued for sending.
    pub async fn send_fire_and_forget(&self, envelope: Envelope) -> WshResult<()> {
        self.send_control_message(envelope).await
    }

    /// Send a control message and wait for a specific response type (public API).
    ///
    /// Used by modules like `mcp` and `file_transfer` that need request-response
    /// patterns over the control channel.
    pub async fn send_and_wait_public(
        &self,
        envelope: Envelope,
        expected_type: MsgType,
    ) -> WshResult<Envelope> {
        self.send_and_wait(envelope, expected_type).await
    }

    /// Whether the server advertised `name` in SERVER_HELLO.
    pub async fn has_feature(&self, name: &str) -> bool {
        self.server_features.lock().await.iter().any(|f| f == name)
    }

    /// `send_and_wait_public`, but the reply must satisfy `matcher`.
    ///
    /// Needed wherever concurrent requests share a response type -- without
    /// it the first reply to arrive satisfies whichever waiter dispatch
    /// happens to find, and both callers get a result that is not theirs.
    #[allow(clippy::type_complexity)]
    pub async fn send_and_wait_matching_public(
        &self,
        envelope: Envelope,
        expected_type: MsgType,
        matcher: Box<dyn Fn(&Envelope) -> bool + Send + Sync>,
    ) -> WshResult<Envelope> {
        self.send_and_wait_matching(envelope, expected_type, Some(matcher))
            .await
    }

    /// Open a new session (pty, exec, etc.).
    pub async fn open_session(&self, opts: SessionOpts) -> WshResult<Arc<WshSession>> {
        let SessionOpts {
            kind,
            command,
            cols,
            rows,
            env,
        } = opts;

        // Build and send OPEN message
        let envelope = Envelope {
            msg_type: MsgType::Open,
            payload: Payload::Open(OpenPayload {
                kind: kind.clone(),
                command,
                cols,
                rows,
                env,
            }),
        };

        let response = self.send_and_wait(envelope, MsgType::OpenOk).await?;

        // Parse OPEN_OK response
        match response.payload {
            Payload::OpenOk(ok) => {
                let session = match ok.data_mode {
                    SessionDataMode::Stream => {
                        let stream = {
                            let mut t = self.transport.lock().await;
                            t.open_stream().await?
                        };

                        Arc::new(
                            WshSession::new_stream(
                                ok.channel_id,
                                kind,
                                stream.stream,
                                self.control_action_tx.clone(),
                                ok.capabilities.clone(),
                            )
                            .with_session_credentials(ok.session_id.clone(), ok.token.clone()),
                        )
                    }
                    SessionDataMode::Virtual => Arc::new(
                        WshSession::new_virtual(
                            ok.channel_id,
                            kind,
                            self.control_action_tx.clone(),
                            ok.capabilities.clone(),
                        )
                        .with_session_credentials(ok.session_id.clone(), ok.token.clone()),
                    ),
                };

                {
                    let mut sessions = self.sessions.lock().await;
                    sessions.insert(ok.channel_id, session.clone());
                }

                tracing::info!(
                    "opened channel {} ({:?}) with data mode {:?}",
                    ok.channel_id,
                    session.kind(),
                    session.data_mode()
                );
                Ok(session)
            }
            Payload::OpenFail(fail) => Err(WshError::Channel(fail.reason)),
            _ => Err(WshError::InvalidMessage(
                "unexpected response to OPEN".into(),
            )),
        }
    }

    /// List active sessions.
    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.lock().await;
        let mut result = Vec::new();

        for (channel_id, session) in sessions.iter() {
            let state = session.state().await;
            result.push(SessionInfo {
                session_id: self
                    .session_id
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                channel_id: *channel_id,
                kind: session.kind().clone(),
                state,
                name: None,
            });
        }

        result
    }

    /// List sessions from the server that are visible to this user.
    pub async fn list_remote_sessions(&self) -> WshResult<Vec<RemoteSessionInfo>> {
        let response = self
            .send_and_wait(
                Envelope {
                    msg_type: MsgType::SessionListRequest,
                    payload: Payload::SessionListRequest(SessionListRequestPayload {}),
                },
                MsgType::SessionList,
            )
            .await?;

        match response.payload {
            Payload::SessionList(list) => Ok(list
                .sessions
                .into_iter()
                .map(|s| RemoteSessionInfo {
                    session_id: s.session_id,
                    name: s.name,
                    username: s.username,
                    fingerprint_short: s.fingerprint_short,
                    created_at_secs: s.created_at_secs,
                    idle_secs: s.idle_secs,
                    attached_count: s.attached_count,
                })
                .collect()),
            Payload::Error(err) => Err(WshError::Channel(err.message)),
            _ => Err(WshError::InvalidMessage(
                "unexpected response to SESSION_LIST_REQUEST".into(),
            )),
        }
    }

    /// Attach to an existing session (read-only or control mode).
    ///
    /// `token` is optional (clawser #48): the server accepts either a
    /// valid session-scoped token (from `WshSession::resume_token`, if
    /// this process is the one that opened the session) OR the caller
    /// already owning/being ACL-granted access to `session_id` --
    /// `check_session_access` server-side. Pass `None` for the common
    /// case of a principal attaching via ownership or a `SessionGrant`
    /// grant, who never held the session's token to begin with (only the
    /// opener receives one, via `OpenOk`). This previously fell back to
    /// this connection's own AUTH-level token (`WshClient::token`), which
    /// is bound to a completely different session_id (the connection's
    /// auth session, not the target PTY/exec session) and so could never
    /// actually verify -- that was the root cause of clawser #48.
    pub async fn attach_session(
        &self,
        session_id: &str,
        read_only: bool,
        token: Option<&[u8]>,
    ) -> WshResult<()> {
        let mode = if read_only {
            "view".to_string()
        } else {
            "control".to_string()
        };

        let envelope = Envelope {
            msg_type: MsgType::Attach,
            payload: Payload::Attach(AttachPayload {
                session_id: session_id.to_string(),
                token: token.map(|t| t.to_vec()),
                mode,
                device_label: None,
            }),
        };

        let response = self.send_and_wait(envelope, MsgType::Presence).await?;
        match response.payload {
            Payload::Presence(_) => Ok(()),
            Payload::Error(err) => Err(WshError::Channel(err.message)),
            _ => Err(WshError::InvalidMessage(
                "unexpected response to ATTACH".into(),
            )),
        }
    }

    /// Resume a previously-opened session, replaying its ring buffer.
    ///
    /// Unlike `attach_session`, `token` is required: Resume is
    /// specifically for the connection that was handed this exact token
    /// (via `OpenOk`/`WshSession::resume_token`, when it originally opened
    /// the session) coming back, so the server verifies it unconditionally
    /// rather than falling back to an ACL/ownership check. Use
    /// `attach_session` instead for a principal who only has ACL/ownership
    /// access but never held the token.
    ///
    /// `last_seq` is currently advisory server-side (the ring buffer
    /// replays its full contents regardless), but is still required on
    /// the wire for future partial-replay support.
    pub async fn resume_session(
        &self,
        session_id: &str,
        token: &[u8],
        last_seq: u64,
    ) -> WshResult<()> {
        let envelope = Envelope {
            msg_type: MsgType::Resume,
            payload: Payload::Resume(ResumePayload {
                session_id: session_id.to_string(),
                token: token.to_vec(),
                last_seq,
            }),
        };

        let response = self.send_and_wait(envelope, MsgType::Presence).await?;
        match response.payload {
            Payload::Presence(_) => Ok(()),
            Payload::Error(err) => Err(WshError::Channel(err.message)),
            _ => Err(WshError::InvalidMessage(
                "unexpected response to RESUME".into(),
            )),
        }
    }

    /// Detach from an existing session.
    pub async fn detach_session(&self, session_id: &str) -> WshResult<()> {
        let response = self
            .send_and_wait(
                Envelope {
                    msg_type: MsgType::Detach,
                    payload: Payload::Detach(DetachPayload {
                        session_id: session_id.to_string(),
                    }),
                },
                MsgType::DetachOk,
            )
            .await?;
        match response.payload {
            Payload::DetachOk(_) => Ok(()),
            Payload::DetachFail(fail) => Err(WshError::Channel(fail.reason)),
            Payload::Error(err) => Err(WshError::Channel(err.message)),
            _ => Err(WshError::InvalidMessage(
                "unexpected response to DETACH".into(),
            )),
        }
    }

    // ── E2E Encryption ───────────────────────────────────────────────

    /// Initiate end-to-end encryption for a session (wsh #18).
    ///
    /// `algorithm: "X25519"` (default -- pass [`crate::e2e::ALGORITHM_X25519`]):
    /// classical ECDH only, one round trip -- both sides send their
    /// ephemeral public key, derive the shared secret directly.
    ///
    /// `algorithm: "X25519+ML-KEM-768"` (pass [`ALGORITHM_HYBRID`]): hybrid
    /// classical+post-quantum. Round 1 is the same as classical, plus both
    /// sides also send a fresh ML-KEM-768 public key. Each side then
    /// deterministically derives the same "encapsulator"/"decapsulator"
    /// role assignment by comparing the two exchanged X25519 public keys
    /// byte-lexicographically (no extra round trip needed, since both
    /// sides already have both values after round 1) -- the encapsulator
    /// encapsulates against the decapsulator's ML-KEM-768 key and sends
    /// the ciphertext in a second `KeyExchange` message; the decapsulator
    /// decapsulates it. Both combine the X25519 and ML-KEM-768 outputs via
    /// HKDF-SHA256 (see [`crate::e2e::combine_hybrid_secret`]). Falls back
    /// to classical automatically if the peer's round-1 message doesn't
    /// include a `kem_public_key` (it doesn't support hybrid mode) --
    /// algorithm agility, not a hard cutover; check the returned `hybrid`
    /// flag to see which actually happened.
    ///
    /// Mirrors `@johnhenry/wsh`'s `WshClient.initiateE2E` (`src/client.mjs`)
    /// byte-for-byte for wire interop.
    pub async fn initiate_e2e(
        &self,
        session_id: &str,
        algorithm: &str,
        timeout: Duration,
    ) -> WshResult<E2eKeyExchange> {
        let want_hybrid = algorithm == ALGORITHM_HYBRID;

        // Generate an ephemeral X25519 key pair (and, for hybrid, a fresh
        // ML-KEM-768 key pair too).
        let ephemeral_secret = EphemeralSecret::random();
        let local_public = X25519PublicKey::from(&ephemeral_secret);
        let local_public_bytes = local_public.as_bytes().to_vec();

        let local_kem = if want_hybrid {
            Some(MlKem768::generate_keypair())
        } else {
            None
        };
        let local_kem_public_bytes = local_kem.as_ref().map(|(_dk, ek)| ek.to_bytes().to_vec());

        let round1 = Envelope {
            msg_type: MsgType::KeyExchange,
            payload: Payload::KeyExchange(KeyExchangePayload {
                algorithm: algorithm.to_string(),
                public_key: Some(local_public_bytes.clone()),
                session_id: session_id.to_string(),
                kem_public_key: local_kem_public_bytes,
                kem_ciphertext: None,
            }),
        };

        let peer_round1 = self
            .send_and_wait_for(round1, MsgType::KeyExchange, timeout)
            .await?;
        let peer = match peer_round1.payload {
            Payload::KeyExchange(p) => p,
            _ => {
                return Err(WshError::InvalidMessage(
                    "unexpected response to round-1 KEY_EXCHANGE".into(),
                ))
            }
        };

        let peer_public_key = peer.public_key.clone().ok_or_else(|| {
            WshError::InvalidMessage("peer KEY_EXCHANGE missing public_key".into())
        })?;
        let peer_public_array: [u8; 32] = peer_public_key.as_slice().try_into().map_err(|_| {
            WshError::InvalidMessage(format!(
                "peer public_key must be 32 bytes, got {}",
                peer_public_key.len()
            ))
        })?;
        let peer_x25519_public = X25519PublicKey::from(peer_public_array);
        let x25519_shared = ephemeral_secret.diffie_hellman(&peer_x25519_public);
        let x25519_secret_bytes = *x25519_shared.as_bytes();

        let hybrid_active = want_hybrid && local_kem.is_some() && peer.kem_public_key.is_some();

        let shared_secret = if hybrid_active {
            let (local_dk, _local_ek) = local_kem.expect("checked by hybrid_active");
            let peer_kem_public_key = peer.kem_public_key.expect("checked by hybrid_active");

            // Lexicographic byte comparison: Rust's `Ord` on `&[u8]`
            // already compares elementwise then by length, matching the
            // JS `compareBytes` helper exactly, so no separate comparator
            // is needed here.
            let is_encapsulator = local_public_bytes < peer_public_key;

            let kem_shared_secret: [u8; 32] = if is_encapsulator {
                let peer_ek = EncapsulationKey::<MlKem768>::new_from_slice(&peer_kem_public_key)
                    .map_err(|_| WshError::InvalidMessage("invalid peer kem_public_key".into()))?;
                let (ciphertext, shared) = peer_ek.encapsulate();

                let round2 = Envelope {
                    msg_type: MsgType::KeyExchange,
                    payload: Payload::KeyExchange(KeyExchangePayload {
                        algorithm: algorithm.to_string(),
                        public_key: None,
                        session_id: session_id.to_string(),
                        kem_public_key: None,
                        kem_ciphertext: Some(ciphertext.to_vec()),
                    }),
                };
                self.send_fire_and_forget(round2).await?;

                shared.as_slice().try_into().map_err(|_| {
                    WshError::Other("ML-KEM-768 shared secret was not 32 bytes".into())
                })?
            } else {
                let peer_round2 = self.wait_for(MsgType::KeyExchange, timeout).await?;
                let ct_payload = match peer_round2.payload {
                    Payload::KeyExchange(p) => p,
                    _ => {
                        return Err(WshError::InvalidMessage(
                            "unexpected response to round-2 KEY_EXCHANGE".into(),
                        ))
                    }
                };
                let kem_ciphertext = ct_payload.kem_ciphertext.ok_or_else(|| {
                    WshError::InvalidMessage("round-2 KEY_EXCHANGE missing kem_ciphertext".into())
                })?;
                let shared = local_dk
                    .decapsulate_slice(&kem_ciphertext)
                    .map_err(|_| WshError::InvalidMessage("invalid peer kem_ciphertext".into()))?;
                shared.as_slice().try_into().map_err(|_| {
                    WshError::Other("ML-KEM-768 shared secret was not 32 bytes".into())
                })?
            };

            combine_hybrid_secret(&x25519_secret_bytes, &kem_shared_secret)?
        } else {
            x25519_secret_bytes
        };

        Ok(E2eKeyExchange {
            peer_public_key,
            shared_secret,
            hybrid: hybrid_active,
        })
    }

    /// Disconnect from the server.
    pub async fn disconnect(&self) -> WshResult<()> {
        {
            let mut connected = self.connected.lock().await;
            *connected = false;
        }

        // Close all active sessions
        {
            let sessions = self.sessions.lock().await;
            for (_, session) in sessions.iter() {
                let _ = session.close().await;
            }
        }

        // Stop the dispatch/keepalive tasks *before* touching the
        // transport lock below. The dispatch loop's "receive" select arm
        // holds `self.transport`'s lock for the full duration of its
        // `recv_control().await` call, which -- once there's no more
        // traffic left to receive (as here, right after the last session
        // closed) -- blocks forever. Without this abort, the
        // `self.transport.lock().await` a few lines down would deadlock
        // against that still-parked task instead of ever closing the
        // transport. (First hit in practice by issue #38's Phase 1
        // loopback proof: nothing had exercised a full connect ->
        // exec -> disconnect cycle to completion before.)
        if let Some(handle) = &self.dispatch_handle {
            handle.abort();
        }
        if let Some(handle) = &self.keepalive_handle {
            handle.abort();
        }

        // Close the transport
        {
            let mut transport = self.transport.lock().await;
            transport.close().await?;
        }

        Ok(())
    }

    // ── Internal ─────────────────────────────────────────────────────

    /// Perform the handshake: HELLO -> SERVER_HELLO -> CHALLENGE -> AUTH -> AUTH_OK.
    async fn handshake(&mut self, config: &ConnectConfig, known_host: &str) -> WshResult<String> {
        // Determine auth method
        let auth_method = if config.key_name.is_some() {
            AuthMethod::Pubkey
        } else {
            AuthMethod::Password
        };

        // Send HELLO
        let hello = Envelope {
            msg_type: MsgType::Hello,
            payload: Payload::Hello(HelloPayload {
                version: PROTOCOL_VERSION.to_string(),
                username: config.username.clone(),
                features: vec!["mcp".to_string(), "file-transfer".to_string()],
                auth_method: Some(auth_method.clone()),
            }),
        };
        self.send_raw(&hello).await?;

        // Receive SERVER_HELLO
        let server_hello_data = self.recv_raw().await?;
        let server_hello = decode_envelope(&server_hello_data)?;

        let (_server_hello_session_id, server_fingerprints, advertised_features) =
            match &server_hello.payload {
                Payload::ServerHello(sh) => (
                    sh.session_id.clone(),
                    sh.fingerprints.clone(),
                    sh.features.clone(),
                ),
                _ => return Err(WshError::InvalidMessage("expected SERVER_HELLO".into())),
            };
        *self.server_features.lock().await = advertised_features;

        // Verify host key (TOFU)
        if config.verify_host {
            if let Some(first_fp) = server_fingerprints.first() {
                self.verify_host_key(known_host, first_fp)?;
            }
        }

        // Receive CHALLENGE
        let challenge_data = self.recv_raw().await?;
        let challenge = decode_envelope(&challenge_data)?;

        // Challenge.session_id (not SERVER_HELLO's) is authoritative for the
        // transcript -- it's the one guaranteed present regardless of
        // whether a given server sends SERVER_HELLO at all.
        let (nonce, server_session_id) = match &challenge.payload {
            Payload::Challenge(c) => (c.nonce.clone(), c.session_id.clone()),
            _ => return Err(WshError::InvalidMessage("expected CHALLENGE".into())),
        };

        // Authenticate
        let auth_envelope = match auth_method {
            AuthMethod::Pubkey => {
                let key_name = config.key_name.as_deref().unwrap_or("default");

                let keystore = crate::keystore::KeyStore::default_location()?;
                let (signing_key, verifying_key) = keystore.load(key_name)?;

                let signature = auth::sign_challenge(
                    &signing_key,
                    &config.username,
                    &server_session_id,
                    &nonce,
                );
                let public_key = auth::public_key_bytes(&verifying_key);

                Envelope {
                    msg_type: MsgType::Auth,
                    payload: Payload::Auth(AuthPayload {
                        method: AuthMethod::Pubkey,
                        signature: Some(signature),
                        public_key: Some(public_key),
                        password: None,
                    }),
                }
            }
            AuthMethod::Password => {
                let password = config
                    .password
                    .clone()
                    .ok_or_else(|| WshError::AuthFailed("no password provided".into()))?;

                Envelope {
                    msg_type: MsgType::Auth,
                    payload: Payload::Auth(AuthPayload {
                        method: AuthMethod::Password,
                        signature: None,
                        public_key: None,
                        password: Some(password),
                    }),
                }
            }
        };

        self.send_raw(&auth_envelope).await?;

        // Receive AUTH_OK or AUTH_FAIL
        let auth_response_data = self.recv_raw().await?;
        let auth_response = decode_envelope(&auth_response_data)?;

        match auth_response.payload {
            Payload::AuthOk(ok) => {
                tracing::info!(
                    "authenticated as '{}' -- session {}",
                    config.username,
                    ok.session_id
                );
                self.token = Some(ok.token);
                Ok(ok.session_id)
            }
            Payload::AuthFail(fail) => Err(WshError::AuthFailed(fail.reason)),
            other => Err(WshError::InvalidMessage(format!(
                "expected AUTH_OK or AUTH_FAIL, got msg_type={:?}, payload={:?}",
                auth_response.msg_type, other
            ))),
        }
    }

    /// Verify the server's host key via TOFU.
    fn verify_host_key(&self, host: &str, fingerprint: &str) -> WshResult<()> {
        let known_hosts = KnownHosts::default_location()?;

        match known_hosts.verify_host(host, fingerprint)? {
            HostStatus::Known => {
                tracing::debug!("host {} verified (known)", host);
                Ok(())
            }
            HostStatus::Unknown => {
                // TOFU: trust on first use
                tracing::info!(
                    "new host {} with fingerprint {}, adding to known_hosts",
                    host,
                    fingerprint
                );
                known_hosts.add_host(host, fingerprint)?;
                Ok(())
            }
            HostStatus::Changed { expected } => Err(WshError::AuthFailed(format!(
                "HOST KEY CHANGED for {}: expected {}, got {}. \
                 This could indicate a man-in-the-middle attack.",
                host, expected, fingerprint
            ))),
        }
    }

    /// Send a CBOR-encoded envelope over the transport control channel.
    async fn send_raw(&self, envelope: &Envelope) -> WshResult<()> {
        let encoded = frame_encode(envelope)?;
        let mut transport = self.transport.lock().await;
        transport.send_control(&encoded).await
    }

    /// Receive a raw CBOR payload from the transport control channel.
    async fn recv_raw(&self) -> WshResult<Vec<u8>> {
        let mut transport = self.transport.lock().await;
        transport.recv_control().await
    }

    /// Send a control message (fire-and-forget).
    async fn send_control_message(&self, envelope: Envelope) -> WshResult<()> {
        let frame = frame_encode(&envelope)?;
        self.outgoing_tx
            .send(frame)
            .await
            .map_err(|_| WshError::Transport("outgoing channel closed".into()))
    }

    /// Send a control message and wait for a specific response type.
    ///
    /// Matches on message type alone, which is only safe when one request of
    /// this type is in flight. Use `send_and_wait_matching` when concurrent
    /// requests share a response type.
    async fn send_and_wait(
        &self,
        envelope: Envelope,
        expected_type: MsgType,
    ) -> WshResult<Envelope> {
        self.send_and_wait_matching(envelope, expected_type, None)
            .await
    }

    /// Send a control message and wait for the response that `matcher`
    /// claims, so concurrent requests sharing a response type cannot receive
    /// each other's replies. `None` accepts any envelope of `expected_type`.
    #[allow(clippy::type_complexity)]
    async fn send_and_wait_matching(
        &self,
        envelope: Envelope,
        expected_type: MsgType,
        matcher: Option<Box<dyn Fn(&Envelope) -> bool + Send + Sync>>,
    ) -> WshResult<Envelope> {
        let (tx, rx) = oneshot::channel();

        // Register the response listener
        {
            let mut responses = self.response_tx.lock().await;
            responses
                .entry(expected_type.into())
                .or_insert_with(Vec::new)
                .push(Waiter { tx, matcher });
        }

        // Also register for the fail variant
        let fail_type = match expected_type {
            MsgType::OpenOk => Some(MsgType::OpenFail),
            MsgType::AuthOk => Some(MsgType::AuthFail),
            MsgType::DetachOk => Some(MsgType::DetachFail),
            MsgType::ReverseAccept => Some(MsgType::ReverseReject),
            MsgType::SessionList => Some(MsgType::Error),
            MsgType::Presence => Some(MsgType::Error),
            _ => None,
        };

        let fail_rx = if let Some(ft) = fail_type {
            let (fail_tx, fail_rx) = oneshot::channel();
            let mut responses = self.response_tx.lock().await;
            responses
                .entry(ft.into())
                .or_insert_with(Vec::new)
                .push(Waiter {
                    tx: fail_tx,
                    matcher: None,
                });
            Some(fail_rx)
        } else {
            None
        };

        // Send the message
        self.send_control_message(envelope).await?;

        // Wait for response
        let timeout_duration = Duration::from_secs(30);

        if let Some(fail_rx) = fail_rx {
            tokio::select! {
                result = rx => {
                    result.map_err(|_| WshError::Transport("response channel dropped".into()))
                }
                fail_result = fail_rx => {
                    fail_result.map_err(|_| WshError::Transport("response channel dropped".into()))
                }
                _ = time::sleep(timeout_duration) => {
                    Err(WshError::Timeout)
                }
            }
        } else {
            tokio::select! {
                result = rx => {
                    result.map_err(|_| WshError::Transport("response channel dropped".into()))
                }
                _ = time::sleep(timeout_duration) => {
                    Err(WshError::Timeout)
                }
            }
        }
    }

    /// Register a one-shot waiter for the next incoming message of
    /// `expected_type`, without sending anything. Used by `initiate_e2e`'s
    /// "decapsulator" role, which only ever waits for the encapsulator's
    /// round-2 `KeyExchange` (it doesn't send one itself).
    async fn register_waiter(&self, expected_type: MsgType) -> oneshot::Receiver<Envelope> {
        let (tx, rx) = oneshot::channel();
        let mut responses = self.response_tx.lock().await;
        responses
            .entry(expected_type.into())
            .or_insert_with(Vec::new)
            .push(Waiter { tx, matcher: None });
        rx
    }

    /// Await a previously-registered waiter, subject to `timeout_duration`.
    async fn await_waiter(
        rx: oneshot::Receiver<Envelope>,
        timeout_duration: Duration,
    ) -> WshResult<Envelope> {
        tokio::select! {
            result = rx => {
                result.map_err(|_| WshError::Transport("response channel dropped".into()))
            }
            _ = time::sleep(timeout_duration) => {
                Err(WshError::Timeout)
            }
        }
    }

    /// Wait for the next incoming message of `expected_type`, without
    /// sending anything first.
    async fn wait_for(
        &self,
        expected_type: MsgType,
        timeout_duration: Duration,
    ) -> WshResult<Envelope> {
        let rx = self.register_waiter(expected_type).await;
        Self::await_waiter(rx, timeout_duration).await
    }

    /// Send a control message and wait for a specific response type, with
    /// a caller-provided timeout. Like `send_and_wait`, but lets the
    /// caller pick the timeout instead of the fixed 30s default -- used by
    /// `initiate_e2e`, whose timeout is a parameter mirroring the JS
    /// `initiateE2E(sessionId, algorithm, timeout)` signature. Unlike
    /// `send_and_wait`, this doesn't register a companion "fail type"
    /// waiter, since `KeyExchange` has no failure-reply counterpart.
    async fn send_and_wait_for(
        &self,
        envelope: Envelope,
        expected_type: MsgType,
        timeout_duration: Duration,
    ) -> WshResult<Envelope> {
        let rx = self.register_waiter(expected_type).await;
        self.send_control_message(envelope).await?;
        Self::await_waiter(rx, timeout_duration).await
    }

    /// The control message dispatch loop.
    ///
    /// Reads incoming control messages, routes responses to waiting tasks,
    /// handles session events (Exit, Close), and sends outgoing messages.
    async fn dispatch_loop(
        transport: Arc<Mutex<AnyTransport>>,
        mut outgoing_rx: mpsc::Receiver<Vec<u8>>,
        mut action_rx: mpsc::Receiver<ControlAction>,
        response_tx: Arc<Mutex<HashMap<u8, Vec<Waiter>>>>,
        sessions: Arc<Mutex<HashMap<u32, Arc<WshSession>>>>,
        connected: Arc<Mutex<bool>>,
        outgoing_tx: mpsc::Sender<Vec<u8>>,
        reverse_connect_tx: Option<mpsc::Sender<Envelope>>,
        relay_message_tx: Option<mpsc::Sender<Envelope>>,
        accepted_relay_peers: Arc<Mutex<HashSet<String>>>,
    ) {
        loop {
            let is_connected = { *connected.lock().await };
            if !is_connected {
                break;
            }

            tokio::select! {
                // Handle outgoing control messages
                Some(frame) = outgoing_rx.recv() => {
                    let mut t = transport.lock().await;
                    if let Err(e) = t.send_control(&frame).await {
                        tracing::error!("failed to send control message: {}", e);
                        let mut c = connected.lock().await;
                        *c = false;
                        break;
                    }
                }

                // Handle control actions from sessions (resize, signal, close)
                Some(action) = action_rx.recv() => {
                    let envelope = match action {
                        ControlAction::Data { channel_id, data } => Envelope {
                            msg_type: MsgType::SessionData,
                            payload: Payload::SessionData(SessionDataPayload { channel_id, data }),
                        },
                        ControlAction::EncryptedData { channel_id, session_id, nonce, ciphertext } => Envelope {
                            msg_type: MsgType::EncryptedFrame,
                            payload: Payload::EncryptedFrame(EncryptedFramePayload {
                                channel_id,
                                nonce,
                                ciphertext,
                                session_id,
                            }),
                        },
                        ControlAction::Resize { channel_id, cols, rows } => Envelope {
                            msg_type: MsgType::Resize,
                            payload: Payload::Resize(ResizePayload { channel_id, cols, rows }),
                        },
                        ControlAction::Signal { channel_id, signal } => Envelope {
                            msg_type: MsgType::Signal,
                            payload: Payload::Signal(SignalPayload { channel_id, signal }),
                        },
                        ControlAction::Close { channel_id } => Envelope {
                            msg_type: MsgType::Close,
                            payload: Payload::Close(ClosePayload { channel_id }),
                        },
                    };

                    match frame_encode(&envelope) {
                        Ok(frame) => {
                            let mut t = transport.lock().await;
                            if let Err(e) = t.send_control(&frame).await {
                                tracing::error!("failed to send action: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("failed to encode action: {}", e);
                        }
                    }
                }

                // Try to receive an incoming control message
                result = async {
                    let mut t = transport.lock().await;
                    t.recv_control().await
                } => {
                    match result {
                        Ok(data) => {
                            match decode_envelope(&data) {
                                Ok(envelope) => {
                                    eprintln!("DEBUGTRACE dispatch_loop got envelope msg_type={:?}", envelope.msg_type);
                                    Self::handle_incoming(
                                        envelope,
                                        &response_tx,
                                        &sessions,
                                        &outgoing_tx,
                                        &reverse_connect_tx,
                                        &relay_message_tx,
                                        &accepted_relay_peers,
                                    ).await;
                                    eprintln!("DEBUGTRACE dispatch_loop handle_incoming returned");
                                }
                                Err(e) => {
                                    tracing::warn!("failed to decode control message: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("control recv error: {}", e);
                            let mut c = connected.lock().await;
                            *c = false;
                            break;
                        }
                    }
                }
            }
        }

        tracing::debug!("dispatch loop ended");
    }

    /// Handle an incoming control message.
    fn handle_incoming<'a>(
        envelope: Envelope,
        response_tx: &'a Arc<Mutex<HashMap<u8, Vec<Waiter>>>>,
        sessions: &'a Arc<Mutex<HashMap<u32, Arc<WshSession>>>>,
        outgoing_tx: &'a mpsc::Sender<Vec<u8>>,
        reverse_connect_tx: &'a Option<mpsc::Sender<Envelope>>,
        relay_message_tx: &'a Option<mpsc::Sender<Envelope>>,
        accepted_relay_peers: &'a Arc<Mutex<HashSet<String>>>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            // Unwrap RelayForward: only deliver the inner message if it came
            // from a peer this client has actually accepted a bridge with, and
            // only if the inner message's own type is on the shared
            // relay-forwardable allowlist (defense in depth against a
            // misbehaving or compromised relay server).
            if let MsgType::RelayForward = envelope.msg_type {
                if let Payload::RelayForward(p) = &envelope.payload {
                    let trusted = accepted_relay_peers
                        .lock()
                        .await
                        .contains(&p.from_fingerprint);
                    if !trusted {
                        tracing::warn!(
                            from = %p.from_fingerprint,
                            "dropping RelayForward from untrusted/unaccepted peer"
                        );
                        return;
                    }
                    match decode_envelope(&p.inner) {
                        Ok(inner) if is_relay_forwardable(inner.msg_type) => {
                            Self::handle_incoming(
                                inner,
                                response_tx,
                                sessions,
                                outgoing_tx,
                                reverse_connect_tx,
                                relay_message_tx,
                                accepted_relay_peers,
                            )
                            .await;
                        }
                        Ok(inner) => {
                            tracing::warn!(
                                msg_type = ?inner.msg_type,
                                "dropping RelayForward wrapping a non-forwardable message type"
                            );
                        }
                        Err(err) => {
                            tracing::warn!(%err, "failed to decode RelayForward inner envelope");
                        }
                    }
                }
                return;
            }

            let msg_type_u8: u8 = envelope.msg_type.into();

            match envelope.msg_type {
                // Respond to server pings
                MsgType::Ping => {
                    if let Payload::PingPong(pp) = &envelope.payload {
                        let pong = Envelope {
                            msg_type: MsgType::Pong,
                            payload: Payload::PingPong(PingPongPayload { id: pp.id }),
                        };
                        if let Ok(frame) = frame_encode(&pong) {
                            let _ = outgoing_tx.send(frame).await;
                        }
                    }
                }

                // Ignore pong responses (keepalive ack)
                MsgType::Pong => {
                    tracing::trace!("received pong");
                }

                MsgType::Exit
                | MsgType::Close
                | MsgType::SessionData
                | MsgType::EncryptedFrame
                | MsgType::EchoAck
                | MsgType::EchoState
                | MsgType::TermSync
                | MsgType::TermDiff => {
                    let Some(channel_id) = envelope_channel_id(&envelope) else {
                        tracing::debug!(
                            "session-scoped message without channel ID: {:?}",
                            envelope.msg_type
                        );
                        return;
                    };

                    let session = {
                        let sessions = sessions.lock().await;
                        sessions.get(&channel_id).cloned()
                    };

                    if let Some(session) = session {
                        if matches!(envelope.msg_type, MsgType::Exit) {
                            if let Payload::Exit(exit) = &envelope.payload {
                                // `eprintln!`, not `tracing::info!`, is
                                // deliberate here: a `tracing::info!` call at
                                // exactly this point -- the dispatch loop
                                // processing an `Exit` envelope for a Virtual
                                // session, right after that same loop already
                                // logged at least one other event on this
                                // connection -- was found to hang forever
                                // (confirmed by bisecting with manual
                                // `eprintln!` markers immediately before/after
                                // the call; execution stops inside the macro
                                // and never returns). Root cause not
                                // identified (suspected interaction between
                                // this i686-unknown-linux-musl cross-compiled
                                // binary and `tracing-subscriber`'s global
                                // writer lock, but unconfirmed) -- tracked as
                                // a known issue on #38. `eprintln!` sidesteps
                                // the tracing subscriber entirely and is not
                                // known to hang.
                                eprintln!(
                                    "channel {} exited with code {}",
                                    exit.channel_id, exit.code
                                );
                            }
                        }

                        if let Err(err) = session.handle_control(&envelope).await {
                            tracing::debug!(
                                channel_id,
                                msg_type = ?envelope.msg_type,
                                "failed to route session control message: {err}"
                            );
                        }

                        if matches!(envelope.msg_type, MsgType::Close) {
                            let mut sessions = sessions.lock().await;
                            sessions.remove(&channel_id);
                        }
                    } else {
                        if let Some(tx) = relay_message_tx {
                            if let Err(err) = tx.send(envelope).await {
                                tracing::debug!("relay message channel closed: {err}");
                            }
                        } else {
                            tracing::debug!(
                                channel_id,
                                msg_type = ?envelope.msg_type,
                                "received session control message for unknown channel"
                            );
                        }
                    }
                }

                // Server error
                MsgType::Error => {
                    if let Payload::Error(err) = &envelope.payload {
                        tracing::error!("server error [{}]: {}", err.code, err.message);
                    }
                }

                // Shutdown notice
                MsgType::Shutdown => {
                    if let Payload::Shutdown(sd) = &envelope.payload {
                        tracing::warn!("server shutdown: {}", sd.reason);
                    }
                }

                // Incoming reverse connection request (unsolicited from relay)
                MsgType::ReverseConnect => {
                    tracing::info!("incoming reverse connect request");
                    if let Some(tx) = reverse_connect_tx {
                        if let Err(e) = tx.send(envelope).await {
                            tracing::warn!("reverse connect channel full or closed: {}", e);
                        }
                    } else {
                        tracing::debug!("reverse connect received but no handler registered");
                    }
                }

                // Route to waiting response handlers
                _ => {
                    let mut responses = response_tx.lock().await;
                    if let Some(waiters) = responses.get_mut(&msg_type_u8) {
                        if let Some(waiter) = take_matching_waiter(waiters, &envelope) {
                            let _ = waiter.tx.send(envelope);
                            if waiters.is_empty() {
                                responses.remove(&msg_type_u8);
                            }
                            return;
                        }
                    }

                    drop(responses);

                    if is_relay_forwardable(envelope.msg_type) {
                        if let Some(tx) = relay_message_tx {
                            if let Err(err) = tx.send(envelope).await {
                                tracing::debug!("relay message channel closed: {err}");
                            }
                            return;
                        }
                    }

                    tracing::debug!(
                        "unhandled control message: {:?}",
                        MsgType::try_from(msg_type_u8)
                    );
                }
            }
        })
    }
}

fn envelope_channel_id(envelope: &Envelope) -> Option<u32> {
    match &envelope.payload {
        Payload::Resize(payload) => Some(payload.channel_id),
        Payload::Signal(payload) => Some(payload.channel_id),
        Payload::Exit(payload) => Some(payload.channel_id),
        Payload::Close(payload) => Some(payload.channel_id),
        Payload::SessionData(payload) => Some(payload.channel_id),
        Payload::EncryptedFrame(payload) => Some(payload.channel_id),
        Payload::EchoAck(payload) => Some(payload.channel_id),
        Payload::EchoState(payload) => Some(payload.channel_id),
        Payload::TermSync(payload) => Some(payload.channel_id),
        Payload::TermDiff(payload) => Some(payload.channel_id),
        _ => None,
    }
}

fn known_host_label(url: &str) -> WshResult<String> {
    let (scheme, remainder) = url
        .split_once("://")
        .ok_or_else(|| WshError::Transport(format!("invalid URL: {url}")))?;

    let authority = remainder
        .split('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| WshError::Transport(format!("invalid URL authority: {url}")))?;

    if authority_has_port(authority) {
        return Ok(authority.to_string());
    }

    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "ws" => 80,
        "wss" | "https" | "wt" => 443,
        other => {
            return Err(WshError::Transport(format!(
                "unsupported URL scheme for known_hosts: {other}"
            )))
        }
    };

    Ok(format!("{authority}:{default_port}"))
}

fn authority_has_port(authority: &str) -> bool {
    if authority.starts_with('[') {
        authority
            .split_once(']')
            .is_some_and(|(_, remainder)| remainder.starts_with(':'))
    } else {
        authority.rsplit_once(':').is_some()
    }
}

impl Drop for WshClient {
    fn drop(&mut self) {
        if let Some(h) = self.dispatch_handle.take() {
            h.abort();
        }
        if let Some(h) = self.keepalive_handle.take() {
            h.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::{mpsc, oneshot, Mutex};
    use wsh_core::codec::decode_envelope;
    use wsh_core::messages::{
        ChannelKind, ClosePayload, EncryptedFramePayload, Envelope, KeyExchangePayload, MsgType,
        OpenOkPayload, Payload, ResizePayload, SessionDataMode, SessionDataPayload, SignalPayload,
    };

    use super::{known_host_label, SessionOpts, Waiter, WshClient};
    use crate::e2e::{ALGORITHM_HYBRID, ALGORITHM_X25519};
    use crate::session::ControlAction;
    use crate::session::WshSession;
    use crate::stream_frame::CoalesceOverride;
    use wsh_core::transport::ByteStream;
    use wsh_core::WshResult;

    // ── waiter selection (#139) ──────────────────────────────────────
    //
    // Waiters were keyed on message type alone and dispatch used Vec::pop(),
    // which is LIFO. With two McpCalls in flight the second caller received
    // the first reply; neither could detect it, because the normalised
    // result carries nothing identifying the tool.

    fn mcp_result(call_id: Option<&str>, body: &str) -> Envelope {
        Envelope {
            msg_type: MsgType::McpResult,
            payload: Payload::McpResult(wsh_core::messages::McpResultPayload {
                result: serde_json::json!({ "output": body }),
                call_id: call_id.map(|s| s.to_string()),
            }),
        }
    }

    fn waiter(
        matcher: Option<Box<dyn Fn(&Envelope) -> bool + Send + Sync>>,
    ) -> (super::Waiter, oneshot::Receiver<Envelope>) {
        let (tx, rx) = oneshot::channel();
        (super::Waiter { tx, matcher }, rx)
    }

    fn matches_call_id(id: &'static str) -> Box<dyn Fn(&Envelope) -> bool + Send + Sync> {
        Box::new(move |env: &Envelope| match &env.payload {
            Payload::McpResult(r) => r.call_id.is_none() || r.call_id.as_deref() == Some(id),
            _ => true,
        })
    }

    fn text_of(e: &Envelope) -> String {
        match &e.payload {
            Payload::McpResult(r) => r.result["output"].as_str().unwrap().to_string(),
            _ => panic!("not an McpResult"),
        }
    }

    #[tokio::test]
    async fn uncorrelated_waiters_are_served_first_in_first_out() {
        let (first, rx_first) = waiter(None);
        let (second, rx_second) = waiter(None);
        let mut waiters = vec![first, second];

        let reply = mcp_result(None, "the first reply");
        let taken =
            super::take_matching_waiter(&mut waiters, &reply).expect("a waiter must claim it");
        taken.tx.send(reply).unwrap();

        // The caller who registered FIRST must receive it. pop() handed this
        // to the SECOND caller, so this assertion is what fails under LIFO --
        // checking only `waiters.len()` would pass either way.
        // Drop the remaining waiter so its receiver resolves (as an error)
        // instead of hanging. Without this, a regression to LIFO makes this
        // test hang for the whole suite timeout rather than fail.
        drop(waiters);

        // The caller who registered FIRST must receive it. Under LIFO this
        // reply went to the SECOND caller, so rx_first resolves as an error
        // and this unwrap panics -- fast, and pointing at the real problem.
        assert_eq!(text_of(&rx_first.await.unwrap()), "the first reply");
        assert!(
            rx_second.await.is_err(),
            "the second waiter must not have been served"
        );
    }

    #[tokio::test]
    async fn each_correlated_waiter_takes_only_its_own_reply() {
        // Registration order is fast-then-slow and the FAST reply arrives
        // first. That ordering is deliberate: LIFO would hand it to the SLOW
        // waiter, which is exactly the swap being tested. Registering the
        // other way round lets pop() coincidentally do the right thing.
        let (w_fast, rx_fast) = waiter(Some(matches_call_id("rs-fast")));
        let (w_slow, rx_slow) = waiter(Some(matches_call_id("rs-slow")));
        let mut waiters = vec![w_fast, w_slow];

        let fast_reply = mcp_result(Some("rs-fast"), "RESULT OF fast_tool");
        let taken = super::take_matching_waiter(&mut waiters, &fast_reply)
            .expect("the fast waiter must claim its own reply");
        taken.tx.send(fast_reply).unwrap();

        let slow_reply = mcp_result(Some("rs-slow"), "RESULT OF slow_tool");
        let taken = super::take_matching_waiter(&mut waiters, &slow_reply)
            .expect("the slow waiter must claim its own reply");
        taken.tx.send(slow_reply).unwrap();

        assert_eq!(text_of(&rx_fast.await.unwrap()), "RESULT OF fast_tool");
        assert_eq!(text_of(&rx_slow.await.unwrap()), "RESULT OF slow_tool");
    }

    #[test]
    fn a_reply_matching_no_outstanding_call_is_left_alone() {
        let (w, _rx) = waiter(Some(matches_call_id("rs-mine")));
        let mut waiters = vec![w];

        let stray = mcp_result(Some("rs-someone-else"), "STRAY");
        assert!(super::take_matching_waiter(&mut waiters, &stray).is_none());
        // Still registered, still waiting for its own reply.
        assert_eq!(waiters.len(), 1);
    }

    #[test]
    fn a_responder_that_echoes_no_call_id_is_still_matched() {
        // An older server predating the field: nothing to correlate on, so
        // type-matching is all that is available and must keep working.
        let (w, _rx) = waiter(Some(matches_call_id("rs-mine")));
        let mut waiters = vec![w];
        assert!(super::take_matching_waiter(&mut waiters, &mcp_result(None, "legacy")).is_some());
    }

    #[test]
    fn known_host_label_preserves_explicit_websocket_port() {
        assert_eq!(
            known_host_label("ws://example.com:4422").unwrap(),
            "example.com:4422"
        );
    }

    #[test]
    fn known_host_label_adds_default_websocket_port() {
        assert_eq!(
            known_host_label("ws://example.com").unwrap(),
            "example.com:80"
        );
    }

    #[test]
    fn known_host_label_adds_default_tls_port() {
        assert_eq!(
            known_host_label("https://example.com/wsh").unwrap(),
            "example.com:443"
        );
    }

    #[test]
    fn known_host_label_preserves_ipv6_authority() {
        assert_eq!(
            known_host_label("wss://[2001:db8::1]:4422").unwrap(),
            "[2001:db8::1]:4422"
        );
    }

    #[test]
    fn known_host_label_adds_default_webtransport_port() {
        assert_eq!(
            known_host_label("wt://example.com/wsh").unwrap(),
            "example.com:443"
        );
    }

    #[test]
    fn known_host_label_preserves_explicit_webtransport_port() {
        assert_eq!(
            known_host_label("wt://example.com:5544/wsh").unwrap(),
            "example.com:5544"
        );
    }

    #[test]
    fn known_host_label_preserves_ipv6_webtransport_authority() {
        assert_eq!(
            known_host_label("wt://[2001:db8::1]:5544/wsh").unwrap(),
            "[2001:db8::1]:5544"
        );
    }

    #[tokio::test]
    async fn handle_incoming_routes_session_data_to_virtual_session() {
        let response_tx = Arc::new(Mutex::new(HashMap::new()));
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let (control_tx, _control_rx) = mpsc::channel(4);
        let session = Arc::new(WshSession::new_virtual(
            21,
            ChannelKind::Pty,
            control_tx,
            vec!["resize".into()],
        ));
        sessions.lock().await.insert(21, session.clone());
        let (outgoing_tx, _outgoing_rx) = mpsc::channel(4);

        WshClient::handle_incoming(
            Envelope {
                msg_type: MsgType::SessionData,
                payload: Payload::SessionData(SessionDataPayload {
                    channel_id: 21,
                    data: b"pwd\n".to_vec(),
                }),
            },
            &response_tx,
            &sessions,
            &outgoing_tx,
            &None,
            &None,
            &Arc::new(Mutex::new(HashSet::new())),
        )
        .await;

        let mut buf = [0_u8; 8];
        let n = session.read(&mut buf).await.unwrap();

        assert_eq!(n, 4);
        assert_eq!(&buf[..n], b"pwd\n");
    }

    #[tokio::test]
    async fn handle_incoming_removes_closed_session_from_tracking() {
        let response_tx = Arc::new(Mutex::new(HashMap::new()));
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let (control_tx, _control_rx) = mpsc::channel(4);
        let session = Arc::new(WshSession::new_virtual(
            22,
            ChannelKind::Pty,
            control_tx,
            vec![],
        ));
        sessions.lock().await.insert(22, session.clone());
        let (outgoing_tx, _outgoing_rx) = mpsc::channel(4);

        WshClient::handle_incoming(
            Envelope {
                msg_type: MsgType::Close,
                payload: Payload::Close(ClosePayload { channel_id: 22 }),
            },
            &response_tx,
            &sessions,
            &outgoing_tx,
            &None,
            &None,
            &Arc::new(Mutex::new(HashSet::new())),
        )
        .await;

        assert_eq!(session.state().await, crate::session::SessionState::Closed);
        assert!(!sessions.lock().await.contains_key(&22));
    }

    #[tokio::test]
    async fn handle_incoming_routes_unknown_session_messages_to_relay_channel() {
        let response_tx = Arc::new(Mutex::new(HashMap::new()));
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let (outgoing_tx, _outgoing_rx) = mpsc::channel(4);
        let (relay_tx, mut relay_rx) = mpsc::channel(4);

        WshClient::handle_incoming(
            Envelope {
                msg_type: MsgType::SessionData,
                payload: Payload::SessionData(SessionDataPayload {
                    channel_id: 99,
                    data: b"whoami\n".to_vec(),
                }),
            },
            &response_tx,
            &sessions,
            &outgoing_tx,
            &None,
            &Some(relay_tx),
            &Arc::new(Mutex::new(HashSet::new())),
        )
        .await;

        let forwarded = relay_rx
            .recv()
            .await
            .expect("missing relay-forwarded message");
        match forwarded.payload {
            Payload::SessionData(payload) => {
                assert_eq!(payload.channel_id, 99);
                assert_eq!(payload.data, b"whoami\n");
            }
            other => panic!("unexpected payload: {:?}", other),
        }
    }

    #[tokio::test]
    async fn open_session_uses_virtual_data_mode_when_server_returns_virtual_open_ok() {
        let response_tx = Arc::new(Mutex::new(HashMap::new()));
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let (control_action_tx, _control_action_rx) = mpsc::channel(4);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(4);

        let client = WshClient {
            transport: Arc::new(Mutex::new(crate::transport::AnyTransport::Test(
                crate::transport::TestTransport,
            ))),
            session_id: Some("sess-1".into()),
            token: None,
            sessions: sessions.clone(),
            control_action_tx,
            dispatch_handle: None,
            keepalive_handle: None,
            outgoing_tx,
            response_tx: response_tx.clone(),
            server_features: Arc::new(Mutex::new(Vec::new())),
            connected: Arc::new(Mutex::new(true)),
            reverse_connect_rx: Arc::new(Mutex::new(None)),
            relay_message_rx: Arc::new(Mutex::new(None)),
            accepted_relay_peers: Arc::new(Mutex::new(HashSet::new())),
        };

        let response_task = tokio::spawn(async move {
            let _open_frame = outgoing_rx.recv().await.expect("missing OPEN frame");
            let mut waiters = response_tx.lock().await;
            let tx = waiters
                .get_mut(&u8::from(MsgType::OpenOk))
                .and_then(|entries| entries.pop())
                .expect("missing OPEN_OK waiter");
            tx.tx
                .send(Envelope {
                    msg_type: MsgType::OpenOk,
                    payload: Payload::OpenOk(OpenOkPayload {
                        channel_id: 31,
                        stream_ids: vec![],
                        data_mode: SessionDataMode::Virtual,
                        capabilities: vec!["resize".into(), "signal".into()],
                        session_id: Some("sess-31".into()),
                        token: Some(vec![9u8; 40]),
                    }),
                })
                .unwrap();
        });

        let session = client.open_session(SessionOpts::default()).await.unwrap();
        assert_eq!(session.channel_id(), 31);
        assert_eq!(*session.data_mode(), SessionDataMode::Virtual);
        assert_eq!(
            session.capabilities(),
            &["resize".to_string(), "signal".to_string()]
        );
        // clawser #48: OpenOk now carries the session_id/token this channel
        // belongs to (pty/exec only), so a later Attach/Resume from another
        // connection has something real to present.
        assert_eq!(session.session_id(), Some("sess-31"));
        assert_eq!(session.resume_token(), Some(&[9u8; 40][..]));
        response_task.await.unwrap();
    }

    // ── initiate_e2e (wsh #18) ──────────────────────────────────────
    //
    // No integration test goes through the real wsh-server relay here:
    // that relay requires two different connections to share a session_id
    // via Attach/Resume (fixed in clawser #48 -- see wsh-server's own test
    // suite and tools/test/wsh-rust-server.test.mjs for real two-party
    // coverage through the actual server). These *unit* tests don't spin
    // up a server at all, so instead they build two independent
    // `WshClient`s over `AnyTransport::Test` and
    // wire each one's outgoing control frames directly into the other's
    // `handle_incoming`, i.e. a loopback transport pair fully under test
    // control, exercising the exact same `initiate_e2e` code path real
    // peers would use.

    /// Bundle of handles needed both to construct a `WshClient` for
    /// testing and to build a loopback relay *targeting* it (since the
    /// relevant fields aren't otherwise reachable once moved into the
    /// struct).
    struct TestClientRig {
        client: WshClient,
        outgoing_rx: mpsc::Receiver<Vec<u8>>,
        response_tx: Arc<Mutex<HashMap<u8, Vec<Waiter>>>>,
        sessions: Arc<Mutex<HashMap<u32, Arc<WshSession>>>>,
        outgoing_tx: mpsc::Sender<Vec<u8>>,
        accepted_relay_peers: Arc<Mutex<HashSet<String>>>,
        /// Receiver for this client's `WshSession`s' `ControlAction`s
        /// (resize/signal/close/data/encrypted-data). A real connection's
        /// `dispatch_loop` drains this; these tests instead pump it via
        /// `wire_action_loopback` so `WshSession::write` (and the E2E
        /// sealing it does when enabled) exercises the exact same
        /// production code path.
        control_action_rx: mpsc::Receiver<ControlAction>,
    }

    fn build_test_client(session_id: &str) -> TestClientRig {
        let response_tx = Arc::new(Mutex::new(HashMap::new()));
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let (control_action_tx, control_action_rx) = mpsc::channel(4);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(64);
        let accepted_relay_peers = Arc::new(Mutex::new(HashSet::new()));

        let client = WshClient {
            transport: Arc::new(Mutex::new(crate::transport::AnyTransport::Test(
                crate::transport::TestTransport,
            ))),
            session_id: Some(session_id.to_string()),
            token: None,
            sessions: sessions.clone(),
            control_action_tx,
            dispatch_handle: None,
            keepalive_handle: None,
            outgoing_tx: outgoing_tx.clone(),
            response_tx: response_tx.clone(),
            server_features: Arc::new(Mutex::new(Vec::new())),
            connected: Arc::new(Mutex::new(true)),
            reverse_connect_rx: Arc::new(Mutex::new(None)),
            relay_message_rx: Arc::new(Mutex::new(None)),
            accepted_relay_peers: accepted_relay_peers.clone(),
        };

        TestClientRig {
            client,
            outgoing_rx,
            response_tx,
            sessions,
            outgoing_tx,
            accepted_relay_peers,
            control_action_rx,
        }
    }

    /// Pump every frame received on `rx` into `handle_incoming` for
    /// whichever client owns the given `response_tx`/`sessions`/
    /// `outgoing_tx`/`accepted_relay_peers`, as if it arrived over the
    /// wire from a real peer. Runs until the sender end of `rx` is
    /// dropped or the task is aborted.
    ///
    /// Frames on `rx` are `frame_encode`'s length-prefixed CBOR (the same
    /// bytes a real transport's `send_control` would write to the wire),
    /// so the 4-byte length prefix is stripped before `decode_envelope`,
    /// matching what a real transport's `recv_control` already does for
    /// the dispatch loop (see e.g. `transport::websocket::decode_control_payload`).
    async fn relay_forever(
        mut rx: mpsc::Receiver<Vec<u8>>,
        response_tx: Arc<Mutex<HashMap<u8, Vec<Waiter>>>>,
        sessions: Arc<Mutex<HashMap<u32, Arc<WshSession>>>>,
        outgoing_tx: mpsc::Sender<Vec<u8>>,
        accepted_relay_peers: Arc<Mutex<HashSet<String>>>,
    ) {
        while let Some(frame) = rx.recv().await {
            if frame.len() < 4 {
                continue;
            }
            if let Ok(envelope) = decode_envelope(&frame[4..]) {
                WshClient::handle_incoming(
                    envelope,
                    &response_tx,
                    &sessions,
                    &outgoing_tx,
                    &None,
                    &None,
                    &accepted_relay_peers,
                )
                .await;
            }
        }
    }

    /// Wire up a bidirectional loopback relay between two rigs and return
    /// the join handles so the caller can abort them once the exchange
    /// under test has completed.
    fn wire_loopback(
        rig_a: &mut TestClientRig,
        rig_b: &mut TestClientRig,
    ) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        let a_to_b_rx = std::mem::replace(&mut rig_a.outgoing_rx, mpsc::channel(1).1);
        let b_to_a_rx = std::mem::replace(&mut rig_b.outgoing_rx, mpsc::channel(1).1);

        let a_to_b = tokio::spawn(relay_forever(
            a_to_b_rx,
            rig_b.response_tx.clone(),
            rig_b.sessions.clone(),
            rig_b.outgoing_tx.clone(),
            rig_b.accepted_relay_peers.clone(),
        ));
        let b_to_a = tokio::spawn(relay_forever(
            b_to_a_rx,
            rig_a.response_tx.clone(),
            rig_a.sessions.clone(),
            rig_a.outgoing_tx.clone(),
            rig_a.accepted_relay_peers.clone(),
        ));
        (a_to_b, b_to_a)
    }

    /// Pump every `ControlAction` a `WshSession` sends (via `write`,
    /// `resize`, `signal`, `close`) into the peer's `handle_incoming`, the
    /// same conversion `dispatch_loop`'s `action_rx` arm performs for a
    /// real connection (see the `ControlAction::Data`/`EncryptedData`/...
    /// match in `dispatch_loop` above) -- this is what lets
    /// `e2e_frame_round_trip_through_two_in_process_sessions` exercise
    /// `WshSession::write`'s real E2E-sealing branch end-to-end instead of
    /// calling `e2e_frame::seal_frame` directly.
    async fn action_relay_forever(
        mut rx: mpsc::Receiver<ControlAction>,
        response_tx: Arc<Mutex<HashMap<u8, Vec<Waiter>>>>,
        sessions: Arc<Mutex<HashMap<u32, Arc<WshSession>>>>,
        outgoing_tx: mpsc::Sender<Vec<u8>>,
        accepted_relay_peers: Arc<Mutex<HashSet<String>>>,
    ) {
        while let Some(action) = rx.recv().await {
            let envelope = match action {
                ControlAction::Data { channel_id, data } => Envelope {
                    msg_type: MsgType::SessionData,
                    payload: Payload::SessionData(SessionDataPayload { channel_id, data }),
                },
                ControlAction::EncryptedData {
                    channel_id,
                    session_id,
                    nonce,
                    ciphertext,
                } => Envelope {
                    msg_type: MsgType::EncryptedFrame,
                    payload: Payload::EncryptedFrame(EncryptedFramePayload {
                        channel_id,
                        nonce,
                        ciphertext,
                        session_id,
                    }),
                },
                ControlAction::Resize {
                    channel_id,
                    cols,
                    rows,
                } => Envelope {
                    msg_type: MsgType::Resize,
                    payload: Payload::Resize(ResizePayload {
                        channel_id,
                        cols,
                        rows,
                    }),
                },
                ControlAction::Signal { channel_id, signal } => Envelope {
                    msg_type: MsgType::Signal,
                    payload: Payload::Signal(SignalPayload { channel_id, signal }),
                },
                ControlAction::Close { channel_id } => Envelope {
                    msg_type: MsgType::Close,
                    payload: Payload::Close(ClosePayload { channel_id }),
                },
            };

            WshClient::handle_incoming(
                envelope,
                &response_tx,
                &sessions,
                &outgoing_tx,
                &None,
                &None,
                &accepted_relay_peers,
            )
            .await;
        }
    }

    /// Wire up a bidirectional `ControlAction` relay between two rigs'
    /// sessions, so writes on one rig's `WshSession` are delivered to the
    /// peer rig's matching-channel_id session. Returns join handles to
    /// abort once the exchange under test is done.
    fn wire_action_loopback(
        rig_a: &mut TestClientRig,
        rig_b: &mut TestClientRig,
    ) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        let a_to_b_rx = std::mem::replace(&mut rig_a.control_action_rx, mpsc::channel(1).1);
        let b_to_a_rx = std::mem::replace(&mut rig_b.control_action_rx, mpsc::channel(1).1);

        let a_to_b = tokio::spawn(action_relay_forever(
            a_to_b_rx,
            rig_b.response_tx.clone(),
            rig_b.sessions.clone(),
            rig_b.outgoing_tx.clone(),
            rig_b.accepted_relay_peers.clone(),
        ));
        let b_to_a = tokio::spawn(action_relay_forever(
            b_to_a_rx,
            rig_a.response_tx.clone(),
            rig_a.sessions.clone(),
            rig_a.outgoing_tx.clone(),
            rig_a.accepted_relay_peers.clone(),
        ));
        (a_to_b, b_to_a)
    }

    #[tokio::test]
    async fn e2e_frame_round_trip_through_two_in_process_sessions_over_the_control_action_path() {
        // Extends the initiate_e2e coverage below: after two clients agree
        // on a shared secret via the real initiate_e2e handshake, wire two
        // WshSessions (one per client, opposite E2E roles) over the same
        // ControlAction -> dispatch-loop-equivalent -> handle_incoming path
        // a real connection uses, and prove WshSession::write/handle_control
        // seal/open real SessionData-equivalent traffic end-to-end --
        // exercising the exact production code added for clawser's E2E PR 2
        // (wsh #19), not just e2e_frame's unit-level primitives.
        let session_id = "sess-e2e-frame-roundtrip";
        let mut rig_a = build_test_client(session_id);
        let mut rig_b = build_test_client(session_id);
        let (a_to_b, b_to_a) = wire_loopback(&mut rig_a, &mut rig_b);

        let (result_a, result_b) = tokio::join!(
            rig_a
                .client
                .initiate_e2e(session_id, ALGORITHM_X25519, Duration::from_secs(5)),
            rig_b
                .client
                .initiate_e2e(session_id, ALGORITHM_X25519, Duration::from_secs(5)),
        );
        let result_a = result_a.expect("client A initiate_e2e failed");
        let result_b = result_b.expect("client B initiate_e2e failed");
        assert_eq!(result_a.shared_secret, result_b.shared_secret);

        // Build two in-process virtual sessions, one per client, sharing
        // channel_id=1 and this test's session_id -- as a real OpenOk
        // would establish on each connection.
        let session_a = Arc::new(
            WshSession::new_virtual(
                1,
                ChannelKind::Pty,
                rig_a.client.control_action_tx.clone(),
                vec![],
            )
            .with_session_credentials(Some(session_id.to_string()), None),
        );
        let session_b = Arc::new(
            WshSession::new_virtual(
                1,
                ChannelKind::Pty,
                rig_b.client.control_action_tx.clone(),
                vec![],
            )
            .with_session_credentials(Some(session_id.to_string()), None),
        );
        rig_a.sessions.lock().await.insert(1, session_a.clone());
        rig_b.sessions.lock().await.insert(1, session_b.clone());

        session_a
            .enable_e2e(
                result_a.shared_secret,
                crate::e2e_frame::RoleTag::Initiator,
                crate::stream_frame::CoalesceOverride::Default,
            )
            .await
            .expect("enable_e2e on session A failed");
        session_b
            .enable_e2e(
                result_b.shared_secret,
                crate::e2e_frame::RoleTag::Responder,
                crate::stream_frame::CoalesceOverride::Default,
            )
            .await
            .expect("enable_e2e on session B failed");

        let (action_a_to_b, action_b_to_a) = wire_action_loopback(&mut rig_a, &mut rig_b);

        session_a.write(b"hello from A, sealed").await.unwrap();
        let mut buf = [0_u8; 64];
        let n = session_b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from A, sealed");

        session_b.write(b"hello from B, sealed").await.unwrap();
        let n = session_a.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from B, sealed");

        // A second frame each direction proves the monotonic counters keep
        // advancing correctly across multiple writes, not just the first.
        session_a.write(b"second message from A").await.unwrap();
        let n = session_b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"second message from A");

        a_to_b.abort();
        b_to_a.abort();
        action_a_to_b.abort();
        action_b_to_a.abort();
    }

    /// A `ByteStream` wrapping one end of a `tokio::io::duplex` pipe --
    /// stands in for a real WebTransport/WebSocket stream-mode data
    /// stream, giving two in-process `WshSession`s a real raw byte pipe
    /// between them (as opposed to the mpsc-based `ControlAction` relay
    /// the virtual-mode tests above use).
    struct DuplexByteStream {
        inner: tokio::io::DuplexStream,
        /// If set, every byte slice passed to `write_all` is appended here
        /// before being written to `inner` -- lets a test assert on the
        /// exact bytes that crossed the "wire" (e.g. that plaintext never
        /// appears in it), independent of what the peer decodes.
        recorded: Option<Arc<std::sync::Mutex<Vec<u8>>>>,
    }

    impl ByteStream for DuplexByteStream {
        fn read<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = WshResult<usize>> + Send + 'a>>
        {
            use tokio::io::AsyncReadExt;
            Box::pin(async move { Ok(self.inner.read(buf).await?) })
        }

        fn write_all<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = WshResult<()>> + Send + 'a>>
        {
            use tokio::io::AsyncWriteExt;
            Box::pin(async move {
                if let Some(recorded) = &self.recorded {
                    recorded.lock().unwrap().extend_from_slice(data);
                }
                self.inner.write_all(data).await?;
                self.inner.flush().await?;
                Ok(())
            })
        }

        fn close(
            &mut self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = WshResult<()>> + Send + '_>>
        {
            use tokio::io::AsyncWriteExt;
            Box::pin(async move {
                let _ = self.inner.shutdown().await;
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn stream_mode_e2e_round_trip_through_real_write_and_read_path() {
        // Extends the virtual-mode coverage above (wsh #19 / clawser E2E PR
        // 2) to stream-mode sessions (wsh #22 / clawser E2E PR 2): after a
        // real initiate_e2e handshake between two in-process clients, wire
        // two stream-backed WshSessions over a real raw byte pipe
        // (tokio::io::duplex, standing in for a WebTransport/WebSocket data
        // stream) and prove WshSession::write/read seal+frame/reassemble+
        // open real chunk-framed traffic end-to-end -- exercising the
        // production stream_frame::ChunkAccumulator/encode_chunk plus
        // session.rs's generalized enable_e2e, not just unit-level
        // primitives. Also asserts the raw wire bytes never contain the
        // plaintext, proving the data is actually encrypted in transit and
        // not merely framed.
        let session_id = "sess-stream-e2e-roundtrip";
        let mut rig_a = build_test_client(session_id);
        let mut rig_b = build_test_client(session_id);
        let (a_to_b, b_to_a) = wire_loopback(&mut rig_a, &mut rig_b);

        let (result_a, result_b) = tokio::join!(
            rig_a
                .client
                .initiate_e2e(session_id, ALGORITHM_X25519, Duration::from_secs(5)),
            rig_b
                .client
                .initiate_e2e(session_id, ALGORITHM_X25519, Duration::from_secs(5)),
        );
        let result_a = result_a.expect("client A initiate_e2e failed");
        let result_b = result_b.expect("client B initiate_e2e failed");
        assert_eq!(result_a.shared_secret, result_b.shared_secret);

        a_to_b.abort();
        b_to_a.abort();

        let (dup_a, dup_b) = tokio::io::duplex(64 * 1024);
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stream_a: Box<dyn ByteStream> = Box::new(DuplexByteStream {
            inner: dup_a,
            recorded: Some(recorded.clone()),
        });
        let stream_b: Box<dyn ByteStream> = Box::new(DuplexByteStream {
            inner: dup_b,
            recorded: None,
        });

        let session_a = Arc::new(
            WshSession::new_stream(
                1,
                ChannelKind::Exec,
                stream_a,
                rig_a.client.control_action_tx.clone(),
                vec![],
            )
            .with_session_credentials(Some(session_id.to_string()), None),
        );
        let session_b = Arc::new(
            WshSession::new_stream(
                1,
                ChannelKind::Exec,
                stream_b,
                rig_b.client.control_action_tx.clone(),
                vec![],
            )
            .with_session_credentials(Some(session_id.to_string()), None),
        );

        session_a
            .enable_e2e(
                result_a.shared_secret,
                crate::e2e_frame::RoleTag::Initiator,
                CoalesceOverride::Disabled,
            )
            .await
            .expect("enable_e2e on stream session A failed");
        session_b
            .enable_e2e(
                result_b.shared_secret,
                crate::e2e_frame::RoleTag::Responder,
                CoalesceOverride::Disabled,
            )
            .await
            .expect("enable_e2e on stream session B failed");

        let plaintext = b"secret exec output that must never appear on the wire in cleartext";
        session_a.write(plaintext).await.unwrap();

        let mut buf = [0_u8; 256];
        let n = session_b.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            plaintext,
            "session B must recover A's exact plaintext"
        );

        let recorded_bytes = recorded.lock().unwrap().clone();
        assert!(
            !recorded_bytes
                .windows(plaintext.len())
                .any(|window| window == plaintext.as_slice()),
            "plaintext must never appear verbatim in the raw wire bytes"
        );

        // A second write/read in the same direction proves the monotonic
        // send/recv counters (and the chunk accumulator's cursor) keep
        // working correctly across multiple chunks, not just the first.
        let second = b"a second exec chunk";
        session_a.write(second).await.unwrap();
        let n = session_b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], second);

        // And the reverse direction, proving the two sides' opposite role
        // tags keep nonces from colliding on a real duplex pipe.
        let reply = b"reply from B";
        session_b.write(reply).await.unwrap();
        let n = session_a.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], reply);
    }

    #[tokio::test]
    async fn initiate_e2e_classical_round_trip_matches_between_both_sides() {
        let mut rig_a = build_test_client("sess-e2e-classical");
        let mut rig_b = build_test_client("sess-e2e-classical");
        let (a_to_b, b_to_a) = wire_loopback(&mut rig_a, &mut rig_b);

        let (result_a, result_b) = tokio::join!(
            rig_a.client.initiate_e2e(
                "sess-e2e-classical",
                ALGORITHM_X25519,
                Duration::from_secs(5)
            ),
            rig_b.client.initiate_e2e(
                "sess-e2e-classical",
                ALGORITHM_X25519,
                Duration::from_secs(5)
            ),
        );

        let result_a = result_a.expect("client A initiate_e2e failed");
        let result_b = result_b.expect("client B initiate_e2e failed");

        assert!(!result_a.hybrid, "classical mode should not report hybrid");
        assert!(!result_b.hybrid, "classical mode should not report hybrid");
        assert_eq!(
            result_a.shared_secret, result_b.shared_secret,
            "both sides must derive the same AES-256-GCM key"
        );

        a_to_b.abort();
        b_to_a.abort();
    }

    #[tokio::test]
    async fn initiate_e2e_hybrid_round_trip_matches_and_uses_hybrid() {
        // Loop for probabilistic coverage of both ML-KEM-768
        // encapsulator/decapsulator role assignments (the role is chosen
        // by comparing two randomly generated ephemeral X25519 public
        // keys, so a single run only exercises one side of that branch),
        // mirroring @johnhenry/wsh's test/client.test.mjs hybrid-mode test
        // loop.
        let mut previous_secret: Option<[u8; 32]> = None;

        for i in 0..10 {
            let session_id = format!("sess-e2e-hybrid-{i}");
            let mut rig_a = build_test_client(&session_id);
            let mut rig_b = build_test_client(&session_id);
            let (a_to_b, b_to_a) = wire_loopback(&mut rig_a, &mut rig_b);

            let (result_a, result_b) = tokio::join!(
                rig_a
                    .client
                    .initiate_e2e(&session_id, ALGORITHM_HYBRID, Duration::from_secs(5)),
                rig_b
                    .client
                    .initiate_e2e(&session_id, ALGORITHM_HYBRID, Duration::from_secs(5)),
            );

            let result_a = result_a.expect("client A initiate_e2e failed");
            let result_b = result_b.expect("client B initiate_e2e failed");

            assert!(
                result_a.hybrid,
                "iteration {i}: client A should report hybrid active"
            );
            assert!(
                result_b.hybrid,
                "iteration {i}: client B should report hybrid active"
            );
            assert_eq!(
                result_a.shared_secret, result_b.shared_secret,
                "iteration {i}: both sides must derive the same hybrid-combined key"
            );

            // Sanity check mirroring the JS suite's "different final keys"
            // test: successive runs (fresh ephemeral keys each time) must
            // not collide.
            if let Some(prev) = previous_secret {
                assert_ne!(
                    prev, result_a.shared_secret,
                    "iteration {i}: fresh ephemeral keys must not reproduce the previous key"
                );
            }
            previous_secret = Some(result_a.shared_secret);

            a_to_b.abort();
            b_to_a.abort();
        }
    }

    #[tokio::test]
    async fn initiate_e2e_falls_back_to_classical_when_peer_lacks_hybrid_support() {
        // Client A asks for hybrid; client B only speaks classical (as a
        // pre-#18 peer would). Algorithm agility, not a hard cutover: both
        // sides must still agree on a classical-only key.
        let mut rig_a = build_test_client("sess-e2e-fallback");
        let mut rig_b = build_test_client("sess-e2e-fallback");
        let (a_to_b, b_to_a) = wire_loopback(&mut rig_a, &mut rig_b);

        let (result_a, result_b) = tokio::join!(
            rig_a.client.initiate_e2e(
                "sess-e2e-fallback",
                ALGORITHM_HYBRID,
                Duration::from_secs(5)
            ),
            rig_b.client.initiate_e2e(
                "sess-e2e-fallback",
                ALGORITHM_X25519,
                Duration::from_secs(5)
            ),
        );

        let result_a = result_a.expect("client A initiate_e2e failed");
        let result_b = result_b.expect("client B initiate_e2e failed");

        assert!(
            !result_a.hybrid,
            "client A requested hybrid but must fall back since peer didn't support it"
        );
        assert!(!result_b.hybrid);
        assert_eq!(
            result_a.shared_secret, result_b.shared_secret,
            "fallback must still agree on the classical X25519 key"
        );

        a_to_b.abort();
        b_to_a.abort();
    }

    #[test]
    fn key_exchange_payload_round_trips_all_hybrid_fields() {
        // Cross-language interop guard: proves the Rust `KeyExchangePayload`
        // CBOR encoding preserves every field a JS peer's round-1 hybrid
        // message would send (algorithm, public_key, session_id,
        // kem_public_key), and that a round-2 ciphertext-only message
        // (kem_ciphertext only, no public_key/kem_public_key) round-trips
        // too -- field presence/absence here is exactly what
        // `@johnhenry/wsh`'s `messages.gen.mjs` `keyExchange()` produces
        // (only sets `public_key`/`kem_public_key`/`kem_ciphertext` when
        // not `undefined`), so a wrong `#[serde(skip_serializing_if)]`
        // here would silently desync from real JS peers.
        let round1 = Envelope {
            msg_type: MsgType::KeyExchange,
            payload: Payload::KeyExchange(KeyExchangePayload {
                algorithm: ALGORITHM_HYBRID.to_string(),
                public_key: Some(vec![0xAB; 32]),
                session_id: "sess-interop".to_string(),
                kem_public_key: Some(vec![0xCD; 1184]),
                kem_ciphertext: None,
            }),
        };
        let encoded = wsh_core::codec::frame_encode(&round1).unwrap();
        let decoded = decode_envelope(&encoded[4..]).unwrap();
        match decoded.payload {
            Payload::KeyExchange(p) => {
                assert_eq!(p.algorithm, ALGORITHM_HYBRID);
                assert_eq!(p.public_key, Some(vec![0xAB; 32]));
                assert_eq!(p.session_id, "sess-interop");
                assert_eq!(p.kem_public_key, Some(vec![0xCD; 1184]));
                assert_eq!(p.kem_ciphertext, None);
            }
            other => panic!("unexpected payload: {other:?}"),
        }

        let round2 = Envelope {
            msg_type: MsgType::KeyExchange,
            payload: Payload::KeyExchange(KeyExchangePayload {
                algorithm: ALGORITHM_HYBRID.to_string(),
                public_key: None,
                session_id: "sess-interop".to_string(),
                kem_public_key: None,
                kem_ciphertext: Some(vec![0xEF; 1088]),
            }),
        };
        let encoded = wsh_core::codec::frame_encode(&round2).unwrap();
        let decoded = decode_envelope(&encoded[4..]).unwrap();
        match decoded.payload {
            Payload::KeyExchange(p) => {
                assert_eq!(p.public_key, None);
                assert_eq!(p.kem_public_key, None);
                assert_eq!(p.kem_ciphertext, Some(vec![0xEF; 1088]));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }
}
