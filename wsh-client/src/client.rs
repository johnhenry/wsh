//! The main wsh client.
//!
//! `WshClient` manages the connection lifecycle: transport selection, handshake,
//! authentication, session management, and keepalive.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time;

use wsh_core::codec::{decode_envelope, frame_encode};
use wsh_core::error::{WshError, WshResult};
use wsh_core::messages::*;

use crate::auth;
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
    response_tx: Arc<Mutex<HashMap<u8, Vec<oneshot::Sender<Envelope>>>>>,
    /// Whether the client is connected.
    connected: Arc<Mutex<bool>>,
    /// Receiver for incoming ReverseConnect notifications (take-once).
    reverse_connect_rx: Arc<Mutex<Option<mpsc::Receiver<Envelope>>>>,
    /// Receiver for relay-forwarded control/data messages (take-once).
    relay_message_rx: Arc<Mutex<Option<mpsc::Receiver<Envelope>>>>,
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
        let response_tx: Arc<Mutex<HashMap<u8, Vec<oneshot::Sender<Envelope>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let sessions: Arc<Mutex<HashMap<u32, Arc<WshSession>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let connected = Arc::new(Mutex::new(true));

        // Channel for unsolicited incoming ReverseConnect messages
        let (rc_tx, rc_rx) = mpsc::channel::<Envelope>(16);
        let reverse_connect_rx = Arc::new(Mutex::new(Some(rc_rx)));
        let (relay_tx, relay_rx) = mpsc::channel::<Envelope>(128);
        let relay_message_rx = Arc::new(Mutex::new(Some(relay_rx)));

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
            connected: connected.clone(),
            reverse_connect_rx,
            relay_message_rx,
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

                        Arc::new(WshSession::new_stream(
                            ok.channel_id,
                            kind,
                            stream.stream,
                            self.control_action_tx.clone(),
                            ok.capabilities.clone(),
                        ))
                    }
                    SessionDataMode::Virtual => Arc::new(WshSession::new_virtual(
                        ok.channel_id,
                        kind,
                        self.control_action_tx.clone(),
                        ok.capabilities.clone(),
                    )),
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
    pub async fn attach_session(&self, session_id: &str, read_only: bool) -> WshResult<()> {
        let token = self
            .token
            .as_ref()
            .ok_or_else(|| WshError::AuthFailed("no session token available".into()))?;

        let mode = if read_only {
            "view".to_string()
        } else {
            "control".to_string()
        };

        let envelope = Envelope {
            msg_type: MsgType::Attach,
            payload: Payload::Attach(AttachPayload {
                session_id: session_id.to_string(),
                token: token.clone(),
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

        let (server_session_id, server_fingerprints) = match &server_hello.payload {
            Payload::ServerHello(sh) => (sh.session_id.clone(), sh.fingerprints.clone()),
            _ => return Err(WshError::InvalidMessage("expected SERVER_HELLO".into())),
        };

        // Verify host key (TOFU)
        if config.verify_host {
            if let Some(first_fp) = server_fingerprints.first() {
                self.verify_host_key(known_host, first_fp)?;
            }
        }

        // Receive CHALLENGE
        let challenge_data = self.recv_raw().await?;
        let challenge = decode_envelope(&challenge_data)?;

        let nonce = match &challenge.payload {
            Payload::Challenge(c) => c.nonce.clone(),
            _ => return Err(WshError::InvalidMessage("expected CHALLENGE".into())),
        };

        // Authenticate
        let auth_envelope = match auth_method {
            AuthMethod::Pubkey => {
                let key_name = config.key_name.as_deref().unwrap_or("default");

                let keystore = crate::keystore::KeyStore::default_location()?;
                let (signing_key, verifying_key) = keystore.load(key_name)?;

                let signature = auth::sign_challenge(&signing_key, &server_session_id, &nonce);
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
    async fn send_and_wait(
        &self,
        envelope: Envelope,
        expected_type: MsgType,
    ) -> WshResult<Envelope> {
        let (tx, rx) = oneshot::channel();

        // Register the response listener
        {
            let mut responses = self.response_tx.lock().await;
            responses
                .entry(expected_type.into())
                .or_insert_with(Vec::new)
                .push(tx);
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
                .push(fail_tx);
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

    /// The control message dispatch loop.
    ///
    /// Reads incoming control messages, routes responses to waiting tasks,
    /// handles session events (Exit, Close), and sends outgoing messages.
    async fn dispatch_loop(
        transport: Arc<Mutex<AnyTransport>>,
        mut outgoing_rx: mpsc::Receiver<Vec<u8>>,
        mut action_rx: mpsc::Receiver<ControlAction>,
        response_tx: Arc<Mutex<HashMap<u8, Vec<oneshot::Sender<Envelope>>>>>,
        sessions: Arc<Mutex<HashMap<u32, Arc<WshSession>>>>,
        connected: Arc<Mutex<bool>>,
        outgoing_tx: mpsc::Sender<Vec<u8>>,
        reverse_connect_tx: Option<mpsc::Sender<Envelope>>,
        relay_message_tx: Option<mpsc::Sender<Envelope>>,
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
                                    Self::handle_incoming(
                                        envelope,
                                        &response_tx,
                                        &sessions,
                                        &outgoing_tx,
                                        &reverse_connect_tx,
                                        &relay_message_tx,
                                    ).await;
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
    async fn handle_incoming(
        envelope: Envelope,
        response_tx: &Arc<Mutex<HashMap<u8, Vec<oneshot::Sender<Envelope>>>>>,
        sessions: &Arc<Mutex<HashMap<u32, Arc<WshSession>>>>,
        outgoing_tx: &mpsc::Sender<Vec<u8>>,
        reverse_connect_tx: &Option<mpsc::Sender<Envelope>>,
        relay_message_tx: &Option<mpsc::Sender<Envelope>>,
    ) {
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
                            tracing::info!(
                                "channel {} exited with code {}",
                                exit.channel_id,
                                exit.code
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
                    if let Some(tx) = waiters.pop() {
                        let _ = tx.send(envelope);
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

                tracing::debug!("unhandled control message: {:?}", MsgType::try_from(msg_type_u8));
            }
        }
    }
}

fn is_relay_forwardable(msg_type: MsgType) -> bool {
    matches!(
        msg_type,
        MsgType::Open
            | MsgType::OpenOk
            | MsgType::OpenFail
            | MsgType::Close
            | MsgType::Exit
            | MsgType::Resize
            | MsgType::Signal
            | MsgType::SessionData
            | MsgType::GatewayData
            | MsgType::GatewayOk
            | MsgType::GatewayFail
            | MsgType::GatewayClose
            | MsgType::McpDiscover
            | MsgType::McpTools
            | MsgType::McpCall
            | MsgType::McpResult
            | MsgType::EchoAck
            | MsgType::EchoState
            | MsgType::TermSync
            | MsgType::TermDiff
    )
}

fn envelope_channel_id(envelope: &Envelope) -> Option<u32> {
    match &envelope.payload {
        Payload::Resize(payload) => Some(payload.channel_id),
        Payload::Signal(payload) => Some(payload.channel_id),
        Payload::Exit(payload) => Some(payload.channel_id),
        Payload::Close(payload) => Some(payload.channel_id),
        Payload::SessionData(payload) => Some(payload.channel_id),
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
    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::sync::{mpsc, Mutex};
    use wsh_core::messages::{
        ChannelKind, ClosePayload, Envelope, MsgType, OpenOkPayload, Payload, SessionDataMode,
        SessionDataPayload,
    };

    use super::{known_host_label, SessionOpts, WshClient};
    use crate::session::WshSession;

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
        )
        .await;

        let forwarded = relay_rx.recv().await.expect("missing relay-forwarded message");
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
            connected: Arc::new(Mutex::new(true)),
            reverse_connect_rx: Arc::new(Mutex::new(None)),
            relay_message_rx: Arc::new(Mutex::new(None)),
        };

        let response_task = tokio::spawn(async move {
            let _open_frame = outgoing_rx.recv().await.expect("missing OPEN frame");
            let mut waiters = response_tx.lock().await;
            let tx = waiters
                .get_mut(&u8::from(MsgType::OpenOk))
                .and_then(|entries| entries.pop())
                .expect("missing OPEN_OK waiter");
            tx.send(Envelope {
                msg_type: MsgType::OpenOk,
                payload: Payload::OpenOk(OpenOkPayload {
                    channel_id: 31,
                    stream_ids: vec![],
                    data_mode: SessionDataMode::Virtual,
                    capabilities: vec!["resize".into(), "signal".into()],
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
        response_task.await.unwrap();
    }
}
