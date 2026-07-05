//! Core server: accepts connections and dispatches to the handshake flow.
//!
//! Owns the server secret (for token signing), session manager, relay subsystem,
//! and MCP bridge. Coordinates the lifecycle of all incoming connections.

use crate::config::ServerConfig;
use crate::gateway::forwarder::GatewayForwarder;
use crate::gateway::listener::ReverseListenerManager;
use crate::gateway::policy::{GatewayPolicy, GatewayPolicyEnforcer};
use crate::gateway::GatewayEvent;
use crate::handshake;
use crate::mcp::{McpBridge, McpProxy};
use crate::relay::{PeerMetadata, PeerRegistry, RelayBroker};
use crate::session::SessionManager;
use crate::transport::{websocket, webtransport};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};
use wsh_core::keys::{load_authorized_keys, AuthorizedKey};
use wsh_core::messages::*;
use wsh_core::{decode_envelope, fingerprint, frame_encode, verify_token, WshError, WshResult};

/// Per-connection context threaded through the session loop.
struct ConnectionContext {
    /// Authenticated username.
    username: String,
    /// Key fingerprint (from auth).
    fingerprint: String,
    /// Session ID assigned during auth.
    session_id: String,
    /// Session token.
    token: Vec<u8>,
    /// Sender for pushing messages to this connection's transport.
    peer_tx: mpsc::Sender<Envelope>,
    /// Connection ID from peer registry (set when registered as reverse peer).
    conn_id: Option<u64>,
}

/// A share link entry for session sharing.
#[derive(Clone, Debug)]
struct ShareEntry {
    /// The generated share ID.
    share_id: String,
    /// The underlying session this share refers to.
    session_id: String,
    /// Share mode ("read" or "control").
    mode: String,
    /// Time-to-live in seconds.
    ttl: u64,
    /// When this share was created.
    created: std::time::Instant,
}

/// An ephemeral guest invite token with metadata.
#[derive(Clone, Debug)]
struct GuestToken {
    /// The opaque token string.
    token: String,
    /// Session this token grants access to.
    session_id: String,
    /// Granted permissions (e.g. ["read"]).
    permissions: Vec<String>,
    /// When this token was created.
    created: std::time::Instant,
    /// Time-to-live in seconds.
    ttl: u64,
    /// Whether the token has been revoked.
    revoked: bool,
}

impl GuestToken {
    fn is_expired(&self) -> bool {
        self.created.elapsed().as_secs() >= self.ttl
    }

    fn is_valid(&self) -> bool {
        !self.revoked && !self.is_expired()
    }
}

/// Per-session rate control state.
#[derive(Clone, Debug)]
struct RateControlState {
    max_bytes_per_sec: u64,
    policy: String,
    queued_bytes: u64,
}

/// Per-session copilot attachment.
#[derive(Clone, Debug)]
struct CopilotSession {
    model: String,
    conn_id: u64,
    peer_tx: mpsc::Sender<Envelope>,
}

/// A node in the cluster for horizontal scaling.
#[derive(Clone, Debug)]
struct ClusterNode {
    node_id: String,
    endpoint: String,
    load: f64,
    capacity: u32,
    last_seen: std::time::Instant,
}

/// Loaded policy for the policy engine.
#[derive(Clone, Debug)]
struct PolicyStore {
    policy_id: String,
    version: u64,
    rules: serde_json::Value,
}

/// Per-session terminal config.
#[derive(Clone, Debug)]
struct TerminalConfigState {
    frontend: String,
    options: serde_json::Value,
}

/// Per-session echo tracking for predictive local echo.
#[derive(Clone, Debug)]
struct EchoTracker {
    last_echo_seq: u64,
    cursor_x: u16,
    cursor_y: u16,
    pending: u32,
}

/// The wsh server instance.
pub struct WshServer {
    /// Server configuration.
    config: ServerConfig,
    /// HMAC secret for session tokens.
    secret: Vec<u8>,
    /// Authorized keys loaded from disk.
    authorized_keys: Vec<AuthorizedKey>,
    /// Session manager.
    sessions: Arc<SessionManager>,
    /// Peer registry for reverse connections.
    peer_registry: Arc<PeerRegistry>,
    /// Relay broker.
    relay_broker: Arc<RelayBroker>,
    /// MCP CLI tool bridge.
    mcp_bridge: Arc<RwLock<McpBridge>>,
    /// MCP proxy to local servers.
    mcp_proxy: Arc<RwLock<McpProxy>>,
    /// Directory for session recordings.
    recording_dir: Option<PathBuf>,
    /// Gateway forwarder (TCP/UDP/DNS).
    gateway_forwarder: Arc<GatewayForwarder>,
    /// Reverse listener manager.
    reverse_listener: Arc<ReverseListenerManager>,
    /// Whether gateway is enabled.
    gateway_enabled: bool,
    /// Per-connection outbound senders, keyed by connection_id.
    /// Used to forward ReverseConnect messages to specific peers.
    peer_senders: Arc<RwLock<HashMap<u64, mpsc::Sender<Envelope>>>>,
    /// Rate limiters for auth and attach attempts.
    rate_limits: Arc<tokio::sync::Mutex<crate::auth::ServerRateLimits>>,
    /// Broadcast sender for server shutdown notification.
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// Guest token store: token string → GuestToken.
    guest_tokens: Arc<RwLock<HashMap<String, GuestToken>>>,
    /// Per-session ACL: session_id → set of allowed principals.
    session_acls: Arc<RwLock<HashMap<String, HashMap<String, Vec<String>>>>>,
    /// Per-session rate control state: session_id → RateControlState.
    rate_control_state: Arc<RwLock<HashMap<String, RateControlState>>>,
    /// Per-session copilot attachments: session_id → Vec<CopilotSession>.
    copilot_sessions: Arc<RwLock<HashMap<String, Vec<CopilotSession>>>>,
    /// Cluster node registry for horizontal scaling.
    cluster_nodes: Arc<RwLock<HashMap<String, ClusterNode>>>,
    /// Active policy store.
    policy_store: Arc<RwLock<Option<PolicyStore>>>,
    /// Per-channel terminal config.
    terminal_configs: Arc<RwLock<HashMap<u32, TerminalConfigState>>>,
    /// Per-channel echo tracking.
    echo_trackers: Arc<RwLock<HashMap<u32, EchoTracker>>>,
    /// Share link store: share_id → ShareEntry.
    share_entries: Arc<RwLock<HashMap<String, ShareEntry>>>,
    /// Connection-to-session mapping: conn_id → session_id.
    /// Used to scope E2E relay and CopilotSuggest to session participants only.
    conn_session_map: Arc<RwLock<HashMap<u64, String>>>,
    /// Channel-to-session mapping: channel_id → session_id.
    /// Used by Close/Resize to operate on the correct session.
    channel_sessions: Arc<RwLock<HashMap<u32, String>>>,
    /// Relay pairs: maps conn_id → partner conn_id for bidirectional relay.
    /// When a ReverseConnect bridge is established between a CLI client and a
    /// browser peer, both directions are stored here so that forwardable
    /// messages from one side are relayed to the other.
    relay_pairs: Arc<RwLock<HashMap<u64, u64>>>,
    /// Pending reverse-connect handshakes: conn_id → partner conn_id.
    /// These entries exist after `ReverseConnect` is forwarded and before the
    /// target peer answers with `ReverseAccept` or `ReverseReject`.
    pending_relay_pairs: Arc<RwLock<HashMap<u64, u64>>>,
    /// Atomic counter for generating unique connection IDs.
    /// Starts at 1; 0 is reserved as sentinel for unwrap_or(0).
    next_conn_id: Arc<AtomicU64>,
    /// Atomic counter for generating unique channel IDs (collision-free).
    next_channel_id: Arc<AtomicU32>,
}

impl WshServer {
    /// Create a new server instance.
    pub fn new(config: ServerConfig) -> WshResult<Self> {
        // Generate server secret
        let secret = wsh_core::generate_secret();

        // Load authorized keys
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        let authorized_keys = load_authorized_keys(&home).unwrap_or_else(|e| {
            warn!(error = %e, "failed to load authorized_keys, no pubkey auth available");
            Vec::new()
        });

        if authorized_keys.is_empty() {
            warn!("no authorized keys loaded — pubkey authentication will fail");
        } else {
            info!(count = authorized_keys.len(), "loaded authorized keys");
        }

        // Session manager
        let sessions = Arc::new(SessionManager::new(
            config.max_sessions,
            config.session_ttl,
            config.idle_timeout,
        ));

        // Relay
        let peer_registry = Arc::new(PeerRegistry::new());
        let relay_broker = Arc::new(RelayBroker::new(peer_registry.clone()));

        // MCP
        let mcp_bridge = Arc::new(RwLock::new(McpBridge::new()));
        let mcp_proxy = Arc::new(RwLock::new(McpProxy::new()));

        // Recording directory
        let recording_dir = dirs::home_dir().map(|h| h.join(".wsh").join("recordings"));
        if let Some(ref dir) = recording_dir {
            if let Err(e) = std::fs::create_dir_all(dir) {
                warn!(path = %dir.display(), error = %e, "could not create recordings dir");
            }
        }

        // Gateway
        let gateway_policy = GatewayPolicy {
            allowed_destinations: config.gateway_allowed_destinations.clone(),
            max_connections: config.gateway_max_connections,
            enable_reverse_tunnels: config.gateway_enable_reverse_tunnels,
        };
        let policy_enforcer = Arc::new(GatewayPolicyEnforcer::new(gateway_policy));
        let gateway_forwarder = Arc::new(GatewayForwarder::new(policy_enforcer.clone()));
        let reverse_listener = Arc::new(ReverseListenerManager::new(policy_enforcer));
        let gateway_enabled = config.gateway_enabled;

        Ok(Self {
            config,
            secret,
            authorized_keys,
            sessions,
            peer_registry,
            relay_broker,
            mcp_bridge,
            mcp_proxy,
            recording_dir,
            gateway_forwarder,
            reverse_listener,
            gateway_enabled,
            peer_senders: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(tokio::sync::Mutex::new(
                crate::auth::ServerRateLimits::default(),
            )),
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            guest_tokens: Arc::new(RwLock::new(HashMap::new())),
            session_acls: Arc::new(RwLock::new(HashMap::new())),
            rate_control_state: Arc::new(RwLock::new(HashMap::new())),
            copilot_sessions: Arc::new(RwLock::new(HashMap::new())),
            cluster_nodes: Arc::new(RwLock::new(HashMap::new())),
            policy_store: Arc::new(RwLock::new(None)),
            terminal_configs: Arc::new(RwLock::new(HashMap::new())),
            echo_trackers: Arc::new(RwLock::new(HashMap::new())),
            share_entries: Arc::new(RwLock::new(HashMap::new())),
            conn_session_map: Arc::new(RwLock::new(HashMap::new())),
            channel_sessions: Arc::new(RwLock::new(HashMap::new())),
            relay_pairs: Arc::new(RwLock::new(HashMap::new())),
            pending_relay_pairs: Arc::new(RwLock::new(HashMap::new())),
            next_conn_id: Arc::new(AtomicU64::new(1)),
            next_channel_id: Arc::new(AtomicU32::new(1)),
        })
    }

    /// Start listening on both WebTransport and WebSocket.
    pub async fn run(self, tls_config: Arc<rustls::ServerConfig>) -> WshResult<()> {
        let server = Arc::new(self);

        let quic_addr: SocketAddr = format!("0.0.0.0:{}", server.config.port)
            .parse()
            .map_err(|e| WshError::Other(format!("invalid address: {e}")))?;
        let ws_addr: SocketAddr = format!("0.0.0.0:{}", server.config.port)
            .parse()
            .map_err(|e| WshError::Other(format!("invalid address: {e}")))?;

        // Start WebTransport listener
        let (_endpoint, mut wt_rx) = webtransport::start_listener(
            quic_addr,
            &server.config.cert_path,
            &server.config.key_path,
        )
        .await?;

        // Start WebSocket listener on the same configured port over TCP/TLS.
        let mut ws_rx = websocket::start_listener(ws_addr, tls_config).await?;

        // Start session GC + idle warning task
        let gc_sessions = server.sessions.clone();
        let gc_registry = server.peer_registry.clone();
        let gc_peer_senders = server.peer_senders.clone();
        let gc_rate_limits = server.rate_limits.clone();
        let gc_guest_tokens = server.guest_tokens.clone();
        let gc_cluster_nodes = server.cluster_nodes.clone();
        let gc_share_entries = server.share_entries.clone();
        let gc_conn_session_map = server.conn_session_map.clone();
        let gc_session_acls = server.session_acls.clone();
        let gc_rate_control_state = server.rate_control_state.clone();
        let gc_copilot_sessions = server.copilot_sessions.clone();
        let gc_terminal_configs = server.terminal_configs.clone();
        let gc_echo_trackers = server.echo_trackers.clone();
        let gc_channel_sessions = server.channel_sessions.clone();
        let gc_relay_pairs = server.relay_pairs.clone();
        let gc_pending_relay_pairs = server.pending_relay_pairs.clone();
        let idle_warning_grace: u64 = 300; // Warn 5 minutes before idle timeout
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;

                // Send idle warnings to sessions nearing timeout (scoped to session participants)
                {
                    let sessions = gc_sessions.list().await;
                    let senders = gc_peer_senders.read().await;
                    let conn_map = gc_conn_session_map.read().await;
                    for session in &sessions {
                        if session.attached_count == 0 {
                            // Session is detached; check if idle warning threshold reached
                            let idle_timeout = gc_sessions.idle_timeout().await;
                            if session.idle_secs + idle_warning_grace >= idle_timeout
                                && session.idle_secs < idle_timeout
                            {
                                let expires_in = idle_timeout.saturating_sub(session.idle_secs);
                                let warning = Envelope {
                                    msg_type: MsgType::IdleWarning,
                                    payload: Payload::IdleWarning(IdleWarningPayload {
                                        expires_in,
                                    }),
                                };
                                // Send only to connections associated with THIS session
                                for (&conn_id, sid) in conn_map.iter() {
                                    if sid == &session.id {
                                        if let Some(sender) = senders.get(&conn_id) {
                                            let _ = sender.try_send(warning.clone());
                                        }
                                    }
                                }
                                debug!(
                                    session_id = %session.id,
                                    expires_in,
                                    "sent idle warning"
                                );
                            }
                        }
                    }
                }

                gc_sessions.gc().await;
                gc_registry.gc(3600).await;

                // GC expired guest tokens
                {
                    let mut tokens = gc_guest_tokens.write().await;
                    tokens.retain(|_, t| t.is_valid());
                }

                // GC stale cluster nodes (>5 min since last announce)
                {
                    let mut nodes = gc_cluster_nodes.write().await;
                    nodes.retain(|_, n| n.last_seen.elapsed().as_secs() < 300);
                }

                // GC expired share entries
                {
                    let mut shares = gc_share_entries.write().await;
                    shares.retain(|_, s| s.created.elapsed().as_secs() < s.ttl);
                }

                // GC rate limiters periodically
                {
                    let mut limits = gc_rate_limits.lock().await;
                    limits.gc();
                }

                // GC session-keyed maps for sessions that no longer exist
                {
                    let active_ids: std::collections::HashSet<String> = gc_sessions
                        .list()
                        .await
                        .iter()
                        .map(|s| s.id.clone())
                        .collect();
                    // session_acls
                    gc_session_acls
                        .write()
                        .await
                        .retain(|sid, _| active_ids.contains(sid));
                    // rate_control_state
                    gc_rate_control_state
                        .write()
                        .await
                        .retain(|sid, _| active_ids.contains(sid));
                    // copilot_sessions
                    gc_copilot_sessions
                        .write()
                        .await
                        .retain(|sid, _| active_ids.contains(sid));
                    // channel_sessions
                    gc_channel_sessions
                        .write()
                        .await
                        .retain(|_, sid| active_ids.contains(sid));
                }

                // GC conn_session_map entries for connections no longer in peer_senders
                {
                    let senders = gc_peer_senders.read().await;
                    gc_conn_session_map
                        .write()
                        .await
                        .retain(|cid, _| senders.contains_key(cid));
                }

                // GC relay_pairs entries for connections no longer in peer_senders
                {
                    let senders = gc_peer_senders.read().await;
                    gc_relay_pairs
                        .write()
                        .await
                        .retain(|cid, _| senders.contains_key(cid));
                    gc_pending_relay_pairs
                        .write()
                        .await
                        .retain(|cid, _| senders.contains_key(cid));
                }

                // GC channel-keyed maps (terminal_configs, echo_trackers)
                // Evict oldest half when maps exceed 1000 entries, preserving active entries.
                // Since channel_ids are hashed from session_ids, we can't reliably map them
                // back to sessions, but we can prevent unbounded growth.
                {
                    let mut configs = gc_terminal_configs.write().await;
                    if configs.len() > 1000 {
                        // Keep only half (arbitrary eviction since we lack age tracking)
                        let to_remove: Vec<u32> =
                            configs.keys().take(configs.len() / 2).copied().collect();
                        for key in to_remove {
                            configs.remove(&key);
                        }
                    }
                    let mut trackers = gc_echo_trackers.write().await;
                    if trackers.len() > 1000 {
                        let to_remove: Vec<u32> =
                            trackers.keys().take(trackers.len() / 2).copied().collect();
                        for key in to_remove {
                            trackers.remove(&key);
                        }
                    }
                }
            }
        });

        info!(
            webtransport_port = server.config.port,
            websocket_port = server.config.port,
            relay = server.config.enable_relay,
            "wsh-server ready"
        );

        // Accept connections from both transports
        loop {
            tokio::select! {
                Some(wt_conn) = wt_rx.recv() => {
                    let srv = server.clone();
                    tokio::spawn(async move {
                        if let Err(e) = srv.handle_webtransport(wt_conn).await {
                            warn!(error = %e, "WebTransport connection error");
                        }
                    });
                }
                Some(ws_conn) = ws_rx.recv() => {
                    let srv = server.clone();
                    tokio::spawn(async move {
                        if let Err(e) = srv.handle_websocket(ws_conn).await {
                            warn!(error = %e, "WebSocket connection error");
                        }
                    });
                }
                else => {
                    info!("all listeners closed, shutting down");
                    break;
                }
            }
        }

        // Broadcast shutdown to all connected clients
        info!("broadcasting shutdown to connected clients");
        let _ = server.shutdown_tx.send(());

        Ok(())
    }

    /// Handle a WebTransport connection through the auth handshake.
    async fn handle_webtransport(
        &self,
        conn: webtransport::WebTransportConnection,
    ) -> WshResult<()> {
        let remote = conn.remote_addr;
        info!(remote = %remote, "handling WebTransport connection");

        // Accept the first bidirectional stream as the control channel.
        let (mut send, mut recv) = conn
            .connection
            .accept_bi()
            .await
            .map_err(|e| WshError::Transport(format!("WebTransport accept failed: {e}")))?;

        // Read HELLO
        let hello_bytes = read_webtransport_frame(&mut recv).await?;
        let envelope = decode_envelope(&hello_bytes)?;

        let hello = match (&envelope.msg_type, &envelope.payload) {
            (MsgType::Hello, Payload::Hello(h)) => h.clone(),
            _ => {
                return Err(WshError::InvalidMessage(
                    "expected HELLO as first message".into(),
                ));
            }
        };

        // Send SERVER_HELLO + CHALLENGE
        let server_fingerprints: Vec<String> = self
            .authorized_keys
            .iter()
            .map(|k| k.fingerprint.clone())
            .collect();
        let features = self.build_feature_list();
        let hello_result = handshake::handle_hello(&hello, &server_fingerprints, Some(&features))?;

        let sh_frame = frame_encode(&hello_result.server_hello)?;
        send.write_all(&sh_frame)
            .await
            .map_err(|e| WshError::Transport(format!("WebTransport write failed: {e}")))?;

        let challenge_frame = frame_encode(&hello_result.challenge)?;
        send.write_all(&challenge_frame)
            .await
            .map_err(|e| WshError::Transport(format!("WebTransport write failed: {e}")))?;

        // Read AUTH
        let auth_bytes = read_webtransport_frame(&mut recv).await?;
        let auth_envelope = decode_envelope(&auth_bytes)?;

        let auth = match (&auth_envelope.msg_type, &auth_envelope.payload) {
            (MsgType::Auth, Payload::Auth(a)) => a.clone(),
            _ => {
                let fail = handshake::build_auth_fail("expected AUTH message");
                let fail_frame = frame_encode(&fail)?;
                let _ = send.write_all(&fail_frame).await;
                return Err(WshError::InvalidMessage("expected AUTH message".into()));
            }
        };

        // Rate limit check (WebTransport)
        {
            let ip = remote.ip();
            let rate_limited = {
                let mut limits = self.rate_limits.lock().await;
                !limits.check_auth(&ip)
            };
            if rate_limited {
                let fail = handshake::build_auth_fail("rate limited: too many auth attempts");
                let fail_frame = frame_encode(&fail)?;
                let _ = send.write_all(&fail_frame).await;
                return Err(WshError::AuthFailed("rate limited".into()));
            }
        }

        // Pre-check password auth against config hashes
        if auth.method == AuthMethod::Password {
            match auth.password {
                Some(ref password) => {
                    if let Some(expected_hash) = self.config.password_hashes.get(&hello.username) {
                        if !handshake::verify_password_hash(password, expected_hash) {
                            let fail = handshake::build_auth_fail("invalid password");
                            let fail_frame = frame_encode(&fail)?;
                            let _ = send.write_all(&fail_frame).await;
                            return Err(WshError::AuthFailed("invalid password".into()));
                        }
                    } else {
                        let fail = handshake::build_auth_fail("unknown user");
                        let fail_frame = frame_encode(&fail)?;
                        let _ = send.write_all(&fail_frame).await;
                        return Err(WshError::AuthFailed(
                            "unknown user for password auth".into(),
                        ));
                    }
                }
                None => {
                    let fail = handshake::build_auth_fail("password required");
                    let fail_frame = frame_encode(&fail)?;
                    let _ = send.write_all(&fail_frame).await;
                    return Err(WshError::AuthFailed(
                        "password auth without password".into(),
                    ));
                }
            }
        }

        // Verify
        match handshake::verify_auth(
            &auth,
            &hello_result.nonce,
            &hello_result.session_id,
            &self.authorized_keys,
            &self.secret,
            self.config.session_ttl,
            self.config.allow_pubkey,
            self.config.allow_password,
        ) {
            Ok(mut result) => {
                result.username = hello.username.clone();
                let ok = handshake::build_auth_ok(
                    &result.session_id,
                    &result.token,
                    self.config.session_ttl,
                );
                let ok_frame = frame_encode(&ok)?;
                send.write_all(&ok_frame)
                    .await
                    .map_err(|e| WshError::Transport(format!("WebTransport write failed: {e}")))?;

                info!(
                    remote = %remote,
                    username = %result.username,
                    session_id = %result.session_id,
                    "WebTransport auth OK"
                );

                let (peer_tx, peer_rx) = mpsc::channel::<Envelope>(64);
                // Assign a unique conn_id and register in peer_senders/conn_session_map
                // so E2E relay, CopilotSuggest, and idle warnings are session-scoped.
                let conn_id = self.alloc_conn_id();
                self.peer_senders
                    .write()
                    .await
                    .insert(conn_id, peer_tx.clone());
                self.conn_session_map
                    .write()
                    .await
                    .insert(conn_id, result.session_id.clone());
                let mut ctx = ConnectionContext {
                    username: result.username.clone(),
                    fingerprint: result.fingerprint.clone(),
                    session_id: result.session_id.clone(),
                    token: result.token.clone(),
                    peer_tx,
                    conn_id: Some(conn_id),
                };

                // Session message loop
                self.session_loop_quic(&mut send, &mut recv, &mut ctx, peer_rx)
                    .await?;

                // Cleanup: unregister peer if registered
                if let Some(cid) = ctx.conn_id {
                    self.peer_senders.write().await.remove(&cid);
                    self.conn_session_map.write().await.remove(&cid);
                    self.clear_relay_links(cid).await;
                }
                self.peer_registry.unregister(&ctx.fingerprint).await;
            }
            Err(e) => {
                let fail = handshake::build_auth_fail(&e.to_string());
                let fail_frame = frame_encode(&fail)?;
                let _ = send.write_all(&fail_frame).await;
                return Err(e);
            }
        }

        Ok(())
    }

    /// Handle a WebSocket connection through the auth handshake.
    async fn handle_websocket(&self, mut conn: websocket::WebSocketConnection) -> WshResult<()> {
        let remote = conn.remote_addr;
        info!(remote = %remote, "handling WebSocket connection");

        // Read HELLO
        let hello_bytes = websocket::ws_recv_control(&mut conn.ws_stream)
            .await?
            .ok_or_else(|| WshError::Transport("connection closed before HELLO".into()))?;
        let envelope = decode_envelope(&hello_bytes)?;

        let hello = match (&envelope.msg_type, &envelope.payload) {
            (MsgType::Hello, Payload::Hello(h)) => h.clone(),
            _ => {
                return Err(WshError::InvalidMessage(
                    "expected HELLO as first message".into(),
                ));
            }
        };

        // Send SERVER_HELLO + CHALLENGE
        let server_fingerprints: Vec<String> = self
            .authorized_keys
            .iter()
            .map(|k| k.fingerprint.clone())
            .collect();
        let features = self.build_feature_list();
        let hello_result = handshake::handle_hello(&hello, &server_fingerprints, Some(&features))?;

        let sh_frame = frame_encode(&hello_result.server_hello)?;
        websocket::ws_send_control(&mut conn.ws_stream, &sh_frame).await?;

        let challenge_frame = frame_encode(&hello_result.challenge)?;
        websocket::ws_send_control(&mut conn.ws_stream, &challenge_frame).await?;

        // Read AUTH
        let auth_bytes = websocket::ws_recv_control(&mut conn.ws_stream)
            .await?
            .ok_or_else(|| WshError::Transport("connection closed before AUTH".into()))?;
        let auth_envelope = decode_envelope(&auth_bytes)?;

        let auth = match (&auth_envelope.msg_type, &auth_envelope.payload) {
            (MsgType::Auth, Payload::Auth(a)) => a.clone(),
            _ => {
                let fail = handshake::build_auth_fail("expected AUTH message");
                let fail_frame = frame_encode(&fail)?;
                let _ = websocket::ws_send_control(&mut conn.ws_stream, &fail_frame).await;
                return Err(WshError::InvalidMessage("expected AUTH message".into()));
            }
        };

        // Rate limit check (WebSocket)
        {
            let ip = remote.ip();
            let rate_limited = {
                let mut limits = self.rate_limits.lock().await;
                !limits.check_auth(&ip)
            };
            if rate_limited {
                let fail = handshake::build_auth_fail("rate limited: too many auth attempts");
                let fail_frame = frame_encode(&fail)?;
                let _ = websocket::ws_send_control(&mut conn.ws_stream, &fail_frame).await;
                return Err(WshError::AuthFailed("rate limited".into()));
            }
        }

        // Pre-check password auth against config hashes
        if auth.method == AuthMethod::Password {
            match auth.password {
                Some(ref password) => {
                    if let Some(expected_hash) = self.config.password_hashes.get(&hello.username) {
                        if !handshake::verify_password_hash(password, expected_hash) {
                            let fail = handshake::build_auth_fail("invalid password");
                            let fail_frame = frame_encode(&fail)?;
                            let _ =
                                websocket::ws_send_control(&mut conn.ws_stream, &fail_frame).await;
                            return Err(WshError::AuthFailed("invalid password".into()));
                        }
                    } else {
                        let fail = handshake::build_auth_fail("unknown user");
                        let fail_frame = frame_encode(&fail)?;
                        let _ = websocket::ws_send_control(&mut conn.ws_stream, &fail_frame).await;
                        return Err(WshError::AuthFailed(
                            "unknown user for password auth".into(),
                        ));
                    }
                }
                None => {
                    let fail = handshake::build_auth_fail("password required");
                    let fail_frame = frame_encode(&fail)?;
                    let _ = websocket::ws_send_control(&mut conn.ws_stream, &fail_frame).await;
                    return Err(WshError::AuthFailed(
                        "password auth without password".into(),
                    ));
                }
            }
        }

        // Verify
        match handshake::verify_auth(
            &auth,
            &hello_result.nonce,
            &hello_result.session_id,
            &self.authorized_keys,
            &self.secret,
            self.config.session_ttl,
            self.config.allow_pubkey,
            self.config.allow_password,
        ) {
            Ok(mut result) => {
                result.username = hello.username.clone();
                let ok = handshake::build_auth_ok(
                    &result.session_id,
                    &result.token,
                    self.config.session_ttl,
                );
                let ok_frame = frame_encode(&ok)?;
                websocket::ws_send_control(&mut conn.ws_stream, &ok_frame).await?;

                info!(
                    remote = %remote,
                    username = %result.username,
                    session_id = %result.session_id,
                    "WebSocket auth OK"
                );

                let (peer_tx, peer_rx) = mpsc::channel::<Envelope>(64);
                // Assign a unique conn_id and register in peer_senders/conn_session_map
                // so E2E relay, CopilotSuggest, and idle warnings are session-scoped.
                let conn_id = self.alloc_conn_id();
                self.peer_senders
                    .write()
                    .await
                    .insert(conn_id, peer_tx.clone());
                self.conn_session_map
                    .write()
                    .await
                    .insert(conn_id, result.session_id.clone());
                let mut ctx = ConnectionContext {
                    username: result.username.clone(),
                    fingerprint: result.fingerprint.clone(),
                    session_id: result.session_id.clone(),
                    token: result.token.clone(),
                    peer_tx,
                    conn_id: Some(conn_id),
                };

                // Session message loop
                self.session_loop_ws(&mut conn, &mut ctx, peer_rx).await?;

                // Cleanup: unregister peer if registered
                if let Some(cid) = ctx.conn_id {
                    self.peer_senders.write().await.remove(&cid);
                    self.conn_session_map.write().await.remove(&cid);
                    self.clear_relay_links(cid).await;
                }
                self.peer_registry.unregister(&ctx.fingerprint).await;
            }
            Err(e) => {
                let fail = handshake::build_auth_fail(&e.to_string());
                let fail_frame = frame_encode(&fail)?;
                let _ = websocket::ws_send_control(&mut conn.ws_stream, &fail_frame).await;
                return Err(e);
            }
        }

        Ok(())
    }

    /// Access the session manager.
    pub fn sessions(&self) -> &SessionManager {
        &self.sessions
    }

    /// Access the MCP bridge.
    pub fn mcp_bridge(&self) -> &Arc<RwLock<McpBridge>> {
        &self.mcp_bridge
    }

    /// Access the MCP proxy.
    pub fn mcp_proxy(&self) -> &Arc<RwLock<McpProxy>> {
        &self.mcp_proxy
    }

    /// Access the relay broker.
    pub fn relay_broker(&self) -> &RelayBroker {
        &self.relay_broker
    }

    // ── Session message loops ──────────────────────────────────────────

    /// Post-auth message loop over WebTransport.
    async fn session_loop_quic(
        &self,
        send: &mut wtransport::SendStream,
        recv: &mut wtransport::RecvStream,
        ctx: &mut ConnectionContext,
        mut peer_rx: mpsc::Receiver<Envelope>,
    ) -> WshResult<()> {
        let (inbound_tx, mut inbound_rx) = mpsc::channel(64);
        let (data_tx, mut data_rx) = mpsc::channel::<GatewayEvent>(256);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    debug!("shutdown signal received, notifying QUIC client");
                    let shutdown_msg = Envelope {
                        msg_type: MsgType::Shutdown,
                        payload: Payload::Shutdown(ShutdownPayload {
                            reason: "server shutdown".into(),
                            retry_after: None,
                        }),
                    };
                    if let Ok(frame) = frame_encode(&shutdown_msg) {
                        let _ = send.write_all(&frame).await;
                    }
                    break;
                }

                Some(event) = inbound_rx.recv() => {
                    let msg = build_inbound_open(&event);
                    let frame = frame_encode(&msg)?;
                    send.write_all(&frame)
                        .await
                        .map_err(|e| WshError::Transport(format!("WebTransport write: {e}")))?;
                }

                Some(event) = data_rx.recv() => {
                    let msg = match &event {
                        GatewayEvent::Data { gateway_id, data } => {
                            build_gateway_data(*gateway_id, data.clone())
                        }
                        GatewayEvent::Closed { gateway_id } => {
                            self.gateway_forwarder.close(*gateway_id).await;
                            build_gateway_close_msg(*gateway_id)
                        }
                    };
                    let frame = frame_encode(&msg)?;
                    send.write_all(&frame)
                        .await
                        .map_err(|e| WshError::Transport(format!("WebTransport write: {e}")))?;
                }

                // Peer push messages (e.g. forwarded ReverseConnect)
                Some(envelope) = peer_rx.recv() => {
                    let frame = frame_encode(&envelope)?;
                    send.write_all(&frame)
                        .await
                        .map_err(|e| WshError::Transport(format!("WebTransport write: {e}")))?;
                }

                frame_result = read_webtransport_frame(recv) => {
                    match frame_result {
                        Ok(data) => {
                            let envelope = decode_envelope(&data)?;
                            if let Some(response) = self.dispatch_message(envelope, ctx, inbound_tx.clone(), data_tx.clone()).await? {
                                let frame = frame_encode(&response)?;
                                send.write_all(&frame)
                                    .await
                                    .map_err(|e| WshError::Transport(format!("WebTransport write: {e}")))?;
                            }
                        }
                        Err(e) => {
                            debug!(error = %e, "WebTransport session ended");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Post-auth message loop over WebSocket.
    async fn session_loop_ws(
        &self,
        conn: &mut websocket::WebSocketConnection,
        ctx: &mut ConnectionContext,
        mut peer_rx: mpsc::Receiver<Envelope>,
    ) -> WshResult<()> {
        let (inbound_tx, mut inbound_rx) = mpsc::channel(64);
        let (data_tx, mut data_rx) = mpsc::channel::<GatewayEvent>(256);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    debug!("shutdown signal received, notifying WebSocket client");
                    let shutdown_msg = Envelope {
                        msg_type: MsgType::Shutdown,
                        payload: Payload::Shutdown(ShutdownPayload {
                            reason: "server shutdown".into(),
                            retry_after: None,
                        }),
                    };
                    if let Ok(frame) = frame_encode(&shutdown_msg) {
                        let _ = websocket::ws_send_control(&mut conn.ws_stream, &frame).await;
                    }
                    break;
                }

                Some(event) = inbound_rx.recv() => {
                    let msg = build_inbound_open(&event);
                    let frame = frame_encode(&msg)?;
                    websocket::ws_send_control(&mut conn.ws_stream, &frame).await?;
                }

                Some(event) = data_rx.recv() => {
                    let msg = match &event {
                        GatewayEvent::Data { gateway_id, data } => {
                            build_gateway_data(*gateway_id, data.clone())
                        }
                        GatewayEvent::Closed { gateway_id } => {
                            self.gateway_forwarder.close(*gateway_id).await;
                            build_gateway_close_msg(*gateway_id)
                        }
                    };
                    let frame = frame_encode(&msg)?;
                    websocket::ws_send_control(&mut conn.ws_stream, &frame).await?;
                }

                // Peer push messages (e.g. forwarded ReverseConnect)
                Some(envelope) = peer_rx.recv() => {
                    let frame = frame_encode(&envelope)?;
                    websocket::ws_send_control(&mut conn.ws_stream, &frame).await?;
                }

                ws_result = websocket::ws_recv_control(&mut conn.ws_stream) => {
                    match ws_result {
                        Ok(Some(data)) => {
                            let envelope = decode_envelope(&data)?;
                            if let Some(response) = self.dispatch_message(envelope, ctx, inbound_tx.clone(), data_tx.clone()).await? {
                                let frame = frame_encode(&response)?;
                                websocket::ws_send_control(&mut conn.ws_stream, &frame).await?;
                            }
                        }
                        Ok(None) => {
                            debug!("WebSocket session ended (peer closed)");
                            break;
                        }
                        Err(e) => {
                            debug!(error = %e, "WebSocket session ended");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Allocate a unique connection ID, skipping 0 (reserved as sentinel).
    fn alloc_conn_id(&self) -> u64 {
        loop {
            let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
            // Wrapped to 0 — skip it and try next
        }
    }

    async fn clear_relay_links(&self, conn_id: u64) {
        {
            let mut pending = self.pending_relay_pairs.write().await;
            if let Some(partner) = pending.remove(&conn_id) {
                pending.remove(&partner);
            }
        }

        let mut pairs = self.relay_pairs.write().await;
        if let Some(partner) = pairs.remove(&conn_id) {
            pairs.remove(&partner);
        }
    }

    /// Build the list of features this server advertises based on configuration.
    fn build_feature_list(&self) -> Vec<String> {
        let mut features = vec!["mcp".to_string(), "file-transfer".to_string()];
        if self.gateway_enabled {
            features.push("gateway".to_string());
        }
        if self.config.enable_relay {
            features.push("reverse".to_string());
        }
        if self.recording_dir.is_some() {
            features.push("recording".to_string());
        }
        features
    }

    /// Check whether the caller is the **owner** of a session (no ACL fallback).
    /// Use this for privileged operations like Grant, Revoke, GuestInvite, ShareSession
    /// where only the session creator should be able to act.
    async fn check_session_owner(&self, session_id: &str, username: &str) -> bool {
        self.sessions
            .with_session(session_id, |s| Ok(s.username == username))
            .await
            .unwrap_or(false)
    }

    /// Dispatch a single decoded message to the appropriate handler.
    /// Check whether the caller owns or has been granted access to a session.
    async fn check_session_access(&self, session_id: &str, username: &str) -> bool {
        // Check if user is the session owner
        let is_owner = self
            .sessions
            .with_session(session_id, |s| Ok(s.username == username))
            .await
            .unwrap_or(false);
        if is_owner {
            return true;
        }

        // Check ACL grants
        let acls = self.session_acls.read().await;
        if let Some(session_acl) = acls.get(session_id) {
            return session_acl.contains_key(username);
        }
        false
    }

    /// Sanitize a session_id to prevent path traversal attacks.
    /// Returns None if the session_id contains dangerous characters.
    fn sanitize_session_id(session_id: &str) -> Option<&str> {
        // Reject empty, path separators, parent directory, and null bytes
        if session_id.is_empty()
            || session_id.contains('/')
            || session_id.contains('\\')
            || session_id.contains("..")
            || session_id.contains('\0')
        {
            None
        } else {
            Some(session_id)
        }
    }

    /// Check whether a message type should be forwarded through a relay bridge
    /// rather than processed locally. These are the "data plane" messages that
    /// flow between CLI and browser during a reverse connection.
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

    async fn dispatch_message(
        &self,
        envelope: Envelope,
        ctx: &mut ConnectionContext,
        inbound_tx: mpsc::Sender<crate::gateway::listener::InboundEvent>,
        data_tx: mpsc::Sender<GatewayEvent>,
    ) -> WshResult<Option<Envelope>> {
        if let Some(conn_id) = ctx.conn_id {
            if matches!(
                envelope.msg_type,
                MsgType::ReverseAccept | MsgType::ReverseReject
            ) {
                let partner_id = {
                    let pending = self.pending_relay_pairs.read().await;
                    pending.get(&conn_id).copied()
                };

                if let Some(partner_id) = partner_id {
                    let msg_type = envelope.msg_type;
                    let senders = self.peer_senders.read().await;
                    if let Some(sender) = senders.get(&partner_id) {
                        let _ = sender.try_send(envelope);
                    } else {
                        drop(senders);
                        self.clear_relay_links(conn_id).await;
                        warn!(
                            conn_id,
                            partner_id,
                            "pending reverse partner sender gone, cleaning up handshake"
                        );
                        return Ok(None);
                    }
                    drop(senders);

                    {
                        let mut pending = self.pending_relay_pairs.write().await;
                        pending.remove(&conn_id);
                        pending.remove(&partner_id);
                    }

                    if matches!(msg_type, MsgType::ReverseAccept) {
                        let mut pairs = self.relay_pairs.write().await;
                        pairs.insert(conn_id, partner_id);
                        pairs.insert(partner_id, conn_id);
                        info!(
                            requester = partner_id,
                            target = conn_id,
                            "relay bridge established after reverse accept"
                        );
                    }

                    return Ok(None);
                }
            }
        }

        // ── Relay bridge forwarding ──────────────────────────────
        // If this connection has a relay partner (established via ReverseConnect),
        // forward eligible message types to the partner instead of processing
        // them locally. This creates a transparent bidirectional bridge between
        // CLI client and browser peer.
        if let Some(conn_id) = ctx.conn_id {
            if Self::is_relay_forwardable(envelope.msg_type) {
                let relay_pairs = self.relay_pairs.read().await;
                if let Some(&partner_id) = relay_pairs.get(&conn_id) {
                    drop(relay_pairs);
                    let senders = self.peer_senders.read().await;
                    if let Some(sender) = senders.get(&partner_id) {
                        let _ = sender.try_send(envelope);
                        return Ok(None); // forwarded, don't process locally
                    }
                    // Partner sender gone — clean up stale relay pair
                    drop(senders);
                    self.clear_relay_links(conn_id).await;
                    warn!(
                        conn_id,
                        partner_id, "relay partner sender gone, cleaning up bridge"
                    );
                }
            }
        }

        match (&envelope.msg_type, &envelope.payload) {
            // ── Reverse peer messages ───────────────────────────────
            (MsgType::ReverseRegister, Payload::ReverseRegister(p)) => {
                let fp = fingerprint(&p.public_key);
                // Register in the relay peer registry, passing the server-assigned conn_id
                // so that ReverseConnect lookups match peer_senders keys.
                let cid = ctx.conn_id.unwrap_or(0);
                let _registry_id = self
                    .peer_registry
                    .register_with_conn_id(
                        fp.clone(),
                        p.username.clone(),
                        p.capabilities.clone(),
                        PeerMetadata {
                            peer_type: p.peer_type.clone(),
                            shell_backend: p.shell_backend.clone(),
                            supports_attach: p.supports_attach,
                            supports_replay: p.supports_replay,
                            supports_echo: p.supports_echo,
                            supports_term_sync: p.supports_term_sync,
                        },
                        Some(cid),
                    )
                    .await;
                info!(
                    fingerprint = %&fp[..8.min(fp.len())],
                    username = %p.username,
                    conn_id = cid,
                    "reverse peer registered"
                );
                Ok(None)
            }
            (MsgType::ReverseList, Payload::ReverseList(_)) => {
                let entries = self.peer_registry.list().await;
                let peers: Vec<PeerInfo> = entries
                    .iter()
                    .map(|e| PeerInfo {
                        fingerprint: e.fingerprint.clone(),
                        fingerprint_short: if e.fingerprint.len() >= 8 {
                            e.fingerprint[..8].to_string()
                        } else {
                            e.fingerprint.clone()
                        },
                        username: e.username.clone(),
                        capabilities: e.capabilities.clone(),
                        peer_type: e.peer_type.clone(),
                        shell_backend: e.shell_backend.clone(),
                        source: "wsh-relay".to_string(),
                        supports_attach: e.supports_attach,
                        supports_replay: e.supports_replay,
                        supports_echo: e.supports_echo,
                        supports_term_sync: e.supports_term_sync,
                        last_seen: Some(e.last_seen.elapsed().as_secs()),
                    })
                    .collect();
                Ok(Some(Envelope {
                    msg_type: MsgType::ReversePeers,
                    payload: Payload::ReversePeers(ReversePeersPayload { peers }),
                }))
            }
            (MsgType::ReverseConnect, Payload::ReverseConnect(p)) => {
                match self
                    .relay_broker
                    .route(&p.target_fingerprint, &p.username)
                    .await
                {
                    Ok(result) => {
                        let target_conn_id = result.target_connection_id;
                        // Forward the ReverseConnect to the target peer's transport
                        let senders = self.peer_senders.read().await;
                        if let Some(target_tx) = senders.get(&target_conn_id) {
                            let fwd = Envelope {
                                msg_type: MsgType::ReverseConnect,
                                payload: Payload::ReverseConnect(ReverseConnectPayload {
                                    target_fingerprint: p.target_fingerprint.clone(),
                                    username: p.username.clone(),
                                }),
                            };
                            if target_tx.try_send(fwd).is_err() {
                                warn!(target = %&p.target_fingerprint, "failed to forward ReverseConnect");
                                return Ok(Some(Envelope {
                                    msg_type: MsgType::Error,
                                    payload: Payload::Error(ErrorPayload {
                                        code: 1,
                                        message: "target peer unreachable".into(),
                                    }),
                                }));
                            }
                            drop(senders);

                            if let Some(requester_conn_id) = ctx.conn_id {
                                let mut pending = self.pending_relay_pairs.write().await;
                                pending.insert(requester_conn_id, target_conn_id);
                                pending.insert(target_conn_id, requester_conn_id);
                                info!(
                                    requester = requester_conn_id,
                                    target = target_conn_id,
                                    target_fp = %&result.target_fingerprint[..8.min(result.target_fingerprint.len())],
                                    "reverse connect forwarded, awaiting target accept"
                                );
                            } else {
                                info!(
                                    requester = %p.username,
                                    target = %&result.target_fingerprint[..8.min(result.target_fingerprint.len())],
                                    "reverse connect forwarded (no bridge — requester has no conn_id)"
                                );
                            }
                            Ok(None)
                        } else {
                            Ok(Some(Envelope {
                                msg_type: MsgType::Error,
                                payload: Payload::Error(ErrorPayload {
                                    code: 1,
                                    message: "target peer transport not found".into(),
                                }),
                            }))
                        }
                    }
                    Err(e) => Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 1,
                            message: e.to_string(),
                        }),
                    })),
                }
            }

            // ── Session management ──────────────────────────────────
            (MsgType::Attach, Payload::Attach(p)) => {
                // Rate limit attach attempts
                {
                    let mut limits = self.rate_limits.lock().await;
                    if !limits.check_attach(&ctx.fingerprint) {
                        return Ok(Some(Envelope {
                            msg_type: MsgType::Error,
                            payload: Payload::Error(ErrorPayload {
                                code: 3,
                                message: "rate limited: too many attach attempts".into(),
                            }),
                        }));
                    }
                }

                if let Err(e) = verify_token(&self.secret, &p.session_id, &p.token) {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: format!("invalid token: {e}"),
                        }),
                    }));
                }
                // Verify the caller owns or has been granted access to this session
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to attach to this session".into(),
                        }),
                    }));
                }
                if let Err(e) = self.sessions.attach(&p.session_id).await {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 3,
                            message: e.to_string(),
                        }),
                    }));
                }
                // Update conn_session_map so E2E relay is session-scoped
                if let Some(cid) = ctx.conn_id {
                    self.conn_session_map
                        .write()
                        .await
                        .insert(cid, p.session_id.clone());
                }
                // Replay ring buffer contents
                let replay_data = self
                    .sessions
                    .with_session(&p.session_id, |s| Ok(s.ring_buffer.read_all()))
                    .await
                    .unwrap_or_default();
                if !replay_data.is_empty() {
                    // Send replay as GatewayData on channel 0 (convention for PTY replay)
                    // The client knows to render this as terminal output
                    let replay_envelope = Envelope {
                        msg_type: MsgType::GatewayData,
                        payload: Payload::GatewayData(GatewayDataPayload {
                            gateway_id: 0,
                            data: replay_data,
                        }),
                    };
                    let _ = ctx.peer_tx.try_send(replay_envelope);
                }
                info!(session_id = %p.session_id, mode = %p.mode, "client attached");
                Ok(Some(Envelope {
                    msg_type: MsgType::Presence,
                    payload: Payload::Presence(PresencePayload {
                        attachments: vec![AttachmentInfo {
                            session_id: p.session_id.clone(),
                            mode: p.mode.clone(),
                            username: Some(ctx.username.clone()),
                        }],
                    }),
                }))
            }
            (MsgType::SessionListRequest, Payload::SessionListRequest(_)) => {
                let all_sessions = self.sessions.list().await;
                let mut visible = Vec::new();
                for s in all_sessions {
                    if self.check_session_access(&s.id, &ctx.username).await {
                        visible.push(SessionSummary {
                            session_id: s.id,
                            name: s.name,
                            username: s.username,
                            fingerprint_short: s.fingerprint_short,
                            created_at_secs: s.created_at_secs,
                            idle_secs: s.idle_secs,
                            attached_count: s.attached_count,
                        });
                    }
                }
                Ok(Some(Envelope {
                    msg_type: MsgType::SessionList,
                    payload: Payload::SessionList(SessionListPayload { sessions: visible }),
                }))
            }
            (MsgType::Detach, Payload::Detach(p)) => {
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::DetachFail,
                        payload: Payload::DetachFail(DetachFailPayload {
                            reason: "not authorized to detach from this session".into(),
                        }),
                    }));
                }
                match self.sessions.detach(&p.session_id).await {
                    Ok(()) => {
                        if let Some(cid) = ctx.conn_id {
                            self.conn_session_map.write().await.remove(&cid);
                        }
                        Ok(Some(Envelope {
                            msg_type: MsgType::DetachOk,
                            payload: Payload::DetachOk(DetachOkPayload {
                                session_id: p.session_id.clone(),
                            }),
                        }))
                    }
                    Err(e) => Ok(Some(Envelope {
                        msg_type: MsgType::DetachFail,
                        payload: Payload::DetachFail(DetachFailPayload {
                            reason: e.to_string(),
                        }),
                    })),
                }
            }
            (MsgType::Resume, Payload::Resume(p)) => {
                if let Err(e) = verify_token(&self.secret, &p.session_id, &p.token) {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: format!("invalid token: {e}"),
                        }),
                    }));
                }
                // Verify the caller owns or has been granted access to this session
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to resume this session".into(),
                        }),
                    }));
                }
                if let Err(e) = self.sessions.attach(&p.session_id).await {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 3,
                            message: e.to_string(),
                        }),
                    }));
                }
                // Update conn_session_map so E2E relay is session-scoped
                if let Some(cid) = ctx.conn_id {
                    self.conn_session_map
                        .write()
                        .await
                        .insert(cid, p.session_id.clone());
                }
                // For resume, replay from last_seq - ring buffer replays all for now
                let replay_data = self
                    .sessions
                    .with_session(&p.session_id, |s| Ok(s.ring_buffer.read_all()))
                    .await
                    .unwrap_or_default();
                if !replay_data.is_empty() {
                    let replay_envelope = Envelope {
                        msg_type: MsgType::GatewayData,
                        payload: Payload::GatewayData(GatewayDataPayload {
                            gateway_id: 0,
                            data: replay_data,
                        }),
                    };
                    let _ = ctx.peer_tx.try_send(replay_envelope);
                }
                info!(session_id = %p.session_id, last_seq = p.last_seq, "client resumed");
                Ok(Some(Envelope {
                    msg_type: MsgType::Presence,
                    payload: Payload::Presence(PresencePayload {
                        attachments: vec![AttachmentInfo {
                            session_id: p.session_id.clone(),
                            mode: "control".into(),
                            username: Some(ctx.username.clone()),
                        }],
                    }),
                }))
            }

            // ── Channel management ──────────────────────────────────
            (MsgType::Open, Payload::Open(p)) => {
                let cols = p.cols.unwrap_or(80);
                let rows = p.rows.unwrap_or(24);
                // Look up key options for permission enforcement
                let key_options = self
                    .authorized_keys
                    .iter()
                    .find(|k| k.fingerprint == ctx.fingerprint)
                    .and_then(|k| k.options.as_deref());
                let permissions = crate::auth::permissions::KeyPermissions::from_options(
                    ctx.fingerprint.clone(),
                    key_options,
                );

                // Check PTY permission
                if p.kind == ChannelKind::Pty && !permissions.allow_pty {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::OpenFail,
                        payload: Payload::OpenFail(OpenFailPayload {
                            reason: "PTY not permitted for this key".into(),
                        }),
                    }));
                }
                // Check scope for PTY and Exec separately.
                if p.kind == ChannelKind::Pty
                    && !permissions.has_scope(&crate::auth::permissions::SessionScope::Shell)
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::OpenFail,
                        payload: Payload::OpenFail(OpenFailPayload {
                            reason: "shell access not permitted for this key".into(),
                        }),
                    }));
                }
                if p.kind == ChannelKind::Exec
                    && !permissions.has_scope(&crate::auth::permissions::SessionScope::Exec)
                    && !permissions.has_scope(&crate::auth::permissions::SessionScope::Shell)
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::OpenFail,
                        payload: Payload::OpenFail(OpenFailPayload {
                            reason: "exec access not permitted for this key".into(),
                        }),
                    }));
                }
                // Check file transfer scope
                if p.kind == ChannelKind::File
                    && !permissions.has_scope(&crate::auth::permissions::SessionScope::FileTransfer)
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::OpenFail,
                        payload: Payload::OpenFail(OpenFailPayload {
                            reason: "file transfer not permitted for this key".into(),
                        }),
                    }));
                }
                // Enforce forced command semantics.
                if permissions.forced_command.is_some() && p.kind != ChannelKind::Exec {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::OpenFail,
                        payload: Payload::OpenFail(OpenFailPayload {
                            reason: "key is restricted to forced exec command".into(),
                        }),
                    }));
                }
                // Enforce key-specific session cap if present.
                if let Some(max_sessions) = permissions.max_sessions {
                    let active_for_key =
                        self.sessions.count_for_fingerprint(&ctx.fingerprint).await;
                    if active_for_key >= max_sessions {
                        return Ok(Some(Envelope {
                            msg_type: MsgType::OpenFail,
                            payload: Payload::OpenFail(OpenFailPayload {
                                reason: format!(
                                    "max sessions for this key reached ({max_sessions})"
                                ),
                            }),
                        }));
                    }
                }

                match p.kind {
                    ChannelKind::Pty | ChannelKind::Exec => {
                        let effective_command_owned = permissions
                            .forced_command
                            .clone()
                            .or_else(|| p.command.clone());
                        match self
                            .sessions
                            .create(
                                ctx.username.clone(),
                                ctx.fingerprint.clone(),
                                permissions,
                                effective_command_owned.as_deref(),
                                cols,
                                rows,
                                p.env.as_ref(),
                                self.recording_dir.as_deref(),
                            )
                            .await
                        {
                            Ok(session_id) => {
                                // Atomic monotonic counter — collision-free channel IDs
                                let channel_id =
                                    self.next_channel_id.fetch_add(1, Ordering::Relaxed);
                                // Register channel → session mapping for Close/Resize routing
                                self.channel_sessions
                                    .write()
                                    .await
                                    .insert(channel_id, session_id.clone());
                                // Update conn_session_map so E2E relay is session-scoped
                                if let Some(cid) = ctx.conn_id {
                                    self.conn_session_map
                                        .write()
                                        .await
                                        .insert(cid, session_id.clone());
                                }
                                info!(session_id = %session_id, channel_id, kind = ?p.kind, "channel opened");
                                Ok(Some(Envelope {
                                    msg_type: MsgType::OpenOk,
                                    payload: Payload::OpenOk(OpenOkPayload {
                                        channel_id,
                                        stream_ids: vec![],
                                        data_mode: SessionDataMode::Stream,
                                        capabilities: vec![],
                                    }),
                                }))
                            }
                            Err(e) => Ok(Some(Envelope {
                                msg_type: MsgType::OpenFail,
                                payload: Payload::OpenFail(OpenFailPayload {
                                    reason: e.to_string(),
                                }),
                            })),
                        }
                    }
                    _ => Ok(Some(Envelope {
                        msg_type: MsgType::OpenFail,
                        payload: Payload::OpenFail(OpenFailPayload {
                            reason: format!("unsupported channel kind: {:?}", p.kind),
                        }),
                    })),
                }
            }
            (MsgType::Resize, Payload::Resize(p)) => {
                // Look up the session for this channel_id
                let target_session = {
                    let ch_map = self.channel_sessions.read().await;
                    ch_map.get(&p.channel_id).cloned()
                };
                let sid = target_session.as_deref().unwrap_or(&ctx.session_id);
                debug!(channel_id = p.channel_id, cols = p.cols, rows = p.rows, session_id = %sid, "resize request");
                // Touch session activity on the correct session
                self.sessions.touch(sid).await;
                Ok(None)
            }
            (MsgType::Signal, Payload::Signal(p)) => {
                debug!(channel_id = p.channel_id, signal = %p.signal, "signal request");
                Ok(None)
            }
            (MsgType::Close, Payload::Close(p)) => {
                // Look up the session for this channel_id
                let target_session = {
                    let ch_map = self.channel_sessions.read().await;
                    ch_map.get(&p.channel_id).cloned()
                };
                let sid = target_session.as_deref().unwrap_or(&ctx.session_id);
                debug!(channel_id = p.channel_id, session_id = %sid, "close request");
                // Detach from the correct session and clean up channel mapping
                if let Err(e) = self.sessions.detach(sid).await {
                    warn!(channel_id = p.channel_id, error = %e, "detach failed on close");
                }
                self.channel_sessions.write().await.remove(&p.channel_id);
                Ok(None)
            }

            // ── Session metadata ────────────────────────────────────
            (MsgType::Rename, Payload::Rename(p)) => {
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to rename this session".into(),
                        }),
                    }));
                }
                match self.sessions.rename(&p.session_id, p.name.clone()).await {
                    Ok(()) => {
                        info!(session_id = %p.session_id, name = %p.name, "session renamed");
                        Ok(None)
                    }
                    Err(e) => Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 3,
                            message: e.to_string(),
                        }),
                    })),
                }
            }
            (MsgType::Snapshot, Payload::Snapshot(p)) => {
                if !self
                    .check_session_access(&ctx.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized".into(),
                        }),
                    }));
                }
                debug!(label = %p.label, "snapshot recorded");
                Ok(None)
            }
            (MsgType::Presence, Payload::Presence(_)) => {
                // Client-sent presence is a no-op (server generates these)
                Ok(None)
            }
            (MsgType::ControlChanged, Payload::ControlChanged(_)) => {
                // Informational, no action needed
                Ok(None)
            }
            (MsgType::Metrics, Payload::Metrics(_)) => {
                // Return server metrics
                let session_count = self.sessions.count().await as u32;
                Ok(Some(Envelope {
                    msg_type: MsgType::Metrics,
                    payload: Payload::Metrics(MetricsPayload {
                        cpu: None,
                        memory: None,
                        sessions: Some(session_count),
                        rtt: None,
                    }),
                }))
            }

            // ── Clipboard (OSC 52) ────────────────────────────────────
            (MsgType::Clipboard, Payload::Clipboard(p)) => {
                debug!(direction = %p.direction, "clipboard sync message");
                // For now, forward clipboard messages as-is.
                // In future, detect OSC 52 in PTY output and generate these.
                Ok(None)
            }

            // ── MCP messages ────────────────────────────────────────
            (MsgType::McpDiscover, Payload::McpDiscover(_)) => {
                let bridge = self.mcp_bridge.read().await;
                let mut tools = bridge.list_tools();
                let proxy = self.mcp_proxy.read().await;
                tools.extend(proxy.list_tools());
                Ok(Some(Envelope {
                    msg_type: MsgType::McpTools,
                    payload: Payload::McpTools(McpToolsPayload { tools }),
                }))
            }
            (MsgType::McpCall, Payload::McpCall(p)) => {
                // Try bridge first, then proxy
                let bridge = self.mcp_bridge.read().await;
                if bridge.has_tool(&p.tool) {
                    let result = bridge.call(p).await;
                    Ok(Some(Envelope {
                        msg_type: MsgType::McpResult,
                        payload: Payload::McpResult(result),
                    }))
                } else {
                    drop(bridge);
                    let proxy = self.mcp_proxy.read().await;
                    let result = proxy.call(p).await;
                    Ok(Some(Envelope {
                        msg_type: MsgType::McpResult,
                        payload: Payload::McpResult(result),
                    }))
                }
            }

            // ── Gateway messages ────────────────────────────────────
            (MsgType::OpenTcp, Payload::OpenTcp(p)) => {
                if !self.gateway_enabled {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::GatewayFail,
                        payload: Payload::GatewayFail(GatewayFailPayload {
                            gateway_id: p.gateway_id,
                            code: 5,
                            message: "gateway disabled".to_string(),
                        }),
                    }));
                }
                let resp = self
                    .gateway_forwarder
                    .handle_open_tcp(p.gateway_id, &p.host, p.port, data_tx)
                    .await;
                Ok(Some(resp))
            }
            (MsgType::OpenUdp, Payload::OpenUdp(p)) => {
                if !self.gateway_enabled {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::GatewayFail,
                        payload: Payload::GatewayFail(GatewayFailPayload {
                            gateway_id: p.gateway_id,
                            code: 5,
                            message: "gateway disabled".to_string(),
                        }),
                    }));
                }
                let resp = self
                    .gateway_forwarder
                    .handle_open_udp(p.gateway_id, &p.host, p.port, data_tx)
                    .await;
                Ok(Some(resp))
            }
            (MsgType::ResolveDns, Payload::ResolveDns(p)) => {
                if !self.gateway_enabled {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::GatewayFail,
                        payload: Payload::GatewayFail(GatewayFailPayload {
                            gateway_id: p.gateway_id,
                            code: 5,
                            message: "gateway disabled".to_string(),
                        }),
                    }));
                }
                let resp = self
                    .gateway_forwarder
                    .handle_resolve_dns(p.gateway_id, &p.name, &p.record_type)
                    .await;
                Ok(Some(resp))
            }
            (MsgType::GatewayData, Payload::GatewayData(p)) => {
                self.gateway_forwarder
                    .handle_gateway_data(p.gateway_id, p.data.clone())
                    .await;
                Ok(None)
            }
            (MsgType::GatewayClose, Payload::GatewayClose(p)) => {
                self.gateway_forwarder.close(p.gateway_id).await;
                Ok(None)
            }
            (MsgType::ListenRequest, Payload::ListenRequest(p)) => {
                if !self.gateway_enabled {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::ListenFail,
                        payload: Payload::ListenFail(ListenFailPayload {
                            listener_id: p.listener_id,
                            reason: "gateway disabled".to_string(),
                        }),
                    }));
                }
                let resp = self
                    .reverse_listener
                    .handle_listen_request(p.listener_id, p.port, &p.bind_addr, inbound_tx)
                    .await;
                Ok(Some(resp))
            }
            (MsgType::ListenClose, Payload::ListenClose(p)) => {
                let resp = self.reverse_listener.close_listener(p.listener_id).await;
                Ok(resp)
            }
            (MsgType::InboundAccept, Payload::InboundAccept(p)) => {
                if let Some(gateway_id) = p.gateway_id {
                    self.reverse_listener
                        .handle_inbound_accept(
                            p.channel_id,
                            gateway_id,
                            data_tx,
                            &self.gateway_forwarder,
                        )
                        .await;
                } else {
                    debug!(
                        channel_id = p.channel_id,
                        "InboundAccept without gateway_id, ignoring"
                    );
                }
                Ok(None)
            }
            (MsgType::InboundReject, Payload::InboundReject(p)) => {
                self.reverse_listener
                    .handle_inbound_reject(p.channel_id)
                    .await;
                Ok(None)
            }

            // ── Keepalive ───────────────────────────────────────────
            (MsgType::Ping, Payload::PingPong(p)) => Ok(Some(Envelope {
                msg_type: MsgType::Pong,
                payload: Payload::PingPong(PingPongPayload { id: p.id }),
            })),

            // ── Recording export ──────────────────────────────────
            (MsgType::RecordingExport, Payload::RecordingExport(p)) => {
                // Verify the caller owns or has access to this session
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to export recording for this session".into(),
                        }),
                    }));
                }
                debug!(session_id = %p.session_id, format = %p.format, "recording export request");
                // Sanitize session_id to prevent path traversal
                let safe_id = match Self::sanitize_session_id(&p.session_id) {
                    Some(id) => id,
                    None => {
                        return Ok(Some(Envelope {
                            msg_type: MsgType::Error,
                            payload: Payload::Error(ErrorPayload {
                                code: 2,
                                message: "invalid session_id".into(),
                            }),
                        }));
                    }
                };
                let recording_path = self
                    .recording_dir
                    .as_ref()
                    .map(|dir| dir.join(format!("{}.jsonl", safe_id)));

                match recording_path {
                    Some(path) if path.exists() => match tokio::fs::read_to_string(&path).await {
                        Ok(data) => Ok(Some(Envelope {
                            msg_type: MsgType::RecordingExport,
                            payload: Payload::RecordingExport(RecordingExportPayload {
                                session_id: p.session_id.clone(),
                                format: p.format.clone(),
                                data: Some(data),
                            }),
                        })),
                        Err(e) => Ok(Some(Envelope {
                            msg_type: MsgType::Error,
                            payload: Payload::Error(ErrorPayload {
                                code: 1,
                                message: format!("failed to read recording: {e}"),
                            }),
                        })),
                    },
                    _ => Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 4,
                            message: format!("no recording found for session {}", p.session_id),
                        }),
                    })),
                }
            }

            // ── Command journal ──────────────────────────────────────
            (MsgType::CommandJournal, Payload::CommandJournal(p)) => {
                // Verify the caller owns or has access to this session
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to write journal for this session".into(),
                        }),
                    }));
                }
                debug!(
                    session_id = %p.session_id,
                    command = %p.command,
                    exit_code = ?p.exit_code,
                    "command journal entry"
                );
                // Sanitize session_id to prevent path traversal
                let safe_id = match Self::sanitize_session_id(&p.session_id) {
                    Some(id) => id.to_string(),
                    None => {
                        return Ok(Some(Envelope {
                            msg_type: MsgType::Error,
                            payload: Payload::Error(ErrorPayload {
                                code: 2,
                                message: "invalid session_id".into(),
                            }),
                        }));
                    }
                };
                // Record in session recorder if available
                if let Some(ref dir) = self.recording_dir {
                    let journal_path = dir.join(format!("{}.journal.jsonl", safe_id));
                    let entry = serde_json::to_string(&serde_json::json!({
                        "command": p.command,
                        "exit_code": p.exit_code,
                        "duration_ms": p.duration_ms,
                        "cwd": p.cwd,
                        "timestamp": p.timestamp,
                    }))
                    .unwrap_or_default();
                    if let Ok(mut f) = tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&journal_path)
                        .await
                    {
                        use tokio::io::AsyncWriteExt;
                        let _ = f.write_all(entry.as_bytes()).await;
                        let _ = f.write_all(b"\n").await;
                    }
                }
                Ok(None)
            }

            // ── Metrics request ──────────────────────────────────────
            (MsgType::MetricsRequest, Payload::MetricsRequest(_)) => {
                let session_count = self.sessions.count().await as u32;
                // Collect basic server metrics
                let metrics = Envelope {
                    msg_type: MsgType::Metrics,
                    payload: Payload::Metrics(MetricsPayload {
                        cpu: None, // TODO: integrate sysinfo crate
                        memory: None,
                        sessions: Some(session_count),
                        rtt: None,
                    }),
                };
                Ok(Some(metrics))
            }

            // ── Suspend/resume session ───────────────────────────────
            (MsgType::SuspendSession, Payload::SuspendSession(p)) => {
                // Check session access
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized for this session".into(),
                        }),
                    }));
                }
                debug!(session_id = %p.session_id, action = %p.action, "suspend/resume request");
                // Suspend/resume is not yet implemented — return an honest error
                // instead of falsely succeeding (previous bug: was a no-op that returned Ok)
                Ok(Some(Envelope {
                    msg_type: MsgType::Error,
                    payload: Payload::Error(ErrorPayload {
                        code: 5,
                        message: format!("session {} not yet implemented", p.action),
                    }),
                }))
            }

            // ── Restart PTY ──────────────────────────────────────────
            (MsgType::RestartPty, Payload::RestartPty(p)) => {
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to restart PTY for this session".into(),
                        }),
                    }));
                }
                debug!(session_id = %p.session_id, "PTY restart request");
                // Restart the shell within the session, preserving session metadata
                let result = self
                    .sessions
                    .with_session_mut(&p.session_id, |session| {
                        // Kill the old PTY process
                        let _ = session.pty.kill();
                        // Get current size
                        let (cols, rows) = session.pty.size();
                        // Spawn new PTY with same size
                        let new_pty = crate::session::pty::PtyHandle::spawn(
                            p.command.as_deref(),
                            cols,
                            rows,
                            None,
                        )?;
                        session.pty = new_pty;
                        session.last_activity = std::time::Instant::now();
                        Ok(())
                    })
                    .await;

                match result {
                    Ok(()) => {
                        info!(session_id = %p.session_id, "PTY restarted successfully");
                        Ok(None)
                    }
                    Err(e) => Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 1,
                            message: format!("PTY restart failed: {e}"),
                        }),
                    })),
                }
            }

            // ── Guest sessions ─────────────────────────────────────
            (MsgType::GuestInvite, Payload::GuestInvite(p)) => {
                // Only session owner can create guest tokens (not ACL grantees)
                if !self.check_session_owner(&p.session_id, &ctx.username).await {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to create guest tokens for this session"
                                .into(),
                        }),
                    }));
                }
                // Generate a high-entropy guest token (u128 for sufficient randomness)
                // Use chars().take(8) to avoid UTF-8 panic on multi-byte session_id
                let sid_prefix: String = p.session_id.chars().take(8).collect();
                let token = format!("guest-{}-{:032x}", sid_prefix, rand::random::<u128>());
                // Cap TTL at 24 hours to prevent effectively-permanent tokens
                let ttl = p.ttl.min(86400);
                let guest = GuestToken {
                    token: token.clone(),
                    session_id: p.session_id.clone(),
                    permissions: p.permissions.clone(),
                    created: std::time::Instant::now(),
                    ttl,
                    revoked: false,
                };
                self.guest_tokens.write().await.insert(token.clone(), guest);
                info!(session_id = %p.session_id, ttl, "guest token created");
                // Return the token to the session owner via GuestInvite echo
                // Note: the token is embedded in the session_id field for transport
                // (a dedicated 'token' field would be cleaner but requires spec change)
                Ok(Some(Envelope {
                    msg_type: MsgType::GuestInvite,
                    payload: Payload::GuestInvite(GuestInvitePayload {
                        session_id: token,
                        ttl,
                        permissions: p.permissions.clone(),
                    }),
                }))
            }

            (MsgType::GuestJoin, Payload::GuestJoin(p)) => {
                debug!(token = %p.token, "guest join attempt");
                // Validate and consume the token (single-use)
                let mut tokens = self.guest_tokens.write().await;
                match tokens.get(&p.token) {
                    Some(guest) if guest.is_valid() => {
                        let session_id = guest.session_id.clone();
                        let permissions = guest.permissions.clone();
                        // Consume the token — mark as revoked after use (single-use)
                        if let Some(g) = tokens.get_mut(&p.token) {
                            g.revoked = true;
                        }
                        drop(tokens);
                        // Update conn_session_map so E2E relay is session-scoped
                        if let Some(cid) = ctx.conn_id {
                            self.conn_session_map
                                .write()
                                .await
                                .insert(cid, session_id.clone());
                        }
                        // Attach the guest to the session
                        if let Err(e) = self.sessions.attach(&session_id).await {
                            return Ok(Some(Envelope {
                                msg_type: MsgType::Error,
                                payload: Payload::Error(ErrorPayload {
                                    code: 3,
                                    message: e.to_string(),
                                }),
                            }));
                        }
                        let mode = if permissions.contains(&"control".to_string()) {
                            "control"
                        } else {
                            "read"
                        };
                        info!(session_id = %session_id, mode, "guest joined session");
                        Ok(Some(Envelope {
                            msg_type: MsgType::Presence,
                            payload: Payload::Presence(PresencePayload {
                                attachments: vec![AttachmentInfo {
                                    session_id,
                                    mode: mode.into(),
                                    username: p.device_label.clone(),
                                }],
                            }),
                        }))
                    }
                    Some(_) => {
                        // Token exists but expired or revoked
                        Ok(Some(Envelope {
                            msg_type: MsgType::AuthFail,
                            payload: Payload::AuthFail(AuthFailPayload {
                                reason: "guest token expired or revoked".into(),
                            }),
                        }))
                    }
                    None => Ok(Some(Envelope {
                        msg_type: MsgType::AuthFail,
                        payload: Payload::AuthFail(AuthFailPayload {
                            reason: "invalid guest token".into(),
                        }),
                    })),
                }
            }

            (MsgType::GuestRevoke, Payload::GuestRevoke(p)) => {
                debug!(token = %p.token, "guest token revoke attempt");
                // Verify caller owns the session the token belongs to
                let tokens = self.guest_tokens.read().await;
                if let Some(guest) = tokens.get(&p.token) {
                    let session_id = guest.session_id.clone();
                    drop(tokens);
                    if !self.check_session_owner(&session_id, &ctx.username).await {
                        return Ok(Some(Envelope {
                            msg_type: MsgType::Error,
                            payload: Payload::Error(ErrorPayload {
                                code: 2,
                                message: "not authorized to revoke this token".into(),
                            }),
                        }));
                    }
                    let mut tokens = self.guest_tokens.write().await;
                    if let Some(guest) = tokens.get_mut(&p.token) {
                        guest.revoked = true;
                        info!(token = %p.token, session_id = %session_id, "guest token revoked");
                    }
                    // Confirm revocation to client
                    Ok(Some(Envelope {
                        msg_type: MsgType::GuestRevoke,
                        payload: Payload::GuestRevoke(GuestRevokePayload {
                            token: p.token.clone(),
                            reason: Some("revoked by owner".into()),
                        }),
                    }))
                } else {
                    drop(tokens);
                    Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 4,
                            message: "guest token not found".into(),
                        }),
                    }))
                }
            }

            // ── Session sharing ───────────────────────────────────────
            (MsgType::ShareSession, Payload::ShareSession(p)) => {
                // Only session owner can share (not ACL grantees)
                if !self.check_session_owner(&p.session_id, &ctx.username).await {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to share this session".into(),
                        }),
                    }));
                }
                debug!(session_id = %p.session_id, mode = %p.mode, ttl = p.ttl, "share session");
                // Generate a share_id with high entropy and store it
                // Use chars().take(8) to avoid UTF-8 panic on multi-byte session_id
                let sid_prefix: String = p.session_id.chars().take(8).collect();
                let share_id = format!("share-{}-{:032x}", sid_prefix, rand::random::<u128>());
                let entry = ShareEntry {
                    share_id: share_id.clone(),
                    session_id: p.session_id.clone(),
                    mode: p.mode.clone(),
                    ttl: p.ttl,
                    created: std::time::Instant::now(),
                };
                self.share_entries
                    .write()
                    .await
                    .insert(share_id.clone(), entry);
                info!(session_id = %p.session_id, share_id = %share_id, "session shared");
                Ok(Some(Envelope {
                    msg_type: MsgType::ShareSession,
                    payload: Payload::ShareSession(ShareSessionPayload {
                        session_id: share_id,
                        mode: p.mode.clone(),
                        ttl: p.ttl,
                    }),
                }))
            }

            (MsgType::ShareRevoke, Payload::ShareRevoke(p)) => {
                debug!(share_id = %p.share_id, "share revoke attempt");
                // Look up the share entry to verify ownership
                let shares = self.share_entries.read().await;
                if let Some(entry) = shares.get(&p.share_id) {
                    let session_id = entry.session_id.clone();
                    drop(shares);
                    // Only the session owner can revoke shares
                    if !self.check_session_owner(&session_id, &ctx.username).await {
                        return Ok(Some(Envelope {
                            msg_type: MsgType::Error,
                            payload: Payload::Error(ErrorPayload {
                                code: 2,
                                message: "not authorized to revoke this share".into(),
                            }),
                        }));
                    }
                    self.share_entries.write().await.remove(&p.share_id);
                    info!(share_id = %p.share_id, session_id = %session_id, "share revoked");
                    // Confirm revocation to client
                    Ok(Some(Envelope {
                        msg_type: MsgType::ShareRevoke,
                        payload: Payload::ShareRevoke(ShareRevokePayload {
                            share_id: p.share_id.clone(),
                            reason: Some("revoked by owner".into()),
                        }),
                    }))
                } else {
                    drop(shares);
                    Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 4,
                            message: "share not found".into(),
                        }),
                    }))
                }
            }

            // ── Compression negotiation ────────────────────────────
            (MsgType::CompressBegin, Payload::CompressBegin(p)) => {
                debug!(algorithm = %p.algorithm, level = p.level, "compression proposed");
                // Reject all compression until a codec is actually installed.
                // Previously this falsely claimed to accept zstd.
                warn!(algorithm = %p.algorithm, "compression not yet implemented, rejecting");
                Ok(Some(Envelope {
                    msg_type: MsgType::CompressAck,
                    payload: Payload::CompressAck(CompressAckPayload {
                        algorithm: p.algorithm.clone(),
                        accepted: false,
                    }),
                }))
            }

            (MsgType::CompressAck, Payload::CompressAck(p)) => {
                debug!(algorithm = %p.algorithm, accepted = p.accepted, "compression ack");
                Ok(None)
            }

            // ── Rate control ──────────────────────────────────────
            (MsgType::RateControl, Payload::RateControl(p)) => {
                // Verify session access
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized for this session".into(),
                        }),
                    }));
                }
                // Store rate control state for the session
                let state = RateControlState {
                    max_bytes_per_sec: p.max_bytes_per_sec,
                    policy: p.policy.clone(),
                    queued_bytes: 0,
                };
                self.rate_control_state
                    .write()
                    .await
                    .insert(p.session_id.clone(), state);
                info!(session_id = %p.session_id, max_bps = p.max_bytes_per_sec, policy = %p.policy, "rate control configured");
                Ok(None)
            }

            (MsgType::RateWarning, Payload::RateWarning(p)) => {
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized for this session".into(),
                        }),
                    }));
                }
                debug!(session_id = %p.session_id, queued = p.queued_bytes, action = %p.action, "rate warning");
                // Update queued bytes in state
                if let Some(state) = self.rate_control_state.write().await.get_mut(&p.session_id) {
                    state.queued_bytes = p.queued_bytes;
                }
                Ok(None)
            }

            // ── Cross-session linking (jump host) ─────────────────
            (MsgType::SessionLink, Payload::SessionLink(p)) => {
                // Verify session access
                if !self
                    .check_session_access(&p.source_session, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized for source session".into(),
                        }),
                    }));
                }
                debug!(source = %p.source_session, target = %p.target_host, port = p.target_port, "session link request");
                // Session linking requires opening a new wsh connection to target_host
                // and bridging the two sessions — not yet implemented
                Ok(Some(Envelope {
                    msg_type: MsgType::Error,
                    payload: Payload::Error(ErrorPayload {
                        code: 5,
                        message: "session linking not yet implemented".into(),
                    }),
                }))
            }

            (MsgType::SessionUnlink, Payload::SessionUnlink(p)) => {
                // Verify the caller has session access (defense-in-depth for stub)
                if !self
                    .check_session_access(&ctx.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to unlink sessions".into(),
                        }),
                    }));
                }
                debug!(link_id = %p.link_id, "session unlink");
                Ok(None)
            }

            // ── AI co-pilot ────────────────────────────────────────
            (MsgType::CopilotAttach, Payload::CopilotAttach(p)) => {
                // Verify the caller has access to this session
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to attach copilot to this session".into(),
                        }),
                    }));
                }
                // Register as read-only observer for the session
                let copilot = CopilotSession {
                    model: p.model.clone(),
                    conn_id: ctx.conn_id.unwrap_or(0),
                    peer_tx: ctx.peer_tx.clone(),
                };
                let mut sessions = self.copilot_sessions.write().await;
                sessions
                    .entry(p.session_id.clone())
                    .or_default()
                    .push(copilot);
                info!(session_id = %p.session_id, model = %p.model, "copilot attached");
                // Notify the session controller via Presence
                Ok(Some(Envelope {
                    msg_type: MsgType::Presence,
                    payload: Payload::Presence(PresencePayload {
                        attachments: vec![AttachmentInfo {
                            session_id: p.session_id.clone(),
                            mode: "copilot".into(),
                            username: Some(format!("copilot:{}", p.model)),
                        }],
                    }),
                }))
            }

            (MsgType::CopilotSuggest, Payload::CopilotSuggest(p)) => {
                // Verify the caller has access to this session
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized for copilot on this session".into(),
                        }),
                    }));
                }
                debug!(session_id = %p.session_id, "copilot suggestion");
                // Forward suggestion only to connections attached to this session (not globally)
                let conn_map = self.conn_session_map.read().await;
                let senders = self.peer_senders.read().await;
                let suggestion = Envelope {
                    msg_type: MsgType::CopilotSuggest,
                    payload: Payload::CopilotSuggest(CopilotSuggestPayload {
                        session_id: p.session_id.clone(),
                        suggestion: p.suggestion.clone(),
                        confidence: p.confidence,
                    }),
                };
                let sender_conn_id = ctx.conn_id;
                for (&conn_id, session_id) in conn_map.iter() {
                    if session_id == &p.session_id && Some(conn_id) != sender_conn_id {
                        if let Some(sender) = senders.get(&conn_id) {
                            let _ = sender.try_send(suggestion.clone());
                        }
                    }
                }
                Ok(None)
            }

            (MsgType::CopilotDetach, Payload::CopilotDetach(p)) => {
                // Remove copilot matching this connection's conn_id (not pop())
                let caller_conn_id = ctx.conn_id.unwrap_or(0);
                let mut sessions = self.copilot_sessions.write().await;
                if let Some(copilots) = sessions.get_mut(&p.session_id) {
                    copilots.retain(|c| c.conn_id != caller_conn_id);
                    if copilots.is_empty() {
                        sessions.remove(&p.session_id);
                    }
                }
                info!(session_id = %p.session_id, conn_id = caller_conn_id, "copilot detached");
                Ok(None)
            }

            // ── E2E encryption ─────────────────────────────────────
            (MsgType::KeyExchange, Payload::KeyExchange(p)) => {
                // Verify the caller has access to this session before relaying
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized for key exchange on this session".into(),
                        }),
                    }));
                }
                debug!(session_id = %p.session_id, algorithm = %p.algorithm, "key exchange");
                // Relay the key exchange ONLY to other clients attached to the SAME session,
                // excluding the sender. Previously broadcast to ALL peers (cross-session leak).
                let fwd = Envelope {
                    msg_type: MsgType::KeyExchange,
                    payload: Payload::KeyExchange(KeyExchangePayload {
                        session_id: p.session_id.clone(),
                        algorithm: p.algorithm.clone(),
                        public_key: p.public_key.clone(),
                    }),
                };
                let conn_map = self.conn_session_map.read().await;
                let senders = self.peer_senders.read().await;
                let sender_conn_id = ctx.conn_id;
                for (&conn_id, session_id) in conn_map.iter() {
                    if session_id == &p.session_id && Some(conn_id) != sender_conn_id {
                        if let Some(sender) = senders.get(&conn_id) {
                            let _ = sender.try_send(fwd.clone());
                        }
                    }
                }
                Ok(None)
            }

            (MsgType::EncryptedFrame, Payload::EncryptedFrame(p)) => {
                // Verify the caller has access to this session before relaying
                if !self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized for encrypted relay on this session".into(),
                        }),
                    }));
                }
                // Opaque relay — forward ONLY to other clients attached to the SAME session,
                // excluding the sender. Previously broadcast to ALL peers (cross-session leak).
                let fwd = Envelope {
                    msg_type: MsgType::EncryptedFrame,
                    payload: Payload::EncryptedFrame(EncryptedFramePayload {
                        session_id: p.session_id.clone(),
                        nonce: p.nonce.clone(),
                        ciphertext: p.ciphertext.clone(),
                    }),
                };
                let conn_map = self.conn_session_map.read().await;
                let senders = self.peer_senders.read().await;
                let sender_conn_id = ctx.conn_id;
                for (&conn_id, session_id) in conn_map.iter() {
                    if session_id == &p.session_id && Some(conn_id) != sender_conn_id {
                        if let Some(sender) = senders.get(&conn_id) {
                            let _ = sender.try_send(fwd.clone());
                        }
                    }
                }
                Ok(None)
            }

            // ── Predictive local echo ─────────────────────────────
            (MsgType::EchoAck, Payload::EchoAck(p)) => {
                // Scope to caller's session (defense-in-depth)
                if !self
                    .check_session_access(&ctx.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized".into(),
                        }),
                    }));
                }
                // Update echo tracker for this channel
                let mut trackers = self.echo_trackers.write().await;
                let tracker = trackers.entry(p.channel_id).or_insert_with(|| EchoTracker {
                    last_echo_seq: 0,
                    cursor_x: 0,
                    cursor_y: 0,
                    pending: 0,
                });
                tracker.last_echo_seq = p.echo_seq;
                debug!(
                    channel_id = p.channel_id,
                    echo_seq = p.echo_seq,
                    "echo ack tracked"
                );
                Ok(None)
            }

            (MsgType::EchoState, Payload::EchoState(p)) => {
                // Scope to caller's session (defense-in-depth)
                if !self
                    .check_session_access(&ctx.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized".into(),
                        }),
                    }));
                }
                // Update echo tracker with full state
                let mut trackers = self.echo_trackers.write().await;
                trackers.insert(
                    p.channel_id,
                    EchoTracker {
                        last_echo_seq: p.echo_seq,
                        cursor_x: p.cursor_x,
                        cursor_y: p.cursor_y,
                        pending: p.pending,
                    },
                );
                debug!(
                    channel_id = p.channel_id,
                    echo_seq = p.echo_seq,
                    pending = p.pending,
                    "echo state updated"
                );
                Ok(None)
            }

            // ── Terminal diff sync ──────────────────────────────────
            (MsgType::TermSync, Payload::TermSync(p)) => {
                if !self
                    .check_session_access(&ctx.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized".into(),
                        }),
                    }));
                }
                debug!(
                    channel_id = p.channel_id,
                    frame_seq = p.frame_seq,
                    "term sync"
                );
                Ok(None)
            }

            (MsgType::TermDiff, Payload::TermDiff(p)) => {
                if !self
                    .check_session_access(&ctx.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized".into(),
                        }),
                    }));
                }
                debug!(
                    channel_id = p.channel_id,
                    frame_seq = p.frame_seq,
                    base_seq = p.base_seq,
                    patch_len = p.patch.len(),
                    "term diff"
                );
                Ok(None)
            }

            // ── Horizontal scaling ──────────────────────────────────
            (MsgType::NodeAnnounce, Payload::NodeAnnounce(p)) => {
                // Only authenticated sessions with valid session owner can announce nodes
                if !self
                    .check_session_owner(&ctx.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to announce cluster nodes".into(),
                        }),
                    }));
                }
                // Register or update the node in our cluster registry
                let node = ClusterNode {
                    node_id: p.node_id.clone(),
                    endpoint: p.endpoint.clone(),
                    load: p.load,
                    capacity: p.capacity,
                    last_seen: std::time::Instant::now(),
                };
                self.cluster_nodes
                    .write()
                    .await
                    .insert(p.node_id.clone(), node);
                info!(node_id = %p.node_id, endpoint = %p.endpoint, load = p.load, capacity = p.capacity, "cluster node registered/updated");
                Ok(None)
            }

            (MsgType::NodeRedirect, Payload::NodeRedirect(_)) => {
                // NodeRedirect is server-to-client only; reject client-sent redirects
                Ok(Some(Envelope {
                    msg_type: MsgType::Error,
                    payload: Payload::Error(ErrorPayload {
                        code: 4,
                        message: "NodeRedirect is a server-to-client message".into(),
                    }),
                }))
            }

            // ── Cross-principal session sharing ─────────────────────
            (MsgType::SessionGrant, Payload::SessionGrant(p)) => {
                // Only session owner can grant access (not ACL grantees — prevents escalation)
                if !self.check_session_owner(&p.session_id, &ctx.username).await {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to grant access to this session".into(),
                        }),
                    }));
                }
                // Add principal to session ACL
                let mut acls = self.session_acls.write().await;
                let session_acl = acls.entry(p.session_id.clone()).or_default();
                session_acl.insert(p.principal.clone(), p.permissions.clone());
                info!(session_id = %p.session_id, principal = %p.principal, permissions = ?p.permissions, "session access granted");
                Ok(None)
            }

            (MsgType::SessionRevoke, Payload::SessionRevoke(p)) => {
                // Only session owner can revoke access (not ACL grantees — prevents escalation)
                if !self.check_session_owner(&p.session_id, &ctx.username).await {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to revoke access to this session".into(),
                        }),
                    }));
                }
                // Remove principal from session ACL
                let mut acls = self.session_acls.write().await;
                if let Some(session_acl) = acls.get_mut(&p.session_id) {
                    session_acl.remove(&p.principal);
                    if session_acl.is_empty() {
                        acls.remove(&p.session_id);
                    }
                }
                info!(session_id = %p.session_id, principal = %p.principal, "session access revoked");
                Ok(None)
            }

            // ── Structured file channel ────────────────────────────
            (MsgType::FileOp, Payload::FileOp(p)) => {
                debug!(channel_id = p.channel_id, op = %p.op, path = %p.path, "file op");
                // Stub: dispatch file operation (stat, list, read, write, etc.)
                Ok(Some(Envelope {
                    msg_type: MsgType::FileResult,
                    payload: Payload::FileResult(FileResultPayload {
                        channel_id: p.channel_id,
                        success: false,
                        metadata: serde_json::Value::Object(Default::default()),
                        error_message: Some("file operations not yet implemented".into()),
                    }),
                }))
            }

            (MsgType::FileResult, Payload::FileResult(_)) => {
                // FileResult is server-to-client only; reject client-sent
                Ok(Some(Envelope {
                    msg_type: MsgType::Error,
                    payload: Payload::Error(ErrorPayload {
                        code: 4,
                        message: "FileResult is a server-to-client message".into(),
                    }),
                }))
            }

            (MsgType::FileChunk, Payload::FileChunk(p)) => {
                if !self
                    .check_session_access(&ctx.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized".into(),
                        }),
                    }));
                }
                debug!(
                    channel_id = p.channel_id,
                    offset = p.offset,
                    len = p.data.len(),
                    is_final = p.is_final,
                    "file chunk"
                );
                Ok(None)
            }

            // ── Policy engine ──────────────────────────────────────
            (MsgType::PolicyEval, Payload::PolicyEval(p)) => {
                debug!(request_id = %p.request_id, action = %p.action, principal = %p.principal, "policy eval");
                let policy = self.policy_store.read().await;
                let (allowed, reason) = match policy.as_ref() {
                    Some(store) => {
                        // Check if the action is explicitly denied in the policy rules
                        let denied = store
                            .rules
                            .get("deny")
                            .and_then(|d| d.as_array())
                            .map(|arr| arr.iter().any(|v| v.as_str() == Some(&p.action)))
                            .unwrap_or(false);
                        if denied {
                            (
                                false,
                                format!("denied by policy {} v{}", store.policy_id, store.version),
                            )
                        } else {
                            let explicitly_allowed = store
                                .rules
                                .get("allow")
                                .and_then(|a| a.as_array())
                                .map(|arr| {
                                    arr.iter().any(|v| {
                                        v.as_str() == Some(&p.action) || v.as_str() == Some("*")
                                    })
                                })
                                .unwrap_or(false);
                            if explicitly_allowed {
                                (
                                    true,
                                    format!(
                                        "allowed by policy {} v{}",
                                        store.policy_id, store.version
                                    ),
                                )
                            } else {
                                // Default-deny when a policy is loaded but action isn't explicitly allowed
                                (
                                    false,
                                    format!(
                                        "not allowed by policy {} v{} (default deny)",
                                        store.policy_id, store.version
                                    ),
                                )
                            }
                        }
                    }
                    None => {
                        // No policy loaded: default-deny
                        (false, "no policy loaded (default deny)".to_string())
                    }
                };
                Ok(Some(Envelope {
                    msg_type: MsgType::PolicyResult,
                    payload: Payload::PolicyResult(PolicyResultPayload {
                        request_id: p.request_id.clone(),
                        allowed,
                        reason: Some(reason),
                    }),
                }))
            }

            (MsgType::PolicyResult, Payload::PolicyResult(_)) => {
                // PolicyResult is server-to-client only; reject client-sent
                Ok(Some(Envelope {
                    msg_type: MsgType::Error,
                    payload: Payload::Error(ErrorPayload {
                        code: 4,
                        message: "PolicyResult is a server-to-client message".into(),
                    }),
                }))
            }

            (MsgType::PolicyUpdate, Payload::PolicyUpdate(p)) => {
                // Only the server administrator (first authorized key) can update policies.
                // The first key in authorized_keys is treated as admin.
                let is_admin = self
                    .authorized_keys
                    .first()
                    .map(|k| k.fingerprint == ctx.fingerprint)
                    .unwrap_or(false);
                if !is_admin {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "only the server administrator can update policies".into(),
                        }),
                    }));
                }
                // Store policy rules for future evaluation
                let store = PolicyStore {
                    policy_id: p.policy_id.clone(),
                    version: p.version,
                    rules: p.rules.clone(),
                };
                *self.policy_store.write().await = Some(store);
                info!(policy_id = %p.policy_id, version = p.version, "policy updated");
                Ok(None)
            }

            // ── Terminal frontend config ────────────────────────────
            (MsgType::TerminalConfig, Payload::TerminalConfig(p)) => {
                // Verify the caller has access to their own session
                if !self
                    .check_session_access(&ctx.session_id, &ctx.username)
                    .await
                {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to configure terminal".into(),
                        }),
                    }));
                }
                // Store per-channel terminal config
                let config = TerminalConfigState {
                    frontend: p.frontend.clone(),
                    options: p.options.clone(),
                };
                self.terminal_configs
                    .write()
                    .await
                    .insert(p.channel_id, config);
                info!(channel_id = p.channel_id, frontend = %p.frontend, "terminal config updated");
                Ok(None)
            }

            // ── Unhandled ───────────────────────────────────────────
            (msg_type, _) => {
                debug!(?msg_type, "unhandled message type in session loop");
                Ok(None)
            }
        }
    }
}

/// Build a [`MsgType::GatewayData`] envelope to forward TCP data to the client.
fn build_gateway_data(gateway_id: u32, data: Vec<u8>) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayData,
        payload: Payload::GatewayData(GatewayDataPayload { gateway_id, data }),
    }
}

/// Build a [`MsgType::GatewayClose`] envelope to notify the client of connection close.
fn build_gateway_close_msg(gateway_id: u32) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayClose,
        payload: Payload::GatewayClose(GatewayClosePayload {
            gateway_id,
            reason: None,
        }),
    }
}

/// Build an [`MsgType::InboundOpen`] envelope from a reverse tunnel
/// [`InboundEvent`](crate::gateway::listener::InboundEvent).
///
/// Sent to the client to notify it that a new inbound TCP connection was
/// accepted on one of its reverse tunnel listeners.
fn build_inbound_open(event: &crate::gateway::listener::InboundEvent) -> Envelope {
    Envelope {
        msg_type: MsgType::InboundOpen,
        payload: Payload::InboundOpen(InboundOpenPayload {
            listener_id: event.listener_id,
            channel_id: event.channel_id,
            peer_addr: event.peer_addr.clone(),
            peer_port: event.peer_port,
        }),
    }
}

/// Read a length-prefixed frame from a WebTransport recv stream.
async fn read_webtransport_frame(recv: &mut wtransport::RecvStream) -> WshResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| WshError::Transport(format!("WebTransport read len failed: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 1_048_576 {
        return Err(WshError::InvalidMessage(format!(
            "frame too large: {len} bytes"
        )));
    }

    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| WshError::Transport(format!("WebTransport read payload failed: {e}")))?;

    Ok(buf)
}
