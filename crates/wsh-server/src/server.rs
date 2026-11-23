//! Core server: accepts connections and dispatches to the handshake flow.
//!
//! Owns the server secret (for token signing), session manager, relay subsystem,
//! and MCP bridge. Coordinates the lifecycle of all incoming connections.

use crate::auth::permissions::KeyRequest;
use crate::config::{SealSession, ServerConfig};
use crate::gateway::policy::{GatewayPolicy, GatewayPolicyEnforcer};
use crate::gateway::GatewaySession;
use crate::handshake;
use crate::mcp::{McpBridge, McpProxy};
use crate::relay::bridges::Route;
use crate::relay::{
    wisp, Bridges, PeerMetadata, PeerRegistry, RelayBroker, WispGuestSession, WispRegistry,
};
use crate::rpc::session::{open_fail as rpc_open_fail, peek_rpc_open, RpcSessions};
use crate::rpc::RpcSettings;
use crate::session::{AttachError, Attachment, SessionManager};
use crate::transport::{websocket, webtransport};
/// The most a peer may wrap in one `RelayForward` it writes itself (the JS relay's bound).
const MAX_RELAY_FORWARD_BYTES: usize = 8 * 1024 * 1024;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};
use wsh_client::e2e::{E2eResponder, InitiatorAuth};
use wsh_client::seal_gate::{SealGate, SESSION_SEAL_FEATURE, SESSION_SEAL_REQUIRED_FEATURE};
use wsh_core::keys::{load_authorized_keys, AuthorizedKey};
use wsh_core::messages::*;
use wsh_core::qmux::ErrorCode;
use wsh_core::qmux_connection::{QMuxConnection, QMuxConnectionConfig, QMuxEvent};
use wsh_core::{
    decode_envelope, fingerprint, frame_encode, verify_token, FrameDecoder, WshError, WshResult,
};

/// Write one encoded message to a WebSocket connection's control stream, through the sealed-session
/// gate (wsh #155): on a sealed session it leaves as an `EncryptedFrame` (the keepalive stays plain),
/// and nothing leaves a session whose key exchange failed. Every write to the control stream of an
/// authenticated connection goes through here, in the order the session loop makes them (the frame
/// counter is strict).
async fn write_control(
    qmux: &QMuxConnection,
    seal: &SealGate,
    stream_id: u64,
    frame: Vec<u8>,
) -> WshResult<()> {
    match seal.outgoing(frame) {
        Some(out) => qmux.write_stream(stream_id, &out).await.map_err(Into::into),
        None => Ok(()),
    }
}

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
    /// In-flight `McpCall`s, by call_id, so `McpCancel` can stop them. Dropping the
    /// context (connection closed) aborts whatever is still running.
    mcp_calls: crate::mcp::McpCalls,
    /// This connection's gateway: its connections, listeners and credit. Dropping the context
    /// closes them all.
    gateway: GatewaySession,
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
    /// #38 Phase 2: registry of connected guests' WISP tunnels
    /// (`/wisp/<fingerprint>`), used to bridge external `wsh connect`
    /// requests via `REVERSE_OPEN` (`/wisp-connect/<fingerprint>`).
    wisp_registry: Arc<WispRegistry>,
    /// MCP CLI tool bridge.
    mcp_bridge: Arc<RwLock<McpBridge>>,
    /// MCP proxy to local servers.
    mcp_proxy: Arc<RwLock<McpProxy>>,
    /// Directory for session recordings.
    recording_dir: Option<PathBuf>,
    /// Gateway policy; each connection builds its own [`GatewaySession`] on it.
    gateway_policy: Arc<GatewayPolicyEnforcer>,
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
    /// Relay bridges (wsh #93): which operator connections are bridged to which peer, and the
    /// `ReverseConnect` handshakes that await their peer's answer. Forwardable messages from
    /// either side are relayed to the other (a peer serving several operators addresses them).
    bridges: Arc<RwLock<Bridges>>,
    /// Atomic counter for generating unique connection IDs.
    /// Starts at 1; 0 is reserved as sentinel for unwrap_or(0).
    next_conn_id: Arc<AtomicU64>,
    /// Atomic counter for generating unique channel IDs (collision-free).
    next_channel_id: Arc<AtomicU32>,
    /// In-progress file uploads: channel_id → open file handle + path.
    /// Populated on Open{kind: File, command: "upload:<path>"}, written to
    /// as FileChunk messages arrive, removed on the final chunk or Close.
    file_uploads: Arc<RwLock<HashMap<u32, FileUploadState>>>,
    /// Typed rpc channels (`Open { kind: "rpc" }`); `None` when `[rpc] enabled = false`.
    rpc: Option<Arc<RpcSettings>>,
    /// This server's own identity (`[server] host_key`); `None` = it proves nothing.
    identity: Option<Arc<crate::host_key::HostIdentity>>,
}

/// State for an in-progress file upload (Open{kind: File, command: "upload:..."}).
struct FileUploadState {
    file: tokio::fs::File,
    path: PathBuf,
}

impl WshServer {
    /// Does `password` match the configured hash for `username`?
    ///
    /// Argon2id is deliberately slow, so it runs on the blocking pool, not on the
    /// connection's task. A user with no usable entry costs the same and answers the
    /// same as a wrong password. Callers have already checked `allow_password`, and
    /// the per-address auth rate limit bounds how many of these one peer can start.
    async fn check_password(&self, username: &str, password: &str) -> bool {
        let stored = self.config.password_hashes.get(username).cloned();
        let password = password.to_string();
        tokio::task::spawn_blocking(move || {
            crate::auth::password::verify_login(&password, stored.as_ref())
        })
        .await
        .unwrap_or(false)
    }

    /// Create a new server instance.
    pub fn new(config: ServerConfig) -> WshResult<Self> {
        // Generate server secret
        let secret = wsh_core::generate_secret();
        let relay_max_operators_per_peer = config.relay_max_operators_per_peer;

        // Load authorized keys
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        let authorized_keys = load_authorized_keys(&home).unwrap_or_else(|e| {
            warn!(error = %e, "failed to load authorized_keys, no pubkey auth available");
            Vec::new()
        });
        // wsh #122: a key whose options this server does not understand is not loaded (fail closed, with a logged reason).
        let authorized_keys =
            crate::auth::permissions::refuse_keys_with_bad_options(authorized_keys);

        if authorized_keys.is_empty() {
            warn!("no authorized keys loaded — pubkey authentication will fail");
        } else {
            info!(count = authorized_keys.len(), "loaded authorized keys");
        }

        let identity = match &config.host_key_path {
            Some(path) => {
                let id = crate::host_key::HostIdentity::load_or_create(
                    path,
                    config.require_channel_binding,
                )?;
                info!(fingerprint = %id.fingerprint, path = %path.display(), "host key loaded");
                Some(Arc::new(id))
            }
            None => None,
        };
        if config.seal_session != SealSession::Off && identity.is_none() {
            return Err(WshError::Other(
                "seal_session needs a host key: the server signs its half of the key exchange with it".into(),
            ));
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
        let wisp_registry = Arc::new(WispRegistry::new());

        // MCP
        let mut bridge = McpBridge::new();
        for t in &config.mcp_tools {
            bridge.register(crate::mcp::bridge::CliToolDefinition {
                name: t.name.clone(),
                description: t.description.clone(),
                command: t.command.clone(),
                parameters: t.parameters.clone(),
                working_dir: t.working_dir.as_deref().map(|d| {
                    crate::config::expand_tilde_str(d)
                        .to_string_lossy()
                        .into_owned()
                }),
                env: t.env.clone(),
                timeout_secs: t.timeout_secs,
            });
        }
        let mcp_bridge = Arc::new(RwLock::new(bridge));
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
            reverse_bind_addr: config.gateway_reverse_bind_addr,
            unix: config.gateway_unix.clone(),
            max_buffered_bytes: config.gateway_max_buffered_bytes,
            max_client_buffered_bytes: config.gateway_max_client_buffered_bytes,
        };
        let policy_enforcer = Arc::new(GatewayPolicyEnforcer::new(gateway_policy));
        let gateway_policy = policy_enforcer;
        let gateway_enabled = config.gateway_enabled;

        // Typed rpc channels (#86). `wsh-fs` needs an explicit root: file access is opt-in.
        // A sealed session (#155) carries everything as frames on the control stream; a typed rpc channel rides client-opened
        // data streams, whose bytes are not frames, so rpc is not offered while sealing is (as the JS host does not offer
        // `e2e-session` where there are client-opened streams).
        if config.rpc_enabled && config.seal_session != SealSession::Off {
            warn!("[server] seal_session is on: typed rpc channels (wsh-fs, ...) are not offered, their data streams cannot be sealed");
        }
        let rpc = if config.rpc_enabled && config.seal_session == SealSession::Off {
            if config.rpc_max_message_bytes < crate::rpc::RPC_MIN_MAX_MESSAGE {
                return Err(WshError::Other(format!(
                    "rpc max_message_bytes must be at least {}",
                    crate::rpc::RPC_MIN_MAX_MESSAGE
                )));
            }
            let fs = match &config.rpc_fs_root {
                Some(root) => Some(
                    crate::rpc::fs::FileAccess::new(
                        root,
                        config.rpc_fs_read_only,
                        config.rpc_fs_max_file_bytes,
                    )
                    .map_err(|e| WshError::Other(format!("rpc fs_root {}: {e}", root.display())))?,
                ),
                None => None,
            };
            Some(Arc::new(RpcSettings {
                max_message_bytes: config.rpc_max_message_bytes,
                max_inflight: config.rpc_max_inflight.max(1),
                fs,
            }))
        } else {
            None
        };

        Ok(Self {
            config,
            secret,
            authorized_keys,
            sessions,
            peer_registry,
            relay_broker,
            wisp_registry,
            mcp_bridge,
            mcp_proxy,
            recording_dir,
            gateway_policy,
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
            bridges: Arc::new(RwLock::new(Bridges::new(relay_max_operators_per_peer))),
            next_conn_id: Arc::new(AtomicU64::new(1)),
            next_channel_id: Arc::new(AtomicU32::new(1)),
            file_uploads: Arc::new(RwLock::new(HashMap::new())),
            rpc,
            identity,
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
        // Also routes #38 Phase 2's WISP guest tunnels and reverse-connect
        // bridge requests, which share the same TCP/TLS listener but are
        // distinguished by request path (see `transport::websocket::parse_route`).
        let websocket::ListenerChannels {
            mut ws_rx,
            mut wisp_guest_rx,
            mut wisp_connect_rx,
        } = websocket::start_listener(ws_addr, tls_config).await?;

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
        let gc_bridges = server.bridges.clone();
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

                // GC relay bridges of connections no longer in peer_senders
                {
                    let senders = gc_peer_senders.read().await;
                    let mut bridges = gc_bridges.write().await;
                    for cid in bridges.connections() {
                        if !senders.contains_key(&cid) {
                            bridges.depart(cid);
                        }
                    }
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
                Some(guest_conn) = wisp_guest_rx.recv() => {
                    let srv = server.clone();
                    tokio::spawn(async move {
                        srv.handle_wisp_guest(guest_conn).await;
                    });
                }
                Some(connect_req) = wisp_connect_rx.recv() => {
                    let srv = server.clone();
                    tokio::spawn(async move {
                        srv.handle_wisp_connect(connect_req).await;
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

        // `seal_session = "require"` serves nothing that is not sealed, and the sealed session is a WebSocket one (its
        // frames ride the control stream; a WebTransport session has per-session QUIC data streams whose bytes are not
        // frames). Refused, not served in the clear.
        if self.config.seal_session == SealSession::Require {
            warn!(remote = %remote, "refused a WebTransport connection: [server] seal_session = \"require\" (connect over WebSocket and seal the session)");
            conn.connection
                .close(wtransport::VarInt::from_u32(1), b"sealed session required");
            return Ok(());
        }

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
        let features = self.build_feature_list(false);
        let hello_result = handshake::handle_hello(
            &hello,
            &server_fingerprints,
            Some(&features),
            self.identity.as_deref(),
        )?;

        // Send SERVER_HELLO with the real session id, then CHALLENGE. This
        // used to deliberately skip SERVER_HELLO (falling back to a shared
        // literal "pending" session id for the transcript) to dodge a
        // client-side dispatch race: a QUIC stream has no message-boundary
        // framing at that layer, so both messages could land in one
        // client-side `read()`, and the client could dispatch CHALLENGE
        // before SERVER_HELLO's `await`'d continuation had registered the
        // CHALLENGE waiter, silently dropping it. That race is now fixed at
        // the source (@johnhenry/wsh >= 0.3.0's WebTransportTransport
        // drains inbound messages one at a time with a microtask yield
        // between each dispatch), so both messages can be sent normally.
        let server_hello_frame = frame_encode(&hello_result.server_hello)?;
        send.write_all(&server_hello_frame)
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
        if auth.method == AuthMethod::Password && self.config.allow_password {
            match auth.password {
                Some(ref password) => {
                    // An unknown user and a wrong password are one answer, after the
                    // same work (see `auth::password::verify_login`).
                    if !self.check_password(&hello.username, password).await {
                        let fail = handshake::build_auth_fail("invalid password");
                        let fail_frame = frame_encode(&fail)?;
                        let _ = send.write_all(&fail_frame).await;
                        return Err(WshError::AuthFailed("invalid password".into()));
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

        // Verify against the real session id from SERVER_HELLO — see the
        // comment above where it's sent for why this no longer needs the
        // "pending" placeholder.
        match handshake::verify_auth(
            &auth,
            &hello_result.nonce,
            &hello_result.session_id,
            &hello.username,
            &self.authorized_keys,
            &self.secret,
            self.config.session_ttl,
            self.config.allow_pubkey,
            self.config.allow_password,
            &hello_result.acceptable_bindings,
            hello_result.binding_required,
        ) {
            Ok(mut result) => {
                result.username = hello.username.clone();
                let ok = handshake::build_auth_ok(
                    &result.session_id,
                    &result.token,
                    handshake::AUTH_OK_TTL,
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
                    peer_tx: peer_tx.clone(),
                    conn_id: Some(conn_id),
                    mcp_calls: Default::default(),
                    gateway: GatewaySession::new(
                        self.gateway_policy.clone(),
                        peer_tx.clone(),
                        self.gateway_enabled,
                        &hello.features,
                    ),
                };

                // Session message loop
                self.session_loop_quic(&mut send, &mut recv, &mut ctx, peer_rx)
                    .await?;

                // Cleanup: unregister peer if registered
                if let Some(cid) = ctx.conn_id {
                    self.peer_senders.write().await.remove(&cid);
                    self.conn_session_map.write().await.remove(&cid);
                    self.clear_relay_links(cid).await;
                    self.sessions.detach_connection(cid).await;
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

    /// Attach the calling connection to `session_id` on a fresh channel
    /// (Attach: the retained output; Resume: `from` = `last_seq`, only the
    /// bytes after it). The reply, the replay and the live output all travel
    /// through the attachment's ordered queue (see `Attachment`), so this
    /// returns `Ok(None)` once it is queued -- the Presence answering the
    /// request is the first thing on it.
    async fn attach_to_session(
        &self,
        ctx: &ConnectionContext,
        session_id: &str,
        mode: &str,
        from: Option<u64>,
    ) -> WshResult<Option<Envelope>> {
        let error = |code: u32, message: String| {
            Ok(Some(Envelope {
                msg_type: MsgType::Error,
                payload: Payload::Error(ErrorPayload { code, message }),
            }))
        };
        let channel_id = self.next_channel_id.fetch_add(1, Ordering::Relaxed);
        let (att_tx, att_rx) = mpsc::unbounded_channel();
        let attachment = Attachment {
            conn_id: ctx.conn_id,
            channel_id,
            mode: mode.to_string(),
            username: ctx.username.clone(),
            tx: att_tx,
        };
        match self
            .sessions
            .attach_with_replay(session_id, attachment, from)
            .await
        {
            Ok(start_seq) => {
                // Register channel -> session so SessionData/Close/Resize on the
                // new channel route; conn_session_map so E2E relay is session-scoped.
                self.channel_sessions
                    .write()
                    .await
                    .insert(channel_id, session_id.to_string());
                if let Some(cid) = ctx.conn_id {
                    self.conn_session_map
                        .write()
                        .await
                        .insert(cid, session_id.to_string());
                }
                // Only now can the client learn the channel id (the Presence is
                // still queued, undelivered), so everything is routable by then.
                Self::spawn_attachment_forwarder(att_rx, ctx.peer_tx.clone());
                info!(
                    session_id,
                    channel_id,
                    mode,
                    from = start_seq,
                    "client attached"
                );
                Ok(None)
            }
            Err(AttachError::NotFound) => error(3, format!("session not found: {session_id}")),
            Err(AttachError::Gap(message)) => error(4, message),
        }
    }

    /// Spawn the background task that pumps a session's PTY output into the
    /// session (`SessionManager::push_output`: the ring buffer, whose byte
    /// count is `seq`, and every attached channel as `SessionData`), and
    /// reports the exit (`SessionManager::finish`) once the child terminates.
    ///
    /// The pump belongs to the session, not to a connection: when the
    /// connection that opened it drops, the process keeps running and its
    /// output keeps filling the ring buffer, ready for a Resume/Attach.
    ///
    /// This is the "virtual" data-mode counterpart to a real multiplexed
    /// data stream: neither the WebSocket transport (which only ever
    /// reads/writes `FRAME_CONTROL` frames) nor the WebTransport transport
    /// (which only accepts a single bidirectional control stream) implement
    /// a second stream for session I/O, so output is delivered over the
    /// existing control-channel envelope path (each attachment's queue,
    /// forwarded to its connection's `peer_tx`).
    fn spawn_pty_output_pump(&self, session_id: String) {
        let sessions = self.sessions.clone();
        tokio::spawn(async move {
            let (reader, child_handle) = match sessions
                .with_session(&session_id, |session| {
                    let pty = session
                        .io
                        .as_pty()
                        .ok_or_else(|| wsh_core::WshError::Other("not a PTY session".into()))?;
                    Ok((pty.reader(), pty.child_handle()))
                })
                .await
            {
                Ok(handles) => handles,
                Err(e) => {
                    warn!(session_id = %session_id, error = %e, "PTY output pump: session not found at startup");
                    return;
                }
            };

            loop {
                let reader = reader.clone();
                let read_result = tokio::task::spawn_blocking(move || {
                    let mut buf = [0u8; 8192];
                    let mut guard = reader.blocking_lock();
                    guard.read(&mut buf).map(|n| (buf, n))
                })
                .await;

                let (buf, n) = match read_result {
                    Ok(Ok((buf, n))) => (buf, n),
                    Ok(Err(_)) | Err(_) => {
                        // Read error (including EIO on PTY close, common on Linux/macOS
                        // when the child exits) — treat as EOF and fall through to wait().
                        ([0u8; 8192], 0)
                    }
                };

                if n == 0 {
                    break;
                }

                if !sessions.push_output(&session_id, &buf[..n]).await {
                    debug!(session_id = %session_id, "PTY output pump: session gone, stopping");
                    return;
                }
            }

            // EOF on the PTY reader — the child has exited or is exiting.
            // Wait for the exact exit code, then notify whoever is attached.
            let code = tokio::task::spawn_blocking(move || {
                let mut child = child_handle.blocking_lock();
                child.wait()
            })
            .await
            .ok()
            .and_then(|r| r.ok())
            .map(|status| status.exit_code().try_into().unwrap_or(-1))
            .unwrap_or(-1);

            info!(session_id = %session_id, code, "PTY session ended");
            sessions.finish(&session_id, code).await;
        });
    }

    /// Output pump for an exec session on plain pipes: stdout feeds the
    /// session output (ring buffer, `seq`, every attachment), stderr goes to
    /// the opener on its own channel. Exit is reported only after both pipes
    /// have drained (bounded wait, so a background process that inherited the
    /// pipes cannot hold the exit hostage), so no output is lost behind it.
    fn spawn_pipe_output_pump(&self, session_id: String) {
        use tokio::io::AsyncReadExt;
        let sessions = self.sessions.clone();
        tokio::spawn(async move {
            let parts = sessions
                .with_session(&session_id, |s| match &s.io {
                    crate::session::pipes::SessionIo::Pipes(p) => Ok(p.take_parts()),
                    _ => Ok(None),
                })
                .await
                .ok()
                .flatten();
            let Some(mut parts) = parts else {
                warn!(session_id = %session_id, "pipe output pump: no pipes at startup");
                return;
            };

            let out_task = {
                let sessions = sessions.clone();
                let sid = session_id.clone();
                let mut stdout = parts.stdout;
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match stdout.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if !sessions.push_output(&sid, &buf[..n]).await {
                                    break;
                                }
                            }
                        }
                    }
                })
            };
            let err_task = {
                let sessions = sessions.clone();
                let sid = session_id.clone();
                let mut stderr = parts.stderr;
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match stderr.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if !sessions.push_stderr(&sid, &buf[..n]).await {
                                    break;
                                }
                            }
                        }
                    }
                })
            };

            // Wait for the process; a kill request (or the session being
            // dropped) ends it early.
            let status = loop {
                tokio::select! {
                    status = parts.child.wait() => break status.ok(),
                    msg = parts.kill_rx.recv() => {
                        let _ = parts.child.start_kill();
                        if msg.is_none() {
                            break parts.child.wait().await.ok();
                        }
                    }
                }
            };
            let code = status
                .map(|st| {
                    use std::os::unix::process::ExitStatusExt;
                    st.code()
                        .or_else(|| st.signal().map(|s| 128 + s))
                        .unwrap_or(-1)
                })
                .unwrap_or(-1);

            // Everything the command wrote is already in the pipes; give the
            // readers a moment to deliver it.
            let drain = std::time::Duration::from_millis(1500);
            let _ = tokio::time::timeout(drain, async {
                let _ = out_task.await;
                let _ = err_task.await;
            })
            .await;

            info!(session_id = %session_id, code, "pipes session ended");
            sessions.finish(&session_id, code).await;
        });
    }

    /// Forward one attachment's ordered queue to its connection's sender.
    /// Ends (closing the queue, so the attachment is pruned on the next
    /// push) when the connection goes away.
    fn spawn_attachment_forwarder(
        mut rx: mpsc::UnboundedReceiver<Envelope>,
        peer_tx: mpsc::Sender<Envelope>,
    ) {
        tokio::spawn(async move {
            while let Some(envelope) = rx.recv().await {
                if peer_tx.send(envelope).await.is_err() {
                    break;
                }
            }
        });
    }

    /// Stream a file to the client as a sequence of FileChunk control
    /// messages, ending with Exit + Close. FileChunk travels as an
    /// ordinary control message (not raw stream bytes) so this works
    /// identically over both transports, matching every other channel
    /// kind's data_mode: virtual today.
    fn spawn_file_download(
        &self,
        channel_id: u32,
        path: String,
        total_size: u64,
        peer_tx: mpsc::Sender<Envelope>,
    ) {
        const CHUNK_SIZE: usize = 65_536;

        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;

            let mut file = match tokio::fs::File::open(&path).await {
                Ok(f) => f,
                Err(e) => {
                    warn!(channel_id, path = %path, error = %e, "file download: failed to open file");
                    let _ = peer_tx
                        .send(Envelope {
                            msg_type: MsgType::Exit,
                            payload: Payload::Exit(ExitPayload {
                                channel_id,
                                code: 1,
                            }),
                        })
                        .await;
                    let _ = peer_tx
                        .send(Envelope {
                            msg_type: MsgType::Close,
                            payload: Payload::Close(ClosePayload { channel_id }),
                        })
                        .await;
                    return;
                }
            };

            let mut offset: u64 = 0;
            let mut buf = vec![0u8; CHUNK_SIZE];
            let mut read_error = false;

            loop {
                let n = match file.read(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(channel_id, path = %path, error = %e, "file download: read error");
                        read_error = true;
                        0
                    }
                };

                // n == 0 or a read error both force a final chunk even if
                // offset hasn't reached total_size yet (the file shrank or
                // errored mid-transfer) -- total_size always stays what was
                // captured at Open time, so the client's own
                // offset + len(data) == total_size truncation check
                // correctly flags that case as a truncated transfer rather
                // than looping forever trying to read past real EOF.
                let is_final = read_error || n == 0 || offset + n as u64 >= total_size;

                let sent = peer_tx
                    .send(Envelope {
                        msg_type: MsgType::FileChunk,
                        payload: Payload::FileChunk(FileChunkPayload {
                            channel_id,
                            offset,
                            data: buf[..n].to_vec(),
                            is_final,
                            total_size,
                        }),
                    })
                    .await;

                if sent.is_err() {
                    debug!(channel_id, "file download: peer channel closed, stopping");
                    return;
                }

                offset += n as u64;
                if is_final {
                    break;
                }
            }

            info!(channel_id, path = %path, bytes = offset, "file download complete");

            let _ = peer_tx
                .send(Envelope {
                    msg_type: MsgType::Exit,
                    payload: Payload::Exit(ExitPayload {
                        channel_id,
                        code: if read_error { 1 } else { 0 },
                    }),
                })
                .await;
            let _ = peer_tx
                .send(Envelope {
                    msg_type: MsgType::Close,
                    payload: Payload::Close(ClosePayload { channel_id }),
                })
                .await;
        });
    }

    /// Handle a "list" FileOp: read a directory's entries from the real
    /// filesystem and return them as typed `FileEntry` values (wsh #59 --
    /// previously this arrived only as an untyped `metadata` json bag, and
    /// only over `wsh-server`'s stub, which always refused; there was no
    /// real implementation on either client, let alone this server).
    ///
    /// Same unsandboxed-by-design filesystem access as the existing
    /// upload/download handlers above (`Open<ChannelKind::File>`): an
    /// authenticated connection here already has unrestricted exec/file
    /// access, so this does not introduce a new privilege boundary. Any
    /// I/O failure (no such path, not a directory, permission denied)
    /// comes back as `success: false` with `error_message` naming the
    /// reason -- never as an empty `entries` list, so a caller can't
    /// mistake "refused" for "empty directory" (wsh #58).
    async fn handle_file_list(&self, channel_id: u32, path: &str) -> FileResultPayload {
        fn refusal(channel_id: u32, error_message: String) -> FileResultPayload {
            FileResultPayload {
                channel_id,
                success: false,
                metadata: serde_json::Value::Object(Default::default()),
                entries: vec![],
                error_message: Some(error_message),
            }
        }

        let mut read_dir = match tokio::fs::read_dir(path).await {
            Ok(rd) => rd,
            Err(e) => return refusal(channel_id, format!("cannot list {path:?}: {e}")),
        };

        let mut entries = Vec::new();
        loop {
            let dir_entry = match read_dir.next_entry().await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(e) => return refusal(channel_id, format!("error reading {path:?}: {e}")),
            };

            let name = dir_entry.file_name().to_string_lossy().into_owned();
            let entry_path = dir_entry.path();

            // symlink_metadata (not metadata()) so a symlink is reported as
            // a symlink rather than transparently followed to its target's
            // type -- "a browse surface that flattens that is lying about
            // the remote filesystem" (wsh #58).
            let meta = match tokio::fs::symlink_metadata(&entry_path).await {
                Ok(m) => m,
                Err(e) => {
                    warn!(path = %entry_path.display(), error = %e, "list: skipping entry whose metadata could not be read");
                    continue;
                }
            };

            let file_type = meta.file_type();
            let (entry_type, symlink_target) = if file_type.is_symlink() {
                let target = tokio::fs::read_link(&entry_path)
                    .await
                    .ok()
                    .map(|t| t.to_string_lossy().into_owned());
                (FileEntryType::Symlink, target)
            } else if file_type.is_dir() {
                (FileEntryType::Directory, None)
            } else if file_type.is_file() {
                (FileEntryType::File, None)
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if file_type.is_block_device() || file_type.is_char_device() {
                        (FileEntryType::Device, None)
                    } else if file_type.is_fifo() {
                        (FileEntryType::Pipe, None)
                    } else if file_type.is_socket() {
                        (FileEntryType::Socket, None)
                    } else {
                        (FileEntryType::File, None)
                    }
                }
                #[cfg(not(unix))]
                {
                    (FileEntryType::File, None)
                }
            };

            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            entries.push(FileEntry {
                name,
                size: meta.len(),
                modified,
                r#type: entry_type,
                symlink_target,
            });
        }

        FileResultPayload {
            channel_id,
            success: true,
            metadata: serde_json::Value::Object(Default::default()),
            entries,
            error_message: None,
        }
    }

    /// Handle an `AuthorizedKeyAdd` request: idempotently install a raw
    /// Ed25519 public key into `~/.wsh/authorized_keys` (wsh #59).
    ///
    /// This replaces `wsh copy-id`'s previous approach of building and
    /// running a remote shell command
    /// (`crates/wsh-cli/src/commands/copy_id.rs`), which had a quoting
    /// hazard and was unreachable from any implementation without a shell
    /// channel (notably the browser SDK). Reachable here only by an
    /// already-authenticated connection, same as every other post-AUTH_OK
    /// message dispatched by this function -- an authenticated caller can
    /// already achieve the same file edit via `exec`, so this adds no new
    /// privilege boundary, only a structured, quote-free way to do it that
    /// works for clients with no shell channel at all.
    async fn handle_authorized_key_add(
        &self,
        p: &AuthorizedKeyAddPayload,
    ) -> AuthorizedKeyResultPayload {
        let raw_key: [u8; 32] = match p.public_key.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => {
                return AuthorizedKeyResultPayload {
                    success: false,
                    added: false,
                    error_message: Some(format!(
                        "invalid public key length: expected 32 bytes, got {}",
                        p.public_key.len()
                    )),
                };
            }
        };
        let fingerprint = wsh_core::fingerprint(&raw_key);

        let home = match dirs::home_dir() {
            Some(h) => h,
            None => {
                return AuthorizedKeyResultPayload {
                    success: false,
                    added: false,
                    error_message: Some("cannot determine home directory".into()),
                };
            }
        };
        let wsh_dir = home.join(".wsh");
        let path = wsh_dir.join("authorized_keys");

        let existing = tokio::fs::read_to_string(&path).await.unwrap_or_default();
        if wsh_core::keys::parse_authorized_keys(&existing)
            .iter()
            .any(|k| k.fingerprint == fingerprint)
        {
            return AuthorizedKeyResultPayload {
                success: true,
                added: false,
                error_message: None,
            };
        }

        if let Err(e) = tokio::fs::create_dir_all(&wsh_dir).await {
            return AuthorizedKeyResultPayload {
                success: false,
                added: false,
                error_message: Some(format!("cannot create {}: {e}", wsh_dir.display())),
            };
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                tokio::fs::set_permissions(&wsh_dir, std::fs::Permissions::from_mode(0o700)).await
            {
                warn!(path = %wsh_dir.display(), error = %e, "authorized-key-add: failed to set directory permissions");
            }
        }

        let comment = p.comment.clone().unwrap_or_default();
        let line = wsh_core::keys::format_authorized_key_line(&raw_key, &comment);
        let mut new_content = existing;
        if !new_content.is_empty() && !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str(&line);
        new_content.push('\n');

        if let Err(e) = tokio::fs::write(&path, &new_content).await {
            return AuthorizedKeyResultPayload {
                success: false,
                added: false,
                error_message: Some(format!("cannot write {}: {e}", path.display())),
            };
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await
            {
                warn!(path = %path.display(), error = %e, "authorized-key-add: failed to set file permissions");
            }
        }

        info!(fingerprint = %fingerprint, path = %path.display(), "authorized key installed");
        AuthorizedKeyResultPayload {
            success: true,
            added: true,
            error_message: None,
        }
    }

    /// Handle a WebSocket connection.
    ///
    /// The transport now speaks QMux (draft-ietf-quic-qmux-02) rather than
    /// the old hand-rolled `FRAME_CONTROL` framing: every control message
    /// (HELLO/CHALLENGE/AUTH/AUTH_OK and everything post-auth) travels as a
    /// CBOR envelope, length-prefix-framed (`FrameDecoder`/`frame_encode`),
    /// inside QMux STREAM frames on the client's control stream — always
    /// QMux stream ID 0, since the client always opens it first
    /// (`first_bidi_stream_id(Client) == 0`).
    ///
    /// Because HELLO/AUTH now arrive as QMux events rather than sequential
    /// awaits on raw WS reads, the handshake and the post-auth session loop
    /// (formerly a separate `session_loop_ws`) are unified into one
    /// `tokio::select!` loop driven by a small `ConnState` state machine —
    /// both consume the same QMux control-stream event source.
    async fn handle_websocket(&self, mut conn: websocket::WebSocketConnection) -> WshResult<()> {
        let remote = conn.remote_addr;
        info!(remote = %remote, "handling WebSocket connection");

        /// The client's control stream is always its first locally-opened
        /// bidirectional stream.
        const CONTROL_STREAM_ID: u64 = 0;

        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<QMuxEvent>();
        let qmux = Arc::new(QMuxConnection::new(
            QMuxConnectionConfig {
                is_client: false,
                ..Default::default()
            },
            move |bytes: &[u8]| {
                let _ = outbound_tx.send(bytes.to_vec());
            },
            event_tx,
        ));
        qmux.send_handshake()?;

        // Frames a single WS binary message can map to 0..N QMux records
        // can map to 0..N of these — a layer entirely separate from QMux's
        // own record framing.
        let mut control_decoder = FrameDecoder::new();

        /// Handshake/session state threaded through the unified select loop.
        enum ConnState {
            AwaitingHello,
            AwaitingAuth {
                hello: HelloPayload,
                hello_result: handshake::HelloResult,
            },
            Authenticated,
        }
        let mut state = ConnState::AwaitingHello;
        let mut ctx: Option<ConnectionContext> = None;
        // The sealed session (#155): off until a key login with `seal_session` on; then every message but the keepalive
        // leaves as an `EncryptedFrame` and arrives as one, and a frame that does not open ends the connection.
        let seal = SealGate::default();
        let must_seal = self.config.seal_session == SealSession::Require;
        // Typed rpc channels of this connection (#86); features are filled in at Hello.
        let mut rpc_sessions = RpcSessions::new(self.rpc.clone(), Vec::new());

        // Created eagerly so it can
        // be a plain, unconditional `select!` arm: nothing holds a clone of
        // `peer_tx` until auth succeeds and it's registered in
        // `peer_senders`, so this simply never fires before then.
        let (peer_tx, mut peer_rx) = mpsc::channel::<Envelope>(64);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let loop_result: WshResult<()> = 'session: loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    debug!("shutdown signal received, notifying WebSocket client");
                    if matches!(state, ConnState::Authenticated) {
                        let shutdown_msg = Envelope {
                            msg_type: MsgType::Shutdown,
                            payload: Payload::Shutdown(ShutdownPayload {
                                reason: "server shutdown".into(),
                                retry_after: None,
                            }),
                        };
                        if let Ok(frame) = frame_encode(&shutdown_msg) {
                            let _ = write_control(&qmux, &seal, CONTROL_STREAM_ID, frame).await;
                        }
                    }
                    break 'session Ok(());
                }

                // Peer push messages (e.g. forwarded ReverseConnect)
                Some(envelope) = peer_rx.recv() => {
                    match frame_encode(&envelope) {
                        Ok(frame) => {
                            // A write can wait for flow-control credit, and the
                            // client's credit arrives on this very socket. While
                            // it waits, keep serving the socket (flush outbound
                            // records, feed inbound bytes into QMux); otherwise
                            // output larger than the window, e.g. a command that
                            // echoes a big stdin, deadlocks both ends. Inbound
                            // control messages queue in `event_rx` meanwhile.
                            let write = write_control(&qmux, &seal, CONTROL_STREAM_ID, frame);
                            tokio::pin!(write);
                            loop {
                                tokio::select! {
                                    res = &mut write => {
                                        if let Err(e) = res {
                                            break 'session Err(e.into());
                                        }
                                        break;
                                    }
                                    Some(bytes) = outbound_rx.recv() => {
                                        if let Err(e) = websocket::ws_send_raw(&mut conn.ws_stream, &bytes).await {
                                            break 'session Err(e);
                                        }
                                    }
                                    ws_result = websocket::ws_recv_raw(&mut conn.ws_stream) => {
                                        match ws_result {
                                            Ok(Some(data)) => qmux.receive_bytes(&data),
                                            Ok(None) => {
                                                debug!("WebSocket session ended (peer closed)");
                                                break 'session Ok(());
                                            }
                                            Err(e) => {
                                                debug!(error = %e, "WebSocket session ended");
                                                break 'session Err(e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => break 'session Err(e),
                    }
                }

                // Outbound QMux record bytes (handshake/window-update/data
                // frames the connection wants to send) -- pump them to the
                // real WebSocket.
                Some(bytes) = outbound_rx.recv() => {
                    if let Err(e) = websocket::ws_send_raw(&mut conn.ws_stream, &bytes).await {
                        break 'session Err(e);
                    }
                }

                // Raw bytes off the wire -- sync feed into the QMux state
                // machine, which may itself synchronously enqueue outbound
                // bytes and/or push QMuxEvents.
                ws_result = websocket::ws_recv_raw(&mut conn.ws_stream) => {
                    match ws_result {
                        Ok(Some(data)) => {
                            qmux.receive_bytes(&data);
                        }
                        Ok(None) => {
                            debug!("WebSocket session ended (peer closed)");
                            break 'session Ok(());
                        }
                        Err(e) => {
                            debug!(error = %e, "WebSocket session ended");
                            break 'session Err(e);
                        }
                    }
                }

                Some(event) = event_rx.recv() => {
                    match event {
                        QMuxEvent::StreamOpen { stream_id } => {
                            debug!(stream_id, "QMux stream opened");
                            if stream_id != CONTROL_STREAM_ID {
                                // A client-opened data stream binds to the oldest open rpc channel.
                                let bound = match &ctx {
                                    Some(c) => rpc_sessions.on_stream_open(stream_id, &qmux, c.peer_tx.clone()),
                                    None => false,
                                };
                                if !bound {
                                    let _ = qmux.close_stream(stream_id);
                                }
                            }
                        }

                        QMuxEvent::StreamData { stream_id, data } => {
                            if stream_id != CONTROL_STREAM_ID {
                                if rpc_sessions.on_stream_data(stream_id, data) {
                                    continue;
                                }
                                // Session data (PTY/exec output) doesn't
                                // migrate onto real QMux streams in this
                                // phase -- it still flows over the control
                                // channel as `SessionData` envelopes.
                                warn!(stream_id, "ignoring StreamData on non-control QMux stream");
                                continue;
                            }

                            for raw in control_decoder.feed_raw(&data) {
                                // The sealed-session gate (#155): once the session is sealed, or must be, what
                                // arrives is the keepalive, the key exchange for this connection or a frame of the
                                // session; a plain message is not heard (a relay in the middle can write any), and a
                                // frame that does not open ends the connection. `sealed_in` is the message to handle.
                                let mut sealed_in: Option<Envelope> = None;
                                // (A plain `Open { kind: "rpc" }` is not a typed message: on a server that only offers sealing it
                                // is answered below as it always was, so a client that never seals sees no difference.)
                                let plain_rpc = !must_seal && !seal.is_sealed() && peek_rpc_open(&raw).is_some();
                                if seal.is_active() && !plain_rpc {
                                    let envelope = match decode_envelope(&raw) {
                                        Ok(e) => e,
                                        Err(e) => break 'session Err(e),
                                    };
                                    // `require`: before the key exists nothing is served. Say so, once, and close.
                                    let setup = matches!(&envelope.payload, Payload::KeyExchange(k)
                                        if Some(&k.session_id) == ctx.as_ref().map(|c| &c.session_id));
                                    let keepalive = matches!(envelope.msg_type, MsgType::Ping | MsgType::Pong);
                                    if must_seal && !seal.is_sealed() && !setup && !keepalive {
                                        warn!(msg_type = ?envelope.msg_type, "refused a plaintext message: this server requires a sealed session");
                                        let refusal = Envelope {
                                            msg_type: MsgType::Error,
                                            payload: Payload::Error(ErrorPayload {
                                                code: 1,
                                                message: "this server requires a sealed session (e2e-session-required)".into(),
                                            }),
                                        };
                                        if let Ok(frame) = frame_encode(&refusal) {
                                            let _ = qmux.write_stream(CONTROL_STREAM_ID, &frame).await;
                                        }
                                        break 'session Err(WshError::AuthFailed("a sealed session is required".into()));
                                    }
                                    let gated = seal.incoming_direct(envelope);
                                    if seal.has_failed() {
                                        break 'session Err(WshError::AuthFailed(
                                            "sealed session: a frame did not open (or the key exchange was refused); closing".into(),
                                        ));
                                    }
                                    for reply in &gated.replies {
                                        let frame = match frame_encode(reply) {
                                            Ok(f) => f,
                                            Err(e) => break 'session Err(e),
                                        };
                                        if let Err(e) = write_control(&qmux, &seal, CONTROL_STREAM_ID, frame).await {
                                            break 'session Err(e);
                                        }
                                    }
                                    match gated.deliver {
                                        Some(e) => sealed_in = Some(e),
                                        None => continue,
                                    }
                                }
                                // `Open { kind: "rpc" }` is not in the generated `ChannelKind`
                                // enum (a free string on the wire), so it is recognised before
                                // the typed decoder would reject it.
                                if sealed_in.is_none() && matches!(state, ConnState::Authenticated) {
                                    if let Some(protocol) = peek_rpc_open(&raw) {
                                        let ctx_ref = ctx.as_ref().expect("ctx set once Authenticated");
                                        let reply = self.open_rpc(ctx_ref, &protocol, &mut rpc_sessions);
                                        let frame = match frame_encode(&reply) {
                                            Ok(f) => f,
                                            Err(e) => break 'session Err(e),
                                        };
                                        if let Err(e) = write_control(&qmux, &seal, CONTROL_STREAM_ID, frame).await {
                                            break 'session Err(e);
                                        }
                                        continue;
                                    }
                                }
                                let envelope = match sealed_in {
                                    Some(e) => e,
                                    None => match decode_envelope(&raw) {
                                        Ok(e) => e,
                                        Err(e) => break 'session Err(e),
                                    },
                                };
                                // A `Close` for an rpc channel is not a session `Close`.
                                if matches!(state, ConnState::Authenticated) {
                                    if let Payload::Close(p) = &envelope.payload {
                                        if rpc_sessions.on_close(p.channel_id) {
                                            continue;
                                        }
                                    }
                                }

                                match &mut state {
                                    ConnState::AwaitingHello => {
                                        let hello = match (&envelope.msg_type, &envelope.payload) {
                                            (MsgType::Hello, Payload::Hello(h)) => h.clone(),
                                            _ => break 'session Err(WshError::InvalidMessage(
                                                "expected HELLO as first message".into(),
                                            )),
                                        };

                                        let server_fingerprints: Vec<String> = self
                                            .authorized_keys
                                            .iter()
                                            .map(|k| k.fingerprint.clone())
                                            .collect();
                                        let mut features = self.build_feature_list(true);
                                        // A sealed session (#155) is offered on a WebSocket connection (its control stream
                                        // carries the frames); `build_feature_list(false)` (WebTransport) never lists it.
                                        if self.config.seal_session != SealSession::Off && self.identity.is_some() {
                                            features.push(SESSION_SEAL_FEATURE.to_string());
                                            if must_seal {
                                                features.push(SESSION_SEAL_REQUIRED_FEATURE.to_string());
                                            }
                                        }
                                        rpc_sessions = RpcSessions::new(self.rpc.clone(), features.clone());
                                        let hello_result = match handshake::handle_hello(
                                            &hello,
                                            &server_fingerprints,
                                            Some(&features),
                                            self.identity.as_deref(),
                                        ) {
                                            Ok(r) => r,
                                            Err(e) => break 'session Err(e),
                                        };

                                        let sh_frame = match frame_encode(&hello_result.server_hello) {
                                            Ok(f) => f,
                                            Err(e) => break 'session Err(e),
                                        };
                                        if let Err(e) = qmux.write_stream(CONTROL_STREAM_ID, &sh_frame).await {
                                            break 'session Err(e.into());
                                        }
                                        let challenge_frame = match frame_encode(&hello_result.challenge) {
                                            Ok(f) => f,
                                            Err(e) => break 'session Err(e),
                                        };
                                        if let Err(e) = qmux.write_stream(CONTROL_STREAM_ID, &challenge_frame).await {
                                            break 'session Err(e.into());
                                        }

                                        state = ConnState::AwaitingAuth { hello, hello_result };
                                    }

                                    ConnState::AwaitingAuth { hello, hello_result } => {
                                        let auth = match (&envelope.msg_type, &envelope.payload) {
                                            (MsgType::Auth, Payload::Auth(a)) => a.clone(),
                                            _ => {
                                                let fail = handshake::build_auth_fail("expected AUTH message");
                                                if let Ok(fail_frame) = frame_encode(&fail) {
                                                    let _ = qmux.write_stream(CONTROL_STREAM_ID, &fail_frame).await;
                                                }
                                                break 'session Err(WshError::InvalidMessage("expected AUTH message".into()));
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
                                                if let Ok(fail_frame) = frame_encode(&fail) {
                                                    let _ = qmux.write_stream(CONTROL_STREAM_ID, &fail_frame).await;
                                                }
                                                break 'session Err(WshError::AuthFailed("rate limited".into()));
                                            }
                                        }

                                        // `require`: a password login has no key to authenticate the key exchange with.
                                        if must_seal && auth.method != AuthMethod::Pubkey {
                                            let fail = handshake::build_auth_fail(
                                                "this server requires a sealed session, which needs a key login",
                                            );
                                            if let Ok(fail_frame) = frame_encode(&fail) {
                                                let _ = qmux.write_stream(CONTROL_STREAM_ID, &fail_frame).await;
                                            }
                                            break 'session Err(WshError::AuthFailed("sealed session needs a key login".into()));
                                        }

                                        // Pre-check password auth against config hashes
                                        if auth.method == AuthMethod::Password && self.config.allow_password {
                                            match auth.password {
                                                Some(ref password) => {
                                                    // An unknown user and a wrong password are one
                                                    // answer, after the same work (see
                                                    // `auth::password::verify_login`).
                                                    if !self.check_password(&hello.username, password).await {
                                                        let fail = handshake::build_auth_fail("invalid password");
                                                        if let Ok(fail_frame) = frame_encode(&fail) {
                                                            let _ = qmux.write_stream(CONTROL_STREAM_ID, &fail_frame).await;
                                                        }
                                                        break 'session Err(WshError::AuthFailed("invalid password".into()));
                                                    }
                                                }
                                                None => {
                                                    let fail = handshake::build_auth_fail("password required");
                                                    if let Ok(fail_frame) = frame_encode(&fail) {
                                                        let _ = qmux.write_stream(CONTROL_STREAM_ID, &fail_frame).await;
                                                    }
                                                    break 'session Err(WshError::AuthFailed(
                                                        "password auth without password".into(),
                                                    ));
                                                }
                                            }
                                        }

                                        match handshake::verify_auth(
                                            &auth,
                                            &hello_result.nonce,
                                            &hello_result.session_id,
                                            &hello.username,
                                            &self.authorized_keys,
                                            &self.secret,
                                            self.config.session_ttl,
                                            self.config.allow_pubkey,
                                            self.config.allow_password,
                                            &hello_result.acceptable_bindings,
                                            hello_result.binding_required,
                                        ) {
                                            Ok(mut result) => {
                                                result.username = hello.username.clone();
                                                let ok = handshake::build_auth_ok(
                                                    &result.session_id,
                                                    &result.token,
                                                    handshake::AUTH_OK_TTL,
                                                );
                                                let ok_frame = match frame_encode(&ok) {
                                                    Ok(f) => f,
                                                    Err(e) => break 'session Err(e),
                                                };
                                                if let Err(e) = qmux.write_stream(CONTROL_STREAM_ID, &ok_frame).await {
                                                    break 'session Err(e.into());
                                                }

                                                info!(
                                                    remote = %remote,
                                                    username = %result.username,
                                                    session_id = %result.session_id,
                                                    "WebSocket auth OK"
                                                );

                                                // Assign a unique conn_id and register in
                                                // peer_senders/conn_session_map so E2E relay,
                                                // CopilotSuggest, and idle warnings are
                                                // session-scoped.
                                                let conn_id = self.alloc_conn_id();
                                                self.peer_senders
                                                    .write()
                                                    .await
                                                    .insert(conn_id, peer_tx.clone());
                                                self.conn_session_map
                                                    .write()
                                                    .await
                                                    .insert(conn_id, result.session_id.clone());
                                                ctx = Some(ConnectionContext {
                                                    username: result.username.clone(),
                                                    fingerprint: result.fingerprint.clone(),
                                                    session_id: result.session_id.clone(),
                                                    token: result.token.clone(),
                                                    peer_tx: peer_tx.clone(),
                                                    conn_id: Some(conn_id),
                                                    mcp_calls: Default::default(),
                                                    gateway: GatewaySession::new(
                                                        self.gateway_policy.clone(),
                                                        peer_tx.clone(),
                                                        self.gateway_enabled,
                                                        &hello.features,
                                                    ),
                                                });
                                                rpc_sessions.set_user(&result.username);
                                                // A sealed session (#155): from here the key exchange for this connection's
                                                // session id is answered by the gate, which holds the host key and the login
                                                // key this connection just proved (the initiator signs its half with it).
                                                // `offer` serves a client that never asks plainly; `require` hears nothing else.
                                                if self.config.seal_session != SealSession::Off && auth.method == AuthMethod::Pubkey {
                                                    let login_key: Option<[u8; 32]> = auth
                                                        .public_key
                                                        .as_deref()
                                                        .and_then(|k| k.try_into().ok())
                                                        .filter(|k: &[u8; 32]| fingerprint(k) == result.fingerprint);
                                                    match (self.identity.as_deref(), login_key) {
                                                        (Some(identity), Some(login_key)) => {
                                                            seal.begin_session_responder(
                                                                result.session_id.clone(),
                                                                must_seal,
                                                                E2eResponder::new(
                                                                    Some(identity.signing_key().clone()),
                                                                    true,
                                                                    Some(identity.public_key()),
                                                                    Some(InitiatorAuth { public_key: login_key, require: true }),
                                                                ),
                                                            );
                                                        }
                                                        _ => break 'session Err(WshError::AuthFailed(
                                                            "sealed session: no login key to authenticate the key exchange with".into(),
                                                        )),
                                                    }
                                                }
                                                state = ConnState::Authenticated;
                                            }
                                            Err(e) => {
                                                let fail = handshake::build_auth_fail(&e.to_string());
                                                if let Ok(fail_frame) = frame_encode(&fail) {
                                                    let _ = qmux.write_stream(CONTROL_STREAM_ID, &fail_frame).await;
                                                }
                                                break 'session Err(e);
                                            }
                                        }
                                    }

                                    ConnState::Authenticated => {
                                        let ctx_ref = ctx.as_mut().expect("ctx set once Authenticated");
                                        match self
                                            .dispatch_message(envelope, ctx_ref)
                                            .await
                                        {
                                            Ok(Some(response)) => {
                                                let frame = match frame_encode(&response) {
                                                    Ok(f) => f,
                                                    Err(e) => break 'session Err(e),
                                                };
                                                if let Err(e) = write_control(&qmux, &seal, CONTROL_STREAM_ID, frame).await {
                                                    break 'session Err(e);
                                                }
                                            }
                                            Ok(None) => {}
                                            Err(e) => break 'session Err(e),
                                        }
                                    }
                                }
                            }
                        }

                        QMuxEvent::StreamEnd { stream_id } => {
                            if rpc_sessions.on_stream_end(stream_id) {
                                continue;
                            }
                            if stream_id == CONTROL_STREAM_ID {
                                debug!("WebSocket control stream ended (peer closed)");
                                break 'session Ok(());
                            }
                        }

                        QMuxEvent::StreamReset { stream_id, error_code } => {
                            if rpc_sessions.on_stream_reset(stream_id) {
                                continue;
                            }
                            if stream_id == CONTROL_STREAM_ID {
                                debug!(?error_code, "WebSocket control stream reset by peer");
                                break 'session Ok(());
                            }
                        }

                        QMuxEvent::StreamDestroyed { stream_id } => {
                            if stream_id == CONTROL_STREAM_ID {
                                break 'session Ok(());
                            }
                        }

                        QMuxEvent::Datagram { .. } => {
                            debug!("ignoring QMux datagram (unused by wsh)");
                        }

                        QMuxEvent::ConnectionClosed { error_code, reason } => {
                            debug!(?error_code, %reason, "QMux connection closed by peer");
                            break 'session Ok(());
                        }

                        QMuxEvent::Error { message } => {
                            break 'session Err(WshError::Transport(format!("QMux error: {message}")));
                        }
                    }
                }
            }
        };

        // Flush any outbound QMux bytes still sitting in the channel --
        // e.g. an AUTH_FAIL or Shutdown frame `write_stream`'d just before
        // breaking out of the loop above only reaches `outbound_tx`
        // (the synchronous `send` callback), not the wire; nothing drains
        // it once the loop has already exited, so do that explicitly here
        // before the WebSocket is dropped.
        while let Ok(bytes) = outbound_rx.try_recv() {
            let _ = websocket::ws_send_raw(&mut conn.ws_stream, &bytes).await;
        }

        // Cleanup: unregister peer if it ever got registered, regardless of
        // whether the loop above ended cleanly or with an error.
        if let Some(ctx) = ctx.take() {
            if let Some(cid) = ctx.conn_id {
                self.peer_senders.write().await.remove(&cid);
                self.conn_session_map.write().await.remove(&cid);
                self.clear_relay_links(cid).await;
                self.sessions.detach_connection(cid).await;
            }
            self.peer_registry.unregister(&ctx.fingerprint).await;
        }

        loop_result
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

    /// Access the #38 Phase 2 WISP guest registry.
    pub fn wisp_registry(&self) -> &WispRegistry {
        &self.wisp_registry
    }

    // ── #38 Phase 2: WISP reverse-connect bridge ─────────────────────────

    /// Handle a guest's outbound `/wisp/<fingerprint>` WISP tunnel.
    ///
    /// Registers a [`WispGuestSession`] for the connection's lifetime so
    /// `/wisp-connect/<fingerprint>` requests can find and bridge to it, then
    /// pumps bytes in both directions: raw WISP frame bytes queued by the
    /// session (`REVERSE_OPEN`/`DATA`/`CLOSE` destined for the guest) go out
    /// over the WebSocket, and frames arriving from the guest are decoded
    /// and handed to `WispGuestSession::handle_incoming`.
    async fn handle_wisp_guest(&self, conn: websocket::WispGuestConnection) {
        let websocket::WispGuestConnection {
            mut ws_stream,
            remote_addr,
            fingerprint,
        } = conn;

        // A WISP tunnel is a byte pipe that no wsh session of this server rides, and it cannot be sealed: with
        // `seal_session = "require"` the server serves nothing in the clear, so it is refused.
        if self.config.seal_session == SealSession::Require {
            warn!(remote = %remote_addr, "refused a WISP guest tunnel: [server] seal_session = \"require\"");
            let _ = ws_stream.close(None).await;
            return;
        }

        info!(remote = %remote_addr, %fingerprint, "WISP guest tunnel connected");

        let (to_guest_tx, mut to_guest_rx) = mpsc::channel::<Vec<u8>>(64);
        let session = WispGuestSession::new(fingerprint.clone(), to_guest_tx);
        self.wisp_registry.register(session.clone()).await;

        loop {
            tokio::select! {
                outbound = to_guest_rx.recv() => {
                    match outbound {
                        Some(bytes) => {
                            if let Err(e) = websocket::ws_send_raw(&mut ws_stream, &bytes).await {
                                warn!(%fingerprint, error = %e, "failed to send WISP frame to guest");
                                break;
                            }
                        }
                        None => break,
                    }
                }
                incoming = websocket::ws_recv_raw(&mut ws_stream) => {
                    match incoming {
                        Ok(Some(bytes)) => {
                            if let Some(frame) = wisp::decode_frame(&bytes) {
                                session.handle_incoming(frame).await;
                            } else {
                                debug!(%fingerprint, "malformed WISP frame from guest, dropping");
                            }
                        }
                        Ok(None) => {
                            debug!(%fingerprint, "WISP guest tunnel closed by guest");
                            break;
                        }
                        Err(e) => {
                            warn!(%fingerprint, error = %e, "WISP guest tunnel read error");
                            break;
                        }
                    }
                }
            }
        }

        self.wisp_registry.unregister(&fingerprint).await;
        info!(%fingerprint, "WISP guest tunnel disconnected");
    }

    /// Handle an external `wsh connect <fingerprint>` client's reverse-bridge
    /// request (`/wisp-connect/<fingerprint>`).
    ///
    /// Looks the fingerprint up in the WISP registry; if a guest tunnel is
    /// live, opens a `REVERSE_OPEN` reverse stream against it and proxies raw
    /// bytes bidirectionally between this external WebSocket and that
    /// stream — a NAT-style byte pipe, not wsh's own Envelope/QMux relay
    /// protocol (the guest's own `wsh-server` terminates its own independent
    /// session with whatever ends up on the other end).
    async fn handle_wisp_connect(&self, conn: websocket::WispConnectRequest) {
        let websocket::WispConnectRequest {
            mut ws_stream,
            remote_addr,
            fingerprint,
            local_port,
        } = conn;

        if self.config.seal_session == SealSession::Require {
            warn!(remote = %remote_addr, "refused a WISP reverse-connect: [server] seal_session = \"require\"");
            let _ = ws_stream.close(None).await;
            return;
        }

        let Some(session) = self.wisp_registry.get(&fingerprint).await else {
            warn!(remote = %remote_addr, %fingerprint, "WISP reverse-connect: no guest tunnel registered for fingerprint");
            let _ = ws_stream.close(None).await;
            return;
        };

        let (stream_id, mut reverse_rx) = session.open_reverse(local_port).await;
        info!(remote = %remote_addr, %fingerprint, stream_id, local_port, "WISP reverse-connect bridge established");

        loop {
            tokio::select! {
                incoming = websocket::ws_recv_raw(&mut ws_stream) => {
                    match incoming {
                        Ok(Some(bytes)) => {
                            if !session.send_reverse_data(stream_id, &bytes).await {
                                break;
                            }
                        }
                        Ok(None) => {
                            session.close_reverse(stream_id, 0).await;
                            break;
                        }
                        Err(e) => {
                            warn!(%fingerprint, stream_id, error = %e, "WISP reverse-connect read error");
                            session.close_reverse(stream_id, 5 /* CLOSE_REASON_ERROR */).await;
                            break;
                        }
                    }
                }
                event = reverse_rx.recv() => {
                    match event {
                        Some(wisp::ReverseEvent::Data(bytes)) => {
                            if let Err(e) = websocket::ws_send_raw(&mut ws_stream, &bytes).await {
                                warn!(%fingerprint, stream_id, error = %e, "failed to forward reverse data to external client");
                                break;
                            }
                        }
                        Some(wisp::ReverseEvent::Closed) | None => {
                            let _ = ws_stream.close(None).await;
                            break;
                        }
                    }
                }
            }
        }

        info!(%fingerprint, stream_id, "WISP reverse-connect bridge closed");
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
                            if let Some(response) = self.dispatch_message(envelope, ctx).await? {
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

    /// Answer `Open { kind: "rpc", command: <protocol> }` (WebSocket / QMux connections only).
    ///
    /// Key options apply as they do to other channels: a key restricted to a
    /// forced command gets no rpc channels, and `wsh-fs` needs the file-transfer scope.
    fn open_rpc(
        &self,
        ctx: &ConnectionContext,
        protocol: &str,
        rpc_sessions: &mut RpcSessions,
    ) -> Envelope {
        let permissions = self.key_permissions(&ctx.fingerprint);
        if let Err(refusal) = permissions.check(KeyRequest::OpenRpc(protocol), 0) {
            return rpc_open_fail(&refusal.reason);
        }
        let allow_fs = permissions.has_scope(&crate::auth::permissions::SessionScope::FileTransfer);
        let next = self.next_channel_id.clone();
        rpc_sessions.open(
            protocol,
            move || next.fetch_add(1, Ordering::Relaxed),
            allow_fs,
        )
    }

    /// What the authorized_keys options of the key `fingerprint` allow (wsh #122). The first line for a key decides, as on the
    /// Node host; a key without options, or one that logged in some other way, has full access.
    fn key_permissions(&self, fingerprint: &str) -> crate::auth::permissions::KeyPermissions {
        let key_options = self
            .authorized_keys
            .iter()
            .find(|k| k.fingerprint == fingerprint)
            .and_then(|k| k.options.as_deref());
        crate::auth::permissions::KeyPermissions::from_options(fingerprint.to_string(), key_options)
    }

    /// The reply that refuses a gateway message the key's capabilities do not cover (`GatewayFail` / `ListenFail`), or `None`
    /// (wsh #122, step two). Asked before the gateway's own policy; a key without a capability list is not affected.
    /// This server has no named endpoints or targets, so `OpenEndpoint` is refused here whatever the key holds, and
    /// the gateway answers a target it does not have.
    fn gateway_key_refusal(&self, fingerprint: &str, envelope: &Envelope) -> Option<Envelope> {
        let permissions = self.key_permissions(fingerprint);
        let (request, gateway_id, listener_id) = match &envelope.payload {
            Payload::OpenTcp(p) => (KeyRequest::Tcp(&p.host, p.port), Some(p.gateway_id), None),
            Payload::OpenUdp(p) => (KeyRequest::Udp(&p.host, p.port), Some(p.gateway_id), None),
            Payload::ResolveDns(p) => (KeyRequest::Dns(&p.name), Some(p.gateway_id), None),
            Payload::OpenUnix(p) => (KeyRequest::Unix(&p.path), Some(p.gateway_id), None),
            Payload::OpenEndpoint(p) => (
                KeyRequest::Endpoint(&p.name, p.target.as_deref()),
                Some(p.gateway_id),
                None,
            ),
            Payload::ListenRequest(p) => (KeyRequest::ListenTcp(p.port), None, Some(p.listener_id)),
            Payload::ListenUnix(p) => (KeyRequest::ListenUnix(&p.path), None, Some(p.listener_id)),
            _ => return None,
        };
        let refusal = permissions.check(request, 0).err()?;
        warn!(
            fingerprint = %&fingerprint[..8.min(fingerprint.len())],
            code = refusal.code,
            capability = refusal.capability.as_deref().unwrap_or(""),
            "gateway request refused by the key's permissions"
        );
        Some(match (gateway_id, listener_id) {
            (Some(gateway_id), _) => Envelope {
                msg_type: MsgType::GatewayFail,
                payload: Payload::GatewayFail(GatewayFailPayload {
                    gateway_id,
                    code: 4,
                    message: refusal.reason,
                }),
            },
            (_, Some(listener_id)) => Envelope {
                msg_type: MsgType::ListenFail,
                payload: Payload::ListenFail(ListenFailPayload {
                    listener_id,
                    reason: refusal.reason,
                }),
            },
            _ => return None,
        })
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

    /// A connection ended (or its partner is gone): forget its bridges. A peer that serves several
    /// operators (wsh #93) is told with `ReverseClose` which one left; any other peer is left
    /// connected, as it always was.
    async fn clear_relay_links(&self, conn_id: u64) {
        let departed = self.bridges.write().await.depart(conn_id);
        if let Some((peer, operator_fingerprint)) = departed.reverse_close {
            if let Some(tx) = self.peer_senders.read().await.get(&peer) {
                let _ = tx.try_send(Envelope {
                    msg_type: MsgType::ReverseClose,
                    payload: Payload::ReverseClose(ReverseClosePayload {
                        target_fingerprint: operator_fingerprint,
                        reason: Some("operator left".to_string()),
                    }),
                });
            }
        }
    }

    /// Build the list of features this server advertises based on configuration.
    /// `data_streams`: the transport can carry client-opened data streams (QMux
    /// over WebSocket). The native WebTransport path has a single control
    /// stream, so it must not advertise the stream-based `rpc` channels.
    fn build_feature_list(&self, data_streams: bool) -> Vec<String> {
        // "mcp-call-id": McpResult echoes McpCall's call_id, so a client may
        // correlate concurrent tool calls. Advertised rather than assumed --
        // McpCallPayload is deny_unknown_fields, so a client must not send
        // call_id to a server that predates it.
        let mut features = vec![
            "mcp".to_string(),
            "mcp-call-id".to_string(),
            // `McpCancel` stops an in-flight `McpCall` (it runs as its own task,
            // keyed by call_id). Implies mcp-call-id: McpCancelPayload is
            // deny_unknown_fields, so only a client that saw this sends it.
            "mcp-cancel".to_string(),
            "file-transfer".to_string(),
            // `Open { kind: exec, stdio: "pipes" }` runs the command on plain
            // pipes (separate stderr, stdin EOF); see spec Open.stdio. Advertised
            // rather than assumed: OpenPayload is deny_unknown_fields.
            "exec-pipes".to_string(),
        ];
        if self.gateway_enabled {
            features.push("gateway".to_string());
            // GatewayCredit flow control: used only when the client lists it too.
            features.push(crate::gateway::session::GATEWAY_CREDIT_FEATURE.to_string());
            // OpenUnix / ListenUnix, only when the operator listed sockets.
            if self.gateway_policy.unix().is_enabled() {
                features.push(crate::gateway::session::GATEWAY_UNIX_FEATURE.to_string());
            }
        }
        if self.config.enable_relay {
            features.push("reverse".to_string());
            // ReverseChallenge / ReverseProof and ReverseConnect.features are carried (wsh #117).
            features.push(wsh_core::operator_proof::OPERATOR_PROOF_FEATURE.to_string());
            // The relay carries `KeyExchange.signature` (the regenerated payload has the field), so a
            // peer may sign its half of an end-to-end exchange; the JS reverse host signs only after
            // reading this (wsh #93). A relay built before the field drops a connection that sends it.
            features.push(wsh_core::e2e_exchange::E2E_SIGN_FEATURE.to_string());
            // `RelayForward.to_fingerprint` and `ReverseClose`: a peer that states the same feature
            // in its ReverseAccept may be bridged to several operators (wsh #93). Only when the
            // operator configured more than one, so a default relay advertises nothing new.
            if self.config.relay_max_operators_per_peer > 1 {
                features.push(wsh_core::RELAY_MULTI_OPERATOR_FEATURE.to_string());
            }
        }
        if self.recording_dir.is_some() {
            features.push("recording".to_string());
        }
        if data_streams {
            if let Some(rpc) = &self.rpc {
                features.extend(rpc.features());
            }
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

    /// A `features` list as the relay reads or copies it: at most `max_entries` entries of at most
    /// `max_len` bytes each; anything else is dropped (the reader then sees a peer that claims
    /// nothing). `ReverseConnect.features` is bounded at 8 x 64, `ReverseAccept.features` at 64 x 128.
    fn bounded_features(
        features: Option<&[String]>,
        max_entries: usize,
        max_len: usize,
    ) -> Option<Vec<String>> {
        let f = features?;
        (f.len() <= max_entries && f.iter().all(|s| !s.is_empty() && s.len() <= max_len))
            .then(|| f.to_vec())
    }

    /// Check whether a message type should be forwarded through a relay bridge
    /// rather than processed locally. These are the "data plane" messages that
    /// flow between CLI and browser during a reverse connection.
    async fn dispatch_message(
        &self,
        envelope: Envelope,
        ctx: &mut ConnectionContext,
    ) -> WshResult<Option<Envelope>> {
        if let Some(conn_id) = ctx.conn_id {
            if matches!(
                envelope.msg_type,
                MsgType::ReverseAccept | MsgType::ReverseReject
            ) {
                // Only the peer a request was forwarded to can answer it.
                let partner_id = self.bridges.read().await.pending_operator(conn_id);

                if let Some(partner_id) = partner_id {
                    let msg_type = envelope.msg_type;
                    // A peer that serves several operators says so in the features of its accept
                    // (bounded: anything else is not read).
                    let multi = match &envelope.payload {
                        Payload::ReverseAccept(a) => {
                            Self::bounded_features(a.features.as_deref(), 64, 128).is_some_and(
                                |f| {
                                    f.iter()
                                        .any(|f| f == wsh_core::RELAY_MULTI_OPERATOR_FEATURE)
                                },
                            )
                        }
                        _ => false,
                    };
                    let senders = self.peer_senders.read().await;
                    if let Some(sender) = senders.get(&partner_id) {
                        let _ = sender.try_send(envelope);
                    } else {
                        drop(senders);
                        // The requester is gone: its pending request and anything of it go.
                        self.clear_relay_links(partner_id).await;
                        warn!(
                            conn_id,
                            partner_id,
                            "pending reverse partner sender gone, cleaning up handshake"
                        );
                        return Ok(None);
                    }
                    drop(senders);

                    let accepted = matches!(msg_type, MsgType::ReverseAccept);
                    self.bridges.write().await.answer(conn_id, accepted, multi);
                    if accepted {
                        info!(
                            requester = partner_id,
                            target = conn_id,
                            multi_operator = multi,
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
            let forwardable = is_relay_forwardable(envelope.msg_type);
            // A peer that serves several operators writes its own `RelayForward` to address one
            // (`to_fingerprint`); the relay checks the inner, then re-wraps it with the sender's
            // authenticated key, so the field is never delivered (wsh #93).
            let own_forward = matches!(envelope.msg_type, MsgType::RelayForward);
            if forwardable || own_forward {
                let to = match &envelope.payload {
                    Payload::RelayForward(p) => p.to_fingerprint.as_deref(),
                    _ => None,
                };
                let route = self.bridges.read().await.recipient(conn_id, to);
                match route {
                    Route::NoBridge => {}
                    Route::Drop(why) => {
                        warn!(conn_id, "relay: dropped {why}");
                        return Ok(None);
                    }
                    Route::To(partner_id) => {
                        // What is delivered: this message wrapped (a plain forwardable one) or the
                        // inner of the forward the connection wrote, once it has been checked.
                        let inner = match &envelope.payload {
                            Payload::RelayForward(p) => {
                                if p.inner.len() > MAX_RELAY_FORWARD_BYTES {
                                    warn!(conn_id, "relay: dropped an oversized RelayForward");
                                    return Ok(None);
                                }
                                match wsh_core::decode_envelope(&p.inner) {
                                    Ok(decoded) if is_relay_forwardable(decoded.msg_type) => {
                                        Ok(p.inner.clone())
                                    }
                                    Ok(decoded) => {
                                        warn!(
                                            conn_id,
                                            msg_type = ?decoded.msg_type,
                                            "relay: dropped a RelayForward wrapping a non-forwardable type"
                                        );
                                        return Ok(None);
                                    }
                                    Err(err) => {
                                        warn!(conn_id, %err, "relay: dropped a RelayForward with an undecodable inner");
                                        return Ok(None);
                                    }
                                }
                            }
                            _ => wsh_core::cbor_encode(&envelope),
                        };
                        let senders = self.peer_senders.read().await;
                        if let Some(sender) = senders.get(&partner_id) {
                            // Wrap in RelayForward so the receiving peer can verify
                            // who actually sent this rather than trusting the relay
                            // blindly. from_fingerprint is the server's own record
                            // of this connection's authenticated identity, never a
                            // client-supplied value.
                            match inner {
                                Ok(inner) => {
                                    let wrapped = Envelope {
                                        msg_type: MsgType::RelayForward,
                                        payload: Payload::RelayForward(RelayForwardPayload {
                                            from_fingerprint: ctx.fingerprint.clone(),
                                            inner,
                                            to_fingerprint: None,
                                        }),
                                    };
                                    let _ = sender.try_send(wrapped);
                                }
                                Err(err) => {
                                    warn!(conn_id, %err, "failed to encode relay-forwarded envelope");
                                }
                            }
                            return Ok(None); // forwarded, don't process locally
                        }
                        // Partner sender gone — clean up its stale links (and tell a multi-operator
                        // peer when it was an operator)
                        drop(senders);
                        self.clear_relay_links(partner_id).await;
                        warn!(
                            conn_id,
                            partner_id, "relay partner sender gone, cleaning up bridge"
                        );
                    }
                }
            }
        }

        match (&envelope.msg_type, &envelope.payload) {
            // ── Reverse peer messages ───────────────────────────────
            // wsh #122: a key without `permit-relay` cannot register, list or connect (the answers are the Node host's).
            (MsgType::ReverseRegister | MsgType::ReverseList, _)
                if self
                    .key_permissions(&ctx.fingerprint)
                    .check(KeyRequest::Relay, 0)
                    .is_err() =>
            {
                warn!(
                    fingerprint = %&ctx.fingerprint[..8.min(ctx.fingerprint.len())],
                    "relay request refused by the key's options"
                );
                Ok(Some(Envelope {
                    msg_type: MsgType::Error,
                    payload: Payload::Error(ErrorPayload {
                        code: 2,
                        message: "relay not permitted for this key".into(),
                    }),
                }))
            }
            (MsgType::ReverseConnect, Payload::ReverseConnect(p))
                if self
                    .key_permissions(&ctx.fingerprint)
                    .check(KeyRequest::Relay, 0)
                    .is_err() =>
            {
                warn!(
                    fingerprint = %&ctx.fingerprint[..8.min(ctx.fingerprint.len())],
                    "relay request refused by the key's options"
                );
                Ok(Some(Envelope {
                    msg_type: MsgType::ReverseReject,
                    payload: Payload::ReverseReject(ReverseRejectPayload {
                        target_fingerprint: p.target_fingerprint.clone(),
                        username: String::new(),
                        reason: "relay not permitted for this key".into(),
                    }),
                }))
            }
            (MsgType::ReverseRegister, Payload::ReverseRegister(p)) => {
                // Verify the peer's self-signed record before accepting
                // registration at all (wsh #17) -- p.public_key must belong
                // to *this* connection's own authenticated identity
                // (ctx.fingerprint, established during AUTH), not merely be
                // *some* validly-signed key the client happens to control.
                // Also enforces the signed record's monotonic seq, so a
                // later stale re-registration can't silently regress a
                // peer's advertised capabilities. All rejections are
                // silent drops (log + no response), matching this
                // protocol's existing forgiving conventions elsewhere.
                if p.public_key.is_empty() || p.record_signature.is_empty() {
                    warn!(
                        fingerprint = %&ctx.fingerprint[..8.min(ctx.fingerprint.len())],
                        "rejecting ReverseRegister: missing signed-record fields"
                    );
                    return Ok(None);
                }
                let claimed_fingerprint = fingerprint(&p.public_key);
                if claimed_fingerprint != ctx.fingerprint {
                    warn!(
                        fingerprint = %&ctx.fingerprint[..8.min(ctx.fingerprint.len())],
                        "rejecting ReverseRegister: public_key does not match the authenticated identity"
                    );
                    return Ok(None);
                }
                if let Some(existing) = self.peer_registry.get(&ctx.fingerprint).await {
                    if p.seq <= existing.seq {
                        warn!(
                            fingerprint = %&ctx.fingerprint[..8.min(ctx.fingerprint.len())],
                            seq = p.seq,
                            existing_seq = existing.seq,
                            "rejecting stale ReverseRegister"
                        );
                        return Ok(None);
                    }
                }
                let record = wsh_core::PeerRecord {
                    username: p.username.clone(),
                    peer_type: p.peer_type.clone(),
                    shell_backend: p.shell_backend.clone(),
                    capabilities: p.capabilities.clone(),
                    supports_attach: p.supports_attach,
                    supports_replay: p.supports_replay,
                    supports_echo: p.supports_echo,
                    supports_term_sync: p.supports_term_sync,
                    seq: p.seq,
                };
                if !wsh_core::verify_peer_record(&p.public_key, &p.record_signature, &record) {
                    warn!(
                        fingerprint = %&ctx.fingerprint[..8.min(ctx.fingerprint.len())],
                        "rejecting ReverseRegister: signature verification failed"
                    );
                    return Ok(None);
                }

                let fp = ctx.fingerprint.clone();
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
                            public_key: p.public_key.clone(),
                            seq: p.seq,
                            record_signature: p.record_signature.clone(),
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
                        public_key: if e.public_key.is_empty() {
                            None
                        } else {
                            Some(e.public_key.clone())
                        },
                        seq: Some(e.seq),
                        record_signature: if e.record_signature.is_empty() {
                            None
                        } else {
                            Some(e.record_signature.clone())
                        },
                    })
                    .collect();
                Ok(Some(Envelope {
                    msg_type: MsgType::ReversePeers,
                    payload: Payload::ReversePeers(ReversePeersPayload { peers }),
                }))
            }
            // ── Operator proof (#117): carried, not interpreted ───────
            // The peer signed its challenge and the operator its proof, so the relay can
            // neither forge nor profit from reading them; it only keeps the two ends of a
            // PENDING request talking, and stamps who sent each.
            (MsgType::ReverseChallenge, Payload::ReverseChallenge(p)) => {
                if let Some(conn_id) = ctx.conn_id {
                    if p.public_key.len() <= 64
                        && p.signature.len() <= 128
                        && p.nonce.len() <= 64
                        && p.session_id.len() <= 256
                        && p.operator_fingerprint.len() <= 256
                    {
                        // only the peer a request is waiting on challenges its operator
                        let partner = self.bridges.read().await.pending_operator(conn_id);
                        if let Some(partner) = partner {
                            let fwd = Envelope {
                                msg_type: MsgType::ReverseChallenge,
                                payload: Payload::ReverseChallenge(ReverseChallengePayload {
                                    // the answering peer, not whatever it wrote
                                    target_fingerprint: ctx.fingerprint.clone(),
                                    ..p.clone()
                                }),
                            };
                            if let Some(tx) = self.peer_senders.read().await.get(&partner) {
                                let _ = tx.try_send(fwd);
                            }
                        }
                    }
                }
                Ok(None)
            }
            (MsgType::ReverseProof, Payload::ReverseProof(p)) => {
                if let Some(conn_id) = ctx.conn_id {
                    if p.public_key.len() <= 64
                        && p.signature.len() <= 128
                        && p.nonce.len() <= 64
                        && p.session_id.len() <= 256
                        && p.username.len() <= 64
                    {
                        // only the operator whose request is pending proves itself, to that peer
                        let partner = self.bridges.read().await.pending_peer(conn_id);
                        if let Some(partner) = partner {
                            let fwd = Envelope {
                                msg_type: MsgType::ReverseProof,
                                payload: Payload::ReverseProof(ReverseProofPayload {
                                    // the relay speaks for the operator's identity
                                    from_fingerprint: Some(ctx.fingerprint.clone()),
                                    ..p.clone()
                                }),
                            };
                            if let Some(tx) = self.peer_senders.read().await.get(&partner) {
                                let _ = tx.try_send(fwd);
                            }
                        }
                    }
                }
                Ok(None)
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
                            // One request per operator and per peer at a time, and one operator per
                            // peer unless the relay and the peer allow several (wsh #93). The
                            // answer is a ReverseReject, as the JS relay's.
                            if let Some(requester) = ctx.conn_id {
                                if let Err(reason) = self.bridges.write().await.begin_connect(
                                    requester,
                                    &ctx.fingerprint,
                                    target_conn_id,
                                    std::time::Instant::now(),
                                ) {
                                    return Ok(Some(Envelope {
                                        msg_type: MsgType::ReverseReject,
                                        payload: Payload::ReverseReject(ReverseRejectPayload {
                                            target_fingerprint: p.target_fingerprint.clone(),
                                            username: p.username.clone(),
                                            reason,
                                        }),
                                    }));
                                }
                            }
                            let fwd = Envelope {
                                msg_type: MsgType::ReverseConnect,
                                payload: Payload::ReverseConnect(ReverseConnectPayload {
                                    target_fingerprint: p.target_fingerprint.clone(),
                                    // The relay speaks for the operator: its authenticated login name,
                                    // not whatever the client wrote (wsh #117; the proof names it).
                                    username: ctx.username.clone(),
                                    from_fingerprint: ctx.fingerprint.clone(),
                                    // What the OPERATOR says it can do (#117), bounded; the
                                    // relay decides nothing by it and drops a claim it cannot bound.
                                    features: Self::bounded_features(p.features.as_deref(), 8, 64),
                                }),
                            };
                            if target_tx.try_send(fwd).is_err() {
                                warn!(target = %&p.target_fingerprint, "failed to forward ReverseConnect");
                                self.bridges
                                    .write()
                                    .await
                                    .answer(target_conn_id, false, false);
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

                // Authorization (clawser #48): EITHER a valid session token
                // OR check_session_access (owner or SessionGrant-ACL'd) is
                // sufficient -- neither is required on its own.
                //
                // Why not require the token, now that Open actually mints
                // one? Because check_session_access is already the
                // authoritative authorization check elsewhere in this file
                // (SessionListRequest, Detach, ...), and it's derived from
                // ctx.username -- only ever set via a real completed AUTH,
                // never client-supplied. A principal granted access via
                // SessionGrant has no way to ever obtain the session's
                // token (only the opener receives it, via OpenOk), so
                // requiring it here would leave ACL grants just as
                // unreachable as this whole message type was before this
                // fix -- the exact gap clawser #48 is about closing.
                //
                // Why accept the token as an alternative, rather than
                // dropping it entirely? It still means something: proof of
                // holding the specific credential minted for this session,
                // independent of check_session_access. That's useful for
                // e.g. the owner attaching from a brand-new connection
                // where nothing has established ctx.username yet as
                // matching the session's owner through some other means --
                // though in practice check_session_access already covers
                // that once AUTH completes, since ctx.username is set by
                // then. Kept mainly for symmetry with Resume and to avoid
                // a spurious failure mode: a client that *does* have a
                // valid token but ends up with a stale/wrong ACL state
                // isn't gratuitously blocked.
                //
                // A token that's present but fails verification does NOT
                // by itself reject the request -- it only fails to grant
                // access on its own. This matters because it means a
                // client bug that sends a garbage/stale token (the
                // original form of this exact issue: the JS/Rust clients
                // used to send the wrong, connection-level auth token)
                // can't accidentally block an otherwise-authorized
                // ACL/ownership attach.
                let token_ok = p
                    .token
                    .as_ref()
                    .is_some_and(|t| verify_token(&self.secret, &p.session_id, t).is_ok());
                let access_ok = self
                    .check_session_access(&p.session_id, &ctx.username)
                    .await;
                if !token_ok && !access_ok {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::Error,
                        payload: Payload::Error(ErrorPayload {
                            code: 2,
                            message: "not authorized to attach to this session".into(),
                        }),
                    }));
                }
                // The mode is normalised: only a read-only request is read-only.
                let mode = if matches!(
                    p.mode.to_ascii_lowercase().as_str(),
                    "readonly" | "read" | "view" | "ro"
                ) {
                    "readonly"
                } else {
                    "control"
                };
                self.attach_to_session(ctx, &p.session_id, mode, None).await
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
                match self
                    .sessions
                    .detach_session(&p.session_id, ctx.conn_id)
                    .await
                {
                    Ok(_) => {
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
                // Unlike Attach, Resume's token is required and
                // unconditionally verified (clawser #48) -- Resume is
                // specifically "the connection that was handed this exact
                // token, at Open time, is coming back", so demanding proof
                // of that precise credential is the entire point. A
                // principal who only has ACL/ownership access but never
                // held the token (e.g. someone else's SessionGrant
                // grantee) should use Attach instead, not Resume.
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
                // `last_seq` is the cumulative number of output bytes the
                // client has received: only what follows it is replayed.
                self.attach_to_session(ctx, &p.session_id, "control", Some(p.last_seq))
                    .await
            }

            // ── Channel management ──────────────────────────────────
            (MsgType::Open, Payload::Open(p)) => {
                // wsh #121: this server has no execution targets (it never advertises `targets`),
                // so a channel that names one is refused rather than run on the server itself.
                if p.target.is_some() {
                    return Ok(Some(Envelope {
                        msg_type: MsgType::OpenFail,
                        payload: Payload::OpenFail(OpenFailPayload {
                            reason: "this host has no targets".into(),
                        }),
                    }));
                }
                let cols = p.cols.unwrap_or(80);
                let rows = p.rows.unwrap_or(24);
                // The key's authorized_keys options (wsh #122), the same table as the Node host's.
                let permissions = self.key_permissions(&ctx.fingerprint);
                let request = match p.kind {
                    ChannelKind::Pty => Some(KeyRequest::OpenPty),
                    ChannelKind::Exec => Some(KeyRequest::OpenExec),
                    ChannelKind::File => Some(KeyRequest::OpenFile {
                        upload: !p
                            .command
                            .as_deref()
                            .is_some_and(|c| c.starts_with("download:")),
                    }),
                    // Any other kind is not this key's business: a key tied to one command gets nothing else.
                    _ if permissions.forced_command.is_some() => Some(KeyRequest::OpenRpc("")),
                    _ => None,
                };
                if let Some(request) = request {
                    let active_for_key = if permissions.max_sessions.is_some() {
                        self.sessions.count_for_fingerprint(&ctx.fingerprint).await
                    } else {
                        0
                    };
                    if let Err(refusal) = permissions.check(request, active_for_key) {
                        warn!(
                            fingerprint = %&ctx.fingerprint[..8.min(ctx.fingerprint.len())],
                            code = refusal.code,
                            "open refused by the key's options"
                        );
                        return Ok(Some(Envelope {
                            msg_type: MsgType::OpenFail,
                            payload: Payload::OpenFail(OpenFailPayload {
                                reason: refusal.reason,
                            }),
                        }));
                    }
                }

                let pipes = match p.stdio.as_deref() {
                    None | Some("pty") => false,
                    Some("pipes") if p.kind == ChannelKind::Exec => true,
                    Some(other) => {
                        return Ok(Some(Envelope {
                            msg_type: MsgType::OpenFail,
                            payload: Payload::OpenFail(OpenFailPayload {
                                reason: format!(
                                    "unsupported stdio {other:?} for this channel kind (only exec accepts \"pipes\")"
                                ),
                            }),
                        }));
                    }
                };

                match p.kind {
                    ChannelKind::Pty | ChannelKind::Exec => {
                        let effective_command_owned = permissions
                            .forced_command
                            .clone()
                            .or_else(|| p.command.clone());
                        // Only the variables this server's `client_env` policy
                        // accepts (TERM, LANG, LC_* ... by default; wsh #126).
                        let accepted_env = self.config.client_env.filter(p.env.as_ref());
                        match self
                            .sessions
                            .create(
                                ctx.username.clone(),
                                ctx.fingerprint.clone(),
                                permissions,
                                effective_command_owned.as_deref(),
                                cols,
                                rows,
                                accepted_env.as_ref(),
                                self.recording_dir.as_deref(),
                                pipes,
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

                                // wsh #22 PR 3 of 3's decision (recorded on the
                                // issue) is to switch `exec` channels to
                                // `data_mode: Stream` in *both* of clawser's wsh
                                // servers. This server intentionally still declares
                                // `Virtual` for every kind, including `exec` --
                                // tried the literal flip first and reverted it after
                                // the real end-to-end test suite (tools/test/
                                // wsh-rust-server.test.mjs) caught a genuine hang:
                                // `WshSession.close()` (dataMode: 'stream') awaits
                                // its background read pump finishing, which only
                                // happens once the *server* sends data or a FIN on
                                // the client-initiated data stream -- but neither
                                // this server's WebSocket transport (only ever
                                // reads/writes FRAME_CONTROL frames) nor its
                                // WebTransport transport (handle_webtransport()
                                // only accepts a single bidirectional stream, for
                                // control) ever touches that stream. Every test that
                                // closes a still-running exec session (e.g.
                                // session management / Attach-Resume, which call
                                // `session.close()` on a `sleep 5` session instead
                                // of waiting for natural exit) hung forever. Output
                                // delivery for `exec` still works fine as SessionData
                                // control messages below (@johnhenry/wsh's WshSession
                                // delivers those to onData regardless of the
                                // session's declared data_mode) -- it's specifically
                                // *declaring* `Stream` without a real second
                                // multiplexed stream behind it that's unsafe here.
                                // Standing up a real per-transport data stream (the
                                // way tools/wsh-server.mjs's #bindDataStream does)
                                // is necessary follow-up work before this server can
                                // make the same switch -- tracked separately, out of
                                // scope for wsh #22 PR 3, whose actual live caller
                                // is tools/wsh-server.mjs.
                                let data_mode = SessionDataMode::Virtual;

                                // Pipes sessions carry stderr on a second channel
                                // id, announced in OpenOk.
                                let stderr_channel_id = if pipes {
                                    let id = self.next_channel_id.fetch_add(1, Ordering::Relaxed);
                                    let opener = channel_id;
                                    let _ = self
                                        .sessions
                                        .with_session_mut(&session_id, |s| {
                                            s.stderr_route = Some((opener, id));
                                            Ok(())
                                        })
                                        .await;
                                    Some(id)
                                } else {
                                    None
                                };

                                // Mint the session-scoped HMAC token here, at the
                                // only point a PTY/exec session_id actually comes
                                // into existence (clawser #48: previously no code
                                // path ever minted one, so Attach/Resume's
                                // verify_token check could never succeed for any
                                // caller). Returned only to the opener via OpenOk
                                // -- see Attach/Resume's handlers below for how
                                // each uses it.
                                let session_token = wsh_core::create_token(
                                    &self.secret,
                                    &session_id,
                                    self.config.session_ttl,
                                );

                                // The opener is the session's first attachment.
                                // OpenOk goes through the attachment's own ordered
                                // queue so no output can overtake it, and the
                                // pump starts only once the attachment exists
                                // (the opener sees the output from byte 0). The
                                // pump belongs to the session, not this
                                // connection (see `spawn_pty_output_pump`).
                                let (att_tx, att_rx) = mpsc::unbounded_channel();
                                let _ = att_tx.send(Envelope {
                                    msg_type: MsgType::OpenOk,
                                    payload: Payload::OpenOk(OpenOkPayload {
                                        channel_id,
                                        stream_ids: vec![],
                                        data_mode,
                                        capabilities: if pipes {
                                            vec!["stdin-eof".to_string()]
                                        } else {
                                            vec![]
                                        },
                                        session_id: Some(session_id.clone()),
                                        token: Some(session_token),
                                        stderr_channel_id,
                                    }),
                                });
                                if let Err(e) = self
                                    .sessions
                                    .add_attachment(
                                        &session_id,
                                        Attachment {
                                            conn_id: ctx.conn_id,
                                            channel_id,
                                            mode: "control".into(),
                                            username: ctx.username.clone(),
                                            tx: att_tx,
                                        },
                                    )
                                    .await
                                {
                                    return Ok(Some(Envelope {
                                        msg_type: MsgType::OpenFail,
                                        payload: Payload::OpenFail(OpenFailPayload {
                                            reason: e.to_string(),
                                        }),
                                    }));
                                }
                                Self::spawn_attachment_forwarder(att_rx, ctx.peer_tx.clone());
                                if pipes {
                                    self.spawn_pipe_output_pump(session_id.clone());
                                } else {
                                    self.spawn_pty_output_pump(session_id.clone());
                                }
                                Ok(None)
                            }
                            Err(e) => Ok(Some(Envelope {
                                msg_type: MsgType::OpenFail,
                                payload: Payload::OpenFail(OpenFailPayload {
                                    reason: e.to_string(),
                                }),
                            })),
                        }
                    }
                    ChannelKind::File => {
                        let channel_id = self.next_channel_id.fetch_add(1, Ordering::Relaxed);
                        let command = p.command.clone().unwrap_or_default();
                        let Some((op, path)) = command.split_once(':') else {
                            return Ok(Some(Envelope {
                                msg_type: MsgType::OpenFail,
                                payload: Payload::OpenFail(OpenFailPayload {
                                    reason: format!(
                                        "malformed file command {command:?} (expected \"upload:<path>\" or \"download:<path>\")"
                                    ),
                                }),
                            }));
                        };
                        let path = path.to_string();

                        match op {
                            "upload" => match tokio::fs::File::create(&path).await {
                                Ok(file) => {
                                    self.file_uploads.write().await.insert(
                                        channel_id,
                                        FileUploadState {
                                            file,
                                            path: PathBuf::from(&path),
                                        },
                                    );
                                    info!(channel_id, path = %path, "file upload channel opened");
                                    Ok(Some(Envelope {
                                        msg_type: MsgType::OpenOk,
                                        payload: Payload::OpenOk(OpenOkPayload {
                                            channel_id,
                                            stream_ids: vec![],
                                            data_mode: SessionDataMode::Virtual,
                                            capabilities: vec![],
                                            // File channels have no Attach/Resume-able
                                            // session -- session_id/token are pty/exec-only.
                                            session_id: None,
                                            token: None,
                                            stderr_channel_id: None,
                                        }),
                                    }))
                                }
                                Err(e) => Ok(Some(Envelope {
                                    msg_type: MsgType::OpenFail,
                                    payload: Payload::OpenFail(OpenFailPayload {
                                        reason: format!("cannot open {path:?} for writing: {e}"),
                                    }),
                                })),
                            },
                            "download" => match tokio::fs::metadata(&path).await {
                                Ok(meta) if meta.is_file() => {
                                    info!(channel_id, path = %path, size = meta.len(), "file download channel opened");
                                    self.spawn_file_download(
                                        channel_id,
                                        path,
                                        meta.len(),
                                        ctx.peer_tx.clone(),
                                    );
                                    Ok(Some(Envelope {
                                        msg_type: MsgType::OpenOk,
                                        payload: Payload::OpenOk(OpenOkPayload {
                                            channel_id,
                                            stream_ids: vec![],
                                            data_mode: SessionDataMode::Virtual,
                                            capabilities: vec![],
                                            session_id: None,
                                            token: None,
                                            stderr_channel_id: None,
                                        }),
                                    }))
                                }
                                Ok(_) => Ok(Some(Envelope {
                                    msg_type: MsgType::OpenFail,
                                    payload: Payload::OpenFail(OpenFailPayload {
                                        reason: format!("{path:?} is not a regular file"),
                                    }),
                                })),
                                Err(e) => Ok(Some(Envelope {
                                    msg_type: MsgType::OpenFail,
                                    payload: Payload::OpenFail(OpenFailPayload {
                                        reason: format!("cannot open {path:?}: {e}"),
                                    }),
                                })),
                            },
                            _ => Ok(Some(Envelope {
                                msg_type: MsgType::OpenFail,
                                payload: Payload::OpenFail(OpenFailPayload {
                                    reason: format!("unsupported file command: {op:?}"),
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
                // Delivered to the channel's process group, like ^C or `kill -INT -pgid`:
                // only by a control attachment of this connection (a viewer cannot),
                // and only the job-control names `session::signals` knows.
                let target_session = {
                    let ch_map = self.channel_sessions.read().await;
                    ch_map.get(&p.channel_id).cloned()
                };
                if let Some(sid) = target_session {
                    if !self
                        .sessions
                        .may_write(&sid, ctx.conn_id, p.channel_id)
                        .await
                    {
                        warn!(channel_id = p.channel_id, session_id = %sid, "Signal refused: not a control attachment of this connection");
                        return Ok(None);
                    }
                    self.sessions.touch(&sid).await;
                    let name = p.signal.clone();
                    match self
                        .sessions
                        .with_session(&sid, |session| Ok(session.io.signal(&name)))
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(channel_id = p.channel_id, signal = %p.signal, "Signal not delivered (unknown name or the process is gone)")
                        }
                        Err(e) => {
                            warn!(channel_id = p.channel_id, error = %e, "Signal: session lookup failed")
                        }
                    }
                } else {
                    warn!(channel_id = p.channel_id, "Signal for unknown channel");
                }
                Ok(None)
            }
            (MsgType::SessionData, Payload::SessionData(p)) => {
                // Client stdin for a direct-host (non-relay) session in "virtual"
                // data mode: write straight to the PTY. (Relay-forwarded
                // SessionData for reverse/peer sessions is handled earlier in
                // dispatch_message, before this match, via is_relay_forwardable.)
                let target_session = {
                    let ch_map = self.channel_sessions.read().await;
                    ch_map.get(&p.channel_id).cloned()
                };
                if let Some(sid) = target_session {
                    // Only a control attachment of THIS connection writes to the
                    // session (a read-only viewer, or a channel id that belongs to
                    // another connection, does not).
                    if !self
                        .sessions
                        .may_write(&sid, ctx.conn_id, p.channel_id)
                        .await
                    {
                        warn!(channel_id = p.channel_id, session_id = %sid, "SessionData refused: not a control attachment of this connection");
                        return Ok(None);
                    }
                    self.sessions.touch(&sid).await;
                    let data = p.data.clone();
                    if let Err(e) = self
                        .sessions
                        .with_session(&sid, |session| session.io.write_input(&data))
                        .await
                    {
                        warn!(channel_id = p.channel_id, session_id = %sid, error = %e, "PTY write failed");
                    }
                } else {
                    warn!(channel_id = p.channel_id, "SessionData for unknown channel");
                }
                Ok(None)
            }
            (MsgType::Close, Payload::Close(p)) => {
                // File-kind channels aren't PTY/exec sessions and never
                // appear in channel_sessions, so without this check they'd
                // fall through to the session-detach path below and
                // (since target_session would be None) incorrectly detach
                // ctx.session_id -- this connection's own top-level session.
                if self
                    .file_uploads
                    .write()
                    .await
                    .remove(&p.channel_id)
                    .is_some()
                {
                    debug!(
                        channel_id = p.channel_id,
                        "file upload channel closed by client"
                    );
                    return Ok(None);
                }

                // Look up the session for this channel_id
                let target_session = {
                    let ch_map = self.channel_sessions.read().await;
                    ch_map.get(&p.channel_id).cloned()
                };
                let sid = target_session.as_deref().unwrap_or(&ctx.session_id);
                debug!(channel_id = p.channel_id, session_id = %sid, "close request");
                // Detach from the correct session and clean up channel mapping
                if let Err(e) = self
                    .sessions
                    .detach_channel(sid, ctx.conn_id, p.channel_id)
                    .await
                {
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
                // wsh #122: a key without MCP sees no tools, as it would on a server that has none.
                let permissions = self.key_permissions(&ctx.fingerprint);
                let permitted = permissions.check(KeyRequest::Mcp, 0).is_ok();
                let bridge = self.mcp_bridge.read().await;
                let mut tools = if permitted {
                    bridge.list_tools()
                } else {
                    vec![]
                };
                let proxy = self.mcp_proxy.read().await;
                if permitted {
                    tools.extend(proxy.list_tools());
                    // A key with `mcp:<tool>` capabilities is told only of those tools.
                    tools.retain(|t| permissions.check(KeyRequest::McpTool(&t.name), 0).is_ok());
                }
                Ok(Some(Envelope {
                    msg_type: MsgType::McpTools,
                    payload: Payload::McpTools(McpToolsPayload { tools }),
                }))
            }
            (MsgType::McpCall, Payload::McpCall(p)) => {
                if let Err(refusal) = self
                    .key_permissions(&ctx.fingerprint)
                    .check(KeyRequest::McpCall(&p.tool), 0)
                {
                    warn!(
                        fingerprint = %&ctx.fingerprint[..8.min(ctx.fingerprint.len())],
                        code = refusal.code,
                        "MCP call refused by the key's options"
                    );
                    return Ok(Some(Envelope {
                        msg_type: MsgType::McpResult,
                        payload: Payload::McpResult(McpResultPayload {
                            call_id: p.call_id.clone(),
                            result: serde_json::json!({ "success": false, "error": refusal.reason }),
                        }),
                    }));
                }
                let bridge = self.mcp_bridge.clone();
                let proxy = self.mcp_proxy.clone();
                let call = p.clone();
                let run = async move {
                    // Try bridge first, then proxy
                    let bridge = bridge.read().await;
                    if bridge.has_tool(&call.tool) {
                        bridge.call(&call).await
                    } else {
                        drop(bridge);
                        proxy.read().await.call(&call).await
                    }
                };
                match &p.call_id {
                    // A correlated call runs as its own task: the message loop is not
                    // held up, and McpCancel can reach it. The reply goes out through
                    // the connection's peer channel when the task finishes.
                    Some(id) => {
                        ctx.mcp_calls.spawn(id.clone(), ctx.peer_tx.clone(), run);
                        Ok(None)
                    }
                    // No call_id: nothing could address it, and a client that sends none
                    // has no way to tell replies apart, so keep the in-order inline reply.
                    None => Ok(Some(Envelope {
                        msg_type: MsgType::McpResult,
                        payload: Payload::McpResult(run.await),
                    })),
                }
            }
            (MsgType::McpCancel, Payload::McpCancel(p)) => Ok(ctx.mcp_calls.cancel(&p.call_id)),

            // ── Gateway messages ────────────────────────────────────
            // One session per connection (see `gateway::session`): the work runs in its own tasks
            // and the answers go out through the connection's outbound queue, so nothing here
            // waits on a connect.
            (msg_type, _) if GatewaySession::serves(*msg_type) => {
                if let Some(refusal) = self.gateway_key_refusal(&ctx.fingerprint, &envelope) {
                    return Ok(Some(refusal));
                }
                ctx.gateway.handle(envelope.clone());
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
                        let Some(old) = session.io.as_pty() else {
                            return Err(wsh_core::WshError::Other(
                                "cannot restart a pipes (non-PTY) exec session".into(),
                            ));
                        };
                        let _ = old.kill();
                        // Get current size
                        let (cols, rows) = old.size();
                        // Spawn new PTY with same size
                        let new_pty = crate::session::pty::PtyHandle::spawn(
                            p.command.as_deref(),
                            cols,
                            rows,
                            None,
                        )?;
                        session.io = crate::session::pipes::SessionIo::Pty(new_pty);
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
                        // Attach the guest like any other attachment: it gets its
                        // own channel, the retained output and the live stream,
                        // read-only unless the invite granted "control".
                        let mode = if permissions.contains(&"control".to_string()) {
                            "control"
                        } else {
                            "readonly"
                        };
                        info!(session_id = %session_id, mode, "guest joined session");
                        self.attach_to_session(ctx, &session_id, mode, None).await
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
                            channel_id: None,
                            seq: None,
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
                //
                // Forward the whole payload verbatim (not field-by-field) so this
                // opaque relay doesn't silently drop fields it doesn't know about
                // -- it previously reconstructed KeyExchangePayload by hand with
                // only {session_id, algorithm, public_key}, which meant the hybrid
                // X25519+ML-KEM-768 fields (kem_public_key/kem_ciphertext, wsh #18)
                // got silently dropped in transit, degrading two JS clients'
                // relayed hybrid E2E exchange to classical-only without either
                // side knowing.
                let fwd = Envelope {
                    msg_type: MsgType::KeyExchange,
                    payload: Payload::KeyExchange(p.clone()),
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
                        channel_id: p.channel_id,
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

            // ── Execution targets (wsh #121): this server has none ─────
            (MsgType::ListTargets, Payload::ListTargets(_)) => Ok(Some(Envelope {
                msg_type: MsgType::Error,
                payload: Payload::Error(ErrorPayload {
                    code: 3,
                    message: "this host has no targets".into(),
                }),
            })),

            // ── Structured file channel ────────────────────────────
            (MsgType::FileOp, Payload::FileOp(p)) => {
                debug!(channel_id = p.channel_id, op = %p.op, path = %p.path, "file op");

                // FileOp travels as a bare message with no Open/OpenOk step
                // (unlike upload/download, which go through
                // Open{kind:File, ...} and are scope-checked above at the
                // "Check file transfer scope" block). Without an equivalent
                // check here, "list"/"remove" would bypass per-key
                // SessionScope::FileTransfer authorization entirely --
                // confirmed exploitable: an exec-only key (`restrict,permit-exec`,
                // no FileTransfer scope) could still `list()` real directory
                // entries. Mirror the Open<File> check exactly so both paths
                // enforce the same scope the same way.
                let permissions = self.key_permissions(&ctx.fingerprint);

                let result_payload = if p.target.is_some() {
                    // wsh #121: this server has no execution targets (it never advertises
                    // `targets`). A request that names one is refused, never answered from the
                    // server's own files.
                    FileResultPayload {
                        channel_id: p.channel_id,
                        success: false,
                        metadata: serde_json::Value::Object(Default::default()),
                        entries: vec![],
                        error_message: Some("this host has no targets".to_string()),
                    }
                } else if let Err(refusal) = permissions.check(KeyRequest::FileOp(&p.op), 0) {
                    // Named refusal identifying the missing "fs" capability
                    // (wsh #58: "an unauthorized fs capability must be
                    // reported as a named refusal, never rendered as an
                    // empty directory") -- never an empty Ok, and never a
                    // generic "not implemented" that would hide the real
                    // reason.
                    FileResultPayload {
                        channel_id: p.channel_id,
                        success: false,
                        metadata: serde_json::Value::Object(Default::default()),
                        entries: vec![],
                        error_message: Some(if refusal.code == "file-transfer-not-permitted" {
                            format!(
                                "file operation {:?} requires the \"fs\" capability, which this key does not have (file transfer not permitted for this key)",
                                p.op
                            )
                        } else {
                            refusal.reason
                        }),
                    }
                } else if p.op == "list" {
                    // wsh #59: "list" is now a real implementation (see
                    // handle_file_list above) instead of the unconditional
                    // stub refusal every op previously got. The remaining
                    // ops (stat, read, write, mkdir, remove, rename) are
                    // unchanged -- still refused with a named reason, not
                    // silently dropped or rendered as success. Note
                    // upload/download already work today, but via the
                    // dedicated FileChunk channel path
                    // (Open{kind:File, command:"upload:<path>"/"download:<path>"}
                    // above), not through FileOp at all.
                    self.handle_file_list(p.channel_id, &p.path).await
                } else {
                    FileResultPayload {
                        channel_id: p.channel_id,
                        success: false,
                        metadata: serde_json::Value::Object(Default::default()),
                        entries: vec![],
                        error_message: Some(format!(
                            "file operation {:?} not yet implemented",
                            p.op
                        )),
                    }
                };

                Ok(Some(Envelope {
                    msg_type: MsgType::FileResult,
                    payload: Payload::FileResult(result_payload),
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
                debug!(
                    channel_id = p.channel_id,
                    offset = p.offset,
                    len = p.data.len(),
                    is_final = p.is_final,
                    "file chunk"
                );

                let mut uploads = self.file_uploads.write().await;
                let Some(state) = uploads.get_mut(&p.channel_id) else {
                    // Not an error worth surfacing: a chunk for an upload
                    // that already finished/failed (or was never opened by
                    // this connection) is simply stale/misdirected.
                    return Ok(None);
                };

                let write_result = async {
                    state.file.seek(std::io::SeekFrom::Start(p.offset)).await?;
                    state.file.write_all(&p.data).await?;
                    if p.is_final {
                        state.file.flush().await?;
                    }
                    Ok::<(), std::io::Error>(())
                }
                .await;

                if write_result.is_err() || p.is_final {
                    let channel_id = p.channel_id;
                    let path = state.path.clone();
                    let ok = write_result.is_ok();
                    uploads.remove(&channel_id);
                    drop(uploads);

                    if let Err(e) = write_result {
                        warn!(channel_id, path = ?path, error = %e, "file upload: write failed");
                    } else {
                        info!(channel_id, path = ?path, "file upload complete");
                    }

                    let _ = ctx
                        .peer_tx
                        .send(Envelope {
                            msg_type: MsgType::Exit,
                            payload: Payload::Exit(ExitPayload {
                                channel_id,
                                code: if ok { 0 } else { 1 },
                            }),
                        })
                        .await;
                    let _ = ctx
                        .peer_tx
                        .send(Envelope {
                            msg_type: MsgType::Close,
                            payload: Payload::Close(ClosePayload { channel_id }),
                        })
                        .await;
                }

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

            // ── Authorized-key management (wsh #59) ─────────────────
            (MsgType::AuthorizedKeyAdd, Payload::AuthorizedKeyAdd(p)) => {
                // wsh #122: the key installed has no options, so only a key that is not restricted may install one.
                let result = if let Err(refusal) = self
                    .key_permissions(&ctx.fingerprint)
                    .check(KeyRequest::KeyAdmin, 0)
                {
                    warn!(
                        fingerprint = %&ctx.fingerprint[..8.min(ctx.fingerprint.len())],
                        code = refusal.code,
                        "AuthorizedKeyAdd refused by the key's options"
                    );
                    AuthorizedKeyResultPayload {
                        success: false,
                        added: false,
                        error_message: Some(refusal.reason),
                    }
                } else {
                    self.handle_authorized_key_add(&p).await
                };
                Ok(Some(Envelope {
                    msg_type: MsgType::AuthorizedKeyResult,
                    payload: Payload::AuthorizedKeyResult(result),
                }))
            }

            (MsgType::AuthorizedKeyResult, Payload::AuthorizedKeyResult(_)) => {
                // Server-to-client only; reject client-sent, same as FileResult above.
                Ok(Some(Envelope {
                    msg_type: MsgType::Error,
                    payload: Payload::Error(ErrorPayload {
                        code: 4,
                        message: "AuthorizedKeyResult is a server-to-client message".into(),
                    }),
                }))
            }

            // ── Unhandled ───────────────────────────────────────────
            (msg_type, _) => {
                debug!(?msg_type, "unhandled message type in session loop");
                Ok(None)
            }
        }
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

// ── #38 Phase 2: WISP reverse-connect end-to-end proof ──────────────────
//
// Unlike the demux-only unit tests in `relay::wisp`, this spins up the
// *real* `websocket::start_listener` (a live TCP/TLS socket) and the real
// `WshServer::handle_wisp_guest`/`handle_wisp_connect` handlers, then drives
// them with two independent `tokio-tungstenite` clients standing in for:
//
//   - a v86 guest's patched `wisp_network.js` (`FakeGuestWisp` below) —
//     reacts to `REVERSE_OPEN` by opening a real loopback TCP connection to
//     a stand-in "guest-local service" (mirroring what `fake_tcp_connect()`
//     really does inside v86: synthesize an inbound connection into the
//     guest's own TCP stack) and pumps bytes between that TCP connection
//     and WISP `DATA` frames tagged with the relay-assigned stream_id.
//   - an external `wsh connect <fingerprint>` client, dialing
//     `/wisp-connect/<fingerprint>` directly.
//
// The "guest-local service" is a minimal scripted echo-with-transform
// (not a full wsh-server) — reusing real wsh-server/QMux protocol code
// here would just be re-proving Phase 1's already-proven loopback exec
// path. What Phase 2 actually adds, and what this test exercises against
// real sockets end to end, is everything between the external client and
// that service: `/wisp-connect/` accept → `WispRegistry::get` →
// `REVERSE_OPEN` → the guest's `/wisp/` tunnel → the fake_tcp_connect
// stand-in → bytes flowing back the same path. A real v86 guest running
// the real (patched) wsh-server as that "guest-local service" is exactly
// what `tools/guest-image/boot-test.mjs` proves for Phase 1's loopback
// case; wiring an actual v86-in-Node boot into this same test is tracked
// as follow-up work (needs the Docker-built guest image + a self-hosted
// patched v86 bundle, both outside this crate).
#[cfg(test)]
mod wisp_reverse_connect_e2e_tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::Arc as StdArc;
    use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tokio_tungstenite::{connect_async_tls_with_config, Connector};

    /// Test-only cert verifier that accepts anything — mirrors
    /// `wsh-client`'s `NoOpServerCertVerifier` (see
    /// `crates/wsh-client/src/transport/websocket.rs`), duplicated here
    /// rather than shared so this stays confined to `#[cfg(test)]` and
    /// never touches a real connection path.
    #[derive(Debug)]
    struct NoOpVerifier {
        schemes: Vec<rustls::SignatureScheme>,
    }
    impl rustls::client::danger::ServerCertVerifier for NoOpVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.schemes.clone()
        }
    }

    fn insecure_test_connector() -> Connector {
        let provider = StdArc::new(rustls::crypto::ring::default_provider());
        let verifier = StdArc::new(NoOpVerifier {
            schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
        });
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("default protocol versions are valid")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Connector::Rustls(StdArc::new(config))
    }

    fn self_signed_tls_config() -> Arc<rustls::ServerConfig> {
        let mut params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
                .unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_der = cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        );

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("valid self-signed cert/key");
        Arc::new(config)
    }

    fn test_server_config(port: u16) -> ServerConfig {
        ServerConfig {
            port,
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
            max_sessions: 10,
            session_ttl: 3600,
            idle_timeout: 3600,
            enable_relay: true,
            relay_max_operators_per_peer: 1,
            allow_pubkey: true,
            allow_password: false,
            gateway_enabled: false,
            gateway_allowed_destinations: Vec::new(),
            gateway_max_connections: 10,
            gateway_enable_reverse_tunnels: false,
            gateway_reverse_bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            gateway_unix: Default::default(),
            gateway_max_buffered_bytes: crate::gateway::policy::DEFAULT_MAX_BUFFERED_BYTES,
            gateway_max_client_buffered_bytes:
                crate::gateway::policy::DEFAULT_MAX_CLIENT_BUFFERED_BYTES,
            password_hashes: std::collections::HashMap::new(),
            rpc_enabled: true,
            rpc_max_message_bytes: crate::rpc::RPC_DEFAULT_MAX_MESSAGE,
            rpc_max_inflight: 64,
            rpc_fs_root: None,
            rpc_fs_read_only: false,
            rpc_fs_max_file_bytes: 1024,
            mcp_tools: Vec::new(),
            client_env: crate::client_env::ClientEnvPolicy::default(),
            host_key_path: None,
            require_channel_binding: false,
            seal_session: crate::config::SealSession::Off,
        }
    }

    /// Simulates a v86 guest's *already-patched* `wisp_network.js`: reacts
    /// to `REVERSE_OPEN` by opening a real TCP connection to
    /// `guest_service_port` (standing in for `fake_tcp_connect()`) and
    /// bridges bytes between it and WISP `DATA`/`CLOSE` frames on the
    /// relay-assigned stream_id.
    async fn run_fake_guest(
        mut ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
        guest_service_port: u16,
    ) {
        use crate::relay::wisp::{decode_frame, encode_frame, WISP_DATA, WISP_REVERSE_OPEN};

        while let Some(msg) = ws.next().await {
            let Ok(WsMessage::Binary(bytes)) = msg else {
                continue;
            };
            let Some(frame) = decode_frame(&bytes) else {
                continue;
            };
            if frame.frame_type == WISP_REVERSE_OPEN {
                let stream_id = frame.stream_id;
                // Emulate fake_tcp_connect(): open a real TCP connection to
                // the "guest-local service".
                let mut svc = TcpStream::connect(("127.0.0.1", guest_service_port))
                    .await
                    .expect("guest-local service reachable");
                let (mut svc_rd, mut svc_wr) = svc.split();

                // Pump: WS -> service, service -> WS, until either side closes.
                let mut buf = [0u8; 4096];
                loop {
                    tokio::select! {
                        ws_msg = ws.next() => {
                            match ws_msg {
                                Some(Ok(WsMessage::Binary(b))) => {
                                    if let Some(f) = decode_frame(&b) {
                                        if f.frame_type == WISP_DATA && f.stream_id == stream_id {
                                            use tokio::io::AsyncWriteExt as _;
                                            if svc_wr.write_all(&f.payload).await.is_err() { break; }
                                        }
                                    }
                                }
                                _ => break,
                            }
                        }
                        n = { use tokio::io::AsyncReadExt as _; svc_rd.read(&mut buf) } => {
                            match n {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    let frame = encode_frame(WISP_DATA, stream_id, &buf[..n]);
                                    if ws.send(WsMessage::Binary(frame.into())).await.is_err() { break; }
                                }
                            }
                        }
                    }
                }
                let _ = svc.shutdown().await;
                return; // single reverse connection is enough to prove the path
            }
        }
    }

    /// A minimal scripted "guest-local service": reads one request, replies
    /// with a deterministic transform, proving real bidirectional bytes
    /// flowed through the whole REVERSE_OPEN bridge (not just one direction).
    async fn run_fake_guest_service(listener: TokioTcpListener) {
        if let Ok((mut sock, _)) = listener.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 4096];
            if let Ok(n) = sock.read(&mut buf).await {
                if n > 0 {
                    let mut reply = b"EXEC-OK:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    let _ = sock.write_all(&reply).await;
                }
            }
        }
    }

    #[tokio::test]
    async fn external_wsh_connect_reaches_guest_service_via_reverse_open() {
        // Normally installed once in `main()`; tests bypass main, so install
        // it here (harmless if another test in this binary already did).
        let _ = rustls::crypto::ring::default_provider().install_default();

        // 1. Real listener: routes /wisp/<fp> and /wisp-connect/<fp> exactly
        //    as production `WshServer::run` does.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tls_config = self_signed_tls_config();
        let tcp_probe = std::net::TcpListener::bind(addr).unwrap();
        let bound_addr = tcp_probe.local_addr().unwrap();
        drop(tcp_probe);

        let websocket::ListenerChannels {
            ws_rx: _ws_rx,
            mut wisp_guest_rx,
            mut wisp_connect_rx,
        } = websocket::start_listener(bound_addr, tls_config)
            .await
            .unwrap();

        let server = Arc::new(WshServer::new(test_server_config(bound_addr.port())).unwrap());
        {
            let server = server.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        Some(g) = wisp_guest_rx.recv() => {
                            let srv = server.clone();
                            tokio::spawn(async move { srv.handle_wisp_guest(g).await; });
                        }
                        Some(c) = wisp_connect_rx.recv() => {
                            let srv = server.clone();
                            tokio::spawn(async move { srv.handle_wisp_connect(c).await; });
                        }
                        else => break,
                    }
                }
            });
        }

        // 2. The "guest-local service" this fake guest will fake_tcp_connect to.
        let svc_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let svc_port = svc_listener.local_addr().unwrap().port();
        tokio::spawn(run_fake_guest_service(svc_listener));

        // 3. Fake guest dials its outbound WISP tunnel.
        let fingerprint = "e2e-guest-fingerprint";
        let (guest_ws, _) = connect_async_tls_with_config(
            format!("wss://127.0.0.1:{}/wisp/{fingerprint}", bound_addr.port()),
            None,
            false,
            Some(insecure_test_connector()),
        )
        .await
        .expect("fake guest connects");
        tokio::spawn(run_fake_guest(guest_ws, svc_port));

        // Give the guest tunnel a moment to register in WispRegistry.
        for _ in 0..50 {
            if server.wisp_registry().get(fingerprint).await.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            server.wisp_registry().get(fingerprint).await.is_some(),
            "guest tunnel never registered"
        );

        // 4. External `wsh connect <fingerprint>` client.
        let (mut client_ws, _) = connect_async_tls_with_config(
            format!(
                "wss://127.0.0.1:{}/wisp-connect/{fingerprint}?port={svc_port}",
                bound_addr.port()
            ),
            None,
            false,
            Some(insecure_test_connector()),
        )
        .await
        .expect("external client connects");

        client_ws
            .send(WsMessage::Binary(b"hello guest".to_vec().into()))
            .await
            .unwrap();

        let reply = tokio::time::timeout(std::time::Duration::from_secs(5), client_ws.next())
            .await
            .expect("reply within timeout")
            .expect("stream not closed")
            .expect("no ws error");

        let WsMessage::Binary(reply_bytes) = reply else {
            panic!("expected binary reply, got {reply:?}");
        };

        // Proves real bidirectional bytes flowed: external client ->
        // /wisp-connect -> REVERSE_OPEN -> guest's /wisp tunnel ->
        // fake_tcp_connect stand-in -> guest-local service -> back the
        // same path -> external client.
        assert_eq!(reply_bytes, b"EXEC-OK:hello guest");
    }
}
