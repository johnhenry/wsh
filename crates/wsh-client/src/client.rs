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
use crate::e2e::{combine_hybrid_secret, E2eKeyExchange, E2eOptions, ALGORITHM_HYBRID};
use crate::gateway::GatewayHub;
use crate::known_hosts::{HostStatus, KnownHosts};
use crate::seal_gate::SealGate;
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
    /// The `known_hosts` key (`host:port`) the host's fingerprint is recorded and checked
    /// under. `None`: the authority of the URL dialled. Set it when the URL is NOT the
    /// host's address -- a pipe relay (`wss://relay/r/<id>`) -- so the host is pinned by
    /// who it is, not by which relay carried the connection (the JS client's `hostLabel`).
    pub known_host: Option<String>,
    /// Refuse a host that proves no host key (wsh #145): without this a host that presents none is
    /// connected to with its identity unverified, as before. A host that advertises a key it
    /// cannot prove is always refused.
    pub require_host_key: bool,
    /// Pin the host to this key fingerprint (the hex SHA-256 of its Ed25519 key, as `known_hosts`
    /// records it): the host must PROVE that key, whatever `known_hosts` says, or the connection is
    /// refused before any credential is sent. A host that proves no key is refused too. `None`:
    /// only `known_hosts` decides. (`wsh mcp --host-key`.)
    pub expect_host_key: Option<String>,
    /// What to do the first time a PROVEN host key is seen (no `known_hosts` entry): see [`FirstUse`].
    /// A CHANGED key is always refused.
    pub first_use: FirstUse,
    /// `known_hosts` file; `None`: `~/.wsh/known_hosts`.
    pub known_hosts_path: Option<std::path::PathBuf>,
    /// Refuse to log in unless the signature is bound to this connection (wsh #119): the host
    /// must offer a binding kind this client can supply, or nothing is signed.
    pub require_channel_binding: bool,
    /// The SHA-256 of the WebTransport certificate this connection is pinned to (the JS client's
    /// `serverCertificateHashes`): the server's certificate must have exactly this hash, and no
    /// certificate authority is consulted. When the connection is pinned to exactly one
    /// certificate it is also the `cert-hash` channel-binding kind. The certificate must be an
    /// ECDSA P-256 one valid for at most 14 days (`wsh-server --generate-cert` makes one).
    /// `None` and `cert_hashes` empty: the certificate is validated against the system trust store.
    pub cert_hash: Option<[u8; 32]>,
    /// More certificate hashes to accept, for a rotation (the current and the next certificate),
    /// pinned together with `cert_hash`. Not a channel binding unless it is the only pin.
    pub cert_hashes: Vec<[u8; 32]>,
    /// Do NOT verify the WebTransport server's certificate at all. Development only: anyone on
    /// the path can be the server, and every connection prints a warning. Contradicts a pin, and
    /// is refused with a password login (a password cannot be sealed, so it would cross a channel
    /// whose other end is unverified). `wsh --insecure-skip-cert-verification`.
    pub insecure_skip_cert_verification: bool,
    /// Seal the whole session end to end (wsh #155): see [`SessionSeal`].
    pub seal_session: SessionSeal,
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
            known_host: None,
            require_host_key: false,
            expect_host_key: None,
            seal_session: SessionSeal::Auto,
            first_use: FirstUse::Refuse,
            known_hosts_path: None,
            require_channel_binding: false,
            cert_hash: None,
            cert_hashes: Vec::new(),
            insecure_skip_cert_verification: false,
            ping_interval_secs: 30,
            timeout_secs: 10,
        }
    }
}

impl ConnectConfig {
    /// How the WebTransport server's certificate is to be checked, or why this configuration is
    /// refused: the default validates it, pins are used when given, and skipping the check is only
    /// ever the explicit `insecure_skip_cert_verification`.
    pub fn cert_policy(&self) -> WshResult<transport::CertPolicy> {
        let pins: Vec<[u8; 32]> = self
            .cert_hash
            .iter()
            .chain(self.cert_hashes.iter())
            .copied()
            .collect();
        if self.insecure_skip_cert_verification {
            if !pins.is_empty() {
                return Err(WshError::Other(
                    "a certificate hash and --insecure-skip-cert-verification contradict each other: \
                     pin the certificate, or do not verify it, not both"
                        .into(),
                ));
            }
            if self.password.is_some() {
                return Err(WshError::Other(
                    "a password login is refused with --insecure-skip-cert-verification: a password cannot be \
                     sealed end to end, so it would be sent to whoever answers the unverified connection. \
                     Verify the certificate (system roots, or --cert-hash), or log in with a key"
                        .into(),
                ));
            }
            return Ok(transport::CertPolicy::InsecureSkipVerification);
        }
        Ok(if pins.is_empty() {
            transport::CertPolicy::SystemRoots
        } else {
            transport::CertPolicy::Pinned(pins)
        })
    }

    /// The certificate hash the login signature is bound to: the one pin, when there is exactly one.
    pub fn bound_cert_hash(&self) -> Option<[u8; 32]> {
        let mut all = self.cert_hash.iter().chain(self.cert_hashes.iter());
        match (all.next(), all.next()) {
            (Some(h), None) => Some(*h),
            _ => None,
        }
    }
}

/// What a client does the first time it sees a proven host key it has no `known_hosts` entry for.
/// The default refuses: a first use is a trust decision, and a person (or `--accept-new-host-key`)
/// makes it, as with OpenSSH `StrictHostKeyChecking`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FirstUse {
    /// Refuse with [`WshError::HostKeyUnknown`], which carries the fingerprint.
    #[default]
    Refuse,
    /// Record whatever key the host proves.
    Accept,
    /// Record the key only if its fingerprint is this one (what a person just confirmed).
    AcceptFingerprint(String),
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

/// SERVER_HELLO feature: the host runs `Open { stdio: "pipes" }` exec channels on
/// plain pipes (separate stderr, stdin EOF).
pub const EXEC_PIPES_FEATURE: &str = "exec-pipes";

/// SERVER_HELLO feature (wsh #121): the host has execution targets. `Open`, `FileOp` and
/// `OpenEndpoint` take an optional `target`, and `ListTargets` is answered with `TargetList`.
/// Negotiated rather than assumed: the Rust types deny unknown fields, so a host that predates the
/// field rejects an `Open` that carries it.
pub const TARGETS_FEATURE: &str = "targets";

/// How many channels may be waiting for their session at once.
const EARLY_MAX_CHANNELS: usize = 16;
/// Largest backlog kept per channel: messages, and payload bytes. A host that
/// answers `OpenOk` and streams at once has a few messages in flight, not megabytes;
/// the cap only bounds what an `OpenOk` nobody ever claims can hold.
const EARLY_MAX_MESSAGES: usize = 1024;
const EARLY_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Session messages that arrive between a channel's `OpenOk` and the moment
/// `open_session` has registered the session for it (#135).
///
/// The dispatch loop hands `OpenOk` to the waiting task and goes straight on to the
/// next frame. A host that answers at once sends that frame -- the first
/// `SessionData`, even the `Exit` -- in the same burst, so the loop can reach it
/// before the opener has run and inserted the session. Nothing was listening on that
/// channel id then, and the data was dropped (or sent to the relay channel). The
/// loop now notes the channel the moment it hands over its `OpenOk`
/// ([`reserve`](Self::reserve)); frames for a reserved channel are kept in arrival order
/// and replayed by `open_session` as it registers the session, under the same lock.
#[derive(Default)]
struct EarlyChannels {
    channels: HashMap<u32, EarlyBacklog>,
}

#[derive(Default)]
struct EarlyBacklog {
    messages: Vec<Envelope>,
    bytes: usize,
}

impl EarlyChannels {
    fn reserve(&mut self, channel_id: u32) {
        if self.channels.len() < EARLY_MAX_CHANNELS {
            self.channels.entry(channel_id).or_default();
        }
    }

    fn release(&mut self, channel_id: u32) -> Vec<Envelope> {
        self.channels
            .remove(&channel_id)
            .map(|b| b.messages)
            .unwrap_or_default()
    }

    /// Keep `envelope` if `channel_id` is reserved. Returns the envelope back when the
    /// channel is not waiting (the caller routes it as before) and `None` when kept
    /// or dropped for exceeding the cap.
    fn hold(&mut self, channel_id: u32, envelope: Envelope) -> Option<Envelope> {
        let Some(backlog) = self.channels.get_mut(&channel_id) else {
            return Some(envelope);
        };
        let size = match &envelope.payload {
            Payload::SessionData(p) => p.data.len(),
            Payload::FileChunk(p) => p.data.len(),
            Payload::EncryptedFrame(p) => p.ciphertext.len(),
            _ => 0,
        };
        if backlog.messages.len() >= EARLY_MAX_MESSAGES || backlog.bytes + size > EARLY_MAX_BYTES {
            tracing::warn!(
                channel_id,
                "dropping session message that arrived before its session was registered: backlog full"
            );
            return None;
        }
        backlog.bytes += size;
        backlog.messages.push(envelope);
        None
    }
}

type EarlyShared = Arc<Mutex<EarlyChannels>>;

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

/// Whether to seal a direct or pipe-relayed session end to end (wsh #155).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionSeal {
    /// Seal when the host says it serves nothing else (`e2e-session-required`); otherwise as before.
    #[default]
    Auto,
    /// Seal, or fail: a host that does not offer it is refused (no silent downgrade).
    Required,
    /// Never (a host that requires it will then serve nothing).
    Off,
}

/// Options of [`WshClient::reverse_connect_with`].
#[derive(Default, Clone, Copy)]
pub struct ReverseConnectOptions<'a> {
    /// The login key and username to answer a challenge with.
    pub operator: Option<(&'a ed25519_dalek::SigningKey, &'a str)>,
    /// Refuse the bridge unless the peer signed a challenge.
    pub require_peer_proof: bool,
    /// Seal the bridge (needs `operator` and a request that offers `operator-proof`).
    pub sealed: Option<SealOptions>,
}

/// How to seal a bridge.
#[derive(Clone, Copy)]
pub struct SealOptions {
    /// Offer X25519+ML-KEM-768 (the peer may still answer with classical X25519).
    pub hybrid: bool,
}

/// What [`WshClient::reverse_connect_with`] learned.
pub struct ReverseOutcome {
    /// The peer's `ReverseAccept` or `ReverseReject`.
    pub response: Envelope,
    /// The peer's challenge, verified: it proved it holds this key.
    pub peer_proven: Option<wsh_core::operator_proof::VerifiedChallenge>,
    /// Is the bridge sealed?
    pub sealed: bool,
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
    /// Session frames that beat their session's registration (see [`EarlyChannels`]).
    early: EarlyShared,
    /// The host key this connection's host proved (wsh #145), if it proved one.
    host_key: Option<crate::host_key::ProvenHostKey>,
    /// Whether this connection recorded the host key in `known_hosts` just now (first use).
    host_key_newly_pinned: bool,
    /// The channel-binding kinds the login signature covered.
    channel_binding_kinds: Vec<&'static str>,
    /// Connections and listeners opened through the host (see [`crate::gateway`]).
    gateway: Arc<GatewayHub>,
    /// Seals what crosses a sealed bridge (wsh #117, #145); off until a bridge is set up.
    seal: Arc<SealGate>,
    /// The key this connection logged in with (kept to sign the sealed-session key exchange).
    login_key: Option<ed25519_dalek::SigningKey>,
    /// Opens data streams without the transport lock (the dispatch loop holds it while it waits).
    stream_opener: Option<crate::transport::StreamOpener>,
}

/// Opens connections through the host and listens on it; cheap to clone, usable from any task.
/// Get one with [`WshClient::gateway`].
#[derive(Clone)]
pub struct GatewayHandle {
    hub: Arc<GatewayHub>,
    features: Arc<Mutex<Vec<String>>>,
}

impl GatewayHandle {
    async fn features(&self) -> Vec<String> {
        self.features.lock().await.clone()
    }

    /// Does the host offer `feature` (as listed in its `ServerHello`)?
    pub async fn has_feature(&self, feature: &str) -> bool {
        self.features.lock().await.iter().any(|f| f == feature)
    }

    /// Offer folders to the host (`wsh --share`, #159): sends the `ShareOffer` and answers the
    /// host's file requests with `provider` for the life of the connection. Needs the host's
    /// `shares` feature; an offer is made once.
    pub async fn offer_shares(
        &self,
        provider: std::sync::Arc<dyn crate::share::ShareProvider>,
        offer: wsh_core::messages::ShareOfferPayload,
    ) -> WshResult<()> {
        let features = self.features().await;
        self.hub.shares.offer(&features, provider, offer).await
    }

    /// Open a TCP connection FROM the host to `host:port` (needs the host's `gateway` feature
    /// and a destination its policy allows). `wsh -L [bind:]port:host:hostport`.
    pub async fn open_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> WshResult<crate::gateway::GatewayStream> {
        crate::gateway::require_feature(
            &self.features().await,
            crate::gateway::GATEWAY_FEATURE,
            "TCP forwarding",
        )?;
        let host = host.to_string();
        self.hub
            .open(move |id| crate::gateway::open_tcp_msg(id, &host, port))
            .await
    }

    /// Connect to a unix-domain socket on the HOST's file system (OpenSSH streamlocal). Needs the
    /// host's `gateway-unix` feature and a path its policy lists.
    pub async fn open_unix(&self, path: &str) -> WshResult<crate::gateway::GatewayStream> {
        crate::gateway::require_feature(
            &self.features().await,
            crate::gateway::GATEWAY_UNIX_FEATURE,
            "unix-socket forwarding",
        )?;
        let path = path.to_string();
        self.hub
            .open(move |id| crate::gateway::open_unix_msg(id, &path))
            .await
    }

    /// Open the host's NAMED endpoint: an in-process handler a host without a file system (an
    /// in-page host) registers instead of unix sockets. Needs `gateway-endpoints`.
    pub async fn open_endpoint(&self, name: &str) -> WshResult<crate::gateway::GatewayStream> {
        if !crate::gateway::valid_endpoint_name(name) {
            return Err(WshError::Other(format!(
                "{name:?} is not a valid endpoint name (letters, digits, \".\", \"_\", \"-\"; at most 64)"
            )));
        }
        crate::gateway::require_feature(
            &self.features().await,
            crate::gateway::GATEWAY_ENDPOINTS_FEATURE,
            "named endpoints",
        )?;
        let name = name.to_string();
        self.hub
            .open(move |id| crate::gateway::open_endpoint_msg(id, &name))
            .await
    }

    /// Ask the host to listen on a unix-domain socket at `path` on ITS file system and hand each
    /// connection to us (OpenSSH `-R /remote.sock:...`). `replace` asks to replace a stale socket
    /// file there; the host's policy decides whether that is allowed.
    pub async fn listen_unix(
        &self,
        path: &str,
        replace: bool,
    ) -> WshResult<crate::gateway::GatewayListener> {
        crate::gateway::require_feature(
            &self.features().await,
            crate::gateway::GATEWAY_UNIX_FEATURE,
            "unix-socket listening",
        )?;
        let path = path.to_string();
        self.hub
            .listen(move |id| crate::gateway::listen_unix_msg(id, &path, replace))
            .await
    }

    /// Ask the host to listen on a TCP port and hand each connection to us (`-R`). The host binds
    /// where its own configuration says, whatever `bind_addr` is; `port` 0 lets it choose.
    pub async fn listen_tcp(
        &self,
        port: u16,
        bind_addr: &str,
    ) -> WshResult<crate::gateway::GatewayListener> {
        crate::gateway::require_feature(
            &self.features().await,
            crate::gateway::GATEWAY_FEATURE,
            "TCP listening",
        )?;
        let bind_addr = bind_addr.to_string();
        self.hub
            .listen(move |id| crate::gateway::listen_tcp_msg(id, port, &bind_addr))
            .await
    }
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
        let known_host = match config.known_host.as_deref().filter(|h| !h.is_empty()) {
            Some(label) => label.to_string(),
            None => known_host_label(url)?,
        };
        let timeout = Duration::from_secs(config.timeout_secs);
        let cert_policy = config.cert_policy()?;

        // Auto-select and connect transport within the configured connection timeout.
        let transport =
            match time::timeout(timeout, transport::auto_connect_with(url, &cert_policy)).await {
                Ok(Ok(transport)) => transport,
                Ok(Err(err)) => return Err(err),
                Err(_) => return Err(WshError::Timeout),
            };
        let stream_opener = transport.stream_opener();
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
        let early: EarlyShared = Arc::new(Mutex::new(EarlyChannels::default()));
        let gateway = Arc::new(GatewayHub::new(outgoing_tx.clone()));
        let seal: Arc<SealGate> = Arc::default();

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
            gateway: gateway.clone(),
            seal: seal.clone(),
            login_key: None,
            early: early.clone(),
            host_key: None,
            host_key_newly_pinned: false,
            channel_binding_kinds: Vec::new(),
            stream_opener,
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
            let early = early.clone();
            let gateway = gateway.clone();
            let seal = seal.clone();

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
                    early,
                    gateway,
                    seal,
                )
                .await;
            })
        };
        client.dispatch_handle = Some(dispatch_handle);

        // A sealed session (#155): after login, before anything else is sent.
        let host_requires = client
            .server_features
            .lock()
            .await
            .iter()
            .any(|f| f == crate::seal_gate::SESSION_SEAL_REQUIRED_FEATURE);
        if config.seal_session == SessionSeal::Required
            || (config.seal_session == SessionSeal::Auto && host_requires)
        {
            if let Err(e) = client.seal_session(true, timeout).await {
                let _ = client.disconnect().await;
                return Err(e);
            }
        }

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
    /// The host key the host proved over this connection, if it proved one. `None`: the host
    /// presented no host-key proof, so its identity was NOT verified.
    pub fn host_key(&self) -> Option<&crate::host_key::ProvenHostKey> {
        self.host_key.as_ref()
    }

    /// Whether this connection recorded the proven host key in `known_hosts` (first use).
    pub fn host_key_newly_pinned(&self) -> bool {
        self.host_key_newly_pinned
    }

    /// The channel-binding kinds the login signature covered (`"host"`, `"cert-hash"`); empty when unbound.
    pub fn channel_binding(&self) -> &[&'static str] {
        &self.channel_binding_kinds
    }

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

    /// `ReverseConnect` with operator proof (wsh #117, #145): the peer may answer with a signed
    /// `ReverseChallenge` before it accepts; this verifies it (it names the peer asked for and
    /// THIS operator's fingerprint, so a relay that rewrote `from_fingerprint` shows) and
    /// answers with a `ReverseProof` signed by `operator`, which is also the login key.
    ///
    /// `request.features` should list `operator-proof` only when `operator` is given and the relay
    /// listed the feature in its `ServerHello`. Returns the peer's `ReverseAccept` or `ReverseReject`.
    pub async fn reverse_connect(
        &self,
        request: ReverseConnectPayload,
        operator: Option<(&ed25519_dalek::SigningKey, &str)>,
    ) -> WshResult<Envelope> {
        Ok(self
            .reverse_connect_with(
                request,
                ReverseConnectOptions {
                    operator,
                    ..Default::default()
                },
            )
            .await?
            .response)
    }

    /// [`reverse_connect`](Self::reverse_connect) that can also require the peer's proof and
    /// SEAL the bridge (wsh #117, #145): with `sealed`, a signed `KeyExchange` for the
    /// challenge's session id follows the accept, and from then on everything that would cross
    /// the relay travels as an `EncryptedFrame` on channel 0. Nothing that names a command, a
    /// path or a session is sent before the key exists (the gate is on from before the request
    /// leaves), and nothing plain is heard afterwards. The peer must have signed its challenge and
    /// state `e2e-sealed` in its `ReverseAccept`, else the call fails and nothing was sent.
    pub async fn reverse_connect_with(
        &self,
        request: ReverseConnectPayload,
        opts: ReverseConnectOptions<'_>,
    ) -> WshResult<ReverseOutcome> {
        let sealed = opts.sealed;
        let must_prove = sealed.is_some() || opts.require_peer_proof;
        let offers_proof = request.features.as_ref().is_some_and(|f| {
            f.iter()
                .any(|f| f == wsh_core::operator_proof::OPERATOR_PROOF_FEATURE)
        });
        if must_prove && (opts.operator.is_none() || !offers_proof) {
            return Err(WshError::Other(format!(
                "reverse_connect: {} needs operator proof offered (a key login, and a relay and peer that carry it) -- nothing was sent",
                if sealed.is_some() { "a sealed bridge" } else { "requiring the peer's proof" }
            )));
        }
        let target = request.target_fingerprint.clone();
        let (accept_rx, reject_rx, mut challenge_rx) = (
            self.register_waiter(MsgType::ReverseAccept).await,
            self.register_waiter(MsgType::ReverseReject).await,
            self.register_waiter(MsgType::ReverseChallenge).await,
        );
        if sealed.is_some() {
            // From before the request leaves: nothing but the key exchange may cross until the key exists.
            self.seal.begin(String::new(), true);
            self.seal.set_close_on_failure(true);
        }
        let result = self
            .reverse_connect_inner(
                request,
                &opts,
                &target,
                accept_rx,
                reject_rx,
                &mut challenge_rx,
            )
            .await;
        match &result {
            Ok(o) if o.sealed => {}
            _ => self.seal.end(),
        }
        result
    }

    async fn reverse_connect_inner(
        &self,
        request: ReverseConnectPayload,
        opts: &ReverseConnectOptions<'_>,
        target: &str,
        accept_rx: oneshot::Receiver<Envelope>,
        reject_rx: oneshot::Receiver<Envelope>,
        challenge_rx: &mut oneshot::Receiver<Envelope>,
    ) -> WshResult<ReverseOutcome> {
        self.send_control_message(Envelope {
            msg_type: MsgType::ReverseConnect,
            payload: Payload::ReverseConnect(request),
        })
        .await?;
        tokio::pin!(accept_rx, reject_rx);
        let deadline = time::sleep(Duration::from_secs(30));
        tokio::pin!(deadline);
        let mut answered = false;
        let mut verified: Option<wsh_core::operator_proof::VerifiedChallenge> = None;
        let response = loop {
            tokio::select! {
                r = &mut accept_rx => break r.map_err(|_| WshError::Transport("response channel dropped".into()))?,
                r = &mut reject_rx => {
                    let rejected = r.map_err(|_| WshError::Transport("response channel dropped".into()))?;
                    return Ok(ReverseOutcome { response: rejected, peer_proven: None, sealed: false });
                }
                challenge = &mut *challenge_rx, if !answered => {
                    answered = true;
                    let challenge = challenge.map_err(|_| WshError::Transport("response channel dropped".into()))?;
                    let (Some((key, username)), Payload::ReverseChallenge(msg)) = (opts.operator, &challenge.payload) else {
                        continue;
                    };
                    let own = wsh_core::fingerprint(&key.verifying_key().to_bytes());
                    let v = wsh_core::operator_proof::verify_challenge(msg, target, &own)?;
                    let proof = wsh_core::operator_proof::create_proof(key, &v, username);
                    if opts.sealed.is_some() {
                        // the bridge's session is the challenge's: only its key exchange may cross now
                        self.seal.begin(v.session_id.clone(), true);
                    }
                    verified = Some(v);
                    self.send_control_message(Envelope {
                        msg_type: MsgType::ReverseProof,
                        payload: Payload::ReverseProof(proof),
                    })
                    .await?;
                }
                _ = &mut deadline => return Err(WshError::Timeout),
            }
        };

        let Payload::ReverseAccept(accept) = &response.payload else {
            return Ok(ReverseOutcome {
                response,
                peer_proven: verified,
                sealed: false,
            });
        };
        if opts.require_peer_proof && verified.is_none() {
            return Err(WshError::AuthFailed(
                "reverse_connect: the peer did not prove its identity (require_peer_proof) -- nothing was sent over the bridge".into(),
            ));
        }
        if let Some(v) = &verified {
            if !accept.target_fingerprint.is_empty()
                && accept.target_fingerprint != v.peer_fingerprint
            {
                return Err(WshError::AuthFailed(
                    "reverse_connect: the relay named a different peer than the one that signed the challenge".into(),
                ));
            }
        }
        // Only RelayForward-wrapped messages from a peer this operator accepted are unwrapped.
        let peer = verified
            .as_ref()
            .map(|v| v.peer_fingerprint.clone())
            .unwrap_or_else(|| accept.target_fingerprint.clone());
        if !peer.is_empty() {
            self.trust_relay_peer(peer).await;
        }
        let Some(seal) = opts.sealed else {
            return Ok(ReverseOutcome {
                response,
                peer_proven: verified,
                sealed: false,
            });
        };
        let (Some(v), Some((key, _))) = (verified.clone(), opts.operator) else {
            return Err(WshError::AuthFailed(
                "reverse_connect: a sealed bridge needs the peer to answer with a challenge (does it support operator proof?)".into(),
            ));
        };
        let states_sealed = accept.features.as_ref().is_some_and(|f| {
            f.iter()
                .any(|f| f == wsh_core::operator_proof::E2E_SEALED_FEATURE)
        });
        if !states_sealed {
            return Err(WshError::AuthFailed(format!(
                "reverse_connect: the peer does not state \"{}\", so a sealed bridge is not available -- nothing was sent",
                wsh_core::operator_proof::E2E_SEALED_FEATURE
            )));
        }
        let algorithm = if seal.hybrid {
            ALGORITHM_HYBRID
        } else {
            crate::e2e::ALGORITHM_X25519
        };
        let exchanged = self
            .initiate_e2e_with(
                &v.session_id,
                algorithm,
                Duration::from_secs(10),
                E2eOptions {
                    verify_peer: Some(v.peer_public_key),
                    sign_as: Some(key),
                    responder_identity: Some(v.peer_public_key),
                },
            )
            .await?;
        self.seal.install(crate::bridge_seal::SealedBridge::new(
            exchanged.shared_secret,
            v.session_id.clone(),
            crate::e2e_frame::RoleTag::Initiator,
        ));
        Ok(ReverseOutcome {
            response,
            peer_proven: verified,
            sealed: true,
        })
    }

    /// Seal this whole connection end to end (wsh #155): a `KeyExchange` for the connection's
    /// session id, signed by this login key and by the host's PROVEN key, then every message but
    /// the keepalive -- gateway and endpoint data included -- travels as an `EncryptedFrame` on
    /// channel 0, so a relay that only copies bytes (a pipe relay) can neither read nor alter it,
    /// and a frame that does not open closes the connection. Needs a host that lists
    /// `e2e-session`, a host key it proved, and a key login; fails with a sentence, having sent
    /// nothing, otherwise.
    pub async fn seal_session(&self, hybrid: bool, timeout: Duration) -> WshResult<()> {
        let fail = |why: &str| {
            Err(WshError::AuthFailed(format!(
                "sealed session: {why} -- nothing was sent"
            )))
        };
        if !self
            .has_feature(crate::seal_gate::SESSION_SEAL_FEATURE)
            .await
        {
            return fail(&format!(
                "the host does not offer \"{}\" (it must have a host key and serve a connection without client-opened data streams)",
                crate::seal_gate::SESSION_SEAL_FEATURE
            ));
        }
        let Some(host_key) = self.host_key.as_ref() else {
            return fail("the host proved no host key to authenticate the exchange against");
        };
        let Some(login_key) = self.login_key.as_ref() else {
            return fail(
                "a sealed session needs a key login (a password login has nothing to sign with)",
            );
        };
        let Some(session_id) = self.session_id.clone() else {
            return fail("no session id");
        };
        self.seal.begin_session(session_id.clone());
        self.seal.set_close_on_failure(true);
        let algorithm = if hybrid {
            ALGORITHM_HYBRID
        } else {
            crate::e2e::ALGORITHM_X25519
        };
        let exchanged = self
            .initiate_e2e_with(
                &session_id,
                algorithm,
                timeout,
                E2eOptions {
                    verify_peer: Some(host_key.public_key),
                    sign_as: Some(login_key),
                    responder_identity: Some(host_key.public_key),
                },
            )
            .await;
        match exchanged {
            Ok(x) => {
                self.seal
                    .install(crate::bridge_seal::SealedBridge::with_scope(
                        x.shared_secret,
                        session_id,
                        crate::e2e_frame::RoleTag::Initiator,
                        crate::bridge_seal::Scope::Session,
                    ));
                Ok(())
            }
            Err(e) => {
                self.seal.end();
                Err(e)
            }
        }
    }

    /// Is this session sealed end to end (see [`seal_session`](Self::seal_session))?
    pub fn session_sealed(&self) -> bool {
        self.seal.is_sealed() && self.seal.scope() == Some(crate::bridge_seal::Scope::Session)
    }

    /// A bridge for `session_id` is being set up on this connection (the peer side of a sealed
    /// bridge; see [`reverse_connect_with`](Self::reverse_connect_with) for the operator side).
    /// With `must`, nothing but its key exchange crosses until [`install_bridge`](Self::install_bridge).
    pub fn begin_sealing(&self, session_id: String, must: bool) {
        self.seal.begin(session_id, must);
    }

    /// The peer side of a sealed bridge: answer the operator's signed `KeyExchange` for
    /// `session_id` with `responder` (inside the dispatch loop, so the key is in place before the
    /// next frame is read); `must`: nothing else crosses until then.
    pub fn begin_sealing_as_responder(
        &self,
        session_id: String,
        must: bool,
        responder: crate::e2e::E2eResponder,
    ) {
        self.seal.begin_responder(session_id, must, responder);
    }

    /// Resolves once a bridge set up with
    /// [`begin_sealing_as_responder`](Self::begin_sealing_as_responder) is sealed.
    pub async fn bridge_sealed_event(&self) {
        self.seal.wait_sealed().await;
    }

    /// The bridge key exists: from here everything crossing the relay is sealed.
    pub fn install_bridge(&self, bridge: crate::bridge_seal::SealedBridge) {
        self.seal.install(bridge);
    }

    /// The bridge is over: plain again.
    pub fn end_sealing(&self) {
        self.seal.end();
    }

    /// For a peer that serves several operators (wsh #93): deliver each relayed message on the
    /// relay-message channel still wrapped in the `RelayForward` the relay sent, so that its
    /// `from_fingerprint` says which operator wrote it. Off by default: the channel then carries
    /// the bare messages, as it always did.
    pub fn tag_relay_origin(&self, on: bool) {
        self.seal.set_tag_relay_origin(on);
    }

    /// Is the bridge on this connection sealed?
    pub fn bridge_sealed(&self) -> bool {
        self.seal.is_sealed()
    }

    /// Resolves once the sealed bridge failed: a frame did not open (forged, tampered with,
    /// replayed or reordered), so the relay is not honest and nothing crosses the bridge any
    /// more. On the operator side the connection is closed as well.
    pub async fn bridge_failed(&self) {
        self.seal.wait_failed().await;
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

    // ── Gateway: connections through the host ───────────────────────

    /// A handle for opening connections through the host (and listening on it), usable from
    /// other tasks while this client runs the session. It stops working when the client is
    /// dropped or disconnects.
    pub fn gateway(&self) -> GatewayHandle {
        GatewayHandle {
            hub: self.gateway.clone(),
            features: self.server_features.clone(),
        }
    }

    /// See [`GatewayHandle::open_tcp`].
    pub async fn open_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> WshResult<crate::gateway::GatewayStream> {
        self.gateway().open_tcp(host, port).await
    }

    /// See [`GatewayHandle::open_unix`].
    pub async fn open_unix(&self, path: &str) -> WshResult<crate::gateway::GatewayStream> {
        self.gateway().open_unix(path).await
    }

    /// See [`GatewayHandle::open_endpoint`].
    pub async fn open_endpoint(&self, name: &str) -> WshResult<crate::gateway::GatewayStream> {
        self.gateway().open_endpoint(name).await
    }

    /// See [`GatewayHandle::listen_unix`].
    pub async fn listen_unix(
        &self,
        path: &str,
        replace: bool,
    ) -> WshResult<crate::gateway::GatewayListener> {
        self.gateway().listen_unix(path, replace).await
    }

    /// See [`GatewayHandle::listen_tcp`].
    pub async fn listen_tcp(
        &self,
        port: u16,
        bind_addr: &str,
    ) -> WshResult<crate::gateway::GatewayListener> {
        self.gateway().listen_tcp(port, bind_addr).await
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
            stdio,
            target,
        } = opts;
        if target.is_some() && !self.has_feature(TARGETS_FEATURE).await {
            return Err(WshError::Other(format!(
                "this host does not advertise \"{TARGETS_FEATURE}\" (execution targets): it would run the \
                 request on its own default or reject the unknown field, so it was not sent"
            )));
        }

        // Build and send OPEN message
        let envelope = Envelope {
            msg_type: MsgType::Open,
            payload: Payload::Open(OpenPayload {
                kind: kind.clone(),
                command,
                cols,
                rows,
                env,
                stdio,
                target,
            }),
        };

        let response = self.send_and_wait(envelope, MsgType::OpenOk).await?;

        // Parse OPEN_OK response
        match response.payload {
            Payload::OpenOk(ok) => {
                // The dispatch loop reserved these channels when it handed us the
                // `OpenOk`; whatever the host sent after it is waiting in `early`.
                // Every way out of here must release them.
                let built = self.build_session(&ok, kind).await;
                let session = match built {
                    Ok(session) => session,
                    Err(err) => {
                        let mut early = self.early.lock().await;
                        early.release(ok.channel_id);
                        if let Some(stderr_id) = ok.stderr_channel_id {
                            early.release(stderr_id);
                        }
                        return Err(err);
                    }
                };

                self.register_session(&session, &ok).await;

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

    /// What the host's `ServerHello` says about typed rpc channels (wsh #85): whether it serves them, which
    /// protocols, and the largest message.
    pub async fn rpc_offer(&self) -> crate::rpc::RpcOffer {
        crate::rpc::RpcOffer::parse(&self.server_features.lock().await)
    }

    /// Open a typed rpc channel (wsh #85) speaking `protocol` (`mcp`, `wsh-fs`, `wsh-host`, or a host's own).
    ///
    /// Refuses, before sending anything, a protocol the host did not advertise (`rpc` and
    /// `rpc-protocol:<name>` in its `ServerHello.features`): an older host would not know the kind.
    /// Needs a transport that can open data streams (WebSocket, WebTransport).
    pub async fn open_rpc(&self, protocol: &str) -> WshResult<crate::rpc::RpcChannel> {
        self.open_rpc_with(protocol, false).await
    }

    /// [`open_rpc`](Self::open_rpc) for a protocol whose messages carry byte strings (`wsh-objects`): the channel's
    /// messages are read and written as CBOR values (`send_values` / `recv_values`) instead of JSON.
    pub async fn open_rpc_values(&self, protocol: &str) -> WshResult<crate::rpc::RpcChannel> {
        self.open_rpc_with(protocol, true).await
    }

    async fn open_rpc_with(
        &self,
        protocol: &str,
        values: bool,
    ) -> WshResult<crate::rpc::RpcChannel> {
        if !crate::rpc::valid_protocol_name(protocol) {
            return Err(WshError::Other(format!(
                "{protocol:?} is not a valid rpc protocol name"
            )));
        }
        let offer = self.rpc_offer().await;
        if !offer.offered() {
            return Err(WshError::Other(format!(
                "UNSUPPORTED_PROTOCOL: this host does not advertise \"{}\" channels (cannot open \"{protocol}\")",
                crate::rpc::RPC_FEATURE
            )));
        }
        if !offer.serves(protocol) {
            return Err(WshError::Other(format!(
                "UNSUPPORTED_PROTOCOL: this host does not advertise the \"{protocol}\" rpc protocol"
            )));
        }
        // The form follows what the host states: `rpc` is a data stream, `rpc-virtual` rides the control plane (wsh #191).
        let virtual_mode = offer.is_virtual();
        if !virtual_mode && self.session_sealed() {
            // A host that states stream-mode rpc on a sealed session would put the channel's bytes where no frame seals them.
            return Err(WshError::Other(
                "this host states stream-mode rpc, whose data stream a sealed session cannot seal: refusing to open it".into(),
            ));
        }
        let envelope = Envelope {
            msg_type: MsgType::Open,
            payload: Payload::Open(OpenPayload {
                kind: ChannelKind::Rpc,
                command: Some(protocol.to_string()),
                cols: None,
                rows: None,
                env: None,
                stdio: None,
                target: None,
            }),
        };
        let response = self.send_and_wait(envelope, MsgType::OpenOk).await?;
        let ok = match response.payload {
            Payload::OpenOk(ok) => ok,
            Payload::OpenFail(fail) => return Err(WshError::Channel(fail.reason)),
            _ => {
                return Err(WshError::InvalidMessage(
                    "unexpected response to OPEN".into(),
                ))
            }
        };
        if virtual_mode {
            if ok.data_mode != SessionDataMode::Virtual {
                self.early.lock().await.release(ok.channel_id);
                return Err(WshError::Channel(
                    "the host answered an rpc Open with a data mode other than virtual".into(),
                ));
            }
            // The channel stands in the session table; its SessionData and GatewayCredit go to the channel, and what it
            // writes leaves as SessionData (sealed with everything else on a sealed session).
            let stub = Arc::new(WshSession::new_virtual(
                ok.channel_id,
                ChannelKind::Rpc,
                self.control_action_tx.clone(),
                Vec::new(),
            ));
            let channel = crate::rpc::RpcChannel::start_virtual(
                offer.max_message_bytes,
                stub.clone(),
                self.control_action_tx.clone(),
                self.rpc_credit_sender(ok.channel_id),
                values,
            );
            self.register_session(&stub, &ok).await;
            return Ok(channel);
        }
        let opened = async {
            if ok.data_mode != SessionDataMode::Stream {
                return Err(WshError::Channel(
                    "the host answered an rpc Open with a data mode other than stream".into(),
                ));
            }
            // Not through the transport lock: the dispatch loop holds it while it waits for a control message.
            match &self.stream_opener {
                Some(opener) => opener.open().await,
                None => Err(WshError::Transport(
                    "this transport cannot open data streams".into(),
                )),
            }
        }
        .await;
        let stream = match opened {
            Ok(s) => s,
            Err(err) => {
                self.early.lock().await.release(ok.channel_id);
                return Err(err);
            }
        };
        // The channel stands in the session table (a virtual stand-in), so the host's `Close` for it
        // finds something and our own `close` can tell the host.
        let stub = Arc::new(WshSession::new_virtual(
            ok.channel_id,
            ChannelKind::Rpc,
            self.control_action_tx.clone(),
            Vec::new(),
        ));
        self.register_session(&stub, &ok).await;
        Ok(crate::rpc::RpcChannel::start(
            stream.stream,
            offer.max_message_bytes,
            stub,
            values,
        ))
    }

    /// Writes `GatewayCredit` for rpc channel `channel_id` (wsh #191): `bytes` of credit handed back to the host.
    fn rpc_credit_sender(&self, channel_id: u32) -> Box<dyn Fn(u64) + Send + Sync> {
        let tx = self.outgoing_tx.clone();
        Box::new(move |mut left| {
            while left > 0 {
                let part = left.min(u64::from(u32::MAX));
                left -= part;
                let envelope = Envelope {
                    msg_type: MsgType::GatewayCredit,
                    payload: Payload::GatewayCredit(GatewayCreditPayload {
                        gateway_id: wsh_core::rpc_credit::rpc_credit_id(channel_id),
                        bytes: part as u32,
                    }),
                };
                if let Ok(frame) = frame_encode(&envelope) {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(frame).await;
                    });
                }
            }
        })
    }

    /// Build the `WshSession` (and its stderr companion) an `OpenOk` describes.
    async fn build_session(
        &self,
        ok: &OpenOkPayload,
        kind: ChannelKind,
    ) -> WshResult<Arc<WshSession>> {
        let session = match ok.data_mode {
            SessionDataMode::Stream => {
                let stream = {
                    let mut t = self.transport.lock().await;
                    t.open_stream().await?
                };

                WshSession::new_stream(
                    ok.channel_id,
                    kind,
                    stream.stream,
                    self.control_action_tx.clone(),
                    ok.capabilities.clone(),
                )
                .with_session_credentials(ok.session_id.clone(), ok.token.clone())
            }
            SessionDataMode::Virtual => WshSession::new_virtual(
                ok.channel_id,
                kind,
                self.control_action_tx.clone(),
                ok.capabilities.clone(),
            )
            .with_session_credentials(ok.session_id.clone(), ok.token.clone()),
        };
        // `stdio: "pipes"`: stderr arrives as SessionData on its own channel id.
        let session = match ok.stderr_channel_id {
            Some(stderr_id) => session.with_stderr(Arc::new(WshSession::new_virtual(
                stderr_id,
                ChannelKind::Exec,
                self.control_action_tx.clone(),
                Vec::new(),
            ))),
            None => session,
        };
        Ok(Arc::new(session))
    }

    /// Make `session` routable and replay what arrived for it before it was.
    ///
    /// Holds `early` throughout (taken before `sessions`, as the dispatch loop does)
    /// so a frame is either replayed here, in arrival order, or delivered by the
    /// loop to the registered session -- never reordered, never lost.
    async fn register_session(&self, session: &Arc<WshSession>, ok: &OpenOkPayload) {
        let mut early = self.early.lock().await;
        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(ok.channel_id, session.clone());
            if let (Some(stderr_id), Some(stderr)) =
                (ok.stderr_channel_id, session.stderr_session())
            {
                sessions.insert(stderr_id, stderr);
            }
        }

        // stderr first: the main channel's Exit closes both, and the host sent stderr
        // before it (spec: OpenOk.stderr_channel_id).
        let mut closed = false;
        for channel_id in ok.stderr_channel_id.into_iter().chain([ok.channel_id]) {
            let target = if channel_id == ok.channel_id {
                Some(session.clone())
            } else {
                session.stderr_session()
            };
            let backlog = early.release(channel_id);
            if !backlog.is_empty() {
                tracing::debug!(
                    channel_id,
                    frames = backlog.len(),
                    "replaying frames that arrived before the session was registered"
                );
            }
            for envelope in backlog {
                if let Some(target) = &target {
                    if let Err(err) = target.handle_control(&envelope).await {
                        tracing::debug!(channel_id, "failed to route early session message: {err}");
                    }
                }
                if matches!(envelope.msg_type, MsgType::Close) {
                    closed = true;
                }
            }
        }
        if closed {
            self.sessions.lock().await.remove(&ok.channel_id);
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

    /// The execution targets this connection may use (wsh #121): what the host decides to show
    /// THIS key, in the host's order. Fails, without sending anything, against a host that did not
    /// advertise `targets`.
    pub async fn list_targets(&self) -> WshResult<Vec<TargetInfo>> {
        if !self.has_feature(TARGETS_FEATURE).await {
            return Err(WshError::Other(format!(
                "this host does not advertise \"{TARGETS_FEATURE}\" (execution targets)"
            )));
        }
        let response = self
            .send_and_wait(
                Envelope {
                    msg_type: MsgType::ListTargets,
                    payload: Payload::ListTargets(ListTargetsPayload {}),
                },
                MsgType::TargetList,
            )
            .await?;
        match response.payload {
            Payload::TargetList(list) => Ok(list.targets),
            other => Err(WshError::Other(format!(
                "unexpected reply to ListTargets: {other:?}"
            ))),
        }
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

    /// Install a raw 32-byte Ed25519 public key into the remote host's
    /// `~/.wsh/authorized_keys` (wsh #59).
    ///
    /// Replaces `wsh copy-id`'s previous approach of building and running a
    /// remote shell command (`crates/wsh-cli/src/commands/copy_id.rs`) --
    /// see that module's doc comment for the quoting hazard this avoids.
    /// Making this a real protocol message (rather than CLI-only) also
    /// makes key installation reachable from implementations with no shell
    /// channel to build a command string for, starting with the browser
    /// SDK (`WshClient.addAuthorizedKey` in `src/client.mjs`).
    ///
    /// Idempotent: installing an already-present key returns `Ok(false)`
    /// (not newly added) rather than duplicating the line or erroring.
    pub async fn add_authorized_key(
        &self,
        public_key_raw: &[u8],
        comment: Option<&str>,
    ) -> WshResult<bool> {
        let response = self
            .send_and_wait(
                Envelope {
                    msg_type: MsgType::AuthorizedKeyAdd,
                    payload: Payload::AuthorizedKeyAdd(AuthorizedKeyAddPayload {
                        public_key: public_key_raw.to_vec(),
                        comment: comment.map(str::to_string),
                    }),
                },
                MsgType::AuthorizedKeyResult,
            )
            .await?;

        match response.payload {
            Payload::AuthorizedKeyResult(r) if r.success => Ok(r.added),
            Payload::AuthorizedKeyResult(r) => Err(WshError::Channel(
                r.error_message
                    .unwrap_or_else(|| "key installation refused".into()),
            )),
            _ => Err(WshError::InvalidMessage(
                "unexpected response to AUTHORIZED_KEY_ADD".into(),
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
        self.initiate_e2e_with(session_id, algorithm, timeout, E2eOptions::default())
            .await
    }

    /// [`initiate_e2e`](Self::initiate_e2e) with both halves signed (wsh #117, #145):
    /// `verify_peer` is the peer's long-term Ed25519 key -- the exchange is refused unless the
    /// peer signed its half with it (a relay that swaps either ephemeral key cannot); `sign_as`
    /// signs this (initiator) half with the operator's key, naming the responder it means to
    /// reach (`responder_identity`, default `verify_peer`). The transcripts are those of
    /// `src/e2e-exchange.mjs` ([`wsh_core::e2e_exchange`]).
    pub async fn initiate_e2e_with(
        &self,
        session_id: &str,
        algorithm: &str,
        timeout: Duration,
        opts: E2eOptions<'_>,
    ) -> WshResult<E2eKeyExchange> {
        let want_hybrid = algorithm == ALGORITHM_HYBRID;

        // Register both waiters before ANY await: two peers establishing E2E at once, or a host
        // whose ML-KEM ciphertext follows its reply at once, send into a window in which a
        // message no waiter is listening for is routed elsewhere (wsh #33).
        let round1_rx = self.register_waiter(MsgType::KeyExchange).await;
        let round2_rx = if want_hybrid {
            Some(self.register_waiter(MsgType::KeyExchange).await)
        } else {
            None
        };

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

        // The initiator signs its half too when it has a signer and knows whom it is talking to.
        let signature = match opts.sign_as {
            Some(key) => {
                let responder = opts
                    .responder_identity
                    .or(opts.verify_peer)
                    .ok_or_else(|| {
                        WshError::Other(
                            "initiate_e2e: sign_as needs responder_identity or verify_peer".into(),
                        )
                    })?;
                Some(wsh_core::e2e_exchange::sign_initiator(
                    key,
                    session_id,
                    algorithm,
                    &local_public_bytes,
                    &responder,
                ))
            }
            None => None,
        };

        let round1 = Envelope {
            msg_type: MsgType::KeyExchange,
            payload: Payload::KeyExchange(KeyExchangePayload {
                algorithm: algorithm.to_string(),
                public_key: Some(local_public_bytes.clone()),
                session_id: session_id.to_string(),
                kem_public_key: local_kem_public_bytes,
                kem_ciphertext: None,
                signature,
            }),
        };
        self.send_control_message(round1).await?;
        let peer_round1 = Self::await_waiter(round1_rx, timeout).await?;
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

        let mut peer_authenticated = false;
        if let Some(identity) = opts.verify_peer {
            if !wsh_core::e2e_exchange::verify_key_exchange_signature(
                &identity,
                peer.signature.as_deref(),
                session_id,
                algorithm,
                &local_public_bytes,
                &peer_public_key,
            ) {
                return Err(WshError::AuthFailed(if peer.signature.is_none() {
                    "initiate_e2e: the peer did not sign its key exchange (verify_peer was given)"
                        .into()
                } else {
                    "initiate_e2e: the peer's key exchange signature does not verify against verify_peer"
                        .into()
                }));
            }
            peer_authenticated = true;
        }

        let peer_x25519_public = X25519PublicKey::from(peer_public_array);
        let x25519_shared = ephemeral_secret.diffie_hellman(&peer_x25519_public);
        let x25519_secret_bytes = *x25519_shared.as_bytes();

        let hybrid_active = want_hybrid && local_kem.is_some() && peer.kem_public_key.is_some();

        let shared_secret = if hybrid_active {
            let (local_dk, _local_ek) = local_kem.expect("checked by hybrid_active");
            let peer_kem_public_key = peer.kem_public_key.expect("checked by hybrid_active");

            // Lexicographic byte comparison: Rust's `Ord` on `&[u8]`
            // already compares elementwise then by length, matching the
            // JS `compareBytes` helper exactly.
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
                        signature: None,
                    }),
                };
                self.send_fire_and_forget(round2).await?;

                shared.as_slice().try_into().map_err(|_| {
                    WshError::Other("ML-KEM-768 shared secret was not 32 bytes".into())
                })?
            } else {
                let peer_round2 = Self::await_waiter(
                    round2_rx.expect("registered when hybrid was wanted"),
                    timeout,
                )
                .await?;
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
            peer_authenticated,
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

        // Send HELLO. The fresh nonce asks the host to prove its key over THIS connection
        // (`host_key`); a host that does not know the string ignores it.
        let host_key_nonce = crate::host_key::new_nonce();
        let hello = Envelope {
            msg_type: MsgType::Hello,
            payload: Payload::Hello(HelloPayload {
                version: PROTOCOL_VERSION.to_string(),
                username: config.username.clone(),
                features: vec![
                    format!("{}{host_key_nonce}", crate::host_key::HOST_KEY_NONCE_PREFIX),
                    "mcp".to_string(),
                    "file-transfer".to_string(),
                    // GatewayCredit flow control for connections opened through the host.
                    wsh_core::gateway_credit::GATEWAY_CREDIT_FEATURE.to_string(),
                ],
                auth_method: Some(auth_method.clone()),
            }),
        };
        self.send_raw(&hello).await?;

        // Receive SERVER_HELLO
        let server_hello_data = self.recv_raw().await?;
        let server_hello = decode_envelope(&server_hello_data)?;

        let (hello_session_id, server_fingerprints, host_fingerprint, advertised_features) =
            match &server_hello.payload {
                Payload::ServerHello(sh) => (
                    sh.session_id.clone(),
                    sh.fingerprints.clone(),
                    sh.host_fingerprint.clone(),
                    sh.features.clone(),
                ),
                _ => return Err(WshError::InvalidMessage("expected SERVER_HELLO".into())),
            };
        gateway_credit_on(&self.gateway, &advertised_features);
        *self.server_features.lock().await = advertised_features.clone();

        // Host key (wsh #59, #145): trust only a key the host PROVED it holds, over this
        // connection, before any credential leaves. A bare `host_fingerprint` is not a proof.
        if config.verify_host || config.expect_host_key.is_some() {
            let proven = crate::host_key::verify_advert(
                &advertised_features,
                host_fingerprint.as_deref(),
                &hello_session_id,
                &host_key_nonce,
                &config.username,
            )?;
            if let Some(want) = &config.expect_host_key {
                match &proven {
                    Some(key) if key.fingerprint.eq_ignore_ascii_case(want) => {}
                    Some(key) => {
                        return Err(WshError::AuthFailed(format!(
                            "HOST KEY MISMATCH for {known_host}: pinned {want}, the host proved {}; \
                             refusing before sending credentials",
                            key.fingerprint
                        )))
                    }
                    None => {
                        return Err(WshError::AuthFailed(format!(
                            "HOST KEY REQUIRED: {known_host} proved no host key, but {want} is pinned; \
                             refusing before sending credentials"
                        )))
                    }
                }
            }
            match proven {
                // An explicit pin that matched is the whole decision: `known_hosts` is neither
                // consulted nor written (the person named the key; it is not a trust-on-first-use).
                Some(key) if config.expect_host_key.is_some() => {
                    self.host_key = Some(key);
                }
                Some(key) => {
                    self.host_key_newly_pinned = self.pin_host_key(config, known_host, &key)?;
                    self.host_key = Some(key);
                }
                None => self.accept_unproven_host(
                    config,
                    known_host,
                    host_fingerprint.as_deref(),
                    &server_fingerprints,
                )?,
            }
        } else {
            self.host_key = crate::host_key::verify_advert(
                &advertised_features,
                host_fingerprint.as_deref(),
                &hello_session_id,
                &host_key_nonce,
                &config.username,
            )
            .ok()
            .flatten();
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
                self.login_key = Some(signing_key.clone());

                // Channel binding (wsh #119): bind every kind the host offers that this client can
                // supply -- the host key it just saw prove possession, a pinned certificate hash.
                let mut available: Vec<(&'static str, Vec<u8>)> = Vec::new();
                if let Some(k) = &self.host_key {
                    available.push(("host", k.public_key.to_vec()));
                }
                if let Some(h) = &config.bound_cert_hash() {
                    available.push(("cert-hash", h.to_vec()));
                }
                let (binding, kinds) =
                    crate::channel_binding::client_binding(&advertised_features, &available);
                let host_requires = crate::channel_binding::requires_binding(&advertised_features);
                if kinds.is_empty() && (config.require_channel_binding || host_requires) {
                    let offered = crate::channel_binding::offered_kinds(&advertised_features);
                    return Err(WshError::AuthFailed(format!(
                        "channel binding {} but not available (host offers: {}; bound: none) -- nothing was signed",
                        if config.require_channel_binding { "required" } else { "is required by the host" },
                        if offered.is_empty() { "none".to_string() } else { offered.join(", ") },
                    )));
                }
                self.channel_binding_kinds = kinds;
                let signature = auth::sign_challenge_bound(
                    &signing_key,
                    &config.username,
                    &server_session_id,
                    &nonce,
                    &binding,
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
                if config.require_channel_binding {
                    return Err(WshError::AuthFailed(
                        "channel binding required but a password login signs nothing to bind"
                            .into(),
                    ));
                }
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

    fn known_hosts_for(config: &ConnectConfig) -> WshResult<KnownHosts> {
        match &config.known_hosts_path {
            Some(p) => Ok(KnownHosts::new(p.clone())),
            None => KnownHosts::default_location(),
        }
    }

    /// Check a PROVEN host key against `known_hosts` and record it on first use if allowed.
    /// Returns whether it was recorded just now. A changed key is always refused.
    fn pin_host_key(
        &self,
        config: &ConnectConfig,
        host: &str,
        key: &crate::host_key::ProvenHostKey,
    ) -> WshResult<bool> {
        let known_hosts = Self::known_hosts_for(config)?;
        match known_hosts.verify_host(host, &key.fingerprint)? {
            HostStatus::Known => {
                tracing::debug!("host {} verified (known)", host);
                Ok(false)
            }
            HostStatus::Unknown => {
                let allowed = match &config.first_use {
                    FirstUse::Accept => true,
                    FirstUse::AcceptFingerprint(fp) => fp == &key.fingerprint,
                    FirstUse::Refuse => false,
                };
                if !allowed {
                    return Err(WshError::HostKeyUnknown {
                        host: host.to_string(),
                        fingerprint: key.fingerprint.clone(),
                    });
                }
                tracing::info!(
                    "new host {} with fingerprint {}, adding to known_hosts",
                    host,
                    key.fingerprint
                );
                known_hosts.add_host(host, &key.fingerprint)?;
                Ok(true)
            }
            HostStatus::Changed { expected } => Err(WshError::AuthFailed(format!(
                "HOST KEY CHANGED for {}: expected {}, got {}. \
                 This could indicate a man-in-the-middle attack.",
                host, expected, key.fingerprint
            ))),
        }
    }

    /// The host proved no host key. Refuse when one is required, or when a key is already
    /// pinned for this host (a host that had a key and now shows none is a downgrade); the one
    /// exception is an entry the OLD client recorded from `fingerprints[0]` -- an unauthenticated
    /// list, what a host with no key sent -- which keeps working for a host that still sends
    /// no `host_fingerprint`. Nothing is written to `known_hosts`.
    fn accept_unproven_host(
        &self,
        config: &ConnectConfig,
        host: &str,
        host_fingerprint: Option<&str>,
        fingerprints: &[String],
    ) -> WshResult<()> {
        if config.require_host_key {
            return Err(WshError::AuthFailed(format!(
                "HOST KEY REQUIRED but {host} proved none (a bare host_fingerprint is not a proof); \
                 refusing before sending credentials"
            )));
        }
        if let Some(pinned) = Self::known_hosts_for(config)?.get(host)? {
            let legacy = host_fingerprint.is_none_or(str::is_empty)
                && fingerprints.first().is_some_and(|f| *f == pinned);
            if !legacy {
                return Err(WshError::AuthFailed(format!(
                    "HOST KEY MISSING for {host}: a host key ({pinned}) is pinned for it but the host \
                     proved none now. This could be a man-in-the-middle attack, or the host dropped \
                     its key; remove its line from known_hosts if you trust that change."
                )));
            }
        }
        tracing::debug!(
            host = %host,
            "host presented no host-key proof; its identity is not verified"
        );
        Ok(())
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
        early: EarlyShared,
        gateway: Arc<GatewayHub>,
        seal: Arc<SealGate>,
    ) {
        loop {
            let is_connected = { *connected.lock().await };
            if !is_connected {
                break;
            }

            tokio::select! {
                // Handle outgoing control messages
                Some(frame) = outgoing_rx.recv() => {
                    // A sealed bridge: what leaves is sealed, in this (the sending) order.
                    let Some(frame) = seal.outgoing(frame) else { continue };
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
                        ControlAction::FileChunk { channel_id, offset, data, is_final, total_size } => Envelope {
                            msg_type: MsgType::FileChunk,
                            payload: Payload::FileChunk(FileChunkPayload { channel_id, offset, data, is_final, total_size }),
                        },
                    };

                    match frame_encode(&envelope) {
                        Ok(frame) => {
                            let Some(frame) = seal.outgoing(frame) else { continue };
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
                                    tracing::trace!(msg_type = ?envelope.msg_type, "control message");
                                    // A sealed session (#155): everything from the host but the keepalive is a frame.
                                    let envelope = if seal.scope() == Some(crate::bridge_seal::Scope::Session) {
                                        let gated = seal.incoming_direct(envelope);
                                        for reply in gated.replies {
                                            if let Ok(frame) = frame_encode(&reply) {
                                                let _ = outgoing_tx.send(frame).await;
                                            }
                                        }
                                        match gated.deliver {
                                            Some(opened) => opened,
                                            None => {
                                                if seal.has_failed() && seal.closes_on_failure() {
                                                    tracing::error!("the sealed session failed: closing the connection");
                                                    let mut c = connected.lock().await;
                                                    *c = false;
                                                    break;
                                                }
                                                continue;
                                            }
                                        }
                                    } else {
                                        envelope
                                    };
                                    // A plain message a relay may forward is not heard on a bridge that is sealed.
                                    if seal.drop_unwrapped(&envelope) {
                                        tracing::warn!(msg_type = ?envelope.msg_type, "dropping an unwrapped plaintext message on a sealed bridge");
                                        continue;
                                    }
                                    Self::handle_incoming(
                                        envelope,
                                        &response_tx,
                                        &sessions,
                                        &outgoing_tx,
                                        &reverse_connect_tx,
                                        &relay_message_tx,
                                        &accepted_relay_peers,
                                        &early,
                                        &gateway,
                                        &seal,
                                    ).await;
                                    if seal.has_failed() && seal.closes_on_failure() {
                                        tracing::error!("the sealed bridge failed: closing the connection");
                                        let mut c = connected.lock().await;
                                        *c = false;
                                        break;
                                    }
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

        // The connection is gone, so nothing more will ever arrive for these
        // sessions. Close them: a reader blocked in `read()` otherwise waits forever
        // for data from a peer that has disconnected (`wsh connect` never exited).
        let open: Vec<Arc<WshSession>> = sessions.lock().await.values().cloned().collect();
        for session in open {
            session.mark_closed().await;
        }

        gateway.close_all();
        tracing::debug!("dispatch loop ended");
    }

    /// Handle an incoming control message.
    #[allow(clippy::too_many_arguments)]
    fn handle_incoming<'a>(
        mut envelope: Envelope,
        response_tx: &'a Arc<Mutex<HashMap<u8, Vec<Waiter>>>>,
        sessions: &'a Arc<Mutex<HashMap<u32, Arc<WshSession>>>>,
        outgoing_tx: &'a mpsc::Sender<Vec<u8>>,
        reverse_connect_tx: &'a Option<mpsc::Sender<Envelope>>,
        relay_message_tx: &'a Option<mpsc::Sender<Envelope>>,
        accepted_relay_peers: &'a Arc<Mutex<HashSet<String>>>,
        early: &'a EarlyShared,
        gateway: &'a Arc<GatewayHub>,
        seal: &'a Arc<SealGate>,
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
                            // A sealed bridge (#117, #145): `from_fingerprint` is whatever the relay stamped, so
                            // plain traffic proves nothing -- only frames of the bridge (and, while it is being
                            // set up, its key exchange) are heard.
                            let gated = seal.incoming_forwarded(inner);
                            // The key exchange's replies (this side is the responder) leave in order, plain.
                            for reply in gated.replies {
                                if let Ok(frame) = frame_encode(&reply) {
                                    let _ = outgoing_tx.send(frame).await;
                                }
                            }
                            let Some(inner) = gated.deliver else {
                                return;
                            };
                            // A peer that serves several operators (wsh #93) must know which one
                            // sent this: it gets the forward as the relay stamped it, and unwraps it
                            // itself.
                            if seal.tags_relay_origin() {
                                if let Some(tx) = relay_message_tx {
                                    if let Ok(bytes) = wsh_core::cbor_encode(&inner) {
                                        let tagged = Envelope {
                                            msg_type: MsgType::RelayForward,
                                            payload: Payload::RelayForward(RelayForwardPayload {
                                                from_fingerprint: p.from_fingerprint.clone(),
                                                inner: bytes,
                                                to_fingerprint: None,
                                            }),
                                        };
                                        if let Err(err) = tx.send(tagged).await {
                                            tracing::debug!("relay message channel closed: {err}");
                                        }
                                    }
                                    return;
                                }
                            }
                            Self::handle_incoming(
                                inner,
                                response_tx,
                                sessions,
                                outgoing_tx,
                                reverse_connect_tx,
                                relay_message_tx,
                                accepted_relay_peers,
                                early,
                                gateway,
                                seal,
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

            // Credit for an rpc channel in virtual data mode (wsh #191) is a GatewayCredit in a number space of its
            // own (`0x80000000 | channel_id`); it is never the gateway's, and for a channel that is gone it is dropped.
            if let Payload::GatewayCredit(p) = &envelope.payload {
                if let Some(channel_id) = wsh_core::rpc_credit::rpc_channel_of_credit(p.gateway_id)
                {
                    let session = sessions.lock().await.get(&channel_id).cloned();
                    if let Some(session) = session {
                        session.rpc_credit(p.bytes);
                    }
                    return;
                }
            }

            // Gateway traffic for a connection or listener this client opened goes to it. What
            // matches nothing here (a reverse host's own gateway messages) goes on as before.
            if matches!(
                envelope.msg_type,
                MsgType::GatewayOk
                    | MsgType::GatewayFail
                    | MsgType::GatewayData
                    | MsgType::GatewayCredit
                    | MsgType::GatewayClose
                    | MsgType::ListenOk
                    | MsgType::ListenFail
                    | MsgType::InboundOpen
                    | MsgType::ShareRequest
            ) && gateway.on_message(&envelope).await
            {
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
                | MsgType::FileChunk
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

                    // `early` is taken before `sessions` (as `open_session` does) so a
                    // frame is either routed to the registered session or kept for the
                    // one being registered, never lost in between.
                    let session = {
                        let mut early_guard = early.lock().await;
                        let found = sessions.lock().await.get(&channel_id).cloned();
                        if found.is_none() {
                            match early_guard.hold(channel_id, envelope) {
                                None => return,
                                Some(not_waiting) => envelope = not_waiting,
                            }
                        }
                        found
                    };

                    if let Some(session) = session {
                        if matches!(envelope.msg_type, MsgType::Exit) {
                            if let Payload::Exit(exit) = &envelope.payload {
                                // This was an `eprintln!` because a
                                // `tracing::info!` here hung forever (#38): the
                                // old `wsh exec` held `stdout().lock()` across its
                                // `session.read().await` loop, and the default
                                // tracing writer is stdout, so the first log line
                                // this loop emitted while exec was reading blocked
                                // on a lock exec would release only after this loop
                                // delivered its data. exec no longer holds the lock
                                // and the CLI logs to stderr, so this is an
                                // ordinary event (and no longer a line on every run).
                                tracing::debug!(
                                    channel = exit.channel_id,
                                    code = exit.code,
                                    "channel exited"
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

                // Incoming reverse connection request (unsolicited from relay), and the
                // operator's proof that follows a challenge this peer issued (#117).
                // `ReverseClose` (wsh #93) names an operator that left a peer which serves several.
                MsgType::ReverseConnect | MsgType::ReverseProof | MsgType::ReverseClose => {
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
                            // An `OpenOk` hands a channel to whoever is opening it. Note
                            // the channel BEFORE they are woken, so a frame that follows
                            // in the same burst is held for them instead of being lost.
                            let opened = match &envelope.payload {
                                Payload::OpenOk(ok) => {
                                    let mut channels = vec![ok.channel_id];
                                    channels.extend(ok.stderr_channel_id);
                                    channels
                                }
                                _ => Vec::new(),
                            };
                            if !opened.is_empty() {
                                let mut early = early.lock().await;
                                for channel_id in &opened {
                                    early.reserve(*channel_id);
                                }
                            }
                            if waiter.tx.send(envelope).is_err() && !opened.is_empty() {
                                // Nobody is waiting any more (the open timed out).
                                let mut early = early.lock().await;
                                for channel_id in &opened {
                                    early.release(*channel_id);
                                }
                            }
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

/// Credit is on when the host advertised `gateway-credit` (the client always lists it in `Hello`).
fn gateway_credit_on(gateway: &GatewayHub, host_features: &[String]) {
    gateway.set_credit(
        host_features
            .iter()
            .any(|f| f == wsh_core::gateway_credit::GATEWAY_CREDIT_FEATURE),
    );
}

fn envelope_channel_id(envelope: &Envelope) -> Option<u32> {
    match &envelope.payload {
        Payload::Resize(payload) => Some(payload.channel_id),
        Payload::Signal(payload) => Some(payload.channel_id),
        Payload::Exit(payload) => Some(payload.channel_id),
        Payload::Close(payload) => Some(payload.channel_id),
        Payload::SessionData(payload) => Some(payload.channel_id),
        Payload::FileChunk(payload) => Some(payload.channel_id),
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
mod cert_policy_tests {
    use super::ConnectConfig;
    use crate::transport::CertPolicy;

    #[test]
    fn the_default_config_validates_the_certificate() {
        assert_eq!(
            ConnectConfig::default().cert_policy().unwrap(),
            CertPolicy::SystemRoots
        );
    }

    #[test]
    fn pins_from_both_fields_are_pinned_together() {
        let config = ConnectConfig {
            cert_hash: Some([1; 32]),
            cert_hashes: vec![[2; 32]],
            ..Default::default()
        };
        assert_eq!(
            config.cert_policy().unwrap(),
            CertPolicy::Pinned(vec![[1; 32], [2; 32]])
        );
    }

    #[test]
    fn the_opt_out_is_explicit_and_cannot_be_mixed_with_a_pin() {
        let config = ConnectConfig {
            insecure_skip_cert_verification: true,
            ..Default::default()
        };
        assert_eq!(
            config.cert_policy().unwrap(),
            CertPolicy::InsecureSkipVerification
        );
        let both = ConnectConfig {
            insecure_skip_cert_verification: true,
            cert_hash: Some([1; 32]),
            ..Default::default()
        };
        assert!(
            both.cert_policy().is_err(),
            "pinning and not verifying contradict each other"
        );
    }

    #[test]
    fn a_password_is_never_sent_over_an_unverified_certificate() {
        let config = ConnectConfig {
            insecure_skip_cert_verification: true,
            password: Some("pw".into()),
            ..Default::default()
        };
        let err = config.cert_policy().unwrap_err().to_string();
        assert!(err.contains("password"), "{err}");
        // A password with a verified certificate is the ordinary case.
        let ok = ConnectConfig {
            password: Some("pw".into()),
            ..Default::default()
        };
        assert!(ok.cert_policy().is_ok());
    }

    #[test]
    fn only_a_single_pin_is_a_channel_binding() {
        let one = ConnectConfig {
            cert_hash: Some([1; 32]),
            ..Default::default()
        };
        assert_eq!(one.bound_cert_hash(), Some([1; 32]));
        let two = ConnectConfig {
            cert_hash: Some([1; 32]),
            cert_hashes: vec![[2; 32]],
            ..Default::default()
        };
        assert_eq!(two.bound_cert_hash(), None);
        let only_list = ConnectConfig {
            cert_hashes: vec![[3; 32]],
            ..Default::default()
        };
        assert_eq!(only_list.bound_cert_hash(), Some([3; 32]));
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
            &Default::default(),
            &Default::default(),
            &Default::default(),
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
            &Default::default(),
            &Default::default(),
            &Default::default(),
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
            &Default::default(),
            &Default::default(),
            &Default::default(),
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

    // ── frames that arrive in the same burst as OpenOk (#135) ────────────
    //
    // `dispatch_loop` hands OpenOk to the task inside `open_session` and goes on
    // to the next frame. When a host answers at once, that frame (the first
    // output, even the Exit) is already queued, and the loop reached it before the
    // opener had registered the session: nothing was listening on the channel and
    // the data was dropped -- `wsh host -- echo hi` printed nothing, some runs.

    fn open_ok_for(channel_id: u32, stderr_channel_id: Option<u32>) -> Envelope {
        Envelope {
            msg_type: MsgType::OpenOk,
            payload: Payload::OpenOk(OpenOkPayload {
                channel_id,
                stream_ids: vec![],
                data_mode: SessionDataMode::Virtual,
                capabilities: vec![],
                session_id: Some("sess".into()),
                token: Some(vec![1u8; 16]),
                stderr_channel_id,
            }),
        }
    }

    fn data_for(channel_id: u32, data: &[u8]) -> Envelope {
        Envelope {
            msg_type: MsgType::SessionData,
            payload: Payload::SessionData(SessionDataPayload {
                channel_id,
                data: data.to_vec(),
            }),
        }
    }

    fn exit_for(channel_id: u32, code: i32) -> Envelope {
        Envelope {
            msg_type: MsgType::Exit,
            payload: Payload::Exit(wsh_core::messages::ExitPayload { channel_id, code }),
        }
    }

    /// Feed `frames` to the client the way its dispatch loop does, with the
    /// opener task not yet run in between (a current-thread runtime only polls it
    /// when the test awaits something that suspends).
    async fn dispatch_burst(client: &WshClient, frames: Vec<Envelope>) {
        let (reverse_connect_tx, relay_message_tx) = (None, None);
        for frame in frames {
            WshClient::handle_incoming(
                frame,
                &client.response_tx,
                &client.sessions,
                &client.outgoing_tx,
                &reverse_connect_tx,
                &relay_message_tx,
                &client.accepted_relay_peers,
                &client.early,
                &client.gateway,
                &client.seal,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn output_and_exit_that_arrive_with_open_ok_reach_the_session() {
        let mut rig = build_test_client("s");
        let client = Arc::new(rig.client);
        let opener = {
            let client = client.clone();
            tokio::spawn(async move { client.open_session(SessionOpts::default()).await })
        };
        // The OPEN has gone out, so the opener is registered as the waiter.
        rig.outgoing_rx.recv().await.expect("OPEN frame");

        dispatch_burst(
            &client,
            vec![
                open_ok_for(31, None),
                data_for(31, b"hi\n"),
                data_for(31, b"there\n"),
                exit_for(31, 5),
            ],
        )
        .await;

        let session = opener.await.unwrap().expect("open_session");
        let mut got = Vec::new();
        let mut buf = [0_u8; 64];
        // Bounded: with the frames lost, `read` never sees data or EOF and waits forever.
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let n = session.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
        })
        .await;
        assert_eq!(
            got, b"hi\nthere\n",
            "output sent with OpenOk was lost or reordered"
        );
        assert_eq!(session.exit_code().await, Some(5), "the Exit was lost");
    }

    #[tokio::test]
    async fn frames_for_a_channel_nobody_opened_still_go_to_the_relay_channel() {
        // The hold applies only to a channel an OpenOk was just handed out for.
        let rig = build_test_client("s");
        let (relay_tx, mut relay_rx) = mpsc::channel(4);
        WshClient::handle_incoming(
            data_for(77, b"x"),
            &rig.response_tx,
            &rig.sessions,
            &rig.outgoing_tx,
            &None,
            &Some(relay_tx),
            &rig.accepted_relay_peers,
            &rig.client.early,
            &rig.client.gateway,
            &rig.client.seal,
        )
        .await;
        assert!(relay_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn a_stderr_channel_granted_with_open_ok_collects_its_early_output() {
        let mut rig = build_test_client("s");
        let client = Arc::new(rig.client);
        let opener = {
            let client = client.clone();
            tokio::spawn(async move {
                client
                    .open_session(SessionOpts {
                        kind: ChannelKind::Exec,
                        command: Some("x".into()),
                        stdio: Some("pipes".into()),
                        ..Default::default()
                    })
                    .await
            })
        };
        rig.outgoing_rx.recv().await.expect("OPEN frame");
        dispatch_burst(
            &client,
            vec![
                open_ok_for(8, Some(9)),
                data_for(9, b"oops\n"),
                data_for(8, b"out\n"),
                exit_for(8, 1),
            ],
        )
        .await;
        let session = opener.await.unwrap().expect("open_session");
        assert!(session.has_stderr());
        let mut buf = [0_u8; 16];
        let n = session.read_stderr(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"oops\n");
        assert_eq!(session.read_stderr(&mut buf).await.unwrap(), 0);
        let n = session.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"out\n");
        assert_eq!(session.exit_code().await, Some(1));
    }

    #[test]
    fn the_backlog_for_one_unclaimed_channel_is_bounded() {
        let mut early = super::EarlyChannels::default();
        early.reserve(1);
        let chunk = vec![0_u8; 1024 * 1024];
        for _ in 0..16 {
            assert!(early.hold(1, data_for(1, &chunk)).is_none());
        }
        let kept = early.release(1).len();
        assert!(
            kept <= 4,
            "an OpenOk nobody claims must not hold more than a few MiB, held {kept} MiB"
        );
        // Too many channels reserved at once: the extras are simply not held.
        for id in 0..64 {
            early.reserve(id);
        }
        assert!(early.channels.len() <= 16);
    }

    #[tokio::test]
    async fn open_session_uses_virtual_data_mode_when_server_returns_virtual_open_ok() {
        let response_tx = Arc::new(Mutex::new(HashMap::new()));
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let (control_action_tx, _control_action_rx) = mpsc::channel(4);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(4);

        let client = WshClient {
            seal: Default::default(),
            login_key: None,
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
            early: Default::default(),
            host_key: None,
            host_key_newly_pinned: false,
            channel_binding_kinds: Vec::new(),
            stream_opener: None,
            gateway: Default::default(),
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
                        stderr_channel_id: None,
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
            seal: Default::default(),
            login_key: None,
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
            early: Default::default(),
            host_key: None,
            host_key_newly_pinned: false,
            channel_binding_kinds: Vec::new(),
            stream_opener: None,
            gateway: Default::default(),
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
                    &Default::default(),
                    &Default::default(),
                    &Default::default(),
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
                ControlAction::FileChunk {
                    channel_id,
                    offset,
                    data,
                    is_final,
                    total_size,
                } => Envelope {
                    msg_type: MsgType::FileChunk,
                    payload: Payload::FileChunk(wsh_core::messages::FileChunkPayload {
                        channel_id,
                        offset,
                        data,
                        is_final,
                        total_size,
                    }),
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
                &Default::default(),
                &Default::default(),
                &Default::default(),
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
                signature: None,
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
                signature: None,
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
