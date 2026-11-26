//! Server configuration: TOML file + CLI overrides.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};
use wsh_core::WshResult;

use crate::auth::password::StoredHash;

/// Top-level config file structure.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub auth: AuthSection,
    #[serde(default)]
    pub gateway: GatewaySection,
    #[serde(default)]
    pub rpc: RpcSection,
    #[serde(default)]
    pub mcp: McpSection,
    #[serde(default)]
    pub relay: RelaySection,
}

/// `[relay]` section: how the relay (started with `--enable-relay`) bridges operators to peers.
///
/// ```toml
/// [relay]
/// max_operators_per_peer = 4
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct RelaySection {
    /// How many operators one peer may be bridged to at once (wsh #93). Default: `1`, the relay
    /// as it always was. Above 1 the relay advertises `relay-multi-operator`; only a peer that
    /// states the same feature in its `ReverseAccept` (it then addresses each message to one
    /// operator with `RelayForward.to_fingerprint` and is told with `ReverseClose` when one
    /// leaves) is bridged to several, every other peer stays at one.
    #[serde(default = "default_relay_max_operators")]
    pub max_operators_per_peer: usize,
}

fn default_relay_max_operators() -> usize {
    1
}

impl Default for RelaySection {
    fn default() -> Self {
        Self {
            max_operators_per_peer: default_relay_max_operators(),
        }
    }
}

/// `[mcp]` section: command-line tools offered over `McpDiscover` / `McpCall`.
///
/// ```toml
/// [[mcp.tools]]
/// name = "disk-free"
/// description = "Free space under a path"
/// command = "df -h {path}"
/// parameters = { path = "directory to inspect" }
/// timeout_secs = 10
/// ```
///
/// Default: no tools. A tool runs `sh -c <command>` with each `{arg}` replaced by the
/// call's argument of that name, so only register commands you are happy for every
/// authenticated client to run.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct McpSection {
    #[serde(default)]
    pub tools: Vec<McpToolSection>,
}

/// One `[[mcp.tools]]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct McpToolSection {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub command: String,
    #[serde(default)]
    pub parameters: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    /// Seconds before the call fails; 0 (the default) = no limit.
    #[serde(default)]
    pub timeout_secs: u64,
}

/// `[server]` section of the config TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerSection {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_cert_path")]
    pub cert: String,
    #[serde(default = "default_key_path")]
    pub key: String,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_session_ttl")]
    pub session_ttl: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,
    /// Which environment variables a client may set for what it runs
    /// (`Open.env`): absent = `TERM`, `COLORTERM`, `LANG`, `LANGUAGE`, `LC_*`;
    /// `true` = everything; `false` = nothing; a list = exactly those names
    /// (a trailing `*` makes a prefix). See [`crate::client_env`].
    #[serde(default)]
    pub client_env: Option<crate::client_env::ClientEnvSetting>,
    /// Path of this server's own Ed25519 identity (PKCS#8 PEM, the same file format the Node host
    /// reads). Created with mode 0600 on first start. Absent = no host key: the server sends no
    /// `host_fingerprint` and proves nothing, as every release before it did (wsh #59, #145).
    /// Turning it on makes new clients verify and pin this host; a client that pinned the old
    /// `fingerprints[0]` guess will report the host key as changed.
    #[serde(default)]
    pub host_key: Option<String>,
    /// Accept a login only if the client's signature is bound to this connection (the host key
    /// that proved itself; wsh #119). Needs `host_key`. A released client that cannot bind is
    /// refused -- turn this on only when every client is new enough.
    #[serde(default)]
    pub require_channel_binding: bool,
    /// Seal a WebSocket session end to end (wsh #155): `off` (default: nothing changes for any
    /// client), `offer` (a client that asks -- `wsh --sealed`, `connect({ sealSession: true })` --
    /// gets a sealed session, any other is served as before) or `require` (nothing is served on a
    /// session that is not sealed: no password login, no WebTransport, no relay tunnels). Needs
    /// `host_key`. Typed rpc channels are not offered while this is on (their streams are not frames).
    #[serde(default)]
    pub seal_session: SealSession,
    /// With `seal_session = "require"`: seconds after a login that the session may stay unsealed
    /// (wsh #244). At the deadline the server sends an `Error` saying so and closes the
    /// connection. Default 30; 0 = no deadline. No effect where sealing is not required.
    #[serde(default = "default_seal_timeout_secs")]
    pub seal_timeout_secs: u64,
    /// Seconds a connection may take, from the moment the server accepts it, to complete its login
    /// (wsh #248): the TLS and WebSocket handshakes, `Hello` and `Auth`. At the deadline the server
    /// sends an `AuthFail` saying so and closes the connection. Default 60; 0 = no deadline.
    #[serde(default = "default_login_timeout_secs")]
    pub login_timeout_secs: u64,
}

/// The most operators `[relay] max_operators_per_peer` may allow one peer.
pub const MAX_RELAY_OPERATORS_PER_PEER: usize = 64;

/// `[server] seal_session`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SealSession {
    #[default]
    Off,
    Offer,
    Require,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            port: default_port(),
            cert: default_cert_path(),
            key: default_key_path(),
            max_sessions: default_max_sessions(),
            session_ttl: default_session_ttl(),
            idle_timeout: default_idle_timeout(),
            client_env: None,
            host_key: None,
            require_channel_binding: false,
            seal_session: SealSession::Off,
            seal_timeout_secs: default_seal_timeout_secs(),
            login_timeout_secs: default_login_timeout_secs(),
        }
    }
}

/// `[auth]` section of the config TOML.
///
/// # Password Authentication
///
/// Password login is **off** unless `allow_password = true`. Each user needs an
/// Argon2id hash in PHC format with its own random salt; make one with
/// `printf '%s' "$PASSWORD" | wsh-server --hash-password`:
///
/// ```toml
/// [auth]
/// allow_password = true
///
/// [auth.password_hashes]
/// alice = "$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>"
/// ```
///
/// Entries written as `sha256:<hex>` (one unsalted SHA-256 of the password, the
/// only format before this release) are **refused**: the server says so at start-up
/// and the user cannot log in. `allow_legacy_sha256 = true` keeps them working, with
/// a warning at every start-up, as a stop-gap while the hashes are replaced.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthSection {
    #[serde(default = "default_true")]
    pub allow_pubkey: bool,
    /// Accept password login at all. Default: `false`.
    #[serde(default)]
    pub allow_password: bool,
    /// Accept the old unsalted `sha256:<hex>` entries in `password_hashes`. Default: `false`.
    #[serde(default)]
    pub allow_legacy_sha256: bool,
    /// Username → Argon2id PHC hash (see above).
    #[serde(default)]
    pub password_hashes: std::collections::HashMap<String, String>,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            allow_pubkey: true,
            allow_password: false,
            allow_legacy_sha256: false,
            password_hashes: std::collections::HashMap::new(),
        }
    }
}

/// `[gateway]` section of the config TOML.
///
/// Controls the gateway subsystem that handles TCP/UDP forwarding, DNS
/// resolution, and reverse tunnel listeners. **All of it is off by default**:
/// the gateway lets an authenticated client open connections *from this
/// machine*, so it is something to switch on deliberately.
///
/// # TOML Example
///
/// ```toml
/// [gateway]
/// enabled = true
/// # Public destinations only unless a rule names an internal one:
/// allowed_destinations = ["example.com:443", "203.0.113.0/24", "*"]
/// max_connections = 100
/// # Off unless set; when on, listeners bind to loopback unless reverse_bind_addr says otherwise.
/// enable_reverse_tunnels = true
/// reverse_bind_addr = "127.0.0.1"
/// ```
///
/// To get the pre-0.7 behaviour (anything reachable, listeners on every interface):
///
/// ```toml
/// [gateway]
/// enabled = true
/// allowed_destinations = ["*", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1", "fc00::/7", "fe80::/10"]
/// enable_reverse_tunnels = true
/// reverse_bind_addr = "0.0.0.0"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct GatewaySection {
    /// Master switch for the gateway subsystem.
    ///
    /// When `false`, all gateway message types (`OpenTcp`, `OpenUdp`,
    /// `ResolveDns`, `ListenRequest`) are rejected with error code 5
    /// (`GATEWAY_DISABLED`) and `gateway` is not advertised.
    ///
    /// Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Destination rules for outbound connections and DNS lookups.
    ///
    /// Forms: `"example.com"`, `"example.com:443"`, `"10.0.0.0/8"`,
    /// `"10.0.0.0/8:5432"`, `"127.0.0.1:5432"`, and the wildcard `"*"`.
    /// The wildcard means any *public* destination: an address that is
    /// loopback, link-local, private, unique-local, carrier-grade NAT, unspecified
    /// or multicast is refused after the name is resolved unless a rule names that
    /// host or address. See `gateway::policy`.
    ///
    /// Default: `[]` (nothing is allowed).
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
    /// Maximum number of concurrent gateway connections (TCP + UDP +
    /// reverse tunnel listeners combined).
    ///
    /// Default: `100`.
    #[serde(default = "default_gateway_max_connections")]
    pub max_connections: usize,
    /// Whether clients may open reverse tunnel listeners via `ListenRequest`.
    ///
    /// Default: `false`.
    #[serde(default)]
    pub enable_reverse_tunnels: bool,
    /// Address reverse tunnel listeners bind to. The client's own `bind_addr` in
    /// `ListenRequest` is ignored. Must be an IP address.
    ///
    /// Default: `"127.0.0.1"`.
    #[serde(default = "default_reverse_bind_addr")]
    pub reverse_bind_addr: String,
    /// Ports a client may ask a reverse tunnel listener to bind (`ListenRequest`), as integers and
    /// `"lo-hi"` ranges: `reverse_ports = [0, "20000-20100", 8080]`. Unset: `[0, "1024-65535"]`
    /// (ephemeral, or any unprivileged port). A list REPLACES that default, so a port below 1024
    /// is allowed only when listed. A bad entry stops start-up.
    #[serde(default)]
    pub reverse_ports: Option<Vec<crate::gateway::reverse_policy::PortRule>>,
    /// Reverse tunnel listeners one client connection may hold.
    ///
    /// Default: `4`.
    #[serde(default = "default_reverse_max_listeners")]
    pub reverse_max_listeners: usize,
    /// Open (and not yet answered) connections one reverse listener may have; the next is closed.
    ///
    /// Default: `16`.
    #[serde(default = "default_reverse_max_connections_per_listener")]
    pub reverse_max_connections_per_listener: usize,
    /// The `listen(2)` backlog of a reverse listener.
    ///
    /// Default: `8`.
    #[serde(default = "default_reverse_backlog")]
    pub reverse_backlog: u32,
    /// Seconds without a byte in either direction before an accepted reverse connection is
    /// closed; `0` never closes one for being idle. Only a connection the relay is reading is
    /// watched: one parked waiting for the client's credit is bounded by the credit window and
    /// the connection caps, not by this.
    ///
    /// Default: `300`.
    #[serde(default = "default_reverse_idle_secs")]
    pub reverse_idle_secs: u64,
    /// UDP flows (`OpenUdp`) one client connection may hold.
    ///
    /// Default: `16`.
    #[serde(default = "default_udp_max_flows")]
    pub udp_max_flows: usize,
    /// Datagrams per second one UDP flow may move, both directions together; the rest are dropped.
    /// `0`: no limit.
    ///
    /// Default: `500`.
    #[serde(default = "default_udp_packets_per_second_per_flow")]
    pub udp_packets_per_second_per_flow: u64,
    /// The same, over all of one client's flows. `0`: no limit.
    ///
    /// Default: `2000`.
    #[serde(default = "default_udp_packets_per_second_per_client")]
    pub udp_packets_per_second_per_client: u64,
    /// Payload bytes per second over all of one client's UDP flows, both directions together (what
    /// bounds amplification: no matter how much an origin answers with, no more than this reaches
    /// the client). `0`: no limit.
    ///
    /// Default: `4194304` (4 MiB).
    #[serde(default = "default_udp_bytes_per_second_per_client")]
    pub udp_bytes_per_second_per_client: u64,
    /// Seconds without a datagram in either direction before a UDP flow is closed. At least 1.
    ///
    /// Default: `60`.
    #[serde(default = "default_udp_idle_secs")]
    pub udp_idle_secs: u64,
    /// Offer `gateway-datagram` on WebTransport connections: when the client lists it too, the
    /// payloads of its UDP flows travel as WebTransport datagrams (`[gateway_id u32 BE][payload]`)
    /// instead of `GatewayData` on the control stream. `false` keeps every flow on the control
    /// stream. Has no effect over WebSocket, which has no datagrams.
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub udp_datagrams: bool,
    /// A UDP payload that does not fit one WebTransport datagram (the transport's maximum minus the
    /// 4-byte flow id): `"reliable"` sends it on the control stream (ordered, retransmitted, metered
    /// by credit), `"drop"` drops it as a path over its MTU would.
    ///
    /// Default: `"reliable"`.
    #[serde(default = "default_udp_oversize")]
    pub udp_oversize: String,
    /// Unix-domain sockets in THIS machine's file system a client may connect to
    /// (`OpenUnix`, `wsh -L ...:/remote.sock`). Needs `enabled = true`. Each entry is an
    /// absolute path, exact (`"/var/run/docker.sock"`) or a directory prefix with a trailing
    /// slash (`"/run/user/1000/wsh/"`); on Linux `"@name"` / `"@prefix/"` list abstract-namespace
    /// sockets. A request is judged after the PARENT directory is resolved with realpath, the
    /// target must be a socket, and a symlink is never followed out of the allowed place.
    /// Listing a daemon socket such as Docker's gives every authorized client the daemon's
    /// full power (it is root-equivalent). `gateway-unix` is advertised only when this or
    /// `unix_listen` is non-empty.
    ///
    /// Default: `[]` (no unix sockets are reachable).
    #[serde(default)]
    pub unix_connect: Vec<String>,
    /// Sockets a client may ask this host to CREATE and listen on (`ListenUnix`,
    /// `wsh -R /remote.sock:...`); same pattern forms. The host creates them with mode 0600
    /// and removes them when the listener closes or the connection ends.
    ///
    /// Default: `[]`.
    #[serde(default)]
    pub unix_listen: Vec<String>,
    /// Let a client replace an existing, stale socket file at a `unix_listen` path (OpenSSH
    /// `StreamLocalBindUnlink`). Only when the client asks AND nothing is accepting
    /// connections on the old socket AND the file is a socket.
    ///
    /// Default: `false`.
    #[serde(default)]
    pub unix_replace_stale: bool,
    /// Unix listeners one client connection may hold.
    ///
    /// Default: `4`.
    #[serde(default = "default_unix_max_listeners")]
    pub unix_max_listeners: usize,
    /// Bytes a client may have sent for one gateway connection that its origin has not yet
    /// taken. With `gateway-credit` negotiated a client cannot exceed its credit (256 KiB);
    /// for an older client this is the only bound, and a connection that exceeds it is closed.
    /// At least 262144.
    ///
    /// Default: `4194304` (4 MiB).
    #[serde(default = "default_max_buffered_bytes")]
    pub max_buffered_bytes: usize,
    /// The same, summed over every connection of one client. At least `max_buffered_bytes`.
    ///
    /// Default: `33554432` (32 MiB).
    #[serde(default = "default_max_client_buffered_bytes")]
    pub max_client_buffered_bytes: usize,
    /// A gateway connection one side of which has half-closed (sent `GatewayClose`; the other has
    /// not) stays open while anything moves in either direction, so a client that half-closes and
    /// keeps reading gets what the origin sends later. It is closed after this many seconds with
    /// nothing moving in either direction, which reaps a peer that half-closes and never reads.
    /// `0` turns the bound off.
    ///
    /// Default: `300` (five minutes).
    #[serde(default = "default_half_close_idle_secs")]
    pub half_close_idle_secs: u64,
    /// An origin (or a reverse listener's caller) that has half-closed (sent its end of file) and
    /// then goes away (killed, crashed) tells a plain read loop nothing, so the connection and its
    /// slot would be held until the client next sent something (wsh #282). While a socket is
    /// half-closed the host waits for the kernel's hang-up of it, which a unix socket gives at
    /// once, and (TCP) gives it keep-alive on a schedule of this many seconds (first probe after
    /// this long, then one per this long, three in all). A peer that went away is handled as a
    /// destroyed connection: the client is sent `GatewayClose` with the reason `discarded`. A TCP
    /// peer that exited without unread data leaves a socket its kernel keeps for about a minute,
    /// so it is noticed then, not after this. `0` turns the watch off.
    ///
    /// Default: `2`.
    #[serde(default = "default_half_close_probe_secs")]
    pub half_close_probe_secs: u64,
}

impl Default for GatewaySection {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_destinations: Vec::new(),
            max_connections: default_gateway_max_connections(),
            enable_reverse_tunnels: false,
            reverse_bind_addr: default_reverse_bind_addr(),
            reverse_ports: None,
            reverse_max_listeners: default_reverse_max_listeners(),
            reverse_max_connections_per_listener: default_reverse_max_connections_per_listener(),
            reverse_backlog: default_reverse_backlog(),
            reverse_idle_secs: default_reverse_idle_secs(),
            udp_max_flows: default_udp_max_flows(),
            udp_packets_per_second_per_flow: default_udp_packets_per_second_per_flow(),
            udp_packets_per_second_per_client: default_udp_packets_per_second_per_client(),
            udp_bytes_per_second_per_client: default_udp_bytes_per_second_per_client(),
            udp_idle_secs: default_udp_idle_secs(),
            udp_datagrams: true,
            udp_oversize: default_udp_oversize(),
            unix_connect: Vec::new(),
            unix_listen: Vec::new(),
            unix_replace_stale: false,
            unix_max_listeners: default_unix_max_listeners(),
            max_buffered_bytes: default_max_buffered_bytes(),
            max_client_buffered_bytes: default_max_client_buffered_bytes(),
            half_close_idle_secs: default_half_close_idle_secs(),
            half_close_probe_secs: default_half_close_probe_secs(),
        }
    }
}

fn default_unix_max_listeners() -> usize {
    crate::gateway::unix_policy::DEFAULT_MAX_UNIX_LISTENERS
}
fn default_udp_oversize() -> String {
    "reliable".to_string()
}
fn default_udp_max_flows() -> usize {
    crate::gateway::udp_policy::DEFAULT_MAX_FLOWS
}
fn default_udp_packets_per_second_per_flow() -> u64 {
    crate::gateway::udp_policy::DEFAULT_PACKETS_PER_SECOND_PER_FLOW
}
fn default_udp_packets_per_second_per_client() -> u64 {
    crate::gateway::udp_policy::DEFAULT_PACKETS_PER_SECOND_PER_CLIENT
}
fn default_udp_bytes_per_second_per_client() -> u64 {
    crate::gateway::udp_policy::DEFAULT_BYTES_PER_SECOND_PER_CLIENT
}
fn default_udp_idle_secs() -> u64 {
    crate::gateway::udp_policy::DEFAULT_IDLE_SECS
}
fn default_reverse_max_listeners() -> usize {
    crate::gateway::reverse_policy::DEFAULT_MAX_LISTENERS
}
fn default_reverse_max_connections_per_listener() -> usize {
    crate::gateway::reverse_policy::DEFAULT_MAX_CONNECTIONS_PER_LISTENER
}
fn default_reverse_backlog() -> u32 {
    crate::gateway::reverse_policy::DEFAULT_BACKLOG
}
fn default_reverse_idle_secs() -> u64 {
    crate::gateway::reverse_policy::DEFAULT_IDLE_SECS
}
fn default_max_buffered_bytes() -> usize {
    crate::gateway::policy::DEFAULT_MAX_BUFFERED_BYTES
}
fn default_max_client_buffered_bytes() -> usize {
    crate::gateway::policy::DEFAULT_MAX_CLIENT_BUFFERED_BYTES
}
fn default_half_close_idle_secs() -> u64 {
    crate::gateway::policy::DEFAULT_HALF_CLOSE_IDLE_SECS
}
fn default_half_close_probe_secs() -> u64 {
    wsh_core::peer_watch::DEFAULT_HALF_CLOSE_PROBE.as_secs()
}

/// `[rpc]` section of the config TOML: typed RPC channels (`Open { kind: "rpc" }`, wsh #85 / #86).
///
/// `wsh-host` (`host.info`, `host.ping`) is always offered while `enabled`.
/// `wsh-fs` (file access over rpc) is offered only when `fs_root` is set, and
/// is confined to that directory exactly as the JS server's `fs` option is.
///
/// ```toml
/// [rpc]
/// enabled = true
/// max_message_bytes = 1048576
/// max_inflight = 64
/// fs_root = "/srv/files"
/// fs_read_only = false
/// fs_max_file_bytes = 67108864
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct RpcSection {
    /// Serve `rpc` channels at all. Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Largest single rpc message, advertised as `rpc-max-message:<n>` (at least 256). Default: 1 MiB.
    #[serde(default = "default_rpc_max_message")]
    pub max_message_bytes: usize,
    /// Concurrent requests per channel before `-32002`. Default: 64.
    #[serde(default = "default_rpc_max_inflight")]
    pub max_inflight: usize,
    /// Directory `wsh-fs` is confined to. Unset (the default): `wsh-fs` is not offered.
    #[serde(default)]
    pub fs_root: Option<String>,
    /// Refuse every `wsh-fs` operation that changes anything. Default: `false`.
    #[serde(default)]
    pub fs_read_only: bool,
    /// Largest file `wsh-fs` will read or write in one operation. Default: 64 MiB.
    #[serde(default = "default_rpc_fs_max_file")]
    pub fs_max_file_bytes: u64,
}

impl Default for RpcSection {
    fn default() -> Self {
        Self {
            enabled: true,
            max_message_bytes: default_rpc_max_message(),
            max_inflight: default_rpc_max_inflight(),
            fs_root: None,
            fs_read_only: false,
            fs_max_file_bytes: default_rpc_fs_max_file(),
        }
    }
}

fn default_rpc_max_message() -> usize {
    crate::rpc::RPC_DEFAULT_MAX_MESSAGE
}
fn default_rpc_max_inflight() -> usize {
    crate::rpc::RPC_DEFAULT_MAX_INFLIGHT
}
fn default_rpc_fs_max_file() -> u64 {
    crate::rpc::fs::DEFAULT_MAX_FILE_BYTES
}

fn default_reverse_bind_addr() -> String {
    "127.0.0.1".to_string()
}
fn default_gateway_max_connections() -> usize {
    100
}

fn default_port() -> u16 {
    4422
}
fn default_cert_path() -> String {
    "~/.wsh/cert.pem".to_string()
}
fn default_key_path() -> String {
    "~/.wsh/key.pem".to_string()
}
fn default_max_sessions() -> usize {
    100
}
fn default_session_ttl() -> u64 {
    86400
}
fn default_idle_timeout() -> u64 {
    3600
}
/// How long a login under `seal_session = "require"` may stay unsealed: three times the
/// 10 s every client step (login, key exchange) is given by default.
fn default_seal_timeout_secs() -> u64 {
    30
}
/// How long a connection may take to complete its login: twice the 30 s a login takes at the
/// client's default of 10 s for each of its three steps, so a person confirming on the client
/// (with its timeout raised to allow it) is not cut off.
fn default_login_timeout_secs() -> u64 {
    60
}
fn default_true() -> bool {
    true
}

/// Resolved server configuration (all paths expanded, CLI overrides applied).
///
/// Produced by [`ServerConfig::load`], which merges TOML file values with
/// command-line overrides and expands `~` in file paths.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Port for the QUIC (WebTransport) listener.
    pub port: u16,
    /// Path to the TLS certificate PEM file (tilde-expanded).
    pub cert_path: PathBuf,
    /// Path to the TLS private key PEM file (tilde-expanded).
    pub key_path: PathBuf,
    /// Maximum number of concurrent authenticated sessions.
    pub max_sessions: usize,
    /// Session token lifetime in seconds.
    pub session_ttl: u64,
    /// Idle timeout in seconds before a session is reaped.
    pub idle_timeout: u64,
    /// Whether the relay (peer-to-peer forwarding) subsystem is enabled.
    pub enable_relay: bool,
    /// See [`RelaySection::max_operators_per_peer`].
    pub relay_max_operators_per_peer: usize,
    /// Whether public-key authentication is accepted.
    pub allow_pubkey: bool,
    /// Whether password authentication is accepted.
    pub allow_password: bool,
    /// Whether the gateway subsystem (TCP/UDP/DNS/listeners) is enabled.
    /// Corresponds to `[gateway] enabled` in the TOML config.
    pub gateway_enabled: bool,
    /// Gateway destination allowlist. See [`GatewaySection::allowed_destinations`].
    pub gateway_allowed_destinations: Vec<String>,
    /// Maximum concurrent gateway connections. See [`GatewaySection::max_connections`].
    pub gateway_max_connections: usize,
    /// Whether reverse tunnel listeners are allowed. See [`GatewaySection::enable_reverse_tunnels`].
    pub gateway_enable_reverse_tunnels: bool,
    /// Where reverse tunnel listeners bind. See [`GatewaySection::reverse_bind_addr`].
    pub gateway_reverse_bind_addr: std::net::IpAddr,
    /// Ports and bounds of reverse tunnel listeners. See [`crate::gateway::reverse_policy`].
    pub gateway_reverse: crate::gateway::reverse_policy::ReversePolicy,
    /// UDP flow count, rates and idle limit. See [`crate::gateway::udp_policy`].
    pub gateway_udp: crate::gateway::udp_policy::UdpPolicy,
    /// Unix-domain socket policy. See [`GatewaySection::unix_connect`].
    pub gateway_unix: crate::gateway::unix_policy::UnixPolicy,
    /// See [`GatewaySection::max_buffered_bytes`].
    pub gateway_max_buffered_bytes: usize,
    /// See [`GatewaySection::max_client_buffered_bytes`].
    pub gateway_max_client_buffered_bytes: usize,
    /// See [`GatewaySection::half_close_idle_secs`].
    pub gateway_half_close_idle_secs: u64,
    /// See [`GatewaySection::half_close_probe_secs`].
    pub gateway_half_close_probe_secs: u64,
    /// Username → usable password hash, for password auth. Entries that could not be
    /// used (an unsalted `sha256:` without `allow_legacy_sha256`, anything unparsable)
    /// are logged at start-up and left out, so those users cannot log in.
    pub password_hashes: std::collections::HashMap<String, StoredHash>,
    /// Whether typed rpc channels are served. See [`RpcSection::enabled`].
    pub rpc_enabled: bool,
    /// Largest rpc message in bytes. See [`RpcSection::max_message_bytes`].
    pub rpc_max_message_bytes: usize,
    /// Concurrent requests per rpc channel. See [`RpcSection::max_inflight`].
    pub rpc_max_inflight: usize,
    /// `wsh-fs` root (tilde-expanded); `None` = `wsh-fs` not offered.
    pub rpc_fs_root: Option<PathBuf>,
    /// `wsh-fs` read-only switch.
    pub rpc_fs_read_only: bool,
    /// `wsh-fs` per-operation size limit.
    pub rpc_fs_max_file_bytes: u64,
    /// CLI tools offered over MCP. See [`McpSection`].
    pub mcp_tools: Vec<McpToolSection>,
    /// Which `Open.env` variables are applied. See [`crate::client_env`].
    pub client_env: crate::client_env::ClientEnvPolicy,
    /// The host key file (tilde-expanded); `None` = no host identity. See [`ServerSection::host_key`].
    pub host_key_path: Option<PathBuf>,
    /// See [`ServerSection::require_channel_binding`].
    pub require_channel_binding: bool,
    /// See [`ServerSection::seal_session`].
    pub seal_session: SealSession,
    /// See [`ServerSection::seal_timeout_secs`] (0 = no deadline).
    pub seal_timeout_secs: u64,
    /// See [`ServerSection::login_timeout_secs`] (0 = no deadline).
    pub login_timeout_secs: u64,
}

impl ServerConfig {
    /// Load configuration from a TOML file, then apply CLI overrides.
    ///
    /// If `config_path` points to a file that does not exist, defaults are
    /// used silently. CLI arguments, when `Some`, take precedence over the
    /// file values.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Optional path to the TOML config file (tilde is expanded).
    /// * `cli_port` - Override for the QUIC listener port.
    /// * `cli_cert` - Override for the TLS certificate path.
    /// * `cli_key` - Override for the TLS key path.
    /// * `cli_max_sessions` - Override for the maximum session count.
    /// * `cli_session_ttl` - Override for the session TTL (seconds).
    /// * `cli_idle_timeout` - Override for the idle timeout (seconds).
    /// * `cli_enable_relay` - Whether the relay subsystem is enabled (CLI flag; no TOML equivalent).
    ///
    /// # Errors
    ///
    /// Returns an error if the config file exists but cannot be read or
    /// contains invalid TOML.
    pub fn load(
        config_path: Option<&Path>,
        cli_port: Option<u16>,
        cli_cert: Option<&str>,
        cli_key: Option<&str>,
        cli_max_sessions: Option<usize>,
        cli_session_ttl: Option<u64>,
        cli_idle_timeout: Option<u64>,
        cli_enable_relay: bool,
    ) -> WshResult<Self> {
        // Load base config from file
        let file_config = if let Some(path) = config_path {
            let expanded = expand_tilde(path);
            if expanded.exists() {
                info!(path = %expanded.display(), "loading config file");
                let content = std::fs::read_to_string(&expanded)?;
                toml::from_str::<ConfigFile>(&content)
                    .map_err(|e| wsh_core::WshError::Other(format!("config parse error: {e}")))?
            } else {
                info!(path = %expanded.display(), "config file not found, using defaults");
                ConfigFile {
                    server: ServerSection::default(),
                    auth: AuthSection::default(),
                    gateway: GatewaySection::default(),
                    rpc: RpcSection::default(),
                    mcp: McpSection::default(),
                    relay: RelaySection::default(),
                }
            }
        } else {
            ConfigFile {
                server: ServerSection::default(),
                auth: AuthSection::default(),
                gateway: GatewaySection::default(),
                rpc: RpcSection::default(),
                mcp: McpSection::default(),
                relay: RelaySection::default(),
            }
        };

        // Merge CLI overrides
        let port = cli_port.unwrap_or(file_config.server.port);
        let cert_str = cli_cert
            .map(|s| s.to_string())
            .unwrap_or(file_config.server.cert);
        let key_str = cli_key
            .map(|s| s.to_string())
            .unwrap_or(file_config.server.key);
        let max_sessions = cli_max_sessions.unwrap_or(file_config.server.max_sessions);
        let session_ttl = cli_session_ttl.unwrap_or(file_config.server.session_ttl);
        let idle_timeout = cli_idle_timeout.unwrap_or(file_config.server.idle_timeout);

        let gateway_reverse_bind_addr: std::net::IpAddr =
            file_config.gateway.reverse_bind_addr.parse().map_err(|_| {
                wsh_core::WshError::Other(format!(
                    "config: [gateway] reverse_bind_addr '{}' is not an IP address",
                    file_config.gateway.reverse_bind_addr
                ))
            })?;
        let password_hashes = parse_password_hashes(&file_config.auth);
        let client_env = crate::client_env::ClientEnvPolicy::from_setting(
            file_config.server.client_env.as_ref(),
        )
        .map_err(wsh_core::WshError::Other)?;
        if client_env == crate::client_env::ClientEnvPolicy::Everything {
            warn!("[server] client_env = true: a client can set any environment variable (PATH, LD_PRELOAD...) for what it runs");
        }
        let gateway_reverse = crate::gateway::reverse_policy::ReversePolicy::new(
            file_config.gateway.reverse_ports.as_deref(),
            file_config.gateway.reverse_max_listeners,
            file_config.gateway.reverse_max_connections_per_listener,
            file_config.gateway.reverse_backlog,
            file_config.gateway.reverse_idle_secs,
        )
        .map_err(wsh_core::WshError::Other)?;
        let gateway_udp = crate::gateway::udp_policy::UdpPolicy::new(
            file_config.gateway.udp_max_flows,
            file_config.gateway.udp_packets_per_second_per_flow,
            file_config.gateway.udp_packets_per_second_per_client,
            file_config.gateway.udp_bytes_per_second_per_client,
            file_config.gateway.udp_idle_secs,
        )
        .map_err(wsh_core::WshError::Other)?
        .with_datagrams(
            file_config.gateway.udp_datagrams,
            crate::gateway::udp_policy::Oversize::parse(&file_config.gateway.udp_oversize)
                .map_err(wsh_core::WshError::Other)?,
        );
        let gateway_unix = crate::gateway::unix_policy::UnixPolicy::new(
            file_config.gateway.unix_connect.clone(),
            file_config.gateway.unix_listen.clone(),
            file_config.gateway.unix_replace_stale,
            file_config.gateway.unix_max_listeners,
        )
        .map_err(wsh_core::WshError::Other)?;
        let (max_buffered, max_client_buffered) = (
            file_config.gateway.max_buffered_bytes,
            file_config.gateway.max_client_buffered_bytes,
        );
        if max_buffered < crate::gateway::session::GATEWAY_CREDIT_WINDOW {
            return Err(wsh_core::WshError::Other(format!(
                "config: [gateway] max_buffered_bytes must be at least {}",
                crate::gateway::session::GATEWAY_CREDIT_WINDOW
            )));
        }
        if max_client_buffered < max_buffered {
            return Err(wsh_core::WshError::Other(
                "config: [gateway] max_client_buffered_bytes must be at least max_buffered_bytes"
                    .into(),
            ));
        }
        warn_about_gateway(&file_config.gateway, gateway_reverse_bind_addr);
        if file_config.server.require_channel_binding && file_config.server.host_key.is_none() {
            return Err(wsh_core::WshError::Other(
                "config: [server] require_channel_binding = true needs [server] host_key: the server \
                 has nothing to bind a login to without its own key, so nobody could log in"
                    .into(),
            ));
        }
        if file_config.server.seal_session != SealSession::Off
            && file_config.server.host_key.is_none()
        {
            return Err(wsh_core::WshError::Other(
                "config: [server] seal_session = \"offer\" or \"require\" needs [server] host_key: the \
                 server signs its half of the key exchange with its own key, and a client has nothing \
                 to authenticate the exchange against without it"
                    .into(),
            ));
        }

        if !(1..=MAX_RELAY_OPERATORS_PER_PEER).contains(&file_config.relay.max_operators_per_peer) {
            return Err(wsh_core::WshError::Other(format!(
                "config: [relay] max_operators_per_peer must be between 1 and {MAX_RELAY_OPERATORS_PER_PEER}"
            )));
        }

        Ok(Self {
            port,
            cert_path: expand_tilde_str(&cert_str),
            key_path: expand_tilde_str(&key_str),
            max_sessions,
            session_ttl,
            idle_timeout,
            enable_relay: cli_enable_relay,
            relay_max_operators_per_peer: file_config.relay.max_operators_per_peer,
            allow_pubkey: file_config.auth.allow_pubkey,
            allow_password: file_config.auth.allow_password,
            gateway_enabled: file_config.gateway.enabled,
            gateway_allowed_destinations: file_config.gateway.allowed_destinations,
            gateway_max_connections: file_config.gateway.max_connections,
            gateway_enable_reverse_tunnels: file_config.gateway.enable_reverse_tunnels,
            gateway_reverse_bind_addr,
            gateway_reverse,
            gateway_udp,
            gateway_unix,
            gateway_max_buffered_bytes: max_buffered,
            gateway_max_client_buffered_bytes: max_client_buffered,
            gateway_half_close_idle_secs: file_config.gateway.half_close_idle_secs,
            gateway_half_close_probe_secs: file_config.gateway.half_close_probe_secs,
            password_hashes,
            rpc_enabled: file_config.rpc.enabled,
            rpc_max_message_bytes: file_config.rpc.max_message_bytes,
            rpc_max_inflight: file_config.rpc.max_inflight,
            rpc_fs_root: file_config.rpc.fs_root.as_deref().map(expand_tilde_str),
            rpc_fs_read_only: file_config.rpc.fs_read_only,
            rpc_fs_max_file_bytes: file_config.rpc.fs_max_file_bytes,
            mcp_tools: file_config.mcp.tools,
            client_env,
            host_key_path: file_config.server.host_key.as_deref().map(expand_tilde_str),
            require_channel_binding: file_config.server.require_channel_binding,
            seal_session: file_config.server.seal_session,
            seal_timeout_secs: file_config.server.seal_timeout_secs,
            login_timeout_secs: file_config.server.login_timeout_secs,
        })
    }
}

/// Parse `[auth.password_hashes]`, saying so -- loudly, once, at start-up -- about every
/// entry that cannot be used and every legacy entry that is.
fn parse_password_hashes(auth: &AuthSection) -> HashMap<String, StoredHash> {
    let mut usable = HashMap::new();
    for (user, value) in &auth.password_hashes {
        match StoredHash::parse(value, auth.allow_legacy_sha256) {
            Ok(hash) => {
                if matches!(hash, StoredHash::LegacySha256(_)) {
                    warn!(
                        user = %user,
                        "DEPRECATED: [auth.password_hashes] entry is an unsalted SHA-256 hash, accepted only \
                         because allow_legacy_sha256 = true. Anyone who reads this file can guess passwords \
                         at billions per second. Replace it: printf '%s' \"$PASSWORD\" | wsh-server --hash-password"
                    );
                }
                usable.insert(user.clone(), hash);
            }
            Err(problem) => error!(
                user = %user,
                "[auth.password_hashes] entry ignored, so this user cannot log in with a password: {problem}"
            ),
        }
    }
    if auth.allow_password && usable.is_empty() {
        warn!("[auth] allow_password = true but no usable password_hashes: nobody can log in with a password");
    }
    if !auth.allow_password && !auth.password_hashes.is_empty() {
        warn!(
            "[auth.password_hashes] has entries but password login is off: set `allow_password = true` under [auth] to use them"
        );
    }
    usable
}

/// Say what an enabled gateway exposes, so it is not a surprise in the log.
fn warn_about_gateway(gateway: &GatewaySection, reverse_bind_addr: std::net::IpAddr) {
    if !gateway.enabled {
        if gateway.enable_reverse_tunnels
            || !gateway.allowed_destinations.is_empty()
            || !gateway.unix_connect.is_empty()
            || !gateway.unix_listen.is_empty()
        {
            warn!("[gateway] has settings but `enabled = false`: the gateway stays off");
        }
        return;
    }
    if !gateway.unix_connect.is_empty() || !gateway.unix_listen.is_empty() {
        warn!(
            connect = ?gateway.unix_connect,
            listen = ?gateway.unix_listen,
            "[gateway] unix sockets are reachable by every authorized client: a socket such as Docker's is as powerful as the daemon behind it"
        );
    }
    if gateway.allowed_destinations.is_empty() {
        warn!("[gateway] enabled with no allowed_destinations: every outbound connection will be refused");
    }
    if gateway.allowed_destinations.iter().any(|d| d == "*") {
        info!("[gateway] allowed_destinations contains \"*\": any authorized client can use this host to reach the public internet (not its own network, unless a rule names it)");
    }
    if gateway.enable_reverse_tunnels && !reverse_bind_addr.is_loopback() {
        warn!(
            bind = %reverse_bind_addr,
            "[gateway] reverse listeners are reachable from the network: reverse_bind_addr is not a loopback address"
        );
    }
}

/// Expand `~` to the user's home directory.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    expand_tilde_str(&s)
}

pub(crate) fn expand_tilde_str(s: &str) -> PathBuf {
    if s.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&s[2..]);
        }
    }
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name of a scratch directory for one config test (not created yet). The process id keeps two
    /// test processes apart and a process-wide counter keeps two tests of this process apart: unlike a
    /// clock, the counter cannot give two callers the same value (wsh #248; the same scheme as the
    /// known-hosts tests of `wsh-client`).
    fn scratch_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("wsh-config-{tag}-{}-{n}", std::process::id()))
    }

    /// A fresh, empty scratch directory for one config test. A directory left behind under the same
    /// name by an earlier process that had this process id is removed first.
    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = scratch_path(tag);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn scratch_directories_never_share_a_name_within_one_process() {
        use std::collections::HashSet;
        const THREADS: usize = 8;
        const PER_THREAD: usize = 2_000;
        let names: Vec<PathBuf> = (0..THREADS)
            .map(|_| {
                std::thread::spawn(|| {
                    (0..PER_THREAD)
                        .map(|_| scratch_path("t"))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        let distinct: HashSet<&PathBuf> = names.iter().collect();
        assert_eq!(
            distinct.len(),
            names.len(),
            "two scratch directories got one name"
        );
    }

    fn load(toml_text: &str) -> ServerConfig {
        let dir = scratch_dir("test");
        let path = dir.join("config.toml");
        std::fs::write(&path, toml_text).unwrap();
        let cfg = ServerConfig::load(Some(&path), None, None, None, None, None, None, false)
            .expect("config loads");
        std::fs::remove_dir_all(&dir).ok();
        cfg
    }

    fn load_defaults() -> ServerConfig {
        ServerConfig::load(None, None, None, None, None, None, None, false).unwrap()
    }

    // ── client_env: allow-list by default (BREAKING, wsh #126 / #145) ──

    #[test]
    fn client_env_defaults_to_the_allow_list_and_the_changelog_line_restores_the_old_behaviour() {
        use crate::client_env::ClientEnvPolicy;
        for cfg in [load_defaults(), load("")] {
            assert_eq!(cfg.client_env, ClientEnvPolicy::default());
            let kept = cfg.client_env.filter(Some(
                &[
                    ("PATH".to_string(), "/x".to_string()),
                    ("LC_ALL".to_string(), "C".to_string()),
                ]
                .into(),
            ));
            assert_eq!(kept.unwrap().keys().collect::<Vec<_>>(), ["LC_ALL"]);
        }
        // The exact line the CHANGELOG gives:
        let cfg = load("[server]\nclient_env = true\n");
        assert_eq!(cfg.client_env, ClientEnvPolicy::Everything);
        let kept = cfg
            .client_env
            .filter(Some(&[("PATH".to_string(), "/x".to_string())].into()));
        assert!(kept.unwrap().contains_key("PATH"));
    }

    // ── gateway: off, deny, loopback ─────────────────────────────────

    #[test]
    fn the_gateway_is_off_by_default_and_allows_nothing() {
        for cfg in [load_defaults(), load("")] {
            assert!(!cfg.gateway_enabled);
            assert!(cfg.gateway_allowed_destinations.is_empty());
            assert!(!cfg.gateway_enable_reverse_tunnels);
            assert!(cfg.gateway_reverse_bind_addr.is_loopback());
        }
    }

    #[test]
    fn enabling_the_gateway_does_not_enable_destinations_or_reverse_tunnels() {
        let cfg = load("[gateway]\nenabled = true\n");
        assert!(cfg.gateway_enabled);
        assert!(cfg.gateway_allowed_destinations.is_empty(), "default-deny");
        assert!(!cfg.gateway_enable_reverse_tunnels);
        assert_eq!(cfg.gateway_reverse_bind_addr.to_string(), "127.0.0.1");
    }

    #[test]
    fn the_half_closed_origin_probe_defaults_to_two_seconds_and_can_be_changed_or_turned_off() {
        assert_eq!(
            load("[gateway]\nenabled = true\n").gateway_half_close_probe_secs,
            2
        );
        assert_eq!(
            load("[gateway]\nenabled = true\nhalf_close_probe_secs = 5\n")
                .gateway_half_close_probe_secs,
            5
        );
        assert_eq!(
            load("[gateway]\nenabled = true\nhalf_close_probe_secs = 0\n")
                .gateway_half_close_probe_secs,
            0,
            "0 turns the watch off"
        );
    }

    #[test]
    fn a_half_closed_connection_idle_bound_defaults_to_five_minutes_and_can_be_changed_or_turned_off(
    ) {
        assert_eq!(
            load("[gateway]\nenabled = true\n").gateway_half_close_idle_secs,
            300
        );
        assert_eq!(
            load("[gateway]\nenabled = true\nhalf_close_idle_secs = 60\n")
                .gateway_half_close_idle_secs,
            60
        );
        assert_eq!(
            load("[gateway]\nenabled = true\nhalf_close_idle_secs = 0\n")
                .gateway_half_close_idle_secs,
            0,
            "0 turns the bound off"
        );
    }

    #[test]
    fn the_old_behaviour_is_restored_by_the_lines_in_the_changelog() {
        let cfg = load(
            r#"
[gateway]
enabled = true
allowed_destinations = ["*", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1", "fc00::/7", "fe80::/10"]
enable_reverse_tunnels = true
reverse_bind_addr = "0.0.0.0"
"#,
        );
        assert!(cfg.gateway_enabled && cfg.gateway_enable_reverse_tunnels);
        assert_eq!(cfg.gateway_reverse_bind_addr.to_string(), "0.0.0.0");
        let policy = crate::gateway::policy::GatewayPolicyEnforcer::new(
            crate::gateway::policy::GatewayPolicy {
                allowed_destinations: cfg.gateway_allowed_destinations.clone(),
                max_connections: cfg.gateway_max_connections,
                enable_reverse_tunnels: cfg.gateway_enable_reverse_tunnels,
                reverse_bind_addr: cfg.gateway_reverse_bind_addr,
                ..Default::default()
            },
        );
        for (host, addr) in [
            ("example.com", "93.184.216.34"),
            ("127.0.0.1", "127.0.0.1"),
            ("db", "10.0.0.5"),
            ("meta", "169.254.169.254"),
            ("::1", "::1"),
        ] {
            assert!(policy.check_connect(host, 80).is_ok(), "{host}");
            assert!(
                !policy
                    .authorize_addrs(host, Some(80), &[addr.parse().unwrap()])
                    .is_empty(),
                "{host} -> {addr} should be reachable again with those lines"
            );
        }
    }

    #[test]
    fn a_reverse_bind_address_that_is_not_an_address_is_an_error() {
        let dir = scratch_dir("bad");
        let path = dir.join("config.toml");
        std::fs::write(&path, "[gateway]\nreverse_bind_addr = \"all interfaces\"\n").unwrap();
        let result = ServerConfig::load(Some(&path), None, None, None, None, None, None, false);
        std::fs::remove_dir_all(&dir).ok();
        assert!(result.is_err());
    }

    // ── sealed sessions (#155): off by default, `offer` / `require` need the host key ──

    fn load_err(toml_text: &str) -> String {
        let dir = scratch_dir("seal");
        let path = dir.join("config.toml");
        std::fs::write(&path, toml_text).unwrap();
        let result = ServerConfig::load(Some(&path), None, None, None, None, None, None, false);
        std::fs::remove_dir_all(&dir).ok();
        result.err().expect("config is refused").to_string()
    }

    #[test]
    fn the_relay_takes_one_operator_per_peer_unless_the_config_says_more() {
        assert_eq!(load_defaults().relay_max_operators_per_peer, 1);
        assert_eq!(load("").relay_max_operators_per_peer, 1);
        assert_eq!(
            load("[relay]\nmax_operators_per_peer = 4\n").relay_max_operators_per_peer,
            4
        );
        for bad in ["0", "65", "-1"] {
            let err = load_err(&format!("[relay]\nmax_operators_per_peer = {bad}\n"));
            assert!(
                err.contains("max_operators_per_peer"),
                "{bad} is refused: {err}"
            );
        }
    }

    #[test]
    fn seal_session_is_off_by_default_so_no_released_client_is_affected() {
        assert_eq!(load_defaults().seal_session, SealSession::Off);
        assert_eq!(load("").seal_session, SealSession::Off);
        assert_eq!(
            load("[server]\nseal_session = \"off\"\n").seal_session,
            SealSession::Off
        );
    }

    #[test]
    fn seal_session_offer_and_require_load_with_a_host_key() {
        let offer = load("[server]\nhost_key = \"/tmp/k\"\nseal_session = \"offer\"\n");
        assert_eq!(offer.seal_session, SealSession::Offer);
        let require = load("[server]\nhost_key = \"/tmp/k\"\nseal_session = \"require\"\n");
        assert_eq!(require.seal_session, SealSession::Require);
    }

    #[test]
    fn seal_session_needs_a_host_key_and_a_known_value() {
        for mode in ["offer", "require"] {
            let e = load_err(&format!("[server]\nseal_session = \"{mode}\"\n"));
            assert!(e.contains("seal_session") && e.contains("host_key"), "{e}");
        }
        let e = load_err("[server]\nhost_key = \"/tmp/k\"\nseal_session = \"yes\"\n");
        assert!(e.contains("seal_session") || e.contains("yes"), "{e}");
    }

    #[test]
    fn seal_timeout_defaults_to_thirty_seconds_and_is_configurable() {
        assert_eq!(load_defaults().seal_timeout_secs, 30);
        assert_eq!(load("").seal_timeout_secs, 30);
        let set = load(
            "[server]\nhost_key = \"/tmp/k\"\nseal_session = \"require\"\nseal_timeout_secs = 5\n",
        );
        assert_eq!(set.seal_timeout_secs, 5);
        let off = load("[server]\nseal_timeout_secs = 0\n");
        assert_eq!(off.seal_timeout_secs, 0, "0 turns the deadline off");
    }

    #[test]
    fn seal_timeout_must_be_a_whole_number_of_seconds() {
        for bad in ["-1", "\"soon\"", "1.5"] {
            let e = load_err(&format!("[server]\nseal_timeout_secs = {bad}\n"));
            assert!(
                e.contains("seal_timeout_secs") || e.contains("invalid"),
                "{bad}: {e}"
            );
        }
    }

    #[test]
    fn login_timeout_defaults_to_sixty_seconds_and_is_configurable() {
        assert_eq!(load_defaults().login_timeout_secs, 60);
        assert_eq!(load("").login_timeout_secs, 60);
        let set = load("[server]\nlogin_timeout_secs = 5\n");
        assert_eq!(set.login_timeout_secs, 5);
        let off = load("[server]\nlogin_timeout_secs = 0\n");
        assert_eq!(off.login_timeout_secs, 0, "0 turns the deadline off");
    }

    #[test]
    fn login_timeout_must_be_a_whole_number_of_seconds() {
        for bad in ["-1", "\"soon\"", "1.5"] {
            let e = load_err(&format!("[server]\nlogin_timeout_secs = {bad}\n"));
            assert!(
                e.contains("login_timeout_secs") || e.contains("invalid"),
                "{bad}: {e}"
            );
        }
    }

    // ── passwords: off, salted, no legacy ────────────────────────────

    #[test]
    fn password_login_is_off_by_default_even_with_hashes_configured() {
        assert!(!load_defaults().allow_password);
        let hash = crate::auth::password::hash_password("pw").unwrap();
        let cfg = load(&format!("[auth.password_hashes]\nalice = '{hash}'\n"));
        assert!(!cfg.allow_password);
        assert!(cfg.allow_pubkey);
    }

    #[test]
    fn argon2id_hashes_load_and_verify() {
        let hash = crate::auth::password::hash_password("pw").unwrap();
        let cfg = load(&format!(
            "[auth]\nallow_password = true\n[auth.password_hashes]\nalice = '{hash}'\n"
        ));
        assert!(cfg.allow_password);
        assert!(cfg.password_hashes["alice"].verify("pw"));
        assert!(!cfg.password_hashes["alice"].verify("nope"));
    }

    #[test]
    fn legacy_sha256_entries_are_dropped_unless_allowed() {
        let legacy = "sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        let off = load(&format!(
            "[auth]\nallow_password = true\n[auth.password_hashes]\nbob = '{legacy}'\n"
        ));
        assert!(
            off.password_hashes.is_empty(),
            "refused, so bob cannot log in"
        );
        let on = load(&format!("[auth]\nallow_password = true\nallow_legacy_sha256 = true\n[auth.password_hashes]\nbob = '{legacy}'\n"));
        assert!(on.password_hashes["bob"].verify("password"));
    }
}
