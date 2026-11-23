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
}

impl Default for GatewaySection {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_destinations: Vec::new(),
            max_connections: default_gateway_max_connections(),
            enable_reverse_tunnels: false,
            reverse_bind_addr: default_reverse_bind_addr(),
        }
    }
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
                }
            }
        } else {
            ConfigFile {
                server: ServerSection::default(),
                auth: AuthSection::default(),
                gateway: GatewaySection::default(),
                rpc: RpcSection::default(),
                mcp: McpSection::default(),
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
        let client_env =
            crate::client_env::ClientEnvPolicy::from_setting(file_config.server.client_env.as_ref())
                .map_err(wsh_core::WshError::Other)?;
        if client_env == crate::client_env::ClientEnvPolicy::Everything {
            warn!("[server] client_env = true: a client can set any environment variable (PATH, LD_PRELOAD...) for what it runs");
        }
        warn_about_gateway(&file_config.gateway, gateway_reverse_bind_addr);

        Ok(Self {
            port,
            cert_path: expand_tilde_str(&cert_str),
            key_path: expand_tilde_str(&key_str),
            max_sessions,
            session_ttl,
            idle_timeout,
            enable_relay: cli_enable_relay,
            allow_pubkey: file_config.auth.allow_pubkey,
            allow_password: file_config.auth.allow_password,
            gateway_enabled: file_config.gateway.enabled,
            gateway_allowed_destinations: file_config.gateway.allowed_destinations,
            gateway_max_connections: file_config.gateway.max_connections,
            gateway_enable_reverse_tunnels: file_config.gateway.enable_reverse_tunnels,
            gateway_reverse_bind_addr,
            password_hashes,
            rpc_enabled: file_config.rpc.enabled,
            rpc_max_message_bytes: file_config.rpc.max_message_bytes,
            rpc_max_inflight: file_config.rpc.max_inflight,
            rpc_fs_root: file_config.rpc.fs_root.as_deref().map(expand_tilde_str),
            rpc_fs_read_only: file_config.rpc.fs_read_only,
            rpc_fs_max_file_bytes: file_config.rpc.fs_max_file_bytes,
            mcp_tools: file_config.mcp.tools,
            client_env,
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
        if gateway.enable_reverse_tunnels || !gateway.allowed_destinations.is_empty() {
            warn!("[gateway] has settings but `enabled = false`: the gateway stays off");
        }
        return;
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

    fn load(toml_text: &str) -> ServerConfig {
        let dir = std::env::temp_dir().join(format!(
            "wsh-config-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
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
                &[("PATH".to_string(), "/x".to_string()), ("LC_ALL".to_string(), "C".to_string())].into(),
            ));
            assert_eq!(kept.unwrap().keys().collect::<Vec<_>>(), ["LC_ALL"]);
        }
        // The exact line the CHANGELOG gives:
        let cfg = load("[server]\nclient_env = true\n");
        assert_eq!(cfg.client_env, ClientEnvPolicy::Everything);
        let kept = cfg.client_env.filter(Some(&[("PATH".to_string(), "/x".to_string())].into()));
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
        let dir = std::env::temp_dir().join(format!("wsh-config-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "[gateway]\nreverse_bind_addr = \"all interfaces\"\n").unwrap();
        let result = ServerConfig::load(Some(&path), None, None, None, None, None, None, false);
        std::fs::remove_dir_all(&dir).ok();
        assert!(result.is_err());
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
