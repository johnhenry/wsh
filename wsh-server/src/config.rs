//! Server configuration: TOML file + CLI overrides.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use tracing::info;
use wsh_core::WshResult;

/// Top-level config file structure.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub auth: AuthSection,
    #[serde(default)]
    pub gateway: GatewaySection,
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
        }
    }
}

/// `[auth]` section of the config TOML.
///
/// # Password Authentication
///
/// To enable password auth, set `allow_password = true` and add entries
/// to `password_hashes`:
///
/// ```toml
/// [auth]
/// allow_password = true
///
/// [auth.password_hashes]
/// alice = "sha256:e3b0c44298fc..."  # SHA-256 hex digest of password
/// bob = "sha256:5e884898da28..."
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct AuthSection {
    #[serde(default = "default_true")]
    pub allow_pubkey: bool,
    #[serde(default = "default_true")]
    pub allow_password: bool,
    /// Username → "sha256:<hex>" password hash pairs.
    #[serde(default)]
    pub password_hashes: std::collections::HashMap<String, String>,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            allow_pubkey: true,
            allow_password: true,
            password_hashes: std::collections::HashMap::new(),
        }
    }
}

/// `[gateway]` section of the config TOML.
///
/// Controls the gateway subsystem that handles TCP/UDP forwarding, DNS
/// resolution, and reverse tunnel listeners.
///
/// # TOML Example
///
/// ```toml
/// [gateway]
/// enabled = true
/// allowed_destinations = ["example.com", "10.0.0.0/8:443", "*"]
/// max_connections = 100
/// enable_reverse_tunnels = true
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct GatewaySection {
    /// Master switch for the gateway subsystem.
    ///
    /// When `false`, all gateway message types (`OpenTcp`, `OpenUdp`,
    /// `ResolveDns`, `ListenRequest`) are rejected with error code 5
    /// (`GATEWAY_DISABLED`).
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Destination allowlist for outbound connections.
    ///
    /// Supports exact hostnames (`"example.com"`), exact host:port pairs
    /// (`"example.com:443"`), or a wildcard (`"*"`) to allow all.
    /// An empty list blocks all outbound connections.
    ///
    /// Default: `["*"]` (allow all).
    #[serde(default = "default_gateway_destinations")]
    pub allowed_destinations: Vec<String>,
    /// Maximum number of concurrent gateway connections (TCP + UDP +
    /// reverse tunnel listeners combined).
    ///
    /// Default: `100`.
    #[serde(default = "default_gateway_max_connections")]
    pub max_connections: usize,
    /// Whether clients may open reverse tunnel listeners via `ListenRequest`.
    ///
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub enable_reverse_tunnels: bool,
}

impl Default for GatewaySection {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_destinations: default_gateway_destinations(),
            max_connections: default_gateway_max_connections(),
            enable_reverse_tunnels: true,
        }
    }
}

fn default_gateway_destinations() -> Vec<String> {
    vec!["*".to_string()]
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
    /// Username → "sha256:<hex>" password hash pairs for password auth.
    pub password_hashes: std::collections::HashMap<String, String>,
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
                }
            }
        } else {
            ConfigFile {
                server: ServerSection::default(),
                auth: AuthSection::default(),
                gateway: GatewaySection::default(),
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
            password_hashes: file_config.auth.password_hashes,
        })
    }
}

/// Expand `~` to the user's home directory.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    expand_tilde_str(&s)
}

fn expand_tilde_str(s: &str) -> PathBuf {
    if s.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&s[2..]);
        }
    }
    PathBuf::from(s)
}
