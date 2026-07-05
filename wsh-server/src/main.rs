//! wsh-server: Web Shell server.
//!
//! Accepts WebTransport (QUIC) and WebSocket connections, authenticates
//! clients via public key or password, and provides PTY-backed shell sessions.

mod auth;
mod config;
mod gateway;
mod handshake;
mod mcp;
mod relay;
mod server;
mod session;
mod transport;

use clap::Parser;
use config::ServerConfig;
use rustls::crypto::ring;
use server::WshServer;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

/// wsh-server — Web Shell server
#[derive(Parser, Debug)]
#[command(name = "wsh-server", version, about = "Web Shell server")]
struct Cli {
    /// Listen port
    #[arg(short, long, default_value_t = 4422)]
    port: u16,

    /// TLS certificate (PEM)
    #[arg(long)]
    cert: Option<String>,

    /// TLS private key (PEM)
    #[arg(long)]
    key: Option<String>,

    /// Config file path
    #[arg(long, default_value = "~/.wsh/config.toml")]
    config: String,

    /// Generate self-signed certificate for development
    #[arg(long)]
    generate_cert: bool,

    /// Accept reverse (relay) connections
    #[arg(long)]
    enable_relay: bool,

    /// Maximum concurrent sessions
    #[arg(long)]
    max_sessions: Option<usize>,

    /// Session time-to-live in seconds
    #[arg(long)]
    session_ttl: Option<u64>,

    /// Idle timeout in seconds (detached sessions)
    #[arg(long)]
    idle_timeout: Option<u64>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() {
    install_rustls_crypto_provider();

    let cli = Cli::parse();

    // Initialize tracing
    use tracing_subscriber::EnvFilter;
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        port = cli.port,
        "starting wsh-server"
    );

    // Resolve cert/key paths
    let (cert_path, key_path) = if cli.generate_cert {
        match generate_self_signed_cert() {
            Ok((c, k)) => {
                info!(cert = %c.display(), key = %k.display(), "generated self-signed certificate");
                (Some(c), Some(k))
            }
            Err(e) => {
                error!(error = %e, "failed to generate self-signed certificate");
                std::process::exit(1);
            }
        }
    } else {
        (
            cli.cert.as_ref().map(PathBuf::from),
            cli.key.as_ref().map(PathBuf::from),
        )
    };

    // Load server config (file + CLI overrides)
    let config_path = PathBuf::from(&cli.config);
    let server_config = match ServerConfig::load(
        Some(&config_path),
        Some(cli.port),
        cert_path.as_ref().and_then(|p| p.to_str()),
        key_path.as_ref().and_then(|p| p.to_str()),
        cli.max_sessions,
        cli.session_ttl,
        cli.idle_timeout,
        cli.enable_relay,
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(error = %e, "failed to load config");
            std::process::exit(1);
        }
    };

    // Load TLS config
    let tls_config = match load_tls_config(&server_config.cert_path, &server_config.key_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(error = %e, "failed to load TLS config");
            std::process::exit(1);
        }
    };

    // Create server
    let wsh_server = match WshServer::new(server_config) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to create server");
            std::process::exit(1);
        }
    };

    // Run until shutdown signal
    let tls_arc = Arc::new(tls_config);

    tokio::select! {
        result = wsh_server.run(tls_arc) => {
            if let Err(e) = result {
                error!(error = %e, "server error");
                std::process::exit(1);
            }
        }
        _ = shutdown_signal() => {
            info!("received shutdown signal");
        }
    }

    info!("wsh-server stopped");
}

fn install_rustls_crypto_provider() {
    let _ = ring::default_provider().install_default();
}

/// Load TLS certificate and key from PEM files, returning a rustls ServerConfig.
///
/// Uses `rustls-pki-types`'s built-in `pem::PemObject` parsing directly
/// (rather than the `rustls-pemfile` crate, which is flagged unmaintained —
/// RUSTSEC-2025-0134) since `rustls-pki-types` is already a transitive
/// dependency of `rustls` and provides the same PEM-section extraction.
fn load_tls_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    use rustls::pki_types::pem::PemObject;

    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| format!("cannot read cert {}: {e}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| format!("cannot read key {}: {e}", key_path.display()))?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<Vec<_>, _>>()?;

    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Enable ALPN for WebTransport (h3) and HTTP/1.1 (websocket upgrade)
    tls_config.alpn_protocols = vec![b"h3".to_vec(), b"http/1.1".to_vec()];

    Ok(tls_config)
}

/// Generate a self-signed certificate for development use.
fn generate_self_signed_cert() -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let wsh_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".wsh");
    std::fs::create_dir_all(&wsh_dir)?;

    let cert_path = wsh_dir.join("cert.pem");
    let key_path = wsh_dir.join("key.pem");

    // Generate using rcgen
    let mut params = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "wsh-server dev cert");

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;

    Ok((cert_path, key_path))
}

/// Wait for SIGTERM or SIGINT (Ctrl+C).
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}
