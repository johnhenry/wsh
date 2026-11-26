//! wsh-server: Web Shell server.
//!
//! Accepts WebTransport (QUIC) and WebSocket connections, authenticates
//! clients via public key or password, and provides PTY-backed shell sessions.

mod auth;
mod client_env;
mod config;
// The gateway lives in `wsh-core` (the CLI's reverse host serves the same one); `crate::gateway::...` paths keep working.
use wsh_core::gateway;
mod handshake;
mod host_key;
mod mcp;
mod relay;
mod rpc;
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

    /// Read a password from standard input (first line) and print its Argon2id hash for
    /// `[auth.password_hashes]`, then exit. Pipe it in so it stays out of the process list
    /// and shell history: printf '%s' "$PASSWORD" | wsh-server --hash-password
    #[arg(long)]
    hash_password: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Print the Argon2id hash of a password, for `[auth.password_hashes]`. The password is read from
    /// standard input (first line) or, at a terminal, prompted for without echo; it is never an argument.
    HashPassword,
}

/// `hash-password` / `--hash-password`: stdin (or a no-echo prompt at a terminal) in, a PHC string on
/// stdout, a status code out.
fn hash_password_from_stdin() -> i32 {
    use std::io::{BufRead as _, IsTerminal as _};
    let password = if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        match dialoguer::Password::new()
            .with_prompt("Password")
            .with_confirmation("Repeat password", "The passwords differ")
            .interact()
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("wsh-server: cannot read the password: {e}");
                return 1;
            }
        }
    } else {
        let mut line = String::new();
        if let Err(e) = std::io::stdin().lock().read_line(&mut line) {
            eprintln!("wsh-server: cannot read the password: {e}");
            return 1;
        }
        line.trim_end_matches(['\n', '\r']).to_string()
    };
    let password = password.as_str();
    if password.is_empty() {
        eprintln!("wsh-server: refusing to hash an empty password");
        return 1;
    }
    match auth::password::hash_password(password) {
        Ok(hash) => {
            println!("{hash}");
            0
        }
        Err(e) => {
            eprintln!("wsh-server: hashing failed: {e}");
            1
        }
    }
}

#[tokio::main]
async fn main() {
    install_rustls_crypto_provider();

    let cli = Cli::parse();

    if cli.hash_password || matches!(cli.command, Some(Command::HashPassword)) {
        std::process::exit(hash_password_from_stdin());
    }

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
/// The SHA-256 of a DER certificate as lowercase hex: the value a client pins the server to.
fn cert_sha256_hex(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(der))
}

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

    if let Some(leaf) = certs.first() {
        // What a client pins a self-signed server to: `wsh --cert-hash`, or `serverCertificateHashes`
        // in a browser or the JS client. (A certificate a public authority signed needs no pin.)
        info!(
            sha256 = %cert_sha256_hex(leaf.as_ref()),
            "certificate hash, for `wsh --cert-hash` / serverCertificateHashes (self-signed certificates only)"
        );
    }

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Enable ALPN for WebTransport (h3) and HTTP/1.1 (websocket upgrade)
    tls_config.alpn_protocols = vec![b"h3".to_vec(), b"http/1.1".to_vec()];

    Ok(tls_config)
}

/// Generate a self-signed certificate for development use.
///
/// `not_before`/`not_after` and `is_ca` are set explicitly rather than left
/// at rcgen's defaults (a cert with an intentionally "forever" validity
/// window, 1975-01-01..4096-01-01, and no Basic Constraints / Subject or
/// Authority Key Identifier extensions at all).
///
/// The validity window specifically must be **at most 14 days**: the
/// WebTransport spec's certificate-hash-pinning algorithm
/// (`serverCertificateHashes`, used by any client — browser or
/// `@fails-components/webtransport`'s Node binding, both used against this
/// server in `tools/wsh-server.mjs`/`tools/test/wsh-rust-server.test.mjs`
/// respectively — connecting to a self-signed dev cert instead of a
/// CA-trusted one) requires it, alongside SHA-256 hashes and a non-RSA key
/// (already satisfied — ECDSA P-256 below). A from-scratch, one-variable-
/// at-a-time investigation (see docs/WSH-INTO-CLAWSER.md) initially missed
/// this and wrongly concluded a rcgen-vs-openssl WebTransport interop
/// failure was unresolvable: a 365-day cert (well past the 14-day cap) was
/// tested and correctly failed, but a 13-day cert generated earlier in that
/// same investigation had actually succeeded and was misread as a stale-
/// process false positive. 13 days here, matching the cert that verified
/// working, with a day of slack on `not_before` for clock skew.
fn generate_self_signed_cert() -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let wsh_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".wsh");
    generate_self_signed_cert_in(&wsh_dir)
}

/// The certificate is a LEAF (not CA-flagged; `serverAuth` and
/// `digitalSignature` only), so a TLS client that has been told to trust it
/// (`SSL_CERT_FILE=~/.wsh/cert.pem` for the Rust CLI, `ca:` for Node) accepts
/// it as a server certificate. Until this was fixed it was generated as a
/// CA, which webpki refuses as an end entity (wsh #145).
fn generate_self_signed_cert_in(
    wsh_dir: &std::path::Path,
) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(wsh_dir)?;

    let cert_path = wsh_dir.join("cert.pem");
    let key_path = wsh_dir.join("key.pem");

    let mut params = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "wsh-server dev cert");

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(13);
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_certificate_hash_is_the_lowercase_hex_sha256_of_the_der() {
        // SHA-256 of the empty string.
        assert_eq!(
            cert_sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_password_is_a_subcommand_and_still_a_flag_and_never_takes_the_password_as_an_argument()
    {
        let sub = Cli::try_parse_from(["wsh-server", "hash-password"]).unwrap();
        assert!(matches!(sub.command, Some(Command::HashPassword)));
        let flag = Cli::try_parse_from(["wsh-server", "--hash-password"]).unwrap();
        assert!(flag.hash_password);
        // A password on the command line would sit in the process list and the shell history.
        assert!(Cli::try_parse_from(["wsh-server", "hash-password", "hunter2"]).is_err());
        assert!(Cli::try_parse_from(["wsh-server", "--hash-password", "hunter2"]).is_err());
    }

    /// The generated development certificate has to work as a SERVER
    /// certificate for a TLS client that trusts it: webpki refuses an end
    /// entity that is flagged as a CA (`CaUsedAsEndEntity`).
    #[test]
    fn generated_cert_is_accepted_as_a_server_certificate() {
        use rustls::pki_types::pem::PemObject;
        install_rustls_crypto_provider();
        let dir = std::env::temp_dir().join(format!("wsh-gen-cert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, _key) = generate_self_signed_cert_in(&dir).unwrap();
        let pem = std::fs::read(&cert_path).unwrap();
        let der = rustls::pki_types::CertificateDer::from_pem_slice(&pem).unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        for name in ["localhost", "127.0.0.1", "::1"] {
            let server_name = rustls::pki_types::ServerName::try_from(name.to_string()).unwrap();
            rustls::client::danger::ServerCertVerifier::verify_server_cert(
                &*verifier,
                &der,
                &[],
                &server_name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
