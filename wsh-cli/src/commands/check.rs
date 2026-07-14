//! `wsh check relay <host>` — diagnose common relay/bootstrap failures.

use anyhow::{Context, Result};
use serde::Serialize;
use wsh_client::KnownHosts;

use crate::commands::common::{connect_client, resolve_target};
use crate::commands::relay::fetch_peers;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CheckStatus {
    Ok,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
struct CheckItem {
    name: &'static str,
    status: CheckStatus,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct RelayCheckReport {
    relay_host: String,
    port: u16,
    url: String,
    fallback_urls: Vec<String>,
    checks: Vec<CheckItem>,
    peers_online: Option<usize>,
    diagnosis: Vec<String>,
}

pub async fn run_relay(
    relay_host: &str,
    port: u16,
    identity: &str,
    transport: Option<&str>,
    json: bool,
) -> Result<()> {
    let resolved = resolve_target(relay_host, port, transport)?;
    let mut checks = Vec::new();
    let mut diagnosis = Vec::new();
    let mut peers_online = None;

    match load_identity_status(identity) {
        Ok(detail) => checks.push(CheckItem {
            name: "identity-key",
            status: CheckStatus::Ok,
            detail,
        }),
        Err(error) => {
            checks.push(CheckItem {
                name: "identity-key",
                status: CheckStatus::Error,
                detail: error.to_string(),
            });
            diagnosis.push(format!(
                "Generate or select a valid identity key before connecting: {error}"
            ));
            return emit_report(
                RelayCheckReport {
                    relay_host: resolved.host,
                    port: resolved.port,
                    url: resolved.url,
                    fallback_urls: resolved.fallback_urls,
                    checks,
                    peers_online,
                    diagnosis,
                },
                json,
            );
        }
    }

    checks.push(CheckItem {
        name: "known-hosts",
        status: known_host_status(&resolved.host, resolved.port)?,
        detail: known_host_detail(&resolved.host, resolved.port)?,
    });

    match connect_client(&resolved, identity).await {
        Ok(client) => {
            checks.push(CheckItem {
                name: "relay-connect",
                status: CheckStatus::Ok,
                detail: format!("connected to {}", resolved.url),
            });

            let peers = fetch_peers(&client)
                .await
                .context("relay peer listing failed after successful connect")?;
            peers_online = Some(peers.peers.len());
            checks.push(CheckItem {
                name: "relay-auth",
                status: CheckStatus::Ok,
                detail: format!("authenticated and listed {} peer(s)", peers.peers.len()),
            });

            client
                .disconnect()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))
                .context("failed to disconnect after relay check")?;
        }
        Err(error) => {
            let error_text = error.to_string();
            let (status, hint) = classify_relay_failure(&error_text, &resolved.host, resolved.port);
            checks.push(CheckItem {
                name: "relay-connect",
                status,
                detail: error_text.clone(),
            });
            diagnosis.push(hint);
        }
    }

    emit_report(
        RelayCheckReport {
            relay_host: resolved.host,
            port: resolved.port,
            url: resolved.url,
            fallback_urls: resolved.fallback_urls,
            checks,
            peers_online,
            diagnosis,
        },
        json,
    )
}

fn emit_report(report: RelayCheckReport, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("failed to serialize relay check")?
        );
        return Ok(());
    }

    println!("Relay check: {}:{}", report.relay_host, report.port);
    println!("Primary URL: {}", report.url);
    if !report.fallback_urls.is_empty() {
        println!("Fallbacks: {}", report.fallback_urls.join(", "));
    }
    println!();
    for check in &report.checks {
        let prefix = match check.status {
            CheckStatus::Ok => "[ok]",
            CheckStatus::Warning => "[warn]",
            CheckStatus::Error => "[err]",
        };
        println!("{prefix} {:<14} {}", check.name, check.detail);
    }
    if let Some(count) = report.peers_online {
        println!("\nPeers online: {count}");
    }
    if !report.diagnosis.is_empty() {
        println!("\nLikely fixes:");
        for hint in &report.diagnosis {
            println!("- {hint}");
        }
    }
    Ok(())
}

fn load_identity_status(identity: &str) -> Result<String> {
    let keystore = wsh_client::KeyStore::default_location()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to initialize keystore")?;
    let (_, verifying_key) = keystore
        .load(identity)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to load key '{identity}'"))?;
    let fingerprint = wsh_core::fingerprint(&wsh_client::auth::public_key_bytes(&verifying_key));
    Ok(format!("loaded '{identity}' ({})", &fingerprint[..fingerprint.len().min(12)]))
}

fn known_host_status(host: &str, port: u16) -> Result<CheckStatus> {
    let known_hosts = KnownHosts::default_location().map_err(|e| anyhow::anyhow!("{e}"))?;
    let key = format!("{host}:{port}");
    let listed = known_hosts
        .list()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .iter()
        .any(|(entry, _)| entry == &key);
    Ok(if listed {
        CheckStatus::Ok
    } else {
        CheckStatus::Warning
    })
}

fn known_host_detail(host: &str, port: u16) -> Result<String> {
    let known_hosts = KnownHosts::default_location().map_err(|e| anyhow::anyhow!("{e}"))?;
    let key = format!("{host}:{port}");
    let list = known_hosts.list().map_err(|e| anyhow::anyhow!("{e}"))?;
    if list.iter().any(|(entry, _)| entry == &key) {
        Ok(format!("{key} is present in ~/.wsh/known_hosts"))
    } else {
        Ok(format!("{key} is not yet in ~/.wsh/known_hosts"))
    }
}

fn classify_relay_failure(error_text: &str, host: &str, port: u16) -> (CheckStatus, String) {
    let lower = error_text.to_ascii_lowercase();
    if lower.contains("unknown key:") {
        return (
            CheckStatus::Error,
            "Generate the local identity first with `wsh keygen <name>` or pass `-i <existing-key>`.".into(),
        );
    }
    if lower.contains("host key changed") || lower.contains("fingerprint mismatch") {
        return (
            CheckStatus::Error,
            format!(
                "The stored known-host entry for {host}:{port} is stale. Remove or update it in ~/.wsh/known_hosts."
            ),
        );
    }
    if lower.contains("key not authorized") {
        return (
            CheckStatus::Error,
            "The relay rejected your key. Add this identity's public key to ~/.wsh/authorized_keys on the relay and restart the relay if needed.".into(),
        );
    }
    if lower.contains("certificateunknown")
        || lower.contains("certificate unknown")
        || lower.contains("tls")
        || lower.contains("certificate")
    {
        return (
            CheckStatus::Error,
            "TLS trust failed. Use a trusted localhost/dev certificate for the relay and make sure the browser and CLI both use the same relay host:port.".into(),
        );
    }
    if lower.contains("connection refused") {
        return (
            CheckStatus::Error,
            format!("The relay is not listening on {host}:{port}. Start `wsh-server --enable-relay` on that host and port."),
        );
    }
    if lower.contains("invalid http version") {
        return (
            CheckStatus::Error,
            "The target is speaking plain HTTP or the wrong scheme/port. Use the relay's TLS port and let `wsh` use https/wss automatically.".into(),
        );
    }
    if lower.contains("opening handshake failed") {
        return (
            CheckStatus::Error,
            "The WebTransport handshake failed. Check relay certificate trust and confirm the browser and CLI are using the same TLS relay endpoint.".into(),
        );
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return (
            CheckStatus::Warning,
            "The relay did not complete the handshake in time. Check network reachability, relay load, and whether the target host/port is correct.".into(),
        );
    }
    (
        CheckStatus::Error,
        "Inspect the relay startup logs and confirm the CLI host, port, identity key, and authorized_keys all match.".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::{classify_relay_failure, CheckStatus};

    #[test]
    fn classify_relay_failure_detects_authorized_keys_mismatch() {
        let (status, hint) = classify_relay_failure(
            "authentication failed: key not authorized",
            "relay.example",
            4422,
        );
        assert_eq!(status, CheckStatus::Error);
        assert!(hint.contains("authorized_keys"));
    }

    #[test]
    fn classify_relay_failure_detects_stale_known_host() {
        let (status, hint) = classify_relay_failure(
            "authentication failed: HOST KEY CHANGED for relay.example:4422",
            "relay.example",
            4422,
        );
        assert_eq!(status, CheckStatus::Error);
        assert!(hint.contains("known_hosts"));
    }

    #[test]
    fn classify_relay_failure_detects_tls_trust_failures() {
        let (status, hint) =
            classify_relay_failure("transport error: received fatal alert: CertificateUnknown", "relay.example", 4422);
        assert_eq!(status, CheckStatus::Error);
        assert!(hint.contains("TLS trust failed"));
    }

    #[test]
    fn classify_relay_failure_detects_connection_refused() {
        let (status, hint) =
            classify_relay_failure("transport error: Connection refused", "relay.example", 4422);
        assert_eq!(status, CheckStatus::Error);
        assert!(hint.contains("not listening"));
    }
}
