//! Shared connection/session helpers for CLI commands.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use wsh_client::{ConnectConfig, WshClient};

use crate::config::parse_target;

/// A parsed `[user@]host:path` (or plain local path) endpoint, shared by
/// every command that accepts this syntax (`scp`, `sftp`, `ls` -- wsh #58).
///
/// Originally lived only in `scp.rs`; moved here (and made `pub`) so `sftp`
/// and `ls` reuse the exact same parser rather than writing a second one.
/// wsh #58 is explicit about why: two parsers for `[user@]host:path` is how
/// they end up disagreeing about a colon in a filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Local(PathBuf),
    Remote {
        user: String,
        host: String,
        path: String,
    },
}

/// Parse an endpoint string. Remote endpoints use `[user@]host:path` syntax.
pub fn parse_endpoint(s: &str) -> Result<Endpoint> {
    // Look for the colon that separates host from path, but skip Windows drive letters
    // (e.g., C:\path) by requiring that the part before the colon contains no path separators
    // AND isn't itself a single drive-letter character (a bare "C" is never a valid host
    // either, so treating a single alphabetic char before ':' as local is unambiguous --
    // this check was previously missing here, so `C:\Users\...` parsed as remote host "C").
    if let Some(colon_pos) = s.find(':') {
        let before = &s[..colon_pos];
        let is_drive_letter =
            before.len() == 1 && before.chars().next().unwrap().is_ascii_alphabetic();
        // If the part before the colon looks like a host (no slashes), treat as remote.
        if !is_drive_letter && !before.contains('/') && !before.contains('\\') && !before.is_empty()
        {
            let path = &s[colon_pos + 1..];
            if path.is_empty() {
                anyhow::bail!("remote path cannot be empty in '{s}'");
            }
            let (user, host) = if before.contains('@') {
                parse_target(before)?
            } else {
                // No user specified — use current username.
                let user = local_username().unwrap_or_else(|| "root".into());
                (user, before.to_string())
            };
            return Ok(Endpoint::Remote {
                user,
                host,
                path: path.to_string(),
            });
        }
    }

    Ok(Endpoint::Local(PathBuf::from(s)))
}

/// Get the current system username.
fn local_username() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
}

/// Resolved connection details for a target.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub url: String,
    pub fallback_urls: Vec<String>,
    pub transport: Option<String>,
}

/// Persisted "last session" metadata used by session-oriented commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastSession {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub identity: String,
    pub transport: Option<String>,
}

/// Persisted "last reverse peer" metadata used by relay-oriented commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastReversePeer {
    pub relay_host: String,
    pub port: u16,
    pub identity: String,
    pub fingerprint: String,
    pub username: String,
}

/// Resolve `[user@]host` + transport into a concrete connection URL.
pub fn resolve_target(target: &str, port: u16, transport: Option<&str>) -> Result<ResolvedTarget> {
    let (user, host) = parse_target(target)?;
    let transport = transport.map(ToString::to_string);
    let mut urls = connection_urls(&host, port, transport.as_deref())?;
    let url = urls.remove(0);
    Ok(ResolvedTarget {
        user,
        host,
        port,
        url,
        fallback_urls: urls,
        transport,
    })
}

/// Connect and authenticate a client for a resolved target.
pub async fn connect_client(resolved: &ResolvedTarget, identity: &str) -> Result<WshClient> {
    let config = ConnectConfig {
        username: resolved.user.clone(),
        key_name: Some(identity.to_string()),
        ..Default::default()
    };

    let mut attempts = Vec::with_capacity(1 + resolved.fallback_urls.len());
    attempts.push((transport_label(&resolved.url), resolved.url.clone()));
    attempts.extend(
        resolved
            .fallback_urls
            .iter()
            .cloned()
            .map(|url| (transport_label(&url), url)),
    );

    let mut errors = Vec::new();
    for (label, url) in attempts {
        match WshClient::connect(&url, config.clone()).await {
            Ok(client) => return Ok(client),
            Err(err) => errors.push(format!("{label}: {err}")),
        }
    }

    if errors.len() == 1 {
        anyhow::bail!("failed to connect to {} ({})", resolved.url, errors[0]);
    }

    anyhow::bail!(
        "failed to connect to {}:{} across transports ({})",
        resolved.host,
        resolved.port,
        errors.join("; ")
    )
}

/// Save the most recent successful connection for follow-up commands.
pub fn save_last_session(resolved: &ResolvedTarget, port: u16, identity: &str) -> Result<()> {
    let entry = LastSession {
        user: resolved.user.clone(),
        host: resolved.host.clone(),
        port,
        identity: identity.to_string(),
        transport: resolved.transport.clone(),
    };

    let path = last_session_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(&entry).context("failed to serialize last session")?;
    std::fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Load the most recent connection metadata, if available.
pub fn load_last_session() -> Result<Option<LastSession>> {
    let path = last_session_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let content =
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed: LastSession = serde_json::from_slice(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(parsed))
}

/// Persist the currently attached session id for `wsh detach`.
pub fn save_active_attachment(session_id: &str) -> Result<()> {
    let path = active_attachment_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&path, session_id.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Load the current attachment marker, if present.
pub fn load_active_attachment() -> Result<Option<String>> {
    let path = active_attachment_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let trimmed = content.trim().to_string();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed))
}

/// Clear the current attachment marker.
pub fn clear_active_attachment() -> Result<()> {
    let path = active_attachment_path()?;
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

/// Save the most recent successful reverse-peer connection target.
pub fn save_last_reverse_peer(entry: &LastReversePeer) -> Result<()> {
    let path = last_reverse_peer_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(entry).context("failed to serialize last reverse peer")?;
    std::fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Load the most recent reverse-peer connection metadata, if available.
pub fn load_last_reverse_peer() -> Result<Option<LastReversePeer>> {
    let path = last_reverse_peer_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let content =
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed: LastReversePeer = serde_json::from_slice(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(parsed))
}

fn last_session_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".wsh").join("last_session.json"))
}

fn active_attachment_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".wsh").join("active_attachment"))
}

fn last_reverse_peer_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    Ok(home.join(".wsh").join("last_reverse_peer.json"))
}

fn connection_urls(host: &str, port: u16, transport: Option<&str>) -> Result<Vec<String>> {
    match transport {
        Some("wt") => Ok(vec![format!("https://{host}:{port}")]),
        Some("ws") => Ok(vec![format!("wss://{host}:{port}")]),
        None => Ok(vec![
            format!("https://{host}:{port}"),
            format!("wss://{host}:{port}"),
        ]),
        Some(other) => anyhow::bail!("unknown transport: {other}"),
    }
}

fn transport_label(url: &str) -> &'static str {
    if url.starts_with("https://") || url.starts_with("wt://") {
        "wt"
    } else {
        "ws"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_target_defaults_to_webtransport_then_websocket() {
        let resolved = resolve_target("alice@example.com", 4422, None).unwrap();
        assert_eq!(resolved.user, "alice");
        assert_eq!(resolved.host, "example.com");
        assert_eq!(resolved.port, 4422);
        assert_eq!(resolved.url, "https://example.com:4422");
        assert_eq!(resolved.fallback_urls, vec!["wss://example.com:4422"]);
    }

    #[test]
    fn resolve_target_supports_wt() {
        let resolved = resolve_target("bob@example.com", 4433, Some("wt")).unwrap();
        assert_eq!(resolved.url, "https://example.com:4433");
        assert!(resolved.fallback_urls.is_empty());
        assert_eq!(resolved.transport.as_deref(), Some("wt"));
    }

    #[test]
    fn resolve_target_supports_secure_websocket() {
        let resolved = resolve_target("carol@example.com", 4422, Some("ws")).unwrap();
        assert_eq!(resolved.url, "wss://example.com:4422");
        assert!(resolved.fallback_urls.is_empty());
        assert_eq!(resolved.transport.as_deref(), Some("ws"));
    }

    // ── parse_endpoint (wsh #58: shared by scp/sftp/ls) ─────────────────

    #[test]
    fn parse_endpoint_plain_local_path() {
        assert_eq!(
            parse_endpoint("/tmp/foo.txt").unwrap(),
            Endpoint::Local(PathBuf::from("/tmp/foo.txt"))
        );
    }

    #[test]
    fn parse_endpoint_relative_local_path() {
        assert_eq!(
            parse_endpoint("./foo/bar.txt").unwrap(),
            Endpoint::Local(PathBuf::from("./foo/bar.txt"))
        );
    }

    #[test]
    fn parse_endpoint_remote_with_user() {
        let ep = parse_endpoint("alice@example.com:/home/alice/file.txt").unwrap();
        assert_eq!(
            ep,
            Endpoint::Remote {
                user: "alice".into(),
                host: "example.com".into(),
                path: "/home/alice/file.txt".into(),
            }
        );
    }

    #[test]
    fn parse_endpoint_remote_without_user_falls_back_to_local_username() {
        let ep = parse_endpoint("example.com:/etc/hosts").unwrap();
        match ep {
            Endpoint::Remote { host, path, .. } => {
                assert_eq!(host, "example.com");
                assert_eq!(path, "/etc/hosts");
            }
            other => panic!("expected Endpoint::Remote, got {other:?}"),
        }
    }

    #[test]
    fn parse_endpoint_windows_drive_letter_is_local_not_remote() {
        // A single-letter "host" before the colon followed by a
        // backslash-rooted path must not be parsed as [user@]host:path.
        assert_eq!(
            parse_endpoint("C:\\Users\\alice\\file.txt").unwrap(),
            Endpoint::Local(PathBuf::from("C:\\Users\\alice\\file.txt"))
        );
    }

    #[test]
    fn parse_endpoint_rejects_empty_remote_path() {
        assert!(parse_endpoint("example.com:").is_err());
    }

    #[test]
    fn parse_endpoint_relative_path_with_colon_in_filename_stays_local() {
        // A colon inside a filename (no leading host-like prefix without
        // slashes before it) must not be misparsed as a remote endpoint --
        // exactly the ambiguity wsh #58 calls out as the reason to share
        // one parser instead of two.
        assert_eq!(
            parse_endpoint("./weird:name.txt").unwrap(),
            Endpoint::Local(PathBuf::from("./weird:name.txt"))
        );
    }
}
