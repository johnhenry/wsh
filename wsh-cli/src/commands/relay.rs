//! `wsh reverse <relay>` / `wsh peers <relay>` — relay and peer discovery.
//!
//! - `reverse`: connect to a relay host and register as a reverse-connectable peer
//! - `peers`: connect to a relay and list available reverse peers

use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::{debug, info};
use wsh_client::SessionOpts;
use wsh_core::messages::*;
use wsh_core::RemotePeerDescriptor;

use crate::commands::common::{
    connect_client, load_last_reverse_peer, resolve_target, save_last_reverse_peer,
    LastReversePeer,
};
use crate::commands::interactive;
use crate::commands::reverse_host::{self, ReverseHostOptions};
use crate::terminal as term;

#[derive(Debug, Clone, Default)]
pub struct PeerQueryOptions {
    pub json: bool,
    pub peer_type: Option<String>,
    pub shell_backend: Option<String>,
    pub capability: Option<String>,
}

fn reverse_accept_summary(accept: &ReverseAcceptPayload) -> String {
    let caps = if accept.capabilities.is_empty() {
        "no capabilities".to_string()
    } else {
        accept.capabilities.join(", ")
    };
    let session_features = peer_session_features(
        accept.supports_attach,
        accept.supports_replay,
        accept.supports_echo,
        accept.supports_term_sync,
    );

    format!(
        "{} / {} [{}] {{{}}}",
        accept.peer_type, accept.shell_backend, caps, session_features
    )
}

fn peer_session_features(
    supports_attach: bool,
    supports_replay: bool,
    supports_echo: bool,
    supports_term_sync: bool,
) -> String {
    let mut features = Vec::new();
    if supports_attach {
        features.push("attach");
    }
    if supports_replay {
        features.push("replay");
    }
    if supports_echo {
        features.push("echo");
    }
    if supports_term_sync {
        features.push("sync");
    }
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}

fn filter_peers(peers: Vec<PeerInfo>, options: &PeerQueryOptions) -> Vec<PeerInfo> {
    peers.into_iter()
        .filter(|peer| {
            options
                .peer_type
                .as_ref()
                .map_or(true, |peer_type| &peer.peer_type == peer_type)
        })
        .filter(|peer| {
            options
                .shell_backend
                .as_ref()
                .map_or(true, |backend| &peer.shell_backend == backend)
        })
        .filter(|peer| {
            options
                .capability
                .as_ref()
                .map_or(true, |capability| {
                    peer.capabilities.iter().any(|cap| cap == capability)
                })
        })
        .collect()
}

fn reverse_connect_label(accept: &ReverseAcceptPayload) -> String {
    if accept.capabilities.is_empty() {
        format!("{} {}", accept.peer_type, accept.shell_backend)
    } else {
        format!(
            "{} {} [{}]",
            accept.peer_type,
            accept.shell_backend,
            accept.capabilities.join(", ")
        )
    }
}

fn parse_reverse_connect_response(payload: Payload) -> Result<ReverseAcceptPayload> {
    match payload {
        Payload::ReverseAccept(accept) => Ok(accept),
        Payload::ReverseReject(reject) => {
            anyhow::bail!("peer rejected reverse connection: {}", reject.reason)
        }
        other => anyhow::bail!("unexpected reverse-connect response: {:?}", other),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReverseConnectTarget<'a> {
    selector: &'a str,
    relay_host: Option<&'a str>,
}

fn parse_reverse_connect_target(input: &str) -> ReverseConnectTarget<'_> {
    if let Some(stripped) = input.strip_prefix('@') {
        if let Some((name, relay_host)) = stripped.rsplit_once('@') {
            if !name.is_empty() && !relay_host.is_empty() {
                return ReverseConnectTarget {
                    selector: &input[..input.len() - relay_host.len() - 1],
                    relay_host: Some(relay_host),
                };
            }
        }
    }

    ReverseConnectTarget {
        selector: input,
        relay_host: None,
    }
}

fn peer_matches_name(peer: &PeerInfo, selector: &str) -> bool {
    let name = selector.trim_start_matches('@');
    peer.username == name || peer.fingerprint_short == name
}

fn resolve_peer_selector<'a>(peers: &'a [PeerInfo], selector: &str) -> Result<&'a PeerInfo> {
    if selector.eq_ignore_ascii_case("only") {
        return match peers {
            [peer] => Ok(peer),
            [] => anyhow::bail!("selector `only` requires exactly one online relay peer, but none are available"),
            _ => anyhow::bail!(
                "selector `only` requires exactly one online relay peer, but {} peers are available",
                peers.len()
            ),
        };
    }

    if let Some(peer) = peers.iter().find(|peer| peer.fingerprint == selector) {
        return Ok(peer);
    }

    if let Some(peer) = peers.iter().find(|peer| peer.fingerprint_short == selector) {
        return Ok(peer);
    }

    if selector.starts_with('@') {
        let matches = peers
            .iter()
            .filter(|peer| peer_matches_name(peer, selector))
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [peer] => Ok(*peer),
            [] => anyhow::bail!("no relay peer matched selector `{selector}`"),
            many => anyhow::bail!(
                "selector `{selector}` matched multiple peers: {}",
                many.iter()
                    .map(|peer| format!("{} ({})", peer.username, peer.fingerprint_short))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
    }

    let prefix_matches = peers
        .iter()
        .filter(|peer| peer.fingerprint.starts_with(selector))
        .collect::<Vec<_>>();
    match prefix_matches.as_slice() {
        [peer] => Ok(*peer),
        [] => anyhow::bail!("no relay peer matched selector `{selector}`"),
        many => anyhow::bail!(
            "selector `{selector}` matched multiple peers: {}",
            many.iter()
                .map(|peer| format!("{} ({})", peer.username, peer.fingerprint_short))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn resolve_last_peer_selector<'a>(
    peers: &'a [PeerInfo],
    relay_host: &str,
    port: u16,
    identity: &str,
) -> Result<&'a PeerInfo> {
    let Some(last) = load_last_reverse_peer()? else {
        anyhow::bail!(
            "selector `last` has no saved peer for this identity yet; connect once by name or fingerprint first"
        );
    };
    if last.relay_host != relay_host || last.port != port || last.identity != identity {
        anyhow::bail!(
            "selector `last` does not match the current relay/identity context; expected {}:{} with identity `{}`",
            last.relay_host,
            last.port,
            last.identity
        );
    }
    resolve_saved_last_peer(peers, &last)
}

fn resolve_saved_last_peer<'a>(
    peers: &'a [PeerInfo],
    last: &LastReversePeer,
) -> Result<&'a PeerInfo> {
    peers.iter()
        .find(|peer| peer.fingerprint == last.fingerprint)
        .ok_or_else(|| anyhow::anyhow!(
            "selector `last` refers to peer {} ({}), which is not currently online",
            last.username, last.fingerprint
        ))
}

/// Register as a reverse-connectable peer on a relay host.
///
/// The client connects to the relay, sends a `ReverseRegister` message with
/// its public key and capabilities, and then holds the connection open so
/// other clients can initiate reverse connections through the relay.
pub async fn run_reverse(
    relay_host: &str,
    port: u16,
    identity: &str,
    transport: Option<&str>,
    capabilities: &[String],
) -> Result<()> {
    info!(relay = %relay_host, "registering as reverse peer");

    // Load signing key and derive public key / fingerprint.
    let keystore = wsh_client::KeyStore::default_location()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to initialize keystore")?;
    let (_signing_key, verifying_key) = keystore
        .load(identity)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to load key '{identity}'"))?;

    let public_bytes = wsh_client::auth::public_key_bytes(&verifying_key);
    let fingerprint = wsh_core::fingerprint(&public_bytes);
    let short_fp = &fingerprint[..fingerprint.len().min(12)];
    let reverse_options = reverse_options(capabilities)?;

    let resolved = resolve_target(relay_host, port, transport)?;
    debug!(url = %resolved.url, fallback_urls = ?resolved.fallback_urls, "relay URL");

    // Connect and authenticate
    let username = resolved.user.clone();
    let client = Arc::new(
        connect_client(&resolved, identity)
        .await
        .context("failed to connect to relay")?,
    );

    // Take the reverse-connect receiver before sending registration
    let rc_rx = client
        .take_reverse_connect_rx()
        .await
        .expect("reverse connect receiver already taken");
    let relay_rx = client
        .take_relay_message_rx()
        .await
        .expect("relay message receiver already taken");

    // Send ReverseRegister message (fire-and-forget, no reply expected)
    let register = Envelope {
        msg_type: MsgType::ReverseRegister,
        payload: Payload::ReverseRegister(
            reverse_options.reverse_register_payload(username, public_bytes),
        ),
    };
    client
        .send_fire_and_forget(register)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to send ReverseRegister")?;

    println!("Registered as peer {short_fp} on {relay_host}:{port}");
    println!("Waiting for connections... (Ctrl+C to stop)");
    reverse_host::run_with_options(client.clone(), rc_rx, relay_rx, reverse_options, None)
        .await?;

    client
        .disconnect()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}

fn reverse_options(capabilities: &[String]) -> Result<ReverseHostOptions> {
    let capabilities = if capabilities.is_empty() {
        vec!["shell".to_string(), "exec".to_string()]
    } else {
        capabilities
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
    };

    for capability in &capabilities {
        if capability != "shell"
            && capability != "exec"
            && capability != "fs"
            && capability != "tools"
            && capability != "gateway"
        {
            anyhow::bail!(
                "unsupported reverse-host capability `{capability}`; supported capabilities are shell, exec, fs, tools, and gateway"
            );
        }
    }

    Ok(ReverseHostOptions {
        capabilities,
        supports_attach: true,
        supports_replay: true,
        ..ReverseHostOptions::default()
    })
}

/// List peers available on a relay host.
pub async fn run_peers(
    relay_host: &str,
    port: u16,
    identity: &str,
    transport: Option<&str>,
    options: &PeerQueryOptions,
) -> Result<()> {
    info!(relay = %relay_host, "listing peers");

    let resolved = resolve_target(relay_host, port, transport)?;
    debug!(url = %resolved.url, fallback_urls = ?resolved.fallback_urls, "relay URL");

    // Connect and authenticate
    let client = connect_client(&resolved, identity)
        .await
        .context("failed to connect to relay")?;

    let peers = fetch_peers(&client).await?;

    {
        let peers = filter_peers(peers.peers, options);

        if options.json {
            let descriptors: Vec<RemotePeerDescriptor> = peers
                .iter()
                .map(|peer| RemotePeerDescriptor::from_wsh_peer_info(peer, relay_host, port))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&descriptors).context("failed to serialize peers")?
            );
        } else {
            println!(
                "{:<14} {:<16} {:<14} {:<16} {:<18} {:<20} {}",
                "FINGERPRINT",
                "USERNAME",
                "TYPE",
                "BACKEND",
                "SESSION",
                "CAPABILITIES",
                "LAST SEEN"
            );
            println!(
                "{:<14} {:<16} {:<14} {:<16} {:<18} {:<20} {}",
                "───────────",
                "────────",
                "────",
                "───────",
                "───────",
                "────────────",
                "─────────"
            );

            if peers.is_empty() {
                println!("(no peers online)");
            } else {
                for peer in &peers {
                    println!(
                        "{:<14} {:<16} {:<14} {:<16} {:<18} {:<20} {}",
                        peer.fingerprint_short,
                        peer.username,
                        peer.peer_type,
                        peer.shell_backend,
                        peer_session_features(
                            peer.supports_attach,
                            peer.supports_replay,
                            peer.supports_echo,
                            peer.supports_term_sync,
                        ),
                        peer.capabilities.join(", "),
                        peer.last_seen
                            .map(|t| format!("{t}s ago"))
                            .unwrap_or_else(|| "—".to_string()),
                    );
                }
            }

            println!("\n{} peer(s).", peers.len());
        }
    }

    client
        .disconnect()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}

/// Reverse connect to a browser peer through a relay.
///
/// Sends `ReverseConnect` to the relay server targeting the given peer
/// fingerprint. The relay forwards this to the target browser, which
/// can then accept and bridge the connection.
pub async fn run_connect(
    target_selector: &str,
    relay_host: Option<&str>,
    port: u16,
    identity: &str,
    transport: Option<&str>,
) -> Result<()> {
    let parsed_target = parse_reverse_connect_target(target_selector);
    let effective_relay = match (relay_host, parsed_target.relay_host) {
        (Some(explicit), Some(qualified)) if explicit != qualified => {
            anyhow::bail!(
                "reverse-connect target `{target_selector}` embeds relay `{qualified}`, which conflicts with explicit relay `{explicit}`"
            );
        }
        (Some(explicit), _) => explicit,
        (None, Some(qualified)) => qualified,
        (None, None) => anyhow::bail!(
            "reverse-connect requires a relay host unless the target is qualified like `@name@relay.example.com`"
        ),
    };

    info!(relay = %effective_relay, target = %target_selector, "reverse connecting to peer");

    let resolved = resolve_target(effective_relay, port, transport)?;
    debug!(url = %resolved.url, fallback_urls = ?resolved.fallback_urls, "relay URL");

    // Connect and authenticate
    let username = resolved.user.clone();
    let client = connect_client(&resolved, identity)
        .await
        .context("failed to connect to relay")?;
    let peers = fetch_peers(&client).await?;
    let target_peer = if parsed_target.selector.eq_ignore_ascii_case("last") {
        resolve_last_peer_selector(&peers.peers, effective_relay, port, identity)?
    } else {
        resolve_peer_selector(&peers.peers, parsed_target.selector)?
    };
    let target_fingerprint = &target_peer.fingerprint;

    let connect_msg = Envelope {
        msg_type: MsgType::ReverseConnect,
        payload: Payload::ReverseConnect(ReverseConnectPayload {
            target_fingerprint: target_fingerprint.to_string(),
            username: username.clone(),
        }),
    };

    println!(
        "Connecting to peer {} ({}) via {}:{}...",
        target_peer.username, target_peer.fingerprint_short, effective_relay, port
    );

    let response = client
        .send_and_wait_public(connect_msg, MsgType::ReverseAccept)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to reverse-connect to peer")?;

    let accept = parse_reverse_connect_response(response.payload)?;
    println!(
        "Peer accepted reverse connection. Backend: {}",
        reverse_accept_summary(&accept)
    );

    let (cols, rows) = term::get_terminal_size();
    let session = client
        .open_session(SessionOpts {
            kind: ChannelKind::Pty,
            command: None,
            cols: Some(cols),
            rows: Some(rows),
            env: None,
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to open reverse PTY session")?;

    interactive::run_session(
        session,
        &format!(
            "peer {target_fingerprint} ({})",
            reverse_connect_label(&accept)
        ),
    )
    .await?;
    save_last_reverse_peer(&LastReversePeer {
        relay_host: effective_relay.to_string(),
        port,
        identity: identity.to_string(),
        fingerprint: target_peer.fingerprint.clone(),
        username: target_peer.username.clone(),
    })?;
    client
        .disconnect()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}

pub async fn fetch_peers(client: &wsh_client::WshClient) -> Result<ReversePeersPayload> {
    let list_msg = Envelope {
        msg_type: MsgType::ReverseList,
        payload: Payload::ReverseList(ReverseListPayload {}),
    };

    let response = client
        .send_and_wait_public(list_msg, MsgType::ReversePeers)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to list peers")?;

    match response.payload {
        Payload::ReversePeers(peers) => Ok(peers),
        other => anyhow::bail!("unexpected response to peer listing: {:?}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        filter_peers, parse_reverse_connect_response, parse_reverse_connect_target,
        peer_session_features, resolve_peer_selector, resolve_saved_last_peer,
        reverse_accept_summary, reverse_options, LastReversePeer, PeerQueryOptions,
    };
    use wsh_core::messages::{Payload, PeerInfo, ReverseAcceptPayload, ReverseRejectPayload};

    #[test]
    fn reverse_accept_summary_includes_backend_and_capabilities() {
        assert_eq!(
            reverse_accept_summary(&ReverseAcceptPayload {
                target_fingerprint: "fp".into(),
                username: "user".into(),
                capabilities: vec!["shell".into()],
                peer_type: "browser-shell".into(),
                shell_backend: "virtual-shell".into(),
                supports_attach: true,
                supports_replay: true,
                supports_echo: true,
                supports_term_sync: true,
            }),
            "browser-shell / virtual-shell [shell] {attach,replay,echo,sync}"
        );
    }

    #[test]
    fn peer_session_features_reports_none_when_no_session_features_are_advertised() {
        assert_eq!(peer_session_features(false, false, false, false), "none");
    }

    #[test]
    fn filter_peers_applies_type_backend_and_capability_filters() {
        let peers = vec![
            PeerInfo {
                fingerprint: "host".into(),
                fingerprint_short: "host".into(),
                username: "host".into(),
                capabilities: vec!["shell".into(), "fs".into()],
                peer_type: "host".into(),
                shell_backend: "pty".into(),
                source: "wsh-relay".into(),
                supports_attach: true,
                supports_replay: true,
                supports_echo: false,
                supports_term_sync: false,
                last_seen: Some(1),
            },
            PeerInfo {
                fingerprint: "browser".into(),
                fingerprint_short: "browser".into(),
                username: "browser".into(),
                capabilities: vec!["shell".into()],
                peer_type: "browser-shell".into(),
                shell_backend: "virtual-shell".into(),
                source: "wsh-relay".into(),
                supports_attach: true,
                supports_replay: true,
                supports_echo: true,
                supports_term_sync: true,
                last_seen: Some(2),
            },
        ];

        let filtered = filter_peers(
            peers,
            &PeerQueryOptions {
                json: false,
                peer_type: Some("browser-shell".into()),
                shell_backend: Some("virtual-shell".into()),
                capability: Some("shell".into()),
            },
        );

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].username, "browser");
    }

    #[test]
    fn parse_reverse_connect_response_accepts_reverse_accept() {
        let accept = parse_reverse_connect_response(Payload::ReverseAccept(ReverseAcceptPayload {
            target_fingerprint: "fp".into(),
            username: "user".into(),
            capabilities: vec!["shell".into()],
            peer_type: "browser-shell".into(),
            shell_backend: "virtual-shell".into(),
            supports_attach: true,
            supports_replay: true,
            supports_echo: true,
            supports_term_sync: true,
        }))
        .unwrap();
        assert_eq!(accept.peer_type, "browser-shell");
        assert_eq!(accept.shell_backend, "virtual-shell");
    }

    #[test]
    fn parse_reverse_connect_response_rejects_reverse_reject() {
        let err = parse_reverse_connect_response(Payload::ReverseReject(ReverseRejectPayload {
            target_fingerprint: "fp".into(),
            username: "user".into(),
            reason: "busy".into(),
        }))
        .unwrap_err();

        assert!(err.to_string().contains("busy"));
    }

    #[test]
    fn reverse_options_advertise_attach_and_replay_for_host_peers() {
        let options = reverse_options(&["shell".into(), "fs".into()]).unwrap();
        assert!(options.supports_attach);
        assert!(options.supports_replay);
    }

    #[test]
    fn parse_reverse_connect_target_supports_qualified_names() {
        let parsed = parse_reverse_connect_target("@builder@relay.example.com");
        assert_eq!(parsed.selector, "@builder");
        assert_eq!(parsed.relay_host, Some("relay.example.com"));
    }

    #[test]
    fn resolve_peer_selector_prefers_named_peer_matches() {
        let peers = vec![
            PeerInfo {
                fingerprint: "abcdef123456".into(),
                fingerprint_short: "abcdef12".into(),
                username: "builder".into(),
                capabilities: vec!["shell".into()],
                peer_type: "host".into(),
                shell_backend: "pty".into(),
                source: "wsh-relay".into(),
                supports_attach: true,
                supports_replay: true,
                supports_echo: false,
                supports_term_sync: false,
                last_seen: Some(1),
            },
            PeerInfo {
                fingerprint: "999999123456".into(),
                fingerprint_short: "99999912".into(),
                username: "browser".into(),
                capabilities: vec!["shell".into()],
                peer_type: "browser-shell".into(),
                shell_backend: "virtual-shell".into(),
                source: "wsh-relay".into(),
                supports_attach: true,
                supports_replay: true,
                supports_echo: true,
                supports_term_sync: true,
                last_seen: Some(2),
            },
        ];

        let peer = resolve_peer_selector(&peers, "@builder").unwrap();
        assert_eq!(peer.username, "builder");
        let by_prefix = resolve_peer_selector(&peers, "abcdef").unwrap();
        assert_eq!(by_prefix.username, "builder");
    }

    #[test]
    fn resolve_peer_selector_rejects_ambiguous_names() {
        let peers = vec![
            PeerInfo {
                fingerprint: "abcdef123456".into(),
                fingerprint_short: "abcdef12".into(),
                username: "builder".into(),
                capabilities: vec!["shell".into()],
                peer_type: "host".into(),
                shell_backend: "pty".into(),
                source: "wsh-relay".into(),
                supports_attach: true,
                supports_replay: true,
                supports_echo: false,
                supports_term_sync: false,
                last_seen: Some(1),
            },
            PeerInfo {
                fingerprint: "abcdef654321".into(),
                fingerprint_short: "abcdef65".into(),
                username: "builder".into(),
                capabilities: vec!["shell".into()],
                peer_type: "browser-shell".into(),
                shell_backend: "virtual-shell".into(),
                source: "wsh-relay".into(),
                supports_attach: true,
                supports_replay: true,
                supports_echo: true,
                supports_term_sync: true,
                last_seen: Some(2),
            },
        ];

        let err = resolve_peer_selector(&peers, "@builder").unwrap_err();
        assert!(err.to_string().contains("matched multiple peers"));
    }

    #[test]
    fn resolve_peer_selector_supports_only_when_one_peer_is_online() {
        let peers = vec![PeerInfo {
            fingerprint: "abcdef123456".into(),
            fingerprint_short: "abcdef12".into(),
            username: "builder".into(),
            capabilities: vec!["shell".into()],
            peer_type: "host".into(),
            shell_backend: "pty".into(),
            source: "wsh-relay".into(),
            supports_attach: true,
            supports_replay: true,
            supports_echo: false,
            supports_term_sync: false,
            last_seen: Some(1),
        }];

        let peer = resolve_peer_selector(&peers, "only").unwrap();
        assert_eq!(peer.username, "builder");
    }

    #[test]
    fn resolve_peer_selector_rejects_only_when_multiple_peers_are_online() {
        let peers = vec![
            PeerInfo {
                fingerprint: "abcdef123456".into(),
                fingerprint_short: "abcdef12".into(),
                username: "builder".into(),
                capabilities: vec!["shell".into()],
                peer_type: "host".into(),
                shell_backend: "pty".into(),
                source: "wsh-relay".into(),
                supports_attach: true,
                supports_replay: true,
                supports_echo: false,
                supports_term_sync: false,
                last_seen: Some(1),
            },
            PeerInfo {
                fingerprint: "999999123456".into(),
                fingerprint_short: "99999912".into(),
                username: "browser".into(),
                capabilities: vec!["shell".into()],
                peer_type: "browser-shell".into(),
                shell_backend: "virtual-shell".into(),
                source: "wsh-relay".into(),
                supports_attach: true,
                supports_replay: true,
                supports_echo: true,
                supports_term_sync: true,
                last_seen: Some(2),
            },
        ];

        let err = resolve_peer_selector(&peers, "only").unwrap_err();
        assert!(err
            .to_string()
            .contains("requires exactly one online relay peer"));
    }

    #[test]
    fn resolve_saved_last_peer_returns_matching_online_peer() {
        let peers = vec![PeerInfo {
            fingerprint: "abcdef123456".into(),
            fingerprint_short: "abcdef12".into(),
            username: "builder".into(),
            capabilities: vec!["shell".into()],
            peer_type: "host".into(),
            shell_backend: "pty".into(),
            source: "wsh-relay".into(),
            supports_attach: true,
            supports_replay: true,
            supports_echo: false,
            supports_term_sync: false,
            last_seen: Some(1),
        }];

        let last = LastReversePeer {
            relay_host: "localhost".into(),
            port: 4422,
            identity: "operator".into(),
            fingerprint: "abcdef123456".into(),
            username: "builder".into(),
        };

        let peer = resolve_saved_last_peer(&peers, &last).unwrap();
        assert_eq!(peer.username, "builder");
    }

    #[test]
    fn resolve_saved_last_peer_rejects_offline_peer() {
        let peers = vec![PeerInfo {
            fingerprint: "999999123456".into(),
            fingerprint_short: "99999912".into(),
            username: "browser".into(),
            capabilities: vec!["shell".into()],
            peer_type: "browser-shell".into(),
            shell_backend: "virtual-shell".into(),
            source: "wsh-relay".into(),
            supports_attach: true,
            supports_replay: true,
            supports_echo: true,
            supports_term_sync: true,
            last_seen: Some(2),
        }];

        let last = LastReversePeer {
            relay_host: "localhost".into(),
            port: 4422,
            identity: "operator".into(),
            fingerprint: "abcdef123456".into(),
            username: "builder".into(),
        };

        let err = resolve_saved_last_peer(&peers, &last).unwrap_err();
        assert!(err.to_string().contains("is not currently online"));
    }
}
