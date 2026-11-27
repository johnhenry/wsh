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
    /// The URL exactly as the user gave it, when the target was a full URL
    /// (`wss://host/path`) rather than `[user@]host`.
    pub explicit_url: Option<String>,
    /// The `known_hosts` key (`host:port`) to record the host's fingerprint under when the
    /// URL dialled is not the host's own address (`--via`). `None`: the URL's authority.
    pub known_host: Option<String>,
}

/// Persisted "last session" metadata used by session-oriented commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastSession {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub identity: String,
    pub transport: Option<String>,
    /// Set when the session was dialled with a full URL, so `sessions`, `attach` and
    /// `detach` reach the same path again. Absent in files written before URL targets.
    #[serde(default)]
    pub url: Option<String>,
}

impl LastSession {
    /// The target string that reaches this session again.
    pub fn target(&self) -> String {
        match &self.url {
            Some(url) => format!("{}@{}", self.user, url),
            None => format!("{}@{}", self.user, self.host),
        }
    }
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

/// Parse a target given as a full URL: `ws://`, `wss://`, `https://` or `wt://`, with an
/// optional path and query (`wss://host:4422/rendezvous/ab12`), and an optional user in
/// front of it or in its userinfo (`alice@wss://host/x`, `wss://alice@host/x`).
///
/// Returns `Ok(None)` for anything that is not a URL (a plain `[user@]host`). The URL
/// is dialled as given -- no fallback to another transport, and `--port` / `--transport`
/// do not apply, because the URL already says both.
fn parse_url_target(target: &str) -> Result<Option<ResolvedTarget>> {
    let Some((before, after)) = target.split_once("://") else {
        return Ok(None);
    };
    let (prefix_user, scheme) = match before.rsplit_once('@') {
        Some((user, scheme)) => (Some(user), scheme),
        None => (None, before),
    };
    let scheme = scheme.to_ascii_lowercase();
    let (transport, default_port) = match scheme.as_str() {
        "ws" => ("ws", 80),
        "wss" => ("ws", 443),
        "https" | "wt" => ("wt", 443),
        other => anyhow::bail!(
            "unsupported URL scheme '{other}' in '{target}' (expected ws, wss, https or wt)"
        ),
    };

    // Everything up to the first `/`, `?` or `#` is the authority; a fragment is never sent.
    let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (authority, tail) = after.split_at(authority_end);
    let tail = tail.split('#').next().unwrap_or("");
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => (Some(userinfo), hostport),
        None => (None, authority),
    };
    if userinfo.is_some_and(|u| u.contains(':')) {
        anyhow::bail!(
            "a password in the URL is not supported ('{target}'): use a key (`wsh keygen`)"
        );
    }
    let (host, explicit_port) =
        split_host_port(hostport).with_context(|| format!("invalid host in '{target}'"))?;
    if host.is_empty() {
        anyhow::bail!("empty host in '{target}'");
    }
    if scheme == "ws" && !is_loopback_host(host) {
        anyhow::bail!(
            "refusing plain-text ws:// to '{host}': nothing in the session would be encrypted. \
             Use wss://, or a loopback host for testing"
        );
    }
    let user = match prefix_user.or(userinfo) {
        Some("") => anyhow::bail!("empty username in '{target}'"),
        Some(user) => user.to_string(),
        None => crate::config::default_user(),
    };

    let url = format!("{scheme}://{hostport}{tail}");
    Ok(Some(ResolvedTarget {
        user,
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
        port: explicit_port.unwrap_or(default_port),
        url: url.clone(),
        fallback_urls: Vec::new(),
        transport: Some(transport.to_string()),
        explicit_url: Some(url),
        known_host: None,
    }))
}

fn is_loopback_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Split `host`, `host:port`, `[v6]` or `[v6]:port` (the brackets stay on `host`).
fn split_host_port(hostport: &str) -> Result<(&str, Option<u16>)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (addr, after) = rest
            .split_once(']')
            .context("unterminated '[' in the host")?;
        let host = &hostport[..addr.len() + 2];
        return match after {
            "" => Ok((host, None)),
            _ => Ok((
                host,
                Some(parse_port(
                    after.strip_prefix(':').context("expected ':' after ']'")?,
                )?),
            )),
        };
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) => Ok((host, Some(parse_port(port)?))),
        None => Ok((hostport, None)),
    }
}

fn parse_port(port: &str) -> Result<u16> {
    port.parse::<u16>()
        .with_context(|| format!("invalid port '{port}'"))
}

/// The operator side of a pipe relay (`--via`), set once from the command line. A process-wide
/// value so every command that dials a `[user@]host` reaches the host through it without each
/// one threading another argument.
static VIA: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Remember `--via <url>` for the rest of this process.
pub fn set_via(url: String) {
    let _ = VIA.set(url);
}

/// Resolve `[user@]host` + transport into a concrete connection URL, or take a full
/// URL (`wss://host:port/path`) as it is. With `--via`, the URL is the pipe relay's and the
/// host stays `[user@]host` (see [`apply_via`]).
pub fn resolve_target(target: &str, port: u16, transport: Option<&str>) -> Result<ResolvedTarget> {
    let resolved = resolve_target_direct(target, port, transport)?;
    match VIA.get() {
        Some(via) => apply_via(resolved, via),
        None => Ok(resolved),
    }
}

fn resolve_target_direct(
    target: &str,
    port: u16,
    transport: Option<&str>,
) -> Result<ResolvedTarget> {
    if let Some(resolved) = parse_url_target(target)? {
        return Ok(resolved);
    }
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
        explicit_url: None,
        known_host: None,
    })
}

/// Dial `via` -- the operator URL of a pipe relay, `wss://relay/r/<id>` -- instead of the
/// host, and keep `[user@]host` as the identity.
///
/// The relay's address says nothing about who answers at the other end, so the host key is
/// recorded in `known_hosts` under `host:port` of the target (the same key a direct connection
/// uses), not under the relay's authority. A pipe relay is WebSocket only and the dial has no
/// fallback; `--transport` does not apply. The rendezvous id is a capability for the pipe, so
/// the URL is not saved to `last_session.json`.
pub fn apply_via(mut resolved: ResolvedTarget, via: &str) -> Result<ResolvedTarget> {
    if resolved.explicit_url.is_some() {
        anyhow::bail!(
            "--via needs a user@host target (the host's identity), not a URL: a URL would be \
             the relay's"
        );
    }
    let relay = parse_url_target(via)?.with_context(|| {
        format!("--via expects a URL like wss://relay.example.com/r/<id>, got '{via}'")
    })?;
    if relay.transport.as_deref() != Some("ws") {
        anyhow::bail!("--via: a pipe relay is reached over WebSocket (wss://), not '{via}'");
    }
    if via.contains('@') {
        anyhow::bail!("--via: put the user in the target (user@host), not in the relay URL");
    }
    let (path, query) = match relay.url.split_once('?') {
        Some((path, query)) => (path, query),
        None => (relay.url.as_str(), ""),
    };
    if query
        .split('&')
        .any(|p| p.starts_with("role=") && p != "role=operator")
    {
        anyhow::bail!(
            "--via: '?role=host' is the HOST side of the pipe; the operator side has no role"
        );
    }
    let mut segments = path
        .trim_end_matches('/')
        .rsplit('/')
        .take(2)
        .collect::<Vec<_>>();
    segments.reverse();
    let id_ok = |id: &str| {
        (22..=128).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    if !matches!(segments.as_slice(), ["r", id] if id_ok(id)) {
        anyhow::bail!(
            "--via: the URL must end in /r/<rendezvous id> (22-128 base64url characters), got '{}'",
            relay.host
        );
    }

    let host = if resolved.host.contains(':') && !resolved.host.starts_with('[') {
        format!("[{}]", resolved.host)
    } else {
        resolved.host.clone()
    };
    resolved.known_host = Some(format!("{host}:{}", resolved.port));
    resolved.url = relay.url;
    resolved.fallback_urls = Vec::new();
    resolved.transport = Some("ws".to_string());
    resolved.explicit_url = None;
    Ok(resolved)
}

static TARGET: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Remember `--target NAME` (wsh #121) for the rest of this process.
pub fn set_target(name: String) {
    let _ = TARGET.set(name);
}

/// The execution target the command line named, if any: the host's own default when it did not.
pub fn target() -> Option<String> {
    TARGET.get().cloned()
}

/// What the operator asked of host identity on the command line (`--accept-new-host-key`,
/// `--require-host-key`, `--require-channel-binding`).
#[derive(Debug, Clone, Default)]
pub struct IdentityPolicy {
    pub accept_new_host_key: bool,
    pub require_host_key: bool,
    pub require_channel_binding: bool,
    /// Reverse host: ask operators to prove who they are, and refuse one that cannot.
    pub require_operator_proof: bool,
    /// Reverse host: the operators it serves (fingerprints or prefixes of at least 8 digits).
    pub allow_operators: Vec<String>,
    /// Reverse host: how many operators it serves at once (0 = unset = 1).
    pub max_operators: usize,
    /// Reverse host (wsh #289): the destination rules of the gateway for an operator behind the relay (`--relay-gateway-allow`).
    /// Empty = no gateway, and the host does not say `relay-gateway`.
    pub relay_gateway_allow: Vec<String>,
    /// Reverse host: also answer `OpenUdp` (`--relay-gateway-udp`).
    pub relay_gateway_udp: bool,
    /// Reverse host: also answer `ResolveDns` (`--relay-gateway-dns`).
    pub relay_gateway_dns: bool,
    /// Reverse host: also answer `ListenRequest` (`--relay-gateway-listen`).
    pub relay_gateway_listen: bool,
    /// Reverse host (wsh #296): the same three switches for the named operators only (`--relay-gateway-udp-for FINGERPRINT`, ...).
    pub relay_gateway_udp_for: Vec<String>,
    pub relay_gateway_dns_for: Vec<String>,
    pub relay_gateway_listen_for: Vec<String>,
    /// Reverse host: take who an operator is from the relay's word (`--relay-gateway-trust-relay`); required for a gateway unless
    /// `--require-operator-proof` makes operators prove themselves.
    pub relay_gateway_trust_relay: bool,
    /// Reverse host: connections one operator may hold open (0 = unset = the default).
    pub relay_gateway_max_connections: usize,
    /// `--no-half-close-probe-answers` (wsh #286): do not watch the ANSWERING socket of a connection (a reverse host's origin, a `-R`'s local
    /// service) for a vanished peer even where `gateway-lossless-close` is negotiated. Default: watched when negotiated.
    pub no_probe_answers: bool,
    /// `--no-lossless-close` (wsh #286): a reverse host does not state `gateway-lossless-close` (nor acknowledge an operator's), so its operators' connections
    /// behave as before the feature. Default: stated.
    pub no_lossless_close: bool,
    /// Reverse operator: how to treat `operator-proof` (see [`OperatorProofMode`]).
    pub operator_proof: OperatorProofMode,
    /// Reverse operator: seal the bridge (`--sealed` on `wsh reverse-connect`).
    pub sealed: bool,
    /// Every other command that dials one host: seal the whole session or fail (`--sealed`, #155).
    pub sealed_session: bool,
    /// `--cert-hash`: pin a WebTransport server to a certificate (SHA-256), no authority involved.
    pub cert_hashes: Vec<[u8; 32]>,
    /// `--insecure-skip-cert-verification`: do not verify a WebTransport server's certificate.
    pub insecure_skip_cert_verification: bool,
}

/// Put the certificate flags into the config of one connection. They apply to WebTransport URLs
/// only: a `wss://` fallback of the same target is checked against the system trust store as ever.
pub fn apply_cert_flags(config: &mut ConnectConfig, p: &IdentityPolicy, url: &str) {
    if transport_label(url) != "wt" {
        return;
    }
    let mut pins = p.cert_hashes.iter().copied();
    config.cert_hash = pins.next();
    config.cert_hashes = pins.collect();
    config.insecure_skip_cert_verification = p.insecure_skip_cert_verification;
}

/// A certificate flag with no WebTransport URL to apply it to would protect nothing: refuse it
/// instead of dialling a `wss://` connection the person thinks is pinned.
pub fn check_cert_flags_apply(p: &IdentityPolicy, urls: &[String]) -> Result<()> {
    let given = !p.cert_hashes.is_empty() || p.insecure_skip_cert_verification;
    if given && !urls.iter().any(|u| transport_label(u) == "wt") {
        anyhow::bail!(
            "--cert-hash and --insecure-skip-cert-verification apply to WebTransport (https://) only, \
             and this connection uses wss:// (a wss:// certificate is checked against the system trust store)"
        );
    }
    Ok(())
}

/// Whether `wsh reverse-connect` offers to prove its identity to the peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OperatorProofMode {
    /// Offer it when the relay carries it AND the peer registered the `operator-proof`
    /// capability: a released reverse host cannot decode the extra field.
    #[default]
    Auto,
    /// Offer it whenever the relay carries it (a JS host, which has no such capability to see).
    Always,
    Never,
}

static IDENTITY: std::sync::OnceLock<IdentityPolicy> = std::sync::OnceLock::new();

/// Remember the identity flags for the rest of this process.
pub fn set_identity_policy(p: IdentityPolicy) {
    let _ = IDENTITY.set(p);
}

/// The identity flags of this process.
pub fn identity_policy() -> IdentityPolicy {
    IDENTITY.get().cloned().unwrap_or_default()
}

/// Put the reverse-host identity policy and key into the options of a reverse host.
pub fn apply_host_policy(
    options: &mut crate::commands::reverse_host::ReverseHostOptions,
    key: &ed25519_dalek::SigningKey,
) -> Result<()> {
    let p = identity_policy();
    options.require_operator_proof = p.require_operator_proof;
    options.max_operators = p.max_operators.max(1);
    if options.max_operators > 1 && p.require_operator_proof {
        anyhow::bail!(
            "--max-operators above 1 cannot be combined with --require-operator-proof: that rule needs \
             a sealed bridge, and a connection holds one seal, so a host cannot seal each of several operators"
        );
    }
    for a in &p.allow_operators {
        if a.len() < 8 || !a.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!("--allow-operator takes at least 8 hex digits of an operator fingerprint, got `{a}`");
        }
    }
    options.allowed_operators = p
        .allow_operators
        .iter()
        .map(|a| a.to_ascii_lowercase())
        .collect();
    options.gateway = relay_gateway_from_policy(&p, options)?;
    options.lossless_close = !p.no_lossless_close;
    options.identity = Some(crate::commands::reverse_host::IdentityKey(
        std::sync::Arc::new(key.clone()),
    ));
    Ok(())
}

/// The gateway for an operator behind the relay that the command line asked for (wsh #289), or `None`: off unless
/// `--relay-gateway-allow` named a destination, and then only for a host that also exposes the `gateway` capability. The other
/// `--relay-gateway-*` flags without a rule are an error, not silently ignored.
fn relay_gateway_from_policy(
    p: &IdentityPolicy,
    options: &crate::commands::reverse_host::ReverseHostOptions,
) -> Result<Option<crate::commands::reverse_host::RelayGateway>> {
    use crate::commands::reverse_gateway::{
        is_operator_scope, OperatorGrant, DEFAULT_MAX_CONNECTIONS,
    };
    if p.relay_gateway_allow.is_empty() {
        if p.relay_gateway_udp
            || p.relay_gateway_dns
            || p.relay_gateway_listen
            || !p.relay_gateway_udp_for.is_empty()
            || !p.relay_gateway_dns_for.is_empty()
            || !p.relay_gateway_listen_for.is_empty()
            || p.relay_gateway_trust_relay
            || p.relay_gateway_max_connections != 0
        {
            anyhow::bail!(
                "--relay-gateway-udp, --relay-gateway-dns, --relay-gateway-listen, --relay-gateway-trust-relay and \
                 --relay-gateway-max-connections need at least one --relay-gateway-allow rule (the gateway is off, and default deny, without one)"
            );
        }
        return Ok(None);
    }
    // Who may use it: the owner names the operators. Proof says WHO an operator is (and seals the bridge); it does not say whether that
    // key should reach this machine's network, so it does not replace the list.
    if p.allow_operators.is_empty() {
        anyhow::bail!(
            "--relay-gateway-allow needs --allow-operator FINGERPRINT (at least 8 hex digits, repeatable): the gateway is for the operators \
             you name, not for whoever the relay lets through"
        );
    }
    // How an operator's identity is taken: with proof (and the sealed bridge it brings) a relay cannot speak for an operator; without it
    // the relay's word is all there is, so the owner says so.
    if !p.require_operator_proof && !p.relay_gateway_trust_relay {
        anyhow::bail!(
            "--relay-gateway-allow needs --require-operator-proof (operators prove themselves and the bridge is sealed) or \
             --relay-gateway-trust-relay (you trust the relay's word about who is asking: it can then open what an accepted operator could)"
        );
    }
    if p.max_operators > 1 && !p.relay_gateway_trust_relay {
        anyhow::bail!(
            "--relay-gateway-allow with --max-operators above 1 needs --relay-gateway-trust-relay: a host serving several operators cannot \
             seal its bridges (one seal per connection), so the relay's word is all there is"
        );
    }
    if !options.has_capability("gateway") {
        anyhow::bail!(
            "--relay-gateway-allow needs `--capability gateway`: the gateway is a capability this host exposes on purpose"
        );
    }
    // `FINGERPRINT=RULE` is scoped to the operators whose fingerprint starts with it (wsh #296); a rule without `=` is every operator's.
    // (A destination rule never contains `=`.) A scope must be one the owner's --allow-operator list can let in, else the rule would be
    // for an operator that is never served.
    let covered = |scope: &str| {
        p.allow_operators.iter().any(|a| {
            let a = a.to_ascii_lowercase();
            a.starts_with(scope) || scope.starts_with(a.as_str())
        })
    };
    let check_scope = |scope: &str, flag: &str| -> Result<String> {
        let scope = scope.to_ascii_lowercase();
        if !is_operator_scope(&scope) {
            anyhow::bail!(
                "{flag}: `{scope}` is not an operator: give at least 8 hex digits of its fingerprint"
            );
        }
        if !covered(&scope) {
            anyhow::bail!(
                "{flag}: `{scope}` is not covered by any --allow-operator (it would be a rule for an operator that is never served)"
            );
        }
        Ok(scope)
    };
    let mut unscoped = Vec::new();
    let mut grants: Vec<OperatorGrant> = Vec::new();
    let grant_for = |grants: &mut Vec<OperatorGrant>, scope: String| -> usize {
        grants
            .iter()
            .position(|g| g.operator == scope)
            .unwrap_or_else(|| {
                grants.push(OperatorGrant {
                    operator: scope,
                    allow: Vec::new(),
                    udp: false,
                    dns: false,
                    listen: false,
                });
                grants.len() - 1
            })
    };
    for entry in &p.relay_gateway_allow {
        match entry.split_once('=') {
            None => unscoped.push(entry.clone()),
            Some((scope, rule)) => {
                if rule.is_empty() {
                    anyhow::bail!("--relay-gateway-allow: `{entry}` has no rule after the `=`");
                }
                let scope = check_scope(scope, "--relay-gateway-allow")?;
                let i = grant_for(&mut grants, scope);
                grants[i].allow.push(rule.to_string());
            }
        }
    }
    for (scopes, flag) in [
        (&p.relay_gateway_udp_for, "--relay-gateway-udp-for"),
        (&p.relay_gateway_dns_for, "--relay-gateway-dns-for"),
        (&p.relay_gateway_listen_for, "--relay-gateway-listen-for"),
    ] {
        for scope in scopes {
            let scope = check_scope(scope, flag)?;
            let i = grant_for(&mut grants, scope.clone());
            match flag {
                "--relay-gateway-udp-for" => grants[i].udp = true,
                "--relay-gateway-dns-for" => grants[i].dns = true,
                _ => grants[i].listen = true,
            }
        }
    }
    // A switch for an operator that no rule reaches would switch on nothing.
    for g in &grants {
        let reached = !unscoped.is_empty()
            || grants.iter().any(|h| {
                !h.allow.is_empty()
                    && (h.operator.starts_with(&g.operator) || g.operator.starts_with(&h.operator))
            });
        if !reached {
            let flag = if g.udp {
                "--relay-gateway-udp-for"
            } else if g.dns {
                "--relay-gateway-dns-for"
            } else {
                "--relay-gateway-listen-for"
            };
            anyhow::bail!(
                "{flag} {}: no --relay-gateway-allow rule (scoped to it or unscoped) reaches this operator, so there is nothing to switch on",
                g.operator
            );
        }
    }
    let gateway = crate::commands::reverse_host::RelayGateway {
        allow: unscoped,
        operators: grants,
        udp: p.relay_gateway_udp,
        dns: p.relay_gateway_dns,
        listen: p.relay_gateway_listen,
        max_connections: if p.relay_gateway_max_connections == 0 {
            DEFAULT_MAX_CONNECTIONS
        } else {
            p.relay_gateway_max_connections
        },
    };
    gateway.validate().map_err(|why| anyhow::anyhow!(why))?;
    Ok(Some(gateway))
}

/// Put the process-wide identity policy into a connection config.
pub fn apply_identity_policy(config: &mut ConnectConfig) {
    let p = identity_policy();
    config.require_host_key = p.require_host_key;
    config.require_channel_binding = p.require_channel_binding;
    config.first_use = if p.accept_new_host_key {
        wsh_client::FirstUse::Accept
    } else {
        wsh_client::FirstUse::Refuse
    };
}

/// Dial with the first-use rule of `StrictHostKeyChecking=ask`: a host key never seen before is
/// shown and needs a yes -- typed at a terminal, or `--accept-new-host-key` for scripts. Without
/// either the connection is refused before any credential is sent. A changed key never gets a
/// prompt. `host` is the `known_hosts` label shown to the person.
pub async fn connect_checked(
    url: &str,
    config: &ConnectConfig,
    host: &str,
) -> Result<WshClient, wsh_client::WshError> {
    use std::io::IsTerminal;
    let mut config = config.clone();
    apply_identity_policy(&mut config);
    apply_cert_flags(&mut config, &identity_policy(), url);
    let mut result = WshClient::connect(url, config.clone()).await;
    if let Err(wsh_client::WshError::HostKeyUnknown { fingerprint, .. }) = &result {
        let fingerprint = fingerprint.clone();
        if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            eprintln!("The authenticity of host '{host}' cannot be established.");
            eprintln!("Host key fingerprint (SHA-256, proven by the host) is {fingerprint}.");
            let yes = dialoguer::Confirm::new()
                .with_prompt("Are you sure you want to continue connecting?")
                .default(false)
                .interact()
                .unwrap_or(false);
            if yes {
                config.first_use = wsh_client::FirstUse::AcceptFingerprint(fingerprint);
                result = WshClient::connect(url, config).await;
            }
        } else {
            return Err(wsh_client::WshError::Other(format!(
                "the authenticity of host '{host}' cannot be established: its host key has \
                 fingerprint {fingerprint} and is not in known_hosts. Check the fingerprint, then \
                 connect with --accept-new-host-key to trust it (or run wsh at a terminal to be asked)"
            )));
        }
    }
    if let Ok(client) = &result {
        match client.host_key() {
            Some(k) if client.host_key_newly_pinned() => eprintln!(
                "Warning: Permanently added '{host}' (host key {}) to the list of known hosts.",
                k.fingerprint
            ),
            Some(_) => {}
            None => {
                // A terminal gets told; a script keeps a quiet stderr (it has --require-host-key).
                if std::io::stderr().is_terminal() {
                    eprintln!(
                        "Warning: {host} presented no host-key proof: its identity is not verified \
                         (--require-host-key refuses such a host)"
                    );
                } else {
                    tracing::debug!("{host} presented no host-key proof");
                }
            }
        }
    }
    result
}

/// Connect and authenticate a client for a resolved target.
pub async fn connect_client(resolved: &ResolvedTarget, identity: &str) -> Result<WshClient> {
    connect_client_with(resolved, identity, |_| {}).await
}

/// [`connect_client`] with the connection settings adjusted first (`wsh mcp --host-key`, `--timeout`).
pub async fn connect_client_with(
    resolved: &ResolvedTarget,
    identity: &str,
    adjust: impl FnOnce(&mut ConnectConfig),
) -> Result<WshClient> {
    let mut config = ConnectConfig {
        username: resolved.user.clone(),
        key_name: Some(identity.to_string()),
        known_host: resolved.known_host.clone(),
        seal_session: if identity_policy().sealed_session {
            wsh_client::SessionSeal::Required
        } else {
            wsh_client::SessionSeal::Auto
        },
        ..Default::default()
    };
    adjust(&mut config);

    let mut attempts = Vec::with_capacity(1 + resolved.fallback_urls.len());
    attempts.push((transport_label(&resolved.url), resolved.url.clone()));
    attempts.extend(
        resolved
            .fallback_urls
            .iter()
            .cloned()
            .map(|url| (transport_label(&url), url)),
    );

    check_cert_flags_apply(
        &identity_policy(),
        &attempts.iter().map(|(_, u)| u.clone()).collect::<Vec<_>>(),
    )?;

    let mut errors = Vec::new();
    for (label, url) in attempts {
        match connect_checked(
            &url,
            &config,
            config.known_host.as_deref().unwrap_or(&resolved.host),
        )
        .await
        {
            Ok(client) => {
                // `-L` / `-R`: the forwards live as long as this connection does.
                if client.session_sealed() {
                    eprintln!("wsh: session sealed end to end (a relay in the middle carries ciphertext only)");
                }
                crate::commands::forward::start_configured(&client).await?;
                // `--share`: offer the folders for the life of this connection.
                crate::commands::share::start_configured(&client).await?;
                return Ok(client);
            }
            Err(err) => errors.push(format!("{label}: {err}")),
        }
    }

    if errors.len() == 1 {
        anyhow::bail!(
            "failed to connect to {} ({})",
            redact_rendezvous(&resolved.url),
            redact_rendezvous(&errors[0])
        );
    }

    anyhow::bail!(
        "failed to connect to {}:{} across transports ({})",
        resolved.host,
        resolved.port,
        redact_rendezvous(&errors.join("; "))
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
        url: resolved.explicit_url.clone(),
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

    // ── WebTransport certificate flags ────────────────────────────────

    fn pinned_policy() -> IdentityPolicy {
        IdentityPolicy {
            cert_hashes: vec![[7; 32]],
            ..Default::default()
        }
    }

    #[test]
    fn a_pin_applies_to_webtransport_urls_and_never_to_websocket_ones() {
        let policy = pinned_policy();
        let mut wt = ConnectConfig::default();
        apply_cert_flags(&mut wt, &policy, "https://host:4422");
        assert_eq!(wt.cert_hash, Some([7; 32]));
        let mut ws = ConnectConfig::default();
        apply_cert_flags(&mut ws, &policy, "wss://host:4422");
        assert_eq!(ws.cert_hash, None);
        assert!(ws.cert_hashes.is_empty());
    }

    #[test]
    fn several_pins_are_all_kept() {
        let policy = IdentityPolicy {
            cert_hashes: vec![[1; 32], [2; 32]],
            ..Default::default()
        };
        let mut wt = ConnectConfig::default();
        apply_cert_flags(&mut wt, &policy, "wt://host");
        assert_eq!(wt.cert_hash, Some([1; 32]));
        assert_eq!(wt.cert_hashes, vec![[2; 32]]);
    }

    #[test]
    fn the_opt_out_is_off_unless_the_flag_was_given() {
        let mut config = ConnectConfig::default();
        apply_cert_flags(&mut config, &IdentityPolicy::default(), "https://host");
        assert!(!config.insecure_skip_cert_verification);
        let policy = IdentityPolicy {
            insecure_skip_cert_verification: true,
            ..Default::default()
        };
        apply_cert_flags(&mut config, &policy, "https://host");
        assert!(config.insecure_skip_cert_verification);
        let mut ws = ConnectConfig::default();
        apply_cert_flags(&mut ws, &policy, "wss://host");
        assert!(!ws.insecure_skip_cert_verification);
    }

    #[test]
    fn a_certificate_flag_with_only_websocket_urls_is_an_error_not_ignored() {
        let urls = vec!["wss://host:4422".to_string()];
        assert!(check_cert_flags_apply(&pinned_policy(), &urls).is_err());
        let both = vec![
            "https://host:4422".to_string(),
            "wss://host:4422".to_string(),
        ];
        assert!(check_cert_flags_apply(&pinned_policy(), &both).is_ok());
        assert!(check_cert_flags_apply(&IdentityPolicy::default(), &urls).is_ok());
    }

    #[test]
    fn resolve_target_defaults_to_webtransport_then_websocket() {
        let resolved = resolve_target("alice@example.com", 4422, None).unwrap();
        assert_eq!(resolved.user, "alice");
        assert_eq!(resolved.host, "example.com");
        assert_eq!(resolved.port, 4422);
        assert_eq!(resolved.url, "https://example.com:4422");
        assert_eq!(resolved.fallback_urls, vec!["wss://example.com:4422"]);
    }

    // ── full-URL targets (#136) ──────────────────────────────────────

    #[test]
    fn a_wss_url_with_a_path_is_dialled_exactly_and_without_fallback() {
        let r = resolve_target(
            "alice@wss://relay.example.com:8443/rendezvous/ab12?x=1",
            4422,
            None,
        )
        .unwrap();
        assert_eq!(r.user, "alice");
        assert_eq!(r.host, "relay.example.com");
        assert_eq!(r.port, 8443);
        assert_eq!(r.url, "wss://relay.example.com:8443/rendezvous/ab12?x=1");
        assert!(r.fallback_urls.is_empty());
        assert_eq!(r.transport.as_deref(), Some("ws"));
        assert_eq!(r.explicit_url.as_deref(), Some(r.url.as_str()));
    }

    #[test]
    fn a_url_ignores_the_port_and_transport_flags() {
        let r = resolve_target("wss://example.com/x", 9999, Some("wt")).unwrap();
        assert_eq!(r.url, "wss://example.com/x");
        assert_eq!(r.port, 443);
        assert_eq!(r.transport.as_deref(), Some("ws"));
    }

    #[test]
    fn the_user_may_be_in_the_url_userinfo_and_a_fragment_is_never_sent() {
        let r = resolve_target("wss://bob@example.com:1234/p#frag", 4422, None).unwrap();
        assert_eq!(r.user, "bob");
        assert_eq!(r.url, "wss://example.com:1234/p");
    }

    #[test]
    fn webtransport_urls_keep_their_scheme() {
        let r = resolve_target("carol@https://example.com/wt", 4422, None).unwrap();
        assert_eq!(r.url, "https://example.com/wt");
        assert_eq!(r.transport.as_deref(), Some("wt"));
    }

    #[test]
    fn ipv6_hosts_keep_their_brackets_in_the_url() {
        let r = resolve_target("wss://[2001:db8::1]:9000/x", 4422, None).unwrap();
        assert_eq!(r.host, "2001:db8::1");
        assert_eq!(r.port, 9000);
        assert_eq!(r.url, "wss://[2001:db8::1]:9000/x");
    }

    #[test]
    fn plain_text_ws_is_refused_except_to_loopback() {
        assert!(resolve_target("ws://127.0.0.1:4422/x", 4422, None).is_ok());
        assert!(resolve_target("ws://localhost/x", 4422, None).is_ok());
        assert!(resolve_target("ws://[::1]:4422/x", 4422, None).is_ok());
        let err = resolve_target("ws://example.com/x", 4422, None).unwrap_err();
        assert!(err.to_string().contains("plain-text"), "{err}");
    }

    #[test]
    fn bad_urls_are_errors() {
        assert!(resolve_target("ftp://example.com", 4422, None).is_err());
        assert!(resolve_target("wss://", 4422, None).is_err());
        assert!(resolve_target("wss://host:notaport/", 4422, None).is_err());
        assert!(resolve_target("wss://user:secret@host/", 4422, None).is_err());
        assert!(resolve_target("@wss://host/", 4422, None).is_err());
    }

    // ── --via: a pipe relay (#118, #145) ─────────────────────────────

    const ID: &str = "AbCdEfGhIjKlMnOpQrStUv"; // 22 base64url characters

    #[test]
    fn via_dials_the_relay_but_keeps_the_host_as_the_identity() {
        let base = resolve_target("alice@build.example.com", 4422, None).unwrap();
        let r = apply_via(base, &format!("wss://relay.example.com:8443/r/{ID}")).unwrap();
        assert_eq!(r.url, format!("wss://relay.example.com:8443/r/{ID}"));
        assert!(r.fallback_urls.is_empty());
        assert_eq!(r.transport.as_deref(), Some("ws"));
        assert_eq!(
            (r.user.as_str(), r.host.as_str(), r.port),
            ("alice", "build.example.com", 4422)
        );
        // The host key is recorded under the host, never under the relay.
        assert_eq!(r.known_host.as_deref(), Some("build.example.com:4422"));
        // The rendezvous id is a capability: it is not written to last_session.json.
        assert_eq!(r.explicit_url, None);
    }

    #[test]
    fn via_known_host_brackets_ipv6_and_follows_the_port_flag() {
        let base = resolve_target("bob@[2001:db8::7]", 9000, None).unwrap();
        let r = apply_via(base, &format!("wss://relay.example.com/r/{ID}")).unwrap();
        assert_eq!(r.known_host.as_deref(), Some("[2001:db8::7]:9000"));
    }

    #[test]
    fn via_may_sit_under_a_base_path_and_keeps_its_query() {
        let base = resolve_target("alice@h", 4422, None).unwrap();
        let r = apply_via(base, &format!("wss://relay.example.com/wsh/r/{ID}?x=1")).unwrap();
        assert_eq!(r.url, format!("wss://relay.example.com/wsh/r/{ID}?x=1"));
    }

    #[test]
    fn via_refuses_what_is_not_the_operator_side_of_a_pipe() {
        let base = || resolve_target("alice@h", 4422, None).unwrap();
        for bad in [
            "wss://relay.example.com".to_string(), // no rendezvous id
            "wss://relay.example.com/r/short".to_string(), // id too short
            format!("wss://relay.example.com/r/{ID}?role=host"), // the HOST side of the pipe
            format!("wss://relay.example.com/x/{ID}"), // not /r/<id>
            format!("https://relay.example.com/r/{ID}"), // a pipe relay is WebSocket
            format!("ws://relay.example.com/r/{ID}"), // plain text off loopback
            format!("wss://user:pw@relay.example.com/r/{ID}"),
            "not a url".to_string(),
        ] {
            assert!(apply_via(base(), &bad).is_err(), "{bad}");
        }
        assert!(apply_via(base(), &format!("ws://127.0.0.1:9/r/{ID}")).is_ok());
    }

    #[test]
    fn via_cannot_be_combined_with_a_url_target() {
        let url = resolve_target("wss://relay.example.com/x", 4422, None).unwrap();
        let err = apply_via(url, &format!("wss://relay.example.com/r/{ID}")).unwrap_err();
        assert!(err.to_string().contains("user@host"), "{err}");
    }

    #[test]
    fn a_url_target_is_pinned_under_its_own_authority_which_for_a_relay_is_the_relay() {
        // Documented limit: without --via the key is recorded under what was dialled.
        let r =
            resolve_target(&format!("alice@wss://relay.example.com/r/{ID}"), 4422, None).unwrap();
        assert_eq!(r.known_host, None);
    }

    #[test]
    fn a_session_dialled_by_url_is_reached_by_url_again() {
        let last = LastSession {
            user: "alice".into(),
            host: "example.com".into(),
            port: 443,
            identity: "default".into(),
            transport: Some("ws".into()),
            url: Some("wss://example.com/rv/1".into()),
        };
        let r = resolve_target(&last.target(), 4422, None).unwrap();
        assert_eq!(r.url, "wss://example.com/rv/1");
        assert_eq!(r.user, "alice");
        // A last_session.json written before URL targets has no `url`.
        let old: LastSession = serde_json::from_str(
            r#"{"user":"a","host":"h","port":1,"identity":"i","transport":null}"#,
        )
        .unwrap();
        assert_eq!(old.target(), "a@h");
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

/// A pipe-relay URL (`wss://relay/r/<id>`) with its rendezvous id shortened: the id is a capability
/// (whoever holds it can dial the other half while it waits), so it does not belong in an error
/// line, a log or a ticket (#156).
pub fn redact_rendezvous(url: &str) -> String {
    match url.split_once("/r/") {
        Some((head, tail)) => {
            let (id, rest) = tail
                .find(['?', '#', '/'])
                .map_or((tail, ""), |i| tail.split_at(i));
            let shown: String = id.chars().take(4).collect();
            if id.len() > 4 {
                format!("{head}/r/{shown}...{rest}")
            } else {
                url.to_string()
            }
        }
        None => url.to_string(),
    }
}

#[cfg(test)]
mod redact_tests {
    use super::{redact_rendezvous, relay_gateway_from_policy, IdentityPolicy};

    #[test]
    fn the_rendezvous_id_is_shortened_and_the_rest_kept() {
        assert_eq!(
            redact_rendezvous("wss://relay.example/r/AbCdEfGhIjKlMnOpQrStUv?role=host"),
            "wss://relay.example/r/AbCd...?role=host"
        );
        assert_eq!(redact_rendezvous("wss://h:1/"), "wss://h:1/");
        assert!(
            !redact_rendezvous("ws://127.0.0.1:9/r/SECRETSECRETSECRETSECRET")
                .contains("SECRETSECRET")
        );
    }

    // ── The gateway for an operator behind a relay (wsh #289) ────────────

    fn host_with(capabilities: &[&str]) -> crate::commands::reverse_host::ReverseHostOptions {
        crate::commands::reverse_host::ReverseHostOptions {
            capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn the_relay_gateway_is_off_without_a_rule() {
        let g = relay_gateway_from_policy(
            &IdentityPolicy::default(),
            &host_with(&["shell", "gateway"]),
        );
        assert_eq!(
            g.unwrap(),
            None,
            "no flag, no gateway, even with the capability"
        );
    }

    /// A rule, with the owner having named an operator and chosen to trust the relay's word.
    fn chosen(rule: &str) -> IdentityPolicy {
        IdentityPolicy {
            relay_gateway_allow: vec![rule.into()],
            allow_operators: vec!["0123456789abcdef".into()],
            relay_gateway_trust_relay: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_gateway_needs_the_owner_to_name_who_may_use_it() {
        let mut p = chosen("db.example.com:5432");
        p.allow_operators.clear();
        let err = relay_gateway_from_policy(&p, &host_with(&["gateway"])).unwrap_err();
        assert!(err.to_string().contains("--allow-operator"), "{err}");
        // proof says who an operator IS, not that it should reach this network: it does not replace the list
        p.relay_gateway_trust_relay = false;
        p.require_operator_proof = true;
        let err = relay_gateway_from_policy(&p, &host_with(&["gateway"])).unwrap_err();
        assert!(err.to_string().contains("--allow-operator"), "{err}");
    }

    #[test]
    fn a_gateway_needs_proof_or_the_explicit_trust_of_the_relays_word() {
        let mut p = chosen("db.example.com:5432");
        p.relay_gateway_trust_relay = false;
        let err = relay_gateway_from_policy(&p, &host_with(&["gateway"])).unwrap_err();
        assert!(
            err.to_string().contains("--require-operator-proof")
                && err.to_string().contains("--relay-gateway-trust-relay"),
            "{err}"
        );
        p.require_operator_proof = true;
        assert!(relay_gateway_from_policy(&p, &host_with(&["gateway"])).is_ok());
        let mut t = chosen("db.example.com:5432");
        t.relay_gateway_trust_relay = true;
        assert!(relay_gateway_from_policy(&t, &host_with(&["gateway"])).is_ok());
    }

    #[test]
    fn several_operators_cannot_seal_so_they_always_need_the_trust() {
        let mut p = chosen("db.example.com:5432");
        p.relay_gateway_trust_relay = false;
        p.require_operator_proof = true;
        p.max_operators = 2;
        let err = relay_gateway_from_policy(&p, &host_with(&["gateway"])).unwrap_err();
        assert!(err.to_string().contains("--max-operators"), "{err}");
        p.relay_gateway_trust_relay = true;
        assert!(relay_gateway_from_policy(&p, &host_with(&["gateway"])).is_ok());
    }

    // ── Per operator (wsh #296) ───────────────────────────────────────────

    fn scoped() -> IdentityPolicy {
        IdentityPolicy {
            relay_gateway_allow: vec![
                "aaaaaaaa=a.example.com:1".into(),
                "BBBBBBBB=b.example.com:2".into(),
            ],
            allow_operators: vec!["aaaaaaaa1111".into(), "bbbbbbbb2222".into()],
            relay_gateway_trust_relay: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_rule_scoped_to_an_operator_is_that_operators_and_an_unscoped_one_everyones() {
        let mut p = scoped();
        p.relay_gateway_allow.push("shared.example.com".into());
        let g = relay_gateway_from_policy(&p, &host_with(&["gateway"]))
            .unwrap()
            .unwrap();
        assert_eq!(g.allow, ["shared.example.com"]);
        assert_eq!(g.operators.len(), 2);
        assert_eq!(g.operators[0].operator, "aaaaaaaa");
        assert_eq!(g.operators[1].operator, "bbbbbbbb", "lower-cased");
        assert_eq!(g.operators[1].allow, ["b.example.com:2"]);
        // only scoped rules is a gateway too, and an operator with no rule then gets nothing
        let only = relay_gateway_from_policy(&scoped(), &host_with(&["gateway"]))
            .unwrap()
            .unwrap();
        assert!(only.allow.is_empty());
        assert!(only.for_operator("aaaaaaaa1111ffff").is_some());
        assert!(only.for_operator("cccccccc00000000").is_none());
    }

    #[test]
    fn a_scope_must_be_a_fingerprint_with_a_rule_and_one_the_owner_lets_in() {
        for bad in [
            "zzzzzzzz=x.example.com",
            "aaaa=x.example.com",
            "=x.example.com",
            "aaaaaaaa=",
        ] {
            let mut p = scoped();
            p.relay_gateway_allow.push(bad.into());
            let err = relay_gateway_from_policy(&p, &host_with(&["gateway"])).unwrap_err();
            assert!(
                err.to_string().contains("--relay-gateway-allow"),
                "{bad}: {err}"
            );
        }
        // a scope no --allow-operator entry covers would be a rule for an operator that is never served
        let mut p = scoped();
        p.relay_gateway_allow.push("cccccccc=x.example.com".into());
        let err = relay_gateway_from_policy(&p, &host_with(&["gateway"])).unwrap_err();
        assert!(err.to_string().contains("--allow-operator"), "{err}");
        // a scope that is a prefix of an allowed fingerprint is covered, and so is a longer one
        let mut q = scoped();
        q.relay_gateway_allow = vec!["aaaaaaaa1111=x.example.com".into()];
        assert!(relay_gateway_from_policy(&q, &host_with(&["gateway"])).is_ok());
    }

    #[test]
    fn a_switch_scoped_to_an_operator_needs_a_rule_that_reaches_it() {
        let mut p = scoped();
        p.relay_gateway_udp_for = vec!["aaaaaaaa".into()];
        p.relay_gateway_dns_for = vec!["bbbbbbbb".into()];
        p.relay_gateway_listen_for = vec!["aaaaaaaa".into()];
        let g = relay_gateway_from_policy(&p, &host_with(&["gateway"]))
            .unwrap()
            .unwrap();
        let (a, b) = (&g.operators[0], &g.operators[1]);
        assert!(a.udp && !a.dns && a.listen);
        assert!(!b.udp && b.dns && !b.listen);
        assert!(!g.udp && !g.dns && !g.listen, "nothing became everyone's");
        // for an operator no rule reaches
        let mut p = scoped();
        p.allow_operators.push("cccccccc3333".into());
        p.relay_gateway_udp_for = vec!["cccccccc".into()];
        let err = relay_gateway_from_policy(&p, &host_with(&["gateway"])).unwrap_err();
        assert!(err.to_string().contains("--relay-gateway-udp-for"), "{err}");
        // a scope that is not a fingerprint
        let mut p = scoped();
        p.relay_gateway_dns_for = vec!["nothex".into()];
        assert!(relay_gateway_from_policy(&p, &host_with(&["gateway"])).is_err());
        // and without any rule the scoped switches are an error too, as the unscoped ones are
        let p = IdentityPolicy {
            relay_gateway_udp_for: vec!["aaaaaaaa".into()],
            ..Default::default()
        };
        assert!(relay_gateway_from_policy(&p, &host_with(&["gateway"])).is_err());
    }

    #[test]
    fn scoped_rules_need_everything_a_gateway_needs() {
        let mut p = scoped();
        p.allow_operators.clear();
        assert!(relay_gateway_from_policy(&p, &host_with(&["gateway"])).is_err());
        let mut p = scoped();
        p.relay_gateway_trust_relay = false;
        assert!(relay_gateway_from_policy(&p, &host_with(&["gateway"])).is_err());
        assert!(relay_gateway_from_policy(&scoped(), &host_with(&["shell"])).is_err());
    }

    #[test]
    fn a_rule_needs_the_gateway_capability() {
        let policy = chosen("db.example.com:5432");
        let err = relay_gateway_from_policy(&policy, &host_with(&["shell"])).unwrap_err();
        assert!(err.to_string().contains("--capability gateway"), "{err}");
    }

    #[test]
    fn the_other_relay_gateway_flags_without_a_rule_are_an_error_not_ignored() {
        for policy in [
            IdentityPolicy {
                relay_gateway_udp: true,
                ..Default::default()
            },
            IdentityPolicy {
                relay_gateway_dns: true,
                ..Default::default()
            },
            IdentityPolicy {
                relay_gateway_listen: true,
                ..Default::default()
            },
            IdentityPolicy {
                relay_gateway_trust_relay: true,
                ..Default::default()
            },
            IdentityPolicy {
                relay_gateway_max_connections: 4,
                ..Default::default()
            },
        ] {
            let err = relay_gateway_from_policy(&policy, &host_with(&["gateway"])).unwrap_err();
            assert!(err.to_string().contains("--relay-gateway-allow"), "{err}");
        }
    }

    #[test]
    fn a_rule_turns_on_tcp_only_with_the_default_bound() {
        let policy = chosen("db.example.com:5432");
        let g = relay_gateway_from_policy(&policy, &host_with(&["gateway"]))
            .unwrap()
            .unwrap();
        assert_eq!(g.allow, vec!["db.example.com:5432".to_string()]);
        assert!(
            !g.udp && !g.dns && !g.listen,
            "UDP, DNS and listening are each off unless asked for"
        );
        assert_eq!(
            g.max_connections,
            crate::commands::reverse_gateway::DEFAULT_MAX_CONNECTIONS
        );
    }

    #[test]
    fn the_switches_are_separate() {
        let base = chosen("*");
        let host = host_with(&["gateway"]);
        let udp = relay_gateway_from_policy(
            &IdentityPolicy {
                relay_gateway_udp: true,
                ..base.clone()
            },
            &host,
        )
        .unwrap()
        .unwrap();
        assert!(udp.udp && !udp.dns && !udp.listen);
        let dns = relay_gateway_from_policy(
            &IdentityPolicy {
                relay_gateway_dns: true,
                ..base.clone()
            },
            &host,
        )
        .unwrap()
        .unwrap();
        assert!(!dns.udp && dns.dns && !dns.listen);
        let listen = relay_gateway_from_policy(
            &IdentityPolicy {
                relay_gateway_listen: true,
                ..base
            },
            &host,
        )
        .unwrap()
        .unwrap();
        assert!(!listen.udp && !listen.dns && listen.listen);
    }
}
