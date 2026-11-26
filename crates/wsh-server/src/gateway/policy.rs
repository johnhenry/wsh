//! Gateway policy — controls what destinations can be connected to,
//! connection limits, and reverse tunnel enablement.
//!
//! The policy layer is split into two types:
//!
//! - [`GatewayPolicy`] — a plain configuration struct (cloneable)
//!   that holds the rules.
//! - [`GatewayPolicyEnforcer`] — the runtime counterpart that owns the policy
//!   plus an atomic connection counter, performing all access-control checks.
//!
//! # Defaults deny
//!
//! The default policy allows **no** destination, refuses reverse listeners, and
//! would bind any listener it did allow to loopback. A destination must match a rule,
//! and an address that is not global unicast -- loopback, link-local, private (RFC 1918),
//! unique-local (`fc00::/7`), carrier-grade NAT (`100.64.0.0/10`), unspecified, multicast,
//! a cloud metadata endpoint, a documentation or benchmarking range, Teredo, or any other
//! reserved space (see [`super::address_class`] for the classes) -- is refused *after the
//! name has been resolved* -- whatever rule matched the name -- unless a rule names that
//! address or range. The wildcard `"*"` and a host name rule therefore mean "that
//! destination, at a public address", never "this machine's network": a name is not
//! trusted to resolve to the same kind of place twice. An IPv6 address that wraps an IPv4
//! one (IPv4-mapped, NAT64, 6to4) is judged by the IPv4 address it carries. The Node host's
//! gateway applies the same classifier (`@johnhenry/wsh/address-guard`), and both run the
//! same vectors (spec/address-class.vectors.json).
//!
//! A rule that is an address range or a literal address permits whatever class that
//! address has (a rule that names a metadata endpoint opens it); the wildcard and host
//! name rules never do. There is no `allowPrivate`-style switch here: private space needs
//! a rule that names it.
//!
//! # Rules
//!
//! | Rule                 | Matches                                                          |
//! |----------------------|------------------------------------------------------------------|
//! | `"*"`                | Any host and port whose address is not restricted (above).       |
//! | `"example.com"`      | That hostname on any port, at a public address.                  |
//! | `"example.com:443"`  | That hostname and port, at a public address.                     |
//! | `"10.0.0.0/8"`       | Any address in the range, any port. Names the range.             |
//! | `"10.0.0.0/8:5432"`  | Addresses in the range, that port. (IPv6 ranges: `fd00::/8`, no port.) |
//! | `"127.0.0.1:5432"`   | A literal address (and optionally port), when a client asks for that address. |
//!
//! To let a NAME reach an internal address, name the address or its range
//! (`"10.1.2.3/32:5432"`); the name rule alone does not.

use super::address_class::{classify_address, AddressClass};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Static gateway access-control configuration.
#[derive(Debug, Clone)]
pub struct GatewayPolicy {
    /// Destination rules (see the module docs). Empty = allow none.
    pub allowed_destinations: Vec<String>,
    /// Maximum number of concurrent gateway connections (TCP + UDP + listeners).
    pub max_connections: usize,
    /// Whether reverse tunnels (`ListenRequest`) are enabled.
    pub enable_reverse_tunnels: bool,
    /// Where reverse listeners bind. The client's `bind_addr` is not honoured; it
    /// cannot widen this.
    pub reverse_bind_addr: IpAddr,
    /// Which ports a client may ask for, and the listener / connection / backlog / idle bounds.
    pub reverse: super::reverse_policy::ReversePolicy,
    /// UDP flow count, rates and idle limit.
    pub udp: super::udp_policy::UdpPolicy,
    /// Unix-domain sockets a client may reach or create (off unless listed).
    pub unix: super::unix_policy::UnixPolicy,
    /// Bytes received from a client for one connection and not yet taken by its origin
    /// before the connection is closed.
    pub max_buffered_bytes: usize,
    /// The same, summed over one client's connections.
    pub max_client_buffered_bytes: usize,
    /// A connection half-closed by one side (and not the other) is closed after this long with
    /// nothing moving in either direction. `None` = never.
    pub half_close_idle: Option<std::time::Duration>,
    /// While an origin's socket is half-closed (it sent its end of file), watch it for a peer that
    /// went away (wsh #282); for TCP, the keep-alive schedule it is given (first probe after this
    /// long, then one per this long). `None` = no watch.
    pub half_close_probe: Option<std::time::Duration>,
}

/// Default for [`GatewayPolicy::half_close_idle`], in seconds (the same as the Node host: five minutes).
pub const DEFAULT_HALF_CLOSE_IDLE_SECS: u64 = 300;
/// Default for [`GatewayPolicy::max_buffered_bytes`] (the same as the Node host).
pub const DEFAULT_MAX_BUFFERED_BYTES: usize = 4 * 1024 * 1024;
/// Default for [`GatewayPolicy::max_client_buffered_bytes`] (the same as the Node host).
pub const DEFAULT_MAX_CLIENT_BUFFERED_BYTES: usize = 32 * 1024 * 1024;

/// Default policy: no destinations, 100 max connections, no reverse tunnels, loopback bind,
/// no unix sockets.
impl Default for GatewayPolicy {
    fn default() -> Self {
        Self {
            allowed_destinations: Vec::new(),
            max_connections: 100,
            enable_reverse_tunnels: false,
            reverse_bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            reverse: super::reverse_policy::ReversePolicy::default(),
            udp: super::udp_policy::UdpPolicy::default(),
            unix: super::unix_policy::UnixPolicy {
                max_listeners: super::unix_policy::DEFAULT_MAX_UNIX_LISTENERS,
                ..Default::default()
            },
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
            max_client_buffered_bytes: DEFAULT_MAX_CLIENT_BUFFERED_BYTES,
            half_close_idle: Some(std::time::Duration::from_secs(DEFAULT_HALF_CLOSE_IDLE_SECS)),
            half_close_probe: Some(wsh_core::peer_watch::DEFAULT_HALF_CLOSE_PROBE),
        }
    }
}

/// One parsed destination rule.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    /// `"*"`.
    Any,
    /// A hostname or literal address, optionally with a port.
    Host {
        host: String,
        ip: Option<IpAddr>,
        port: Option<u16>,
    },
    /// An address range, optionally with a port.
    Cidr {
        network: IpAddr,
        prefix: u8,
        port: Option<u16>,
    },
}

impl Rule {
    fn parse(text: &str) -> Result<Rule, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("empty rule".into());
        }
        if text == "*" {
            return Ok(Rule::Any);
        }
        if let Some((net, rest)) = text.split_once('/') {
            let network: IpAddr = net
                .trim_matches(['[', ']'])
                .parse()
                .map_err(|_| format!("'{net}' is not an address"))?;
            let (prefix, port) = match rest.split_once(':') {
                Some((p, port)) => (p, Some(parse_port(port)?)),
                None => (rest, None),
            };
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| format!("'{prefix}' is not a prefix length"))?;
            let max = if network.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(format!("prefix /{prefix} is longer than {max} bits"));
            }
            return Ok(Rule::Cidr {
                network,
                prefix,
                port,
            });
        }
        // `[v6]:port`, `host:port`, `host`, bare `v6`.
        let (host, port) = if let Some(rest) = text.strip_prefix('[') {
            let (addr, after) = rest.split_once(']').ok_or("unterminated '['")?;
            match after {
                "" => (addr, None),
                _ => (
                    addr,
                    Some(parse_port(
                        after.strip_prefix(':').ok_or("expected ':' after ']'")?,
                    )?),
                ),
            }
        } else if text.matches(':').count() == 1 {
            let (h, p) = text.split_once(':').expect("one colon");
            (h, Some(parse_port(p)?))
        } else {
            (text, None)
        };
        if host.is_empty() {
            return Err("empty host".into());
        }
        Ok(Rule::Host {
            host: host.to_ascii_lowercase(),
            ip: host.parse().ok(),
            port,
        })
    }
}

fn parse_port(s: &str) -> Result<u16, String> {
    s.parse().map_err(|_| format!("'{s}' is not a port"))
}

fn port_matches(rule_port: Option<u16>, port: Option<u16>) -> bool {
    match (rule_port, port) {
        (None, _) => true,
        // A DNS lookup has no port: any port-specific rule for the name applies.
        (Some(_), None) => true,
        (Some(r), Some(p)) => r == p,
    }
}

fn in_cidr(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

/// An address a rule that does not name it may not reach: anything but global unicast.
///
/// This is `!is_public_address(ip)`: the gateway accepts only what the classifier in
/// [`super::address_class`] calls [`AddressClass::Public`], the same classifier the Node host
/// runs (spec/address-class.vectors.json). IPv6 addresses that wrap an IPv4 one (IPv4-mapped,
/// NAT64, 6to4) are judged by the IPv4 address inside them.
pub fn is_restricted_address(ip: IpAddr) -> bool {
    classify_address(ip) != AddressClass::Public
}

/// Runtime policy enforcer with atomic connection tracking.
///
/// Wraps a [`GatewayPolicy`] and adds a shared atomic counter so that
/// connection-limit checks are thread-safe across concurrent tasks.
pub struct GatewayPolicyEnforcer {
    /// The underlying static policy rules.
    policy: GatewayPolicy,
    /// Shared atomic counter of currently active gateway connections.
    active_connections: Arc<AtomicUsize>,
    rules: Vec<Rule>,
}

impl GatewayPolicyEnforcer {
    /// Create a new enforcer from the given policy. A rule that does not parse is
    /// logged and ignored, which can only make the policy stricter.
    pub fn new(policy: GatewayPolicy) -> Self {
        let mut rules = Vec::new();
        let mut seen = HashSet::new();
        for text in &policy.allowed_destinations {
            if !seen.insert(text.clone()) {
                continue;
            }
            match Rule::parse(text) {
                Ok(rule) => rules.push(rule),
                Err(why) => {
                    tracing::warn!(rule = %text, "ignoring gateway destination rule: {why}")
                }
            }
        }
        Self {
            policy,
            active_connections: Arc::new(AtomicUsize::new(0)),
            rules,
        }
    }

    /// Where reverse listeners bind.
    pub fn reverse_bind_addr(&self) -> IpAddr {
        self.policy.reverse_bind_addr
    }

    fn check_limit(&self) -> Result<(), String> {
        let current = self.active_connections.load(Ordering::Relaxed);
        if current >= self.policy.max_connections {
            return Err(format!(
                "connection limit reached ({}/{})",
                current, self.policy.max_connections
            ));
        }
        Ok(())
    }

    /// First stage of a connection check, before any name is resolved: the connection
    /// limit, and whether any rule could apply to this destination at all.
    ///
    /// Passing this does **not** allow the connection. The addresses the name
    /// resolves to must then pass [`authorize_addrs`](Self::authorize_addrs), and the
    /// caller must connect to one of *those* addresses, not resolve the name again.
    pub fn check_connect(&self, host: &str, port: u16) -> Result<(), String> {
        self.check_limit()?;
        self.check_destination(host, port)
    }

    /// [`check_connect`](Self::check_connect) without the connection limit, for a caller that
    /// has already counted its connection with [`try_acquire`](Self::try_acquire).
    pub fn check_destination(&self, host: &str, port: u16) -> Result<(), String> {
        if self.rules_for_name(host, Some(port)).is_empty() {
            return Err(format!("destination not allowed: {host}:{port}"));
        }
        Ok(())
    }

    /// May `name` be looked up with `ResolveDns`? (A name some rule could apply to;
    /// the answers are then filtered with [`authorize_addrs`](Self::authorize_addrs).)
    pub fn check_resolve(&self, name: &str) -> Result<(), String> {
        if self.rules_for_name(name, None).is_empty() {
            return Err(format!("destination not allowed: {name}"));
        }
        Ok(())
    }

    /// The rules that could apply to a request for `host` (and `port`, when it has one):
    /// the wildcard, a host rule for that name, or -- since which addresses a name has
    /// is not known yet -- any address range.
    fn rules_for_name(&self, host: &str, port: Option<u16>) -> Vec<&Rule> {
        let host = normalize_host(host);
        let ip: Option<IpAddr> = host.parse().ok();
        self.rules
            .iter()
            .filter(|rule| match rule {
                Rule::Any => true,
                Rule::Host {
                    host: h,
                    ip: rip,
                    port: rp,
                } => (h == &host || (ip.is_some() && ip == *rip)) && port_matches(*rp, port),
                Rule::Cidr {
                    network,
                    prefix,
                    port: rp,
                } => port_matches(*rp, port) && ip.is_none_or(|ip| in_cidr(ip, *network, *prefix)),
            })
            .collect()
    }

    /// Of the addresses `host` resolved to, those the policy lets a client reach.
    ///
    /// An address is allowed when a rule matches it **and**, if it is restricted
    /// ([`is_restricted_address`]), that rule names the host or the address
    /// specifically -- the wildcard never does.
    pub fn authorize_addrs(&self, host: &str, port: Option<u16>, addrs: &[IpAddr]) -> Vec<IpAddr> {
        let host = normalize_host(host);
        addrs
            .iter()
            .copied()
            .filter(|&ip| {
                let restricted = is_restricted_address(ip);
                self.rules.iter().any(|rule| match rule {
                    Rule::Any => !restricted,
                    Rule::Host {
                        host: h,
                        ip: rip,
                        port: rp,
                    } => {
                        port_matches(*rp, port)
                            && match rip {
                                // A literal address names that address, when it is the one requested.
                                Some(literal) => {
                                    host.parse::<IpAddr>().ok() == Some(*literal) && *literal == ip
                                }
                                // A host name names the host, never the internal network behind it:
                                // what the name resolves to must be a public address.
                                None => h == &host && !restricted,
                            }
                    }
                    Rule::Cidr {
                        network,
                        prefix,
                        port: rp,
                    } => port_matches(*rp, port) && in_cidr(ip, *network, *prefix),
                })
            })
            .collect()
    }

    /// Check if reverse tunnel listening is allowed on the given port.
    ///
    /// Reverse tunnels must be enabled in the policy (`enable_reverse_tunnels`, off by
    /// default) and the connection limit not reached.
    pub fn check_listen(&self, port: u16) -> Result<(), String> {
        if !self.policy.enable_reverse_tunnels {
            return Err("reverse tunnels are disabled".to_string());
        }
        if !self.policy.reverse.port_allowed(port) {
            return Err(self.policy.reverse.port_refusal(port));
        }
        self.check_limit()
    }

    /// The UDP flow bounds.
    pub fn udp(&self) -> &super::udp_policy::UdpPolicy {
        &self.policy.udp
    }

    /// The reverse-tunnel ports and bounds.
    pub fn reverse(&self) -> &super::reverse_policy::ReversePolicy {
        &self.policy.reverse
    }

    /// The unix-socket policy.
    pub fn unix(&self) -> &super::unix_policy::UnixPolicy {
        &self.policy.unix
    }

    /// Per-connection and per-client byte caps on data received from a client.
    pub fn buffer_limits(&self) -> (usize, usize) {
        (
            self.policy.max_buffered_bytes,
            self.policy.max_client_buffered_bytes,
        )
    }

    /// How long a half-closed connection may sit with nothing moving in either direction.
    pub fn half_close_idle(&self) -> Option<std::time::Duration> {
        self.policy.half_close_idle
    }

    /// The schedule of the watch on a half-closed origin socket (`None` = no watch).
    pub fn half_close_probe(&self) -> Option<std::time::Duration> {
        self.policy.half_close_probe
    }

    /// Count a connection if the limit allows it: the check and the count are one step, so
    /// concurrent opens cannot both slip under it.
    pub fn try_acquire(&self) -> Result<ConnectionGuard, String> {
        let before = self.active_connections.fetch_add(1, Ordering::AcqRel);
        let guard = ConnectionGuard {
            counter: self.active_connections.clone(),
        };
        if before >= self.policy.max_connections {
            // `guard` drops here and takes the count back.
            return Err(format!(
                "connection limit reached ({}/{})",
                before, self.policy.max_connections
            ));
        }
        Ok(guard)
    }

    /// Increment active connection count. Returns an owned guard that
    /// decrements on drop. The guard is `Send` so it can be moved into
    /// spawned tasks — the connection stays counted until the task ends.
    pub fn acquire(&self) -> ConnectionGuard {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard {
            counter: self.active_connections.clone(),
        }
    }

    /// Returns the current number of active gateway connections.
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }
}

/// Lowercase, without the brackets of an IPv6 literal or a trailing dot.
fn normalize_host(host: &str) -> String {
    host.trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// RAII guard that decrements the connection count on drop.
/// Owns an `Arc<AtomicUsize>` so it is `Send` and can be moved into spawned tasks.
pub struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(rules: &[&str]) -> GatewayPolicyEnforcer {
        GatewayPolicyEnforcer::new(GatewayPolicy {
            allowed_destinations: rules.iter().map(|s| s.to_string()).collect(),
            max_connections: 100,
            enable_reverse_tunnels: true,
            reverse_bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ..GatewayPolicy::default()
        })
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Full decision for a destination that resolved to `addrs`.
    fn allowed(p: &GatewayPolicyEnforcer, host: &str, port: u16, addrs: &[&str]) -> bool {
        if p.check_connect(host, port).is_err() {
            return false;
        }
        let addrs: Vec<IpAddr> = addrs.iter().map(|a| ip(a)).collect();
        !p.authorize_addrs(host, Some(port), &addrs).is_empty()
    }

    #[test]
    fn the_default_policy_allows_nothing_and_no_reverse_tunnels() {
        let p = GatewayPolicyEnforcer::new(GatewayPolicy::default());
        assert!(p.check_connect("example.com", 80).is_err());
        assert!(p.check_connect("93.184.216.34", 443).is_err());
        assert!(p.check_resolve("example.com").is_err());
        assert!(p.check_listen(8080).is_err());
        assert_eq!(p.reverse_bind_addr(), ip("127.0.0.1"));
    }

    #[test]
    fn an_empty_list_blocks_everything() {
        assert!(!allowed(
            &policy(&[]),
            "example.com",
            80,
            &["93.184.216.34"]
        ));
    }

    #[test]
    fn the_wildcard_allows_public_addresses() {
        let p = policy(&["*"]);
        assert!(allowed(&p, "example.com", 80, &["93.184.216.34"]));
        assert!(allowed(
            &p,
            "2606:2800:220:1::1",
            443,
            &["2606:2800:220:1::1"]
        ));
    }

    #[test]
    fn the_wildcard_never_reaches_restricted_addresses() {
        let p = policy(&["*"]);
        for addr in [
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "10.0.0.5",
            "172.16.9.9",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "fe80::1",
            "fd00::1",
            "fc00::5",
            "100.64.0.1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            // IPv6 spellings of the same IPv4 addresses
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            "::127.0.0.1",
        ] {
            assert!(
                !allowed(&p, addr, 80, &[addr]),
                "{addr} must be refused by the wildcard"
            );
            assert!(
                !allowed(&p, "innocent.example.com", 80, &[addr]),
                "a name resolving to {addr} must be refused"
            );
        }
        // 172.15 and 172.32 are public; 100.63 and 100.128 are outside the CGNAT block.
        for addr in [
            "172.15.0.1",
            "172.32.0.1",
            "100.63.0.1",
            "100.128.0.1",
            "11.0.0.1",
            "169.253.0.1",
        ] {
            assert!(
                allowed(&p, "x.example.com", 80, &[addr]),
                "{addr} is public"
            );
        }
    }

    #[test]
    fn a_name_with_any_restricted_answer_only_gets_the_allowed_ones() {
        // DNS rebinding shape: a public name that also answers with an internal address.
        let p = policy(&["*"]);
        let ok = p.authorize_addrs(
            "x.example.com",
            Some(80),
            &[ip("10.0.0.1"), ip("93.184.216.34")],
        );
        assert_eq!(ok, vec![ip("93.184.216.34")]);
    }

    #[test]
    fn a_rule_that_names_a_restricted_address_allows_it_and_a_name_rule_does_not() {
        let p = policy(&[
            "localhost:5432",
            "10.1.2.3",
            "192.168.0.0/16:443",
            "db.internal",
        ]);
        assert!(
            !allowed(&p, "localhost", 5432, &["127.0.0.1"]),
            "a name rule does not reach loopback: name the address (`127.0.0.1:5432`)"
        );
        assert!(
            !allowed(&p, "127.0.0.1", 5432, &["127.0.0.1"]),
            "the rule names the host `localhost`, not the address"
        );
        let literal = policy(&["127.0.0.1:5432"]);
        assert!(allowed(&literal, "127.0.0.1", 5432, &["127.0.0.1"]));
        assert!(
            !allowed(&literal, "127.0.0.1", 22, &["127.0.0.1"]),
            "other port"
        );
        assert!(allowed(&p, "10.1.2.3", 1, &["10.1.2.3"]));
        assert!(!allowed(&p, "10.1.2.4", 1, &["10.1.2.4"]));
        assert!(allowed(&p, "192.168.7.7", 443, &["192.168.7.7"]));
        assert!(!allowed(&p, "192.168.7.7", 80, &["192.168.7.7"]));
        assert!(
            !allowed(&p, "db.internal", 1, &["10.9.9.9"]),
            "a host NAME rule never reaches a restricted address, whatever the name resolves to"
        );
        assert!(!allowed(&p, "other.internal", 1, &["10.9.9.9"]));
    }

    #[test]
    fn a_host_name_rule_only_reaches_public_addresses() {
        let p = policy(&["partner.example.com"]);
        assert!(allowed(&p, "partner.example.com", 443, &["93.184.216.34"]));
        for addr in [
            "127.0.0.1",
            "::1",
            "10.0.0.5",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
        ] {
            assert!(
                !allowed(&p, "partner.example.com", 443, &[addr]),
                "{addr} must not be reachable through a name rule"
            );
        }
        // A mixed answer keeps only the public address, and a changed answer is judged afresh.
        assert_eq!(
            p.authorize_addrs(
                "partner.example.com",
                Some(443),
                &[ip("10.0.0.5"), ip("93.184.216.34"), ip("127.0.0.1")]
            ),
            vec![ip("93.184.216.34")]
        );
        assert!(p
            .authorize_addrs("partner.example.com", Some(443), &[ip("127.0.0.1")])
            .is_empty());
    }

    #[test]
    fn a_literal_address_rule_names_that_address_only_when_it_is_requested_by_address() {
        let p = policy(&["10.1.2.3"]);
        assert!(allowed(&p, "10.1.2.3", 80, &["10.1.2.3"]));
        assert!(
            !allowed(&p, "some.name.example", 80, &["10.1.2.3"]),
            "a name that resolves to the address is not the address the rule named"
        );
        // An address range is how a name is allowed to resolve inside.
        let range = policy(&["10.1.2.3/32"]);
        assert!(allowed(&range, "some.name.example", 80, &["10.1.2.3"]));
    }

    #[test]
    fn a_named_host_does_not_widen_to_the_rest_of_the_network() {
        let p = policy(&["localhost:5432", "*"]);
        assert!(!allowed(&p, "127.0.0.1", 22, &["127.0.0.1"]));
        assert!(!allowed(&p, "10.0.0.1", 22, &["10.0.0.1"]));
        assert!(allowed(&p, "example.com", 22, &["93.184.216.34"]));
    }

    #[test]
    fn host_rules_are_case_insensitive_and_ignore_a_trailing_dot() {
        let p = policy(&["Example.COM"]);
        assert!(allowed(&p, "example.com.", 80, &["93.184.216.34"]));
        assert!(allowed(&p, "EXAMPLE.com", 80, &["93.184.216.34"]));
        assert!(!allowed(&p, "evil.com", 80, &["93.184.216.34"]));
    }

    #[test]
    fn address_ranges_apply_to_literal_addresses_and_to_resolved_names() {
        let p = policy(&["203.0.113.0/24"]);
        assert!(allowed(&p, "203.0.113.9", 80, &["203.0.113.9"]));
        assert!(!allowed(&p, "203.0.114.9", 80, &["203.0.114.9"]));
        assert!(allowed(&p, "svc.example.com", 80, &["203.0.113.50"]));
        assert!(!allowed(&p, "svc.example.com", 80, &["198.51.100.1"]));
    }

    #[test]
    fn dns_answers_are_filtered_and_a_name_needs_a_rule() {
        let p = policy(&["*"]);
        assert!(p.check_resolve("example.com").is_ok());
        assert_eq!(
            p.authorize_addrs("example.com", None, &[ip("127.0.0.1"), ip("93.184.216.34")]),
            vec![ip("93.184.216.34")]
        );
        assert!(policy(&["only.example.com"])
            .check_resolve("other.example.com")
            .is_err());
    }

    #[test]
    fn rules_that_do_not_parse_are_dropped_not_widened() {
        let p = policy(&["10.0.0.0/33", "host:notaport", "", "10.0.0.0/8:x"]);
        assert!(!allowed(&p, "10.0.0.1", 80, &["10.0.0.1"]));
        assert!(p.check_connect("host", 80).is_err());
    }

    #[test]
    fn the_wildcard_and_a_name_rule_refuse_everything_the_node_guard_refuses() {
        // What the list-of-ranges check let through before it was the same classifier as the Node host's.
        let wild = policy(&["*"]);
        let named = policy(&["partner.example.com"]);
        for addr in [
            "2002:7f00:1::",
            "2002:a00:1::1",
            "2002:c0a8:101::1",
            "2002:a9fe:a9fe::1",
            "2002::",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:1::1",
            "64:ff9b:1::1",
            "64:ff9b:1::808:808",
            "::8.8.8.8",
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.9",
            "198.18.0.1",
            "192.0.0.8",
            "192.88.99.1",
            "240.0.0.1",
            "2001:db8::1",
            "3fff::1",
            "2001:2::1",
            "1::1",
            "4000::1",
            "100::1",
            "168.63.129.16",
            "100.100.100.200",
            "fd00:ec2::254",
            "::ffff:192.0.2.1",
        ] {
            assert!(
                !allowed(&wild, addr, 80, &[addr]),
                "{addr} must be refused by the wildcard"
            );
            assert!(
                !allowed(&named, "partner.example.com", 80, &[addr]),
                "a name resolving to {addr} must be refused"
            );
        }
    }

    #[test]
    fn a_public_address_carried_by_a_wrapped_form_is_public() {
        let p = policy(&["*"]);
        for addr in [
            "2002:808:808::1",
            "2002:5db8:d822::1",
            "64:ff9b::808:808",
            "::ffff:8.8.8.8",
            "2606:4700:4700::1111",
            "2001:200::1",
        ] {
            assert!(allowed(&p, addr, 443, &[addr]), "{addr} is public");
        }
    }

    #[test]
    fn a_rule_that_names_an_address_or_a_range_permits_it_whatever_its_class() {
        // An explicit rule opens any class: that is how an operator reaches a metadata endpoint, a lab's
        // documentation range or a multicast group on purpose. The wildcard never does.
        for (rule, addr) in [
            ("169.254.169.254", "169.254.169.254"),
            ("169.254.169.254/32", "169.254.169.254"),
            ("192.0.2.0/24", "192.0.2.77"),
            ("198.18.0.0/15", "198.19.1.1"),
            ("240.0.0.0/4", "240.1.2.3"),
            ("224.0.0.0/4", "239.1.1.1"),
            ("0.0.0.0/8", "0.1.2.3"),
            ("fd00:ec2::254", "fd00:ec2::254"),
            ("2001:db8::/32", "2001:db8::5"),
            ("2002:7f00:1::/48", "2002:7f00:1::1"),
            ("2001::/32", "2001:0:4136:e378:8000:63bf:3fff:fdd2"),
            ("64:ff9b:1::/48", "64:ff9b:1::7f00:1"),
            ("::ffff:0:0/96", "::ffff:127.0.0.1"),
            ("::/0", "::1"),
        ] {
            let p = policy(&[rule]);
            assert!(allowed(&p, addr, 80, &[addr]), "rule {rule} names {addr}");
            if rule.contains('/') {
                assert!(
                    allowed(&p, "svc.example.com", 80, &[addr]),
                    "rule {rule} lets a name resolve to {addr}"
                );
            }
        }
    }

    #[test]
    fn a_rule_that_names_loopback_does_not_reach_the_forms_that_wrap_it() {
        let p = policy(&["127.0.0.1", "10.0.0.0/8"]);
        assert!(allowed(&p, "127.0.0.1", 80, &["127.0.0.1"]));
        for addr in ["2002:7f00:1::", "64:ff9b::7f00:1", "::ffff:127.0.0.1"] {
            assert!(!allowed(&p, addr, 80, &[addr]), "{addr}");
        }
        for addr in ["2002:a00:1::1", "64:ff9b::a00:1"] {
            assert!(
                !allowed(&p, addr, 80, &[addr]),
                "{addr}: an IPv4 range names IPv4 addresses"
            );
        }
    }

    #[test]
    fn test_allow_specific() {
        let p = policy(&["example.com"]);
        assert!(allowed(&p, "example.com", 80, &["93.184.216.34"]));
        assert!(!allowed(&p, "evil.com", 80, &["93.184.216.34"]));
    }

    #[test]
    fn test_connection_limit() {
        let p = GatewayPolicyEnforcer::new(GatewayPolicy {
            allowed_destinations: vec!["*".to_string()],
            max_connections: 2,
            ..GatewayPolicy::default()
        });
        let _g1 = p.acquire();
        let _g2 = p.acquire();
        assert!(p.check_connect("example.com", 80).is_err());
    }

    #[test]
    fn test_connection_guard_releases() {
        let p = GatewayPolicyEnforcer::new(GatewayPolicy {
            allowed_destinations: vec!["*".to_string()],
            max_connections: 1,
            ..GatewayPolicy::default()
        });
        {
            let _guard = p.acquire();
            assert_eq!(p.active_connections(), 1);
        }
        assert_eq!(p.active_connections(), 0);
        assert!(p.check_connect("example.com", 80).is_ok());
    }

    #[test]
    fn test_reverse_tunnels_disabled() {
        let p = GatewayPolicyEnforcer::new(GatewayPolicy {
            allowed_destinations: vec!["*".to_string()],
            enable_reverse_tunnels: false,
            ..GatewayPolicy::default()
        });
        assert!(p.check_listen(8080).is_err());
        assert!(policy(&["*"]).check_listen(8080).is_ok());
    }
}
