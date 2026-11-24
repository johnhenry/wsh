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
//! and an address that is loopback, link-local, private (RFC 1918), unique-local
//! (`fc00::/7`), carrier-grade NAT (`100.64.0.0/10`), unspecified or multicast is
//! refused *after the name has been resolved* -- whatever rule matched the name --
//! unless a rule names that host or address specifically. The wildcard `"*"` therefore
//! means "any public destination", never "this machine's network".
//!
//! # Rules
//!
//! | Rule                 | Matches                                                          |
//! |----------------------|------------------------------------------------------------------|
//! | `"*"`                | Any host and port whose address is not restricted (above).       |
//! | `"example.com"`      | That hostname on any port. Names a restricted address it resolves to. |
//! | `"example.com:443"`  | That hostname and port.                                          |
//! | `"10.0.0.0/8"`       | Any address in the range, any port. Names the range.             |
//! | `"10.0.0.0/8:5432"`  | Addresses in the range, that port. (IPv6 ranges: `fd00::/8`, no port.) |
//! | `"127.0.0.1:5432"`   | A literal address (and optionally port). Names it.               |

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
}

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

/// An address that belongs to the host's own machine or network rather than the internet.
///
/// IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible and NAT64 (`64:ff9b::/96`) IPv6
/// addresses are judged by the IPv4 address inside them.
pub fn is_restricted_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || o[0] == 0
                // 100.64.0.0/10, carrier-grade NAT (also where some clouds put internal services)
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_restricted_address(IpAddr::V4(v4));
            }
            let s = a.segments();
            // ::a.b.c.d (IPv4-compatible) and 64:ff9b::a.b.c.d (NAT64)
            if s[..6] == [0, 0, 0, 0, 0, 0] || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let v4 =
                    Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
                if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] || !a.is_unspecified() && !a.is_loopback() {
                    return is_restricted_address(IpAddr::V4(v4));
                }
            }
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated)
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
        }
    }
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
                    } => port_matches(*rp, port) && (h == &host || *rip == Some(ip)),
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
    fn a_rule_that_names_a_restricted_host_or_address_allows_it() {
        let p = policy(&[
            "localhost:5432",
            "10.1.2.3",
            "192.168.0.0/16:443",
            "db.internal",
        ]);
        assert!(allowed(&p, "localhost", 5432, &["127.0.0.1"]));
        assert!(!allowed(&p, "localhost", 22, &["127.0.0.1"]), "other port");
        assert!(
            !allowed(&p, "127.0.0.1", 5432, &["127.0.0.1"]),
            "the rule names the host `localhost`, not the address"
        );
        assert!(allowed(&p, "10.1.2.3", 1, &["10.1.2.3"]));
        assert!(!allowed(&p, "10.1.2.4", 1, &["10.1.2.4"]));
        assert!(allowed(&p, "192.168.7.7", 443, &["192.168.7.7"]));
        assert!(!allowed(&p, "192.168.7.7", 80, &["192.168.7.7"]));
        assert!(
            allowed(&p, "db.internal", 1, &["10.9.9.9"]),
            "a name the admin listed may resolve inside"
        );
        assert!(!allowed(&p, "other.internal", 1, &["10.9.9.9"]));
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
