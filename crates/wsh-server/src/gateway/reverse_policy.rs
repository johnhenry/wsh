//! Policy of the TCP reverse tunnels (`ListenRequest`, wsh #98, #145): the host binds a port on the
//! client's behalf and hands each inbound connection to it. This is the dangerous direction (it puts a
//! port of the HOST on the network), so it is bounded the way the Node host's
//! `src/server/reverse-policy.mjs` bounds it, with the same defaults and the same refusal sentences:
//!
//! - off unless `[gateway] enable_reverse_tunnels` (a separate switch from outbound use);
//! - `reverse_ports`: which ports a client may ask for, numbers and `"lo-hi"` ranges. The default is
//!   `[0, "1024-65535"]` (ephemeral, or any unprivileged port); a list you give REPLACES it, so a port
//!   below 1024 is allowed only when listed;
//! - per client: `reverse_max_listeners` (4); per listener: `reverse_max_connections_per_listener` (16),
//!   `reverse_backlog` (8) and `reverse_idle_secs` (300, 0 = never) of an accepted connection.

use std::time::Duration;

/// Listeners one client connection may hold (the Node host's `maxListeners`).
pub const DEFAULT_MAX_LISTENERS: usize = 4;
/// Open connections one listener may have (`maxConnectionsPerListener`).
pub const DEFAULT_MAX_CONNECTIONS_PER_LISTENER: usize = 16;
/// The `listen(2)` backlog (`backlog`).
pub const DEFAULT_BACKLOG: u32 = 8;
/// Seconds without a byte in either direction before an accepted connection is closed (`idleMs` 300000).
pub const DEFAULT_IDLE_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReversePolicy {
    /// Inclusive `(lo, hi)` ranges a client may ask for.
    pub ports: Vec<(u16, u16)>,
    pub max_listeners: usize,
    pub max_connections_per_listener: usize,
    pub backlog: u32,
    /// `None`: a connection is never closed for being idle.
    pub idle: Option<Duration>,
}

impl Default for ReversePolicy {
    fn default() -> Self {
        Self {
            ports: vec![(0, 0), (1024, 65535)],
            max_listeners: DEFAULT_MAX_LISTENERS,
            max_connections_per_listener: DEFAULT_MAX_CONNECTIONS_PER_LISTENER,
            backlog: DEFAULT_BACKLOG,
            idle: Some(Duration::from_secs(DEFAULT_IDLE_SECS)),
        }
    }
}

/// One entry of `reverse_ports` as TOML gives it: an integer, or `"lo-hi"` / `"port"` text.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum PortRule {
    Number(i64),
    Text(String),
}

impl PortRule {
    fn parse(&self) -> Result<(u16, u16), String> {
        let bad = || {
            format!(
                "config: [gateway] reverse_ports: {} is not a port (0-65535) or a \"lo-hi\" range",
                match self {
                    PortRule::Number(n) => n.to_string(),
                    PortRule::Text(t) => format!("{t:?}"),
                }
            )
        };
        let port = |s: &str| -> Option<u16> {
            let s = s.trim();
            if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse::<u16>().ok()
        };
        match self {
            PortRule::Number(n) => u16::try_from(*n).map(|p| (p, p)).map_err(|_| bad()),
            PortRule::Text(t) => match t.split_once('-') {
                None => port(t).map(|p| (p, p)).ok_or_else(bad),
                Some((lo, hi)) => match (port(lo), port(hi)) {
                    (Some(lo), Some(hi)) if lo <= hi => Ok((lo, hi)),
                    _ => Err(bad()),
                },
            },
        }
    }
}

impl ReversePolicy {
    /// Build the policy from the `[gateway]` settings. A bad port rule or a zero where one is not
    /// meaningful stops start-up rather than being ignored (ignoring it could only widen the policy).
    pub fn new(
        ports: Option<&[PortRule]>,
        max_listeners: usize,
        max_connections_per_listener: usize,
        backlog: u32,
        idle_secs: u64,
    ) -> Result<Self, String> {
        let mut policy = ReversePolicy::default();
        if let Some(rules) = ports {
            policy.ports = rules
                .iter()
                .map(PortRule::parse)
                .collect::<Result<Vec<_>, _>>()?;
        }
        if max_connections_per_listener == 0 {
            return Err(
                "config: [gateway] reverse_max_connections_per_listener must be at least 1".into(),
            );
        }
        if backlog == 0 {
            return Err("config: [gateway] reverse_backlog must be at least 1".into());
        }
        policy.max_listeners = max_listeners;
        policy.max_connections_per_listener = max_connections_per_listener;
        policy.backlog = backlog;
        policy.idle = (idle_secs > 0).then(|| Duration::from_secs(idle_secs));
        Ok(policy)
    }

    /// May a client ask for this port?
    pub fn port_allowed(&self, port: u16) -> bool {
        self.ports
            .iter()
            .any(|(lo, hi)| (*lo..=*hi).contains(&port))
    }

    /// The refusal sentence for a port the policy does not allow (the Node host's).
    pub fn port_refusal(&self, port: u16) -> String {
        if port < 1024 && !self.port_allowed(port) {
            format!("port {port} is not allowed by the reverse-tunnel policy (ports below 1024 must be listed explicitly by the host operator)")
        } else {
            format!("port {port} is not allowed by the reverse-tunnel policy")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(list: &[PortRule]) -> ReversePolicy {
        ReversePolicy::new(Some(list), 4, 16, 8, 300).unwrap()
    }

    #[test]
    fn the_default_allows_ephemeral_and_unprivileged_ports_only() {
        let p = ReversePolicy::default();
        for port in [0, 1024, 40000, 65535] {
            assert!(p.port_allowed(port), "{port}");
        }
        for port in [1, 22, 80, 443, 1023] {
            assert!(!p.port_allowed(port), "{port}");
        }
        assert!(p.port_refusal(80).contains("below 1024 must be listed"));
        assert_eq!(
            p.port_refusal(80),
            "port 80 is not allowed by the reverse-tunnel policy (ports below 1024 must be listed explicitly by the host operator)"
        );
    }

    #[test]
    fn a_given_list_replaces_the_default() {
        let p = rules(&[
            PortRule::Number(80),
            PortRule::Text("8000-8010".into()),
            PortRule::Text("9090".into()),
        ]);
        for port in [80, 8000, 8005, 8010, 9090] {
            assert!(p.port_allowed(port), "{port}");
        }
        for port in [0, 81, 7999, 8011, 9091, 40000] {
            assert!(!p.port_allowed(port), "{port}");
        }
        assert_eq!(
            p.port_refusal(40000),
            "port 40000 is not allowed by the reverse-tunnel policy"
        );
        assert!(rules(&[PortRule::Number(0), PortRule::Number(3000)]).port_allowed(0));
    }

    #[test]
    fn a_bad_rule_stops_start_up() {
        for bad in [
            PortRule::Number(70000),
            PortRule::Number(-1),
            PortRule::Text("9-1".into()),
            PortRule::Text("a".into()),
            PortRule::Text("1-2-3".into()),
            PortRule::Text("".into()),
            PortRule::Text("-5".into()),
        ] {
            let e = ReversePolicy::new(Some(&[bad.clone()]), 4, 16, 8, 300).unwrap_err();
            assert!(e.contains("reverse_ports"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn the_bounds_are_validated_and_idle_zero_means_never() {
        assert!(ReversePolicy::new(None, 4, 0, 8, 300).is_err());
        assert!(ReversePolicy::new(None, 4, 16, 0, 300).is_err());
        assert_eq!(ReversePolicy::new(None, 0, 16, 8, 0).unwrap().idle, None);
        assert_eq!(
            ReversePolicy::new(None, 0, 16, 8, 0).unwrap().max_listeners,
            0
        );
    }
}
