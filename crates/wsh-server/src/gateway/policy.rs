//! Gateway policy — controls what destinations can be connected to,
//! connection limits, and reverse tunnel enablement.
//!
//! The policy layer is split into two types:
//!
//! - [`GatewayPolicy`] — a plain configuration struct (cloneable, serializable)
//!   that holds the rules.
//! - [`GatewayPolicyEnforcer`] — the runtime counterpart that owns the policy
//!   plus an atomic connection counter, performing all access-control checks.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Static gateway access-control configuration.
///
/// Describes which destinations a gateway may connect to, how many concurrent
/// connections are permitted, and whether reverse tunnels are allowed.
///
/// # Destination Matching
///
/// The `allowed_destinations` list supports three forms:
///
/// | Pattern           | Matches                                   |
/// |-------------------|-------------------------------------------|
/// | `"*"`             | Any host and port (wildcard).              |
/// | `"example.com"`   | The exact hostname on **any** port.        |
/// | `"example.com:443"`| The exact hostname **and** port pair.     |
///
/// An empty list means **no** destinations are allowed.
#[derive(Debug, Clone)]
pub struct GatewayPolicy {
    /// Allowed destination patterns.
    ///
    /// Empty = allow none. `["*"]` = allow all.
    /// See the struct-level docs for the full matching rules.
    pub allowed_destinations: Vec<String>,
    /// Maximum number of concurrent gateway connections (TCP + UDP + listeners).
    pub max_connections: usize,
    /// Whether reverse tunnels (`ListenRequest`) are enabled.
    pub enable_reverse_tunnels: bool,
}

/// Default policy: allow all destinations, 100 max connections, reverse tunnels enabled.
impl Default for GatewayPolicy {
    fn default() -> Self {
        Self {
            allowed_destinations: vec!["*".to_string()],
            max_connections: 100,
            enable_reverse_tunnels: true,
        }
    }
}

/// Runtime policy enforcer with atomic connection tracking.
///
/// Wraps a [`GatewayPolicy`] and adds a shared atomic counter so that
/// connection-limit checks are thread-safe across concurrent tasks.
/// Pre-computes a `HashSet` of allowed destinations for O(1) lookups.
pub struct GatewayPolicyEnforcer {
    /// The underlying static policy rules.
    policy: GatewayPolicy,
    /// Shared atomic counter of currently active gateway connections.
    active_connections: Arc<AtomicUsize>,
    /// Pre-computed set of allowed destination strings for fast lookups.
    allowed_set: HashSet<String>,
    /// Fast-path flag: `true` when the wildcard `"*"` is present.
    allow_all: bool,
}

impl GatewayPolicyEnforcer {
    /// Create a new enforcer from the given policy.
    ///
    /// Pre-computes the destination allowlist into a `HashSet` and detects
    /// the wildcard `"*"` entry for fast-path evaluation.
    ///
    /// # Arguments
    ///
    /// * `policy` - The [`GatewayPolicy`] describing access-control rules.
    pub fn new(policy: GatewayPolicy) -> Self {
        let allow_all = policy.allowed_destinations.contains(&"*".to_string());
        let allowed_set: HashSet<String> = policy.allowed_destinations.iter().cloned().collect();
        Self {
            policy,
            active_connections: Arc::new(AtomicUsize::new(0)),
            allowed_set,
            allow_all,
        }
    }

    /// Check if a TCP/UDP connection to `host:port` is allowed.
    ///
    /// Verifies two conditions in order:
    /// 1. The current number of active connections is below `max_connections`.
    /// 2. The destination matches the allowlist (wildcard, exact host, or exact host:port).
    ///
    /// # Arguments
    ///
    /// * `host` - The target hostname or IP address.
    /// * `port` - The target port number.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if the connection limit has been reached or if
    /// the destination is not present in the allowlist.
    pub fn check_connect(&self, host: &str, port: u16) -> Result<(), String> {
        // Check connection limit
        let current = self.active_connections.load(Ordering::Relaxed);
        if current >= self.policy.max_connections {
            return Err(format!(
                "connection limit reached ({}/{})",
                current, self.policy.max_connections
            ));
        }

        // Check destination allowlist
        if self.allow_all {
            return Ok(());
        }

        let dest = format!("{}:{}", host, port);
        let host_only = host.to_string();

        if self.allowed_set.contains(&dest) || self.allowed_set.contains(&host_only) {
            return Ok(());
        }

        Err(format!("destination not allowed: {}:{}", host, port))
    }

    /// Check if reverse tunnel listening is allowed on the given port.
    ///
    /// Verifies two conditions:
    /// 1. Reverse tunnels are enabled in the policy (`enable_reverse_tunnels`).
    /// 2. The current number of active connections is below `max_connections`.
    ///
    /// # Arguments
    ///
    /// * `_port` - The requested listen port (currently unused in the check
    ///   but reserved for future per-port restrictions).
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if reverse tunnels are disabled or the
    /// connection limit has been reached.
    pub fn check_listen(&self, _port: u16) -> Result<(), String> {
        if !self.policy.enable_reverse_tunnels {
            return Err("reverse tunnels are disabled".to_string());
        }

        let current = self.active_connections.load(Ordering::Relaxed);
        if current >= self.policy.max_connections {
            return Err(format!(
                "connection limit reached ({}/{})",
                current, self.policy.max_connections
            ));
        }

        Ok(())
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
    ///
    /// Uses `Relaxed` ordering, so the value is an approximation in the
    /// presence of concurrent acquires/releases. Suitable for metrics and
    /// logging, not for synchronisation.
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }
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

    #[test]
    fn test_allow_all() {
        let policy = GatewayPolicy::default();
        let enforcer = GatewayPolicyEnforcer::new(policy);
        assert!(enforcer.check_connect("example.com", 80).is_ok());
        assert!(enforcer.check_connect("10.0.0.1", 443).is_ok());
    }

    #[test]
    fn test_allow_specific() {
        let policy = GatewayPolicy {
            allowed_destinations: vec!["example.com".to_string()],
            max_connections: 100,
            enable_reverse_tunnels: true,
        };
        let enforcer = GatewayPolicyEnforcer::new(policy);
        assert!(enforcer.check_connect("example.com", 80).is_ok());
        assert!(enforcer.check_connect("evil.com", 80).is_err());
    }

    #[test]
    fn test_connection_limit() {
        let policy = GatewayPolicy {
            allowed_destinations: vec!["*".to_string()],
            max_connections: 2,
            enable_reverse_tunnels: true,
        };
        let enforcer = GatewayPolicyEnforcer::new(policy);
        let _g1 = enforcer.acquire();
        let _g2 = enforcer.acquire();
        assert!(enforcer.check_connect("example.com", 80).is_err());
    }

    #[test]
    fn test_connection_guard_releases() {
        let policy = GatewayPolicy {
            allowed_destinations: vec!["*".to_string()],
            max_connections: 1,
            enable_reverse_tunnels: true,
        };
        let enforcer = GatewayPolicyEnforcer::new(policy);
        {
            let _guard = enforcer.acquire();
            assert_eq!(enforcer.active_connections(), 1);
        }
        assert_eq!(enforcer.active_connections(), 0);
        assert!(enforcer.check_connect("example.com", 80).is_ok());
    }

    #[test]
    fn test_reverse_tunnels_disabled() {
        let policy = GatewayPolicy {
            allowed_destinations: vec!["*".to_string()],
            max_connections: 100,
            enable_reverse_tunnels: false,
        };
        let enforcer = GatewayPolicyEnforcer::new(policy);
        assert!(enforcer.check_listen(8080).is_err());
    }
}
