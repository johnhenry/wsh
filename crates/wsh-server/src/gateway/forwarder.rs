//! Destination authorization and DNS for the gateway: the half of `OpenTcp` / `OpenUdp` /
//! `ResolveDns` that decides WHERE a client may reach. The per-connection relays, credit and
//! reverse listeners live in [`session`](super::session).

use super::policy::GatewayPolicyEnforcer;
use super::resolver::DnsResolver;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{self, Duration};
use wsh_core::messages::*;

/// How long a destination name may take to resolve, and each address to connect.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Connect to the first address that accepts, trying them in order.
pub(super) async fn connect_first(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last = std::io::Error::other("no address to connect to");
    for addr in addrs {
        match time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = e,
            Err(_) => last = std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"),
        }
    }
    Err(last)
}

/// Checks destinations against the policy and answers DNS lookups.
pub struct GatewayForwarder {
    /// Shared policy enforcer for destination checks.
    policy: Arc<GatewayPolicyEnforcer>,
}

impl GatewayForwarder {
    /// Create a forwarder backed by the given policy enforcer.
    pub fn new(policy: Arc<GatewayPolicyEnforcer>) -> Self {
        Self { policy }
    }

    /// Handle a `ResolveDns` message.
    ///
    /// Returns a [`MsgType::DnsResult`] envelope on success or [`MsgType::GatewayFail`]
    /// (code 3 = `DNS_FAILED`, 4 = `POLICY_DENIED`) on error.
    pub async fn handle_resolve_dns(
        &self,
        gateway_id: u32,
        name: &str,
        record_type: &str,
    ) -> Envelope {
        if let Err(reason) = self.policy.check_resolve(name) {
            return build_gateway_fail(gateway_id, 4, &reason); // POLICY_DENIED
        }
        match DnsResolver::resolve(name, record_type).await {
            Ok((addresses, ttl)) => {
                // Answers inside the host's own network are not for the client to see
                // either, unless a rule names them.
                let parsed: Vec<IpAddr> = addresses.iter().filter_map(|a| a.parse().ok()).collect();
                let allowed = self.policy.authorize_addrs(name, None, &parsed);
                let addresses: Vec<String> = allowed.iter().map(ToString::to_string).collect();
                if addresses.is_empty() {
                    return build_gateway_fail(
                        gateway_id,
                        4,
                        &format!("destination not allowed: {name}"),
                    );
                }
                build_dns_result(gateway_id, addresses, ttl)
            }
            Err(reason) => build_gateway_fail(gateway_id, 3, &reason), // DNS_FAILED
        }
    }

    /// The addresses a client may reach for `host:port`: the policy's name-level check,
    /// then one resolution (none for a literal address), filtered address by address.
    ///
    /// Callers connect to what comes back instead of resolving the name a second time,
    /// so a name cannot answer "public" to this check and "internal" to the connect.
    pub(super) async fn authorized_destination(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, (u32, String)> {
        self.policy
            .check_destination(host, port)
            .map_err(|reason| (4, reason))?; // POLICY_DENIED
        let bare = host.trim_matches(['[', ']']);
        let resolved: Vec<IpAddr> = match bare.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => match time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((bare, port)))
                .await
            {
                Ok(Ok(found)) => found.map(|a| a.ip()).collect(),
                Ok(Err(e)) => return Err((3, format!("DNS resolution failed for {host}: {e}"))),
                Err(_) => return Err((3, format!("DNS resolution timed out for {host}"))),
            },
        };
        let allowed = self.policy.authorize_addrs(host, Some(port), &resolved);
        if allowed.is_empty() {
            return Err((4, format!("destination not allowed: {host}:{port}")));
        }
        Ok(allowed
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

// ── Message builders ─────────────────────────────────────────────────

/// Build a [`MsgType::GatewayFail`] envelope for a failed connection attempt.
///
/// Common error codes:
/// - `1` — `CONNECTION_REFUSED`
/// - `3` — `DNS_FAILED`
/// - `4` — `POLICY_DENIED`
/// - `5` — `GATEWAY_DISABLED`
fn build_gateway_fail(gateway_id: u32, code: u32, message: &str) -> Envelope {
    Envelope {
        msg_type: MsgType::GatewayFail,
        payload: Payload::GatewayFail(GatewayFailPayload {
            gateway_id,
            code,
            message: message.to_string(),
        }),
    }
}

/// Build a [`MsgType::DnsResult`] envelope containing resolved addresses.
fn build_dns_result(gateway_id: u32, addresses: Vec<String>, ttl: Option<u32>) -> Envelope {
    Envelope {
        msg_type: MsgType::DnsResult,
        payload: Payload::DnsResult(DnsResultPayload {
            gateway_id,
            addresses,
            ttl,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::policy::GatewayPolicy;

    fn forwarder(rules: &[&str]) -> GatewayForwarder {
        GatewayForwarder::new(Arc::new(GatewayPolicyEnforcer::new(GatewayPolicy {
            allowed_destinations: rules.iter().map(|r| r.to_string()).collect(),
            ..GatewayPolicy::default()
        })))
    }

    fn fail_code(reply: &Envelope) -> Option<u32> {
        match &reply.payload {
            Payload::GatewayFail(f) => Some(f.code),
            _ => None,
        }
    }

    #[tokio::test]
    async fn dns_lookups_need_a_rule_and_do_not_reveal_internal_answers() {
        let none = forwarder(&[]).handle_resolve_dns(1, "localhost", "A").await;
        assert_eq!(fail_code(&none), Some(4), "{none:?}");

        // `*` allows the lookup, but its only answer is 127.0.0.1: nothing left to return.
        let wild = forwarder(&["*"])
            .handle_resolve_dns(1, "localhost", "A")
            .await;
        assert_eq!(fail_code(&wild), Some(4), "{wild:?}");

        // A name rule alone does not reveal loopback either.
        let by_name = forwarder(&["localhost"])
            .handle_resolve_dns(1, "localhost", "A")
            .await;
        assert_eq!(fail_code(&by_name), Some(4), "{by_name:?}");

        // A rule that names the range lets the answer through.
        let named = forwarder(&["127.0.0.0/8"])
            .handle_resolve_dns(1, "localhost", "A")
            .await;
        match named.payload {
            Payload::DnsResult(r) => assert!(r.addresses.iter().any(|a| a == "127.0.0.1"), "{r:?}"),
            other => panic!("expected an answer, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_default_policy_refuses_every_destination() {
        let err = forwarder(&[]).authorized_destination("127.0.0.1", 80).await;
        assert_eq!(err.unwrap_err().0, 4);
    }

    #[tokio::test]
    async fn the_wildcard_does_not_reach_this_machines_own_services() {
        let f = forwarder(&["*"]);
        for host in ["127.0.0.1", "localhost", "[::1]", "0.0.0.0"] {
            let err = f.authorized_destination(host, 80).await;
            assert_eq!(err.unwrap_err().0, 4, "{host}");
        }
    }

    #[tokio::test]
    async fn a_rule_that_names_the_address_lets_it_through() {
        let ok = forwarder(&["127.0.0.1:80"])
            .authorized_destination("127.0.0.1", 80)
            .await;
        assert!(ok.is_ok());
        assert!(forwarder(&["127.0.0.0/8"])
            .authorized_destination("127.0.0.1", 80)
            .await
            .is_ok());
        // A name rule is not enough: `localhost` resolves to loopback, and only a rule that
        // names that range or address reaches it.
        let by_name = forwarder(&["localhost"])
            .authorized_destination("localhost", 80)
            .await;
        assert_eq!(by_name.unwrap_err().0, 4);
        assert!(forwarder(&["127.0.0.0/8"])
            .authorized_destination("localhost", 80)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn naming_one_port_does_not_open_the_others() {
        let err = forwarder(&["127.0.0.1:80"])
            .authorized_destination("127.0.0.1", 81)
            .await;
        assert_eq!(err.unwrap_err().0, 4);
    }
}
