//! DNS resolution via `tokio::net::lookup_host`.
//!
//! Provides a thin async wrapper that filters results by record type (`A` /
//! `AAAA`) and returns them as string IP addresses. Used by
//! [`super::forwarder::GatewayForwarder::handle_resolve_dns`].

use tokio::net;
use tracing::{debug, warn};

/// Stateless async DNS resolver.
///
/// All methods are static; the struct exists only for namespacing.
pub struct DnsResolver;

impl DnsResolver {
    /// Resolve a hostname to IP addresses filtered by record type.
    ///
    /// Uses `tokio::net::lookup_host` for non-blocking resolution. A dummy
    /// port (`:0`) is appended internally because the API requires a
    /// `host:port` pair.
    ///
    /// # Arguments
    ///
    /// * `name` - The hostname to resolve (e.g. `"example.com"`).
    /// * `record_type` - Filter for the DNS record type. Supported values:
    ///   - `"A"` — return only IPv4 addresses.
    ///   - `"AAAA"` — return only IPv6 addresses.
    ///   - Any other value — return all addresses (both v4 and v6).
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` if `lookup_host` fails (e.g. NXDOMAIN) or if
    /// no addresses match the requested `record_type`.
    ///
    /// # Note
    ///
    /// The returned TTL is always `None` because `tokio::net::lookup_host`
    /// does not expose DNS TTL information.
    pub async fn resolve(
        name: &str,
        record_type: &str,
    ) -> Result<(Vec<String>, Option<u32>), String> {
        // Append a port for lookup_host (required by the API)
        let lookup_addr = format!("{}:0", name);

        let result = net::lookup_host(&lookup_addr).await;
        match result {
            Ok(addrs) => {
                let addresses: Vec<String> = addrs
                    .filter_map(|addr| {
                        let ip = addr.ip();
                        match record_type {
                            "A" if ip.is_ipv4() => Some(ip.to_string()),
                            "AAAA" if ip.is_ipv6() => Some(ip.to_string()),
                            _ if record_type == "A" || record_type == "AAAA" => None,
                            // For other types, return all
                            _ => Some(ip.to_string()),
                        }
                    })
                    .collect();

                if addresses.is_empty() {
                    debug!(name = %name, record_type = %record_type, "no matching addresses found");
                    Err(format!("no {} records found for {}", record_type, name))
                } else {
                    debug!(name = %name, record_type = %record_type, count = addresses.len(), "resolved");
                    Ok((addresses, None)) // TTL not available from lookup_host
                }
            }
            Err(e) => {
                warn!(name = %name, error = %e, "DNS resolution failed");
                Err(format!("DNS resolution failed for {}: {}", name, e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_localhost() {
        let result = DnsResolver::resolve("localhost", "A").await;
        assert!(result.is_ok(), "localhost should resolve: {:?}", result);
        let (addrs, _ttl) = result.unwrap();
        assert!(
            !addrs.is_empty(),
            "localhost should have at least one address"
        );
        assert!(
            addrs.iter().any(|a| a == "127.0.0.1"),
            "localhost should resolve to 127.0.0.1, got: {:?}",
            addrs
        );
    }

    #[tokio::test]
    async fn test_resolve_invalid() {
        let result = DnsResolver::resolve("this.host.definitely.does.not.exist.invalid", "A").await;
        assert!(result.is_err());
    }
}
