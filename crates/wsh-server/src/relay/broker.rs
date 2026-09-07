//! Relay broker: routes connections between peers.
//!
//! When a client wants to connect to a peer through the relay, the broker
//! finds the target peer in the registry and establishes a bridged connection.

use super::registry::PeerRegistry;
use std::sync::Arc;
use tracing::{info, warn};
use wsh_core::{WshError, WshResult};

/// The relay broker coordinates connections between peers.
pub struct RelayBroker {
    registry: Arc<PeerRegistry>,
}

impl RelayBroker {
    /// Create a new relay broker backed by a peer registry.
    pub fn new(registry: Arc<PeerRegistry>) -> Self {
        Self { registry }
    }

    /// Attempt to broker a connection to a target peer.
    ///
    /// Looks up the target by fingerprint prefix, verifies it is online,
    /// and returns the connection ID for the matched peer.
    ///
    /// The actual stream bridging is handled by the caller using the
    /// returned connection metadata.
    pub async fn route(
        &self,
        target_fingerprint: &str,
        requesting_username: &str,
    ) -> WshResult<BrokerResult> {
        let peer = self.registry.resolve(target_fingerprint).await;

        match peer {
            Some(entry) => {
                info!(
                    target = %&entry.fingerprint[..8.min(entry.fingerprint.len())],
                    target_user = %entry.username,
                    requester = %requesting_username,
                    "brokering connection"
                );

                Ok(BrokerResult {
                    target_fingerprint: entry.fingerprint,
                    target_username: entry.username,
                    target_connection_id: entry.connection_id,
                    target_capabilities: entry.capabilities,
                })
            }
            None => {
                warn!(
                    target_prefix = %target_fingerprint,
                    requester = %requesting_username,
                    "target peer not found"
                );
                Err(WshError::Other(format!(
                    "peer not found: {target_fingerprint}"
                )))
            }
        }
    }

    /// Access the underlying registry (e.g. for listing peers).
    pub fn registry(&self) -> &PeerRegistry {
        &self.registry
    }
}

/// Result of a successful broker lookup.
#[derive(Debug)]
pub struct BrokerResult {
    /// Full fingerprint of the matched target.
    pub target_fingerprint: String,
    /// Username of the target peer.
    pub target_username: String,
    /// Internal connection ID for the target's transport.
    pub target_connection_id: u64,
    /// Capabilities advertised by the target.
    pub target_capabilities: Vec<String>,
}
