//! Peer registry for reverse connections.
//!
//! Stores connected peers indexed by their public key fingerprint,
//! allowing other clients to discover and connect to them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info};
use wsh_core::identity::FingerprintIndex;

/// Additional metadata advertised by a reverse peer.
#[derive(Debug, Clone)]
pub struct PeerMetadata {
    pub peer_type: String,
    pub shell_backend: String,
    pub supports_attach: bool,
    pub supports_replay: bool,
    pub supports_echo: bool,
    pub supports_term_sync: bool,
}

impl Default for PeerMetadata {
    fn default() -> Self {
        Self {
            peer_type: "host".to_string(),
            shell_backend: "pty".to_string(),
            supports_attach: false,
            supports_replay: false,
            supports_echo: false,
            supports_term_sync: false,
        }
    }
}

/// A registered peer available for reverse connections.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// Full fingerprint of the peer's public key.
    pub fingerprint: String,
    /// Username of the peer.
    pub username: String,
    /// Capabilities advertised by the peer.
    pub capabilities: Vec<String>,
    /// Canonical peer category.
    pub peer_type: String,
    /// Shell/runtime backend exposed by the peer.
    pub shell_backend: String,
    /// Whether the peer supports attach semantics.
    pub supports_attach: bool,
    /// Whether the peer supports replay semantics.
    pub supports_replay: bool,
    /// Whether the peer emits echo telemetry.
    pub supports_echo: bool,
    /// Whether the peer emits terminal sync telemetry.
    pub supports_term_sync: bool,
    /// When the peer registered.
    pub registered_at: Instant,
    /// Last heartbeat / activity.
    pub last_seen: Instant,
    /// Opaque connection handle (index into an internal connection table).
    pub connection_id: u64,
}

/// Registry of peers available for reverse connections.
pub struct PeerRegistry {
    /// Peers indexed by full fingerprint.
    peers: Arc<RwLock<HashMap<String, PeerEntry>>>,
    /// Fingerprint index for prefix lookups.
    index: Arc<RwLock<FingerprintIndex>>,
    /// Monotonic connection ID counter.
    next_conn_id: Arc<tokio::sync::Mutex<u64>>,
}

impl PeerRegistry {
    /// Create a new empty peer registry.
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            index: Arc::new(RwLock::new(FingerprintIndex::new())),
            next_conn_id: Arc::new(tokio::sync::Mutex::new(1)),
        }
    }

    /// Register a peer with a specific connection ID (from the server's ID space).
    /// This ensures the registry's connection_id matches peer_senders keys.
    /// If `server_conn_id` is `None`, generates an internal one (legacy fallback).
    pub async fn register(
        &self,
        fingerprint: String,
        username: String,
        capabilities: Vec<String>,
    ) -> u64 {
        self.register_with_conn_id(
            fingerprint,
            username,
            capabilities,
            PeerMetadata::default(),
            None,
        )
            .await
    }

    /// Register a peer with an explicit server-assigned connection ID.
    pub async fn register_with_conn_id(
        &self,
        fingerprint: String,
        username: String,
        capabilities: Vec<String>,
        metadata: PeerMetadata,
        server_conn_id: Option<u64>,
    ) -> u64 {
        let conn_id = match server_conn_id {
            Some(id) => id,
            None => {
                let mut conn_id_lock = self.next_conn_id.lock().await;
                let id = *conn_id_lock;
                *conn_id_lock += 1;
                id
            }
        };

        let now = Instant::now();
        let entry = PeerEntry {
            fingerprint: fingerprint.clone(),
            username: username.clone(),
            capabilities,
            peer_type: metadata.peer_type,
            shell_backend: metadata.shell_backend,
            supports_attach: metadata.supports_attach,
            supports_replay: metadata.supports_replay,
            supports_echo: metadata.supports_echo,
            supports_term_sync: metadata.supports_term_sync,
            registered_at: now,
            last_seen: now,
            connection_id: conn_id,
        };

        let mut peers = self.peers.write().await;
        peers.insert(fingerprint.clone(), entry);

        let mut index = self.index.write().await;
        index.insert(fingerprint.clone(), username.clone());

        info!(fingerprint = %&fingerprint[..8.min(fingerprint.len())], username = %username, "peer registered");

        conn_id
    }

    /// Unregister a peer by fingerprint.
    pub async fn unregister(&self, fingerprint: &str) {
        let mut peers = self.peers.write().await;
        if peers.remove(fingerprint).is_some() {
            let mut index = self.index.write().await;
            index.remove(fingerprint);
            debug!(fingerprint = %&fingerprint[..8.min(fingerprint.len())], "peer unregistered");
        }
    }

    /// Touch a peer's last_seen timestamp.
    pub async fn touch(&self, fingerprint: &str) {
        let mut peers = self.peers.write().await;
        if let Some(entry) = peers.get_mut(fingerprint) {
            entry.last_seen = Instant::now();
        }
    }

    /// List all registered peers.
    pub async fn list(&self) -> Vec<PeerEntry> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    /// Look up a peer by fingerprint prefix.
    pub async fn resolve(&self, prefix: &str) -> Option<PeerEntry> {
        let index = self.index.read().await;
        match index.resolve(prefix) {
            Ok(Some((fp, _))) => {
                let peers = self.peers.read().await;
                peers.get(fp).cloned()
            }
            _ => None,
        }
    }

    /// Remove peers that have been idle for more than `max_idle_secs`.
    pub async fn gc(&self, max_idle_secs: u64) -> Vec<String> {
        let mut peers = self.peers.write().await;
        let mut removed = Vec::new();

        peers.retain(|fp, entry| {
            if entry.last_seen.elapsed().as_secs() > max_idle_secs {
                removed.push(fp.clone());
                false
            } else {
                true
            }
        });

        if !removed.is_empty() {
            let mut index = self.index.write().await;
            for fp in &removed {
                index.remove(fp);
            }
            debug!(count = removed.len(), "GC removed idle peers");
        }

        removed
    }

    /// Number of registered peers.
    pub async fn count(&self) -> usize {
        self.peers.read().await.len()
    }
}
