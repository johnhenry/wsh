//! Canonical remote-runtime descriptor types shared across `wsh` surfaces.
//!
//! These types intentionally live in `wsh-core` so both Rust CLI/server code
//! and browser-facing integrations can serialize the same peer/runtime model.

use serde::{Deserialize, Serialize};

use crate::messages::PeerInfo;

/// Remote peer categories used across BrowserMesh and `wsh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerType {
    Host,
    BrowserShell,
    VmGuest,
    Worker,
}

impl PeerType {
    /// Parse an untrusted string into a canonical peer type.
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "browser-shell" => Self::BrowserShell,
            "vm-guest" => Self::VmGuest,
            "worker" => Self::Worker,
            _ => Self::Host,
        }
    }
}

/// Shell/runtime backends for remote sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShellBackend {
    Pty,
    VirtualShell,
    VmConsole,
    ExecOnly,
    /// A v86 guest's own `wsh-server` exposing a real PTY (clawser#38
    /// Phases 1/2's loopback-exec + WISP reverse-connect proof),
    /// distinct from `VmConsole` (a browser-mediated console
    /// emulation with no real guest-side `wsh-server`). Reachable only
    /// via the spawning browser tab's WISP reverse-connect bridge, not
    /// independently — see `wsh-core::guest_linkage`-shaped tooling
    /// (browser-side `clawser-guest-linkage.mjs`) for "hosted by"
    /// provenance (clawser#38 Phase 4).
    GuestNativePty,
}

impl ShellBackend {
    /// Parse an untrusted string into a canonical shell backend.
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "virtual-shell" => Self::VirtualShell,
            "vm-console" => Self::VmConsole,
            "exec-only" => Self::ExecOnly,
            "guest-native-pty" => Self::GuestNativePty,
            _ => Self::Pty,
        }
    }
}

/// High-level session intent used for route selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionIntent {
    Terminal,
    Exec,
    Files,
    Tools,
    Gateway,
    Service,
    Automation,
}

/// Canonical identity record for a remote runtime target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteIdentity {
    pub canonical_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

impl RemoteIdentity {
    /// Create an identity keyed by a fingerprint.
    #[must_use]
    pub fn from_fingerprint(fingerprint: impl Into<String>) -> Self {
        let fingerprint = fingerprint.into();
        Self {
            canonical_id: fingerprint.clone(),
            fingerprint: Some(fingerprint),
            pod_id: None,
            aliases: Vec::new(),
        }
    }
}

/// Reachability path to a remote runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityDescriptor {
    pub kind: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

/// Unified peer/runtime descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePeerDescriptor {
    pub identity: RemoteIdentity,
    pub username: String,
    pub peer_type: PeerType,
    pub shell_backend: ShellBackend,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub supports_attach: bool,
    #[serde(default)]
    pub supports_replay: bool,
    #[serde(default)]
    pub supports_echo: bool,
    #[serde(default)]
    pub supports_term_sync: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reachability: Vec<ReachabilityDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
}

impl RemotePeerDescriptor {
    /// Convert a relay `PeerInfo` payload into the canonical descriptor shape.
    #[must_use]
    pub fn from_wsh_peer_info(peer: &PeerInfo, relay_host: &str, relay_port: u16) -> Self {
        let identity = RemoteIdentity {
            canonical_id: peer.fingerprint.clone(),
            fingerprint: Some(peer.fingerprint.clone()),
            pod_id: None,
            aliases: vec![peer.fingerprint_short.clone()],
        };
        let reachability = ReachabilityDescriptor {
            kind: "reverse-relay".to_string(),
            source: peer.source.clone(),
            endpoint: None,
            relay_host: Some(relay_host.to_string()),
            relay_port: Some(relay_port),
            transport: None,
            last_seen_secs: peer.last_seen,
            capabilities: peer.capabilities.clone(),
        };
        Self {
            identity,
            username: peer.username.clone(),
            peer_type: PeerType::from_wire(&peer.peer_type),
            shell_backend: ShellBackend::from_wire(&peer.shell_backend),
            capabilities: peer.capabilities.clone(),
            supports_attach: peer.supports_attach,
            supports_replay: peer.supports_replay,
            supports_echo: peer.supports_echo,
            supports_term_sync: peer.supports_term_sync,
            reachability: vec![reachability],
            sources: vec![peer.source.clone()],
            conflicts: Vec::new(),
        }
    }
}

/// A resolved target request for opening a remote session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTarget {
    pub selector: String,
    pub intent: SessionIntent,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
    #[serde(default)]
    pub prefer_direct: bool,
}

#[cfg(test)]
mod tests {
    use super::{
        PeerType, RemoteIdentity, RemotePeerDescriptor, SessionIntent, SessionTarget,
        ShellBackend,
    };
    use crate::messages::PeerInfo;

    #[test]
    fn peer_type_from_wire_defaults_unknown_values_to_host() {
        assert_eq!(PeerType::from_wire("host"), PeerType::Host);
        assert_eq!(PeerType::from_wire("browser-shell"), PeerType::BrowserShell);
        assert_eq!(PeerType::from_wire("unknown"), PeerType::Host);
    }

    #[test]
    fn shell_backend_from_wire_defaults_unknown_values_to_pty() {
        assert_eq!(ShellBackend::from_wire("pty"), ShellBackend::Pty);
        assert_eq!(
            ShellBackend::from_wire("virtual-shell"),
            ShellBackend::VirtualShell
        );
        assert_eq!(ShellBackend::from_wire("bogus"), ShellBackend::Pty);
    }

    #[test]
    fn shell_backend_from_wire_recognizes_guest_native_pty() {
        assert_eq!(
            ShellBackend::from_wire("guest-native-pty"),
            ShellBackend::GuestNativePty
        );
        assert_ne!(ShellBackend::GuestNativePty, ShellBackend::VmConsole);
    }

    #[test]
    fn shell_backend_serializes_guest_native_pty_as_kebab_case() {
        let json = serde_json::to_string(&ShellBackend::GuestNativePty).unwrap();
        assert_eq!(json, "\"guest-native-pty\"");
    }

    #[test]
    fn converts_peer_info_with_guest_native_pty_backend() {
        let peer = PeerInfo {
            fingerprint: "guestfp123".into(),
            fingerprint_short: "guestfp1".into(),
            username: "guest".into(),
            capabilities: vec!["shell".into(), "exec".into()],
            peer_type: "vm-guest".into(),
            shell_backend: "guest-native-pty".into(),
            source: "wsh-relay".into(),
            supports_attach: true,
            supports_replay: true,
            supports_echo: false,
            supports_term_sync: false,
            last_seen: Some(1),
            public_key: None,
            seq: None,
            record_signature: None,
        };

        let descriptor = RemotePeerDescriptor::from_wsh_peer_info(&peer, "relay.example", 4422);
        assert_eq!(descriptor.peer_type, PeerType::VmGuest);
        assert_eq!(descriptor.shell_backend, ShellBackend::GuestNativePty);
    }

    #[test]
    fn converts_peer_info_into_remote_descriptor() {
        let peer = PeerInfo {
            fingerprint: "abc123".into(),
            fingerprint_short: "abc123".into(),
            username: "browser".into(),
            capabilities: vec!["shell".into(), "fs".into()],
            peer_type: "browser-shell".into(),
            shell_backend: "virtual-shell".into(),
            source: "wsh-relay".into(),
            supports_attach: true,
            supports_replay: true,
            supports_echo: true,
            supports_term_sync: true,
            last_seen: Some(5),
            public_key: None,
            seq: None,
            record_signature: None,
        };

        let descriptor = RemotePeerDescriptor::from_wsh_peer_info(&peer, "relay.example", 4422);
        assert_eq!(descriptor.identity.canonical_id, "abc123");
        assert_eq!(descriptor.peer_type, PeerType::BrowserShell);
        assert_eq!(descriptor.shell_backend, ShellBackend::VirtualShell);
        assert_eq!(descriptor.reachability[0].relay_host.as_deref(), Some("relay.example"));
        assert!(descriptor.supports_attach);
    }

    #[test]
    fn session_target_serializes_intent() {
        let target = SessionTarget {
            selector: "@alice".into(),
            intent: SessionIntent::Terminal,
            required_capabilities: vec!["shell".into()],
            prefer_direct: true,
        };

        let json = serde_json::to_string(&target).unwrap();
        assert!(json.contains("\"intent\":\"terminal\""));
    }

    #[test]
    fn remote_identity_from_fingerprint_sets_canonical_id() {
        let identity = RemoteIdentity::from_fingerprint("fp123");
        assert_eq!(identity.canonical_id, "fp123");
        assert_eq!(identity.fingerprint.as_deref(), Some("fp123"));
        assert!(identity.aliases.is_empty());
    }
}
