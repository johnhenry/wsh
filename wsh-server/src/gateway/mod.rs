//! Gateway module — TCP/UDP forwarding, DNS resolution, and reverse tunnel listeners.
//!
//! Handles gateway message types (`0x70`–`0x7d`) by forwarding TCP/UDP
//! connections through the server to external destinations.
//!
//! # Submodule Architecture
//!
//! The gateway is composed of four cooperating submodules:
//!
//! - **[`policy`]** — Defines the [`GatewayPolicy`] configuration and the
//!   [`GatewayPolicyEnforcer`](policy::GatewayPolicyEnforcer) that performs
//!   destination allowlist checks, connection-limit enforcement, and
//!   reverse-tunnel enablement checks. All outbound and listener operations
//!   consult the enforcer before proceeding.
//!
//! - **[`forwarder`]** — The [`GatewayForwarder`] handles `OpenTcp`,
//!   `OpenUdp`, and `ResolveDns` requests. It checks the policy, establishes
//!   the outbound connection or DNS lookup, spawns relay tasks, and returns
//!   `GatewayOk` / `GatewayFail` envelopes to the caller.
//!
//! - **[`resolver`]** — The [`DnsResolver`] provides async hostname-to-IP
//!   resolution via `tokio::net::lookup_host`, filtering results by record
//!   type (`A` or `AAAA`). Used internally by the forwarder.
//!
//! - **[`listener`]** — The [`ReverseListenerManager`] handles `ListenRequest`
//!   messages by binding TCP listeners on the server, accepting inbound
//!   connections, and notifying the client via `InboundOpen` messages sent
//!   through an `mpsc` channel.
//!
//! # Data Flow
//!
//! ```text
//! Client message
//!   → dispatch_message (server.rs)
//!     → GatewayForwarder::handle_open_tcp / handle_open_udp / handle_resolve_dns
//!         → GatewayPolicyEnforcer::check_connect
//!         → DnsResolver::resolve (for DNS requests)
//!         → spawn relay task (for TCP)
//!     → ReverseListenerManager::handle_listen_request
//!         → GatewayPolicyEnforcer::check_listen
//!         → spawn accept loop → InboundEvent → client
//! ```

pub mod forwarder;
pub mod listener;
pub mod policy;
pub mod resolver;

pub use forwarder::GatewayForwarder;
pub use listener::ReverseListenerManager;
pub use policy::GatewayPolicy;
pub use resolver::DnsResolver;

/// Event sent from a TCP relay task back to the session loop.
///
/// The session loop converts these into outbound control messages
/// (`GatewayData` or `GatewayClose`) and sends them to the client.
#[derive(Debug)]
pub enum GatewayEvent {
    /// Data received from a remote TCP peer, to be forwarded to the client.
    Data { gateway_id: u32, data: Vec<u8> },
    /// Remote TCP peer closed the connection.
    Closed { gateway_id: u32 },
}
