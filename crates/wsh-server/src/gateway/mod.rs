//! Gateway module — TCP/UDP/unix-socket forwarding, DNS resolution, and reverse tunnel listeners.
//!
//! Handles the gateway message types (`0x63`-`0x65`, `0x70`-`0x7f`) by forwarding connections
//! through the server to destinations the operator has allowed.
//!
//! # Submodules
//!
//! - **[`policy`]** — [`GatewayPolicy`] (the configuration) and the
//!   [`GatewayPolicyEnforcer`](policy::GatewayPolicyEnforcer): destination rules, the connection
//!   limit, reverse-tunnel enablement, and the byte caps.
//! - **[`unix_policy`]** — which unix-domain socket paths a client may reach or create: default
//!   deny, allow-listed paths checked after `realpath` of the parent, the target must be a socket.
//! - **[`forwarder`]** — [`GatewayForwarder`]: authorizes a destination (name rule, one
//!   resolution, address rule) and answers `ResolveDns`.
//! - **[`session`]** — [`GatewaySession`]: ONE client connection's gateway. It owns that
//!   connection's `gateway_id` and `listener_id` tables, relays with `GatewayCredit` flow control,
//!   reverse listeners (TCP and unix) and their pending inbound connections, and closes all of it
//!   when the connection ends.
//! - **[`resolver`]** — [`DnsResolver`]: `tokio::net::lookup_host`, filtered by record type.
//!
//! # Data flow
//!
//! ```text
//! Client message
//!   → dispatch_message (server.rs)
//!     → GatewaySession::handle           (spawns the work; answers go through the connection's queue)
//!         → GatewayForwarder::authorized_destination / unix_policy::check_unix_path
//!         → relay tasks: origin → client (while credit is held), client → origin (credit returned)
//! ```

pub mod forwarder;
pub mod policy;
pub mod resolver;
pub mod session;
pub mod unix_policy;

pub use forwarder::GatewayForwarder;
pub use policy::GatewayPolicy;
pub use resolver::DnsResolver;
pub use session::GatewaySession;
