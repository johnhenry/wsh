//! Reverse connection relay: registry and broker.

pub mod broker;
pub mod registry;

// #38 Phase 2: WISP reverse-connect bridge, wired into the live relay via
// `transport::websocket`'s `/wisp/<fingerprint>` and
// `/wisp-connect/<fingerprint>` endpoints (see `server.rs`).
pub mod wisp;

// #38 Phase 2 feasibility spike (PR #118): the original demultiplexing
// design proof-of-concept, kept for its design-rationale doc comments and
// its own independent test coverage. Superseded by `wisp` above, which is
// the version actually wired into the relay.
#[cfg(test)]
pub mod wisp_bridge_poc;

pub use broker::RelayBroker;
pub use registry::{PeerEntry, PeerMetadata, PeerRegistry};
pub use wisp::{WispGuestSession, WispRegistry};
