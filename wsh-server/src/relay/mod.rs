//! Reverse connection relay: registry and broker.

pub mod broker;
pub mod registry;

// #38 Phase 2 feasibility spike: WISP reverse-connect demultiplexing design
// proof-of-concept. NOT wired into the live relay — see module docs.
#[cfg(test)]
pub mod wisp_bridge_poc;

pub use broker::RelayBroker;
pub use registry::{PeerEntry, PeerMetadata, PeerRegistry};
