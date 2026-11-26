//! wsh-core: Shared protocol library for the Web Shell.
//!
//! Provides CBOR message types, codec, identity/fingerprint management,
//! authorized_keys parsing, HMAC session tokens, and abstract transport traits.

// The gateway code (moved here from `wsh-server` so the CLI's reverse host serves the same gateway under the same policy)
// names this crate as `wsh_core::...`; that path works inside the crate too.
extern crate self as wsh_core;

pub mod channel_binding;
pub mod codec;
pub mod e2e_exchange;
pub mod error;
pub mod gateway;
pub mod gateway_credit;
pub mod gateway_datagram;
pub mod host_key;
pub mod identity;
pub mod keys;
pub mod messages;
pub mod operator_proof;
pub mod peer_record;
pub mod peer_watch;
pub mod qmux;
pub mod qmux_connection;
pub mod remote_runtime;
pub mod rpc_codec;
pub mod rpc_credit;
pub mod token;
pub mod transport;

/// `ServerHello.features` of a relay that serves several operators per peer, and
/// `ReverseAccept.features` of a peer that does: it addresses each message to one operator with
/// `RelayForward.to_fingerprint` and understands `ReverseClose` (wsh #89, #93).
pub const RELAY_MULTI_OPERATOR_FEATURE: &str = "relay-multi-operator";

/// `ServerHello.features` of a relay that carries a reverse host's gateway requests (`OpenTcp`, `OpenUdp`, `ResolveDns`,
/// `ListenRequest` and their answers: `is_relay_gateway_forwardable`), and `ReverseAccept.features` of a peer whose owner turned its
/// gateway on for operators behind the relay. Implies `gateway-credit` on every connection opened that way (wsh #289).
pub const RELAY_GATEWAY_FEATURE: &str = "relay-gateway";

// Re-export commonly used items at crate root.
pub use codec::{cbor_decode, cbor_encode, decode_envelope, frame_encode, FrameDecoder};
pub use error::{WshError, WshResult};
pub use identity::{fingerprint, short_fingerprint, FingerprintIndex};
pub use messages::{AuthMethod, ChannelKind, MsgType, PROTOCOL_VERSION};
pub use peer_record::{
    build_peer_record_transcript, sign_peer_record, verify_peer_record, PeerRecord,
};
pub use remote_runtime::{
    PeerType, ReachabilityDescriptor, RemoteIdentity, RemotePeerDescriptor, SessionIntent,
    SessionTarget, ShellBackend,
};
pub use token::{create_token, generate_secret, verify_token};
