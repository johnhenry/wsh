//! wsh-core: Shared protocol library for the Web Shell.
//!
//! Provides CBOR message types, codec, identity/fingerprint management,
//! authorized_keys parsing, HMAC session tokens, and abstract transport traits.

pub mod codec;
pub mod error;
pub mod identity;
pub mod keys;
pub mod messages;
pub mod remote_runtime;
pub mod token;
pub mod transport;

// Re-export commonly used items at crate root.
pub use codec::{cbor_decode, decode_envelope, frame_encode, FrameDecoder};
pub use error::{WshError, WshResult};
pub use identity::{fingerprint, short_fingerprint, FingerprintIndex};
pub use messages::{AuthMethod, ChannelKind, MsgType, PROTOCOL_VERSION};
pub use remote_runtime::{
    PeerType, ReachabilityDescriptor, RemoteIdentity, RemotePeerDescriptor, SessionIntent,
    SessionTarget, ShellBackend,
};
pub use token::{create_token, generate_secret, verify_token};
