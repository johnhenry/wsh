//! wsh-client: Rust client library for the Web Shell protocol.
//!
//! Provides a native async client that connects over WebTransport (QUIC) or
//! WebSocket, authenticates via Ed25519 challenge-response, and manages
//! multiplexed terminal/exec/file sessions.
//!
//! # Quick Start
//!
//! ```no_run
//! use wsh_client::{WshClient, ConnectConfig, SessionOpts};
//!
//! # async fn example() -> wsh_core::WshResult<()> {
//! let client = WshClient::connect("wss://example.com:8022/wsh", ConnectConfig {
//!     username: "alice".into(),
//!     key_name: Some("default".into()),
//!     ..Default::default()
//! }).await?;
//!
//! let session = client.open_session(SessionOpts::default()).await?;
//! session.write(b"echo hello\n").await?;
//!
//! let mut buf = vec![0u8; 4096];
//! let n = session.read(&mut buf).await?;
//! println!("{}", String::from_utf8_lossy(&buf[..n]));
//!
//! client.disconnect().await?;
//! # Ok(())
//! # }
//! ```

pub mod auth;
pub mod client;
pub mod file_transfer;
pub mod keystore;
pub mod known_hosts;
pub mod mcp;
pub mod session;
pub mod transport;
pub mod virtual_session;

// Re-export primary public types.
pub use client::{ConnectConfig, RemoteSessionInfo, WshClient};
pub use keystore::{KeyInfo, KeyStore};
pub use known_hosts::{HostStatus, KnownHosts};
pub use session::{SessionInfo, SessionOpts, SessionState, WshSession};
pub use transport::{AnyTransport, TransportKind, WebSocketSession, WebTransportSession};
pub use virtual_session::VirtualSessionBackend;

// Re-export wsh-core error types for convenience.
pub use wsh_core::{WshError, WshResult};
