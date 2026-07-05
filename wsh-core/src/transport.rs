//! Abstract transport session trait for wsh.
//!
//! Both WebTransport and WebSocket implementations must satisfy this trait.

use crate::error::WshResult;
use std::future::Future;
use std::pin::Pin;

/// A bidirectional byte stream (e.g., a QUIC stream or virtual WS stream).
pub trait ByteStream: Send + Sync {
    /// Read up to `buf.len()` bytes. Returns number of bytes read, 0 = EOF.
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = WshResult<usize>> + Send + 'a>>;

    /// Write all bytes.
    fn write_all<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send + 'a>>;

    /// Close this stream.
    fn close(&mut self) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send + '_>>;
}

/// A stream with an associated ID.
pub struct IdentifiedStream {
    pub id: u32,
    pub stream: Box<dyn ByteStream>,
}

/// Abstract transport session for the wsh protocol.
///
/// Implementations handle framing, multiplexing, and stream lifecycle.
#[allow(async_fn_in_trait)]
pub trait TransportSession: Send + Sync {
    /// Send a CBOR-encoded control message.
    async fn send_control(&mut self, data: &[u8]) -> WshResult<()>;

    /// Receive the next control message (CBOR bytes).
    async fn recv_control(&mut self) -> WshResult<Vec<u8>>;

    /// Open a new bidirectional data stream.
    async fn open_stream(&mut self) -> WshResult<IdentifiedStream>;

    /// Accept the next server/peer-initiated stream.
    async fn accept_stream(&mut self) -> WshResult<IdentifiedStream>;

    /// Close the transport session.
    async fn close(&mut self) -> WshResult<()>;

    /// Whether the transport is still connected.
    fn is_connected(&self) -> bool;
}
