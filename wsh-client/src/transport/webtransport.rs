//! Browser-compatible WebTransport implementation for wsh.
//!
//! Uses the `wtransport` crate to establish a real WebTransport-over-HTTP/3
//! session so browser clients and Rust clients speak the same transport.

use std::future::Future;
use std::pin::Pin;

use rustls::crypto::ring;
use wtransport::endpoint::endpoint_side;
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};

use wsh_core::codec::FrameDecoder;
use wsh_core::error::{WshError, WshResult};
use wsh_core::transport::{ByteStream, IdentifiedStream, TransportSession};

/// A WebTransport bidirectional stream wrapped as a `ByteStream`.
struct WebTransportStream {
    send: SendStream,
    recv: RecvStream,
}

impl ByteStream for WebTransportStream {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = WshResult<usize>> + Send + 'a>> {
        Box::pin(async move {
            match self.recv.read(buf).await {
                Ok(Some(n)) => Ok(n),
                Ok(None) => Ok(0),
                Err(e) => Err(WshError::Transport(format!(
                    "WebTransport read error: {e}"
                ))),
            }
        })
    }

    fn write_all<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send + 'a>> {
        Box::pin(async move {
            self.send
                .write_all(data)
                .await
                .map_err(|e| WshError::Transport(format!("WebTransport write error: {e}")))
        })
    }

    fn close(&mut self) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send + '_>> {
        Box::pin(async move {
            self.send
                .finish()
                .await
                .map_err(|e| WshError::Transport(format!("WebTransport close error: {e}")))?;
            Ok(())
        })
    }
}

/// WebTransport session backed by a browser-compatible HTTP/3 session.
pub struct WebTransportSession {
    _endpoint: Endpoint<endpoint_side::Client>,
    connection: Connection,
    control_send: SendStream,
    control_recv: RecvStream,
    decoder: FrameDecoder,
    next_stream_id: u32,
    connected: bool,
}

impl WebTransportSession {
    /// Connect to a wsh server over WebTransport.
    pub async fn connect(url: &str) -> WshResult<Self> {
        install_rustls_crypto_provider();
        let normalized_url = normalize_webtransport_url(url)?;
        let client_config = ClientConfig::builder()
            .with_bind_default()
            .with_no_cert_validation()
            .build();
        let endpoint = Endpoint::client(client_config)
            .map_err(|e| WshError::Transport(format!("endpoint error: {e}")))?;
        let connection = endpoint
            .connect(&normalized_url)
            .await
            .map_err(|e| WshError::Transport(format!("WebTransport connect error: {e}")))?;

        tracing::info!("WebTransport connected to {}", normalized_url);

        let (control_send, control_recv) = connection
            .open_bi()
            .await
            .map_err(|e| WshError::Transport(format!("control stream open failed: {e}")))?
            .await
            .map_err(|e| {
                WshError::Transport(format!("control stream initialization failed: {e}"))
            })?;

        Ok(Self {
            _endpoint: endpoint,
            connection,
            control_send,
            control_recv,
            decoder: FrameDecoder::new(),
            next_stream_id: 1,
            connected: true,
        })
    }
}

fn install_rustls_crypto_provider() {
    let _ = ring::default_provider().install_default();
}

impl TransportSession for WebTransportSession {
    async fn send_control(&mut self, data: &[u8]) -> WshResult<()> {
        let frame = frame_helpers::encode_raw(data);
        self.control_send
            .write_all(&frame)
            .await
            .map_err(|e| WshError::Transport(format!("control send error: {e}")))?;
        Ok(())
    }

    async fn recv_control(&mut self) -> WshResult<Vec<u8>> {
        loop {
            if let Some(frame) = self.decoder.feed_raw(&[]).into_iter().next() {
                return Ok(frame);
            }

            let mut buf = vec![0u8; 8192];
            match self.control_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if let Some(frame) = self.decoder.feed_raw(&buf[..n]).into_iter().next() {
                        return Ok(frame);
                    }
                }
                Ok(None) => {
                    self.connected = false;
                    return Err(WshError::Transport("control stream closed".into()));
                }
                Err(e) => {
                    self.connected = false;
                    return Err(WshError::Transport(format!("control recv error: {e}")));
                }
            }
        }
    }

    async fn open_stream(&mut self) -> WshResult<IdentifiedStream> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| WshError::Transport(format!("failed to open stream: {e}")))?
            .await
            .map_err(|e| {
                WshError::Transport(format!("failed to initialize stream: {e}"))
            })?;

        let id = self.next_stream_id;
        self.next_stream_id += 1;

        Ok(IdentifiedStream {
            id,
            stream: Box::new(WebTransportStream { send, recv }),
        })
    }

    async fn accept_stream(&mut self) -> WshResult<IdentifiedStream> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|e| WshError::Transport(format!("failed to accept stream: {e}")))?;

        let id = self.next_stream_id;
        self.next_stream_id += 1;

        Ok(IdentifiedStream {
            id,
            stream: Box::new(WebTransportStream { send, recv }),
        })
    }

    async fn close(&mut self) -> WshResult<()> {
        self.connected = false;
        self.connection.close(0u32.into(), b"client disconnect");
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Normalize a WebTransport URL so the Rust client accepts both `https://`
/// and the legacy `wt://` alias.
pub fn normalize_webtransport_url(url: &str) -> WshResult<String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        Ok(url.to_string())
    } else if lower.starts_with("wt://") {
        Ok(format!("https://{}", &url[5..]))
    } else {
        Err(WshError::Transport(format!(
            "invalid WebTransport URL: {url}"
        )))
    }
}

/// Helper to encode raw bytes into a length-prefixed frame (used for control messages).
mod frame_helpers {
    pub fn encode_raw(data: &[u8]) -> Vec<u8> {
        let len = data.len() as u32;
        let mut frame = Vec::with_capacity(4 + data.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_webtransport_url;

    #[test]
    fn normalize_webtransport_url_preserves_path_and_query() {
        assert_eq!(
            normalize_webtransport_url("wt://example.com:4433/wsh?transport=web").unwrap(),
            "https://example.com:4433/wsh?transport=web"
        );
    }

    #[test]
    fn normalize_webtransport_url_rejects_non_webtransport_schemes() {
        for url in ["ws://example.com", "wss://example.com", "http://example.com"] {
            assert!(normalize_webtransport_url(url).is_err(), "{url} should be rejected");
        }
    }
}
