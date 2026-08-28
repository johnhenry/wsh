//! WebSocket listener using tokio-tungstenite.
//!
//! Provides a fallback transport for clients that cannot use WebTransport/QUIC.
//! Each WebSocket connection is wrapped in an adapter that provides multiplexed
//! stream semantics over the single WS connection.

use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use wsh_core::{WshError, WshResult};

pub(crate) trait WsIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> WsIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type BoxedWsIo = Box<dyn WsIo>;

/// A handle to an accepted WebSocket connection.
pub struct WebSocketConnection {
    /// The WebSocket stream (split into sink + stream in usage).
    pub ws_stream: WebSocketStream<BoxedWsIo>,
    /// Remote address.
    pub remote_addr: SocketAddr,
}

/// Start the WebSocket listener.
///
/// Returns a receiver that yields accepted connections.
pub async fn start_listener(
    bind_addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
) -> WshResult<mpsc::Receiver<WebSocketConnection>> {
    let tcp_listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| WshError::Transport(format!("WSS bind failed: {e}")))?;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    info!(addr = %bind_addr, "WebSocket TLS listener started");

    let (tx, rx) = mpsc::channel::<WebSocketConnection>(64);

    tokio::spawn(async move {
        loop {
            match tcp_listener.accept().await {
                Ok((stream, addr)) => {
                    let tx = tx.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    tokio::spawn(async move {
                        match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let boxed_stream: BoxedWsIo = Box::new(tls_stream);
                                match tokio_tungstenite::accept_async(boxed_stream).await {
                                    Ok(ws_stream) => {
                                        debug!(remote = %addr, "WebSocket connection accepted");
                                        let conn = WebSocketConnection {
                                            ws_stream,
                                            remote_addr: addr,
                                        };
                                        if tx.send(conn).await.is_err() {
                                            warn!("WebSocket connection channel closed");
                                        }
                                    }
                                    Err(e) => {
                                        warn!(remote = %addr, error = %e, "WebSocket handshake failed");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(remote = %addr, error = %e, "TLS handshake failed");
                            }
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "TCP accept failed");
                }
            }
        }
    });

    Ok(rx)
}

/// Send a raw binary WebSocket message. The bytes are handed to us
/// already-framed by the QMux layer (a QMux record) — this is a plain
/// pass-through, unlike the old `FRAME_CONTROL`-wrapping `ws_send_control`
/// it replaces.
pub async fn ws_send_raw(ws: &mut WebSocketStream<BoxedWsIo>, data: &[u8]) -> WshResult<()> {
    ws.send(Message::Binary(data.to_vec().into()))
        .await
        .map_err(|e| WshError::Transport(format!("WS send failed: {e}")))
}

/// Maximum frame size for WebSocket messages (1 MiB, consistent with QUIC limit).
const MAX_WS_FRAME_SIZE: usize = 1_048_576;

/// Receive the next raw binary WebSocket message, to be fed to
/// `QMuxConnection::receive_bytes`.
///
/// Returns `None` if the connection is closed. Text messages are ignored.
/// Rejects frames larger than 1 MiB (consistent with QUIC transport limit).
pub async fn ws_recv_raw(ws: &mut WebSocketStream<BoxedWsIo>) -> WshResult<Option<Vec<u8>>> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(data))) => {
                if data.len() > MAX_WS_FRAME_SIZE {
                    return Err(WshError::InvalidMessage(format!(
                        "WS frame too large: {} bytes (max {})",
                        data.len(),
                        MAX_WS_FRAME_SIZE
                    )));
                }
                return Ok(Some(data.to_vec()));
            }
            Some(Ok(Message::Close(_))) => return Ok(None),
            Some(Ok(Message::Ping(payload))) => {
                // Respond to pings automatically
                let _ = ws.send(Message::Pong(payload)).await;
            }
            Some(Ok(_)) => {
                // Ignore text and other message types
                continue;
            }
            Some(Err(e)) => {
                return Err(WshError::Transport(format!("WS recv failed: {e}")));
            }
            None => return Ok(None),
        }
    }
}
