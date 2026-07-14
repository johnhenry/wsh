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

const FRAME_CONTROL: u8 = 0x01;
const HEADER_SIZE: usize = 5;

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

fn build_frame(frame_type: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_SIZE + payload.len());
    frame.push(frame_type);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn parse_frame(data: &[u8]) -> WshResult<(u8, u32, &[u8])> {
    if data.len() < HEADER_SIZE {
        return Err(WshError::InvalidMessage(format!(
            "WS frame too short: {} bytes",
            data.len()
        )));
    }

    let frame_type = data[0];
    let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    Ok((frame_type, stream_id, &data[HEADER_SIZE..]))
}

fn decode_control_payload(data: &[u8]) -> WshResult<&[u8]> {
    if data.len() < 4 {
        return Err(WshError::InvalidMessage(format!(
            "WS control payload too short: {} bytes",
            data.len()
        )));
    }

    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() != 4 + len {
        return Err(WshError::InvalidMessage(format!(
            "WS control payload length mismatch: declared {len}, got {} bytes",
            data.len().saturating_sub(4)
        )));
    }

    Ok(&data[4..])
}

/// Helper: send a control frame over a WebSocket.
pub async fn ws_send_control(
    ws: &mut WebSocketStream<BoxedWsIo>,
    data: &[u8],
) -> WshResult<()> {
    let frame = build_frame(FRAME_CONTROL, 0, data);
    ws.send(Message::Binary(frame.into()))
        .await
        .map_err(|e| WshError::Transport(format!("WS send failed: {e}")))
}

/// Maximum frame size for WebSocket messages (1 MiB, consistent with QUIC limit).
const MAX_WS_FRAME_SIZE: usize = 1_048_576;

/// Helper: receive the next control frame from a WebSocket.
///
/// Returns `None` if the connection is closed. Text messages are ignored.
/// Rejects frames larger than 1 MiB (consistent with QUIC transport limit).
pub async fn ws_recv_control(
    ws: &mut WebSocketStream<BoxedWsIo>,
) -> WshResult<Option<Vec<u8>>> {
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
                let (frame_type, _stream_id, payload) = parse_frame(&data)?;
                if frame_type != FRAME_CONTROL {
                    return Err(WshError::InvalidMessage(format!(
                        "expected WS control frame, got type 0x{frame_type:02x}"
                    )));
                }
                let payload = decode_control_payload(payload)?;
                return Ok(Some(payload.to_vec()));
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

#[cfg(test)]
mod tests {
    use super::{build_frame, decode_control_payload, parse_frame, FRAME_CONTROL};

    #[test]
    fn build_and_parse_control_frame_round_trip() {
        let frame = build_frame(FRAME_CONTROL, 0, b"hello");
        let (frame_type, stream_id, payload) = parse_frame(&frame).unwrap();

        assert_eq!(frame_type, FRAME_CONTROL);
        assert_eq!(stream_id, 0);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn parse_frame_rejects_short_payload() {
        assert!(parse_frame(&[FRAME_CONTROL, 0, 0, 0]).is_err());
    }

    #[test]
    fn decode_control_payload_unwraps_inner_frame() {
        let payload = decode_control_payload(&[0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o']).unwrap();
        assert_eq!(payload, b"hello");
    }
}
