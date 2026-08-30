//! WebSocket listener using tokio-tungstenite.
//!
//! Provides a fallback transport for clients that cannot use WebTransport/QUIC.
//! Each WebSocket connection is wrapped in an adapter that provides multiplexed
//! stream semantics over the single WS connection.

use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
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

/// A guest's outbound WISP tunnel connection (`/wisp/<fingerprint>`), #38
/// Phase 2. One of these is created per v86 guest that dials in with its
/// (patched) `wisp_network.js`.
pub struct WispGuestConnection {
    pub ws_stream: WebSocketStream<BoxedWsIo>,
    pub remote_addr: SocketAddr,
    pub fingerprint: String,
}

/// An external `wsh connect <fingerprint>` client requesting a reverse
/// bridge into a WISP-registered guest (`/wisp-connect/<fingerprint>`), #38
/// Phase 2. `local_port` is the guest-local TCP port to target (parsed from
/// `?port=N`; defaults to `wisp::DEFAULT_REVERSE_PORT` if absent/invalid).
pub struct WispConnectRequest {
    pub ws_stream: WebSocketStream<BoxedWsIo>,
    pub remote_addr: SocketAddr,
    pub fingerprint: String,
    pub local_port: u16,
}

/// The three kinds of WebSocket connection this listener can route to,
/// decided from the HTTP request path during the WS handshake.
enum Route {
    Wsh,
    WispGuest { fingerprint: String },
    WispConnect { fingerprint: String, local_port: u16 },
}

/// Parse the request path into a [`Route`]. Anything not matching the WISP
/// prefixes falls back to the existing wsh Envelope/QMux protocol path,
/// preserving today's behavior (which ignores the path entirely) for
/// clients that don't send one of the new prefixes.
fn parse_route(path: &str) -> Route {
    if let Some(fp) = path.strip_prefix("/wisp/") {
        let fp = fp.split(['?', '/']).next().unwrap_or("").to_string();
        if !fp.is_empty() {
            return Route::WispGuest { fingerprint: fp };
        }
    } else if let Some(rest) = path.strip_prefix("/wisp-connect/") {
        let (fp_and_more, query) = match rest.split_once('?') {
            Some((a, b)) => (a, Some(b)),
            None => (rest, None),
        };
        let fp = fp_and_more.split('/').next().unwrap_or("").to_string();
        if !fp.is_empty() {
            let local_port = query
                .and_then(|q| {
                    q.split('&').find_map(|kv| {
                        let (k, v) = kv.split_once('=')?;
                        if k == "port" {
                            v.parse::<u16>().ok()
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(crate::relay::wisp::DEFAULT_REVERSE_PORT);
            return Route::WispConnect {
                fingerprint: fp,
                local_port,
            };
        }
    }
    Route::Wsh
}

/// Receivers for all three routed connection kinds, produced by
/// [`start_listener`].
pub struct ListenerChannels {
    pub ws_rx: mpsc::Receiver<WebSocketConnection>,
    pub wisp_guest_rx: mpsc::Receiver<WispGuestConnection>,
    pub wisp_connect_rx: mpsc::Receiver<WispConnectRequest>,
}

/// Start the WebSocket listener.
///
/// Returns receivers that yield accepted connections, routed by request
/// path into the wsh Envelope protocol, a guest's WISP tunnel, or an
/// external WISP reverse-connect bridge request (#38 Phase 2).
pub async fn start_listener(
    bind_addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
) -> WshResult<ListenerChannels> {
    let tcp_listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| WshError::Transport(format!("WSS bind failed: {e}")))?;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    info!(addr = %bind_addr, "WebSocket TLS listener started");

    let (tx, ws_rx) = mpsc::channel::<WebSocketConnection>(64);
    let (wisp_guest_tx, wisp_guest_rx) = mpsc::channel::<WispGuestConnection>(64);
    let (wisp_connect_tx, wisp_connect_rx) = mpsc::channel::<WispConnectRequest>(64);

    tokio::spawn(async move {
        loop {
            match tcp_listener.accept().await {
                Ok((stream, addr)) => {
                    let tx = tx.clone();
                    let wisp_guest_tx = wisp_guest_tx.clone();
                    let wisp_connect_tx = wisp_connect_tx.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    tokio::spawn(async move {
                        match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let boxed_stream: BoxedWsIo = Box::new(tls_stream);
                                let path_slot: Arc<StdMutex<String>> =
                                    Arc::new(StdMutex::new(String::new()));
                                let cb_slot = path_slot.clone();
                                let callback =
                                    move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                                        if let Ok(mut slot) = cb_slot.lock() {
                                            *slot = req.uri().path().to_string();
                                        }
                                        Ok(resp)
                                    };
                                match tokio_tungstenite::accept_hdr_async(boxed_stream, callback)
                                    .await
                                {
                                    Ok(ws_stream) => {
                                        let path = path_slot
                                            .lock()
                                            .map(|s| s.clone())
                                            .unwrap_or_default();
                                        match parse_route(&path) {
                                            Route::WispGuest { fingerprint } => {
                                                debug!(remote = %addr, %fingerprint, "WISP guest tunnel accepted");
                                                let conn = WispGuestConnection {
                                                    ws_stream,
                                                    remote_addr: addr,
                                                    fingerprint,
                                                };
                                                if wisp_guest_tx.send(conn).await.is_err() {
                                                    warn!("WISP guest connection channel closed");
                                                }
                                            }
                                            Route::WispConnect {
                                                fingerprint,
                                                local_port,
                                            } => {
                                                debug!(remote = %addr, %fingerprint, local_port, "WISP reverse-connect request accepted");
                                                let conn = WispConnectRequest {
                                                    ws_stream,
                                                    remote_addr: addr,
                                                    fingerprint,
                                                    local_port,
                                                };
                                                if wisp_connect_tx.send(conn).await.is_err() {
                                                    warn!("WISP connect channel closed");
                                                }
                                            }
                                            Route::Wsh => {
                                                debug!(remote = %addr, "WebSocket connection accepted");
                                                let conn = WebSocketConnection {
                                                    ws_stream,
                                                    remote_addr: addr,
                                                };
                                                if tx.send(conn).await.is_err() {
                                                    warn!("WebSocket connection channel closed");
                                                }
                                            }
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

    Ok(ListenerChannels {
        ws_rx,
        wisp_guest_rx,
        wisp_connect_rx,
    })
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

#[cfg(test)]
mod route_tests {
    use super::*;

    #[test]
    fn plain_path_routes_to_wsh() {
        assert!(matches!(parse_route("/"), Route::Wsh));
        assert!(matches!(parse_route(""), Route::Wsh));
        assert!(matches!(parse_route("/anything"), Route::Wsh));
    }

    #[test]
    fn wisp_guest_path_extracts_fingerprint() {
        match parse_route("/wisp/abc123def") {
            Route::WispGuest { fingerprint } => assert_eq!(fingerprint, "abc123def"),
            _ => panic!("expected WispGuest route"),
        }
    }

    #[test]
    fn wisp_guest_path_without_fingerprint_falls_back_to_wsh() {
        assert!(matches!(parse_route("/wisp/"), Route::Wsh));
    }

    #[test]
    fn wisp_connect_path_defaults_port_when_absent() {
        match parse_route("/wisp-connect/fp-guest-1") {
            Route::WispConnect {
                fingerprint,
                local_port,
            } => {
                assert_eq!(fingerprint, "fp-guest-1");
                assert_eq!(local_port, crate::relay::wisp::DEFAULT_REVERSE_PORT);
            }
            _ => panic!("expected WispConnect route"),
        }
    }

    #[test]
    fn wisp_connect_path_parses_explicit_port_query_param() {
        match parse_route("/wisp-connect/fp-guest-1?port=2222") {
            Route::WispConnect {
                fingerprint,
                local_port,
            } => {
                assert_eq!(fingerprint, "fp-guest-1");
                assert_eq!(local_port, 2222);
            }
            _ => panic!("expected WispConnect route"),
        }
    }

    #[test]
    fn wisp_connect_path_ignores_malformed_port_and_uses_default() {
        match parse_route("/wisp-connect/fp-guest-1?port=not-a-number") {
            Route::WispConnect { local_port, .. } => {
                assert_eq!(local_port, crate::relay::wisp::DEFAULT_REVERSE_PORT);
            }
            _ => panic!("expected WispConnect route"),
        }
    }
}
