//! WebSocket transport implementation for wsh.
//!
//! Speaks QMux (draft-ietf-quic-qmux-02) over the single WebSocket
//! connection, mirroring the server's `handle_websocket`
//! (`crates/wsh-server/src/server.rs`) and its `transport/websocket.rs`
//! (`ws_send_raw`/`ws_recv_raw`): every WS binary message is a raw QMux
//! record, fed straight into a `wsh_core::qmux_connection::QMuxConnection`.
//! The client's first (and only) locally-initiated bidirectional QMux
//! stream is always ID 0 (`first_bidi_stream_id(Client) == 0`), matching
//! the server's `CONTROL_STREAM_ID` constant, and carries every control
//! *and* session-data envelope -- length-prefix-framed via
//! `wsh_core::codec::{frame_encode, FrameDecoder}` -- because this server
//! always declares `SessionDataMode::Virtual` (see that constant's doc
//! comment in `server.rs`: no per-session second QMux stream exists yet).
//! `open_stream` opens a client-initiated data stream, which only a typed
//! `rpc` channel (wsh #85, `Open { kind: "rpc" }`) uses; `accept_stream`
//! returns an error rather than pretending to support something nothing
//! on the wire implements.
//!
//! This replaces an earlier, unrelated hand-rolled `[type][stream_id]`
//! framing that predated the server's QMux migration and was never
//! actually compatible with it (issue #38's Phase 1 loopback proof is
//! what first exercised a real `wss://` connection all the way through
//! TLS to the protocol layer and caught the mismatch).

use std::sync::Arc;

use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, Connector, MaybeTlsStream, WebSocketStream};

use wsh_core::codec::FrameDecoder;
use wsh_core::error::{WshError, WshResult};
use wsh_core::qmux::ErrorCode;
use wsh_core::qmux_connection::{QMuxConnection, QMuxConnectionConfig, QMuxEvent};
use wsh_core::transport::{ByteStream, IdentifiedStream, TransportSession};

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

/// What a client-opened data stream is told by the connection's event loop.
enum StreamItem {
    Data(Vec<u8>),
    /// The peer finished its side (FIN).
    End,
    /// The peer reset the stream, or the connection died under it.
    Reset,
}

/// Where the event loop delivers the bytes of each client-opened data stream, by QMux stream id.
type StreamSinks = Arc<std::sync::Mutex<HashMap<u64, mpsc::UnboundedSender<StreamItem>>>>;

/// A client-opened QMux data stream as a `ByteStream` (wsh #127: the typed `rpc` channel rides one).
/// Received bytes are bounded by QMux's own flow-control windows, so the queue behind `rx` cannot
/// grow past what the connection granted.
struct QMuxDataStream {
    qmux: Arc<QMuxConnection>,
    id: u64,
    rx: mpsc::UnboundedReceiver<StreamItem>,
    leftover: Vec<u8>,
    ended: bool,
    sinks: StreamSinks,
}

impl ByteStream for QMuxDataStream {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = WshResult<usize>> + Send + 'a>> {
        Box::pin(async move {
            if buf.is_empty() {
                return Ok(0);
            }
            loop {
                if !self.leftover.is_empty() {
                    let n = self.leftover.len().min(buf.len());
                    buf[..n].copy_from_slice(&self.leftover[..n]);
                    self.leftover.drain(..n);
                    return Ok(n);
                }
                if self.ended {
                    return Ok(0);
                }
                match self.rx.recv().await {
                    Some(StreamItem::Data(d)) => self.leftover = d,
                    Some(StreamItem::End) | None => {
                        self.ended = true;
                        return Ok(0);
                    }
                    Some(StreamItem::Reset) => {
                        self.ended = true;
                        return Err(WshError::Transport(format!(
                            "QMux stream {} was reset",
                            self.id
                        )));
                    }
                }
            }
        })
    }

    fn write_all<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send + 'a>> {
        Box::pin(async move {
            if data.is_empty() {
                return Ok(());
            }
            self.qmux
                .write_stream(self.id, data)
                .await
                .map_err(WshError::from)
        })
    }

    fn close(&mut self) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send + '_>> {
        Box::pin(async move { self.qmux.close_stream(self.id).map_err(WshError::from) })
    }
}

impl Drop for QMuxDataStream {
    fn drop(&mut self) {
        if let Ok(mut sinks) = self.sinks.lock() {
            sinks.remove(&self.id);
        }
    }
}

/// Environment variable that, when set to `1` or `true`, disables TLS
/// certificate verification for the `wss://` connection this process
/// makes.
///
/// **This exists solely for the Phase 1 loopback proof harness
/// (`tools/guest-image/init.sh`, driven by
/// `tools/guest-image/boot-test.mjs` — see issue #38) and MUST NOT be set
/// for any real remote connection.** `wsh-server`'s dev cert is
/// self-signed and there is currently no hash-pinning trust path for
/// `wss://` in this codebase (WebTransport has `--cert-hash`, see
/// `transport/webtransport.rs`; trusting the dev cert for `wss://` is
/// `SSL_CERT_FILE`). Skipping verification is, for that harness, the only way to
/// complete a loopback `wss://127.0.0.1` handshake against that cert
/// without a CA-trusted certificate, which the minimal guest image used
/// for the Phase 1 proof doesn't have anyway (no `/etc/ssl/certs`).
///
/// Nothing in this codebase sets this variable except the loopback test
/// harness above — it is off by default, and turning it on for a real
/// connection would allow a MITM to impersonate any server.
const INSECURE_LOOPBACK_TLS_ENV: &str = "WSH_INSECURE_LOOPBACK_TLS";

/// A pipe-relay URL (`wss://relay/r/<id>`) with its rendezvous id shortened for a log line: the id is a
/// capability (whoever holds it can dial the other half while it waits), #156. Same rule as the CLI's.
fn redact_rendezvous(url: &str) -> String {
    match url.split_once("/r/") {
        Some((head, tail)) => {
            let (id, rest) = tail
                .find(['?', '#', '/'])
                .map_or((tail, ""), |i| tail.split_at(i));
            if id.chars().count() > 4 {
                let shown: String = id.chars().take(4).collect();
                format!("{head}/r/{shown}...{rest}")
            } else {
                url.to_string()
            }
        }
        None => url.to_string(),
    }
}

fn insecure_loopback_tls_requested() -> bool {
    matches!(
        std::env::var(INSECURE_LOOPBACK_TLS_ENV).as_deref(),
        Ok("1") | Ok("true")
    )
}

/// A `rustls` certificate verifier that accepts any certificate chain,
/// for any server name, unconditionally.
///
/// Only ever constructed when [`INSECURE_LOOPBACK_TLS_ENV`] is set — see
/// that constant's doc comment for the full scoping rationale. This is
/// the `wss://` analogue of the WebTransport opt-out
/// (`CertPolicy::InsecureSkipVerification`, `transport/webtransport.rs`).
#[derive(Debug)]
struct NoOpServerCertVerifier {
    supported_schemes: Vec<rustls::SignatureScheme>,
}

impl rustls::client::danger::ServerCertVerifier for NoOpServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_schemes.clone()
    }
}

/// Build a `tokio-tungstenite` connector that skips TLS certificate
/// verification. Only called when [`insecure_loopback_tls_requested`]
/// returns true.
fn build_insecure_loopback_connector() -> Connector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(NoOpServerCertVerifier {
        supported_schemes: provider
            .signature_verification_algorithms
            .supported_schemes(),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions are always valid")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Connector::Rustls(Arc::new(config))
}

/// Maximum frame size for WebSocket messages (1 MiB, matching the
/// server's `MAX_WS_FRAME_SIZE`).
const MAX_WS_FRAME_SIZE: usize = 1_048_576;

type WsSink = futures_util::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

pub struct WebSocketSession {
    qmux: Arc<QMuxConnection>,
    control_stream_id: u64,
    control_rx: mpsc::Receiver<Vec<u8>>,
    io_handle: tokio::task::JoinHandle<()>,
    event_handle: tokio::task::JoinHandle<()>,
    connected: Arc<Mutex<bool>>,
    streams: StreamSinks,
}

/// Open and announce a client-initiated QMux data stream (see `TransportSession::open_stream` below).
async fn open_qmux_stream(
    qmux: Arc<QMuxConnection>,
    streams: StreamSinks,
) -> WshResult<IdentifiedStream> {
    let id = qmux.open_stream().await.map_err(WshError::from)?;
    let (tx, rx) = mpsc::unbounded_channel();
    streams
        .lock()
        .map_err(|_| WshError::Transport("stream table poisoned".into()))?
        .insert(id, tx);
    let stream = QMuxDataStream {
        qmux: qmux.clone(),
        id,
        rx,
        leftover: Vec::new(),
        ended: false,
        sinks: streams,
    };
    // Dropping `stream` on failure removes the sink again.
    qmux.announce_stream(id).map_err(WshError::from)?;
    Ok(IdentifiedStream {
        id: id as u32,
        stream: Box::new(stream),
    })
}

impl WebSocketSession {
    /// A handle that opens data streams without the transport lock.
    pub fn stream_opener(&self) -> super::StreamOpener {
        let qmux = self.qmux.clone();
        let streams = self.streams.clone();
        super::StreamOpener::new(move || open_qmux_stream(qmux.clone(), streams.clone()))
    }

    /// Connect to a wsh server over WebSocket.
    pub async fn connect(url: &str) -> WshResult<Self> {
        super::install_crypto_provider();
        let (ws_stream, _response) = if insecure_loopback_tls_requested() {
            // See INSECURE_LOOPBACK_TLS_ENV's doc comment: only reachable
            // when the loopback test harness explicitly opts in.
            tracing::warn!(
                "{} is set — skipping wss:// certificate verification \
                 (loopback test harness only, see issue #38)",
                INSECURE_LOOPBACK_TLS_ENV
            );
            let connector = build_insecure_loopback_connector();
            tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
                .await
                .map_err(|e| WshError::Transport(format!("WebSocket connect error: {e}")))?
        } else {
            connect_async(url)
                .await
                .map_err(|e| WshError::Transport(format!("WebSocket connect error: {e}")))?
        };

        tracing::info!("WebSocket connected to {}", redact_rendezvous(url));

        let (ws_sink, ws_read) = ws_stream.split();
        let ws_sink = Arc::new(Mutex::new(ws_sink));
        let alive = Arc::new(Mutex::new(true));

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<QMuxEvent>();
        let event_tx_for_io = event_tx.clone();

        let qmux = Arc::new(QMuxConnection::new(
            QMuxConnectionConfig {
                is_client: true,
                ..Default::default()
            },
            move |bytes: &[u8]| {
                let _ = outbound_tx.send(bytes.to_vec());
            },
            event_tx,
        ));
        qmux.send_handshake()?;
        let control_stream_id = qmux.open_stream().await?;
        let ws_sink_for_io = ws_sink.clone();
        let qmux_for_io = qmux.clone();
        let alive_for_io = alive.clone();
        let io_handle = tokio::spawn(async move {
            Self::io_loop(
                ws_read,
                ws_sink_for_io,
                outbound_rx,
                qmux_for_io,
                alive_for_io,
            )
            .await;
            // The socket is gone (the peer closed it, or it failed): say so to whoever reads the control
            // stream. The QMux connection (and so the event channel) is held by this session as well, so
            // without this nothing would ever tell the dispatch loop that the host went away, and a
            // `wsh -N -L` would wait forever (#156).
            let _ = event_tx_for_io.send(QMuxEvent::ConnectionClosed {
                error_code: wsh_core::qmux::ErrorCode::NoError,
                reason: "websocket closed".to_string(),
            });
        });

        let (control_tx, control_rx) = mpsc::channel::<Vec<u8>>(256);
        let alive_for_events = alive.clone();
        let streams: StreamSinks = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let streams_for_events = streams.clone();
        let event_handle = tokio::spawn(async move {
            Self::event_loop(
                event_rx,
                control_stream_id,
                control_tx,
                alive_for_events,
                streams_for_events,
            )
            .await;
        });

        Ok(Self {
            qmux,
            control_stream_id,
            control_rx,
            io_handle,
            event_handle,
            connected: alive,
            streams,
        })
    }

    async fn io_loop(
        mut ws_read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        ws_sink: Arc<Mutex<WsSink>>,
        mut outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        qmux: Arc<QMuxConnection>,
        alive: Arc<Mutex<bool>>,
    ) {
        loop {
            tokio::select! {
                outbound = outbound_rx.recv() => {
                    match outbound {
                        Some(bytes) => {
                            let mut sink = ws_sink.lock().await;
                            if sink.send(Message::Binary(bytes.into())).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                msg = ws_read.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            if data.len() > MAX_WS_FRAME_SIZE {
                                tracing::warn!("WS frame too large: {} bytes", data.len());
                                break;
                            }
                            qmux.receive_bytes(&data);
                        }
                        Some(Ok(Message::Close(_))) => {
                            tracing::debug!("WebSocket close frame received");
                            break;
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            let mut sink = ws_sink.lock().await;
                            let _ = sink.send(Message::Pong(payload)).await;
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => {
                            tracing::error!("WebSocket read error: {}", e);
                            break;
                        }
                        None => break,
                    }
                }
            }
        }
        *alive.lock().await = false;
    }

    async fn event_loop(
        mut event_rx: mpsc::UnboundedReceiver<QMuxEvent>,
        control_stream_id: u64,
        control_tx: mpsc::Sender<Vec<u8>>,
        alive: Arc<Mutex<bool>>,
        streams: StreamSinks,
    ) {
        let mut control_decoder = FrameDecoder::new();
        // Tell every open data stream the connection is gone (their readers see a reset).
        let finish_streams = |streams: &StreamSinks| {
            if let Ok(mut sinks) = streams.lock() {
                for (_, sink) in sinks.drain() {
                    let _ = sink.send(StreamItem::Reset);
                }
            }
        };
        let deliver = |streams: &StreamSinks, stream_id: u64, item: StreamItem, last: bool| {
            let sink = {
                let Ok(mut sinks) = streams.lock() else {
                    return false;
                };
                if last {
                    sinks.remove(&stream_id)
                } else {
                    sinks.get(&stream_id).cloned()
                }
            };
            match sink {
                Some(sink) => {
                    let _ = sink.send(item);
                    true
                }
                None => false,
            }
        };
        while let Some(event) = event_rx.recv().await {
            match event {
                QMuxEvent::StreamData { stream_id, data } if stream_id == control_stream_id => {
                    for frame in control_decoder.feed_raw(&data) {
                        if control_tx.send(frame).await.is_err() {
                            finish_streams(&streams);
                            return;
                        }
                    }
                }
                QMuxEvent::StreamData { stream_id, data } => {
                    if !deliver(&streams, stream_id, StreamItem::Data(data), false) {
                        tracing::warn!(stream_id, "ignoring StreamData on an unknown QMux stream");
                    }
                }
                QMuxEvent::StreamEnd { stream_id } if stream_id != control_stream_id => {
                    deliver(&streams, stream_id, StreamItem::End, true);
                }
                QMuxEvent::StreamReset { stream_id, .. }
                | QMuxEvent::StreamDestroyed { stream_id }
                    if stream_id != control_stream_id =>
                {
                    deliver(&streams, stream_id, StreamItem::Reset, true);
                }
                QMuxEvent::StreamEnd { stream_id } | QMuxEvent::StreamReset { stream_id, .. }
                    if stream_id == control_stream_id =>
                {
                    tracing::debug!("QMux control stream ended");
                    break;
                }
                QMuxEvent::StreamDestroyed { stream_id } if stream_id == control_stream_id => {
                    break;
                }
                QMuxEvent::ConnectionClosed { reason, .. } => {
                    tracing::debug!(reason, "QMux connection closed");
                    break;
                }
                QMuxEvent::Error { message } => {
                    tracing::error!("QMux error: {}", message);
                    break;
                }
                _ => {}
            }
        }
        finish_streams(&streams);
        *alive.lock().await = false;
    }

    /// Server-initiated streams are not used by any message this client speaks yet: fail loudly
    /// instead of pretending to support them.
    fn no_real_data_stream_error() -> WshResult<IdentifiedStream> {
        Err(WshError::Transport(
            "WebSocket transport does not support real data streams for this server".into(),
        ))
    }
}

impl TransportSession for WebSocketSession {
    async fn send_control(&mut self, data: &[u8]) -> WshResult<()> {
        self.qmux
            .write_stream(self.control_stream_id, data)
            .await
            .map_err(WshError::from)
    }

    async fn recv_control(&mut self) -> WshResult<Vec<u8>> {
        self.control_rx
            .recv()
            .await
            .ok_or_else(|| WshError::Transport("control channel closed".into()))
    }

    /// Open a client-initiated QMux data stream and announce it, so the host sees it before the
    /// first payload byte (the typed `rpc` channel needs this: wsh #127). The server this client
    /// was written against only ever asks for it when it answered `OpenOk` with `data_mode: stream`.
    async fn open_stream(&mut self) -> WshResult<IdentifiedStream> {
        open_qmux_stream(self.qmux.clone(), self.streams.clone()).await
    }

    async fn accept_stream(&mut self) -> WshResult<IdentifiedStream> {
        Self::no_real_data_stream_error()
    }

    async fn close(&mut self) -> WshResult<()> {
        *self.connected.lock().await = false;
        let _ = self.qmux.close(ErrorCode::NoError, "client disconnect");
        self.io_handle.abort();
        self.event_handle.abort();
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.try_lock().map(|c| *c).unwrap_or(false)
    }
}

impl Drop for WebSocketSession {
    fn drop(&mut self) {
        self.io_handle.abort();
        self.event_handle.abort();
    }
}
