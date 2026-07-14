//! WebSocket transport implementation for wsh.
//!
//! Multiplexes multiple virtual streams over a single WebSocket connection.
//!
//! Frame format: `[1-byte type][4-byte stream_id][payload]`
//!
//! Frame types:
//! - `0x01` — control message
//! - `0x02` — data (routed to stream by stream_id)
//! - `0x03` — open_stream (request to open a new virtual stream)
//! - `0x04` — close_stream (close a virtual stream)

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use wsh_core::error::{WshError, WshResult};
use wsh_core::transport::{ByteStream, IdentifiedStream, TransportSession};

/// WebSocket frame type markers.
const FRAME_CONTROL: u8 = 0x01;
const FRAME_DATA: u8 = 0x02;
const FRAME_OPEN_STREAM: u8 = 0x03;
const FRAME_CLOSE_STREAM: u8 = 0x04;

/// Build a multiplexed frame: `[type][stream_id BE][payload]`.
fn build_frame(frame_type: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + 4 + payload.len());
    frame.push(frame_type);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Parse a multiplexed frame header: `(type, stream_id, payload_offset)`.
fn parse_frame_header(data: &[u8]) -> WshResult<(u8, u32, usize)> {
    if data.len() < 5 {
        return Err(WshError::Transport("frame too short".into()));
    }
    let frame_type = data[0];
    let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    Ok((frame_type, stream_id, 5))
}

fn decode_control_payload(data: &[u8]) -> WshResult<&[u8]> {
    if data.len() < 4 {
        return Err(WshError::Transport(format!(
            "control payload too short: {} bytes",
            data.len()
        )));
    }

    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() != 4 + len {
        return Err(WshError::Transport(format!(
            "control payload length mismatch: declared {len}, got {} bytes",
            data.len().saturating_sub(4)
        )));
    }

    Ok(&data[4..])
}

/// A virtual byte stream backed by mpsc channels.
struct VirtualStream {
    stream_id: u32,
    rx: mpsc::Receiver<Vec<u8>>,
    tx_ws: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    read_buf: Vec<u8>,
    read_offset: usize,
    closed: bool,
}

impl ByteStream for VirtualStream {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = WshResult<usize>> + Send + 'a>> {
        Box::pin(async move {
            // Drain leftover bytes from previous read
            if self.read_offset < self.read_buf.len() {
                let available = self.read_buf.len() - self.read_offset;
                let n = available.min(buf.len());
                buf[..n].copy_from_slice(&self.read_buf[self.read_offset..self.read_offset + n]);
                self.read_offset += n;
                if self.read_offset >= self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_offset = 0;
                }
                return Ok(n);
            }

            // Wait for next chunk
            match self.rx.recv().await {
                Some(data) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    if n < data.len() {
                        self.read_buf = data;
                        self.read_offset = n;
                    }
                    Ok(n)
                }
                None => Ok(0), // Channel closed = EOF
            }
        })
    }

    fn write_all<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send + 'a>> {
        Box::pin(async move {
            let frame = build_frame(FRAME_DATA, self.stream_id, data);
            let mut sink = self.tx_ws.lock().await;
            sink.send(Message::Binary(frame))
                .await
                .map_err(|e| WshError::Transport(format!("WS write error: {e}")))?;
            Ok(())
        })
    }

    fn close(&mut self) -> Pin<Box<dyn Future<Output = WshResult<()>> + Send + '_>> {
        Box::pin(async move {
            if !self.closed {
                self.closed = true;
                let frame = build_frame(FRAME_CLOSE_STREAM, self.stream_id, &[]);
                let mut sink = self.tx_ws.lock().await;
                let _ = sink.send(Message::Binary(frame)).await;
            }
            Ok(())
        })
    }
}

/// WebSocket transport session with virtual stream multiplexing.
pub struct WebSocketSession {
    ws_sink: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    control_rx: mpsc::Receiver<Vec<u8>>,
    incoming_streams_rx: mpsc::Receiver<(u32, mpsc::Receiver<Vec<u8>>)>,
    stream_registry: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    next_stream_id: Arc<Mutex<u32>>,
    dispatch_handle: tokio::task::JoinHandle<()>,
    connected: Arc<Mutex<bool>>,
}

impl WebSocketSession {
    /// Connect to a wsh server over WebSocket.
    pub async fn connect(url: &str) -> WshResult<Self> {
        let (ws_stream, _response) = connect_async(url)
            .await
            .map_err(|e| WshError::Transport(format!("WebSocket connect error: {e}")))?;

        tracing::info!("WebSocket connected to {}", url);

        let (ws_sink, ws_stream_read) = ws_stream.split();
        let ws_sink = Arc::new(Mutex::new(ws_sink));

        let (control_tx, control_rx) = mpsc::channel::<Vec<u8>>(256);
        let (incoming_tx, incoming_streams_rx) =
            mpsc::channel::<(u32, mpsc::Receiver<Vec<u8>>)>(64);

        let stream_registry: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let connected = Arc::new(Mutex::new(true));

        // Spawn the dispatch loop
        let dispatch_handle = {
            let registry = stream_registry.clone();
            let connected = connected.clone();
            let ws_sink_clone = ws_sink.clone();

            tokio::spawn(async move {
                Self::dispatch_loop(
                    ws_stream_read,
                    control_tx,
                    incoming_tx,
                    registry,
                    connected,
                    ws_sink_clone,
                )
                .await;
            })
        };

        Ok(Self {
            ws_sink,
            control_rx,
            incoming_streams_rx,
            stream_registry,
            next_stream_id: Arc::new(Mutex::new(1)), // Client uses odd IDs
            dispatch_handle,
            connected,
        })
    }

    /// Internal dispatch loop that routes incoming WebSocket frames.
    async fn dispatch_loop(
        mut ws_read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        control_tx: mpsc::Sender<Vec<u8>>,
        incoming_tx: mpsc::Sender<(u32, mpsc::Receiver<Vec<u8>>)>,
        stream_registry: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
        connected: Arc<Mutex<bool>>,
        ws_sink: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
    ) {
        while let Some(msg) = ws_read.next().await {
            let data = match msg {
                Ok(Message::Binary(data)) => data,
                Ok(Message::Close(_)) => {
                    tracing::debug!("WebSocket close frame received");
                    break;
                }
                Ok(Message::Ping(payload)) => {
                    // Respond to pings
                    let mut sink = ws_sink.lock().await;
                    let _ = sink.send(Message::Pong(payload)).await;
                    continue;
                }
                Ok(_) => continue, // Ignore text frames, pongs, etc.
                Err(e) => {
                    tracing::error!("WebSocket read error: {}", e);
                    break;
                }
            };

            let (frame_type, stream_id, offset) = match parse_frame_header(&data) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("invalid frame: {}", e);
                    continue;
                }
            };

            let payload = &data[offset..];

            match frame_type {
                FRAME_CONTROL => {
                    let control_payload = match decode_control_payload(payload) {
                        Ok(payload) => payload,
                        Err(e) => {
                            tracing::warn!("invalid control payload: {}", e);
                            continue;
                        }
                    };

                    if control_tx.send(control_payload.to_vec()).await.is_err() {
                        tracing::debug!("control channel closed");
                        break;
                    }
                }
                FRAME_DATA => {
                    let registry = stream_registry.lock().await;
                    if let Some(tx) = registry.get(&stream_id) {
                        let _ = tx.send(payload.to_vec()).await;
                    } else {
                        tracing::warn!("data for unknown stream {}", stream_id);
                    }
                }
                FRAME_OPEN_STREAM => {
                    // Remote side wants to open a stream
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
                    {
                        let mut registry = stream_registry.lock().await;
                        registry.insert(stream_id, tx);
                    }
                    let _ = incoming_tx.send((stream_id, rx)).await;
                }
                FRAME_CLOSE_STREAM => {
                    let mut registry = stream_registry.lock().await;
                    registry.remove(&stream_id);
                }
                _ => {
                    tracing::warn!("unknown frame type: 0x{:02x}", frame_type);
                }
            }
        }

        let mut c = connected.lock().await;
        *c = false;
        tracing::debug!("WebSocket dispatch loop ended");
    }
}

impl TransportSession for WebSocketSession {
    async fn send_control(&mut self, data: &[u8]) -> WshResult<()> {
        let frame = build_frame(FRAME_CONTROL, 0, data);
        let mut sink = self.ws_sink.lock().await;
        sink.send(Message::Binary(frame))
            .await
            .map_err(|e| WshError::Transport(format!("WS control send error: {e}")))?;
        Ok(())
    }

    async fn recv_control(&mut self) -> WshResult<Vec<u8>> {
        self.control_rx
            .recv()
            .await
            .ok_or_else(|| WshError::Transport("control channel closed".into()))
    }

    async fn open_stream(&mut self) -> WshResult<IdentifiedStream> {
        let stream_id = {
            let mut id = self.next_stream_id.lock().await;
            let current = *id;
            *id += 2; // Client uses odd IDs, increment by 2
            current
        };

        // Register the stream's receive channel
        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
        {
            let mut registry = self.stream_registry.lock().await;
            registry.insert(stream_id, tx);
        }

        // Notify the remote side
        let frame = build_frame(FRAME_OPEN_STREAM, stream_id, &[]);
        {
            let mut sink = self.ws_sink.lock().await;
            sink.send(Message::Binary(frame))
                .await
                .map_err(|e| WshError::Transport(format!("WS open_stream error: {e}")))?;
        }

        Ok(IdentifiedStream {
            id: stream_id,
            stream: Box::new(VirtualStream {
                stream_id,
                rx,
                tx_ws: self.ws_sink.clone(),
                read_buf: Vec::new(),
                read_offset: 0,
                closed: false,
            }),
        })
    }

    async fn accept_stream(&mut self) -> WshResult<IdentifiedStream> {
        let (stream_id, rx) = self
            .incoming_streams_rx
            .recv()
            .await
            .ok_or_else(|| WshError::Transport("incoming stream channel closed".into()))?;

        Ok(IdentifiedStream {
            id: stream_id,
            stream: Box::new(VirtualStream {
                stream_id,
                rx,
                tx_ws: self.ws_sink.clone(),
                read_buf: Vec::new(),
                read_offset: 0,
                closed: false,
            }),
        })
    }

    async fn close(&mut self) -> WshResult<()> {
        {
            let mut c = self.connected.lock().await;
            *c = false;
        }
        let mut sink = self.ws_sink.lock().await;
        let _ = sink.send(Message::Close(None)).await;
        self.dispatch_handle.abort();
        Ok(())
    }

    fn is_connected(&self) -> bool {
        // Non-blocking check — use try_lock to avoid blocking
        self.connected.try_lock().map(|c| *c).unwrap_or(false)
    }
}

impl Drop for WebSocketSession {
    fn drop(&mut self) {
        self.dispatch_handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::decode_control_payload;

    #[test]
    fn decode_control_payload_unwraps_inner_frame() {
        let payload = decode_control_payload(&[0, 0, 0, 2, 0xa0, 0xf5]).unwrap();
        assert_eq!(payload, &[0xa0, 0xf5]);
    }
}
