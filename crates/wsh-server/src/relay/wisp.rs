//! WISP reverse-connect relay bridge (#38 Phase 2).
//!
//! Wires the demultiplexing design proven in `wisp_bridge_poc.rs` (PR #118)
//! into the live relay. Two roles, mirrored by two new WebSocket endpoints
//! added in `transport::websocket` and dispatched from `server.rs`:
//!
//!  - **Guest session** (`/wisp/<fingerprint>`): a v86 guest's outbound WISP
//!    tunnel, patched (per the #38 design writeup) to also accept the new
//!    `REVERSE_OPEN` opcode and turn it into `fake_tcp_connect()`. One
//!    [`WispGuestSession`] is created per connected guest and registered in
//!    [`WispRegistry`] under its fingerprint.
//!  - **Reverse-connect bridge** (`/wisp-connect/<fingerprint>`): an external
//!    `wsh connect <fingerprint>` client. The relay looks the fingerprint up
//!    in [`WispRegistry`], asks the guest's session to open a reverse stream
//!    (`REVERSE_OPEN`), and from then on proxies raw bytes bidirectionally:
//!    external WS binary frames become WISP `DATA` frames sent down the
//!    guest's session, and WISP `DATA`/`CLOSE` frames arriving on that
//!    stream become WS frames back to the external client. This is a byte
//!    pipe, not wsh's own Envelope/QMux relay protocol — the guest's own
//!    `wsh-server` still terminates its own independent TLS/QMux session
//!    with whatever client ends up on the other end of the pipe, exactly as
//!    it does today for the fully-local loopback proof (#38 Phase 1).
//!
//! Outbound (guest-initiated, stream_id below [`REVERSE_STREAM_ID_BASE`])
//! WISP traffic — i.e. the guest dialing out to the real internet — is
//! intentionally NOT proxied by this module. That's stock WISP relay
//! behavior orthogonal to #38 Phase 2's acceptance criterion (inbound
//! reverse-connect to the guest's own `wsh-server`); frames on outbound
//! stream_ids are logged and dropped rather than guessed at, matching the
//! same fail-closed posture as the PoC.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, warn};

/// Base WISP opcodes (unchanged from upstream WISP v1 / v86's client).
pub const WISP_CONNECT: u8 = 0x01;
pub const WISP_DATA: u8 = 0x02;
pub const WISP_CONTINUE: u8 = 0x03;
pub const WISP_CLOSE: u8 = 0x04;

/// New opcode (#38 Phase 2 design): relay → guest only. Payload is the
/// guest-local TCP port to synthesize an inbound connection to
/// (`local_port: u16 LE`), via a patched `wisp_network.js`'s
/// `fake_tcp_connect(local_port, this)`.
pub const WISP_REVERSE_OPEN: u8 = 0x10;

/// Stream IDs below this are guest-initiated (outbound). IDs at/above this
/// are relay-initiated (reverse/inbound). Splitting the u32 space in half
/// guarantees no collision with zero coordination handshake.
pub const REVERSE_STREAM_ID_BASE: u32 = 0x8000_0000;

/// Default guest-local port a reverse connection targets when the external
/// `wsh connect` request (or `/wisp-connect/<fp>` query string) doesn't
/// specify one — matches `WSH_CONTROL_PORT` in `web/clawser-wisp-transport.mjs`.
pub const DEFAULT_REVERSE_PORT: u16 = 9083;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    GuestOutbound,
    RelayReverse,
}

pub fn classify_stream(stream_id: u32) -> StreamDirection {
    if stream_id >= REVERSE_STREAM_ID_BASE {
        StreamDirection::RelayReverse
    } else {
        StreamDirection::GuestOutbound
    }
}

/// A decoded WISP frame.
#[derive(Debug, Clone)]
pub struct WispFrame {
    pub frame_type: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

pub fn decode_frame(bytes: &[u8]) -> Option<WispFrame> {
    if bytes.len() < 5 {
        return None;
    }
    let frame_type = bytes[0];
    let stream_id = u32::from_le_bytes(bytes[1..5].try_into().ok()?);
    Some(WispFrame {
        frame_type,
        stream_id,
        payload: bytes[5..].to_vec(),
    })
}

pub fn encode_frame(frame_type: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(frame_type);
    buf.extend_from_slice(&stream_id.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub fn encode_reverse_open(stream_id: u32, local_port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(7);
    buf.push(WISP_REVERSE_OPEN);
    buf.extend_from_slice(&stream_id.to_le_bytes());
    buf.extend_from_slice(&local_port.to_le_bytes());
    buf
}

pub fn encode_close(stream_id: u32, reason: u8) -> Vec<u8> {
    encode_frame(WISP_CLOSE, stream_id, &[reason])
}

/// Allocates stream IDs for relay-initiated reverse connections, wrapping
/// within the upper half of the u32 space.
pub struct ReverseStreamAllocator {
    next: u32,
}

impl Default for ReverseStreamAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReverseStreamAllocator {
    pub fn new() -> Self {
        Self {
            next: REVERSE_STREAM_ID_BASE,
        }
    }

    pub fn allocate(&mut self) -> u32 {
        let id = self.next;
        self.next = if self.next == u32::MAX {
            REVERSE_STREAM_ID_BASE
        } else {
            self.next + 1
        };
        id
    }
}

/// Where an incoming DATA/CLOSE frame from the guest's WebSocket should be
/// routed. `Unknown` frames (unregistered stream_id) must be dropped, never
/// guessed at — mirrors v86's own client-side fail-closed behavior.
#[derive(Debug, PartialEq, Eq)]
pub enum RouteTarget {
    ReverseBridge(u32),
    Unknown,
}

pub fn route_frame(
    frame: &WispFrame,
    known_reverse: &std::collections::HashSet<u32>,
) -> RouteTarget {
    match classify_stream(frame.stream_id) {
        StreamDirection::RelayReverse if known_reverse.contains(&frame.stream_id) => {
            RouteTarget::ReverseBridge(frame.stream_id)
        }
        _ => RouteTarget::Unknown,
    }
}

/// An event delivered to an external `wsh connect` client bridged onto a
/// reverse stream.
#[derive(Debug)]
pub enum ReverseEvent {
    Data(Vec<u8>),
    Closed,
}

/// One connected guest's live outbound `/wisp/<fingerprint>` WISP session.
///
/// Owns raw-frame delivery to the guest (`to_guest`) and the bookkeeping for
/// reverse (relay-initiated) streams opened against it.
pub struct WispGuestSession {
    fingerprint: String,
    to_guest: mpsc::Sender<Vec<u8>>,
    alloc: Mutex<ReverseStreamAllocator>,
    reverse_streams: Arc<RwLock<HashMap<u32, mpsc::Sender<ReverseEvent>>>>,
}

impl WispGuestSession {
    pub fn new(fingerprint: String, to_guest: mpsc::Sender<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            fingerprint,
            to_guest,
            alloc: Mutex::new(ReverseStreamAllocator::new()),
            reverse_streams: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Open a reverse stream to `local_port` inside the guest. Sends
    /// `REVERSE_OPEN` down the guest's tunnel and returns the allocated
    /// stream_id plus a receiver for `DATA`/`CLOSE` events the guest sends
    /// back on it.
    pub async fn open_reverse(&self, local_port: u16) -> (u32, mpsc::Receiver<ReverseEvent>) {
        let stream_id = {
            let mut alloc = self.alloc.lock().await;
            alloc.allocate()
        };
        let (tx, rx) = mpsc::channel(64);
        self.reverse_streams.write().await.insert(stream_id, tx);
        let _ = self
            .to_guest
            .send(encode_reverse_open(stream_id, local_port))
            .await;
        (stream_id, rx)
    }

    /// Forward bytes from the bridged external client to the guest on
    /// `stream_id` (a `DATA` frame).
    pub async fn send_reverse_data(&self, stream_id: u32, data: &[u8]) -> bool {
        self.to_guest
            .send(encode_frame(WISP_DATA, stream_id, data))
            .await
            .is_ok()
    }

    /// Close a reverse stream from the relay side (external client hung up).
    pub async fn close_reverse(&self, stream_id: u32, reason: u8) {
        let _ = self.to_guest.send(encode_close(stream_id, reason)).await;
        self.reverse_streams.write().await.remove(&stream_id);
    }

    /// Handle a frame arriving FROM the guest's WebSocket.
    pub async fn handle_incoming(&self, frame: WispFrame) {
        let known_reverse: std::collections::HashSet<u32> =
            self.reverse_streams.read().await.keys().copied().collect();
        match route_frame(&frame, &known_reverse) {
            RouteTarget::ReverseBridge(stream_id) => match frame.frame_type {
                WISP_DATA => {
                    let streams = self.reverse_streams.read().await;
                    if let Some(tx) = streams.get(&stream_id) {
                        let _ = tx.send(ReverseEvent::Data(frame.payload)).await;
                    }
                }
                WISP_CLOSE => {
                    let mut streams = self.reverse_streams.write().await;
                    if let Some(tx) = streams.remove(&stream_id) {
                        let _ = tx.send(ReverseEvent::Closed).await;
                    }
                }
                WISP_CONTINUE => {
                    // No relay-side buffering to report against — the relay
                    // proxies bytes 1:1 between the external client's own
                    // flow-controlled WebSocket and the guest's WISP stream,
                    // so CONTINUE from the guest is a no-op here.
                }
                other => {
                    debug!(
                        frame_type = other,
                        stream_id, "unhandled WISP frame type on reverse stream"
                    );
                }
            },
            RouteTarget::Unknown => {
                if frame.stream_id >= REVERSE_STREAM_ID_BASE {
                    warn!(
                        stream_id = frame.stream_id,
                        "frame for unregistered reverse stream, dropping"
                    );
                } else {
                    debug!(
                        stream_id = frame.stream_id,
                        frame_type = frame.frame_type,
                        "ignoring guest-outbound WISP frame (egress proxying not implemented by #38 Phase 2)"
                    );
                }
            }
        }
    }

    /// Close every open reverse stream (called when the guest's WebSocket
    /// itself disconnects).
    pub async fn close_all(&self) {
        let mut streams = self.reverse_streams.write().await;
        for (_, tx) in streams.drain() {
            let _ = tx.send(ReverseEvent::Closed).await;
        }
    }
}

/// Registry of connected guests' WISP sessions, keyed by fingerprint.
pub struct WispRegistry {
    sessions: Arc<RwLock<HashMap<String, Arc<WispGuestSession>>>>,
}

impl Default for WispRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WispRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, session: Arc<WispGuestSession>) {
        self.sessions
            .write()
            .await
            .insert(session.fingerprint().to_string(), session);
    }

    pub async fn unregister(&self, fingerprint: &str) {
        if let Some(session) = self.sessions.write().await.remove(fingerprint) {
            session.close_all().await;
        }
    }

    pub async fn get(&self, fingerprint: &str) -> Option<Arc<WispGuestSession>> {
        self.sessions.read().await.get(fingerprint).cloned()
    }

    pub async fn count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_and_outbound_ids_never_collide() {
        let mut alloc = ReverseStreamAllocator::new();
        let r1 = alloc.allocate();
        let r2 = alloc.allocate();
        assert_ne!(r1, r2);
        assert_eq!(classify_stream(r1), StreamDirection::RelayReverse);
        assert_eq!(classify_stream(1), StreamDirection::GuestOutbound);
    }

    #[test]
    fn frame_roundtrips_through_encode_decode() {
        let raw = encode_frame(WISP_DATA, 0x8000_0001, b"hello");
        let frame = decode_frame(&raw).unwrap();
        assert_eq!(frame.frame_type, WISP_DATA);
        assert_eq!(frame.stream_id, 0x8000_0001);
        assert_eq!(frame.payload, b"hello");
    }

    #[test]
    fn reverse_open_frame_encodes_target_port_after_stream_id() {
        let frame = encode_reverse_open(REVERSE_STREAM_ID_BASE, 9999);
        assert_eq!(frame[0], WISP_REVERSE_OPEN);
        let stream_id = u32::from_le_bytes(frame[1..5].try_into().unwrap());
        assert_eq!(stream_id, REVERSE_STREAM_ID_BASE);
        let port = u16::from_le_bytes(frame[5..7].try_into().unwrap());
        assert_eq!(port, 9999);
    }

    #[tokio::test]
    async fn open_reverse_sends_reverse_open_and_registers_stream() {
        let (to_guest_tx, mut to_guest_rx) = mpsc::channel(4);
        let session = WispGuestSession::new("abc123".to_string(), to_guest_tx);

        let (stream_id, mut rx) = session.open_reverse(9083).await;
        assert!(stream_id >= REVERSE_STREAM_ID_BASE);

        let sent = to_guest_rx.recv().await.unwrap();
        let frame = decode_frame(&sent).unwrap();
        assert_eq!(frame.frame_type, WISP_REVERSE_OPEN);
        assert_eq!(frame.stream_id, stream_id);

        // Simulate the guest replying with DATA on that stream.
        session
            .handle_incoming(WispFrame {
                frame_type: WISP_DATA,
                stream_id,
                payload: b"exec output".to_vec(),
            })
            .await;

        match rx.recv().await.unwrap() {
            ReverseEvent::Data(data) => assert_eq!(data, b"exec output"),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unregistered_reverse_stream_is_dropped_not_guessed() {
        let (to_guest_tx, _rx) = mpsc::channel(4);
        let session = WispGuestSession::new("abc123".to_string(), to_guest_tx);

        // No open_reverse call — this stream_id was never allocated.
        session
            .handle_incoming(WispFrame {
                frame_type: WISP_DATA,
                stream_id: REVERSE_STREAM_ID_BASE + 5,
                payload: b"unexpected".to_vec(),
            })
            .await;
        // Nothing to assert beyond "did not panic" — there's no channel to
        // receive on since the stream was never registered.
    }

    #[tokio::test]
    async fn guest_outbound_frames_are_ignored_not_routed_to_reverse_bridges() {
        let (to_guest_tx, _rx) = mpsc::channel(4);
        let session = WispGuestSession::new("abc123".to_string(), to_guest_tx);
        let (stream_id, mut reverse_rx) = session.open_reverse(9083).await;

        // A frame on a guest-outbound stream_id must never be delivered to
        // a reverse bridge, even if a reverse stream happens to be open.
        session
            .handle_incoming(WispFrame {
                frame_type: WISP_DATA,
                stream_id: 42, // guest-outbound range
                payload: b"should not appear".to_vec(),
            })
            .await;

        // Confirm the reverse stream's channel is unaffected.
        session
            .handle_incoming(WispFrame {
                frame_type: WISP_DATA,
                stream_id,
                payload: b"real reply".to_vec(),
            })
            .await;
        match reverse_rx.recv().await.unwrap() {
            ReverseEvent::Data(data) => assert_eq!(data, b"real reply"),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn close_from_guest_delivers_closed_event_and_deregisters() {
        let (to_guest_tx, _rx) = mpsc::channel(4);
        let session = WispGuestSession::new("abc123".to_string(), to_guest_tx);
        let (stream_id, mut reverse_rx) = session.open_reverse(9083).await;

        session
            .handle_incoming(WispFrame {
                frame_type: WISP_CLOSE,
                stream_id,
                payload: vec![0],
            })
            .await;

        match reverse_rx.recv().await.unwrap() {
            ReverseEvent::Closed => {}
            other => panic!("expected Closed, got {other:?}"),
        }
        assert!(session.reverse_streams.read().await.is_empty());
    }

    #[tokio::test]
    async fn registry_round_trips_by_fingerprint() {
        let registry = WispRegistry::new();
        let (to_guest_tx, _rx) = mpsc::channel(4);
        let session = WispGuestSession::new("fp-guest-1".to_string(), to_guest_tx);
        registry.register(session.clone()).await;

        assert_eq!(registry.count().await, 1);
        let found = registry.get("fp-guest-1").await.unwrap();
        assert_eq!(found.fingerprint(), "fp-guest-1");
        assert!(registry.get("nope").await.is_none());

        registry.unregister("fp-guest-1").await;
        assert_eq!(registry.count().await, 0);
    }
}
