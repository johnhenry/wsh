//! QMux connection: stream state machine + flow-control accounting on
//! top of the wire codec in `qmux`.
//!
//! Rust port of `qmux-connection.mjs` in the `@johnhenry/wsh` npm
//! package (the canonical spec-source implementation) — see that
//! file's doc comment for the full rationale.
//!
//! This module has no transport dependency of its own: it takes a
//! synchronous `send` callback for outbound record bytes (expected to
//! be non-blocking — e.g. pushing onto an `mpsc` channel that a task
//! pumps to the real WebSocket) and an `events` channel for everything
//! the JS version delivers via `on*` callbacks. No internal state is
//! ever held across an `.await`, so the connection can be driven from
//! both async call sites (`write_stream`/`open_stream`, which may block
//! on flow control) and sync call sites (`receive_bytes`, `reset_stream`,
//! `close`) without deadlocking each other.
//!
//! Because the underlying transport (a WebSocket) already guarantees
//! in-order, lossless delivery, there is no packet loss, reordering, or
//! retransmission to handle — flow control here exists purely to bound
//! memory (backpressure), not to manage congestion. See `qmux`'s file
//! doc comment for why that's QMux's whole design point.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Notify;

use crate::qmux::{
    decode_frames, encode_connection_close, encode_data_blocked, encode_datagram,
    encode_max_data, encode_max_stream_data, encode_max_streams, encode_record,
    encode_reset_stream, encode_reset_stream_at, encode_stop_sending, encode_stream,
    encode_stream_data_blocked, encode_streams_blocked, encode_transport_parameters,
    first_bidi_stream_id, is_client_initiated, next_bidi_stream_id, ErrorCode, Frame, QMuxError,
    RecordDecoder, StreamInitiator, TransportParameters,
};

pub const DEFAULT_INITIAL_MAX_DATA: u64 = 8 * 1024 * 1024;
pub const DEFAULT_INITIAL_MAX_STREAM_DATA: u64 = 1024 * 1024;
pub const DEFAULT_INITIAL_MAX_STREAMS_BIDI: u64 = 100;

// ── Per-stream send/receive state ───────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    /// Nothing sent yet.
    Ready,
    /// Sending data.
    Send,
    /// We sent RESET_STREAM/RESET_STREAM_AT.
    ResetSent,
    /// We sent FIN (final size known to peer).
    DataSent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    /// Receiving data, final size unknown.
    Recv,
    /// FIN or RESET_STREAM_AT seen; final size known.
    SizeKnown,
    /// All bytes up to final/reliable size delivered to the application.
    DataRecvd,
    /// Peer reset with no reliable prefix left to deliver.
    ResetRecvd,
}

struct StreamState {
    send_state: SendState,
    send_offset: u64,
    /// Bytes we're currently allowed to send beyond `send_offset`. Can
    /// be <= 0 while blocked (never below 0 by more than a single
    /// in-flight chunk, since we only ever reserve what's available).
    send_window: i64,

    recv_state: RecvState,
    /// Bytes delivered to the application (StreamData events).
    recv_offset: u64,
    /// Bytes received from the wire (buffered + delivered).
    recv_buffered_up_to: u64,
    /// The fixed target window size we aim to always keep available.
    recv_window: u64,
    /// The window value last announced via MAX_STREAM_DATA.
    recv_window_granted: u64,
    reliable_size: Option<u64>,
    reset_error_code: Option<ErrorCode>,
}

impl StreamState {
    fn new(send_window: u64, recv_window: u64) -> Self {
        Self {
            send_state: SendState::Ready,
            send_offset: 0,
            send_window: send_window as i64,
            recv_state: RecvState::Recv,
            recv_offset: 0,
            recv_buffered_up_to: 0,
            recv_window,
            recv_window_granted: recv_window,
            reliable_size: None,
            reset_error_code: None,
        }
    }

    /// Both directions have reached a terminal state (sent/reset, and received/reset).
    fn is_fully_closed(&self) -> bool {
        let send_done = matches!(self.send_state, SendState::DataSent | SendState::ResetSent);
        let recv_done = matches!(self.recv_state, RecvState::DataRecvd | RecvState::ResetRecvd);
        send_done && recv_done
    }
}

/// If a reliable prefix (RESET_STREAM_AT) has now fully arrived, finish
/// the reset and return the error code to report; a no-op otherwise.
fn complete_reset_if_ready(stream: &mut StreamState) -> Option<ErrorCode> {
    let reliable_size = stream.reliable_size?;
    if stream.recv_buffered_up_to < reliable_size {
        return None;
    }
    if matches!(stream.recv_state, RecvState::ResetRecvd) {
        return None;
    }
    stream.recv_state = RecvState::ResetRecvd;
    stream.reset_error_code
}

enum PeerStreamLookup {
    Existing,
    Created,
    /// An ID this endpoint should itself have allocated -- never legitimately "peer-initiated".
    NotOurs,
}

/// Events surfaced to whoever owns a `QMuxConnection` — the async
/// equivalent of the `on*` callbacks on the JS `QMuxConnection`/`QMuxStream`.
#[derive(Debug, Clone)]
pub enum QMuxEvent {
    StreamOpen { stream_id: u64 },
    StreamData { stream_id: u64, data: Vec<u8> },
    StreamEnd { stream_id: u64 },
    StreamReset { stream_id: u64, error_code: ErrorCode },
    /// The whole connection died (transport closed/errored) and this
    /// stream was torn down as a result -- not a protocol-level reset.
    StreamDestroyed { stream_id: u64 },
    Datagram { data: Vec<u8> },
    ConnectionClosed { error_code: ErrorCode, reason: String },
    Error { message: String },
}

struct Inner {
    is_client: bool,
    decoder: RecordDecoder,
    streams: HashMap<u64, StreamState>,
    next_local_stream_id: u64,
    closed: bool,

    // Connection-level flow control (send side: bytes *we* may still send)
    conn_send_offset: u64,
    conn_send_window: i64,
    /// Last conn_send_offset a DATA_BLOCKED was announced for, to avoid duplicates.
    last_data_blocked_at: i64,

    // Connection-level flow control (receive side: bytes we allow the peer to send)
    conn_recv_buffered_up_to: u64,
    conn_recv_window: u64,
    conn_recv_window_granted: u64,

    max_streams_bidi: u64,
    streams_opened: u64,
    peer_max_streams_bidi: Option<u64>,

    // MAX_STREAMS we grant the peer: starts at max_streams_bidi (sent in
    // the handshake) and is topped up as peer-initiated streams close,
    // so the peer doesn't permanently lose capacity over a long-lived
    // connection.
    peer_streams_opened: u64,
    peer_streams_granted: u64,

    initial_max_stream_data: u64,
}

pub struct QMuxConnectionConfig {
    pub is_client: bool,
    pub initial_max_data: u64,
    pub initial_max_stream_data: u64,
    pub initial_max_streams_bidi: u64,
}

impl Default for QMuxConnectionConfig {
    fn default() -> Self {
        Self {
            is_client: true,
            initial_max_data: DEFAULT_INITIAL_MAX_DATA,
            initial_max_stream_data: DEFAULT_INITIAL_MAX_STREAM_DATA,
            initial_max_streams_bidi: DEFAULT_INITIAL_MAX_STREAMS_BIDI,
        }
    }
}

pub struct QMuxConnection {
    inner: Mutex<Inner>,
    send: Box<dyn Fn(&[u8]) + Send + Sync>,
    events: UnboundedSender<QMuxEvent>,
    send_notify: Notify,
    stream_open_notify: Notify,
}

impl QMuxConnection {
    pub fn new(
        config: QMuxConnectionConfig,
        send: impl Fn(&[u8]) + Send + Sync + 'static,
        events: UnboundedSender<QMuxEvent>,
    ) -> Self {
        let next_local_stream_id = first_bidi_stream_id(if config.is_client {
            StreamInitiator::Client
        } else {
            StreamInitiator::Server
        });
        let inner = Inner {
            is_client: config.is_client,
            decoder: RecordDecoder::new(),
            streams: HashMap::new(),
            next_local_stream_id,
            closed: false,
            conn_send_offset: 0,
            conn_send_window: config.initial_max_data as i64,
            last_data_blocked_at: -1,
            conn_recv_buffered_up_to: 0,
            conn_recv_window: config.initial_max_data,
            conn_recv_window_granted: config.initial_max_data,
            max_streams_bidi: config.initial_max_streams_bidi,
            streams_opened: 0,
            peer_max_streams_bidi: None,
            peer_streams_opened: 0,
            peer_streams_granted: config.initial_max_streams_bidi,
            initial_max_stream_data: config.initial_max_stream_data,
        };
        Self {
            inner: Mutex::new(inner),
            send: Box::new(send),
            events,
            send_notify: Notify::new(),
            stream_open_notify: Notify::new(),
        }
    }

    // ── Handshake / stream lifecycle ────────────────────────────────

    /// Send the QX_TRANSPORT_PARAMETERS handshake frame — must be the
    /// first frame sent (QMux draft §4.1).
    pub fn send_handshake(&self) -> Result<(), QMuxError> {
        let (granted, stream_data, streams_bidi) = {
            let inner = self.inner.lock().unwrap();
            (
                inner.conn_recv_window_granted,
                inner.initial_max_stream_data,
                inner.max_streams_bidi,
            )
        };
        let params = TransportParameters {
            initial_max_data: Some(granted),
            initial_max_stream_data_bidi_local: Some(stream_data),
            initial_max_stream_data_bidi_remote: Some(stream_data),
            initial_max_streams_bidi: Some(streams_bidi),
            ..Default::default()
        };
        let bytes = encode_transport_parameters(&params)?;
        (self.send)(&encode_record(&bytes)?);
        Ok(())
    }

    /// Open a new locally-initiated bidirectional stream, blocking on
    /// MAX_STREAMS if the peer hasn't granted enough capacity yet.
    pub async fn open_stream(&self) -> Result<u64, QMuxError> {
        loop {
            let notified = self.stream_open_notify.notified();
            let blocked_limit = {
                let inner = self.inner.lock().unwrap();
                match inner.peer_max_streams_bidi {
                    Some(limit) if inner.streams_opened >= limit => Some(limit),
                    _ => None,
                }
            };
            if let Some(limit) = blocked_limit {
                let frame = encode_streams_blocked(false, limit)?;
                (self.send)(&encode_record(&frame)?);
                notified.await;
                continue;
            }

            let mut inner = self.inner.lock().unwrap();
            let id = inner.next_local_stream_id;
            inner.next_local_stream_id = next_bidi_stream_id(id);
            inner.streams_opened += 1;
            let stream_data = inner.initial_max_stream_data;
            inner.streams.insert(id, StreamState::new(stream_data, stream_data));
            return Ok(id);
        }
    }

    pub fn stream_send_state(&self, stream_id: u64) -> Option<SendState> {
        self.inner.lock().unwrap().streams.get(&stream_id).map(|s| s.send_state)
    }

    pub fn stream_recv_state(&self, stream_id: u64) -> Option<RecvState> {
        self.inner.lock().unwrap().streams.get(&stream_id).map(|s| s.recv_state)
    }

    pub fn stream_exists(&self, stream_id: u64) -> bool {
        self.inner.lock().unwrap().streams.contains_key(&stream_id)
    }

    // ── Sending ──────────────────────────────────────────────────────

    /// Write `data` to a stream, blocking on flow control as needed.
    /// Resolves once the bytes have been handed to the connection (the
    /// underlying transport is reliable, so that's as strong a
    /// guarantee as this layer offers or needs).
    pub async fn write_stream(&self, stream_id: u64, data: &[u8]) -> Result<(), QMuxError> {
        {
            let mut inner = self.inner.lock().unwrap();
            let stream = inner.streams.get_mut(&stream_id).ok_or_else(|| {
                QMuxError::new(ErrorCode::InternalError, format!("write to unknown stream {stream_id}"))
            })?;
            match stream.send_state {
                SendState::ResetSent => {
                    return Err(QMuxError::new(ErrorCode::StreamStateError, format!("stream {stream_id} already reset")))
                }
                SendState::DataSent => {
                    return Err(QMuxError::new(
                        ErrorCode::StreamStateError,
                        format!("stream {stream_id} already closed (FIN sent)"),
                    ))
                }
                _ => {}
            }
            stream.send_state = SendState::Send;
        }

        let mut offset = 0usize;
        while offset < data.len() {
            let chunk_len = self.wait_for_send_window(stream_id, data.len() - offset).await?;
            let slice = &data[offset..offset + chunk_len];
            self.send_stream_chunk(stream_id, slice, false)?;
            offset += chunk_len;
        }
        Ok(())
    }

    /// Wait until at least 1 byte of send window is available and
    /// reserve it; returns how many bytes may be sent now (<= requested).
    async fn wait_for_send_window(&self, stream_id: u64, requested: usize) -> Result<usize, QMuxError> {
        loop {
            let notified = self.send_notify.notified();
            let outcome = {
                let mut inner = self.inner.lock().unwrap();
                let conn_send_window = inner.conn_send_window;
                let conn_send_offset = inner.conn_send_offset;

                // Scope the stream borrow tightly: `inner.streams.get_mut`
                // locks the whole `inner` guard (it goes through a
                // DerefMut call, so the borrow checker can't split it
                // field-by-field), so no other `inner.*` field may be
                // touched until this borrow ends.
                let (available, stream_blocked_frame) = {
                    let stream = inner.streams.get_mut(&stream_id).ok_or_else(|| {
                        QMuxError::new(ErrorCode::InternalError, format!("stream {stream_id} disappeared"))
                    })?;
                    if matches!(stream.send_state, SendState::ResetSent) {
                        return Err(QMuxError::new(ErrorCode::StreamStateError, format!("stream {stream_id} was reset")));
                    }
                    let available = (requested as i64).min(stream.send_window).min(conn_send_window).max(0) as usize;
                    if available > 0 {
                        stream.send_window -= available as i64;
                        (available, None)
                    } else if stream.send_window <= 0 {
                        let limit = (stream.send_offset as i64 + stream.send_window).max(0) as u64;
                        (0, Some(encode_stream_data_blocked(stream_id, limit)?))
                    } else {
                        (0, None)
                    }
                };

                if available > 0 {
                    inner.conn_send_window -= available as i64;
                    (Some(available), Vec::new())
                } else {
                    let mut blocked_frames = Vec::new();
                    if let Some(f) = stream_blocked_frame {
                        blocked_frames.push(f);
                    }
                    if conn_send_window <= 0 && inner.last_data_blocked_at != conn_send_offset as i64 {
                        inner.last_data_blocked_at = conn_send_offset as i64;
                        let limit = (conn_send_offset as i64 + conn_send_window).max(0) as u64;
                        blocked_frames.push(encode_data_blocked(limit)?);
                    }
                    (None, blocked_frames)
                }
            };

            match outcome {
                (Some(available), _) => return Ok(available),
                (None, blocked_frames) => {
                    for frame in blocked_frames {
                        (self.send)(&encode_record(&frame)?);
                    }
                    notified.await;
                }
            }
        }
    }

    fn send_stream_chunk(&self, stream_id: u64, data: &[u8], fin: bool) -> Result<(), QMuxError> {
        let (frame, record);
        {
            let mut inner = self.inner.lock().unwrap();
            let stream = inner.streams.get_mut(&stream_id).ok_or_else(|| {
                QMuxError::new(ErrorCode::InternalError, format!("stream {stream_id} disappeared"))
            })?;
            let send_offset = stream.send_offset;
            stream.send_offset += data.len() as u64;
            frame = encode_stream(stream_id, send_offset, data, fin)?;
            inner.conn_send_offset += data.len() as u64;
        }
        record = encode_record(&frame)?;
        (self.send)(&record);
        Ok(())
    }

    /// Half-close the send side: send FIN. No more `write_stream` calls after this.
    pub fn close_stream(&self, stream_id: u64) -> Result<(), QMuxError> {
        let already_done = {
            let inner = self.inner.lock().unwrap();
            match inner.streams.get(&stream_id) {
                Some(s) => matches!(s.send_state, SendState::ResetSent | SendState::DataSent),
                None => true,
            }
        };
        if already_done {
            return Ok(());
        }
        self.send_stream_chunk(stream_id, &[], true)?;
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(s) = inner.streams.get_mut(&stream_id) {
                s.send_state = SendState::DataSent;
            }
        }
        self.maybe_stream_closed(stream_id);
        Ok(())
    }

    /// Abort the send side. `reliable_size` (bytes already written,
    /// counted from offset 0) are guaranteed delivered even though the
    /// stream is reset (draft-ietf-quic-reliable-stream-reset-09). Pass
    /// 0 for an ordinary abrupt reset with no preserved prefix.
    pub fn reset_stream(&self, stream_id: u64, error_code: ErrorCode, reliable_size: u64) -> Result<(), QMuxError> {
        let (already_done, final_size) = {
            let inner = self.inner.lock().unwrap();
            match inner.streams.get(&stream_id) {
                Some(s) => (matches!(s.send_state, SendState::ResetSent | SendState::DataSent), s.send_offset),
                None => (true, 0),
            }
        };
        if already_done {
            return Ok(());
        }

        let frame = if reliable_size > 0 {
            encode_reset_stream_at(stream_id, error_code, final_size, reliable_size.min(final_size))?
        } else {
            encode_reset_stream(stream_id, error_code, final_size)?
        };
        (self.send)(&encode_record(&frame)?);

        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(s) = inner.streams.get_mut(&stream_id) {
                s.send_state = SendState::ResetSent;
            }
        }
        // Wake any writer blocked in wait_for_send_window so it observes
        // ResetSent and fails, rather than waiting forever.
        self.send_notify.notify_waiters();
        self.maybe_stream_closed(stream_id);
        Ok(())
    }

    /// Tell the peer to stop sending (we're no longer interested in their data).
    pub fn stop_sending(&self, stream_id: u64, error_code: ErrorCode) -> Result<(), QMuxError> {
        let frame = encode_stop_sending(stream_id, error_code)?;
        (self.send)(&encode_record(&frame)?);
        Ok(())
    }

    /// Send an unreliable-in-the-QUIC-sense-but-actually-reliable-here datagram (RFC 9221, via QMux).
    pub fn send_datagram(&self, data: &[u8]) -> Result<(), QMuxError> {
        let frame = encode_datagram(data)?;
        (self.send)(&encode_record(&frame)?);
        Ok(())
    }

    /// Gracefully close the connection with CONNECTION_CLOSE.
    pub fn close(&self, error_code: ErrorCode, reason: &str) -> Result<(), QMuxError> {
        let already_closed = {
            let mut inner = self.inner.lock().unwrap();
            if inner.closed {
                true
            } else {
                inner.closed = true;
                false
            }
        };
        if already_closed {
            return Ok(());
        }
        let frame = encode_connection_close(true, error_code.code(), None, reason)?;
        (self.send)(&encode_record(&frame)?);
        Ok(())
    }

    /// Forcibly tear down every stream because the underlying transport
    /// itself died (closed or errored below the QMux layer) -- no
    /// CONNECTION_CLOSE is sent, since there's nowhere left to send it.
    pub fn destroy(&self) {
        let stream_ids: Vec<u64> = {
            let mut inner = self.inner.lock().unwrap();
            inner.closed = true;
            let ids: Vec<u64> = inner.streams.keys().copied().collect();
            inner.streams.clear();
            ids
        };
        self.send_notify.notify_waiters();
        self.stream_open_notify.notify_waiters();
        for stream_id in stream_ids {
            let _ = self.events.send(QMuxEvent::StreamDestroyed { stream_id });
        }
    }

    // ── Receiving ────────────────────────────────────────────────────

    /// Feed raw bytes received from the underlying transport.
    pub fn receive_bytes(&self, chunk: &[u8]) {
        let records = {
            let mut inner = self.inner.lock().unwrap();
            match inner.decoder.feed(chunk) {
                Ok(r) => r,
                Err(err) => {
                    drop(inner);
                    self.emit_error(err.to_string());
                    return;
                }
            }
        };
        for record in records {
            if self.inner.lock().unwrap().closed {
                break;
            }
            self.handle_record(&record);
        }
    }

    fn handle_record(&self, record: &[u8]) {
        let frames = match decode_frames(record) {
            Ok(f) => f,
            Err(err) => {
                self.close_locally(err.error_code, &err.message);
                self.emit_error(err.to_string());
                return;
            }
        };
        for frame in frames {
            if let Err(err) = self.handle_frame(frame) {
                self.close_locally(err.error_code, &err.message);
                self.emit_error(err.to_string());
                return;
            }
        }
    }

    fn handle_frame(&self, frame: Frame) -> Result<(), QMuxError> {
        match frame {
            Frame::QxTransportParameters { params } => {
                let mut inner = self.inner.lock().unwrap();
                if let Some(v) = params.initial_max_data {
                    inner.conn_send_window = v as i64 - inner.conn_send_offset as i64;
                }
                inner.peer_max_streams_bidi =
                    Some(params.initial_max_streams_bidi.unwrap_or(DEFAULT_INITIAL_MAX_STREAMS_BIDI));
                drop(inner);
                self.stream_open_notify.notify_waiters();
            }
            Frame::Stream { stream_id, offset, data, fin } => {
                let delivered = self.receive_stream_data(stream_id, offset, data, fin)?;
                self.account_conn_recv(delivered);
            }
            Frame::ResetStream { stream_id, error_code, final_size } => {
                self.receive_reset(stream_id, ErrorCode::from_code(error_code), final_size, 0)?;
            }
            Frame::ResetStreamAt { stream_id, error_code, final_size, reliable_size } => {
                self.receive_reset(stream_id, ErrorCode::from_code(error_code), final_size, reliable_size)?;
            }
            Frame::StopSending { stream_id, .. } => {
                // We're being told to stop sending; reset our send side
                // with no reliable prefix owed, regardless of the
                // STOP_SENDING frame's own error code.
                let _ = self.reset_stream(stream_id, ErrorCode::NoError, 0);
            }
            Frame::MaxData { max_data } => {
                let mut inner = self.inner.lock().unwrap();
                let new_window = max_data as i64 - inner.conn_send_offset as i64;
                if new_window > inner.conn_send_window {
                    inner.conn_send_window = new_window;
                    drop(inner);
                    self.send_notify.notify_waiters();
                }
            }
            Frame::MaxStreamData { stream_id, max_stream_data } => {
                let mut inner = self.inner.lock().unwrap();
                if let Some(s) = inner.streams.get_mut(&stream_id) {
                    let new_window = max_stream_data as i64 - s.send_offset as i64;
                    if new_window > s.send_window {
                        s.send_window = new_window;
                        drop(inner);
                        self.send_notify.notify_waiters();
                    }
                }
            }
            Frame::MaxStreams { unidirectional, max_streams } => {
                if !unidirectional {
                    let mut inner = self.inner.lock().unwrap();
                    inner.peer_max_streams_bidi = Some(max_streams);
                    drop(inner);
                    self.stream_open_notify.notify_waiters();
                }
            }
            Frame::DataBlocked { .. } | Frame::StreamDataBlocked { .. } | Frame::StreamsBlocked { .. } => {
                // Informational: the peer is blocked on a limit we control.
                // Nothing to do -- we already grant more window proactively
                // as data is consumed (see account_conn_recv / the window-
                // update logic in receive_stream_data).
            }
            Frame::ConnectionClose { error_code, reason, .. } => {
                {
                    let mut inner = self.inner.lock().unwrap();
                    inner.closed = true;
                }
                let _ = self
                    .events
                    .send(QMuxEvent::ConnectionClosed { error_code: ErrorCode::from_code(error_code), reason });
            }
            Frame::Datagram { data } => {
                let _ = self.events.send(QMuxEvent::Datagram { data });
            }
            Frame::Padding => {}
        }
        Ok(())
    }

    /// Look up a stream by ID, lazily creating (and reporting via
    /// `PeerStreamLookup::Created`) a peer-initiated one that hasn't
    /// been referenced yet -- QMux/QUIC streams aren't explicitly
    /// opened on the wire, so any frame referencing an unseen
    /// peer-initiated stream ID implicitly creates it (not just STREAM
    /// frames -- RESET_STREAM/RESET_STREAM_AT can legitimately be the
    /// first frame ever seen for a stream, reset before ever writing
    /// anything).
    fn get_or_create_peer_stream(&self, inner: &mut Inner, stream_id: u64) -> Result<PeerStreamLookup, QMuxError> {
        if inner.streams.contains_key(&stream_id) {
            return Ok(PeerStreamLookup::Existing);
        }
        if is_client_initiated(stream_id) == inner.is_client {
            return Ok(PeerStreamLookup::NotOurs);
        }
        let stream_ordinal = stream_id / 4 + 1;
        if stream_ordinal > inner.peer_streams_granted {
            return Err(QMuxError::new(
                ErrorCode::StreamLimitError,
                format!(
                    "peer referenced stream {stream_id} beyond the granted MAX_STREAMS limit ({})",
                    inner.peer_streams_granted
                ),
            ));
        }
        inner.peer_streams_opened = inner.peer_streams_opened.max(stream_ordinal);
        let stream_data = inner.initial_max_stream_data;
        inner.streams.insert(stream_id, StreamState::new(stream_data, stream_data));
        Ok(PeerStreamLookup::Created)
    }

    fn receive_stream_data(&self, stream_id: u64, offset: u64, data: Vec<u8>, fin: bool) -> Result<usize, QMuxError> {
        enum Outcome {
            Skip,
            Delivered {
                newly_opened: bool,
                delivered: usize,
                fin_fired: bool,
                reset_fired: Option<ErrorCode>,
                window_update: Option<u64>,
            },
        }

        let outcome = {
            let mut inner = self.inner.lock().unwrap();
            let lookup = self.get_or_create_peer_stream(&mut inner, stream_id)?;
            if matches!(lookup, PeerStreamLookup::NotOurs) {
                Outcome::Skip
            } else {
                let newly_opened = matches!(lookup, PeerStreamLookup::Created);
                let stream = inner.streams.get_mut(&stream_id).expect("just inserted or existing");

                if offset != stream.recv_buffered_up_to {
                    return Err(QMuxError::new(
                        ErrorCode::ProtocolViolation,
                        format!(
                            "stream {stream_id}: out-of-order STREAM frame (expected offset {}, got {offset})",
                            stream.recv_buffered_up_to
                        ),
                    ));
                }

                if matches!(stream.recv_state, RecvState::ResetRecvd) {
                    Outcome::Skip
                } else {
                    stream.recv_buffered_up_to += data.len() as u64;
                    let delivered = data.len();
                    if delivered > 0 {
                        stream.recv_offset += delivered as u64;
                    }

                    let mut fin_fired = false;
                    if fin {
                        stream.recv_state = RecvState::DataRecvd;
                        fin_fired = true;
                    }

                    let mut reset_fired = None;
                    let mut window_update = None;
                    if delivered > 0 {
                        reset_fired = complete_reset_if_ready(stream);
                        // Top up once more than half the granted window
                        // (measured against the fixed target window
                        // size, not the absolute granted limit, so
                        // updates don't become rarer over the stream's
                        // lifetime) has been consumed.
                        let remaining = stream.recv_window_granted as i64 - stream.recv_buffered_up_to as i64;
                        if remaining.saturating_mul(2) <= stream.recv_window as i64 {
                            let new_limit = stream.recv_buffered_up_to + stream.recv_window;
                            stream.recv_window_granted = new_limit;
                            window_update = Some(new_limit);
                        }
                    }

                    Outcome::Delivered { newly_opened, delivered, fin_fired, reset_fired, window_update }
                }
            }
        };

        match outcome {
            Outcome::Skip => Ok(0),
            Outcome::Delivered { newly_opened, delivered, fin_fired, reset_fired, window_update } => {
                if newly_opened {
                    let _ = self.events.send(QMuxEvent::StreamOpen { stream_id });
                }
                if delivered > 0 {
                    let _ = self.events.send(QMuxEvent::StreamData { stream_id, data });
                }
                if let Some(new_limit) = window_update {
                    let frame = encode_max_stream_data(stream_id, new_limit)?;
                    (self.send)(&encode_record(&frame)?);
                }
                if let Some(error_code) = reset_fired {
                    let _ = self.events.send(QMuxEvent::StreamReset { stream_id, error_code });
                    self.maybe_stream_closed(stream_id);
                }
                if fin_fired {
                    let _ = self.events.send(QMuxEvent::StreamEnd { stream_id });
                    self.maybe_stream_closed(stream_id);
                }
                Ok(delivered)
            }
        }
    }

    fn receive_reset(
        &self,
        stream_id: u64,
        error_code: ErrorCode,
        final_size: u64,
        reliable_size: u64,
    ) -> Result<(), QMuxError> {
        let outcome = {
            let mut inner = self.inner.lock().unwrap();
            let lookup = self.get_or_create_peer_stream(&mut inner, stream_id)?;
            if matches!(lookup, PeerStreamLookup::NotOurs) {
                return Ok(());
            }
            let newly_opened = matches!(lookup, PeerStreamLookup::Created);
            let stream = inner.streams.get_mut(&stream_id).expect("just inserted or existing");

            if matches!(stream.recv_state, RecvState::ResetRecvd | RecvState::DataRecvd) {
                (newly_opened, None)
            } else {
                let _ = final_size; // tracked implicitly via recv_buffered_up_to/reliable_size
                stream.reliable_size = Some(reliable_size);
                stream.reset_error_code = Some(error_code);
                stream.recv_state = RecvState::SizeKnown;
                let fired = complete_reset_if_ready(stream);
                (newly_opened, fired)
            }
        };

        let (newly_opened, fired) = outcome;
        if newly_opened {
            let _ = self.events.send(QMuxEvent::StreamOpen { stream_id });
        }
        if let Some(ec) = fired {
            let _ = self.events.send(QMuxEvent::StreamReset { stream_id, error_code: ec });
            self.maybe_stream_closed(stream_id);
        }
        Ok(())
    }

    /// Account newly-delivered bytes against the connection-level
    /// receive window and top it up (MAX_DATA) once consumption crosses
    /// the same threshold used for individual streams' MAX_STREAM_DATA.
    fn account_conn_recv(&self, byte_count: usize) {
        if byte_count == 0 {
            return;
        }
        let update = {
            let mut inner = self.inner.lock().unwrap();
            inner.conn_recv_buffered_up_to += byte_count as u64;
            let remaining = inner.conn_recv_window_granted as i64 - inner.conn_recv_buffered_up_to as i64;
            if remaining.saturating_mul(2) <= inner.conn_recv_window as i64 {
                let new_limit = inner.conn_recv_buffered_up_to + inner.conn_recv_window;
                inner.conn_recv_window_granted = new_limit;
                Some(new_limit)
            } else {
                None
            }
        };
        if let Some(new_limit) = update {
            if let Ok(frame) = encode_max_data(new_limit) {
                if let Ok(record) = encode_record(&frame) {
                    (self.send)(&record);
                }
            }
        }
    }

    /// Called whenever either direction of a stream reaches a terminal
    /// state; removes it from bookkeeping once *both* have, and for a
    /// peer-initiated stream, tops up the MAX_STREAMS grant so a
    /// long-lived connection doesn't permanently lose capacity as
    /// streams come and go.
    fn maybe_stream_closed(&self, stream_id: u64) {
        let action = {
            let mut inner = self.inner.lock().unwrap();
            let fully_closed = match inner.streams.get(&stream_id) {
                Some(s) => s.is_fully_closed(),
                None => false,
            };
            if !fully_closed {
                return;
            }
            inner.streams.remove(&stream_id);

            if is_client_initiated(stream_id) != inner.is_client {
                let headroom = inner.peer_streams_granted as i64 - inner.peer_streams_opened as i64;
                if headroom.saturating_mul(2) <= inner.max_streams_bidi as i64 {
                    let new_granted = inner.peer_streams_opened + inner.max_streams_bidi;
                    inner.peer_streams_granted = new_granted;
                    Some(new_granted)
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(new_granted) = action {
            if let Ok(frame) = encode_max_streams(false, new_granted) {
                if let Ok(record) = encode_record(&frame) {
                    (self.send)(&record);
                }
            }
        }
    }

    fn close_locally(&self, error_code: ErrorCode, reason: &str) {
        let already = {
            let mut inner = self.inner.lock().unwrap();
            if inner.closed {
                true
            } else {
                inner.closed = true;
                false
            }
        };
        if already {
            return;
        }
        if let Ok(frame) = encode_connection_close(false, error_code.code(), None, reason) {
            if let Ok(record) = encode_record(&frame) {
                (self.send)(&record);
            }
        }
    }

    fn emit_error(&self, message: String) {
        let _ = self.events.send(QMuxEvent::Error { message });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// Wire two connections together via unbounded channels, pumped by
    /// background tasks that `yield_now()` before delivering -- a
    /// deliberately-async fake wire (mirroring qmux-connection.test.mjs's
    /// setTimeout(0)-based harness) so that flow-control blocking is
    /// actually observable rather than resolving within the same tick.
    struct Pair {
        client: Arc<QMuxConnection>,
        server: Arc<QMuxConnection>,
        client_events: mpsc::UnboundedReceiver<QMuxEvent>,
        server_events: mpsc::UnboundedReceiver<QMuxEvent>,
    }

    fn make_pair_with(config: impl Fn(bool) -> QMuxConnectionConfig) -> Pair {
        let (c2s_tx, mut c2s_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (s2c_tx, mut s2c_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (client_ev_tx, client_events) = mpsc::unbounded_channel();
        let (server_ev_tx, server_events) = mpsc::unbounded_channel();

        let client = Arc::new(QMuxConnection::new(
            config(true),
            move |bytes: &[u8]| {
                let _ = c2s_tx.send(bytes.to_vec());
            },
            client_ev_tx,
        ));
        let server = Arc::new(QMuxConnection::new(
            config(false),
            move |bytes: &[u8]| {
                let _ = s2c_tx.send(bytes.to_vec());
            },
            server_ev_tx,
        ));

        let server_for_pump = server.clone();
        tokio::spawn(async move {
            while let Some(bytes) = c2s_rx.recv().await {
                tokio::task::yield_now().await;
                server_for_pump.receive_bytes(&bytes);
            }
        });
        let client_for_pump = client.clone();
        tokio::spawn(async move {
            while let Some(bytes) = s2c_rx.recv().await {
                tokio::task::yield_now().await;
                client_for_pump.receive_bytes(&bytes);
            }
        });

        Pair { client, server, client_events, server_events }
    }

    fn make_pair() -> Pair {
        make_pair_with(|is_client| QMuxConnectionConfig { is_client, ..Default::default() })
    }

    async fn handshake(pair: &Pair) {
        pair.client.send_handshake().unwrap();
        pair.server.send_handshake().unwrap();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn basic_round_trip_client_opens_stream_and_writes_data() {
        let mut pair = make_pair();
        handshake(&pair).await;

        let stream_id = pair.client.open_stream().await.unwrap();
        pair.client.write_stream(stream_id, b"hello").await.unwrap();
        pair.client.close_stream(stream_id).unwrap();

        let mut got_data = None;
        let mut got_end = false;
        for _ in 0..4 {
            match pair.server_events.recv().await.unwrap() {
                QMuxEvent::StreamOpen { stream_id: id } => assert_eq!(id, stream_id),
                QMuxEvent::StreamData { stream_id: id, data } => {
                    assert_eq!(id, stream_id);
                    got_data = Some(data);
                }
                QMuxEvent::StreamEnd { stream_id: id } => {
                    assert_eq!(id, stream_id);
                    got_end = true;
                    break;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
        assert_eq!(got_data.unwrap(), b"hello");
        assert!(got_end);
    }

    #[tokio::test]
    async fn server_initiated_stream_fires_stream_open_on_the_client() {
        let mut pair = make_pair();
        handshake(&pair).await;

        let stream_id = pair.server.open_stream().await.unwrap();
        pair.server.write_stream(stream_id, b"hi").await.unwrap();

        loop {
            match pair.client_events.recv().await.unwrap() {
                QMuxEvent::StreamOpen { stream_id: id } => {
                    assert_eq!(id, stream_id);
                    assert!(!is_client_initiated(id));
                    break;
                }
                QMuxEvent::StreamData { .. } => continue,
                other => panic!("unexpected event: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn write_blocks_on_stream_level_flow_control_and_unblocks_on_max_stream_data() {
        let mut pair = make_pair_with(|is_client| QMuxConnectionConfig {
            is_client,
            initial_max_stream_data: 8,
            ..Default::default()
        });
        handshake(&pair).await;

        let stream_id = pair.client.open_stream().await.unwrap();
        let payload = vec![7u8; 20];
        let client = pair.client.clone();
        let write_task = tokio::spawn(async move { client.write_stream(stream_id, &payload).await });

        // Drain server-side StreamOpen + StreamData events until all 20
        // bytes have arrived, proving the writer didn't just dump
        // everything synchronously despite the 8-byte window.
        let mut total = 0usize;
        while total < 20 {
            match pair.server_events.recv().await.unwrap() {
                QMuxEvent::StreamData { data, .. } => total += data.len(),
                _ => {}
            }
        }
        write_task.await.unwrap().unwrap();
        assert_eq!(total, 20);
    }

    #[tokio::test]
    async fn reset_stream_at_delivers_the_reliable_prefix_then_fires_stream_reset() {
        // Drive the server's receive side directly with a partial
        // STREAM frame followed by RESET_STREAM_AT, rather than racing
        // a real writer against its own flow-control window (whether
        // the writer gets blocked before the reset depends on how fast
        // the MAX_STREAM_DATA round trip completes on the fake wire,
        // which isn't deterministic). This is a decode-side property of
        // receive_reset/complete_reset_if_ready regardless of how the
        // sender got there.
        let mut pair = make_pair();
        handshake(&pair).await;

        let stream_frame = encode_stream(0, 0, b"abcd", false).unwrap();
        pair.server.receive_bytes(&encode_record(&stream_frame).unwrap());
        let reset_frame = encode_reset_stream_at(0, ErrorCode::ApplicationError, 6, 4).unwrap();
        pair.server.receive_bytes(&encode_record(&reset_frame).unwrap());

        let mut prefix = Vec::new();
        let mut reset_code = None;
        loop {
            match pair.server_events.recv().await.unwrap() {
                QMuxEvent::StreamOpen { .. } => {}
                QMuxEvent::StreamData { data, .. } => prefix.extend(data),
                QMuxEvent::StreamReset { error_code, .. } => {
                    reset_code = Some(error_code);
                    break;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
        assert_eq!(prefix, b"abcd");
        assert_eq!(reset_code, Some(ErrorCode::ApplicationError));
    }

    #[tokio::test]
    async fn stop_sending_causes_the_writer_side_to_reset() {
        let mut pair = make_pair();
        handshake(&pair).await;

        let stream_id = pair.client.open_stream().await.unwrap();
        pair.client.write_stream(stream_id, b"x").await.unwrap();

        // Let the server see the stream, then ask the client to stop sending.
        loop {
            match pair.server_events.recv().await.unwrap() {
                QMuxEvent::StreamOpen { .. } | QMuxEvent::StreamData { .. } => break,
                _ => {}
            }
        }
        pair.server.stop_sending(stream_id, ErrorCode::ApplicationError).unwrap();

        for _ in 0..20 {
            if matches!(pair.client.stream_send_state(stream_id), Some(SendState::ResetSent)) {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("client stream never reached ResetSent after STOP_SENDING");
    }

    #[tokio::test]
    async fn out_of_order_stream_frame_is_a_protocol_violation() {
        let mut pair = make_pair();
        handshake(&pair).await;

        // Bypass the normal write path to inject an out-of-order STREAM
        // frame directly at the wire level.
        let bad_frame = encode_stream(0, 100, b"late", false).unwrap();
        let bad_record = encode_record(&bad_frame).unwrap();
        pair.server.receive_bytes(&bad_record);

        match pair.server_events.recv().await.unwrap() {
            QMuxEvent::Error { message } => assert!(message.contains("out-of-order")),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn open_stream_blocks_on_max_streams_and_unblocks_when_peer_grants_more() {
        let mut pair = make_pair_with(|is_client| QMuxConnectionConfig {
            is_client,
            initial_max_streams_bidi: 1,
            ..Default::default()
        });
        handshake(&pair).await;

        let first = pair.client.open_stream().await.unwrap();
        let client = pair.client.clone();
        let second_task = tokio::spawn(async move { client.open_stream().await });

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(!second_task.is_finished());

        // Closing the first (peer-initiated from the server's point of
        // view... actually client-initiated) stream on both sides frees
        // capacity once the server sees it fully close and tops up
        // MAX_STREAMS.
        pair.client.close_stream(first).unwrap();
        // Server must also close its side for the stream to be "fully closed".
        loop {
            match pair.server_events.recv().await.unwrap() {
                QMuxEvent::StreamEnd { stream_id } => {
                    pair.server.close_stream(stream_id).unwrap();
                    break;
                }
                _ => {}
            }
        }

        let second = tokio::time::timeout(std::time::Duration::from_secs(5), second_task)
            .await
            .expect("open_stream should unblock after MAX_STREAMS is topped up")
            .unwrap()
            .unwrap();
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn connection_close_is_observed_by_the_peer() {
        let pair = make_pair();
        let mut pair = pair;
        handshake(&pair).await;

        pair.client.close(ErrorCode::NoError, "bye").unwrap();
        match pair.server_events.recv().await.unwrap() {
            QMuxEvent::ConnectionClosed { reason, .. } => assert_eq!(reason, "bye"),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn datagram_round_trips_through_the_connection() {
        let mut pair = make_pair();
        handshake(&pair).await;

        pair.client.send_datagram(b"ping").unwrap();
        match pair.server_events.recv().await.unwrap() {
            QMuxEvent::Datagram { data } => assert_eq!(data, b"ping"),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn destroy_tears_down_open_streams_without_sending_anything() {
        let mut pair = make_pair();
        handshake(&pair).await;

        let stream_id = pair.client.open_stream().await.unwrap();
        pair.client.write_stream(stream_id, b"x").await.unwrap();
        let mut seen_open = false;
        let mut seen_data = false;
        while !(seen_open && seen_data) {
            match pair.server_events.recv().await.unwrap() {
                QMuxEvent::StreamOpen { .. } => seen_open = true,
                QMuxEvent::StreamData { .. } => seen_data = true,
                other => panic!("unexpected event: {other:?}"),
            }
        }

        pair.server.destroy();
        match pair.server_events.recv().await.unwrap() {
            QMuxEvent::StreamDestroyed { stream_id: id } => assert_eq!(id, stream_id),
            other => panic!("unexpected event: {other:?}"),
        }
        assert!(!pair.server.stream_exists(stream_id));
    }
}
