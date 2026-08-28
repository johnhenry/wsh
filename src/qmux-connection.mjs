/**
 * QMux connection: stream state machine + flow-control accounting on
 * top of the wire codec in qmux.mjs.
 *
 * This module has no DOM Streams API dependency and no transport
 * dependency of its own — it takes a `send(bytes)` callback for
 * outbound record bytes and a `receiveBytes(chunk)` method fed by
 * whatever owns the underlying connection (transport-ws.mjs). That
 * keeps the state machine testable without a real or fake WebSocket.
 *
 * Because the underlying transport (a WebSocket) already guarantees
 * in-order, lossless delivery, there is no packet loss, reordering, or
 * retransmission to handle — flow control here exists purely to bound
 * memory (backpressure), not to manage congestion. See qmux.mjs's file
 * doc comment for why that's QMux's whole design point.
 */

import {
  encodeRecord, RecordDecoder, decodeFrames,
  encodeStream, encodeResetStream, encodeResetStreamAt, encodeStopSending,
  encodeMaxData, encodeMaxStreamData, encodeMaxStreams,
  encodeDataBlocked, encodeStreamDataBlocked, encodeStreamsBlocked,
  encodeConnectionClose, encodeDatagram, encodeTransportParameters,
  ERROR_CODE, STREAM_INITIATOR, firstBidiStreamId, nextBidiStreamId,
  isClientInitiated, QMuxProtocolError,
} from './qmux.mjs';

export const DEFAULTS = Object.freeze({
  initialMaxData: 8 * 1024 * 1024,          // 8 MiB per connection
  initialMaxStreamData: 1024 * 1024,        // 1 MiB per stream
  initialMaxStreamsBidi: 100,
});

// Send a window update once the peer has consumed at least this
// fraction of the previously-granted window, rather than after every
// single read (classic QUIC-style windowed flow control).
const WINDOW_UPDATE_THRESHOLD = 0.5;

// ── Per-stream send/receive state ───────────────────────────────────

const SEND_STATE = Object.freeze({
  READY: 'ready',           // nothing sent yet
  SEND: 'send',             // sending data
  RESET_SENT: 'reset_sent', // we sent RESET_STREAM/RESET_STREAM_AT
  DATA_SENT: 'data_sent',   // we sent FIN (final size known to peer)
});

const RECV_STATE = Object.freeze({
  RECV: 'recv',                   // receiving data, final size unknown
  SIZE_KNOWN: 'size_known',       // FIN or RESET_STREAM_AT seen; final size known
  DATA_RECVD: 'data_recvd',       // all bytes up to final/reliable size delivered to app
  RESET_RECVD: 'reset_recvd',     // peer reset with no reliable prefix left to deliver
});

/**
 * One multiplexed stream. Exposes a minimal push/pull data API (not a
 * DOM ReadableStream/WritableStream directly) — transport-ws.mjs wraps
 * this in the actual Streams API objects the rest of wsh expects.
 */
class QMuxStream {
  id;
  #conn;

  // Send side
  #sendState = SEND_STATE.READY;
  #sendOffset = 0;
  #sendWindow; // bytes we're currently allowed to send beyond #sendOffset
  #sendWaiters = []; // {resolve} queue, FIFO, woken as window opens

  // Receive side
  #recvState = RECV_STATE.RECV;
  #recvOffset = 0; // bytes delivered to the application (onData)
  #recvBufferedUpTo = 0; // bytes received from the wire (buffered + delivered)
  #recvWindow; // bytes we've told the peer they may still send
  #recvWindowGranted; // the window value last announced via MAX_STREAM_DATA
  #finalSize = null; // set once FIN or RESET_STREAM_AT/RESET_STREAM is seen
  #reliableSize = null; // set on RESET_STREAM_AT; null means "no reset"
  #resetErrorCode = null;
  #outOfOrderChunks = new Map(); // offset -> data, for frames that arrive with gaps (shouldn't happen over an in-order transport, but guarded)

  onData = null;   // (Uint8Array) => void -- in-order delivery
  onEnd = null;     // () => void -- clean FIN, all data delivered
  onReset = null;  // (errorCode) => void -- peer aborted (after any reliable prefix delivered)

  constructor(conn, id, { sendWindow, recvWindow }) {
    this.#conn = conn;
    this.id = id;
    this.#sendWindow = sendWindow;
    this.#recvWindow = recvWindow;
    this.#recvWindowGranted = recvWindow;
  }

  get sendState() { return this.#sendState; }
  get recvState() { return this.#recvState; }

  /** Both directions have reached a terminal state (sent/reset, and received/reset). */
  _isFullyClosed() {
    const sendDone = this.#sendState === SEND_STATE.DATA_SENT || this.#sendState === SEND_STATE.RESET_SENT;
    const recvDone = this.#recvState === RECV_STATE.DATA_RECVD || this.#recvState === RECV_STATE.RESET_RECVD;
    return sendDone && recvDone;
  }

  /**
   * Write `bytes` to the stream. Resolves once the bytes have been
   * hand off to the connection (which may itself wait on connection-
   * level flow control) -- QMux has no real acknowledgment, so "sent"
   * is as strong a guarantee as this layer offers (the underlying
   * transport is reliable, so that's sufficient).
   * @param {Uint8Array} bytes
   */
  async write(bytes) {
    if (this.#sendState === SEND_STATE.RESET_SENT) {
      throw new Error(`Cannot write to stream ${this.id}: already reset`);
    }
    if (this.#sendState === SEND_STATE.DATA_SENT) {
      throw new Error(`Cannot write to stream ${this.id}: already closed (FIN sent)`);
    }
    this.#sendState = SEND_STATE.SEND;

    let offset = 0;
    while (offset < bytes.byteLength) {
      const chunk = await this.#waitForSendWindow(bytes.byteLength - offset);
      const slice = bytes.subarray(offset, offset + chunk);
      this.#conn._sendFrame(encodeStream({
        streamId: this.id,
        offset: this.#sendOffset,
        data: slice,
        fin: false,
      }), slice.byteLength);
      this.#sendOffset += slice.byteLength;
      this.#sendWindow -= slice.byteLength;
      offset += slice.byteLength;
    }
  }

  /** Half-close the send side: send FIN. No more write() calls after this. */
  async close() {
    if (this.#sendState === SEND_STATE.RESET_SENT || this.#sendState === SEND_STATE.DATA_SENT) return;
    this.#conn._sendFrame(encodeStream({
      streamId: this.id,
      offset: this.#sendOffset,
      data: new Uint8Array(0),
      fin: true,
    }), 0);
    this.#sendState = SEND_STATE.DATA_SENT;
    this.#conn._maybeStreamClosed(this.id);
  }

  /**
   * Abort the send side. `reliableSize` (bytes already written via
   * write(), counted from offset 0) are guaranteed delivered even
   * though the stream is reset -- draft-ietf-quic-reliable-stream-
   * reset-09. Defaults to 0 (an ordinary abrupt reset, no prefix
   * preserved) to match RESET_STREAM's semantics exactly when omitted.
   */
  reset(errorCode = ERROR_CODE.APPLICATION_ERROR, reliableSize = 0) {
    if (this.#sendState === SEND_STATE.RESET_SENT || this.#sendState === SEND_STATE.DATA_SENT) return;
    const finalSize = this.#sendOffset;
    if (reliableSize > 0) {
      this.#conn._sendFrame(encodeResetStreamAt({
        streamId: this.id, errorCode, finalSize, reliableSize: Math.min(reliableSize, finalSize),
      }), 0);
    } else {
      this.#conn._sendFrame(encodeResetStream({ streamId: this.id, errorCode, finalSize }), 0);
    }
    this.#sendState = SEND_STATE.RESET_SENT;
    this.#failSendWaiters(new Error(`Stream ${this.id} was reset`));
    this.#conn._maybeStreamClosed(this.id);
  }

  /** Tell the peer to stop sending (we're no longer interested in their data). */
  stopSending(errorCode = ERROR_CODE.APPLICATION_ERROR) {
    this.#conn._sendFrame(encodeStopSending({ streamId: this.id, errorCode }), 0);
  }

  // ── Flow control (send side) ────────────────────────────────────

  /** Wait until at least 1 byte of send window is available; returns how many bytes may be sent now (<= requested). */
  #waitForSendWindow(requested) {
    const available = Math.min(requested, this.#sendWindow, this.#conn._connSendWindow());
    if (available > 0) {
      // Also reserve against the connection-level window immediately,
      // synchronously with this stream's own window check, so two
      // streams can't both observe "room" and together overrun it.
      this.#conn._reserveConnSendWindow(available);
      return Promise.resolve(available);
    }

    // Tell the peer which limit we're blocked on -- informational (we'll
    // proceed as soon as a MAX_DATA/MAX_STREAM_DATA arrives regardless),
    // but real QUIC implementations rely on *_BLOCKED to prioritize whose
    // window to raise first, so a full-spec implementation sends them.
    if (this.#sendWindow <= 0) {
      this.#conn._sendFrame(encodeStreamDataBlocked({ streamId: this.id, streamDataLimit: this.#sendOffset + this.#sendWindow }), 0);
    }
    if (this.#conn._connSendWindow() <= 0) {
      this.#conn._sendDataBlocked();
    }

    return new Promise((resolve, reject) => {
      this.#sendWaiters.push({ resolve, reject, requested });
    });
  }

  /** Called by the connection when peer grants more stream-level window (MAX_STREAM_DATA). */
  _grantSendWindow(newLimit) {
    // newLimit is an absolute offset limit, not a delta; MAX_STREAM_DATA
    // frames MUST NOT be allowed to reduce the window (RFC 9000 §4.1) --
    // a lower/stale value (possible if frames could reorder) is ignored.
    const newWindow = newLimit - this.#sendOffset;
    if (newWindow <= this.#sendWindow) return;
    this.#sendWindow = newWindow;
    this.#wakeSendWaiters();
  }

  /**
   * Called by the connection when connection-level MAX_DATA increases --
   * this stream's own window is unchanged, but a waiter blocked purely
   * on the connection-level window may now be able to proceed.
   */
  _recheckSendWindow() {
    this.#wakeSendWaiters();
  }

  #wakeSendWaiters() {
    while (this.#sendWaiters.length > 0 && this.#sendWindow > 0) {
      const waiter = this.#sendWaiters[0];
      const available = Math.min(waiter.requested, this.#sendWindow, this.#conn._connSendWindow());
      if (available <= 0) break;
      this.#sendWaiters.shift();
      this.#conn._reserveConnSendWindow(available);
      waiter.resolve(available);
    }
  }

  #failSendWaiters(err) {
    for (const waiter of this.#sendWaiters.splice(0)) waiter.reject(err);
  }

  // ── Flow control (receive side) ─────────────────────────────────

  /**
   * Handle an inbound STREAM frame's payload for this stream. Delivers
   * data to onData in order (the underlying transport is already
   * in-order, so out-of-order arrival here would itself be a protocol
   * violation per QMux -- guarded defensively, not expected).
   */
  /** @returns {number} bytes newly accounted for (for the connection's own MAX_DATA bookkeeping) */
  _receiveStreamData(offset, data, fin) {
    if (offset !== this.#recvBufferedUpTo) {
      throw new QMuxProtocolError(
        ERROR_CODE.PROTOCOL_VIOLATION,
        `stream ${this.id}: out-of-order STREAM frame (expected offset ${this.#recvBufferedUpTo}, got ${offset})`
      );
    }
    if (this.#recvState === RECV_STATE.RESET_RECVD) return 0; // peer already reset; ignore trailing data

    this.#recvBufferedUpTo += data.byteLength;
    if (data.byteLength > 0) {
      this.#recvOffset += data.byteLength;
      try { this.onData?.(data); } catch (err) { console.error('[qmux] onData handler error:', err); }
      this.#maybeGrantMoreWindow();
    }

    if (fin) {
      this.#finalSize = this.#recvBufferedUpTo;
      this.#recvState = RECV_STATE.DATA_RECVD;
      try { this.onEnd?.(); } catch (err) { console.error('[qmux] onEnd handler error:', err); }
      this.#conn._maybeStreamClosed(this.id);
    }

    return data.byteLength;
  }

  /** Handle an inbound RESET_STREAM/RESET_STREAM_AT for this stream. */
  _receiveReset(errorCode, finalSize, reliableSize) {
    if (this.#recvState === RECV_STATE.RESET_RECVD || this.#recvState === RECV_STATE.DATA_RECVD) return;

    this.#finalSize = finalSize;
    this.#reliableSize = reliableSize;
    this.#resetErrorCode = errorCode;
    this.#recvState = RECV_STATE.SIZE_KNOWN;

    // If we've already received (and delivered) everything up to the
    // reliable prefix, the abort is actionable immediately. Otherwise
    // wait -- more STREAM frames for the reliable prefix are still
    // coming (guaranteed by the sender's obligation to deliver them).
    this.#maybeCompleteReset();
  }

  #maybeCompleteReset() {
    if (this.#reliableSize === null) return;
    if (this.#recvBufferedUpTo < this.#reliableSize) return;
    if (this.#recvState === RECV_STATE.RESET_RECVD) return;
    this.#recvState = RECV_STATE.RESET_RECVD;
    try { this.onReset?.(this.#resetErrorCode); } catch (err) { console.error('[qmux] onReset handler error:', err); }
    this.#conn._maybeStreamClosed(this.id);
  }

  /**
   * Top up the stream-level window once the peer has used up more than
   * WINDOW_UPDATE_THRESHOLD of the *target* window size (#recvWindow,
   * a fixed size we aim to always keep available) -- not a threshold of
   * the absolute granted limit, which only grows over the stream's
   * lifetime and would make updates rarer and rarer over time if used
   * directly.
   */
  #maybeGrantMoreWindow() {
    this.#maybeCompleteReset();
    const remaining = this.#recvWindowGranted - this.#recvBufferedUpTo;
    if (remaining <= this.#recvWindow * (1 - WINDOW_UPDATE_THRESHOLD)) {
      const newLimit = this.#recvBufferedUpTo + this.#recvWindow;
      this.#recvWindowGranted = newLimit;
      this.#conn._sendFrame(encodeMaxStreamData({ streamId: this.id, maxStreamData: newLimit }), 0);
    }
  }
}

// ── Connection ───────────────────────────────────────────────────────

export class QMuxConnection {
  #isClient;
  #send; // (Uint8Array) => void, raw transport write
  #decoder = new RecordDecoder();
  #streams = new Map(); // streamId -> QMuxStream
  #nextLocalStreamId;
  #closed = false;

  // Connection-level flow control (send side: bytes *we* may still send)
  #connSendOffset = 0;
  #connSendWindow;
  #lastDataBlockedAt = -1; // last connSendOffset a DATA_BLOCKED was announced for, to avoid duplicates

  // Connection-level flow control (receive side: bytes we allow the peer to send)
  #connRecvBufferedUpTo = 0;
  #connRecvWindow;
  #connRecvWindowGranted;

  #maxStreamsBidi;
  #streamsOpened = 0; // locally-initiated bidi streams created so far
  #peerMaxStreamsBidi; // MAX_STREAMS grant from the peer (undefined until received)
  #streamOpenWaiters = [];

  // MAX_STREAMS we grant the peer: streamsGranted starts at #maxStreamsBidi
  // (sent in the handshake) and is topped up as peer-initiated streams
  // close, so the peer doesn't permanently lose capacity as streams
  // come and go over a long-lived connection.
  #peerStreamsOpened = 0; // cumulative count of peer-initiated streams accepted
  #peerStreamsGranted; // last MAX_STREAMS value announced (== #maxStreamsBidi until topped up)

  #initialMaxStreamData;

  onStreamOpen = null; // (QMuxStream) => void, for peer-initiated streams
  onDatagram = null;   // (Uint8Array) => void
  onClose = null;      // (errorCode, reason) => void
  onError = null;      // (Error) => void

  constructor({
    isClient,
    send,
    initialMaxData = DEFAULTS.initialMaxData,
    initialMaxStreamData = DEFAULTS.initialMaxStreamData,
    initialMaxStreamsBidi = DEFAULTS.initialMaxStreamsBidi,
  }) {
    this.#isClient = isClient;
    this.#send = send;
    this.#connSendWindow = initialMaxData; // updated once we learn the peer's real initial_max_data
    this.#connRecvWindow = initialMaxData;
    this.#connRecvWindowGranted = initialMaxData;
    this.#initialMaxStreamData = initialMaxStreamData;
    this.#maxStreamsBidi = initialMaxStreamsBidi;
    this.#peerStreamsGranted = initialMaxStreamsBidi;
    this.#nextLocalStreamId = firstBidiStreamId(isClient ? STREAM_INITIATOR.CLIENT : STREAM_INITIATOR.SERVER);
  }

  /** Send the QX_TRANSPORT_PARAMETERS handshake frame — must be the first frame sent (QMux §4.1). */
  sendHandshake() {
    this.#send(encodeRecord(encodeTransportParameters({
      initial_max_data: this.#connRecvWindowGranted,
      initial_max_stream_data_bidi_local: this.#initialMaxStreamData,
      initial_max_stream_data_bidi_remote: this.#initialMaxStreamData,
      initial_max_streams_bidi: this.#maxStreamsBidi,
    })));
  }

  /** Open a new locally-initiated bidirectional stream. */
  async openStream() {
    if (this.#peerMaxStreamsBidi !== undefined && this.#streamsOpened >= this.#peerMaxStreamsBidi) {
      this.#send(encodeRecord(encodeStreamsBlocked({ unidirectional: false, streamLimit: this.#peerMaxStreamsBidi })));
      await new Promise((resolve) => this.#streamOpenWaiters.push(resolve));
    }
    const id = this.#nextLocalStreamId;
    this.#nextLocalStreamId = nextBidiStreamId(id);
    this.#streamsOpened++;
    return this.#createStream(id);
  }

  #createStream(id) {
    const stream = new QMuxStream(this, id, {
      sendWindow: this.#initialMaxStreamData,
      recvWindow: this.#initialMaxStreamData,
    });
    this.#streams.set(id, stream);
    return stream;
  }

  /**
   * Look up a stream by ID, lazily creating (and firing onStreamOpen for)
   * a peer-initiated one that hasn't been referenced yet -- QMux/QUIC
   * streams aren't explicitly opened on the wire, so any frame
   * referencing an unseen peer-initiated stream ID implicitly creates
   * it, not just STREAM frames. Returns undefined (without creating
   * anything) for an ID this endpoint should itself have allocated,
   * since that can never legitimately be "peer-initiated."
   */
  #getOrCreatePeerStream(id) {
    let stream = this.#streams.get(id);
    if (stream) return stream;
    if (isClientInitiated(id) === this.#isClient) return undefined;

    const streamOrdinal = Math.floor(id / 4) + 1;
    if (streamOrdinal > this.#peerStreamsGranted) {
      throw new QMuxProtocolError(ERROR_CODE.STREAM_LIMIT_ERROR, `peer referenced stream ${id} beyond the granted MAX_STREAMS limit (${this.#peerStreamsGranted})`);
    }
    this.#peerStreamsOpened = Math.max(this.#peerStreamsOpened, streamOrdinal);
    stream = this.#createStream(id);
    try { this.onStreamOpen?.(stream); } catch (err) { console.error('[qmux] onStreamOpen handler error:', err); }
    return stream;
  }

  getStream(id) {
    return this.#streams.get(id);
  }

  /**
   * Called by a QMuxStream whenever either of its directions reaches a
   * terminal state; removes it from bookkeeping once *both* have, and
   * for a peer-initiated stream, tops up the MAX_STREAMS grant so a
   * long-lived connection doesn't permanently lose capacity as streams
   * come and go.
   */
  _maybeStreamClosed(id) {
    const stream = this.#streams.get(id);
    if (!stream || !stream._isFullyClosed()) return;
    this.#streams.delete(id);

    if (isClientInitiated(id) !== this.#isClient) {
      // Peer-initiated: consider raising MAX_STREAMS once less than half
      // the original window's worth of headroom remains, mirroring the
      // same threshold heuristic used for MAX_DATA/MAX_STREAM_DATA.
      const headroom = this.#peerStreamsGranted - this.#peerStreamsOpened;
      if (headroom <= this.#maxStreamsBidi * (1 - WINDOW_UPDATE_THRESHOLD)) {
        this.#peerStreamsGranted = this.#peerStreamsOpened + this.#maxStreamsBidi;
        this.#send(encodeRecord(encodeMaxStreams({ unidirectional: false, maxStreams: this.#peerStreamsGranted })));
      }
    }
  }

  /** Send an unreliable-in-the-QUIC-sense-but-actually-reliable-here datagram (RFC 9221, via QMux). */
  sendDatagram(bytes) {
    this.#send(encodeRecord(encodeDatagram(bytes)));
  }

  /** Feed raw bytes received from the underlying transport. */
  receiveBytes(chunk) {
    let records;
    try {
      records = this.#decoder.feed(chunk);
    } catch (err) {
      this.#emitError(err);
      return;
    }
    for (const record of records) {
      this.#handleRecord(record);
      if (this.#closed) break;
    }
  }

  #handleRecord(record) {
    let frames;
    try {
      frames = decodeFrames(record);
    } catch (err) {
      if (err instanceof QMuxProtocolError) {
        this.#closeLocally(err.errorCode, err.message);
      }
      this.#emitError(err);
      return;
    }
    for (const frame of frames) {
      try {
        this.#handleFrame(frame);
      } catch (err) {
        if (err instanceof QMuxProtocolError) {
          this.#closeLocally(err.errorCode, err.message);
        }
        this.#emitError(err);
        return;
      }
    }
  }

  #handleFrame(frame) {
    switch (frame.frameType) {
      case 'QX_TRANSPORT_PARAMETERS': {
        if (frame.params.initial_max_data !== undefined) {
          this.#connSendWindow = Number(frame.params.initial_max_data) - this.#connSendOffset;
        }
        this.#peerMaxStreamsBidi = frame.params.initial_max_streams_bidi !== undefined
          ? Number(frame.params.initial_max_streams_bidi)
          : DEFAULTS.initialMaxStreamsBidi;
        this.#wakeStreamOpenWaiters();
        break;
      }
      case 'STREAM': {
        const stream = this.#getOrCreatePeerStream(Number(frame.streamId));
        if (!stream) break; // an ID this endpoint should have allocated itself -- ignore/guard
        const delivered = stream._receiveStreamData(Number(frame.offset), frame.data, frame.fin);
        this.#accountConnRecv(delivered);
        break;
      }
      case 'RESET_STREAM': {
        // RESET_STREAM (like RESET_STREAM_AT below) can legitimately be
        // the *first* frame ever seen for a peer-initiated stream (reset
        // before ever writing anything) -- must lazily create it too,
        // not only the STREAM frame handler, or the reset is silently lost.
        const stream = this.#getOrCreatePeerStream(Number(frame.streamId));
        stream?._receiveReset(Number(frame.errorCode), Number(frame.finalSize), 0);
        break;
      }
      case 'RESET_STREAM_AT': {
        const stream = this.#getOrCreatePeerStream(Number(frame.streamId));
        stream?._receiveReset(Number(frame.errorCode), Number(frame.finalSize), Number(frame.reliableSize));
        break;
      }
      case 'STOP_SENDING': {
        const stream = this.#streams.get(Number(frame.streamId));
        // We're being told to stop sending; reset our send side with no reliable prefix owed.
        stream?.reset(ERROR_CODE.NO_ERROR, 0);
        break;
      }
      case 'MAX_DATA': {
        const newWindow = Number(frame.maxData) - this.#connSendOffset;
        if (newWindow > this.#connSendWindow) {
          this.#connSendWindow = newWindow;
          this.#wakeAllStreamSendWaiters();
        }
        break;
      }
      case 'MAX_STREAM_DATA': {
        const stream = this.#streams.get(Number(frame.streamId));
        stream?._grantSendWindow(Number(frame.maxStreamData));
        break;
      }
      case 'MAX_STREAMS': {
        if (!frame.unidirectional) {
          this.#peerMaxStreamsBidi = Number(frame.maxStreams);
          this.#wakeStreamOpenWaiters();
        }
        break;
      }
      case 'DATA_BLOCKED':
      case 'STREAM_DATA_BLOCKED':
      case 'STREAMS_BLOCKED': {
        // Informational: the peer is blocked on a limit we control.
        // Nothing to do here since we already grant more window
        // proactively as data is consumed (see #maybeGrantMoreWindow).
        break;
      }
      case 'CONNECTION_CLOSE': {
        this.#closed = true;
        try { this.onClose?.(frame.errorCode, frame.reason); } catch (err) { console.error('[qmux] onClose handler error:', err); }
        break;
      }
      case 'DATAGRAM': {
        try { this.onDatagram?.(frame.data); } catch (err) { console.error('[qmux] onDatagram handler error:', err); }
        break;
      }
      case 'PADDING':
        break;
      default:
        break;
    }
  }

  /** Gracefully close the connection with CONNECTION_CLOSE. */
  close(errorCode = ERROR_CODE.NO_ERROR, reason = '') {
    if (this.#closed) return;
    this.#send(encodeRecord(encodeConnectionClose({ application: true, errorCode, reason })));
    this.#closed = true;
  }

  #closeLocally(errorCode, reason) {
    if (this.#closed) return;
    try {
      this.#send(encodeRecord(encodeConnectionClose({ application: false, errorCode, reason })));
    } catch { /* best-effort */ }
    this.#closed = true;
  }

  #emitError(err) {
    try { this.onError?.(err); } catch (handlerErr) { console.error('[qmux] onError handler error:', handlerErr); }
  }

  #wakeStreamOpenWaiters() {
    while (
      this.#streamOpenWaiters.length > 0 &&
      (this.#peerMaxStreamsBidi === undefined || this.#streamsOpened < this.#peerMaxStreamsBidi)
    ) {
      this.#streamOpenWaiters.shift()();
    }
  }

  /**
   * Connection-level MAX_DATA increased -- recheck every stream's send
   * waiters, since any of them could have been blocked purely on the
   * connection-level window rather than their own stream-level window.
   */
  #wakeAllStreamSendWaiters() {
    for (const stream of this.#streams.values()) {
      stream._recheckSendWindow();
    }
  }

  /**
   * Account newly-delivered bytes against the connection-level receive
   * window and top it up (MAX_DATA) once consumption crosses the same
   * threshold used for individual streams' MAX_STREAM_DATA.
   */
  #accountConnRecv(byteCount) {
    if (byteCount <= 0) return;
    this.#connRecvBufferedUpTo += byteCount;
    const remaining = this.#connRecvWindowGranted - this.#connRecvBufferedUpTo;
    if (remaining <= this.#connRecvWindow * (1 - WINDOW_UPDATE_THRESHOLD)) {
      const newLimit = this.#connRecvBufferedUpTo + this.#connRecvWindow;
      this.#connRecvWindowGranted = newLimit;
      this.#send(encodeRecord(encodeMaxData(newLimit)));
    }
  }

  // ── Internal hooks used by QMuxStream ───────────────────────────

  _sendFrame(frameBytes, dataLength) {
    this.#send(encodeRecord(frameBytes));
    this.#connSendOffset += dataLength;
  }

  _connSendWindow() {
    return this.#connSendWindow;
  }

  _reserveConnSendWindow(n) {
    this.#connSendWindow -= n;
  }

  _sendDataBlocked() {
    // Avoid spamming an identical DATA_BLOCKED for the same limit on
    // every single blocked write -- only announce when the limit we're
    // blocked on has actually changed since the last announcement.
    if (this.#lastDataBlockedAt === this.#connSendOffset) return;
    this.#lastDataBlockedAt = this.#connSendOffset;
    this.#send(encodeRecord(encodeDataBlocked(this.#connSendOffset + this.#connSendWindow)));
  }
}
