/**
 * wsh transport — WebSocket fallback with multiplexed virtual streams.
 *
 * Wire format per frame:
 *   [1-byte type][4-byte stream_id (big-endian)][payload]
 *
 * Frame types:
 *   0x01 = CONTROL   — CBOR-framed message on stream 0
 *   0x02 = DATA       — raw bytes on a numbered stream
 *   0x03 = OPEN_STREAM — request to open a new stream (payload = empty)
 *   0x04 = CLOSE_STREAM — notify stream closure (payload = empty)
 *
 * Stream 0 is reserved for control messages and uses length-prefixed
 * CBOR framing (frameEncode / FrameDecoder) inside the payload.
 * Data streams carry raw bytes with no additional framing.
 */

import { frameEncode, FrameDecoder, FrameSizeError } from './cbor.mjs';
import { WshTransport } from './transport.mjs';

// ── Frame type constants ─────────────────────────────────────────────
//
// NOTE: these are unrelated to MSG.WS_DATA (0x60) in messages.gen.mjs.
// WS_DATA is a JS-only, CBOR-layer bookkeeping marker (it shares its
// opcode with MSG.DETACH and is explicitly excluded from the Rust
// message enum by spec/codegen.mjs) — it is never sent as the outer
// envelope's frame-type byte below. See spec/wsh-v1.yaml's
// `transport.websocket` section for the authoritative outer-envelope
// framing docs.

const FRAME_CONTROL      = 0x01;
const FRAME_DATA         = 0x02;
const FRAME_OPEN_STREAM  = 0x03;
const FRAME_CLOSE_STREAM = 0x04;

// ── Header helpers ───────────────────────────────────────────────────

const HEADER_SIZE = 5; // 1 byte type + 4 bytes stream ID

/**
 * Build a multiplexing frame.
 * @param {number} type     Frame type byte.
 * @param {number} streamId 32-bit stream ID.
 * @param {Uint8Array} [payload] Optional payload bytes.
 * @returns {Uint8Array}
 */
function buildFrame(type, streamId, payload) {
  const payloadLen = payload ? payload.byteLength : 0;
  const frame = new Uint8Array(HEADER_SIZE + payloadLen);
  const view = new DataView(frame.buffer);
  view.setUint8(0, type);
  view.setUint32(1, streamId);
  if (payload) {
    frame.set(payload, HEADER_SIZE);
  }
  return frame;
}

/**
 * Parse a multiplexing frame header + payload.
 * @param {Uint8Array} data
 * @returns {{ type: number, streamId: number, payload: Uint8Array }}
 */
function parseFrame(data) {
  if (data.byteLength < HEADER_SIZE) {
    throw new Error(`Frame too short: ${data.byteLength} bytes`);
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return {
    type: view.getUint8(0),
    streamId: view.getUint32(1),
    payload: data.subarray(HEADER_SIZE),
  };
}

// ── Virtual stream ───────────────────────────────────────────────────

/**
 * A virtual bidirectional stream multiplexed over a single WebSocket.
 *
 * Exposes standard ReadableStream / WritableStream interfaces so that
 * consumers see the same API as native WebTransport streams.
 */
class VirtualStream {
  /** @type {number} */
  id;

  /** @type {ReadableStream<Uint8Array>} */
  readable;

  /** @type {WritableStream<Uint8Array>} */
  writable;

  /** @type {ReadableStreamDefaultController} */
  #readController = null;

  /** @type {boolean} */
  #readClosed = false;

  /** @type {boolean} */
  #writeClosed = false;

  /**
   * @param {number} id
   * @param {function(number, Uint8Array): void} sendData  Send data frame callback.
   * @param {function(number): void} sendClose              Send close frame callback.
   */
  constructor(id, sendData, sendClose) {
    this.id = id;

    this.readable = new ReadableStream({
      start: (controller) => {
        this.#readController = controller;
      },
      cancel: () => {
        this.#readClosed = true;
      },
    });

    this.writable = new WritableStream({
      write: (chunk) => {
        if (this.#writeClosed) {
          throw new Error(`Stream ${id} writable is closed`);
        }
        const bytes = chunk instanceof Uint8Array
          ? chunk
          : new Uint8Array(chunk);
        sendData(id, bytes);
      },
      close: () => {
        this.#writeClosed = true;
        sendClose(id);
      },
      abort: () => {
        this.#writeClosed = true;
        sendClose(id);
      },
    });
  }

  /**
   * Push inbound data into the readable side.
   * @param {Uint8Array} data
   */
  _pushData(data) {
    if (this.#readClosed || !this.#readController) return;
    try {
      this.#readController.enqueue(data);
    } catch {
      // Controller may already be closed; ignore.
    }
  }

  /**
   * Signal the remote closed this stream's readable side.
   */
  _closeRead() {
    if (this.#readClosed) return;
    this.#readClosed = true;
    try {
      this.#readController?.close();
    } catch {
      // Already closed.
    }
  }

  /**
   * Forcibly error both sides (used on transport close).
   * @param {Error} err
   */
  _destroy(err) {
    if (!this.#readClosed) {
      this.#readClosed = true;
      try {
        this.#readController?.error(err);
      } catch { /* ignore */ }
    }
    this.#writeClosed = true;
  }
}

// ── WebSocket transport ──────────────────────────────────────────────

/**
 * wsh transport over a single WebSocket with multiplexed virtual streams.
 *
 * Provides the same interface as WebTransportTransport so that upper
 * layers (session, client) work identically over either transport.
 */
export class WebSocketTransport extends WshTransport {
  /** @type {WebSocket} */
  #ws = null;

  /** @type {Map<number, VirtualStream>} Active virtual streams by ID. */
  #streams = new Map();

  /** @type {FrameDecoder} Decoder for inbound control messages on stream 0. */
  #decoder = new FrameDecoder();

  /** Next stream ID for locally-opened streams (odd = client, even = server). */
  #nextLocalId = 1;

  /** Resolvers for pending open-stream requests. */
  #openResolvers = new Map();

  /** Tracks whether we initiated the close. */
  #closedByUs = false;

  /**
   * Queue of raw inbound messages awaiting dispatch, plus a drain-in-progress
   * flag. Needed because some `WebSocket` implementations (notably Node's
   * `ws` package parsing several frames out of one TCP read) can fire
   * multiple synchronous `message` events within a single JS task, all
   * before any microtask gets to run. If we dispatched each message inline,
   * a handler that resolves a pending waiter (e.g. SERVER_HELLO resolving
   * the "wait for SERVER_HELLO or CHALLENGE" promise) wouldn't get a chance
   * to run its `await`'d continuation — which registers the *next* waiter
   * (e.g. for CHALLENGE) — before the next queued message arrives. That
   * continuation is a microtask; a same-task, no-yield dispatch loop starves
   * it, so the next message's waiter isn't registered yet and gets dropped.
   * Draining the queue with an `await Promise.resolve()` between each
   * message yields to the microtask queue after every dispatch, and since
   * microtasks run FIFO, any continuation queued by handling message N
   * (which runs first) completes before message N+1 is dispatched.
   * @type {ArrayBuffer[]}
   */
  #messageQueue = [];
  #draining = false;

  // ── Lifecycle ──────────────────────────────────────────────────────

  /** @override */
  async _doConnect(url) {
    this.#streams.clear();
    this.#decoder.reset();
    this.#nextLocalId = 1;
    this.#openResolvers.clear();
    this.#closedByUs = false;
    this.#messageQueue.length = 0;
    this.#draining = false;

    return new Promise((resolve, reject) => {
      // Normalize URL scheme: wsh:// → wss://, http:// → ws://.
      const wsUrl = url
        .replace(/^wsh:\/\//, 'wss://')
        .replace(/^https:\/\//, 'wss://')
        .replace(/^http:\/\//, 'ws://');

      const ws = new WebSocket(wsUrl);
      ws.binaryType = 'arraybuffer';
      this.#ws = ws;

      ws.addEventListener('open', () => resolve(), { once: true });

      ws.addEventListener('error', (ev) => {
        if (this.state === 'connecting') {
          reject(new Error('WebSocket connection failed'));
        } else {
          this._emitError(new Error('WebSocket error'));
        }
      });

      ws.addEventListener('close', (ev) => {
        this.#handleClose(ev.code, ev.reason);
      });

      ws.addEventListener('message', (ev) => {
        this.#messageQueue.push(ev.data);
        this.#drainMessageQueue();
      });
    });
  }

  /** @override */
  async _doClose() {
    this.#closedByUs = true;
    this.#destroyAllStreams(new Error('Transport closed'));
    this.#rejectAllOpens(new Error('Transport closed'));

    if (this.#ws) {
      try {
        this.#ws.close(1000, 'client close');
      } catch { /* may already be closed */ }
      this.#ws = null;
    }

    this.#decoder.reset();
  }

  /** @override */
  async _doSendControl(msg) {
    const cbor = frameEncode(msg);
    const frame = buildFrame(FRAME_CONTROL, 0, cbor);
    this.#send(frame);
  }

  /** @override */
  async _doOpenStream() {
    const id = this.#nextLocalId;
    this.#nextLocalId += 2; // odd IDs for client

    // Send open request.
    this.#send(buildFrame(FRAME_OPEN_STREAM, id));

    // Create the virtual stream.
    const stream = new VirtualStream(
      id,
      (sid, data) => this.#sendData(sid, data),
      (sid) => this.#sendCloseStream(sid),
    );
    this.#streams.set(id, stream);

    return {
      readable: stream.readable,
      writable: stream.writable,
      id,
    };
  }

  // ── Inbound message dispatch ───────────────────────────────────────

  /**
   * Drain `#messageQueue` one message at a time, yielding to the microtask
   * queue between each dispatch. See the `#messageQueue` field doc for why:
   * this is what lets a waiter registered by an earlier message's `await`
   * continuation (e.g. registering the CHALLENGE waiter after SERVER_HELLO
   * resolves) actually be in place before the next queued message arrives,
   * even when the underlying WebSocket implementation delivered several
   * messages synchronously in one task.
   */
  async #drainMessageQueue() {
    if (this.#draining) return;
    this.#draining = true;
    try {
      while (this.#messageQueue.length > 0) {
        const raw = this.#messageQueue.shift();
        this.#handleMessage(raw);
        await Promise.resolve();
      }
    } finally {
      this.#draining = false;
    }
  }

  /**
   * Handle a raw WebSocket message (ArrayBuffer).
   * @param {ArrayBuffer} raw
   */
  #handleMessage(raw) {
    if (typeof raw === 'string') {
      this._emitError(new Error('Received text WebSocket frame; expected binary'));
      return;
    }
    const data = new Uint8Array(raw);

    let frame;
    try {
      frame = parseFrame(data);
    } catch (err) {
      this._emitError(new Error(`Malformed frame: ${err.message}`));
      return;
    }

    switch (frame.type) {
      case FRAME_CONTROL:
        this.#handleControlFrame(frame.payload);
        break;
      case FRAME_DATA:
        this.#handleDataFrame(frame.streamId, frame.payload);
        break;
      case FRAME_OPEN_STREAM:
        this.#handleOpenStream(frame.streamId);
        break;
      case FRAME_CLOSE_STREAM:
        this.#handleCloseStream(frame.streamId);
        break;
      default:
        this._emitError(new Error(`Unknown frame type: 0x${frame.type.toString(16)}`));
    }
  }

  /**
   * Decode CBOR-framed control messages from stream 0.
   * @param {Uint8Array} payload
   */
  #handleControlFrame(payload) {
    let messages;
    try {
      messages = this.#decoder.feed(payload);
    } catch (err) {
      this._emitError(err);
      if (err instanceof FrameSizeError) {
        // Oversized claimed frame length — treat as a hostile or badly
        // broken peer and tear down the connection rather than continue.
        this.close().catch(() => {});
      }
      return;
    }
    for (const msg of messages) {
      this._emitControl(msg);
    }
  }

  /**
   * Route data to the appropriate virtual stream.
   * @param {number} streamId
   * @param {Uint8Array} payload
   */
  #handleDataFrame(streamId, payload) {
    const stream = this.#streams.get(streamId);
    if (!stream) {
      // Data for unknown stream; ignore silently (may arrive after close).
      return;
    }
    stream._pushData(payload);
  }

  /**
   * Server is opening a new stream (even IDs = server-initiated).
   * @param {number} streamId
   */
  #handleOpenStream(streamId) {
    if (this.#streams.has(streamId)) return; // already tracked

    const stream = new VirtualStream(
      streamId,
      (sid, data) => this.#sendData(sid, data),
      (sid) => this.#sendCloseStream(sid),
    );
    this.#streams.set(streamId, stream);

    this._emitStreamOpen({
      readable: stream.readable,
      writable: stream.writable,
      id: streamId,
    });
  }

  /**
   * Remote closed a stream.
   * @param {number} streamId
   */
  #handleCloseStream(streamId) {
    const stream = this.#streams.get(streamId);
    if (!stream) return;
    stream._closeRead();
    this.#streams.delete(streamId);
  }

  /**
   * WebSocket closed.
   * @param {number} code
   * @param {string} reason
   */
  #handleClose(code, reason) {
    const err = new Error(`WebSocket closed: ${code} ${reason}`);
    this.#destroyAllStreams(err);
    this.#rejectAllOpens(err);
    this.#decoder.reset();
    this.#ws = null;

    if (this.state !== 'closed') {
      this._setState('closed');
      if (!this.#closedByUs) {
        this._emitError(err);
      }
      this._emitClose();
    }
  }

  // ── Outbound helpers ───────────────────────────────────────────────

  /**
   * Send raw bytes over the WebSocket.
   * @param {Uint8Array} data
   */
  #send(data) {
    if (!this.#ws || this.#ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }
    this.#ws.send(data);
  }

  /**
   * Send a data frame for a virtual stream.
   * @param {number} streamId
   * @param {Uint8Array} payload
   */
  #sendData(streamId, payload) {
    this.#send(buildFrame(FRAME_DATA, streamId, payload));
  }

  /**
   * Send a close frame for a virtual stream.
   * @param {number} streamId
   */
  #sendCloseStream(streamId) {
    try {
      this.#send(buildFrame(FRAME_CLOSE_STREAM, streamId));
    } catch {
      // WebSocket may already be closed.
    }
  }

  // ── Cleanup ────────────────────────────────────────────────────────

  /**
   * Destroy all active virtual streams with an error.
   * @param {Error} err
   */
  #destroyAllStreams(err) {
    for (const stream of this.#streams.values()) {
      stream._destroy(err);
    }
    this.#streams.clear();
  }

  /**
   * Reject all pending open-stream promises.
   * @param {Error} err
   */
  #rejectAllOpens(err) {
    for (const { reject } of this.#openResolvers.values()) {
      reject(err);
    }
    this.#openResolvers.clear();
  }
}
