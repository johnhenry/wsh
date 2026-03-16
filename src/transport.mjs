/**
 * wsh transport layer — abstract base and WebTransport implementation.
 *
 * Control messages use length-prefixed CBOR framing (frameEncode / FrameDecoder).
 * Data streams carry raw bytes with no framing overhead.
 */

import { frameEncode, FrameDecoder, cborEncode } from './cbor.mjs';

// ── Transport states ─────────────────────────────────────────────────

const STATE_DISCONNECTED = 'disconnected';
const STATE_CONNECTING   = 'connecting';
const STATE_CONNECTED    = 'connected';
const STATE_CLOSED       = 'closed';

// ── Abstract base class ──────────────────────────────────────────────

/**
 * Abstract transport for the wsh protocol.
 *
 * Subclasses must implement:
 *   - _doConnect(url)
 *   - _doClose()
 *   - _doSendControl(msg)
 *   - _doOpenStream()
 */
export class WshTransport {
  #state = STATE_DISCONNECTED;

  /** @type {function(object): void} Callback for incoming control messages. */
  onControl = null;

  /** @type {function({readable: ReadableStream, writable: WritableStream, id: number}): void} */
  onStreamOpen = null;

  /** @type {function(): void} */
  onClose = null;

  /** @type {function(Error): void} */
  onError = null;

  /** Current transport state. */
  get state() {
    return this.#state;
  }

  /** @protected Update internal state. */
  _setState(s) {
    this.#state = s;
  }

  /**
   * Connect to a wsh server.
   * @param {string} url
   */
  async connect(url) {
    if (this.#state === STATE_CONNECTED || this.#state === STATE_CONNECTING) {
      throw new Error(`Transport already ${this.#state}`);
    }
    this.#state = STATE_CONNECTING;
    try {
      await this._doConnect(url);
      this.#state = STATE_CONNECTED;
    } catch (err) {
      this.#state = STATE_CLOSED;
      throw err;
    }
  }

  /**
   * Gracefully close the transport.
   */
  async close() {
    if (this.#state === STATE_CLOSED || this.#state === STATE_DISCONNECTED) return;
    this.#state = STATE_CLOSED;
    try {
      await this._doClose();
    } finally {
      this._emitClose();
    }
  }

  /**
   * Send a control message (CBOR-framed).
   * @param {object} msg - Plain object to CBOR-encode and frame.
   */
  async sendControl(msg) {
    if (this.#state !== STATE_CONNECTED) {
      throw new Error(`Cannot send: transport is ${this.#state}`);
    }
    await this._doSendControl(msg);
  }

  /**
   * Open a new bidirectional data stream.
   * @returns {Promise<{readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>, id: number}>}
   */
  async openStream() {
    if (this.#state !== STATE_CONNECTED) {
      throw new Error(`Cannot open stream: transport is ${this.#state}`);
    }
    return this._doOpenStream();
  }

  // ── Protected helpers ────────────────────────────────────────────────

  /** @protected Emit a control message to the callback. */
  _emitControl(msg) {
    try {
      this.onControl?.(msg);
    } catch (err) {
      console.error('[wsh:transport] onControl handler error:', err);
    }
  }

  /** @protected Emit a new server-initiated stream. */
  _emitStreamOpen(stream) {
    try {
      this.onStreamOpen?.(stream);
    } catch (err) {
      console.error('[wsh:transport] onStreamOpen handler error:', err);
    }
  }

  /** @protected Emit close event. */
  _emitClose() {
    try {
      this.onClose?.();
    } catch (err) {
      console.error('[wsh:transport] onClose handler error:', err);
    }
  }

  /** @protected Emit error event. */
  _emitError(err) {
    try {
      this.onError?.(err);
    } catch (e) {
      console.error('[wsh:transport] onError handler error:', e);
    }
  }

  // ── Abstract methods (must be overridden) ────────────────────────────

  /** @protected */
  async _doConnect(_url) {
    throw new Error('_doConnect not implemented');
  }

  /** @protected */
  async _doClose() {
    throw new Error('_doClose not implemented');
  }

  /** @protected */
  async _doSendControl(_msg) {
    throw new Error('_doSendControl not implemented');
  }

  /** @protected */
  async _doOpenStream() {
    throw new Error('_doOpenStream not implemented');
  }
}

// ── WebTransport implementation ──────────────────────────────────────

/**
 * wsh transport over the WebTransport API.
 *
 * - The first bidirectional stream opened becomes the control stream.
 * - Control messages are length-prefixed CBOR (frameEncode / FrameDecoder).
 * - Subsequent streams carry raw byte data (no framing).
 * - Server-initiated streams are surfaced via onStreamOpen.
 */
export class WebTransportTransport extends WshTransport {
  /** @type {WebTransport} */
  #wt = null;

  /** @type {WritableStreamDefaultWriter} Control stream writer. */
  #controlWriter = null;

  /** @type {AbortController} For cancelling background tasks. */
  #abort = new AbortController();

  /** @type {FrameDecoder} Decoder for inbound control messages. */
  #decoder = new FrameDecoder();

  /** Incremental stream ID counter (control stream = 0). */
  #nextStreamId = 1;

  /** @type {Promise<void>} Resolves when the control reader loop finishes. */
  #controlReaderDone = null;

  /** @type {Promise<void>} Resolves when the incoming-stream acceptor finishes. */
  #incomingAcceptorDone = null;

  // ── Lifecycle ──────────────────────────────────────────────────────

  /** @override */
  async _doConnect(url) {
    this.#abort = new AbortController();
    this.#decoder.reset();
    this.#nextStreamId = 1;

    // Create the WebTransport session.
    const wt = new WebTransport(url);
    this.#wt = wt;

    // Wait for the connection to be ready.
    await wt.ready;

    // Open the control stream (stream ID 0 by convention).
    const controlStream = await wt.createBidirectionalStream();
    this.#controlWriter = controlStream.writable.getWriter();

    // Start reading control messages in the background.
    this.#controlReaderDone = this.#readControlStream(controlStream.readable);

    // Start accepting server-initiated streams.
    this.#incomingAcceptorDone = this.#acceptIncomingStreams();

    // Monitor the session closing.
    this.#monitorClosed(wt);
  }

  /** @override */
  async _doClose() {
    this.#abort.abort();
    try {
      this.#controlWriter?.releaseLock?.();
    } catch { /* already released */ }
    try {
      this.#wt?.close();
    } catch { /* may already be closed */ }

    // Wait for background loops to wind down.
    await Promise.allSettled([
      this.#controlReaderDone,
      this.#incomingAcceptorDone,
    ]);

    this.#wt = null;
    this.#controlWriter = null;
    this.#decoder.reset();
  }

  /** @override */
  async _doSendControl(msg) {
    const frame = frameEncode(msg);
    await this.#controlWriter.write(frame);
  }

  /** @override */
  async _doOpenStream() {
    const bidi = await this.#wt.createBidirectionalStream();
    const id = this.#nextStreamId++;
    return {
      readable: bidi.readable,
      writable: bidi.writable,
      id,
    };
  }

  // ── Background loops ───────────────────────────────────────────────

  /**
   * Read control stream, decode CBOR frames, emit messages.
   * @param {ReadableStream<Uint8Array>} readable
   */
  async #readControlStream(readable) {
    const reader = readable.getReader();
    try {
      while (true) {
        if (this.#abort.signal.aborted) break;

        const { done, value } = await reader.read();
        if (done) break;

        const messages = this.#decoder.feed(value);
        for (const msg of messages) {
          this._emitControl(msg);
        }
      }
    } catch (err) {
      if (!this.#abort.signal.aborted) {
        this._emitError(new Error(`Control stream read error: ${err.message}`));
      }
    } finally {
      reader.releaseLock();
    }
  }

  /**
   * Accept server-initiated bidirectional streams and emit them.
   */
  async #acceptIncomingStreams() {
    const reader = this.#wt.incomingBidirectionalStreams.getReader();
    try {
      while (true) {
        if (this.#abort.signal.aborted) break;

        const { done, value: stream } = await reader.read();
        if (done) break;

        const id = this.#nextStreamId++;
        this._emitStreamOpen({
          readable: stream.readable,
          writable: stream.writable,
          id,
        });
      }
    } catch (err) {
      if (!this.#abort.signal.aborted) {
        this._emitError(new Error(`Incoming stream acceptor error: ${err.message}`));
      }
    } finally {
      reader.releaseLock();
    }
  }

  /**
   * Watch the WebTransport session for closure and propagate.
   * @param {WebTransport} wt
   */
  #monitorClosed(wt) {
    wt.closed
      .then(() => {
        if (this.state !== 'closed') {
          this._setState('closed');
          this._emitClose();
        }
      })
      .catch((err) => {
        if (this.state !== 'closed') {
          this._setState('closed');
          this._emitError(err);
          this._emitClose();
        }
      });
  }
}
