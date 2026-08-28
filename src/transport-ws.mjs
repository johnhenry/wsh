/**
 * wsh transport — WebSocket fallback with multiplexed virtual streams.
 *
 * Wire format: QMux (draft-ietf-quic-qmux-02) framing directly over the
 * WebSocket's binary message stream -- see qmux.mjs for the wire codec
 * and qmux-connection.mjs for the stream state machine and flow control
 * this module wires into the DOM Streams API (ReadableStream/
 * WritableStream) the rest of wsh expects from a transport.
 *
 * Stream 0 (the first client-initiated bidirectional QMux stream) is
 * always opened on connect and carries CBOR control messages using the
 * same length-prefixed framing as before (frameEncode/FrameDecoder) --
 * QMux streams are raw byte pipes with no message-boundary framing of
 * their own, so that inner framing is still needed to know where one
 * control message ends and the next begins. Every other stream (opened
 * via openStream(), or peer-initiated for reverse-mode/server-pushed
 * channels) carries a session's raw data with no extra framing, exactly
 * as before.
 */

import { frameEncode, FrameDecoder, FrameSizeError } from './cbor.mjs';
import { WshTransport, dispatchSerially, SerialQueue } from './transport.mjs';
import { QMuxConnection } from './qmux-connection.mjs';

// ── Frame type constants (kept for backward-compat callers) ──────────
//
// The old hand-rolled 5-byte mux's frame-type byte values. wsh now
// speaks QMux instead (see the file doc comment) -- this export is kept
// so nothing importing WS_FRAME_TYPE breaks, but nothing in this module
// produces or consumes these values anymore. Mirrors QMux's own frame
// type space where it lines up (STREAM/RESET_STREAM), for whatever
// documentation value that has; DATA/OPEN_STREAM/CLOSE_STREAM have no
// QMux equivalent (QMux streams are implicitly opened by reference, and
// "data" is just STREAM frame payload).
export const WS_FRAME_TYPE = Object.freeze({
  CONTROL: 0x01,
  DATA: 0x02,
  OPEN_STREAM: 0x03,
  CLOSE_STREAM: 0x04,
});

// ── DOM Streams adapter over a QMuxStream ───────────────────────────

/**
 * Wraps a qmux-connection.mjs `QMuxStream` (a push/pull data API with
 * no DOM dependency) in the ReadableStream/WritableStream pair the rest
 * of wsh expects from a transport stream.
 */
class QMuxStreamAdapter {
  /** @type {number} */
  id;

  /** @type {ReadableStream<Uint8Array>} */
  readable;

  /** @type {WritableStream<Uint8Array>} */
  writable;

  /**
   * @param {import('./qmux-connection.mjs').QMuxConnection} qs
   */
  constructor(qs) {
    this.id = qs.id;

    this.readable = new ReadableStream({
      start: (controller) => {
        qs.onData = (data) => {
          try { controller.enqueue(data); } catch { /* controller already closed/errored */ }
        };
        qs.onEnd = () => {
          try { controller.close(); } catch { /* already closed */ }
        };
        qs.onReset = (errorCode) => {
          try { controller.error(new Error(`Stream ${qs.id} was reset by peer (error code ${errorCode})`)); } catch { /* already settled */ }
        };
        qs.onDestroy = (err) => {
          try { controller.error(err); } catch { /* already settled */ }
        };
      },
      cancel: () => {
        qs.stopSending();
      },
    });

    this.writable = new WritableStream({
      write: async (chunk) => {
        const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        await qs.write(bytes);
      },
      close: async () => {
        await qs.close();
      },
      abort: () => {
        qs.reset();
      },
    });
  }
}

// ── WebSocket transport ──────────────────────────────────────────────

/**
 * wsh transport over a single WebSocket with QMux-multiplexed virtual
 * streams.
 *
 * Provides the same interface as WebTransportTransport so that upper
 * layers (session, client) work identically over either transport.
 */
export class WebSocketTransport extends WshTransport {
  /** @type {WebSocket} */
  #ws = null;

  /** @type {import('./qmux-connection.mjs').QMuxConnection} */
  #qmux = null;

  /** @type {import('./qmux-connection.mjs').QMuxConnection|null} The control channel (always QMux stream 0). */
  #controlStream = null;

  /** @type {FrameDecoder} Decoder for CBOR control messages carried inside the control stream's byte pipe. */
  #decoder = new FrameDecoder();

  /** Tracks whether we initiated the close. */
  #closedByUs = false;

  /**
   * Serializes dispatch of inbound control-stream bytes. Needed because
   * a single WebSocket 'message' event can decode into QMux STREAM
   * frames for the control stream whose data callback fires
   * synchronously and could otherwise interleave with — or race —
   * whatever microtask continuation the *previous* chunk's dispatch
   * triggers. See `SerialQueue`'s doc comment in transport.mjs.
   * @type {SerialQueue}
   */
  #inbox = new SerialQueue((raw) => this.#handleControlBytes(raw));

  // ── Lifecycle ──────────────────────────────────────────────────────

  /** @override */
  async _doConnect(url) {
    this.#decoder.reset();
    this.#closedByUs = false;
    this.#inbox.clear();
    this.#controlStream = null;

    return new Promise((resolve, reject) => {
      // Normalize URL scheme: wsh:// → wss://, http:// → ws://.
      const wsUrl = url
        .replace(/^wsh:\/\//, 'wss://')
        .replace(/^https:\/\//, 'wss://')
        .replace(/^http:\/\//, 'ws://');

      const ws = new WebSocket(wsUrl);
      ws.binaryType = 'arraybuffer';
      this.#ws = ws;

      const qmux = new QMuxConnection({
        isClient: true,
        send: (bytes) => this.#send(bytes),
      });
      this.#qmux = qmux;

      qmux.onStreamOpen = (qs) => {
        const adapter = new QMuxStreamAdapter(qs);
        this._emitStreamOpen({ readable: adapter.readable, writable: adapter.writable, id: qs.id });
      };
      qmux.onError = (err) => this._emitError(err);
      qmux.onClose = (errorCode, reason) => {
        this.#handleClose(errorCode, reason || 'peer sent CONNECTION_CLOSE');
      };

      ws.addEventListener('open', async () => {
        try {
          qmux.sendHandshake();
          // The control channel is always the first client-initiated
          // QMux stream (ID 0) -- opened here, once, up front.
          const controlQs = await qmux.openStream();
          controlQs.onData = (data) => this.#inbox.push(data);
          controlQs.onReset = (errorCode) => {
            this._emitError(new Error(`control stream reset by peer (error code ${errorCode})`));
          };
          this.#controlStream = controlQs;
          resolve();
        } catch (err) {
          reject(err);
        }
      }, { once: true });

      ws.addEventListener('error', () => {
        if (this.state === 'connecting') {
          reject(new Error('WebSocket connection failed'));
        } else {
          this._emitError(new Error('WebSocket error'));
        }
      });

      ws.addEventListener('close', (ev) => {
        this.#handleClose(null, `WebSocket closed: ${ev.code} ${ev.reason}`);
      });

      ws.addEventListener('message', (ev) => {
        if (typeof ev.data === 'string') {
          this._emitError(new Error('Received text WebSocket frame; expected binary'));
          return;
        }
        qmux.receiveBytes(new Uint8Array(ev.data));
      });
    });
  }

  /** @override */
  async _doClose() {
    this.#closedByUs = true;
    // Tell the peer we're closing gracefully, then locally tear down our
    // own stream objects -- without this, any reader still waiting on a
    // stream's readable side would hang forever, since nothing else
    // errors or closes it once the peer can no longer respond.
    this.#qmux?.close();
    this.#qmux?.destroy(new Error('Transport closed'));

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
    if (!this.#controlStream) {
      throw new Error('Control stream is not open');
    }
    // Length-prefixed CBOR inside the raw QMux byte stream -- QMux
    // streams carry bytes, not pre-delimited messages, same reason the
    // old hand-rolled mux's control channel needed this framing too.
    const cbor = frameEncode(msg);
    await this.#controlStream.write(cbor);
  }

  /** @override */
  async _doOpenStream() {
    const qs = await this.#qmux.openStream();
    const adapter = new QMuxStreamAdapter(qs);
    return { readable: adapter.readable, writable: adapter.writable, id: qs.id };
  }

  // ── Inbound control-stream dispatch ─────────────────────────────────

  /**
   * Decode CBOR-framed control messages from the control stream's byte
   * pipe. A single chunk can decode into more than one protocol message
   * (the CBOR decoder is stateful/streaming), so dispatch uses
   * `dispatchSerially` — see its doc comment for why a plain for-loop
   * here would be unsafe.
   * @param {Uint8Array} payload
   */
  async #handleControlBytes(payload) {
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
    await dispatchSerially(messages, (msg) => this._emitControl(msg));
  }

  /**
   * Connection ended, either because the peer sent CONNECTION_CLOSE
   * (QMux-graceful) or the underlying WebSocket itself closed (abrupt --
   * QMux's own terms for a termination with no prior CONNECTION_CLOSE).
   * @param {number|null} errorCode - QMux/QUIC error code, if this came from a CONNECTION_CLOSE frame
   * @param {string} reason
   */
  #handleClose(errorCode, reason) {
    if (this.state === 'closed') return;
    const err = new Error(reason);
    this.#qmux?.destroy(err);
    this._setState('closed');
    if (!this.#closedByUs) {
      this._emitError(err);
    }
    this._emitClose();
  }

  // ── Outbound helper ──────────────────────────────────────────────

  /**
   * Send raw QMux record bytes over the WebSocket. Passed to
   * QMuxConnection as its `send` callback.
   * @param {Uint8Array} data
   */
  #send(data) {
    if (!this.#ws || this.#ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }
    this.#ws.send(data);
  }
}
