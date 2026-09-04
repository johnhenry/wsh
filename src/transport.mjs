/**
 * wsh transport layer — abstract base and WebTransport implementation.
 *
 * Control messages use length-prefixed CBOR framing (frameEncode / FrameDecoder).
 * Data streams carry raw bytes with no framing overhead.
 */

import { frameEncode, FrameDecoder, cborEncode, FrameSizeError } from './cbor.mjs';

// ── Serial dispatch (shared by both transports) ───────────────────────
//
// A push-based transport can hand this library more than one decoded
// protocol message at once — either because several arrived in a single
// underlying read (e.g. multiple WebSocket `message` events fired
// synchronously from one TCP read, or one CBOR decoder call returning
// several frames from one already-received chunk) — with no guaranteed
// yield to the microtask queue between them. That matters because a
// message handler can be `async`: it resolves a pending waiter
// synchronously, but the code that runs *after* that resolution (e.g.
// registering the *next* waiter) only runs as a microtask continuation.
// Dispatching message N+1 before that continuation gets a turn means
// N+1 arrives with state that N's handling hasn't finished setting up
// yet — most visibly, a dropped CHALLENGE that arrived batched with
// SERVER_HELLO (see CHANGELOG 0.3.0). `dispatchSerially` and
// `SerialQueue` both fix this the same way: yield to the microtask
// queue after every single dispatch, so FIFO microtask ordering
// guarantees any continuation queued by message N runs before message
// N+1 is handled.

/**
 * Invoke `handler` once per item in `items`, awaiting each call before
 * starting the next. Use this for a *fixed* batch that's already fully
 * available (e.g. everything a single decoder.feed() call returned) —
 * see `SerialQueue` for items that arrive incrementally over time via a
 * push callback.
 *
 * `handler` may be sync or async — either way, `await handler(item)`
 * yields to the microtask queue at least once before the next item is
 * dispatched (awaiting any value does, even a plain `undefined`), and if
 * `handler` is itself async, this also waits for its *own* internal work
 * (including any nested dispatchSerially/SerialQueue use) to fully
 * settle first. That matters when a handler for item N does async work
 * that must complete before N+1 is safe to dispatch — a fire-and-forget
 * (non-awaited) handler call wouldn't provide that guarantee, only a
 * same-tick yield.
 * @param {Iterable<*>} items
 * @param {(item: *) => (void | Promise<void>)} handler
 */
export async function dispatchSerially(items, handler) {
  for (const item of items) {
    await handler(item);
  }
}

/**
 * A queue drained one item at a time, awaiting each dispatch before
 * starting the next (see `dispatchSerially`'s doc comment for exactly
 * what that guarantees for sync vs. async handlers). Use this where
 * items arrive incrementally over time via a push callback (e.g. a
 * transport's raw `message` event) rather than as one fixed,
 * already-available batch (see `dispatchSerially` for that case).
 * `push()` is safe to call at any time, including while a previous
 * drain is still in progress — the same drain loop just picks up the
 * newly-pushed item in its next iteration.
 */
export class SerialQueue {
  #items = [];
  #handler;
  #draining = false;

  /** @param {(item: *) => (void | Promise<void>)} handler */
  constructor(handler) {
    this.#handler = handler;
  }

  /** @param {*} item */
  push(item) {
    this.#items.push(item);
    this.#drain();
  }

  /** Discard any queued-but-not-yet-dispatched items (e.g. on reconnect). */
  clear() {
    this.#items.length = 0;
  }

  async #drain() {
    if (this.#draining) return;
    this.#draining = true;
    try {
      while (this.#items.length > 0) {
        const item = this.#items.shift();
        await this.#handler(item);
      }
    } finally {
      this.#draining = false;
    }
  }
}

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
 *   - _doConnect(url, options)
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
   * @param {object} [options] - Transport-specific connect options.
   *   Ignored by transports that have none; `WebTransportTransport`
   *   forwards them to the `WebTransport` constructor (see its docs for
   *   `serverCertificateHashes`).
   */
  async connect(url, options) {
    if (this.#state === STATE_CONNECTED || this.#state === STATE_CONNECTING) {
      throw new Error(`Transport already ${this.#state}`);
    }
    this.#state = STATE_CONNECTING;
    try {
      await this._doConnect(url, options);
      this.#state = STATE_CONNECTED;
    } catch (err) {
      // A connect can fail *after* acquiring a real resource -- an open
      // WebSocket whose QMux handshake then threw, a WebTransport whose
      // session came up but whose control stream did not. Tear that down
      // here, because a later `close()` cannot: it treats the `closed`
      // state this line sets as "already torn down" and returns without
      // calling `_doClose()`, so the socket would stay open for the life
      // of the page. Every rung of WshClient's transport ladder that
      // fails hits this path.
      this.#state = STATE_CLOSED;
      try {
        await this._doClose();
      } catch {
        // Best effort: the connect error is the one worth reporting, and
        // tearing down a half-built transport can fail for its own
        // uninteresting reasons.
      }
      // Deliberately no `_emitClose()`: a transport that never reached
      // `connected` never announced itself, callers have not attached
      // their handlers yet, and a close event for a connection that never
      // opened is a lie.
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
  async _doConnect(_url, _options) {
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

// ── WebTransport options ─────────────────────────────────────────────

/** Digest length in bytes, keyed by the algorithm name WebTransport accepts. */
const CERT_HASH_LENGTHS = Object.freeze({ 'sha-256': 32 });

/**
 * Decode one `serverCertificateHashes` value into the `BufferSource` the
 * WebTransport constructor requires.
 *
 * Accepts, in addition to a `BufferSource` passed straight through:
 *
 * - **Hex**, with or without separators — this is what
 *   `openssl x509 -fingerprint -sha256` prints
 *   (`SHA256 Fingerprint=AB:CD:...`), and pasting that string in is the
 *   single most likely thing a caller will try.
 * - **Base64** or **base64url**, which is how the same digest usually
 *   arrives over a QR code or a pairing payload.
 *
 * Throws on anything else, and on a digest whose decoded length is wrong
 * for the algorithm. Failing here is the whole point: a wrong hash
 * otherwise surfaces as an opaque `WebTransportError` from `wt.ready`
 * with no indication that the *input* was malformed rather than the
 * certificate mismatched.
 *
 * @param {*} value
 * @param {string} algorithm - Lower-cased algorithm name (e.g. 'sha-256').
 * @returns {Uint8Array}
 */
export function parseCertificateHash(value, algorithm = 'sha-256') {
  const expected = CERT_HASH_LENGTHS[algorithm];
  let bytes;

  if (value instanceof Uint8Array) {
    bytes = value;
  } else if (ArrayBuffer.isView(value)) {
    bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  } else if (value instanceof ArrayBuffer) {
    bytes = new Uint8Array(value);
  } else if (typeof value === 'string') {
    bytes = decodeHashString(value);
  } else {
    throw new TypeError(
      'serverCertificateHashes value must be a BufferSource or a hex/base64 string, ' +
      `got ${value === null ? 'null' : typeof value}`
    );
  }

  if (expected !== undefined && bytes.length !== expected) {
    throw new RangeError(
      `serverCertificateHashes value for "${algorithm}" must be ${expected} bytes, got ${bytes.length}`
    );
  }
  return bytes;
}

/**
 * @param {string} str
 * @returns {Uint8Array}
 */
function decodeHashString(str) {
  // Strip the separators OpenSSL and friends emit, plus any surrounding
  // whitespace: "SHA256 Fingerprint=" style output is colon-separated,
  // and hand-copied values often carry spaces or dashes.
  const compact = str.trim().replace(/^[^=]*fingerprint[^=]*=\s*/i, '');
  const hexish = compact.replace(/[\s:-]/g, '');

  if (/^[0-9a-fA-F]+$/.test(hexish) && hexish.length % 2 === 0) {
    const out = new Uint8Array(hexish.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = Number.parseInt(hexish.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  // Not hex — try base64 / base64url.
  const b64 = compact.replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) {
    throw new TypeError(
      `serverCertificateHashes value is neither hex nor base64: ${JSON.stringify(str)}`
    );
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Normalise a caller-supplied options bag into a `WebTransportOptions`
 * dictionary, or `undefined` when there is nothing to pass.
 *
 * Only `serverCertificateHashes` is transformed; every other key is
 * forwarded verbatim, so options the platform gains later
 * (`congestionControl`, `allowPooling`, `requireUnreliable`, the
 * `anticipatedConcurrentIncoming*Streams` hints, …) work without a
 * change here.
 *
 * @param {object} [options]
 * @returns {object|undefined}
 */
export function normalizeWebTransportOptions(options) {
  if (!options) return undefined;
  const keys = Object.keys(options).filter((k) => options[k] !== undefined);
  if (keys.length === 0) return undefined;

  const out = {};
  for (const key of keys) out[key] = options[key];

  if (out.serverCertificateHashes !== undefined) {
    const list = out.serverCertificateHashes;
    if (!Array.isArray(list)) {
      throw new TypeError('serverCertificateHashes must be an array');
    }
    if (list.length === 0) {
      throw new TypeError(
        'serverCertificateHashes must not be empty -- omit the option entirely to use the ' +
        'normal certificate-authority path'
      );
    }
    out.serverCertificateHashes = list.map((entry) => {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry) ||
          ArrayBuffer.isView(entry) || entry instanceof ArrayBuffer) {
        // A bare digest is a natural thing to write; accept it rather
        // than making the caller wrap every value in { algorithm, value }.
        return { algorithm: 'sha-256', value: parseCertificateHash(entry, 'sha-256') };
      }
      const algorithm = String(entry.algorithm ?? 'sha-256').toLowerCase();
      return { algorithm, value: parseCertificateHash(entry.value, algorithm) };
    });
  }

  return out;
}

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

  /** @type {object|undefined} Default WebTransport options for every connect. */
  #options;

  /**
   * @param {object} [options] - Forwarded to the `WebTransport`
   *   constructor. Most usefully `serverCertificateHashes`, which lets
   *   page JavaScript pin a specific short-lived self-signed certificate
   *   by digest instead of requiring one a certificate authority signed:
   *
   *   ```js
   *   new WebTransportTransport({
   *     serverCertificateHashes: [
   *       // hex (with or without colons), base64, or raw bytes
   *       'a1:b2:c3:...',
   *     ],
   *   });
   *   ```
   *
   *   The web platform imposes the rules, not wsh: the URL must be
   *   `https:`, the connection is HTTP/3 only (there is no fallback to
   *   HTTP/2 for a pinned certificate), the certificate must use an
   *   ECDSA P-256 key and be valid for no more than 14 days, and
   *   connection pooling is disabled. Options passed to `connect()`
   *   override these per call.
   */
  constructor(options) {
    super();
    this.#options = options;
  }

  // ── Lifecycle ──────────────────────────────────────────────────────

  /** @override */
  async _doConnect(url, options) {
    this.#abort = new AbortController();
    this.#decoder.reset();
    this.#nextStreamId = 1;

    // Create the WebTransport session. Pass the options dictionary only
    // when there is something in it: `new WebTransport(url)` and
    // `new WebTransport(url, {})` are equivalent per spec, but an empty
    // second argument is noise in a stack trace and in any engine that
    // predates the dictionary.
    const wtOptions = normalizeWebTransportOptions(
      (this.#options || options) && { ...this.#options, ...options }
    );
    const wt = wtOptions ? new WebTransport(url, wtOptions) : new WebTransport(url);
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

        // A QUIC stream has no per-message framing at the transport layer,
        // so a single read() can return bytes for several messages at
        // once (e.g. SERVER_HELLO immediately followed by CHALLENGE).
        // dispatchSerially yields between each — see its doc comment for
        // why that matters.
        const messages = this.#decoder.feed(value);
        await dispatchSerially(messages, (msg) => this._emitControl(msg));
      }
    } catch (err) {
      if (!this.#abort.signal.aborted) {
        this._emitError(new Error(`Control stream read error: ${err.message}`));
        if (err instanceof FrameSizeError) {
          // Oversized claimed frame length — treat as a hostile or badly
          // broken peer and tear down the connection rather than continue.
          this.close().catch(() => {});
        }
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
