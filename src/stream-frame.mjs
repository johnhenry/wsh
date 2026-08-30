/**
 * Stream-mode chunk framing for wsh's opt-in end-to-end encryption layer
 * (see `session.mjs`'s `enableE2E`, which now accepts stream-backed
 * sessions -- this module supplies the framing wrapper that makes that
 * possible; the AEAD primitives themselves live in `e2e-frame.mjs` and
 * are reused unchanged).
 *
 * This is PR 1 of 3 in the stream-mode E2E rollout (wsh #22, follow-up
 * to the virtual-mode rollout in #19). See that issue for the full
 * design doc; the short version below is enough to work on this module.
 *
 * ── Why framing is needed at all ──────────────────────────────────────
 * Stream-mode sessions are raw WebTransport bidirectional byte streams
 * with no message boundaries (`transport.mjs`'s `openStream()`: "Data
 * streams carry raw bytes with no framing overhead"). Virtual-mode reuses
 * the control-message envelope (`EncryptedFrame`) to carry one sealed
 * frame per `SessionData` 1:1, but a byte stream has no such envelope --
 * a single `read()` may return a partial chunk, multiple chunks, or a
 * chunk split across two reads. This module's `ChunkAccumulator` restores
 * chunk boundaries on the read side; `encodeChunk` builds them on the
 * write side.
 *
 * ── Wire format ────────────────────────────────────────────────────────
 *
 *   [ 4-byte big-endian length prefix N ][ 12-byte nonce ][ N bytes: ciphertext + 16-byte GCM tag ]
 *
 * - N counts only the ciphertext+tag bytes that follow the nonce (the
 *   nonce itself is a fixed 12-byte wire constant, not counted -- avoids
 *   an off-by-12 footgun).
 * - The nonce is 12 bytes, clear (not secret -- same convention as
 *   virtual-mode's `EncryptedFrame.nonce`); it encodes the same
 *   8-byte-counter + 4-byte-role-tag scheme from `e2e-frame.mjs`, reused
 *   verbatim: a stream "chunk index" is exactly the same thing as
 *   virtual-mode's "message counter" (see `buildNonce`/`ROLE_TAGS`).
 * - The length field is NOT bound as AEAD additional authenticated data:
 *   there's no tampering scenario it prevents that the GCM tag doesn't
 *   already catch -- a corrupted length either fails decryption outright
 *   or misaligns the *next* chunk's boundary, but plaintext is never
 *   released without passing authentication either way.
 * - Chunk size: soft target ~16 KiB plaintext, hard cap 64 KiB (a `u32`
 *   length prefix has ample headroom above that). See `resolveCoalesceOptions`
 *   for how writes are batched up to (well below) that cap before sealing.
 *
 * ── Failure modes at stream end ───────────────────────────────────────
 * `ChunkAccumulator` distinguishes:
 *  1. Clean EOF -- buffer empty when `finish()` is called.
 *  2. Torn chunk -- partial bytes buffered (not enough for a complete
 *     chunk) when `finish()` is called -- throws `StreamTornChunkError`.
 *  3. Failed AEAD authentication on an otherwise-complete chunk -- this
 *     is *not* raised by this module (it has no key); callers use
 *     `StreamAuthenticationError` to report it after calling `openFrame`
 *     from `e2e-frame.mjs` (see `session.mjs`'s stream read path).
 * No partial-chunk plaintext is ever released in any case.
 *
 * ── Efficiency note ────────────────────────────────────────────────────
 * `ChunkAccumulator` uses a cursor-based internal buffer (append via an
 * amortized-doubling growable `Uint8Array`, consume via advancing a read
 * offset) rather than repeatedly `Uint8Array.slice()`-ing the whole
 * buffer on every `feed()` call, which would go quadratic under many
 * small `read()`s. The only per-chunk `slice()` calls are for the two
 * pieces (`nonce`, `ciphertext`) actually handed back to the caller.
 */

import { sealFrame } from './e2e-frame.mjs';

const LENGTH_PREFIX_BYTES = 4;
const NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;

/** Soft target plaintext chunk size (see module doc comment). */
export const CHUNK_SOFT_TARGET_BYTES = 16 * 1024;

/** Hard cap on plaintext chunk size; ciphertext+tag never exceeds this + 16. */
export const CHUNK_HARD_CAP_BYTES = 64 * 1024;

/**
 * Sanity bound on the wire length prefix, used only to fail fast on an
 * obviously-corrupt/malicious length field (e.g. a torn/garbled header)
 * rather than buffering unboundedly while waiting for a chunk that will
 * never complete. Generous headroom above `CHUNK_HARD_CAP_BYTES` so a
 * legitimate sender is never rejected.
 */
const MAX_WIRE_CIPHERTEXT_BYTES = CHUNK_HARD_CAP_BYTES + GCM_TAG_BYTES;

/**
 * Thrown by `ChunkAccumulator.finish()` when the internal buffer still
 * holds partial (incomplete) chunk bytes at stream EOF -- a truncated
 * stream, not a clean close. Distinct from `StreamAuthenticationError`
 * so callers can tell "the stream ended mid-chunk" apart from "a
 * complete chunk arrived but failed to authenticate".
 */
export class StreamTornChunkError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StreamTornChunkError';
  }
}

/**
 * Thrown by callers (see `session.mjs`'s stream read path) when a
 * complete, well-framed chunk fails AEAD authentication in
 * `openFrame()` (tampered ciphertext, wrong key, or session_id
 * mismatch). Distinct from `StreamTornChunkError` -- this module itself
 * never throws it, since `ChunkAccumulator` has no key and cannot
 * authenticate anything.
 */
export class StreamAuthenticationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StreamAuthenticationError';
  }
}

/**
 * Encode one sealed chunk for the wire: `[len][nonce][ciphertext]`.
 *
 * @param {Uint8Array} nonce - exactly 12 bytes
 * @param {Uint8Array} ciphertext - ciphertext + GCM tag, as returned by `sealFrame`
 * @returns {Uint8Array}
 */
export function encodeChunk(nonce, ciphertext) {
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_BYTES) {
    throw new Error(`stream-frame: nonce must be a ${NONCE_BYTES}-byte Uint8Array`);
  }
  if (!(ciphertext instanceof Uint8Array)) {
    throw new Error('stream-frame: ciphertext must be a Uint8Array');
  }
  const out = new Uint8Array(LENGTH_PREFIX_BYTES + NONCE_BYTES + ciphertext.length);
  new DataView(out.buffer).setUint32(0, ciphertext.length, false);
  out.set(nonce, LENGTH_PREFIX_BYTES);
  out.set(ciphertext, LENGTH_PREFIX_BYTES + NONCE_BYTES);
  return out;
}

/**
 * Reassembles a raw byte stream into complete `{nonce, ciphertext}`
 * chunks. See the module doc comment for the wire format and the
 * efficiency note on the internal buffer strategy.
 */
export class ChunkAccumulator {
  /** @type {Uint8Array} */
  #buf = new Uint8Array(0);
  /** @type {number} Read cursor -- bytes before this offset are already consumed. */
  #start = 0;
  /** @type {number} Write cursor -- bytes before this offset are valid buffered data. */
  #end = 0;

  /**
   * Feed newly-read bytes in and pull out every complete chunk now
   * available. Any trailing partial chunk stays buffered for the next
   * `feed()` call.
   *
   * @param {Uint8Array} bytes
   * @returns {Array<{nonce: Uint8Array, ciphertext: Uint8Array}>}
   */
  feed(bytes) {
    if (bytes && bytes.length > 0) {
      this.#append(bytes);
    }
    const chunks = [];
    for (;;) {
      const chunk = this.#tryParseOne();
      if (chunk === null) break;
      chunks.push(chunk);
    }
    // Once fully drained, reset cursors so the buffer doesn't retain a
    // large-but-empty backing array indefinitely.
    if (this.#start === this.#end) {
      this.#start = 0;
      this.#end = 0;
    }
    return chunks;
  }

  /**
   * Call at clean stream EOF. Throws `StreamTornChunkError` if partial
   * chunk bytes are still buffered (a truncated stream); otherwise a
   * no-op.
   */
  finish() {
    const remaining = this.#end - this.#start;
    if (remaining > 0) {
      throw new StreamTornChunkError(
        `stream-frame: stream ended with ${remaining} torn (incomplete) chunk bytes buffered`
      );
    }
  }

  /** @private */
  #append(bytes) {
    const liveLength = this.#end - this.#start;
    const needed = liveLength + bytes.length;
    if (needed > this.#buf.length - this.#start) {
      // Grow (and compact away already-consumed prefix bytes) with
      // amortized doubling, so repeated small feed() calls stay linear
      // overall rather than re-copying the whole live region every time.
      const newCapacity = Math.max(needed, this.#buf.length * 2, 4096);
      const newBuf = new Uint8Array(newCapacity);
      newBuf.set(this.#buf.subarray(this.#start, this.#end), 0);
      this.#buf = newBuf;
      this.#end = liveLength;
      this.#start = 0;
    }
    this.#buf.set(bytes, this.#end);
    this.#end += bytes.length;
  }

  /** @private */
  #tryParseOne() {
    const available = this.#end - this.#start;
    if (available < LENGTH_PREFIX_BYTES + NONCE_BYTES) return null;
    const headerView = new DataView(this.#buf.buffer, this.#buf.byteOffset + this.#start, LENGTH_PREFIX_BYTES);
    const n = headerView.getUint32(0, false);
    if (n > MAX_WIRE_CIPHERTEXT_BYTES) {
      throw new StreamTornChunkError(
        `stream-frame: chunk length ${n} exceeds max ${MAX_WIRE_CIPHERTEXT_BYTES} -- corrupt or malicious framing`
      );
    }
    const total = LENGTH_PREFIX_BYTES + NONCE_BYTES + n;
    if (available < total) return null; // wait for more bytes
    const nonceStart = this.#start + LENGTH_PREFIX_BYTES;
    const ciphertextStart = nonceStart + NONCE_BYTES;
    const nonce = this.#buf.slice(nonceStart, ciphertextStart);
    const ciphertext = this.#buf.slice(ciphertextStart, this.#start + total);
    this.#start += total;
    return { nonce, ciphertext };
  }
}

// ── Write coalescing ─────────────────────────────────────────────────
//
// Purely local, sender-side batching of small consecutive write() calls
// into one sealed chunk -- NOT a wire protocol change (the receiver has
// no idea how many writes got merged, see wsh #22's design-doc update).
// Smart defaults derive from session `type` (already known at
// `openSession()` time); callers can override via `enableE2E(key, {
// coalesce })` or fully disable via `coalesce: false`.

/**
 * Default coalescing profiles by session kind.
 *  - `pty` (interactive): latency-first -- flush on a short timer or a
 *    small byte threshold, whichever fires first. This isn't "batching
 *    keystrokes"; it mainly catches writes issued in the same event-loop
 *    tick (multi-byte UTF-8, escape sequences, paste bursts) -- a single
 *    keystroke still goes out almost immediately.
 *  - `exec` (bulk): throughput-first -- longer timer and the full 16 KiB
 *    soft target from the chunk-size design above.
 * @type {Record<'pty'|'exec', {maxBytes: number, maxDelayMs: number}>}
 */
export const DEFAULT_COALESCE_PROFILES = Object.freeze({
  pty: Object.freeze({ maxBytes: 4 * 1024, maxDelayMs: 6 }),
  exec: Object.freeze({ maxBytes: CHUNK_SOFT_TARGET_BYTES, maxDelayMs: 30 }),
});

/**
 * Resolve the effective coalescing config for a session.
 *
 * @param {'pty'|'exec'} kind
 * @param {false|{maxBytes?: number, maxDelayMs?: number}|undefined} override
 * @returns {{maxBytes: number, maxDelayMs: number}|null} `null` means "coalescing disabled -- seal every write immediately"
 */
export function resolveCoalesceOptions(kind, override) {
  if (override === false) return null;
  const base = DEFAULT_COALESCE_PROFILES[kind] || DEFAULT_COALESCE_PROFILES.exec;
  if (override && typeof override === 'object') {
    const maxBytes = Number.isFinite(override.maxBytes) && override.maxBytes > 0 ? override.maxBytes : base.maxBytes;
    const maxDelayMs = Number.isFinite(override.maxDelayMs) && override.maxDelayMs >= 0 ? override.maxDelayMs : base.maxDelayMs;
    return { maxBytes, maxDelayMs };
  }
  return { ...base };
}

/**
 * Batches consecutive `write()` calls and flushes them as one chunk once
 * `maxBytes` is buffered or `maxDelayMs` has elapsed since the first
 * buffered byte of the current batch, whichever comes first.
 *
 * `write()` resolves once bytes are queued, not once they're actually
 * flushed -- coalescing is local batching, so "queued" is the caller-
 * visible unit of success (matching wsh #22's resolved design). Flush
 * errors surface on the promise returned by the *next* `write()`/
 * `flush()` call that observes the same underlying flush chain.
 */
export class WriteCoalescer {
  #maxBytes;
  #maxDelayMs;
  #onFlush;
  #pending = [];
  #pendingLength = 0;
  #timer = null;
  #chain = Promise.resolve();

  /**
   * @param {{maxBytes: number, maxDelayMs: number}} options
   * @param {function(Uint8Array): Promise<void>} onFlush - called with the merged buffered bytes
   */
  constructor({ maxBytes, maxDelayMs }, onFlush) {
    if (!(maxBytes > 0)) {
      throw new Error('stream-frame: WriteCoalescer requires a positive maxBytes');
    }
    if (!(maxDelayMs >= 0)) {
      throw new Error('stream-frame: WriteCoalescer requires a non-negative maxDelayMs');
    }
    if (typeof onFlush !== 'function') {
      throw new Error('stream-frame: WriteCoalescer requires an onFlush callback');
    }
    this.#maxBytes = maxBytes;
    this.#maxDelayMs = maxDelayMs;
    this.#onFlush = onFlush;
  }

  /**
   * Buffer bytes for later coalesced sealing.
   * @param {Uint8Array} bytes
   * @returns {Promise<void>}
   */
  write(bytes) {
    this.#pending.push(bytes);
    this.#pendingLength += bytes.length;
    if (this.#pendingLength >= this.#maxBytes) {
      return this.flush();
    }
    if (this.#timer === null) {
      this.#timer = setTimeout(() => {
        this.#timer = null;
        this.flush().catch(() => {
          // Errors are observed via #chain by the next write()/flush()
          // caller; swallow here so an unobserved timer-driven flush
          // doesn't produce an unhandled rejection.
        });
      }, this.#maxDelayMs);
      if (typeof this.#timer.unref === 'function') this.#timer.unref();
    }
    return this.#chain;
  }

  /**
   * Force-flush any currently-buffered bytes immediately (used on
   * session close and by the byte/timer thresholds above).
   * @returns {Promise<void>}
   */
  flush() {
    if (this.#timer !== null) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
    if (this.#pending.length === 0) {
      return this.#chain;
    }
    const merged = concatBytes(this.#pending, this.#pendingLength);
    this.#pending = [];
    this.#pendingLength = 0;
    this.#chain = this.#chain.then(() => this.#onFlush(merged));
    return this.#chain;
  }
}

/** @private */
function concatBytes(parts, totalLength) {
  if (parts.length === 1) return parts[0];
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// Re-exported for convenience so callers that only need stream-mode
// sealing don't have to import from two modules.
export { sealFrame };
