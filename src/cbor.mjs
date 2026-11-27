/**
 * CBOR codec with length-prefixed framing for wsh protocol.
 *
 * Wire format: [4-byte big-endian length][CBOR payload]
 * Uses a minimal CBOR encoder/decoder (subset: maps, arrays, strings, ints,
 * bytes, booleans, null, floats).
 */

// ── CBOR major types ──────────────────────────────────────────────────
const MT_UNSIGNED = 0;
const MT_NEGATIVE = 1;
const MT_BYTES    = 2;
const MT_TEXT     = 3;
const MT_ARRAY    = 4;
const MT_MAP      = 5;
const MT_TAG      = 6; // refused by the decoder: the protocol uses no tags
const MT_SIMPLE   = 7;

const SIMPLE_FALSE = 20;
const SIMPLE_TRUE  = 21;
const SIMPLE_NULL  = 22;
const FLOAT_16     = 25;
const FLOAT_32     = 26;
const FLOAT_64     = 27;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ── Encoder ───────────────────────────────────────────────────────────

/**
 * Encode a JS value into CBOR bytes.
 * @param {*} value
 * @returns {Uint8Array}
 */
export function cborEncode(value) {
  const parts = [];
  encodeValue(value, parts);
  return concat(parts);
}

function encodeValue(value, parts) {
  if (value === null || value === undefined) {
    parts.push(new Uint8Array([0xf6])); // null
    return;
  }
  if (value === true) {
    parts.push(new Uint8Array([0xf5]));
    return;
  }
  if (value === false) {
    parts.push(new Uint8Array([0xf4]));
    return;
  }
  if (typeof value === 'number') {
    // An integral double within the 64-bit ranges is an integer (exactly: BigInt past 2^53); anything else -- a fraction, NaN,
    // an infinity, -0, or an integer at or beyond 2^64 in magnitude -- is a float64, so every finite double round-trips.
    if (Number.isInteger(value) && !Object.is(value, -0) && value >= -TWO_64 && value < TWO_64) {
      if (Number.isSafeInteger(value)) {
        parts.push(value >= 0 ? encodeHead(MT_UNSIGNED, value) : encodeHead(MT_NEGATIVE, -1 - value));
      } else {
        parts.push(value >= 0 ? encodeHead64(MT_UNSIGNED, BigInt(value)) : encodeHead64(MT_NEGATIVE, -1n - BigInt(value)));
      }
    } else {
      // float64
      const buf = new ArrayBuffer(9);
      const view = new DataView(buf);
      view.setUint8(0, (MT_SIMPLE << 5) | FLOAT_64);
      view.setFloat64(1, value);
      parts.push(new Uint8Array(buf));
    }
    return;
  }
  if (typeof value === 'string') {
    const bytes = encoder.encode(value);
    parts.push(encodeHead(MT_TEXT, bytes.length));
    parts.push(bytes);
    return;
  }
  if (value instanceof Uint8Array) {
    parts.push(encodeHead(MT_BYTES, value.length));
    parts.push(value);
    return;
  }
  if (ArrayBuffer.isView(value)) {
    const bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    parts.push(encodeHead(MT_BYTES, bytes.length));
    parts.push(bytes);
    return;
  }
  if (Array.isArray(value)) {
    parts.push(encodeHead(MT_ARRAY, value.length));
    for (const item of value) encodeValue(item, parts);
    return;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value);
    parts.push(encodeHead(MT_MAP, keys.length));
    for (const key of keys) {
      encodeValue(key, parts);
      encodeValue(value[key], parts);
    }
    return;
  }
  throw new Error(`cborEncode: unsupported type ${typeof value}`);
}

const TWO_64 = 2 ** 64;

/** An 8-byte head for a value that is beyond the safe-integer range (exact, from a BigInt in 0 .. 2^64-1). */
function encodeHead64(majorType, big) {
  const buf = new ArrayBuffer(9);
  const view = new DataView(buf);
  view.setUint8(0, (majorType << 5) | 27);
  view.setBigUint64(1, big);
  return new Uint8Array(buf);
}

function encodeHead(majorType, value) {
  const mt = majorType << 5;
  if (value < 24) {
    return new Uint8Array([mt | value]);
  }
  if (value < 0x100) {
    return new Uint8Array([mt | 24, value]);
  }
  if (value < 0x10000) {
    const buf = new Uint8Array(3);
    buf[0] = mt | 25;
    buf[1] = (value >> 8) & 0xff;
    buf[2] = value & 0xff;
    return buf;
  }
  if (value < 0x100000000) {
    const buf = new Uint8Array(5);
    buf[0] = mt | 26;
    buf[1] = (value >> 24) & 0xff;
    buf[2] = (value >> 16) & 0xff;
    buf[3] = (value >> 8) & 0xff;
    buf[4] = value & 0xff;
    return buf;
  }
  // 8-byte (use DataView for 64-bit)
  const buf = new ArrayBuffer(9);
  const view = new DataView(buf);
  view.setUint8(0, mt | 27);
  // JS safe integer fits in 53 bits
  view.setUint32(1, Math.floor(value / 0x100000000));
  view.setUint32(5, value >>> 0);
  return new Uint8Array(buf);
}

// ── Decoder ───────────────────────────────────────────────────────────
//
// Strict (#317). The decoder accepts exactly one well-formed, canonical encoding of every value wsh sends, and nothing else:
//
//   - every declared length (string, bytes, array, map) must fit in what is left of the buffer, checked BEFORE anything is allocated or looped over
//     (an array needs one byte per element, a map two per pair), so a head that claims 2^32 elements fails at once;
//   - after the top-level item there must be no bytes (`cborDecodePrefix` is the explicit way to read one item out of a longer buffer);
//   - integers and lengths use the shortest form of their head; indefinite-length strings, arrays and maps are refused (RFC 8949 section 4.2.1);
//   - no tags, no simple values but false/true/null, no reserved additional-info values, no stray break;
//   - a map has text keys only, each once (so the order of keys is not meaningful: the JS encoder writes insertion order and the Rust encoder field order,
//     and neither is sorted, so sorted order is NOT required);
//   - text is valid UTF-8; nesting is at most MAX_DEPTH deep;
//   - floats of any width are read (the JS encoder writes float64 for every float, the Rust encoder the shortest form that is exact).
//
// One legacy exception, switched off with `legacyIndefiniteMap: false`: the TOP-LEVEL item may be an indefinite-length map. Every released wsh Rust encoder
// wrote its message envelope that way (serde's `flatten` made ciborium use an indefinite-length map), so a decoder that refused it would refuse every
// message a released Rust peer sends. The Rust encoder in this tree writes a definite-length map; the exception exists for peers that predate it.
// It covers the top-level map only: whatever it contains is held to every rule above. See COMPATIBILITY.md.

/** The most deeply nested items a message may have. The rpc channel's scanner (src/rpc.mjs) uses the same bound. */
export const CBOR_MAX_DEPTH = 128;

/**
 * A malformed input. `code` names the rule: `truncated`, `length-exceeds-buffer`, `trailing-bytes`, `non-shortest`, `indefinite-length`,
 * `unexpected-break`, `reserved-additional-info`, `duplicate-key`, `non-text-key`, `tag`, `simple-value`, `invalid-utf8`, `too-deep`.
 */
export class CborError extends Error {
  /** @param {string} code @param {string} message @param {number} [offset] byte offset the rule was broken at */
  constructor(code, message, offset) {
    super(`cborDecode: ${message}${offset === undefined ? '' : ` (at byte ${offset})`}`);
    this.name = 'CborError';
    this.code = code;
    this.offset = offset;
  }
}

const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * Decode CBOR bytes into a JS value. The whole buffer must be exactly one item; see the notes above for what is refused (a {@link CborError}).
 * @param {Uint8Array} data
 * @param {{ legacyIndefiniteMap?: boolean }} [options]
 * @returns {*}
 */
export function cborDecode(data, options) {
  const { value, end } = cborDecodePrefix(data, options);
  if (end !== data.length) throw new CborError('trailing-bytes', `${data.length - end} byte(s) after the value`, end);
  return value;
}

/**
 * Decode ONE item that starts at `offset` and say where it ended, leaving whatever follows to the caller. Every rule that applies to the item
 * applies; only the check that nothing follows it is left out. Nothing in wsh needs this today (the framing layer hands the decoder exactly one
 * item); it is the explicit API for a caller that reads a sequence out of one buffer.
 * @param {Uint8Array} data
 * @param {{ offset?: number, legacyIndefiniteMap?: boolean }} [options]
 * @returns {{ value: *, end: number }}
 */
export function cborDecodePrefix(data, { offset = 0, legacyIndefiniteMap = true } = {}) {
  if (!Number.isInteger(offset) || offset < 0 || offset > data.length) throw new RangeError(`cborDecodePrefix: offset must be an integer from 0 to ${data.length}, got ${String(offset)}`);
  // the item this call reads is its own top level, at whatever offset: the legacy indefinite map is accepted there too
  const state = { data, offset, legacy: legacyIndefiniteMap !== false, view: new DataView(data.buffer, data.byteOffset, data.byteLength) };
  const value = decodeItem(state, 0);
  return { value, end: state.offset };
}

/** The argument of a head whose additional info is `ai` (a number; exact up to 2^53, and anything larger is far past any buffer). */
function readArgument(state, ai, start) {
  if (ai < 24) return ai;
  const { data, view } = state;
  const size = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : 8;
  if (state.offset + size > data.length) throw new CborError('truncated', 'the head is cut off', start);
  let arg;
  if (size === 1) arg = data[state.offset];
  else if (size === 2) arg = view.getUint16(state.offset);
  else if (size === 4) arg = view.getUint32(state.offset);
  else {
    const hi = view.getUint32(state.offset);
    arg = hi * 0x100000000 + view.getUint32(state.offset + 4);
    if (hi === 0) throw new CborError('non-shortest', 'an 8-byte argument below 2^32', start);
  }
  state.offset += size;
  if ((size === 1 && arg < 24) || (size === 2 && arg < 0x100) || (size === 4 && arg < 0x10000)) throw new CborError('non-shortest', `${arg} is not in its shortest form`, start);
  return arg;
}

/** A length: the argument, and it must fit what is left (`perItem` bytes at least for each of the `arg` items) before anything is made for it. */
function readLength(state, ai, start, perItem) {
  const len = readArgument(state, ai, start);
  if (len * perItem > state.data.length - state.offset) throw new CborError('length-exceeds-buffer', `a length of ${len} with ${state.data.length - state.offset} byte(s) left`, start);
  return len;
}

function decodeItem(state, depth) {
  const { data } = state;
  if (depth > CBOR_MAX_DEPTH) throw new CborError('too-deep', `nested more than ${CBOR_MAX_DEPTH} deep`, state.offset);
  const start = state.offset;
  if (start >= data.length) throw new CborError('truncated', 'unexpected end', start);
  const initial = data[state.offset++];
  const mt = initial >> 5;
  const ai = initial & 0x1f;
  if (ai >= 28 && ai <= 30) throw new CborError('reserved-additional-info', `additional info ${ai} is reserved`, start);
  if (ai === 31) {
    if (mt === MT_UNSIGNED || mt === MT_NEGATIVE || mt === MT_TAG) throw new CborError('reserved-additional-info', `additional info 31 on major type ${mt}`, start);
    if (mt === MT_SIMPLE) throw new CborError('unexpected-break', 'a break outside an indefinite-length item', start);
    if (mt === MT_MAP && depth === 0 && state.legacy) return decodeLegacyIndefiniteMap(state, depth);
    throw new CborError('indefinite-length', 'indefinite-length items are not accepted', start);
  }

  switch (mt) {
    case MT_UNSIGNED: return readArgument(state, ai, start);
    case MT_NEGATIVE: {
      if (ai === 27) {
        // Past 2^53 `-1 - n` would round twice (n, then the sum): take the nearest double of the exact value once.
        readArgument(state, ai, start); // the shortest-form check; the exact value is read below
        return Number(-1n - state.view.getBigUint64(state.offset - 8));
      }
      return -1 - readArgument(state, ai, start);
    }
    case MT_BYTES: {
      const len = readLength(state, ai, start, 1);
      const bytes = data.slice(state.offset, state.offset + len);
      state.offset += len;
      return bytes;
    }
    case MT_TEXT: {
      const len = readLength(state, ai, start, 1);
      let text;
      try { text = strictUtf8.decode(data.subarray(state.offset, state.offset + len)); } catch { throw new CborError('invalid-utf8', 'a text string is not valid UTF-8', start); }
      state.offset += len;
      return text;
    }
    case MT_ARRAY: {
      const len = readLength(state, ai, start, 1);
      const arr = new Array(len);
      for (let i = 0; i < len; i++) arr[i] = decodeItem(state, depth + 1);
      return arr;
    }
    case MT_MAP: {
      const len = readLength(state, ai, start, 2);
      const obj = {};
      const seen = new Set();
      for (let i = 0; i < len; i++) addPair(state, depth, obj, seen);
      return obj;
    }
    case MT_TAG:
      throw new CborError('tag', 'tags are not used by the protocol', start);
    default: { // MT_SIMPLE
      if (ai === SIMPLE_FALSE) return false;
      if (ai === SIMPLE_TRUE) return true;
      if (ai === SIMPLE_NULL) return null;
      if (ai === FLOAT_16 || ai === FLOAT_32 || ai === FLOAT_64) {
        const size = ai === FLOAT_16 ? 2 : ai === FLOAT_32 ? 4 : 8;
        if (state.offset + size > data.length) throw new CborError('truncated', 'the float is cut off', start);
        const at = state.offset;
        state.offset += size;
        return ai === FLOAT_16 ? decodeFloat16(state.view.getUint16(at)) : ai === FLOAT_32 ? state.view.getFloat32(at) : state.view.getFloat64(at);
      }
      if (ai === 24 && state.offset >= data.length) throw new CborError('truncated', 'the simple value is cut off', start);
      throw new CborError('simple-value', `simple value ${ai === 24 ? data[state.offset] : ai} is not used by the protocol`, start);
    }
  }
}

/** One key and its value into `obj`: the key must be a text string and not seen in this map. */
function addPair(state, depth, obj, seen) {
  const keyAt = state.offset;
  if (keyAt < state.data.length && (state.data[keyAt] >> 5) !== MT_TEXT) throw new CborError('non-text-key', 'map keys are text strings', keyAt);
  const key = decodeItem(state, depth + 1);
  if (seen.has(key)) throw new CborError('duplicate-key', `the key ${JSON.stringify(key)} is in the map twice`, keyAt);
  seen.add(key);
  setOwn(obj, key, decodeItem(state, depth + 1));
}

/** The legacy exception: the top-level item is a map with no count and a break at its end (what a released wsh Rust encoder wrote). Its contents are strict. */
function decodeLegacyIndefiniteMap(state, depth) {
  const obj = {};
  const seen = new Set();
  for (;;) {
    if (state.offset >= state.data.length) throw new CborError('truncated', 'the indefinite-length map is not closed', state.offset);
    if (state.data[state.offset] === 0xff) { state.offset += 1; return obj; }
    addPair(state, depth, obj, seen);
  }
}

/**
 * Set a decoded map entry as plain own data. A key is untrusted wire input: `obj['__proto__'] = value` would run the
 * prototype setter and change what the object inherits, so that one key is defined as an own property instead. Every other key, `constructor` and
 * `prototype` included, is an ordinary assignment: it creates an own property and inherits no setter.
 */
function setOwn(obj, name, value) {
  if (name === '__proto__') Object.defineProperty(obj, name, { value, writable: true, enumerable: true, configurable: true });
  else obj[name] = value;
}

function decodeFloat16(half) {
  const sign = (half >> 15) & 1;
  const exp = (half >> 10) & 0x1f;
  const mant = half & 0x3ff;
  let val;
  if (exp === 0) {
    val = mant === 0 ? 0 : Math.pow(2, -14) * (mant / 1024);
  } else if (exp === 31) {
    val = mant === 0 ? Infinity : NaN;
  } else {
    val = Math.pow(2, exp - 15) * (1 + mant / 1024);
  }
  return sign ? -val : val;
}

// ── Length-prefixed framing ───────────────────────────────────────────

/**
 * Frame a CBOR-encoded message with a 4-byte big-endian length prefix.
 * @param {*} value - JS value to encode
 * @returns {Uint8Array} [4-byte length][CBOR payload]
 */
export function frameEncode(value) {
  const payload = cborEncode(value);
  const frame = new Uint8Array(4 + payload.length);
  const view = new DataView(frame.buffer);
  view.setUint32(0, payload.length);
  frame.set(payload, 4);
  return frame;
}

/**
 * Default cap on a single frame's claimed payload length (16 MiB).
 *
 * This channel only ever carries CBOR control-message metadata (session
 * lists, MCP tool results, recording-export/command-journal entries,
 * etc.) — bulk data such as file transfers and PTY output travel over
 * separate raw data streams with their own small chunking, not through
 * this decoder. 16 MiB is generous headroom for legitimate control
 * payloads while still bounding memory far below the 4 GiB a hostile or
 * buggy peer could otherwise claim via the 32-bit length prefix.
 */
export const DEFAULT_MAX_FRAME_SIZE = 16 * 1024 * 1024;

/**
 * Thrown by {@link FrameDecoder#feed} when a frame's claimed length
 * exceeds the decoder's configured maximum.
 */
export class FrameSizeError extends Error {
  constructor(len, maxFrameSize) {
    super(`Frame claims length ${len}, which exceeds the maximum of ${maxFrameSize} bytes`);
    this.name = 'FrameSizeError';
    this.len = len;
    this.maxFrameSize = maxFrameSize;
  }
}

/**
 * Streaming frame decoder. Feed it chunks and it yields complete messages.
 */
export class FrameDecoder {
  #buffer = new Uint8Array(0);
  #maxFrameSize;

  /**
   * @param {object} [opts]
   * @param {number} [opts.maxFrameSize] - Maximum allowed claimed frame
   *   length, in bytes. Frames claiming more than this are rejected as
   *   soon as their length prefix is parsed, before any payload bytes
   *   are buffered. Defaults to {@link DEFAULT_MAX_FRAME_SIZE}.
   */
  constructor({ maxFrameSize = DEFAULT_MAX_FRAME_SIZE } = {}) {
    this.#maxFrameSize = maxFrameSize;
  }

  /**
   * Feed bytes and return decoded messages.
   * @param {Uint8Array} chunk
   * @returns {Array} decoded JS values
   * @throws {FrameSizeError} if a frame's claimed length exceeds the
   *   configured maximum. The decoder's buffer is cleared before
   *   throwing; callers should treat this as fatal for the connection.
   */
  feed(chunk) {
    this.#buffer = appendBuffer(this.#buffer, chunk);
    const messages = [];
    while (this.#buffer.length >= 4) {
      const view = new DataView(this.#buffer.buffer, this.#buffer.byteOffset, 4);
      const len = view.getUint32(0);
      if (len > this.#maxFrameSize) {
        // Reject before accumulating toward the (possibly huge) claimed
        // length — do not wait for the payload to arrive.
        this.#buffer = new Uint8Array(0);
        const fatal = new FrameSizeError(len, this.#maxFrameSize);
        fatal.decoded = messages;
        throw fatal;
      }
      if (this.#buffer.length < 4 + len) break;
      const payload = this.#buffer.slice(4, 4 + len);
      this.#buffer = this.#buffer.slice(4 + len);
      try {
        messages.push(cborDecode(payload));
      } catch (err) {
        // The length prefix kept the stream in step: the bad frame is consumed and the frames after it stay buffered.
        // What was decoded before it travels with the error (`err.decoded`) so a caller that catches does not lose it.
        err.decoded = messages;
        throw err;
      }
    }
    return messages;
  }

  /**
   * Like {@link feed}, but never throws and never loses a message: every good frame of the chunk in order, one error per malformed frame (each a
   * {@link CborError}; the frames after it are still read), and `fatal` set (a {@link FrameSizeError}, after which the buffer is empty) when a frame claims
   * more than the maximum. Callers dispatch `messages`, report `errors`, and end the connection if `fatal`.
   * @param {Uint8Array} chunk
   * @returns {{ messages: Array, errors: Error[], fatal: FrameSizeError | null }}
   */
  feedAll(chunk) {
    const messages = []; const errors = [];
    let next = chunk;
    for (;;) {
      try {
        messages.push(...this.feed(next));
        return { messages, errors, fatal: null };
      } catch (err) {
        if (err?.decoded) messages.push(...err.decoded);
        if (err instanceof FrameSizeError) return { messages, errors, fatal: err };
        if (!(err instanceof CborError)) throw err;
        errors.push(err);
        next = new Uint8Array(0);
      }
    }
  }

  /** Reset internal buffer. */
  reset() {
    this.#buffer = new Uint8Array(0);
  }

  /** Bytes remaining in buffer. */
  get pending() {
    return this.#buffer.length;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────

function concat(arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function appendBuffer(existing, chunk) {
  if (existing.length === 0) return chunk;
  const result = new Uint8Array(existing.length + chunk.length);
  result.set(existing, 0);
  result.set(chunk, existing.length);
  return result;
}
