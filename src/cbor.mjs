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
const MT_TAG      = 6; // unused but recognized
const MT_SIMPLE   = 7;

const SIMPLE_FALSE = 20;
const SIMPLE_TRUE  = 21;
const SIMPLE_NULL  = 22;
const FLOAT_16     = 25;
const FLOAT_32     = 26;
const FLOAT_64     = 27;
const BREAK        = 31;

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
    if (Number.isInteger(value)) {
      if (value >= 0) {
        parts.push(encodeHead(MT_UNSIGNED, value));
      } else {
        parts.push(encodeHead(MT_NEGATIVE, -1 - value));
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

/**
 * Decode CBOR bytes into a JS value.
 * @param {Uint8Array} data
 * @returns {*}
 */
export function cborDecode(data) {
  const state = { data, offset: 0 };
  const result = decodeValue(state);
  return result;
}

function decodeValue(state) {
  if (state.offset >= state.data.length) throw new Error('cborDecode: unexpected end');
  const byte = state.data[state.offset++];
  const mt = byte >> 5;
  const ai = byte & 0x1f;

  switch (mt) {
    case MT_UNSIGNED: return decodeUint(state, ai);
    case MT_NEGATIVE: return -1 - decodeUint(state, ai);
    case MT_BYTES: {
      if (ai === BREAK) return decodeIndefiniteBytes(state);
      const len = decodeUint(state, ai);
      const bytes = state.data.slice(state.offset, state.offset + len);
      state.offset += len;
      return bytes;
    }
    case MT_TEXT: {
      if (ai === BREAK) return decodeIndefiniteText(state);
      const len = decodeUint(state, ai);
      const text = decoder.decode(state.data.subarray(state.offset, state.offset + len));
      state.offset += len;
      return text;
    }
    case MT_ARRAY: {
      if (ai === BREAK) return decodeIndefiniteArray(state);
      const len = decodeUint(state, ai);
      const arr = new Array(len);
      for (let i = 0; i < len; i++) arr[i] = decodeValue(state);
      return arr;
    }
    case MT_MAP: {
      if (ai === BREAK) return decodeIndefiniteMap(state);
      const len = decodeUint(state, ai);
      const obj = {};
      for (let i = 0; i < len; i++) {
        const key = decodeValue(state);
        obj[key] = decodeValue(state);
      }
      return obj;
    }
    case MT_TAG: {
      // skip tag number, return inner value
      decodeUint(state, ai);
      return decodeValue(state);
    }
    case MT_SIMPLE: {
      if (ai === SIMPLE_FALSE) return false;
      if (ai === SIMPLE_TRUE) return true;
      if (ai === SIMPLE_NULL) return null;
      if (ai === FLOAT_16) {
        // half-precision float
        const half = (state.data[state.offset] << 8) | state.data[state.offset + 1];
        state.offset += 2;
        return decodeFloat16(half);
      }
      if (ai === FLOAT_32) {
        const view = new DataView(state.data.buffer, state.data.byteOffset + state.offset, 4);
        state.offset += 4;
        return view.getFloat32(0);
      }
      if (ai === FLOAT_64) {
        const view = new DataView(state.data.buffer, state.data.byteOffset + state.offset, 8);
        state.offset += 8;
        return view.getFloat64(0);
      }
      if (ai === BREAK) return undefined; // break code
      return ai; // simple value
    }
    default:
      throw new Error(`cborDecode: unknown major type ${mt}`);
  }
}

function decodeIndefiniteBytes(state) {
  const chunks = [];
  while (!consumeBreak(state)) {
    const chunk = decodeValue(state);
    if (!(chunk instanceof Uint8Array)) {
      throw new Error('cborDecode: invalid chunk in indefinite byte string');
    }
    chunks.push(chunk);
  }
  return concat(chunks);
}

function decodeIndefiniteText(state) {
  let text = '';
  while (!consumeBreak(state)) {
    const chunk = decodeValue(state);
    if (typeof chunk !== 'string') {
      throw new Error('cborDecode: invalid chunk in indefinite text string');
    }
    text += chunk;
  }
  return text;
}

function decodeIndefiniteArray(state) {
  const arr = [];
  while (!consumeBreak(state)) {
    arr.push(decodeValue(state));
  }
  return arr;
}

function decodeIndefiniteMap(state) {
  const obj = {};
  while (!consumeBreak(state)) {
    const key = decodeValue(state);
    obj[key] = decodeValue(state);
  }
  return obj;
}

function consumeBreak(state) {
  if (state.offset >= state.data.length) {
    throw new Error('cborDecode: unexpected end in indefinite value');
  }
  if (state.data[state.offset] === 0xff) {
    state.offset += 1;
    return true;
  }
  return false;
}

function decodeUint(state, ai) {
  if (ai < 24) return ai;
  if (ai === 24) return state.data[state.offset++];
  if (ai === 25) {
    const val = (state.data[state.offset] << 8) | state.data[state.offset + 1];
    state.offset += 2;
    return val;
  }
  if (ai === 26) {
    const view = new DataView(state.data.buffer, state.data.byteOffset + state.offset, 4);
    state.offset += 4;
    return view.getUint32(0);
  }
  if (ai === 27) {
    const view = new DataView(state.data.buffer, state.data.byteOffset + state.offset, 8);
    state.offset += 8;
    const hi = view.getUint32(0);
    const lo = view.getUint32(4);
    return hi * 0x100000000 + lo;
  }
  throw new Error(`cborDecode: invalid additional info ${ai}`);
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
 * Streaming frame decoder. Feed it chunks and it yields complete messages.
 */
export class FrameDecoder {
  #buffer = new Uint8Array(0);

  /**
   * Feed bytes and return decoded messages.
   * @param {Uint8Array} chunk
   * @returns {Array} decoded JS values
   */
  feed(chunk) {
    this.#buffer = appendBuffer(this.#buffer, chunk);
    const messages = [];
    while (this.#buffer.length >= 4) {
      const view = new DataView(this.#buffer.buffer, this.#buffer.byteOffset, 4);
      const len = view.getUint32(0);
      if (this.#buffer.length < 4 + len) break;
      const payload = this.#buffer.slice(4, 4 + len);
      this.#buffer = this.#buffer.slice(4 + len);
      messages.push(cborDecode(payload));
    }
    return messages;
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
