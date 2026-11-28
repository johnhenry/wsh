/**
 * CBOR codec with length-prefixed framing for wsh protocol.
 *
 * Wire format: [4-byte big-endian length][CBOR payload]
 * Uses a minimal CBOR encoder/decoder (subset: maps, arrays, strings, ints,
 * bytes, booleans, null, floats).
 *
 * The encoder writes the deterministic form of RFC 8949 section 4.2.1 and nothing else: map keys sorted length-first then bytewise, the shortest
 * integer, the shortest float that reads back exactly (NaN is f97e00, -0 is f98000). The Rust encoder (crates/wsh-core/src/cbor_canon.rs) writes the
 * same bytes for the same value, and the golden vectors and the differential test hold them to it (#325).
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
  if (typeof value === 'bigint') {
    // exact, in the 64-bit ranges CBOR integers cover: 0 .. 2^64-1 and -2^64 .. -1
    if (value >= 0n) {
      if (value >= 2n ** 64n) throw new RangeError(`cborEncode: ${value} does not fit a CBOR integer (0 .. 2^64-1, -2^64 .. -1)`);
      parts.push(value <= BigInt(Number.MAX_SAFE_INTEGER) ? encodeHead(MT_UNSIGNED, Number(value)) : encodeHead64(MT_UNSIGNED, value));
    } else {
      if (value < -(2n ** 64n)) throw new RangeError(`cborEncode: ${value} does not fit a CBOR integer (0 .. 2^64-1, -2^64 .. -1)`);
      const n = -1n - value;
      parts.push(n <= BigInt(Number.MAX_SAFE_INTEGER) ? encodeHead(MT_NEGATIVE, Number(n)) : encodeHead64(MT_NEGATIVE, n));
    }
    return;
  }
  if (typeof value === 'number') {
    // An integral double within the 64-bit ranges is an integer (exactly: BigInt past 2^53); anything else -- a fraction, NaN,
    // an infinity, -0, or an integer at or beyond 2^64 in magnitude -- is a float, in the shortest width that reads back exactly.
    if (Number.isInteger(value) && !Object.is(value, -0) && value >= -TWO_64 && value < TWO_64) {
      if (Number.isSafeInteger(value)) {
        parts.push(value >= 0 ? encodeHead(MT_UNSIGNED, value) : encodeHead(MT_NEGATIVE, -1 - value));
      } else {
        parts.push(value >= 0 ? encodeHead64(MT_UNSIGNED, BigInt(value)) : encodeHead64(MT_NEGATIVE, -1n - BigInt(value)));
      }
    } else {
      parts.push(encodeFloat(value));
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
    if (keys.length === 1) {
      encodeValue(keys[0], parts);
      encodeValue(value[keys[0]], parts);
      return;
    }
    // RFC 8949 4.2.1: sorted by the bytes of the encoded key, shorter first, then bytewise. A text key's head grows with its length, so that is
    // the UTF-8 length first and then the UTF-8 bytes (not JS's UTF-16 order, and not the engine's order for integer-like names).
    const entries = keys.map((key) => { const bytes = []; encodeValue(key, bytes); return { key, bytes: concat(bytes) }; });
    entries.sort((a, b) => compareKeyBytes(a.bytes, b.bytes));
    for (let i = 1; i < entries.length; i++) {
      if (compareKeyBytes(entries[i - 1].bytes, entries[i].bytes) === 0) throw new Error(`cborEncode: the keys ${JSON.stringify(entries[i - 1].key)} and ${JSON.stringify(entries[i].key)} encode to the same text`);
    }
    for (const { key, bytes } of entries) {
      parts.push(bytes);
      encodeValue(value[key], parts);
    }
    return;
  }
  throw new Error(`cborEncode: unsupported type ${typeof value}`);
}

const TWO_64 = 2 ** 64;

/** Encoded keys in canonical order: shorter first, then bytewise (RFC 8949 4.2.1). */
function compareKeyBytes(a, b) {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

const f64view = new DataView(new ArrayBuffer(8));

/**
 * The IEEE half-precision bits of `v` if `v` is exactly a half-precision value (or +-0, +-Infinity), else -1. NaN is not handled here
 * (it has one canonical form, f97e00).
 */
function halfBitsExact(v) {
  if (v === 0) return Object.is(v, -0) ? 0x8000 : 0;
  if (v === Infinity) return 0x7c00;
  if (v === -Infinity) return 0xfc00;
  const sign = v < 0 ? 0x8000 : 0;
  const a = Math.abs(v);
  if (a > 65504) return -1;
  if (a < 2 ** -14) { // subnormal: a multiple of 2^-24 below 2^-14
    const m = a * 2 ** 24;
    return Number.isInteger(m) ? sign | m : -1;
  }
  f64view.setFloat64(0, a);
  const hi = f64view.getUint32(0);
  if ((hi & 0x3ff) !== 0 || f64view.getUint32(4) !== 0) return -1; // more than 10 mantissa bits
  const exp = ((hi >>> 20) & 0x7ff) - 1023; // -14 .. 15
  return sign | ((exp + 15) << 10) | ((hi >>> 10) & 0x3ff);
}

/** A float in the shortest width that reads back exactly: half, then single, then double; one NaN. */
function encodeFloat(value) {
  if (Number.isNaN(value)) return new Uint8Array([0xf9, 0x7e, 0x00]);
  const half = halfBitsExact(value);
  if (half >= 0) return new Uint8Array([0xf9, half >> 8, half & 0xff]);
  if (Math.fround(value) === value) {
    const buf = new ArrayBuffer(5);
    const view = new DataView(buf);
    view.setUint8(0, (MT_SIMPLE << 5) | FLOAT_32);
    view.setFloat32(1, value);
    return new Uint8Array(buf);
  }
  const buf = new ArrayBuffer(9);
  const view = new DataView(buf);
  view.setUint8(0, (MT_SIMPLE << 5) | FLOAT_64);
  view.setFloat64(1, value);
  return new Uint8Array(buf);
}

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
// Strict (#317, #325). Two kinds of rule:
//
// ALWAYS (a malformed item, whoever sent it):
//   - every declared length (string, bytes, array, map) must fit in what is left of the buffer, checked BEFORE anything is allocated or looped over
//     (an array needs one byte per element, a map two per pair), so a head that claims 2^32 elements fails at once;
//   - after the top-level item there must be no bytes (`cborDecodePrefix` is the explicit way to read one item out of a longer buffer);
//   - integers and lengths use the shortest form of their head; indefinite-length strings, arrays and maps are refused (RFC 8949 section 4.2.1);
//   - no tags, no simple values but false/true/null, no reserved additional-info values, no stray break;
//   - a map has text keys only, each once;
//   - text is valid UTF-8; nesting is at most MAX_DEPTH deep and an item holds at most `maxContainers` arrays and maps (CBOR_MAX_CONTAINERS).
//
// CANONICAL (RFC 8949 4.2.1: the one byte string the encoders write for a value). Released peers did not write it, so while the compatibility
// window is open these are accepted by default and refused with `legacyNonCanonical: false`:
//   - map keys sorted length-first, then bytewise (`non-canonical-key-order`); the released JS encoder wrote insertion order, the released Rust encoder field order;
//   - floats in the shortest width that reads back exactly, one NaN (f97e00): so no f32/f64 that fits a narrower width, no NaN payload or sign
//     (`non-canonical-float`); the released JS encoder wrote every float as float64. -0 is f98000, allowed, and stays -0;
//   - an integer above 2^53 is not a JS number: `unsafeIntegers` says what to do ('round': the released behaviour and the default of the window, the
//     nearest double; 'bigint': a BigInt, exact; 'refuse': `unsafe-integer`, which is what `strict` selects).
//
// One more legacy exception, switched off with `legacyIndefiniteMap: false`: the TOP-LEVEL item (offset 0) may be an indefinite-length map. Every released
// wsh Rust encoder wrote its message envelope that way (serde's `flatten` made ciborium use an indefinite-length map). It covers the top-level map
// only: whatever it contains is held to every rule above.
//
// `strict: true` is the shorthand for every legacy option off. It is what the tests and the differential run, and what becomes the default when the
// window closes (COMPATIBILITY.md rule 7: when and how). An explicit option wins over `strict`.
//
// Not distinguished, by design: `f93c00` (1.0) and `01` both read as the JS number 1. A JS number has no integer/float split, and message fields are
// plain numbers; the Rust typed decoder keeps the split (an integer field refuses a float). The JS encoder never writes an integral number as a float.

/** The most deeply nested items a message may have. The rpc channel's scanner (src/rpc.mjs) uses the same bound. */
export const CBOR_MAX_DEPTH = 128;

/** The most arrays and maps (counting the top-level item) one decoded item may hold. A 4 MiB frame of empty arrays is 4 million of them (about 160 MiB of heap). */
export const CBOR_MAX_CONTAINERS = 1_000_000;

/**
 * A malformed input. `code` names the rule: `truncated`, `length-exceeds-buffer`, `trailing-bytes`, `non-shortest`, `indefinite-length`,
 * `unexpected-break`, `reserved-additional-info`, `duplicate-key`, `non-text-key`, `tag`, `simple-value`, `invalid-utf8`, `too-deep`,
 * `too-many-containers`, and the canonical rules `non-canonical-key-order`, `non-canonical-float`, `unsafe-integer`.
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
 * @typedef {object} DecodeOptions
 * Every option is checked: a wrong type or value throws a TypeError (`strict: 1` is not "strict, roughly"), and an absent one (undefined) takes its default.
 * @property {boolean} [strict] every legacy option off (the default of a later minor; see COMPATIBILITY.md rule 7)
 * @property {boolean} [legacyIndefiniteMap] accept an indefinite-length map as the top-level item at offset 0 (default true)
 * @property {boolean} [legacyNonCanonical] accept key order, float width and NaN forms the released encoders wrote (default true)
 * @property {'round'|'bigint'|'refuse'} [unsafeIntegers] an integer beyond +-(2^53-1): 'round' (default), 'bigint', or 'refuse' (what `strict` selects)
 * @property {number} [maxContainers] arrays and maps one item may hold (default CBOR_MAX_CONTAINERS)
 */

/** An option that is a boolean or absent: anything else is a TypeError, not a silent default (`strict: 1` was "not strict", a security setting that failed open). */
function booleanOption(options, name) {
  const v = options[name];
  if (v !== undefined && typeof v !== 'boolean') throw new TypeError(`cborDecode: ${name} must be a boolean, got ${typeof v === 'symbol' ? 'a symbol' : typeof v === 'bigint' ? `${v}n` : String(v)}`);
  return v;
}

/** Check and resolve the decode options. A wrong type or value throws a TypeError (see {@link DecodeOptions}); an absent option takes its default. */
function resolveOptions(options = {}, offset = 0) {
  if (options === null || typeof options !== 'object') throw new TypeError(`cborDecode: options must be an object, got ${options === null ? 'null' : typeof options}`);
  const strict = booleanOption(options, 'strict') === true;
  const legacyIndefiniteMap = booleanOption(options, 'legacyIndefiniteMap');
  const legacyNonCanonical = booleanOption(options, 'legacyNonCanonical');
  const unsafe = options.unsafeIntegers === undefined ? (strict ? 'refuse' : 'round') : options.unsafeIntegers;
  if (unsafe !== 'round' && unsafe !== 'bigint' && unsafe !== 'refuse') throw new TypeError(`cborDecode: unsafeIntegers must be 'round', 'bigint' or 'refuse', got ${String(unsafe)}`);
  const maxContainers = options.maxContainers === undefined ? CBOR_MAX_CONTAINERS : options.maxContainers;
  if (!Number.isSafeInteger(maxContainers) || maxContainers < 1) throw new TypeError(`cborDecode: maxContainers must be a positive integer, got ${typeof maxContainers === 'bigint' ? `${maxContainers}n` : String(maxContainers)}`);
  return {
    legacyTop: (legacyIndefiniteMap ?? !strict) !== false && offset === 0,
    canonical: (legacyNonCanonical ?? !strict) === false,
    unsafe,
    maxContainers,
  };
}

/**
 * Decode CBOR bytes into a JS value. The whole buffer must be exactly one item; see the notes above for what is refused (a {@link CborError}).
 * @param {Uint8Array} data
 * @param {DecodeOptions} [options]
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
 * item); it is the explicit API for a caller that reads a sequence out of one buffer. The legacy indefinite-length map is the top-level item of a
 * message, so it is read at offset 0 only: after another item it is an `indefinite-length` error. The container count starts again for each call.
 * @param {Uint8Array} data
 * @param {DecodeOptions & { offset?: number }} [options]
 * @returns {{ value: *, end: number }}
 */
export function cborDecodePrefix(data, options = {}) {
  const offset = options.offset === undefined ? 0 : options.offset;
  if (!Number.isInteger(offset) || offset < 0 || offset > data.length) throw new RangeError(`cborDecodePrefix: offset must be an integer from 0 to ${data.length}, got ${String(offset)}`);
  const state = { data, offset, ...resolveOptions(options, offset), containers: 0, view: new DataView(data.buffer, data.byteOffset, data.byteLength) };
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

/** An integer head of major type 0 or 1: a number while it is a safe integer, and past that what `unsafeIntegers` says. */
function readInteger(state, ai, start, negative) {
  const arg = readArgument(state, ai, start);
  // value is arg (major 0) or -1 - arg (major 1); it is unsafe beyond +-(2^53-1), i.e. arg > MAX_SAFE (major 0) or arg >= MAX_SAFE (major 1)
  if (ai !== 27 || (negative ? arg < Number.MAX_SAFE_INTEGER : arg <= Number.MAX_SAFE_INTEGER)) return negative ? -1 - arg : arg;
  const big = state.view.getBigUint64(state.offset - 8);
  if (state.unsafe === 'bigint') return negative ? -1n - big : big;
  if (state.unsafe === 'refuse') throw new CborError('unsafe-integer', `${negative ? -1n - big : big} is beyond the safe integer range of a JS number`, start);
  // 'round': -1 - n would round twice (n, then the sum): take the nearest double of the exact value once
  return negative ? Number(-1n - big) : Number(big);
}

/** Count one more array or map against the cap (before anything is made for it). */
function countContainer(state, start) {
  if (++state.containers > state.maxContainers) throw new CborError('too-many-containers', `more than ${state.maxContainers} arrays and maps in one item`, start);
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
    if (mt === MT_MAP && depth === 0 && state.legacyTop) { countContainer(state, start); return decodeLegacyIndefiniteMap(state, depth); }
    throw new CborError('indefinite-length', 'indefinite-length items are not accepted', start);
  }

  switch (mt) {
    case MT_UNSIGNED: return readInteger(state, ai, start, false);
    case MT_NEGATIVE: return readInteger(state, ai, start, true);
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
      countContainer(state, start);
      const arr = [];
      for (let i = 0; i < len; i++) arr.push(decodeItem(state, depth + 1));
      return arr;
    }
    case MT_MAP: {
      const len = readLength(state, ai, start, 2);
      countContainer(state, start);
      const obj = {};
      const keys = { seen: new Set(), prevAt: -1, prevEnd: -1 };
      for (let i = 0; i < len; i++) addPair(state, depth, obj, keys);
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
        const value = ai === FLOAT_16 ? decodeFloat16(state.view.getUint16(at)) : ai === FLOAT_32 ? state.view.getFloat32(at) : state.view.getFloat64(at);
        if (state.canonical && !isCanonicalFloat(ai, state.view, at, value)) throw new CborError('non-canonical-float', `${ai === FLOAT_16 ? 'a float16' : ai === FLOAT_32 ? 'a float32' : 'a float64'} that is not in its shortest form`, start);
        return value;
      }
      if (ai === 24 && state.offset >= data.length) throw new CborError('truncated', 'the simple value is cut off', start);
      throw new CborError('simple-value', `simple value ${ai === 24 ? data[state.offset] : ai} is not used by the protocol`, start);
    }
  }
}

/** Is the float at `at` (of width `ai`, read as `value`) the shortest form of its value? NaN has one form (f97e00). */
function isCanonicalFloat(ai, view, at, value) {
  if (ai === FLOAT_16) return !Number.isNaN(value) || view.getUint16(at) === 0x7e00;
  if (Number.isNaN(value)) return false;
  if (ai === FLOAT_32) return halfBitsExact(value) < 0;
  return !Object.is(Math.fround(value), value);
}

/** Compare data[aAt, aEnd) with data[bAt, bEnd): shorter first, then bytewise (RFC 8949 4.2.1). */
function compareRanges(data, aAt, aEnd, bAt, bEnd) {
  const la = aEnd - aAt;
  const lb = bEnd - bAt;
  if (la !== lb) return la - lb;
  for (let i = 0; i < la; i++) {
    const d = data[aAt + i] - data[bAt + i];
    if (d !== 0) return d;
  }
  return 0;
}

/** One key and its value into `obj`: the key must be a text string, not seen in this map, and (canonical) after the one before it. */
function addPair(state, depth, obj, keys) {
  const keyAt = state.offset;
  if (keyAt < state.data.length && (state.data[keyAt] >> 5) !== MT_TEXT) throw new CborError('non-text-key', 'map keys are text strings', keyAt);
  const key = decodeItem(state, depth + 1);
  if (keys.seen.has(key)) throw new CborError('duplicate-key', `the key ${JSON.stringify(key)} is in the map twice`, keyAt);
  keys.seen.add(key);
  if (state.canonical) {
    if (keys.prevAt >= 0 && compareRanges(state.data, keys.prevAt, keys.prevEnd, keyAt, state.offset) > 0) throw new CborError('non-canonical-key-order', `the key ${JSON.stringify(key)} is out of order (shorter keys first, then bytewise)`, keyAt);
    keys.prevAt = keyAt;
    keys.prevEnd = state.offset;
  }
  setOwn(obj, key, decodeItem(state, depth + 1));
}

/** The legacy exception: the top-level item is a map with no count and a break at its end (what a released wsh Rust encoder wrote). Its contents are strict. */
function decodeLegacyIndefiniteMap(state, depth) {
  const obj = {};
  const keys = { seen: new Set(), prevAt: -1, prevEnd: -1 };
  for (;;) {
    if (state.offset >= state.data.length) throw new CborError('truncated', 'the indefinite-length map is not closed', state.offset);
    if (state.data[state.offset] === 0xff) { state.offset += 1; return obj; }
    addPair(state, depth, obj, keys);
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
  #decodeOptions;

  /**
   * @param {object} [opts]
   * @param {number} [opts.maxFrameSize] - Maximum allowed claimed frame
   *   length, in bytes. Frames claiming more than this are rejected as
   *   soon as their length prefix is parsed, before any payload bytes
   *   are buffered. Defaults to {@link DEFAULT_MAX_FRAME_SIZE}.
   * @param {boolean} [opts.strict] and the other {@link DecodeOptions} (`legacyIndefiniteMap`, `legacyNonCanonical`, `unsafeIntegers`,
   *   `maxContainers`) are passed to {@link cborDecode} for every frame. The default is the compatibility window of COMPATIBILITY.md rule 7.
   */
  constructor({ maxFrameSize = DEFAULT_MAX_FRAME_SIZE, ...decodeOptions } = {}) {
    this.#maxFrameSize = maxFrameSize;
    resolveOptions(decodeOptions); // a bad option is the constructor's TypeError, not the first frame's
    this.#decodeOptions = Object.keys(decodeOptions).length ? decodeOptions : undefined;
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
        messages.push(cborDecode(payload, this.#decodeOptions));
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
