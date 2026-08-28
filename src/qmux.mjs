/**
 * QMux wire codec — QUIC-v1 frame encoding running directly over an
 * existing reliable, ordered, authenticated byte stream (a WebSocket
 * connection), per draft-ietf-quic-qmux-02, plus RESET_STREAM_AT from
 * draft-ietf-quic-reliable-stream-reset-09.
 *
 * This module is the wire codec only: varint encode/decode, the QMux
 * Record framing (`{Size varint, Frames}`), and encode/decode for every
 * frame type wsh uses. It has no notion of streams, flow-control state,
 * or a state machine — see transport-ws.mjs for that.
 *
 * Because QMux's underlying transport already guarantees in-order,
 * lossless delivery (unlike raw QUIC over UDP), this codec omits
 * everything raw QUIC needs to survive an unreliable network: packet
 * numbers, ACK frames, retransmission, and reordering/reassembly. That
 * is QMux's whole point (draft-ietf-quic-qmux-02 Section 1): reuse
 * QUIC's well-specified multi-stream framing and flow control without
 * reimplementing QUIC's loss-recovery machinery on top of a transport
 * that doesn't need it.
 */

// ── Variable-length integer (QUIC varint, RFC 9000 §16) ────────────────
//
// A 2-bit length prefix in the first byte's high bits selects 1/2/4/8-byte
// encoding, big-endian, with the prefix bits masked out of the value:
//   00 -> 1 byte  (6  data bits, 0..2^6-1)
//   01 -> 2 bytes (14 data bits, 0..2^14-1)
//   10 -> 4 bytes (30 data bits, 0..2^30-1)
//   11 -> 8 bytes (62 data bits, 0..2^62-1)

const VARINT_MAX_1 = 2 ** 6 - 1;
const VARINT_MAX_2 = 2 ** 14 - 1;
const VARINT_MAX_4 = 2 ** 30 - 1;
// 2^62-1 exceeds Number.MAX_SAFE_INTEGER (2^53-1); values that need the
// 8-byte form are represented as BigInt on both the encode and decode
// side (see encodeVarint/decodeVarint below).
const VARINT_MAX_8 = (1n << 62n) - 1n;

/**
 * Encode a non-negative integer as a QUIC variable-length integer.
 * Accepts a Number (must be a safe, non-negative integer) or a BigInt
 * (for values that don't fit in a JS Number) and always returns the
 * shortest encoding that fits the value.
 *
 * @param {number|bigint} value
 * @returns {Uint8Array}
 */
export function encodeVarint(value) {
  const big = typeof value === 'bigint' ? value : BigInt(value);
  if (big < 0n) {
    throw new RangeError('varint value must be non-negative');
  }
  if (big > VARINT_MAX_8) {
    throw new RangeError('varint value exceeds the 62-bit QUIC varint range');
  }

  if (big <= BigInt(VARINT_MAX_1)) {
    return new Uint8Array([Number(big)]);
  }
  if (big <= BigInt(VARINT_MAX_2)) {
    const out = new Uint8Array(2);
    new DataView(out.buffer).setUint16(0, Number(big) | 0x4000);
    return out;
  }
  if (big <= BigInt(VARINT_MAX_4)) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, Number(big) | 0x80000000);
    return out;
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, big | 0xc000000000000000n);
  return out;
}

/**
 * Decode a QUIC variable-length integer starting at `offset`.
 *
 * Returns the value as a plain Number when it fits safely
 * (<= Number.MAX_SAFE_INTEGER), otherwise as a BigInt — callers that
 * only ever deal with wsh-scale sizes (well under 2^53) can safely
 * assume a Number back; only pathological/hostile input produces a
 * BigInt here, since 62-bit varints can exceed what a Number can hold
 * exactly.
 *
 * @param {Uint8Array} data
 * @param {number} offset
 * @returns {{ value: number|bigint, length: number }}
 */
export function decodeVarint(data, offset = 0) {
  if (offset >= data.byteLength) {
    throw new RangeError('varint: no data at offset');
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const first = view.getUint8(offset);
  const prefix = first >> 6;
  const length = 1 << prefix; // 1, 2, 4, or 8

  if (offset + length > data.byteLength) {
    throw new RangeError('varint: truncated');
  }

  let value;
  if (length === 1) {
    value = first & 0x3f;
  } else if (length === 2) {
    value = (view.getUint16(offset) & 0x3fff);
  } else if (length === 4) {
    value = (view.getUint32(offset) & 0x3fffffff) >>> 0;
  } else {
    const raw = view.getBigUint64(offset) & 0x3fffffffffffffffn;
    value = raw <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(raw) : raw;
  }
  return { value, length };
}

/** Number of bytes encodeVarint(value) would produce, without allocating. */
export function varintLength(value) {
  const big = typeof value === 'bigint' ? value : BigInt(value);
  if (big <= BigInt(VARINT_MAX_1)) return 1;
  if (big <= BigInt(VARINT_MAX_2)) return 2;
  if (big <= BigInt(VARINT_MAX_4)) return 4;
  return 8;
}

/** Concatenate several Uint8Arrays into one. */
function concat(parts) {
  let total = 0;
  for (const p of parts) total += p.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.byteLength;
  }
  return out;
}

// ── Frame type constants ────────────────────────────────────────────

export const FRAME_TYPE = Object.freeze({
  PADDING:              0x00,
  RESET_STREAM:         0x04,
  STOP_SENDING:         0x05,
  // STREAM base type; the low 3 bits (FIN=0x01, LEN=0x02, OFF=0x04) are
  // combined in per-frame, not a single fixed value — see encodeStream.
  STREAM:               0x08,
  MAX_DATA:              0x10,
  MAX_STREAM_DATA:       0x11,
  MAX_STREAMS_BIDI:      0x12,
  MAX_STREAMS_UNI:       0x13,
  DATA_BLOCKED:          0x14,
  STREAM_DATA_BLOCKED:   0x15,
  STREAMS_BLOCKED_BIDI:  0x16,
  STREAMS_BLOCKED_UNI:   0x17,
  CONNECTION_CLOSE_TRANSPORT: 0x1c,
  CONNECTION_CLOSE_APPLICATION: 0x1d,
  // DATAGRAM base type; low bit is the LEN flag (RFC 9221).
  DATAGRAM:              0x30,
  // RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-09 §3).
  RESET_STREAM_AT:       0x24,
});

/**
 * QX_TRANSPORT_PARAMETERS frame type, encoded as a QUIC varint (it's a
 * 62-bit constant chosen to double as an ALPN-adjacent protocol
 * discriminator — draft-ietf-quic-qmux-02 §4.1). Always 8 bytes on the
 * wire (the top 2 bits are set, forcing the 8-byte varint form).
 */
export const QX_TRANSPORT_PARAMETERS_TYPE = 0x3f5153300d0a0d0an;

// ── QUIC transport error codes (RFC 9000 §20.1, values used by wsh) ───

export const ERROR_CODE = Object.freeze({
  NO_ERROR: 0x00,
  INTERNAL_ERROR: 0x01,
  FLOW_CONTROL_ERROR: 0x03,
  STREAM_LIMIT_ERROR: 0x04,
  STREAM_STATE_ERROR: 0x05,
  FINAL_SIZE_ERROR: 0x06,
  FRAME_ENCODING_ERROR: 0x07,
  TRANSPORT_PARAMETER_ERROR: 0x08,
  PROTOCOL_VIOLATION: 0x0a,
  APPLICATION_ERROR: 0x0c,
});

// ── QMux Record framing ─────────────────────────────────────────────
//
// { Size (varint): length of Frames in bytes, Frames (Size bytes) }.
// Records are self-delimiting and never split a frame across records.

/**
 * Wrap already-encoded frame bytes in a QMux Record.
 * @param {Uint8Array} framesBytes - one or more concatenated encoded frames
 * @returns {Uint8Array}
 */
export function encodeRecord(framesBytes) {
  return concat([encodeVarint(framesBytes.byteLength), framesBytes]);
}

/**
 * Incrementally accumulates bytes from the underlying transport and
 * yields complete QMux Records (the raw Frames bytes, not yet parsed
 * into individual frames).
 */
export class RecordDecoder {
  #buffer = new Uint8Array(0);

  /**
   * @param {Uint8Array} chunk
   * @returns {Uint8Array[]} Frames payloads of any complete records now available.
   */
  feed(chunk) {
    const merged = new Uint8Array(this.#buffer.byteLength + chunk.byteLength);
    merged.set(this.#buffer, 0);
    merged.set(chunk, this.#buffer.byteLength);
    this.#buffer = merged;

    const records = [];
    while (true) {
      let sizeField;
      try {
        sizeField = decodeVarint(this.#buffer, 0);
      } catch {
        break; // not enough bytes yet for the Size varint
      }
      const size = Number(sizeField.value);
      const total = sizeField.length + size;
      if (this.#buffer.byteLength < total) break;

      records.push(this.#buffer.slice(sizeField.length, total));
      this.#buffer = this.#buffer.slice(total);
    }
    return records;
  }

  reset() {
    this.#buffer = new Uint8Array(0);
  }
}

// ── Frame encoders ───────────────────────────────────────────────────

export function encodePadding(length) {
  return new Uint8Array(length); // all-zero bytes; 0x00 is PADDING's type
}

export function encodeResetStream({ streamId, errorCode, finalSize }) {
  return concat([
    encodeVarint(FRAME_TYPE.RESET_STREAM),
    encodeVarint(streamId),
    encodeVarint(errorCode),
    encodeVarint(finalSize),
  ]);
}

export function encodeResetStreamAt({ streamId, errorCode, finalSize, reliableSize }) {
  return concat([
    encodeVarint(FRAME_TYPE.RESET_STREAM_AT),
    encodeVarint(streamId),
    encodeVarint(errorCode),
    encodeVarint(finalSize),
    encodeVarint(reliableSize),
  ]);
}

export function encodeStopSending({ streamId, errorCode }) {
  return concat([
    encodeVarint(FRAME_TYPE.STOP_SENDING),
    encodeVarint(streamId),
    encodeVarint(errorCode),
  ]);
}

/**
 * Encode a STREAM frame. Offset and Length are always included (OFF=1,
 * LEN=1) for simplicity and because QMux Records already delimit frame
 * boundaries so omitting Length saves nothing at the mux-record level
 * the way it can in a raw QUIC packet.
 */
export function encodeStream({ streamId, offset, data, fin }) {
  const flags = 0x02 /* LEN */ | 0x04 /* OFF */ | (fin ? 0x01 : 0x00);
  return concat([
    encodeVarint(FRAME_TYPE.STREAM | flags),
    encodeVarint(streamId),
    encodeVarint(offset),
    encodeVarint(data.byteLength),
    data,
  ]);
}

export function encodeMaxData(maxData) {
  return concat([encodeVarint(FRAME_TYPE.MAX_DATA), encodeVarint(maxData)]);
}

export function encodeMaxStreamData({ streamId, maxStreamData }) {
  return concat([
    encodeVarint(FRAME_TYPE.MAX_STREAM_DATA),
    encodeVarint(streamId),
    encodeVarint(maxStreamData),
  ]);
}

export function encodeMaxStreams({ unidirectional, maxStreams }) {
  return concat([
    encodeVarint(unidirectional ? FRAME_TYPE.MAX_STREAMS_UNI : FRAME_TYPE.MAX_STREAMS_BIDI),
    encodeVarint(maxStreams),
  ]);
}

export function encodeDataBlocked(dataLimit) {
  return concat([encodeVarint(FRAME_TYPE.DATA_BLOCKED), encodeVarint(dataLimit)]);
}

export function encodeStreamDataBlocked({ streamId, streamDataLimit }) {
  return concat([
    encodeVarint(FRAME_TYPE.STREAM_DATA_BLOCKED),
    encodeVarint(streamId),
    encodeVarint(streamDataLimit),
  ]);
}

export function encodeStreamsBlocked({ unidirectional, streamLimit }) {
  return concat([
    encodeVarint(unidirectional ? FRAME_TYPE.STREAMS_BLOCKED_UNI : FRAME_TYPE.STREAMS_BLOCKED_BIDI),
    encodeVarint(streamLimit),
  ]);
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function encodeConnectionClose({ application = false, errorCode, frameType, reason = '' }) {
  const reasonBytes = textEncoder.encode(reason);
  const parts = [
    encodeVarint(application ? FRAME_TYPE.CONNECTION_CLOSE_APPLICATION : FRAME_TYPE.CONNECTION_CLOSE_TRANSPORT),
    encodeVarint(errorCode),
  ];
  if (!application) {
    parts.push(encodeVarint(frameType ?? 0));
  }
  parts.push(encodeVarint(reasonBytes.byteLength), reasonBytes);
  return concat(parts);
}

export function encodeDatagram(data) {
  return concat([
    encodeVarint(FRAME_TYPE.DATAGRAM | 0x01 /* LEN present */),
    encodeVarint(data.byteLength),
    data,
  ]);
}

/**
 * Encode the QX_TRANSPORT_PARAMETERS frame. `params` is a plain object
 * of QUIC-varint-valued transport parameters this codec understands
 * (see TRANSPORT_PARAM_ID below); unknown/unsupported parameters are
 * simply not emitted (QMux only permits a small allowed subset anyway).
 */
export function encodeTransportParameters(params) {
  const encodedParams = [];
  for (const [name, id] of Object.entries(TRANSPORT_PARAM_ID)) {
    if (params[name] === undefined) continue;
    const valueBytes = encodeVarint(params[name]);
    encodedParams.push(concat([
      encodeVarint(id),
      encodeVarint(valueBytes.byteLength),
      valueBytes,
    ]));
  }
  const paramsBytes = concat(encodedParams);
  const typeBytes = encodeVarint(QX_TRANSPORT_PARAMETERS_TYPE);
  return concat([typeBytes, encodeVarint(paramsBytes.byteLength), paramsBytes]);
}

/**
 * Transport parameter codepoints QMux permits (draft-ietf-quic-qmux-02
 * §5.1) plus RESET_STREAM_AT's negotiation parameter
 * (draft-ietf-quic-reliable-stream-reset-09 §4) and DATAGRAM's
 * (RFC 9221 §3). QMux's own max_record_size parameter
 * (0x0571c59429cd0845) is intentionally omitted from this codec's
 * negotiated set — see transport-ws.mjs for why wsh fixes it instead of
 * negotiating it.
 */
export const TRANSPORT_PARAM_ID = Object.freeze({
  max_idle_timeout: 0x01,
  initial_max_data: 0x04,
  initial_max_stream_data_bidi_local: 0x05,
  initial_max_stream_data_bidi_remote: 0x06,
  initial_max_stream_data_uni: 0x07,
  initial_max_streams_bidi: 0x08,
  initial_max_streams_uni: 0x09,
  max_datagram_frame_size: 0x20,
});
const TRANSPORT_PARAM_NAME = Object.freeze(
  Object.fromEntries(Object.entries(TRANSPORT_PARAM_ID).map(([k, v]) => [v, k]))
);

// ── Frame decoder ─────────────────────────────────────────────────────

/**
 * Decode every frame in a Frames payload (the contents of one QMux
 * Record). Throws on the first malformed frame — per QMux, a malformed
 * frame is a connection-level protocol error, not a recoverable one.
 *
 * @param {Uint8Array} data
 * @returns {Array<object>} Decoded frames, each `{ frameType, ... }`.
 */
export function decodeFrames(data) {
  const frames = [];
  let offset = 0;

  while (offset < data.byteLength) {
    const typeField = decodeVarint(data, offset);
    const rawType = typeField.value;
    offset += typeField.length;

    if (rawType === QX_TRANSPORT_PARAMETERS_TYPE) {
      const len = decodeVarint(data, offset);
      offset += len.length;
      const paramsBytes = data.subarray(offset, offset + Number(len.value));
      offset += Number(len.value);
      frames.push({ frameType: 'QX_TRANSPORT_PARAMETERS', params: decodeTransportParameters(paramsBytes) });
      continue;
    }

    // STREAM frames occupy the type range 0x08-0x0f (base 0x08 | 3 flag bits).
    if (typeof rawType === 'number' && rawType >= 0x08 && rawType <= 0x0f) {
      const fin = (rawType & 0x01) !== 0;
      const hasLen = (rawType & 0x02) !== 0;
      const hasOff = (rawType & 0x04) !== 0;

      const streamIdField = decodeVarint(data, offset);
      offset += streamIdField.length;

      let streamOffset = 0;
      if (hasOff) {
        const off = decodeVarint(data, offset);
        offset += off.length;
        streamOffset = off.value;
      }

      let length;
      if (hasLen) {
        const lenField = decodeVarint(data, offset);
        offset += lenField.length;
        length = Number(lenField.value);
      } else {
        length = data.byteLength - offset; // extends to end of Frames payload
      }

      const streamData = data.slice(offset, offset + length);
      offset += length;

      frames.push({
        frameType: 'STREAM',
        streamId: streamIdField.value,
        offset: streamOffset,
        data: streamData,
        fin,
      });
      continue;
    }

    // DATAGRAM frames occupy 0x30-0x31 (base 0x30 | 1 LEN flag bit).
    if (rawType === FRAME_TYPE.DATAGRAM || rawType === (FRAME_TYPE.DATAGRAM | 0x01)) {
      const hasLen = (Number(rawType) & 0x01) !== 0;
      let length;
      if (hasLen) {
        const lenField = decodeVarint(data, offset);
        offset += lenField.length;
        length = Number(lenField.value);
      } else {
        length = data.byteLength - offset;
      }
      const payload = data.slice(offset, offset + length);
      offset += length;
      frames.push({ frameType: 'DATAGRAM', data: payload });
      continue;
    }

    switch (rawType) {
      case FRAME_TYPE.PADDING: {
        frames.push({ frameType: 'PADDING' });
        break;
      }
      case FRAME_TYPE.RESET_STREAM: {
        const streamId = decodeVarint(data, offset); offset += streamId.length;
        const errorCode = decodeVarint(data, offset); offset += errorCode.length;
        const finalSize = decodeVarint(data, offset); offset += finalSize.length;
        frames.push({ frameType: 'RESET_STREAM', streamId: streamId.value, errorCode: errorCode.value, finalSize: finalSize.value });
        break;
      }
      case FRAME_TYPE.RESET_STREAM_AT: {
        const streamId = decodeVarint(data, offset); offset += streamId.length;
        const errorCode = decodeVarint(data, offset); offset += errorCode.length;
        const finalSize = decodeVarint(data, offset); offset += finalSize.length;
        const reliableSize = decodeVarint(data, offset); offset += reliableSize.length;
        if (Number(reliableSize.value) > Number(finalSize.value)) {
          throw new QMuxProtocolError(ERROR_CODE.FRAME_ENCODING_ERROR, 'RESET_STREAM_AT: reliableSize > finalSize');
        }
        frames.push({ frameType: 'RESET_STREAM_AT', streamId: streamId.value, errorCode: errorCode.value, finalSize: finalSize.value, reliableSize: reliableSize.value });
        break;
      }
      case FRAME_TYPE.STOP_SENDING: {
        const streamId = decodeVarint(data, offset); offset += streamId.length;
        const errorCode = decodeVarint(data, offset); offset += errorCode.length;
        frames.push({ frameType: 'STOP_SENDING', streamId: streamId.value, errorCode: errorCode.value });
        break;
      }
      case FRAME_TYPE.MAX_DATA: {
        const maxData = decodeVarint(data, offset); offset += maxData.length;
        frames.push({ frameType: 'MAX_DATA', maxData: maxData.value });
        break;
      }
      case FRAME_TYPE.MAX_STREAM_DATA: {
        const streamId = decodeVarint(data, offset); offset += streamId.length;
        const maxStreamData = decodeVarint(data, offset); offset += maxStreamData.length;
        frames.push({ frameType: 'MAX_STREAM_DATA', streamId: streamId.value, maxStreamData: maxStreamData.value });
        break;
      }
      case FRAME_TYPE.MAX_STREAMS_BIDI:
      case FRAME_TYPE.MAX_STREAMS_UNI: {
        const maxStreams = decodeVarint(data, offset); offset += maxStreams.length;
        frames.push({ frameType: 'MAX_STREAMS', unidirectional: rawType === FRAME_TYPE.MAX_STREAMS_UNI, maxStreams: maxStreams.value });
        break;
      }
      case FRAME_TYPE.DATA_BLOCKED: {
        const dataLimit = decodeVarint(data, offset); offset += dataLimit.length;
        frames.push({ frameType: 'DATA_BLOCKED', dataLimit: dataLimit.value });
        break;
      }
      case FRAME_TYPE.STREAM_DATA_BLOCKED: {
        const streamId = decodeVarint(data, offset); offset += streamId.length;
        const streamDataLimit = decodeVarint(data, offset); offset += streamDataLimit.length;
        frames.push({ frameType: 'STREAM_DATA_BLOCKED', streamId: streamId.value, streamDataLimit: streamDataLimit.value });
        break;
      }
      case FRAME_TYPE.STREAMS_BLOCKED_BIDI:
      case FRAME_TYPE.STREAMS_BLOCKED_UNI: {
        const streamLimit = decodeVarint(data, offset); offset += streamLimit.length;
        frames.push({ frameType: 'STREAMS_BLOCKED', unidirectional: rawType === FRAME_TYPE.STREAMS_BLOCKED_UNI, streamLimit: streamLimit.value });
        break;
      }
      case FRAME_TYPE.CONNECTION_CLOSE_TRANSPORT:
      case FRAME_TYPE.CONNECTION_CLOSE_APPLICATION: {
        const application = rawType === FRAME_TYPE.CONNECTION_CLOSE_APPLICATION;
        const errorCode = decodeVarint(data, offset); offset += errorCode.length;
        let frameType;
        if (!application) {
          const ft = decodeVarint(data, offset); offset += ft.length;
          frameType = ft.value;
        }
        const reasonLen = decodeVarint(data, offset); offset += reasonLen.length;
        const reasonBytes = data.slice(offset, offset + Number(reasonLen.value));
        offset += Number(reasonLen.value);
        frames.push({ frameType: 'CONNECTION_CLOSE', application, errorCode: errorCode.value, closeFrameType: frameType, reason: textDecoder.decode(reasonBytes) });
        break;
      }
      default:
        throw new QMuxProtocolError(ERROR_CODE.FRAME_ENCODING_ERROR, `unknown/prohibited frame type: 0x${rawType.toString(16)}`);
    }
  }

  return frames;
}

function decodeTransportParameters(data) {
  const params = {};
  let offset = 0;
  while (offset < data.byteLength) {
    const id = decodeVarint(data, offset); offset += id.length;
    const len = decodeVarint(data, offset); offset += len.length;
    const valueBytes = data.subarray(offset, offset + Number(len.value));
    offset += Number(len.value);

    const name = TRANSPORT_PARAM_NAME[Number(id.value)];
    if (name) {
      params[name] = valueBytes.byteLength === 0 ? true : decodeVarint(valueBytes, 0).value;
    }
    // Unknown parameter codepoints are ignored per QMux/QUIC's standard
    // forward-compatibility rule -- not every codepoint we might see
    // needs to be one we understand.
  }
  return params;
}

/** Thrown for a connection-level QMux/QUIC framing violation. */
export class QMuxProtocolError extends Error {
  constructor(errorCode, message) {
    super(message);
    this.name = 'QMuxProtocolError';
    this.errorCode = errorCode;
  }
}

// ── Stream ID helpers (RFC 9000 §2.1) ───────────────────────────────
//
// Low bit: initiator (0 = client, 1 = server).
// Second-lowest bit: directionality (0 = bidirectional, 1 = unidirectional).
// wsh only ever uses bidirectional streams.

export const STREAM_INITIATOR = Object.freeze({ CLIENT: 0, SERVER: 1 });

export function isClientInitiated(streamId) {
  return (Number(streamId) & 0x01) === STREAM_INITIATOR.CLIENT;
}

export function isBidirectional(streamId) {
  return (Number(streamId) & 0x02) === 0;
}

/** First bidirectional stream ID for the given initiator (0 or 1). */
export function firstBidiStreamId(initiator) {
  return initiator;
}

/** Next bidirectional stream ID after `id` for the same initiator (+4). */
export function nextBidiStreamId(id) {
  return id + 4;
}
