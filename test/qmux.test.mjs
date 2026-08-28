import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as qmux from '../src/qmux.mjs';

describe('QMux varint codec', () => {
  it('matches RFC 9000 Appendix A.1 worked examples byte-for-byte', () => {
    assert.deepEqual(Array.from(qmux.encodeVarint(37)), [0x25]);
    assert.deepEqual(Array.from(qmux.encodeVarint(15293)), [0x7b, 0xbd]);
    assert.deepEqual(Array.from(qmux.encodeVarint(494878333)), [0x9d, 0x7f, 0x3e, 0x7d]);
  });

  it('round-trips values at and around every length-class boundary', () => {
    const cases = [0, 1, 63, 64, 65, 16383, 16384, 16385, 1073741823, 1073741824, 1073741825];
    for (const v of cases) {
      const enc = qmux.encodeVarint(v);
      const { value, length } = qmux.decodeVarint(enc, 0);
      assert.equal(length, enc.byteLength, `length mismatch for ${v}`);
      assert.equal(Number(value), v, `value mismatch for ${v}`);
    }
  });

  it('round-trips the maximum 62-bit value as BigInt', () => {
    const max = (1n << 62n) - 1n;
    const enc = qmux.encodeVarint(max);
    assert.equal(enc.byteLength, 8);
    const { value } = qmux.decodeVarint(enc, 0);
    assert.equal(value, max);
  });

  it('rejects values above the 62-bit range', () => {
    assert.throws(() => qmux.encodeVarint(1n << 62n), RangeError);
  });

  it('rejects negative values', () => {
    assert.throws(() => qmux.encodeVarint(-1), RangeError);
  });

  it('decodeVarint throws on truncated input rather than reading out of bounds', () => {
    // 0xc0 prefix claims an 8-byte value but only 3 bytes are present.
    assert.throws(() => qmux.decodeVarint(new Uint8Array([0xc0, 0x01, 0x02]), 0), RangeError);
  });

  it('varintLength matches the actual encoded length for boundary values', () => {
    for (const v of [0, 63, 64, 16383, 16384, 1073741823, 1073741824]) {
      assert.equal(qmux.varintLength(v), qmux.encodeVarint(v).byteLength);
    }
  });

  it('decodes a value at a nonzero offset without disturbing preceding bytes', () => {
    const buf = new Uint8Array([0xff, 0xff, ...qmux.encodeVarint(15293)]);
    const { value, length } = qmux.decodeVarint(buf, 2);
    assert.equal(value, 15293);
    assert.equal(length, 2);
  });
});

describe('QMux Record framing', () => {
  it('encodeRecord prefixes frames bytes with their varint length', () => {
    const frames = new Uint8Array([1, 2, 3, 4, 5]);
    const record = qmux.encodeRecord(frames);
    assert.equal(record[0], 5); // 1-byte varint for size 5
    assert.deepEqual(Array.from(record.subarray(1)), [1, 2, 3, 4, 5]);
  });

  it('RecordDecoder yields nothing until a full record has arrived', () => {
    const decoder = new qmux.RecordDecoder();
    const record = qmux.encodeRecord(new Uint8Array([9, 9, 9]));

    assert.deepEqual(decoder.feed(record.subarray(0, 2)), []);
    const out = decoder.feed(record.subarray(2));
    assert.equal(out.length, 1);
    assert.deepEqual(Array.from(out[0]), [9, 9, 9]);
  });

  it('RecordDecoder yields multiple records fed in a single chunk, in order', () => {
    const decoder = new qmux.RecordDecoder();
    const r1 = qmux.encodeRecord(new Uint8Array([1]));
    const r2 = qmux.encodeRecord(new Uint8Array([2, 2]));
    const r3 = qmux.encodeRecord(new Uint8Array([3, 3, 3]));
    const combined = new Uint8Array(r1.byteLength + r2.byteLength + r3.byteLength);
    combined.set(r1, 0);
    combined.set(r2, r1.byteLength);
    combined.set(r3, r1.byteLength + r2.byteLength);

    const out = decoder.feed(combined);
    assert.equal(out.length, 3);
    assert.deepEqual(Array.from(out[0]), [1]);
    assert.deepEqual(Array.from(out[1]), [2, 2]);
    assert.deepEqual(Array.from(out[2]), [3, 3, 3]);
  });

  it('RecordDecoder handles a record split byte-by-byte across many feed() calls', () => {
    const decoder = new qmux.RecordDecoder();
    const record = qmux.encodeRecord(new Uint8Array([7, 7, 7, 7]));
    let out = [];
    for (let i = 0; i < record.byteLength - 1; i++) {
      out = out.concat(decoder.feed(record.subarray(i, i + 1)));
    }
    assert.equal(out.length, 0);
    out = decoder.feed(record.subarray(record.byteLength - 1));
    assert.equal(out.length, 1);
    assert.deepEqual(Array.from(out[0]), [7, 7, 7, 7]);
  });

  it('a large Frames payload uses a multi-byte Size varint correctly', () => {
    const decoder = new qmux.RecordDecoder();
    const payload = new Uint8Array(20000).fill(0xab);
    const record = qmux.encodeRecord(payload);
    assert.equal(record[0] >> 6, 0b10); // 4-byte varint prefix (20000 > 16383)
    const out = decoder.feed(record);
    assert.equal(out.length, 1);
    assert.equal(out[0].byteLength, 20000);
  });

  it('reset() discards any partially-buffered record', () => {
    const decoder = new qmux.RecordDecoder();
    const record = qmux.encodeRecord(new Uint8Array([1, 2, 3]));
    decoder.feed(record.subarray(0, 2));
    decoder.reset();
    const out = decoder.feed(record);
    assert.equal(out.length, 1);
    assert.deepEqual(Array.from(out[0]), [1, 2, 3]);
  });
});

describe('QMux frame encode/decode round trips', () => {
  it('STREAM frame: type byte encodes FIN/LEN/OFF flags correctly', () => {
    const data = new Uint8Array([65, 66, 67]);
    const encoded = qmux.encodeStream({ streamId: 4, offset: 10, data, fin: true });
    const [frame] = qmux.decodeFrames(encoded);
    assert.equal(frame.frameType, 'STREAM');
    assert.equal(frame.streamId, 4);
    assert.equal(frame.offset, 10);
    assert.equal(frame.fin, true);
    assert.deepEqual(Array.from(frame.data), [65, 66, 67]);

    // First byte: 0x08 (STREAM) | 0x01 (FIN) | 0x02 (LEN) | 0x04 (OFF) = 0x0f
    assert.equal(encoded[0], 0x0f);
  });

  it('STREAM frame without FIN', () => {
    const encoded = qmux.encodeStream({ streamId: 0, offset: 0, data: new Uint8Array([1]), fin: false });
    const [frame] = qmux.decodeFrames(encoded);
    assert.equal(frame.fin, false);
  });

  it('RESET_STREAM round trip', () => {
    const encoded = qmux.encodeResetStream({ streamId: 4, errorCode: qmux.ERROR_CODE.INTERNAL_ERROR, finalSize: 100 });
    const [frame] = qmux.decodeFrames(encoded);
    assert.deepEqual(frame, { frameType: 'RESET_STREAM', streamId: 4, errorCode: 1, finalSize: 100 });
  });

  it('RESET_STREAM_AT round trip', () => {
    const encoded = qmux.encodeResetStreamAt({ streamId: 8, errorCode: 0, finalSize: 1000, reliableSize: 400 });
    const [frame] = qmux.decodeFrames(encoded);
    assert.deepEqual(frame, { frameType: 'RESET_STREAM_AT', streamId: 8, errorCode: 0, finalSize: 1000, reliableSize: 400 });
  });

  it('RESET_STREAM_AT with reliableSize > finalSize is rejected as a frame encoding error', () => {
    const encoded = qmux.encodeResetStreamAt({ streamId: 8, errorCode: 0, finalSize: 10, reliableSize: 20 });
    assert.throws(() => qmux.decodeFrames(encoded), qmux.QMuxProtocolError);
  });

  it('STOP_SENDING round trip', () => {
    const encoded = qmux.encodeStopSending({ streamId: 12, errorCode: qmux.ERROR_CODE.APPLICATION_ERROR });
    const [frame] = qmux.decodeFrames(encoded);
    assert.deepEqual(frame, { frameType: 'STOP_SENDING', streamId: 12, errorCode: 0x0c });
  });

  it('MAX_DATA round trip', () => {
    const encoded = qmux.encodeMaxData(65536);
    const [frame] = qmux.decodeFrames(encoded);
    assert.deepEqual(frame, { frameType: 'MAX_DATA', maxData: 65536 });
  });

  it('MAX_STREAM_DATA round trip', () => {
    const encoded = qmux.encodeMaxStreamData({ streamId: 4, maxStreamData: 32768 });
    const [frame] = qmux.decodeFrames(encoded);
    assert.deepEqual(frame, { frameType: 'MAX_STREAM_DATA', streamId: 4, maxStreamData: 32768 });
  });

  it('MAX_STREAMS round trip (bidi and uni use distinct type bytes)', () => {
    const bidi = qmux.encodeMaxStreams({ unidirectional: false, maxStreams: 10 });
    const uni = qmux.encodeMaxStreams({ unidirectional: true, maxStreams: 5 });
    assert.notEqual(bidi[0], uni[0]);
    assert.deepEqual(qmux.decodeFrames(bidi)[0], { frameType: 'MAX_STREAMS', unidirectional: false, maxStreams: 10 });
    assert.deepEqual(qmux.decodeFrames(uni)[0], { frameType: 'MAX_STREAMS', unidirectional: true, maxStreams: 5 });
  });

  it('DATA_BLOCKED round trip', () => {
    const encoded = qmux.encodeDataBlocked(1000);
    assert.deepEqual(qmux.decodeFrames(encoded)[0], { frameType: 'DATA_BLOCKED', dataLimit: 1000 });
  });

  it('STREAM_DATA_BLOCKED round trip', () => {
    const encoded = qmux.encodeStreamDataBlocked({ streamId: 4, streamDataLimit: 500 });
    assert.deepEqual(qmux.decodeFrames(encoded)[0], { frameType: 'STREAM_DATA_BLOCKED', streamId: 4, streamDataLimit: 500 });
  });

  it('STREAMS_BLOCKED round trip (bidi and uni use distinct type bytes)', () => {
    const bidi = qmux.encodeStreamsBlocked({ unidirectional: false, streamLimit: 3 });
    const uni = qmux.encodeStreamsBlocked({ unidirectional: true, streamLimit: 2 });
    assert.notEqual(bidi[0], uni[0]);
    assert.deepEqual(qmux.decodeFrames(bidi)[0], { frameType: 'STREAMS_BLOCKED', unidirectional: false, streamLimit: 3 });
  });

  it('CONNECTION_CLOSE (transport) round trip includes the triggering frame type', () => {
    const encoded = qmux.encodeConnectionClose({ application: false, errorCode: qmux.ERROR_CODE.PROTOCOL_VIOLATION, frameType: qmux.FRAME_TYPE.STREAM, reason: 'bad stream order' });
    const [frame] = qmux.decodeFrames(encoded);
    assert.deepEqual(frame, {
      frameType: 'CONNECTION_CLOSE',
      application: false,
      errorCode: 0x0a,
      closeFrameType: qmux.FRAME_TYPE.STREAM,
      reason: 'bad stream order',
    });
  });

  it('CONNECTION_CLOSE (application) round trip omits the frame-type field', () => {
    const encoded = qmux.encodeConnectionClose({ application: true, errorCode: 5, reason: 'bye' });
    const [frame] = qmux.decodeFrames(encoded);
    assert.equal(frame.application, true);
    assert.equal(frame.closeFrameType, undefined);
    assert.equal(frame.reason, 'bye');
  });

  it('CONNECTION_CLOSE with an empty reason round trips to an empty string', () => {
    const encoded = qmux.encodeConnectionClose({ application: true, errorCode: 0 });
    assert.equal(qmux.decodeFrames(encoded)[0].reason, '');
  });

  it('DATAGRAM round trip', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const encoded = qmux.encodeDatagram(data);
    const [frame] = qmux.decodeFrames(encoded);
    assert.equal(frame.frameType, 'DATAGRAM');
    assert.deepEqual(Array.from(frame.data), [1, 2, 3, 4, 5]);
  });

  it('PADDING decodes to zero or more PADDING frames without erroring', () => {
    const encoded = qmux.encodePadding(4);
    const frames = qmux.decodeFrames(encoded);
    assert.ok(frames.every((f) => f.frameType === 'PADDING'));
  });

  it('QX_TRANSPORT_PARAMETERS round trip carries only recognized parameters', () => {
    const encoded = qmux.encodeTransportParameters({
      initial_max_data: 1_000_000,
      initial_max_stream_data_bidi_local: 65536,
      initial_max_streams_bidi: 100,
      max_datagram_frame_size: 1200,
    });
    const [frame] = qmux.decodeFrames(encoded);
    assert.equal(frame.frameType, 'QX_TRANSPORT_PARAMETERS');
    assert.equal(frame.params.initial_max_data, 1_000_000);
    assert.equal(frame.params.initial_max_stream_data_bidi_local, 65536);
    assert.equal(frame.params.initial_max_streams_bidi, 100);
    assert.equal(frame.params.max_datagram_frame_size, 1200);
  });

  it('the QX_TRANSPORT_PARAMETERS type varint is always the full 8-byte form', () => {
    const encoded = qmux.encodeTransportParameters({ initial_max_data: 1 });
    // Top 2 bits of the first byte select the 8-byte varint length class.
    assert.equal(encoded[0] >> 6, 0b11);
    assert.equal(encoded.byteLength >= 8, true);
  });

  it('multiple frames concatenated in one Frames payload decode in order', () => {
    const parts = [
      qmux.encodeMaxData(100),
      qmux.encodeStream({ streamId: 0, offset: 0, data: new Uint8Array([1, 2]), fin: false }),
      qmux.encodeStopSending({ streamId: 4, errorCode: 0 }),
    ];
    const total = parts.reduce((n, p) => n + p.byteLength, 0);
    const combined = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { combined.set(p, off); off += p.byteLength; }

    const frames = qmux.decodeFrames(combined);
    assert.deepEqual(frames.map((f) => f.frameType), ['MAX_DATA', 'STREAM', 'STOP_SENDING']);
  });

  it('an unknown/prohibited frame type throws QMuxProtocolError with FRAME_ENCODING_ERROR', () => {
    // 0x06 is CRYPTO -- a QMux-prohibited frame type.
    assert.throws(
      () => qmux.decodeFrames(new Uint8Array([0x06])),
      (err) => err instanceof qmux.QMuxProtocolError && err.errorCode === qmux.ERROR_CODE.FRAME_ENCODING_ERROR
    );
  });
});

describe('QMux stream ID helpers', () => {
  it('classifies initiator and directionality per RFC 9000 §2.1', () => {
    assert.equal(qmux.isClientInitiated(0), true);
    assert.equal(qmux.isClientInitiated(1), false);
    assert.equal(qmux.isBidirectional(0), true);
    assert.equal(qmux.isBidirectional(2), false);
  });

  it('client and server bidi streams start at 0 and 1 and increment by 4', () => {
    let id = qmux.firstBidiStreamId(qmux.STREAM_INITIATOR.CLIENT);
    assert.equal(id, 0);
    id = qmux.nextBidiStreamId(id);
    assert.equal(id, 4);
    id = qmux.nextBidiStreamId(id);
    assert.equal(id, 8);

    let serverId = qmux.firstBidiStreamId(qmux.STREAM_INITIATOR.SERVER);
    assert.equal(serverId, 1);
    serverId = qmux.nextBidiStreamId(serverId);
    assert.equal(serverId, 5);
  });
});
