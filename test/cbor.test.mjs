import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  cborEncode, cborDecode, frameEncode, FrameDecoder,
  FrameSizeError, DEFAULT_MAX_FRAME_SIZE,
} from '../src/cbor.mjs';

describe('CBOR codec', () => {
  it('round-trips integers', () => {
    for (const n of [0, 1, 23, 24, 255, 256, 65535, 65536, 0x7fffffff]) {
      assert.equal(cborDecode(cborEncode(n)), n);
    }
  });

  it('round-trips negative integers', () => {
    for (const n of [-1, -10, -100, -1000]) {
      assert.equal(cborDecode(cborEncode(n)), n);
    }
  });

  it('round-trips strings', () => {
    for (const s of ['', 'hello', 'a'.repeat(1000), '\u{1f600}']) {
      assert.equal(cborDecode(cborEncode(s)), s);
    }
  });

  it('round-trips booleans', () => {
    assert.equal(cborDecode(cborEncode(true)), true);
    assert.equal(cborDecode(cborEncode(false)), false);
  });

  it('round-trips null', () => {
    assert.equal(cborDecode(cborEncode(null)), null);
  });

  it('round-trips floats', () => {
    const val = 3.14159;
    const decoded = cborDecode(cborEncode(val));
    assert.ok(Math.abs(decoded - val) < 1e-10);
  });

  it('round-trips arrays', () => {
    const arr = [1, 'two', true, null, [3, 4]];
    assert.deepEqual(cborDecode(cborEncode(arr)), arr);
  });

  it('round-trips objects (maps)', () => {
    const obj = { name: 'test', value: 42, nested: { a: 1 } };
    assert.deepEqual(cborDecode(cborEncode(obj)), obj);
  });

  it('round-trips Uint8Array (bytes)', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const decoded = cborDecode(cborEncode(bytes));
    assert.ok(decoded instanceof Uint8Array);
    assert.deepEqual([...decoded], [1, 2, 3, 4, 5]);
  });

  it('handles empty containers', () => {
    assert.deepEqual(cborDecode(cborEncode([])), []);
    assert.deepEqual(cborDecode(cborEncode({})), {});
    assert.deepEqual([...cborDecode(cborEncode(new Uint8Array(0)))], []);
  });
});

describe('FrameDecoder', () => {
  it('decodes a single framed message', () => {
    const msg = { type: 1, data: 'hello' };
    const frame = frameEncode(msg);
    const decoder = new FrameDecoder();
    const messages = decoder.feed(frame);
    assert.equal(messages.length, 1);
    assert.deepEqual(messages[0], msg);
  });

  it('decodes multiple framed messages', () => {
    const msgs = [{ a: 1 }, { b: 2 }, { c: 3 }];
    const combined = new Uint8Array(
      msgs.reduce((acc, m) => {
        const f = frameEncode(m);
        const next = new Uint8Array(acc.length + f.length);
        next.set(acc);
        next.set(f, acc.length);
        return next;
      }, new Uint8Array(0))
    );

    const decoder = new FrameDecoder();
    const decoded = decoder.feed(combined);
    assert.equal(decoded.length, 3);
    assert.deepEqual(decoded, msgs);
  });

  it('handles incremental feeding', () => {
    const msg = { type: 5, payload: 'test' };
    const frame = frameEncode(msg);
    const decoder = new FrameDecoder();

    // Feed one byte at a time
    for (let i = 0; i < frame.length - 1; i++) {
      const decoded = decoder.feed(frame.subarray(i, i + 1));
      assert.equal(decoded.length, 0, `unexpected message at byte ${i}`);
    }

    // Feed last byte
    const decoded = decoder.feed(frame.subarray(frame.length - 1));
    assert.equal(decoded.length, 1);
    assert.deepEqual(decoded[0], msg);
  });

  it('tracks pending bytes', () => {
    const decoder = new FrameDecoder();
    decoder.feed(new Uint8Array([0, 0]));
    assert.equal(decoder.pending, 2);
    decoder.reset();
    assert.equal(decoder.pending, 0);
  });

  it('handles frame split across feeds', () => {
    const msg = { x: 'data' };
    const frame = frameEncode(msg);
    const mid = Math.floor(frame.length / 2);

    const decoder = new FrameDecoder();
    const part1 = decoder.feed(frame.subarray(0, mid));
    assert.equal(part1.length, 0);

    const part2 = decoder.feed(frame.subarray(mid));
    assert.equal(part2.length, 1);
    assert.deepEqual(part2[0], msg);
  });

  // Regression test for: FrameDecoder had no maximum frame-size bound,
  // allowing a peer to claim a length near UINT32_MAX and force the
  // decoder to buffer unboundedly while waiting for the (possibly
  // never-arriving) payload — a client-side memory-exhaustion DoS.
  it('rejects a frame claiming a length near UINT32_MAX instead of buffering unboundedly', () => {
    const decoder = new FrameDecoder();
    const header = new Uint8Array(4);
    new DataView(header.buffer).setUint32(0, 0xfffffffe); // ~4 GiB claimed length

    assert.throws(() => decoder.feed(header), FrameSizeError);

    // The bogus length must not be retained as "waiting for more bytes" —
    // the decoder should not be sitting on a multi-gigabyte target.
    assert.equal(decoder.pending, 0);
  });

  it('rejects an oversized frame before the payload has fully arrived', () => {
    const decoder = new FrameDecoder({ maxFrameSize: 16 });
    const msg = { data: 'this payload is well over sixteen bytes long' };
    const frame = frameEncode(msg);
    assert.ok(frame.length > 4 + 16);

    // Feed only the 4-byte length prefix (which already claims more than
    // the configured max) — decoding must fail immediately, without
    // requiring the rest of the oversized payload to show up.
    assert.throws(() => decoder.feed(frame.subarray(0, 4)), FrameSizeError);
  });

  it('respects a configurable maxFrameSize', () => {
    const decoder = new FrameDecoder({ maxFrameSize: 8 });
    const msg = { a: 'this is definitely more than eight bytes of CBOR' };
    const frame = frameEncode(msg);
    assert.throws(() => decoder.feed(frame), FrameSizeError);
  });

  it('still accepts frames within the default max frame size', () => {
    const decoder = new FrameDecoder();
    const msg = { data: 'x'.repeat(1024) };
    const frame = frameEncode(msg);
    assert.ok(frame.length < DEFAULT_MAX_FRAME_SIZE);

    const messages = decoder.feed(frame);
    assert.equal(messages.length, 1);
    assert.deepEqual(messages[0], msg);
  });
});

describe('CBOR indefinite-length decoding', () => {
  it('decodes indefinite-length maps from Rust encoders', () => {
    const data = new Uint8Array([
      0xbf,
      0x64, 0x74, 0x79, 0x70, 0x65, 0x02,
      0x68, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x9f,
      0x67, 0x72, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65,
      0xff,
      0xff,
    ]);

    assert.deepEqual(cborDecode(data), {
      type: 2,
      features: ['reverse'],
    });
  });

  it('decodes indefinite-length byte and text strings', () => {
    const bytes = cborDecode(new Uint8Array([0x5f, 0x42, 0x01, 0x02, 0x41, 0x03, 0xff]));
    const text = cborDecode(new Uint8Array([0x7f, 0x62, 0x68, 0x65, 0x63, 0x6c, 0x6c, 0x6f, 0xff]));

    assert.deepEqual(Array.from(bytes), [1, 2, 3]);
    assert.equal(text, 'hello');
  });
});
