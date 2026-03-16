import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cborEncode, cborDecode, frameEncode, FrameDecoder } from '../src/cbor.mjs';

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
});
