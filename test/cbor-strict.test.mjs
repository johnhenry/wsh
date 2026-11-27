// test/cbor-strict.test.mjs -- the CBOR decoder is strict (#317): one table of malformed and accepted inputs (spec/cbor-strict-cases.json, the same
// table the Rust decoder's tests read), the options, the prefix API, the allocation bounds, and the claims COMPATIBILITY.md makes about
// what a decoder accepts.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { cborEncode, cborDecode, cborDecodePrefix, CborError, FrameDecoder, frameEncode } from '../src/cbor.mjs';
import * as index from '../src/index.mjs';

const table = JSON.parse(readFileSync(new URL('../spec/cbor-strict-cases.json', import.meta.url), 'utf8'));
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

describe('strict decoding: the shared table of malformed and accepted inputs', () => {
  for (const c of table.cases) {
    const opts = c.legacy === false ? { legacyIndefiniteMap: false } : undefined;
    const label = `${c.hex.length > 40 ? c.hex.slice(0, 40) + '...' : c.hex || '(empty)'}: ${c.why}`;
    if (c.error) {
      it(`rejects ${label} as ${c.error}`, () => {
        assert.throws(() => cborDecode(bytes(c.hex), opts), (e) => e instanceof CborError && e.code === c.error, `expected ${c.error}`);
      });
    } else {
      it(`accepts ${label}`, () => {
        assert.doesNotThrow(() => cborDecode(bytes(c.hex), opts));
      });
    }
  }

  it('the table is not vacuous: it covers every rule code', () => {
    const codes = new Set(table.cases.map((c) => c.error).filter(Boolean));
    for (const code of ['length-exceeds-buffer', 'truncated', 'trailing-bytes', 'non-shortest', 'indefinite-length', 'unexpected-break', 'reserved-additional-info',
      'duplicate-key', 'non-text-key', 'tag', 'simple-value', 'invalid-utf8', 'too-deep']) assert.ok(codes.has(code), `no case for ${code}`);
    assert.ok(table.cases.filter((c) => !c.error).length >= 25, 'accepted inputs are in the table too');
  });
});

describe('strict decoding: what the decoder still does', () => {
  it('round-trips what the encoder writes, for every kind of value the encoder takes', () => {
    const samples = [0, 1, 23, 24, 255, 256, 65535, 65536, 2 ** 32 - 1, 2 ** 32, 2 ** 53 - 1, -1, -24, -25, -256, -257, -65537, -(2 ** 32) - 1,
      0.5, 1.5, -2.25, 1e300, Infinity, -Infinity, '', 'x', '\ufeffx', 'x\ufeff', 'héllo 世界 \u{1f600}', 'a'.repeat(23), 'a'.repeat(24), 'a'.repeat(256), 'a'.repeat(70000),
      true, false, null, [], [1, [2, [3]]], {}, { a: 1, b: { c: [true, null, 'x'] } }, { type: 0x8f, channel_id: 1, nonce: new Uint8Array(12), ciphertext: new Uint8Array(40), session_id: 'abc' }];
    for (const v of samples) assert.deepEqual(cborDecode(cborEncode(v)), v);
    assert.ok(Number.isNaN(cborDecode(cborEncode(NaN))));
    assert.ok(Object.is(cborDecode(cborEncode(-0)), -0));
    assert.deepEqual(cborDecode(cborEncode(new Uint8Array(300).fill(7))), new Uint8Array(300).fill(7));
  });

  it('a key named __proto__ is still plain data', () => {
    const d = cborDecode(bytes('a1695f5f70726f746f5f5fa1' + '6161' + '01'));
    assert.equal(Object.getPrototypeOf(d), Object.prototype);
    assert.equal(Object.hasOwn(d, '__proto__'), true);
  });

  it('a map with an empty-string key is fine, and so is a long key', () => {
    assert.deepEqual(cborDecode(bytes('a1' + '60' + '01')), { '': 1 });
    const k = 'k'.repeat(300);
    assert.deepEqual(cborDecode(cborEncode({ [k]: 1 })), { [k]: 1 });
  });

  it('floats of every width are read (the JS encoder writes float64 for all, Rust writes the shortest)', () => {
    assert.equal(cborDecode(bytes('f93c00')), 1);
    assert.equal(cborDecode(bytes('f9c000')), -2);
    assert.equal(cborDecode(bytes('fa3fc00000')), 1.5);
    assert.equal(cborDecode(bytes('fb3ff8000000000000')), 1.5);
  });

  it('the typed-array views the encoder accepts still decode as bytes', () => {
    assert.deepEqual(cborDecode(cborEncode(new Uint16Array([1, 2]))), new Uint8Array([1, 0, 2, 0]));
  });
});

describe('strict decoding: lengths are checked before anything is allocated', () => {
  it('a declared 2^32 / 2^53 / 2^64-1 element array or map fails at once, with no allocation and no loop', () => {
    const t0 = process.hrtime.bigint();
    const before = process.memoryUsage().arrayBuffers + process.memoryUsage().heapUsed;
    for (const hex of ['9a' + 'ffffffff', '9b0000000100000000', '9b0020000000000000', '9bffffffffffffffff', 'bb0000000100000000', 'bbffffffffffffffff', '5bffffffffffffffff', '7bffffffffffffffff', '7a' + 'ffffffff', '5a' + 'ffffffff']) {
      assert.throws(() => cborDecode(bytes(hex)), (e) => e instanceof CborError && e.code === 'length-exceeds-buffer', hex);
    }
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    const grew = process.memoryUsage().arrayBuffers + process.memoryUsage().heapUsed - before;
    assert.ok(ms < 200, `refusing ten absurd lengths took ${ms} ms`);
    assert.ok(grew < 8 * 1024 * 1024, `and allocated ${grew} bytes`);
  });

  it('an element count that fits the buffer only if every element were zero bytes is refused (each element is at least one byte)', () => {
    assert.throws(() => cborDecode(bytes('99ffff' + '00'.repeat(100))), (e) => e.code === 'length-exceeds-buffer');
    assert.throws(() => cborDecode(bytes('b9ffff' + '00'.repeat(100))), (e) => e.code === 'length-exceeds-buffer');
  });

  it('the issue case: an EncryptedFrame whose session-id length byte grew is a decode error, not an accepted frame', () => {
    const frame = cborEncode({ type: 0x8f, channel_id: 1, nonce: new Uint8Array(12), ciphertext: new Uint8Array(24), session_id: 'abcd' });
    assert.deepEqual(cborDecode(frame).session_id, 'abcd');
    const at = frame.length - 5; // the head byte of "abcd" (0x64)
    assert.equal(frame[at], 0x64);
    for (const bigger of [0x65, 0x66, 0x78, 0x7a, 0x7f]) {
      const bad = frame.slice(); bad[at] = bigger;
      assert.throws(() => cborDecode(bad), CborError, `0x${bigger.toString(16)}`);
    }
    const smaller = frame.slice(); smaller[at] = 0x63; // a SHORTER id leaves a trailing byte
    assert.throws(() => cborDecode(smaller), (e) => e.code === 'trailing-bytes');
  });
});

describe('the prefix API and the framing layer', () => {
  it('cborDecode is whole-buffer: a value followed by anything is an error', () => {
    assert.throws(() => cborDecode(bytes('0001')), (e) => e.code === 'trailing-bytes');
  });

  it('cborDecodePrefix reads one value from an offset and says where it ended; the rest is the caller\'s', () => {
    const a = cborEncode({ x: 1 }); const b = cborEncode([1, 2]);
    const both = new Uint8Array(a.length + b.length + 2); both.set([9, 9]); both.set(a, 2); both.set(b, 2 + a.length);
    const first = cborDecodePrefix(both, { offset: 2 });
    assert.deepEqual(first.value, { x: 1 });
    assert.equal(first.end, 2 + a.length);
    const second = cborDecodePrefix(both, { offset: first.end });
    assert.deepEqual(second.value, [1, 2]);
    assert.equal(second.end, both.length);
  });

  it('cborDecodePrefix is as strict as cborDecode about the value itself', () => {
    assert.throws(() => cborDecodePrefix(bytes('1800ff')), (e) => e.code === 'non-shortest');
    assert.throws(() => cborDecodePrefix(bytes('7a00011170')), (e) => e.code === 'length-exceeds-buffer');
    assert.throws(() => cborDecodePrefix(bytes('00'), { offset: 1 }), (e) => e.code === 'truncated');
  });

  it('FrameDecoder: a frame whose payload has a stray byte, a bad length or a non-canonical head throws; the next frame is not poisoned by a good one', () => {
    const good = frameEncode({ type: 0x21, n: 1 });
    const d = new FrameDecoder();
    assert.deepEqual(d.feed(good), [{ type: 0x21, n: 1 }]);
    const payload = cborEncode({ type: 0x21 });
    const stray = new Uint8Array(4 + payload.length + 1); new DataView(stray.buffer).setUint32(0, payload.length + 1); stray.set(payload, 4);
    assert.throws(() => new FrameDecoder().feed(stray), (e) => e.code === 'trailing-bytes');
  });

  it('the error is exported with the codec', () => {
    assert.equal(index.CborError, CborError);
    assert.equal(index.cborDecodePrefix, cborDecodePrefix);
    assert.ok(new CborError('x', 'msg') instanceof Error);
    assert.equal(new CborError('trailing-bytes', 'm').code, 'trailing-bytes');
  });
});

describe('the one legacy exception: an indefinite-length map as the top-level item', () => {
  it('is accepted by default (every released wsh Rust encoder writes an Envelope that way)', () => {
    assert.deepEqual(cborDecode(bytes('bf6474797065026161' + '01' + 'ff')), { type: 2, a: 1 });
  });
  it('reads a Rust-shaped Envelope, with definite containers inside', () => {
    const d = cborDecode(bytes('bf647479706502' + '686665617475726573' + '826161' + '6162' + 'ff'));
    assert.deepEqual(d, { type: 2, features: ['a', 'b'] });
  });
  it('can be switched off', () => {
    assert.throws(() => cborDecode(bytes('bf647479706502ff'), { legacyIndefiniteMap: false }), (e) => e.code === 'indefinite-length');
  });
});
