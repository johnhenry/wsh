// test/cbor-hardening.test.mjs -- two properties of the CBOR codec: a decoded map is plain data (its keys never alter the object's
// prototype), and every finite double round-trips exactly.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cborEncode, cborDecode, frameEncode, FrameDecoder } from '../src/cbor.mjs';
import { MSG, authFail, hello } from '../src/messages.mjs';

/** A CBOR map with the given text keys and values already encoded (definite or indefinite length). */
function mapBytes(pairs, { indefinite = false } = {}) {
  const parts = [];
  parts.push(indefinite ? Uint8Array.of(0xbf) : Uint8Array.of(0xa0 | pairs.length));
  for (const [k, v] of pairs) { parts.push(cborEncode(k)); parts.push(v); }
  if (indefinite) parts.push(Uint8Array.of(0xff));
  return Buffer.concat(parts);
}

describe('decoded maps are plain data', () => {
  for (const indefinite of [false, true]) {
    const label = indefinite ? 'indefinite-length' : 'definite-length';

    it(`${label}: a __proto__ key is an own property and the prototype is unchanged`, () => {
      const decoded = cborDecode(mapBytes([['__proto__', cborEncode({ admin: true })], ['type', cborEncode(7)]], { indefinite }));
      assert.equal(Object.getPrototypeOf(decoded), Object.prototype, 'prototype untouched');
      assert.equal(Object.hasOwn(decoded, '__proto__'), true);
      assert.deepEqual(Object.getOwnPropertyDescriptor(decoded, '__proto__').value, { admin: true });
      assert.equal(decoded.admin, undefined, 'nothing is inherited from the value of the key');
      assert.equal(({}).admin, undefined);
      assert.equal(decoded.type, 7);
      assert.deepEqual(Object.keys(decoded).sort(), ['__proto__', 'type']);
    });

    it(`${label}: constructor and prototype keys are plain own data`, () => {
      const decoded = cborDecode(mapBytes([['constructor', cborEncode('x')], ['prototype', cborEncode(1)], ['toString', cborEncode(null)]], { indefinite }));
      assert.equal(Object.getPrototypeOf(decoded), Object.prototype);
      assert.equal(decoded.constructor, 'x');
      assert.equal(decoded.prototype, 1);
      assert.equal(decoded.toString, null);
      assert.equal(Object.hasOwn(decoded, 'constructor'), true);
    });
  }

  it('nested maps are plain data too, and an array of them', () => {
    const inner = mapBytes([['__proto__', cborEncode({ polluted: 1 })]]);
    const outer = mapBytes([['a', inner], ['list', Buffer.concat([Uint8Array.of(0x81), inner])]]);
    const decoded = cborDecode(outer);
    for (const m of [decoded.a, decoded.list[0]]) {
      assert.equal(Object.getPrototypeOf(m), Object.prototype);
      assert.equal(m.polluted, undefined);
      assert.equal(Object.hasOwn(m, '__proto__'), true);
    }
    assert.equal(({}).polluted, undefined);
  });

  it('a __proto__ key survives an encode/decode round trip as data, and is not mistaken for a prototype by a spread or a copy', () => {
    const wire = mapBytes([['__proto__', cborEncode({ x: 1 })]]);
    const decoded = cborDecode(wire);
    assert.deepEqual(cborDecode(cborEncode(decoded)), decoded);
    const spread = { ...decoded };
    assert.equal(Object.getPrototypeOf(spread), Object.prototype);
    assert.equal(spread.x, undefined);
  });

  it('through the real message path: a framed message with a __proto__ key', () => {
    const body = mapBytes([['type', cborEncode(MSG.AUTH_FAIL)], ['reason', cborEncode('no')], ['__proto__', cborEncode({ type: 0xff, reason: 'inherited' })]]);
    const framed = Buffer.concat([Buffer.from([0, 0, 0, body.length]), body]);
    const [msg, ...rest] = new FrameDecoder().feed(framed);
    assert.equal(rest.length, 0);
    assert.equal(msg.type, MSG.AUTH_FAIL);
    assert.equal(msg.reason, 'no');
    assert.equal(Object.getPrototypeOf(msg), Object.prototype);
    assert.equal(Object.hasOwn(msg, '__proto__'), true);
    // The builders and the encoder see a normal message.
    assert.deepEqual(cborDecode(cborEncode(authFail({ reason: 'x' }))).reason, 'x');
    assert.equal(hello({ username: 'a', authMethod: 'pubkey' }).type, MSG.HELLO);
    assert.ok(frameEncode(authFail({ reason: 'x' })).length > 4);
  });
});

describe('every finite double round-trips exactly', () => {
  const p = (e) => 2 ** e;
  const table = [
    0, 1, -1, 23, 24, 255, 256, 65535, 65536, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1,
    p(53) - 1, p(53), p(53) + 2, -(p(53) - 1), -p(53), -(p(53) + 2),
    p(63), p(63) - 1024, -p(63), -p(63) - 2048,
    2 ** 64 - 2048, // the largest double below 2^64 (2^64-1 is not representable and rounds to 2^64)
    2 ** 64, 2 ** 64 + 4096, 1e21, 1e22, 1.7976931348623157e308,
    -(2 ** 64) + 2048, -(2 ** 64), -(2 ** 64) - 4096, -1e21, -1.7976931348623157e308,
    0.5, -0.5, 1.5, 5e-324, -5e-324, Number.EPSILON, Math.PI,
  ];
  for (const n of table) {
    it(`${n}`, () => {
      const back = cborDecode(cborEncode(n));
      assert.ok(Object.is(back, n), `${n} came back as ${back}`);
    });
  }

  it('-0 keeps its sign, NaN and the infinities are floats', () => {
    assert.ok(Object.is(cborDecode(cborEncode(-0)), -0));
    assert.ok(Object.is(cborDecode(cborEncode(0)), 0));
    assert.ok(Number.isNaN(cborDecode(cborEncode(NaN))));
    assert.equal(cborDecode(cborEncode(Infinity)), Infinity);
    assert.equal(cborDecode(cborEncode(-Infinity)), -Infinity);
  });

  it('integers within the 64-bit ranges stay integers on the wire, and larger ones are floats in the shortest width', () => {
    assert.equal(cborEncode(2 ** 64 - 2048)[0], 0x1b, 'uint64');
    assert.equal(cborEncode(-(2 ** 64) + 2048)[0], 0x3b, 'nint64');
    assert.equal(cborEncode(2 ** 64)[0], 0xfa, 'float32 (2^64 is exact in a float32)');
    assert.equal(cborEncode(1e21)[0], 0xfb);
    assert.equal(cborEncode(-(2 ** 64) - 4096)[0], 0xfb);
    assert.equal(cborEncode(-0)[0], 0xf9, '-0 is a float16');
    assert.equal(cborEncode(2 ** 53)[0], 0x1b);
    assert.equal(cborEncode(1000)[0], 0x19, 'small integers are unchanged');
  });

  it('the exact bytes of the boundaries (what a Rust decoder reads)', () => {
    assert.equal(Buffer.from(cborEncode(2 ** 63)).toString('hex'), '1b8000000000000000');
    assert.equal(Buffer.from(cborEncode(-(2 ** 63))).toString('hex'), '3b7fffffffffffffff');
    assert.equal(Buffer.from(cborEncode(2 ** 64 - 2048)).toString('hex'), '1bfffffffffffff800');
    assert.equal(Buffer.from(cborEncode(2 ** 64)).toString('hex'), 'fa5f800000');
    assert.equal(Buffer.from(cborEncode(1e21)).toString('hex'), 'fb444b1ae4d6e2ef50');
    assert.equal(Buffer.from(cborEncode(-0)).toString('hex'), 'f98000');
  });
});
