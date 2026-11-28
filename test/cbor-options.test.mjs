// test/cbor-options.test.mjs -- the decode options are checked, not guessed at (#336): `strict: 1` used to be silently "not strict", which is a
// security setting that failed open. A non-boolean for a boolean option, and a bad `maxContainers` or `unsafeIntegers`, throw a TypeError.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cborDecode, cborDecodePrefix, cborEncode, FrameDecoder, frameEncode } from '../src/cbor.mjs';

const ONE = Uint8Array.from([0x01]);
const BAD_BOOLEANS = [1, 0, 'true', 'false', '', null, {}, [], 1n, Symbol('x'), NaN];
const OPTIONS = ['strict', 'legacyIndefiniteMap', 'legacyNonCanonical'];

describe('boolean decode options throw a TypeError on a non-boolean (#336)', () => {
  for (const name of OPTIONS) {
    for (const bad of BAD_BOOLEANS) {
      it(`${name}: ${String(bad)} (${typeof bad})`, () => {
        assert.throws(() => cborDecode(ONE, { [name]: bad }), (e) => e instanceof TypeError && e.message.includes(name), 'cborDecode');
        assert.throws(() => cborDecodePrefix(ONE, { [name]: bad }), TypeError, 'cborDecodePrefix');
        assert.throws(() => new FrameDecoder({ [name]: bad }), TypeError, 'FrameDecoder constructor, before any frame');
      });
    }
    it(`${name}: true, false and undefined are accepted`, () => {
      for (const ok of [true, false, undefined]) {
        assert.equal(cborDecode(ONE, { [name]: ok }), 1);
        assert.equal(cborDecodePrefix(ONE, { [name]: ok }).value, 1);
        assert.equal(new FrameDecoder({ [name]: ok }).feed(frameEncode(1))[0], 1);
      }
    });
  }

  it('the refusal is the same whatever is decoded: a non-boolean strict never reaches the data', () => {
    assert.throws(() => cborDecode(Uint8Array.from([0xbf, 0x61, 0x61, 0x01, 0xff]), { strict: 1 }), TypeError);
    assert.throws(() => cborDecode(Uint8Array.from([0xff]), { strict: 1 }), TypeError, 'even for input that would be refused anyway');
  });

  it('options that are not an object: undefined is the default, anything else but an object is a TypeError', () => {
    assert.equal(cborDecode(ONE, undefined), 1);
    assert.equal(cborDecode(ONE, {}), 1);
    for (const bad of [null, 1, 'strict', true]) assert.throws(() => cborDecode(ONE, bad), TypeError, String(bad));
  });
});

describe('maxContainers and unsafeIntegers are checked too (#336)', () => {
  for (const bad of [0, -1, 1.5, NaN, Infinity, '5', null, 5n, true]) {
    it(`maxContainers: ${String(bad)} (${typeof bad}) throws a TypeError`, () => {
      assert.throws(() => cborDecode(ONE, { maxContainers: bad }), (e) => e instanceof TypeError && e.message.includes('maxContainers'));
      assert.throws(() => new FrameDecoder({ maxContainers: bad }), TypeError);
    });
  }
  it('maxContainers: a positive integer is the cap', () => {
    const three = Uint8Array.from([0x83, 0x80, 0x80, 0x80]); // 4 containers
    assert.throws(() => cborDecode(three, { maxContainers: 3 }), (e) => e.code === 'too-many-containers');
    assert.deepEqual(cborDecode(three, { maxContainers: 4 }), [[], [], []]);
    assert.throws(() => new FrameDecoder({ maxContainers: 3 }).feed(frameEncode([[], [], []])), (e) => e.code === 'too-many-containers');
  });
  for (const bad of ['Round', 'bigInt', true, 1, null, {}]) {
    it(`unsafeIntegers: ${String(bad)} throws a TypeError`, () => {
      assert.throws(() => cborDecode(ONE, { unsafeIntegers: bad }), (e) => e instanceof TypeError && e.message.includes('unsafeIntegers'));
    });
  }
  it('every documented value still works', () => {
    for (const unsafeIntegers of ['round', 'bigint', 'refuse']) assert.equal(cborDecode(ONE, { unsafeIntegers }), 1);
    assert.deepEqual(cborDecode(cborEncode({ a: [1] }), { strict: true, maxContainers: 2 }), { a: [1] });
  });
});
