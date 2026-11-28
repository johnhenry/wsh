// test/cbor-canonical.test.mjs -- canonical (RFC 8949 section 4.2.1 deterministic) CBOR, the gaps #317 left (#325), and the sunset of the legacy exceptions (#326).
//
// The encoders write ONE form: map keys sorted length-first then bytewise, the shortest float that reads back exactly (NaN as f97e00, -0 allowed),
// the shortest integer. The decoder reads that form always; what released peers wrote (insertion/field order, float64, a rounded NaN) is read only
// while `legacyNonCanonical` is on (the default for the compatibility window); `strict: true` turns every legacy exception off.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { cborEncode, cborDecode, cborDecodePrefix, CborError, CBOR_MAX_CONTAINERS, FrameDecoder, frameEncode } from '../src/cbor.mjs';

const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (b) => Buffer.from(b).toString('hex');
const enc = (v) => hex(cborEncode(v));
const table = JSON.parse(readFileSync(new URL('../spec/cbor-strict-cases.json', import.meta.url), 'utf8'));
const refuses = (code, input, options) => assert.throws(() => cborDecode(typeof input === 'string' ? bytes(input) : input, options), (e) => e instanceof CborError && e.code === code, `${typeof input === 'string' ? input : '(bytes)'} as ${code}`);

describe('canonical encoding: map keys', () => {
  it('sorts keys length-first, then bytewise (RFC 8949 4.2.1), whatever order the object was built in', () => {
    assert.equal(enc({ b: 1, a: 2 }), 'a2' + '6161' + '02' + '6162' + '01');
    assert.equal(enc({ aa: 1, b: 2, '': 3, a: 4 }), 'a4' + '60' + '03' + '6161' + '04' + '6162' + '02' + '626161' + '01');
    assert.equal(enc({ type: 1, id: 2 }), 'a2' + '626964' + '02' + '6474797065' + '01', 'type no longer comes first');
    assert.deepEqual(Object.keys(cborDecode(cborEncode({ type: 1, id: 2, a: 3, zz: 4 }))), ['a', 'id', 'zz', 'type']);
  });

  it('compares the UTF-8 bytes, not UTF-16 code units, and sorts nested maps too', () => {
    // same encoded length: U+00DF (c3 9f) before U+0101 (c4 81); a 4-byte astral key after a 3-byte BMP key
    assert.deepEqual(Object.keys(cborDecode(cborEncode({ 'ā': 1, 'ß': 2 }))), ['ß', 'ā']);
    assert.deepEqual(Object.keys(cborDecode(cborEncode({ '\u{1f600}': 1, '￿': 2, z: 3 }))), ['z', '￿', '\u{1f600}']);
    assert.equal(enc({ y: { b: 1, a: 2 }, x: [{ d: 1, c: 2 }] }), 'a2' + '6178' + '81' + 'a2' + '6163' + '02' + '6164' + '01' + '6179' + 'a2' + '6161' + '02' + '6162' + '01');
  });

  it('two objects with the same entries encode to the same bytes', () => {
    const a = { z: 1, m: [1, { q: 1, p: 2 }], a: 'x' };
    const b = { a: 'x', m: [1, { p: 2, q: 1 }], z: 1 };
    assert.equal(enc(a), enc(b));
  });

  it('integer-like keys (which the engine orders first) are sorted by their bytes like any other', () => {
    assert.equal(enc({ b: 1, 10: 2, 2: 3 }), 'a3' + '6132' + '03' + '6162' + '01' + '623130' + '02');
  });
});

describe('canonical encoding: floats and integers', () => {
  const cases = [
    [1.5, 'f93e00'], [0.5, 'f93800'], [-4.1, 'fbc010666666666666'], [1.1, 'fb3ff199999999999a'], [1e300, 'fb7e37e43c8800759c'],
    [5.5, 'f94580'], [5.960464477539063e-8, 'f90001'], [0.00006103515625, 'f90400'], [3.4028234663852886e38, 'fa7f7fffff'],
    [1.00048828125, 'fa3f801000'], [2 ** 64, 'fa5f800000'],
    [Infinity, 'f97c00'], [-Infinity, 'f9fc00'], [NaN, 'f97e00'], [-0, 'f98000'],
    [0, '00'], [24, '1818'], [-1, '20'], [2 ** 53, '1b0020000000000000'], [-(2 ** 53), '3b001fffffffffffff'],
  ];
  for (const [v, want] of cases) it(`${Object.is(v, -0) ? '-0' : v} is ${want}`, () => assert.equal(enc(v), want));

  it('every f16 value is written as f16, and the next-wider forms never are', () => {
    for (let h = 0; h < 0x10000; h++) {
      if ((h & 0x7c00) === 0x7c00 && (h & 0x3ff) !== 0) continue; // NaN payloads
      const v = cborDecode(bytes('f9' + h.toString(16).padStart(4, '0')));
      if (Number.isInteger(v) && !Object.is(v, -0)) continue; // an integral value is an integer in the JS encoder
      assert.equal(enc(v), 'f9' + h.toString(16).padStart(4, '0'), `half ${h.toString(16)}`);
    }
  });

  it('a double that is exactly a float32 but not a float16 is written as float32; one that is neither as float64', () => {
    assert.equal(enc(Math.fround(0.1))[0] + enc(Math.fround(0.1))[1], 'fa');
    assert.equal(enc(0.1).slice(0, 2), 'fb');
    assert.equal(enc(65504.5).slice(0, 2), 'fa');
  });

  it('every float the encoder writes reads back exactly, in every width', () => {
    for (const v of [0.1, 1 / 3, Math.PI, 1e-320, 5e-324, Number.MAX_VALUE, Number.MIN_VALUE, Math.fround(1 / 3), 2 ** -24, 2 ** -25, 65504.25, -0, NaN, 123456.789]) {
      const back = cborDecode(cborEncode(v), { strict: true });
      assert.ok(Object.is(back, v) || (Number.isNaN(v) && Number.isNaN(back)), `${v}`);
    }
  });

  it('a BigInt is an integer in the 64-bit ranges, and anything else is a RangeError', () => {
    assert.equal(enc(5n), '05');
    assert.equal(enc(2n ** 53n), '1b0020000000000000');
    assert.equal(enc(2n ** 53n + 1n), '1b0020000000000001');
    assert.equal(enc(2n ** 64n - 1n), '1bffffffffffffffff');
    assert.equal(enc(-(2n ** 64n)), '3bffffffffffffffff');
    assert.equal(enc(-(2n ** 53n) - 2n), '3b0020000000000001');
    assert.throws(() => cborEncode(2n ** 64n), RangeError);
    assert.throws(() => cborEncode(-(2n ** 64n) - 1n), RangeError);
  });
});

describe('canonical decoding: what `strict` refuses and the default still reads', () => {
  const inputs = [
    ['a2 6162 01 6161 02', 'non-canonical-key-order', 'keys b, a'],
    ['a2 626161 01 6162 02', 'non-canonical-key-order', 'keys aa, b: the shorter key goes first'],
    ['a3 6161 01 6162 02 6161 03', 'duplicate-key', 'a duplicate is a duplicate, not an order error'],
    ['a2 6162 01 6163 02', null, 'keys b, c in order'],
    ['82 a2 6162 01 6161 02 00', 'non-canonical-key-order', 'a nested unsorted map'],
    ['fb3ff8000000000000', 'non-canonical-float', '1.5 as float64'],
    ['fa3fc00000', 'non-canonical-float', '1.5 as float32'],
    ['f93e00', null, '1.5 as float16'],
    ['fb7ff8000000000000', 'non-canonical-float', 'NaN as float64'],
    ['fa7fc00000', 'non-canonical-float', 'NaN as float32'],
    ['f97e01', 'non-canonical-float', 'a NaN with a payload'],
    ['f9fe00', 'non-canonical-float', 'a NaN with the sign set'],
    ['f97e00', null, 'the canonical NaN'],
    ['fa7f800000', 'non-canonical-float', 'Infinity as float32'],
    ['fb7ff0000000000000', 'non-canonical-float', 'Infinity as float64'],
    ['f97c00', null, 'Infinity as float16'],
    ['fb8000000000000000', 'non-canonical-float', '-0 as float64'],
    ['fa80000000', 'non-canonical-float', '-0 as float32'],
    ['f98000', null, '-0 as float16 (allowed, and stays -0)'],
    ['fa47c35000', null, '100000.0 as float32 is not an f16 value, so float32 is right'],
    ['fa3f800000', 'non-canonical-float', '1.0 as float32 fits a float16'],
    ['fb3ff199999999999a', null, '1.1 needs float64'],
    ['fa00000001', null, 'the smallest float32 subnormal needs float32'],
  ];
  for (const [h, code, why] of inputs) {
    const input = h.replace(/ /g, '');
    if (code === null) it(`strict accepts ${input}: ${why}`, () => { cborDecode(bytes(input), { strict: true }); });
    else it(`strict refuses ${input} (${code}): ${why}; the default window reads it`, () => { refuses(code, input, { strict: true }); if (code !== 'duplicate-key') cborDecode(bytes(input)); else refuses(code, input); });
  }

  it('the largest float32 written as float64 is refused by strict, and read by the default', () => {
    refuses('non-canonical-float', 'fb47efffffe0000000', { strict: true });
    assert.equal(cborDecode(bytes('fb47efffffe0000000')), 3.4028234663852886e38);
  });

  it('-0 and NaN come back as -0 and NaN', () => {
    assert.ok(Object.is(cborDecode(bytes('f98000'), { strict: true }), -0));
    assert.ok(Number.isNaN(cborDecode(bytes('f97e00'), { strict: true })));
  });

  it('the options are independent, and `strict` is the shorthand for both being off', () => {
    const unsorted = 'a26162016161 02'.replace(/ /g, '');
    const indefinite = 'bf616101ff';
    cborDecode(bytes(unsorted)); cborDecode(bytes(unsorted), { legacyNonCanonical: true });
    refuses('non-canonical-key-order', unsorted, { legacyNonCanonical: false });
    refuses('non-canonical-key-order', unsorted, { strict: true });
    cborDecode(bytes(unsorted), { strict: true, legacyNonCanonical: true });
    refuses('indefinite-length', indefinite, { strict: true });
    cborDecode(bytes(indefinite), { strict: true, legacyIndefiniteMap: true });
    cborDecode(bytes(indefinite), { legacyNonCanonical: false });
    refuses('indefinite-length', indefinite, { legacyIndefiniteMap: false });
  });

  it('the shared table of canonical cases (spec/cbor-strict-cases.json) holds in strict mode and in the default', () => {
    const cases = table.canonical_cases;
    assert.ok(cases.length >= 40, `${cases?.length} canonical cases`);
    for (const c of cases) {
      const input = bytes(c.hex);
      if (c.error) refuses(c.error, input, { strict: true, unsafeIntegers: 'bigint' }); else cborDecode(input, { strict: true, unsafeIntegers: 'bigint' });
      if (c.default_error) refuses(c.default_error, input, { unsafeIntegers: 'bigint' }); else cborDecode(input, { unsafeIntegers: 'bigint' });
    }
    const codes = new Set(cases.map((c) => c.error));
    for (const code of ['non-canonical-key-order', 'non-canonical-float']) assert.ok(codes.has(code), `no canonical case for ${code}`);
  });

  it('a frame is decoded by the same rules (the transports pass no options: the default window)', () => {
    const d = new FrameDecoder();
    const unsorted = bytes('a26162016161 02'.replace(/ /g, ''));
    const frame = new Uint8Array(4 + unsorted.length); new DataView(frame.buffer).setUint32(0, unsorted.length); frame.set(unsorted, 4);
    assert.deepEqual(d.feed(frame), [{ b: 1, a: 2 }]);
    assert.deepEqual(new FrameDecoder({ strict: true }).feedAll(frame).errors.map((e) => e.code), ['non-canonical-key-order']);
    assert.deepEqual(new FrameDecoder({ strict: true }).feed(frameEncode({ b: 1, a: 2 })), [{ a: 2, b: 1 }]);
  });
});

describe('integers above 2^53 (#325 item 4)', () => {
  it('the default window rounds as before; `unsafeIntegers: "bigint"` is exact; strict refuses what a JS number cannot carry', () => {
    assert.equal(cborDecode(bytes('1b0020000000000001')), 2 ** 53);
    assert.equal(cborDecode(bytes('1b0020000000000001'), { unsafeIntegers: 'bigint' }), 9007199254740993n);
    refuses('unsafe-integer', '1b0020000000000001', { strict: true });
    refuses('unsafe-integer', '1b0020000000000001', { unsafeIntegers: 'refuse' });
    assert.equal(cborDecode(bytes('1b0020000000000001'), { strict: true, unsafeIntegers: 'bigint' }), 9007199254740993n);
    assert.equal(cborDecode(bytes('1b0020000000000001'), { strict: true, unsafeIntegers: 'round' }), 2 ** 53);
  });

  it('the safe range is a number in every mode; the first unsafe value is not', () => {
    for (const o of [undefined, { strict: true }, { unsafeIntegers: 'bigint' }]) {
      assert.equal(cborDecode(bytes('1b001fffffffffffff'), o), Number.MAX_SAFE_INTEGER);
      assert.equal(cborDecode(bytes('3b001ffffffffffffe'), o), -Number.MAX_SAFE_INTEGER);
    }
    assert.equal(cborDecode(bytes('1b0020000000000000'), { unsafeIntegers: 'bigint' }), 2n ** 53n);
    refuses('unsafe-integer', '3b001fffffffffffff', { strict: true });
    assert.equal(cborDecode(bytes('3b001fffffffffffff'), { unsafeIntegers: 'bigint' }), -(2n ** 53n));
  });

  it('the whole 64-bit range survives a BigInt round trip', () => {
    for (const n of [2n ** 53n, 2n ** 53n + 1n, 2n ** 63n, 2n ** 64n - 1n, -(2n ** 53n) - 1n, -(2n ** 63n), -(2n ** 64n)]) {
      assert.equal(cborDecode(cborEncode(n), { unsafeIntegers: 'bigint' }), n);
    }
  });

  it('refusing is for the number path only: a nested field is refused the same way, with the offset', () => {
    assert.throws(() => cborDecode(bytes('a16161' + '1b0020000000000001'), { strict: true }), (e) => e.code === 'unsafe-integer' && e.offset === 3);
  });

  it('an unknown `unsafeIntegers` value is a TypeError', () => {
    assert.throws(() => cborDecode(bytes('00'), { unsafeIntegers: 'maybe' }), TypeError);
  });
});

describe('float/integer conflation (#325 item 5): documented, and the same in both decoders', () => {
  it('f93c00 (1.0) and 01 read as the same JS number: JS has one number type and message fields are plain numbers', () => {
    assert.equal(cborDecode(bytes('f93c00')), cborDecode(bytes('01')));
    assert.equal(cborDecode(bytes('f93c00'), { strict: true }), 1);
  });
  it('the encoder writes an integral number as an integer, never as a float', () => {
    assert.equal(enc(1), '01'); assert.equal(enc(1.0), '01'); assert.equal(enc(-3), '22'); assert.equal(enc(2 ** 40), '1b0000010000000000');
  });
});

describe('a container-count cap (#325 item 7)', () => {
  const emptyArrays = (n) => { const b = new Uint8Array(5 + n); b[0] = 0x9a; new DataView(b.buffer).setUint32(1, n); b.fill(0x80, 5); return b; };

  it('the default cap is a million containers, in the module and in the docs', () => {
    assert.equal(CBOR_MAX_CONTAINERS, 1_000_000);
  });

  it('a 4 MiB frame of empty arrays is refused at the cap, quickly and without building them all', () => {
    const input = emptyArrays(4 * 1024 * 1024 - 5);
    const before = process.memoryUsage().heapUsed;
    const t0 = performance.now();
    refuses('too-many-containers', input);
    const grew = process.memoryUsage().heapUsed - before;
    refuses('too-many-containers', input, { strict: true });
    assert.ok(performance.now() - t0 < 1500, `${performance.now() - t0} ms`);
    assert.ok(grew < 100 * 1024 * 1024, `the cap bounds the heap (grew ${(grew / 1048576).toFixed(0)} MiB; without it this input costs about 160 MiB)`);
  });

  it('exactly the cap is accepted (the top-level array counts as one), one more is not', () => {
    cborDecode(emptyArrays(CBOR_MAX_CONTAINERS - 1));
    refuses('too-many-containers', emptyArrays(CBOR_MAX_CONTAINERS));
  });

  it('maps and arrays both count, at any depth; scalars and byte strings do not', () => {
    refuses('too-many-containers', '83 a0 81 80 a0'.replace(/ /g, ''), { maxContainers: 4 });
    cborDecode(bytes('83 a0 81 80 a0'.replace(/ /g, '')), { maxContainers: 5 });
    cborDecode(bytes('85 01 6161 41ff f6 f5'.replace(/ /g, '')), { maxContainers: 1 });
  });

  it('a long list of real records is nowhere near the cap', () => {
    const rows = Array.from({ length: 20000 }, (_, i) => ({ id: i, tags: ['a', 'b'], info: { n: i, ok: true } }));
    assert.equal(cborDecode(cborEncode(rows), { strict: true }).length, 20000);
  });

  it('the cap is per item: each item of a longer buffer starts again', () => {
    const one = bytes('83 a0 a0 a0'.replace(/ /g, ''));
    const two = new Uint8Array([...one, ...one]);
    const first = cborDecodePrefix(two, { maxContainers: 4 });
    assert.equal(cborDecodePrefix(two, { offset: first.end, maxContainers: 4 }).end, two.length);
  });
});

describe('the legacy top-level map is read at offset 0 only (#326)', () => {
  const legacy = '0a bf 6161 01 ff'.replace(/ /g, '');
  it('cborDecodePrefix reads an indefinite-length map at offset 0 and refuses it at any other offset', () => {
    const at0 = cborDecodePrefix(bytes('bf616101ff00'));
    assert.deepEqual(at0, { value: { a: 1 }, end: 5 });
    assert.throws(() => cborDecodePrefix(bytes(legacy), { offset: 1 }), (e) => e instanceof CborError && e.code === 'indefinite-length');
  });
  it('after an item, the next one cannot be a legacy map either', () => {
    const buf = bytes('00bf616101ff');
    const first = cborDecodePrefix(buf);
    assert.throws(() => cborDecodePrefix(buf, { offset: first.end }), (e) => e.code === 'indefinite-length');
  });
  it('legacyIndefiniteMap: false refuses it at offset 0 as well', () => {
    assert.throws(() => cborDecodePrefix(bytes('bf616101ff'), { legacyIndefiniteMap: false }), (e) => e.code === 'indefinite-length');
  });
});
