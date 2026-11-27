// test/cbor-fuzz.test.mjs -- fixed-seed mutation fuzzing of the strict CBOR decoder (#317): no crash other than a CborError, no hang, bounded allocation,
// and whatever is accepted is the canonical encoding of what it decodes to. (JS against Rust: test/rust/cbor-differential.test.mjs.)
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { cborEncode, cborDecode, CborError } from '../src/cbor.mjs';
import { mutate, xorshift } from './helpers/cbor-fuzz.mjs';

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const corpus = read('../spec/cbor-vectors.json').vectors.flatMap((v) => [v.js, v.rust, v.rust_released].map((h) => Uint8Array.from(Buffer.from(h, 'hex'))));
const hex = (b) => Buffer.from(b).toString('hex');
/** Bytes whose presence lets a valid input re-encode differently: floats of a shorter width, and integers past 2^53 (the decoder returns a double). */
const loose = (b) => b[0] === 0xbf || b.some((x) => x === 0xf9 || x === 0xfa || x === 0xfb || x === 0x1b || x === 0x3b);

describe('fuzz: fixed seed, mutated golden vectors', () => {
  it('30000 mutations: only CborError is ever thrown, nothing hangs, and what is accepted is canonical', () => {
    const rng = xorshift(0x9e3779b97f4a7c15n);
    const t0 = Date.now(); let accepted = 0; let refused = 0; let slowest = 0;
    const codes = new Set();
    for (let i = 0; i < 30000; i++) {
      const input = mutate(rng, corpus[rng.below(corpus.length)]);
      const t = performance.now();
      let value;
      try { value = cborDecode(input); } catch (e) {
        assert.ok(e instanceof CborError, `${hex(input)}: ${e.stack}`);
        codes.add(e.code); refused++;
        slowest = Math.max(slowest, performance.now() - t);
        continue;
      }
      slowest = Math.max(slowest, performance.now() - t);
      accepted++;
      const again = cborEncode(value);
      assert.deepEqual(cborDecode(again), value, `idempotent: ${hex(input)}`);
      if (!loose(input)) assert.equal(hex(again), hex(input), `accepted but not canonical: ${hex(input)}`);
    }
    assert.ok(accepted > 1000 && refused > 1000, `${accepted} accepted, ${refused} refused`);
    assert.ok(Date.now() - t0 < 30000, 'finishes in seconds');
    assert.ok(slowest < 100, `no single input took ${slowest} ms`);
    for (const c of ['length-exceeds-buffer', 'trailing-bytes', 'non-shortest', 'truncated']) assert.ok(codes.has(c), `the mutations reached ${c}`);
  });

  it('random heads with huge declared lengths on short buffers: refused at once, with bounded allocation', () => {
    const rng = xorshift(0x1234567812345678n);
    const before = process.memoryUsage();
    const t0 = performance.now();
    for (let i = 0; i < 20000; i++) {
      const major = 2 + rng.below(4); // bytes, text, array, map
      const ai = 24 + rng.below(4);
      const n = [1, 2, 4, 8][ai - 24];
      const head = [(major << 5) | ai, ...Array.from({ length: n }, () => (rng.below(4) === 0 ? 0 : 0x80 + rng.below(128)))];
      const input = Uint8Array.from([...head, ...Array.from({ length: rng.below(8) }, () => rng.below(256))]);
      try { cborDecode(input); } catch (e) { assert.ok(e instanceof CborError, hex(input)); }
    }
    const after = process.memoryUsage();
    assert.ok(performance.now() - t0 < 2000, 'quick');
    assert.ok(after.arrayBuffers + after.heapUsed - before.arrayBuffers - before.heapUsed < 64 * 1024 * 1024, 'no allocation proportional to a declared length');
  });

  it('deep nesting is a CborError, not a stack overflow', () => {
    for (const depth of [129, 1000, 100000]) assert.throws(() => cborDecode(Uint8Array.from({ length: depth + 1 }, (_, i) => (i < depth ? 0x81 : 0))), (e) => e instanceof CborError && e.code === 'too-deep');
    assert.throws(() => cborDecode(Uint8Array.from([0xa1, ...Array.from({ length: 5000 }, () => [0x61, 0x61, 0xa1]).flat(), 0x61, 0x61, 0])), (e) => e instanceof CborError);
  });
});
