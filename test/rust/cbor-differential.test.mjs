// test/rust/cbor-differential.test.mjs -- the JS and the Rust decoder agree on accept/reject, and on the rule that refused, for the shared table and
// for 20000 fixed-seed mutations of the golden vectors (#317). The Rust side is `crates/wsh-core/examples/cbor_accept.rs`.
//
// Prerequisite: cargo build -p wsh-core --example cbor_accept   (or WSH_CBOR_ACCEPT_BIN=<path>; default target/debug/examples/cbor_accept).
import { describe, it } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { cborDecode, cborEncode } from '../../src/cbor.mjs';
import { mutate, xorshift, randomValue } from '../helpers/cbor-fuzz.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = process.env.WSH_CBOR_ACCEPT_BIN || path.join(REPO_ROOT, 'target', 'debug', 'examples', 'cbor_accept');
const CANON = process.env.WSH_CBOR_CANON_BIN || path.join(REPO_ROOT, 'target', 'debug', 'examples', 'cbor_canon');
/** Integers above 2^53 are read exactly: the Rust decoder reads them, so the comparison must not be about what a JS number can carry. */
const BIG = { unsafeIntegers: 'bigint' };
const read = (p) => JSON.parse(readFileSync(path.join(REPO_ROOT, p), 'utf8'));
const hex = (b) => Buffer.from(b).toString('hex');

const jsVerdict = (b, options) => { try { cborDecode(b, options); return 'ok'; } catch (e) { return `err ${e.code ?? 'js:' + e.message}`; } };
const run = (bin, args, inputs) => {
  const r = spawnSync(bin, args, { input: inputs.map(hex).join('\n') + '\n', encoding: 'utf8', maxBuffer: 1 << 28 });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim().split('\n');
};
const rustVerdicts = (inputs, args = []) => run(BIN, args, inputs);
const canonVerdicts = (inputs) => run(CANON, [], inputs);

describe('JS and Rust strict decoders agree (#317, #325)', { skip: existsSync(BIN) ? false : `no ${BIN}: cargo build -p wsh-core --example cbor_accept` }, () => {
  it('on every case of the shared table, with the same rule code', () => {
    const cases = read('spec/cbor-strict-cases.json').cases.filter((c) => c.legacy !== false);
    const rust = rustVerdicts(cases.map((c) => Buffer.from(c.hex, 'hex')));
    cases.forEach((c, i) => assert.equal(rust[i], c.error ? `err ${c.error}` : 'ok', c.hex));
  });

  it('on every canonical case of the shared table, in strict mode and in the compatibility window', () => {
    const cases = read('spec/cbor-strict-cases.json').canonical_cases;
    const inputs = cases.map((c) => Buffer.from(c.hex, 'hex'));
    const strict = rustVerdicts(inputs, ['--strict']);
    const window = rustVerdicts(inputs);
    cases.forEach((c, i) => {
      assert.equal(strict[i], c.error ? `err ${c.error}` : 'ok', `strict ${c.hex}`);
      assert.equal(window[i], c.default_error ? `err ${c.default_error}` : 'ok', `window ${c.hex}`);
      assert.equal(jsVerdict(inputs[i], { strict: true, ...BIG }), strict[i], `js strict ${c.hex}`);
      assert.equal(jsVerdict(inputs[i], BIG), window[i], `js window ${c.hex}`);
    });
  });

  const corpus = () => read('spec/cbor-vectors.json').vectors.flatMap((v) => ['js', 'rust', 'js_released', 'rust_released'].map((side) => Buffer.from(v[side], 'hex')));

  for (const [label, rustArgs, jsOptions] of [['the compatibility window', [], BIG], ['strict mode (every legacy option off)', ['--strict'], { strict: true, ...BIG }]]) {
    it(`on 20000 mutations of the golden vectors, in ${label}: same verdict, and where both refuse, the same rule`, () => {
      const rng = xorshift(0x2545f4914f6cdd1dn);
      const c = corpus();
      const inputs = Array.from({ length: 20000 }, () => mutate(rng, c[rng.below(c.length)]));
      const rust = rustVerdicts(inputs, rustArgs);
      const differ = [];
      inputs.forEach((b, i) => { const js = jsVerdict(b, jsOptions); if (js !== rust[i]) differ.push(`${hex(b)}: js ${js}, rust ${rust[i]}`); });
      assert.deepEqual(differ.slice(0, 10), [], `${differ.length} of ${inputs.length} differ`);
      const accepted = rust.filter((x) => x === 'ok').length;
      assert.ok(accepted > 500 && accepted < inputs.length - 500, `${accepted} accepted: the mutations hit both outcomes`);
      if (rustArgs.length) {
        const codes = new Set(rust.filter((x) => x.startsWith('err ')));
        assert.ok(codes.has('err non-canonical-key-order') || codes.has('err non-canonical-float'), `the mutations reach a canonical rule: ${[...codes]}`);
      }
    });
  }

  it('on a sequence of random decoder inputs built from random headers: same verdict (a head, a length, a float, a map), strict and window', () => {
    const rng = xorshift(0xdeadbeefcafef00dn);
    const inputs = Array.from({ length: 20000 }, () => {
      const n = 1 + rng.below(14);
      return Uint8Array.from({ length: n }, () => [0xa1, 0xa2, 0x82, 0xf9, 0xfa, 0xfb, 0x61, 0x62, 0x00, 0x7e, 0x7c, 0xff, 0x80, 0x1b][rng.below(14)] ^ (rng.below(4) === 0 ? rng.below(256) : 0));
    });
    for (const [args, o] of [[[], BIG], [['--strict'], { strict: true, ...BIG }]]) {
      const rust = rustVerdicts(inputs, args);
      const differ = [];
      inputs.forEach((b, i) => { const js = jsVerdict(b, o); if (js !== rust[i]) differ.push(`${hex(b)}: js ${js}, rust ${rust[i]}`); });
      assert.deepEqual(differ.slice(0, 10), [], `${differ.length} differ (${args})`);
    }
  });
});

describe('the two encoders write the same bytes (#325)', { skip: existsSync(CANON) ? false : `no ${CANON}: cargo build -p wsh-core --example cbor_canon` }, () => {
  const jsCanon = (b) => { try { return hex(cborEncode(cborDecode(b, BIG))); } catch (e) { return `err ${e.code ?? 'js:' + e.message}`; } };
  /** Compare the JS canonical re-encoding with the Rust one for every input; an input holding an integral float is skipped (JS writes it as an integer). */
  const agree = (inputs) => {
    const rust = canonVerdicts(inputs);
    const differ = []; let compared = 0; let skipped = 0;
    inputs.forEach((b, i) => {
      if (rust[i].endsWith(' intfloat')) { skipped++; return; }
      compared++;
      const js = jsCanon(b);
      if (js !== rust[i]) differ.push(`${hex(b)}: js ${js}, rust ${rust[i]}`);
    });
    return { differ, compared, skipped };
  };

  it('for every golden vector of every encoder, old and new: decode leniently, re-encode: identical bytes, and they are the current encoders\' bytes', () => {
    const { vectors } = read('spec/cbor-vectors.json');
    const inputs = []; const want = [];
    for (const v of vectors) for (const side of ['js', 'js_released']) { inputs.push(Buffer.from(v[side], 'hex')); want.push(v.js); }
    for (const v of vectors) for (const side of ['rust', 'rust_released']) { inputs.push(Buffer.from(v[side], 'hex')); want.push(v.rust); }
    const rust = canonVerdicts(inputs);
    rust.forEach((r, i) => { assert.equal(r, want[i], `rust ${hex(inputs[i])}`); assert.equal(jsCanon(inputs[i]), want[i], `js ${hex(inputs[i])}`); });
  });

  it('for 3000 random values: the JS encoder\'s bytes are what Rust re-encodes them to, and strict mode reads them', () => {
    const rng = xorshift(0x0123456789abcdefn);
    const values = Array.from({ length: 3000 }, () => randomValue(rng));
    const inputs = values.map((v) => cborEncode(v));
    for (const b of inputs) cborDecode(b, { strict: true, ...BIG });
    const rust = canonVerdicts(inputs);
    const differ = inputs.map((b, i) => (rust[i] === hex(b) ? null : `${hex(b)} -> rust ${rust[i]}`)).filter(Boolean);
    assert.deepEqual(differ.slice(0, 5), [], `${differ.length} of ${inputs.length} differ`);
    assert.ok(inputs.some((b) => b.some((x) => x === 0xf9)) && inputs.some((b) => b.some((x) => x === 0xfa)) && inputs.some((b) => b.some((x) => x === 0xfb)), 'all three float widths were generated');
  });

  it('for 20000 mutations of the golden vectors that both decoders read: the same canonical bytes', () => {
    const rng = xorshift(0x5eed5eed5eed5eedn);
    const { vectors } = read('spec/cbor-vectors.json');
    const c = vectors.flatMap((v) => ['js', 'rust', 'js_released', 'rust_released'].map((s) => Buffer.from(v[s], 'hex')));
    const inputs = Array.from({ length: 20000 }, () => mutate(rng, c[rng.below(c.length)]));
    const { differ, compared } = agree(inputs);
    assert.deepEqual(differ.slice(0, 10), [], `${differ.length} of ${compared} differ`);
    assert.ok(compared > 5000, `${compared} compared`);
  });

  it('for the unsorted, wide-float and NaN-payload forms the released encoders wrote: normalised to one form by both', () => {
    const forms = ['a26162016161 02', 'a2626161 01 6162 02'.replace(' ', ''), 'fb3ff8000000000000', 'fa3fc00000', 'f97e01', 'fb7ff8000000000001', 'fa7f800000', 'fb8000000000000000', 'fa80000000',
      'a2 6162 fb3ff8000000000000 6161 fa7fc00000', '82 f97e00 fbfff8000000000000', 'bf6162 01 6161 02ff', 'a3 63626262 01 6161 02 6162 03', '1b0020000000000001', '3bffffffffffffffff'].map((h) => Buffer.from(h.replace(/ /g, ''), 'hex'));
    const { differ } = agree(forms);
    assert.deepEqual(differ, []);
    assert.equal(hex(cborEncode(cborDecode(forms[0]))), 'a2616102616201');
  });
});
