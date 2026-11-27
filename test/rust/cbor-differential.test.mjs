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
import { cborDecode } from '../../src/cbor.mjs';
import { mutate, xorshift } from '../helpers/cbor-fuzz.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = process.env.WSH_CBOR_ACCEPT_BIN || path.join(REPO_ROOT, 'target', 'debug', 'examples', 'cbor_accept');
const read = (p) => JSON.parse(readFileSync(path.join(REPO_ROOT, p), 'utf8'));
const hex = (b) => Buffer.from(b).toString('hex');

const jsVerdict = (b) => { try { cborDecode(b); return 'ok'; } catch (e) { return `err ${e.code ?? 'js:' + e.message}`; } };
const rustVerdicts = (inputs) => {
  const r = spawnSync(BIN, [], { input: inputs.map(hex).join('\n') + '\n', encoding: 'utf8', maxBuffer: 1 << 28 });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim().split('\n');
};

describe('JS and Rust strict decoders agree (#317)', { skip: existsSync(BIN) ? false : `no ${BIN}: cargo build -p wsh-core --example cbor_accept` }, () => {
  it('on every case of the shared table, with the same rule code', () => {
    const cases = read('spec/cbor-strict-cases.json').cases.filter((c) => c.legacy !== false);
    const rust = rustVerdicts(cases.map((c) => Buffer.from(c.hex, 'hex')));
    cases.forEach((c, i) => assert.equal(rust[i], c.error ? `err ${c.error}` : 'ok', c.hex));
  });

  it('on 20000 mutations of the golden vectors: same verdict, and where both refuse, the same rule', () => {
    const corpus = read('spec/cbor-vectors.json').vectors.flatMap((v) => [v.js, v.rust].map((h) => Buffer.from(h, 'hex')));
    const rng = xorshift(0x2545f4914f6cdd1dn);
    const inputs = Array.from({ length: 20000 }, () => mutate(rng, corpus[rng.below(corpus.length)]));
    const rust = rustVerdicts(inputs);
    const differ = [];
    inputs.forEach((b, i) => { const js = jsVerdict(b); if (js !== rust[i]) differ.push(`${hex(b)}: js ${js}, rust ${rust[i]}`); });
    assert.deepEqual(differ.slice(0, 10), [], `${differ.length} of ${inputs.length} differ`);
    const accepted = rust.filter((x) => x === 'ok').length;
    assert.ok(accepted > 500 && accepted < inputs.length - 500, `${accepted} accepted: the mutations hit both outcomes`);
  });
});
