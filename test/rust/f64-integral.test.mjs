// test/rust/f64-integral.test.mjs -- a JS peer writes an integral number as a CBOR integer (`cpu: 1` is `01`, the JS decoder cannot tell it from
// `f93c00`), and the Rust typed decode of an `f64` field must accept it (#335). Every `f64` field in spec/wsh-v1.yaml is covered, with what the JS
// encoder writes; other fields stay as strict as before. The Rust side is `crates/wsh-core/examples/decode_envelope.rs`.
//
// Prerequisite: cargo build -p wsh-core --example decode_envelope   (or WSH_DECODE_ENVELOPE_BIN=<path>; default target/debug/examples/decode_envelope).
import { describe, it } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { cborEncode } from '../../src/cbor.mjs';
import { MSG } from '../../src/messages.gen.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = process.env.WSH_DECODE_ENVELOPE_BIN || path.join(REPO_ROOT, 'target', 'debug', 'examples', 'decode_envelope');
const hex = (b) => Buffer.from(b).toString('hex');
const run = (inputs) => {
  const r = spawnSync(BIN, [], { input: inputs.map(hex).join('\n') + '\n', encoding: 'utf8', maxBuffer: 1 << 26 });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim().split('\n');
};

/** Every `type: f64` field of the spec: [{ owner, field }]. */
function specF64Fields() {
  const found = [];
  let owner = null;
  let field = null;
  for (const line of readFileSync(path.join(REPO_ROOT, 'spec', 'wsh-v1.yaml'), 'utf8').split('\n')) {
    let m = /^ {4}(\w+):\s*$/.exec(line);
    if (m) owner = m[1];
    m = /^ {8}(\w+):\s*$/.exec(line);
    if (m) field = m[1];
    if (/^ {10}type: f64\s*$/.test(line)) found.push({ owner, field });
  }
  return found;
}

/** A complete message of each owner that has an f64 field, with the f64 field set to `value` (`undefined` leaves it out). */
const set = (field, value) => (value === undefined ? {} : { [field]: value });
const BUILDERS = {
  Metrics: (field, value) => ({ type: MSG.METRICS, ...set(field, value) }),
  CopilotSuggest: (field, value) => ({ type: MSG.COPILOT_SUGGEST, session_id: 's', suggestion: 'x', ...set(field, value) }),
  NodeAnnounce: (field, value) => ({ type: MSG.NODE_ANNOUNCE, node_id: 'n', endpoint: 'e', capacity: 1, ...set(field, value) }),
};
const REQUIRED = { Metrics: false, CopilotSuggest: false, NodeAnnounce: true };

const f64Bytes = (v) => { const b = Buffer.alloc(9); b[0] = 0xfb; b.writeDoubleBE(v, 1); return b; };
const f32Bytes = (v) => { const b = Buffer.alloc(5); b[0] = 0xfa; b.writeFloatBE(v, 1); return b; };

/** Replace the encoded value of `field` in a message the JS encoder wrote by raw CBOR bytes (the probe value is `1a 7fffffff`). */
function withRaw(msg, field, raw) {
  const enc = Buffer.from(cborEncode({ ...msg, [field]: 0x7fff_ffff }));
  const key = Buffer.concat([Buffer.from([0x60 + field.length]), Buffer.from(field)]);
  const at = enc.indexOf(key) + key.length;
  assert.equal(enc[at], 0x1a);
  return Buffer.concat([enc.subarray(0, at), raw, enc.subarray(at + 5)]);
}

describe('Rust typed decode of an f64 field accepts what a JS peer writes (#335)', { skip: existsSync(BIN) ? false : `no ${BIN}: cargo build -p wsh-core --example decode_envelope` }, () => {
  it('the spec has exactly the f64 fields this test builds messages for', () => {
    assert.deepEqual(specF64Fields().map((f) => `${f.owner}.${f.field}`).sort(), ['CopilotSuggest.confidence', 'Metrics.cpu', 'NodeAnnounce.load']);
  });

  for (const { owner, field } of specF64Fields()) {
    const build = BUILDERS[owner];

    for (const value of [0, 1, 2, 100, 65536, 4294967296, -1, 0.5, 1.5, 0.25]) {
      it(`${owner}.${field} = ${value}, as the JS encoder writes it`, () => {
        // the JS encoder writes an integral value as an integer item, a fractional one as a float
        const bytes = cborEncode(build(field, value));
        const [verdict] = run([bytes]);
        assert.match(verdict, /^ok /, `${hex(bytes)} -> ${verdict}`);
        assert.equal(JSON.parse(verdict.slice(3))[field], value);
      });
    }

    it(`${owner}.${field}: the float forms of an integral value (a Rust or a canonical encoder) are read as before`, () => {
      const msg = build(field, 1);
      for (const raw of [Buffer.from([0xf9, 0x3c, 0x00]), f32Bytes(1), f64Bytes(1)]) {
        const [verdict] = run([withRaw(msg, field, raw)]);
        assert.match(verdict, /^ok /, `${hex(raw)} -> ${verdict}`);
        assert.equal(JSON.parse(verdict.slice(3))[field], 1);
      }
    });

    it(`${owner}.${field}: a text, a boolean, an array, a byte string and a map are still refused`, () => {
      for (const bad of ['1', true, [1], new Uint8Array([1]), {}]) {
        const [verdict] = run([cborEncode(build(field, bad))]);
        assert.match(verdict, /^err /, `${JSON.stringify(bad)} -> ${verdict}`);
      }
      assert.match(run([cborEncode(build(field, undefined))])[0], REQUIRED[owner] ? /^err / : /^ok /, 'an absent field');
    });
  }

  it('fields that are not f64 are untouched: a float in a u64, a u32 and a string field is still refused', () => {
    for (const msg of [{ type: MSG.METRICS, memory: 1.5 }, { type: MSG.METRICS, sessions: 0.5 }, { type: MSG.METRICS, rtt: 2.5 }, { type: MSG.COPILOT_SUGGEST, session_id: 1, suggestion: 'x' }]) {
      assert.match(run([cborEncode(msg)])[0], /^err /, JSON.stringify(msg));
    }
    assert.match(run([withRaw({ type: MSG.METRICS }, 'memory', f64Bytes(1))])[0], /^err /, 'an integral float in a u64 field');
  });
});
