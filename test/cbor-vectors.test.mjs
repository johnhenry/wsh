// test/cbor-vectors.test.mjs -- the interop proof for the strict CBOR decoder (#317): spec/cbor-vectors.json holds what EVERY encoder in the repo
// emits for every message type (the JS encoder: `js`; the Rust encoder, re-encoding the same messages: `rust`; recorded before the decoder was
// tightened), and the strict decoder must accept all of it. It also pins the encoders themselves: what the JS encoder writes today equals the
// recorded bytes, so a change to either encoder is a conscious update of the file.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { cborEncode, cborDecode, CborError } from '../src/cbor.mjs';
import { jsVectors, readSpec } from '../scripts/cbor-vectors.mjs';

const doc = JSON.parse(readFileSync(new URL('../spec/cbor-vectors.json', import.meta.url), 'utf8'));
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

describe('golden vectors: what the encoders emit, the strict decoder accepts', () => {
  it('the file covers every message type in the spec, min and full, and the rpc items', () => {
    const spec = readSpec();
    assert.ok(spec.messages.length >= 100, `spec read: ${spec.messages.length} messages`);
    for (const m of spec.messages) for (const kind of ['min', 'full']) {
      assert.ok(doc.vectors.some((v) => v.name === m.name && v.kind === kind && v.code === m.code), `no ${kind} vector for ${m.name}`);
    }
    assert.ok(doc.vectors.filter((v) => v.layer === 'rpc').length >= 5);
  });

  it('every vector has every encoder side: js, rust (this tree) and rust_released (recorded from the shipped encoder before this change)', () => {
    for (const v of doc.vectors) { assert.ok(v.js, `${v.name}/${v.kind}: js`); assert.ok(v.rust, `${v.name}/${v.kind}: rust (${v.rust_error ?? 'missing'})`); assert.ok(v.rust_released, `${v.name}/${v.kind}: rust_released`); }
  });

  it('what the JS encoder writes now is what was recorded', () => {
    const now = jsVectors();
    assert.equal(now.length, doc.vectors.length);
    for (let i = 0; i < now.length; i++) assert.equal(now[i].js, doc.vectors[i].js, `${now[i].name}/${now[i].kind}`);
  });

  for (const side of ['js', 'rust', 'rust_released']) {
    it(`the strict decoder accepts every vector the ${side} encoder wrote`, () => {
      const refused = [];
      for (const v of doc.vectors) {
        try { cborDecode(bytes(v[side])); } catch (e) { refused.push(`${v.name}/${v.kind}: ${e.code ?? e.message}`); }
      }
      assert.deepEqual(refused, []);
    });
  }

  it('the JS and the Rust bytes of a message decode to the same message (Rust adds defaulted fields, never changes one)', () => {
    for (const v of doc.vectors) {
      const js = cborDecode(bytes(v.js));
      for (const side of ['rust', 'rust_released']) {
        const other = cborDecode(bytes(v[side]));
        for (const k of Object.keys(js)) assert.deepEqual(other[k], js[k], `${v.name}/${v.kind}.${k} (${side})`);
      }
    }
  });

  it('every control vector, JS and Rust, is a map whose first key is "type"', () => {
    for (const v of doc.vectors.filter((x) => x.layer === 'control')) for (const side of ['js', 'rust', 'rust_released']) {
      assert.equal(Object.keys(cborDecode(bytes(v[side])))[0], 'type', `${v.name}/${v.kind}/${side}`);
    }
  });

  it('encoders: the JS encoder and the current Rust encoder write definite lengths only; the RELEASED Rust encoder wrote an indefinite top-level map for every control message', () => {
    const control = doc.vectors.filter((v) => v.layer === 'control');
    assert.equal(doc.vectors.filter((v) => v.js.startsWith('bf')).length, 0, 'the JS encoder never writes an indefinite length');
    assert.equal(doc.vectors.filter((v) => v.rust.startsWith('bf')).length, 0, 'the Rust encoder in this tree (Envelope::serialize) writes a definite map');
    assert.equal(control.filter((v) => v.rust_released.startsWith('bf')).length, control.length, 'serde(flatten) made ciborium write 0xbf ... 0xff');
    assert.equal(doc.vectors.filter((v) => v.layer === 'rpc' && v.rust_released.startsWith('bf')).length, 0, 'rpc items were never affected');
  });

  it('with the legacy exception switched off, every current vector is canonical and every released-Rust control vector is refused for that one reason', () => {
    for (const v of doc.vectors) { cborDecode(bytes(v.js), { legacyIndefiniteMap: false }); cborDecode(bytes(v.rust), { legacyIndefiniteMap: false }); }
    for (const v of doc.vectors) {
      if (v.layer === 'control') assert.throws(() => cborDecode(bytes(v.rust_released), { legacyIndefiniteMap: false }), (e) => e instanceof CborError && e.code === 'indefinite-length', v.name);
      else cborDecode(bytes(v.rust_released), { legacyIndefiniteMap: false });
    }
  });

  it('every encoder output re-encodes to itself through the JS encoder (the JS encoder is canonical for what it decodes): ints, lengths, keys in order', () => {
    for (const v of doc.vectors) {
      const again = cborEncode(cborDecode(bytes(v.js)));
      assert.equal(Buffer.from(again).toString('hex'), v.js, `${v.name}/${v.kind}`);
    }
  });
});
