#!/usr/bin/env node
/**
 * Golden CBOR vectors for every wsh control message (#317).
 *
 * For each message type in spec/wsh-v1.yaml this builds two samples (`min`: required fields only; `full`: every field, with
 * integers at the head-size edges) plus a set of JSON-RPC (rpc channel) messages, encodes them with the JS encoder
 * (`src/cbor.mjs`) and records the bytes as hex under `js`. `crates/wsh-core/examples/cbor_vectors.rs` then reads the same
 * file, decodes each `js` vector with the (lenient) typed Rust decoder, re-encodes it with the Rust encoder and records that
 * under `rust`. Both write canonical CBOR (#325). `rust_released` is what the SHIPPED Rust encoder wrote (recorded once, before the Envelope encoder was fixed to write a definite map; never regenerated); `js_released` is what the JS encoder of npm 0.62.x wrote (insertion order, float64; recorded once before the canonical encoder, never regenerated). `test/cbor-vectors.test.mjs` and the Rust test `codec::tests::golden_vectors` hold BOTH sets against the strict
 * decoder, so a change to either encoder that stops being accepted by either decoder fails.
 *
 *   node scripts/cbor-vectors.mjs            # write the `js` side to spec/cbor-vectors.json (keeps an existing `rust` side)
 *   node scripts/cbor-vectors.mjs --check    # exit 1 if the `js` side differs from what the encoder emits now
 *   cargo run -p wsh-core --example cbor_vectors   # then add the `rust` side
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { cborEncode } from '../src/cbor.mjs';

const root = new URL('..', import.meta.url);
const SPEC = fileURLToPath(new URL('spec/wsh-v1.yaml', root));
const OUT = fileURLToPath(new URL('spec/cbor-vectors.json', root));

/** A reader for the fixed-indentation subset of the spec that matters here: enums, message fields and nested types. */
export function readSpec(text = readFileSync(SPEC, 'utf8')) {
  const lines = text.split('\n');
  const spec = { enums: {}, messages: [], nested: {} };
  let section = null; let cur = null; let fieldsIndent = -1; let field = null; let fieldIndent = -1; let enumName = null;
  for (const raw of lines) {
    if (!raw.trim() || /^\s*#/.test(raw)) continue;
    const indent = raw.match(/^ */)[0].length;
    const t = raw.trim();
    if (indent === 0) { section = t.replace(/:.*/, ''); cur = field = null; fieldsIndent = -1; continue; }
    if (section === 'enums') {
      if (indent === 2 && t.endsWith(':')) enumName = t.slice(0, -1);
      else if (indent === 4 && t.startsWith('values:')) spec.enums[enumName] = t.slice(7).trim().replace(/^\[|\]$/g, '').split(',').map((s) => s.trim());
      continue;
    }
    if (section !== 'messages' && section !== 'nested_types') continue;
    const nameIndent = section === 'messages' ? 4 : 2;
    if (indent === nameIndent && t.endsWith(':')) {
      cur = { name: t.slice(0, -1), code: null, fields: [] };
      if (section === 'messages') spec.messages.push(cur); else spec.nested[cur.name] = cur;
      field = null; fieldsIndent = -1; continue;
    }
    if (!cur) continue;
    if (indent === nameIndent + 2) {
      const code = t.match(/^code:\s*(\S+)/); if (code) cur.code = Number(code[1]);
      fieldsIndent = t === 'fields:' ? indent + 2 : -1; field = null; continue;
    }
    if (fieldsIndent > 0 && indent === fieldsIndent && t.endsWith(':')) { field = { name: t.slice(0, -1), type: 'string', required: false, hasDefault: false }; cur.fields.push(field); fieldIndent = indent; continue; }
    if (field && indent === fieldIndent + 2) {
      let m;
      if ((m = t.match(/^type:\s*(.+)$/))) field.type = m[1].replace(/^["']|["']$/g, '');
      else if ((m = t.match(/^required:\s*(\w+)/))) field.required = m[1] === 'true';
      else if (t.startsWith('default:')) field.hasDefault = true;
    }
  }
  return spec;
}

const INTS = [0, 1, 23, 24, 255, 256, 65535, 65536, 2 ** 32 - 1, 2 ** 32, 2 ** 40];
let ints = 0;
const nextInt = (min = 0) => { const v = INTS[ints++ % INTS.length]; return v < min ? min : v; };

function sample(spec, type, depth = 0) {
  const arr = type.match(/^(.*)\[\]$/);
  if (arr) return [sample(spec, arr[1], depth + 1), sample(spec, arr[1], depth + 1)];
  if (type === 'string') return 'sample text é世';
  if (type === 'bool') return true;
  if (type === 'bytes') return Uint8Array.from({ length: 33 }, (_, i) => (i * 7) & 255);
  if (type === 'u8' || type === 'u16') return Math.min(nextInt(), 65535);
  if (type === 'u32') return Math.min(nextInt(), 2 ** 32 - 1);
  if (type === 'u64') return nextInt();
  if (type === 'i32') return -1 - Math.min(nextInt(), 2 ** 31 - 1);
  if (type === 'f64') return 2.5;
  if (type === 'json') return { a: [1, 'x', null, true, 1.5, -7, { deep: [] }], b: 'text' };
  if (type.startsWith('map<')) return { k1: 'v1', k2: 'v2' };
  if (spec.enums[type]) return spec.enums[type][0];
  if (spec.nested[type]) { if (depth > 4) return {}; return build(spec, spec.nested[type], true, depth + 1); }
  throw new Error(`no sample for type ${type}`);
}

function build(spec, def, full, depth = 0) {
  const out = {};
  for (const f of def.fields) {
    if (!full && !f.required) continue;
    out[f.name] = sample(spec, f.type, depth);
  }
  return out;
}

const hex = (b) => Buffer.from(b).toString('hex');

export function jsVectors() {
  ints = 0;
  const spec = readSpec();
  const vectors = [];
  for (const def of spec.messages) {
    for (const kind of ['min', 'full']) {
      const msg = { type: def.code, ...build(spec, def, kind === 'full') };
      vectors.push({ name: def.name, kind, code: def.code, layer: 'control', js: hex(cborEncode(msg)) });
    }
  }
  // rpc channel items (a CBOR sequence of JSON-RPC 2.0 messages, bytes native): the Rust side encodes the same with `encode_cbor`.
  const rpc = [
    ['rpc-request', { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { cursor: null } }],
    ['rpc-request-big-id', { jsonrpc: '2.0', id: 70000, method: 'x', params: [1, -2, 3.5, 'a'] }],
    ['rpc-result', { jsonrpc: '2.0', id: 'abc', result: { ok: true, n: 2 ** 33, bytes: Uint8Array.of(1, 2, 3), list: [], map: {} } }],
    ['rpc-error', { jsonrpc: '2.0', id: 2, error: { code: -32601, message: 'no such method', data: { reason: 'x' } } }],
    ['rpc-notification', { jsonrpc: '2.0', method: 'notifications/x' }],
  ];
  for (const [name, msg] of rpc) vectors.push({ name, kind: 'rpc', layer: 'rpc', js: hex(cborEncode(msg)) });
  return vectors;
}

/** The recorded encoder sides of an existing vector: kept when the JS side is regenerated. */
const pick = (v) => (v ? Object.fromEntries(["rust", "rust_error", "rust_released", "js_released"].filter((k) => v[k] !== undefined).map((k) => [k, v[k]])) : {});

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let prev = { vectors: [] };
  try { prev = JSON.parse(readFileSync(OUT, 'utf8')) } catch (e) { if (e.code !== 'ENOENT') throw e }
  const byKey = new Map(prev.vectors.map((v) => [`${v.name}/${v.kind}`, v]));
  const vectors = jsVectors().map((v) => ({ ...v, ...pick(byKey.get(`${v.name}/${v.kind}`)) }));
  const doc = { note: 'Golden CBOR vectors (#317): hex of what each encoder emits. Regenerate with scripts/cbor-vectors.mjs, then the Rust example.', vectors };
  if (process.argv.includes('--check')) {
    const same = vectors.length === prev.vectors.length && vectors.every((v, i) => v.js === prev.vectors[i].js && v.name === prev.vectors[i].name);
    if (!same) { console.error('spec/cbor-vectors.json is stale: run node scripts/cbor-vectors.mjs'); process.exit(1); }
    console.log(`cbor vectors current (${vectors.length})`);
  } else {
    writeFileSync(OUT, JSON.stringify(doc, null, 1) + '\n');
    console.log(`wrote ${vectors.length} vectors to ${OUT}`);
  }
}
