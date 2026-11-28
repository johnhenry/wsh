#!/usr/bin/env node
/**
 * What the CBOR encoder of an OLDER @johnhenry/wsh emits, held against the strict decoder in this tree (#317).
 *
 *   mkdir /tmp/old-0.50.0 && cd /tmp/old-0.50.0 && npm install --ignore-scripts @johnhenry/wsh@0.50.0
 *   node scripts/cbor-interop-old.mjs /tmp/old-0.50.0 [/tmp/old-0.13.0 ...]
 *
 * For each install it encodes every golden vector's message (spec/cbor-vectors.json, read back by this tree's decoder) and a table of edge values
 * (integers at every head-size edge, floats, strings, nesting, empty containers, undefined, typed arrays) with THAT version's `cborEncode`, then
 * checks that this tree's `cborDecode` accepts each result and reads the same value. The other direction too (#325): THAT version's `cborDecode` must read
 * what this tree's canonical encoder writes (sorted keys, shortest floats) for every value, and the Rust-written canonical bytes of every golden vector, and read the
 * same value. Prints one line per install and exits 1 on any refusal.
 */
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { cborEncode as newEncode, cborDecode } from '../src/cbor.mjs';

const vectors = JSON.parse(readFileSync(new URL('../spec/cbor-vectors.json', import.meta.url), 'utf8')).vectors;
const hex = (b) => Buffer.from(b).toString('hex');
const edge = [
  0, 1, 23, 24, 25, 255, 256, 65535, 65536, 2 ** 31, 2 ** 32 - 1, 2 ** 32, 2 ** 40, 2 ** 53 - 1, -1, -23, -24, -25, -255, -256, -257, -65536, -65537, -(2 ** 32), -(2 ** 32) - 1,
  0.5, 1.5, -2.5, 3.141592653589793, 1e-7, 1e300, 2 ** 53, 2 ** 64, -(2 ** 63), Infinity, -Infinity, NaN, -0,
  '', 'a', 'a'.repeat(23), 'a'.repeat(24), 'a'.repeat(255), 'a'.repeat(256), 'héllo 世界 \u{1f600}', '﻿bom first', '\u0000nul',
  true, false, null, undefined, [], {}, [[]], [[[]]], { a: {} }, [1, 'two', null, [3.5]], { type: 1, n: [1, 2, 3], nested: { x: null, y: [true, false] } },
  new Uint8Array(0), new Uint8Array(23), new Uint8Array(24), new Uint8Array(300).fill(255), new Uint16Array([1, 2]),
  Object.fromEntries(Array.from({ length: 24 }, (_, i) => [`k${i}`, i])), Array.from({ length: 24 }, (_, i) => i), 'x'.repeat(70000),
];

let bad = 0;
for (const dir of process.argv.slice(2)) {
  const pkgRoot = path.join(path.resolve(dir), 'node_modules', '@johnhenry', 'wsh');
  const version = JSON.parse(readFileSync(path.join(pkgRoot, 'package.json'), 'utf8')).version;
  const old = await import(pathToFileURL(path.join(pkgRoot, 'src', 'cbor.mjs')).href);
  let same = 0; let differentButAccepted = 0; let refused = 0; let total = 0; let oldReads = 0;
  // key order is not part of a value (the encoders now sort; the old ones did not), so the comparison sorts keys
  const flat = (v) => JSON.stringify(v, (k, x) => (typeof x === 'number' && !Number.isFinite(x) ? String(x) : typeof x === 'bigint' ? `${x}n` : x instanceof Uint8Array ? hex(x) : x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) : x));
  /** The old decoder must read these bytes, and to the value this tree reads. */
  const oldReads_ = (label, bytes) => {
    let got;
    try { got = old.cborDecode(bytes); } catch (e) { refused++; bad++; notes.push(`${label}: the old decoder refuses ${hex(bytes).slice(0, 80)}: ${e.message}`); return; }
    oldReads++;
    if (flat(got) !== flat(cborDecode(bytes))) { bad++; notes.push(`${label}: the old decoder reads ${hex(bytes).slice(0, 80)} as a different value`); }
  };
  const notes = [];
  const check = (label, value) => {
    total++;
    const oldBytes = old.cborEncode(value);
    const mine = newEncode(value);
    oldReads_(label + ' (this encoder)', mine);
    let read;
    try { read = cborDecode(oldBytes); } catch (e) { refused++; bad++; notes.push(`${label}: refused (${e.code}) ${hex(oldBytes).slice(0, 80)}`); return; }
    if (hex(oldBytes) === hex(mine)) same++;
    else { differentButAccepted++; notes.push(`${label}: old ${hex(oldBytes).slice(0, 60)} / now ${hex(mine).slice(0, 60)}`); }
    const want = cborDecode(mine);
    if (flat(read) !== flat(want)) {
      bad++; notes.push(`${label}: the old bytes decode to a different value`);
    }
  };
  for (const v of vectors) check(`${v.name}/${v.kind}`, cborDecode(Uint8Array.from(Buffer.from(v.js_released ?? v.js, 'hex'))));
  for (const v of vectors) { oldReads_(`${v.name}/${v.kind} js`, Uint8Array.from(Buffer.from(v.js, 'hex'))); oldReads_(`${v.name}/${v.kind} rust`, Uint8Array.from(Buffer.from(v.rust, 'hex'))); }
  edge.forEach((v, i) => check(`edge[${i}]`, v));
  console.log(`@johnhenry/wsh ${version}: ${total} values encoded by that version, ${same} byte-identical to this encoder, ${differentButAccepted} different but accepted and equal, ${refused} refused by a decoder; ${oldReads} reads by that version's decoder of this tree's bytes`);
  for (const n of notes.slice(0, 12)) console.log(`    ${n}`);
}
if (bad) process.exit(1);
