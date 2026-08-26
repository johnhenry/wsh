/**
 * Frames survive a fragmented transport.
 *
 * The wsh wire format is length-prefixed CBOR: [4-byte be32 length][CBOR payload]
 * (see spec/wsh-v1.md, "Transport Bindings"). A real network delivers bytes in
 * arbitrary chunks, so the FrameDecoder must reassemble frames no matter how
 * the stream is sliced. This example encodes a batch of protocol messages,
 * shreds the byte stream into awkward fragments, and shows every message
 * arrives intact and in order.
 */

import assert from 'node:assert/strict';
import {
  frameEncode, FrameDecoder,
  MSG, hello, ping, open, sessionData, exit, msgName,
} from '@johnhenry/wsh';

// ── Encode a realistic message sequence ───────────────────────────────

const outgoing = [
  hello({ username: 'demo', features: ['mcp'], authMethod: 'pubkey' }),
  open({ kind: 'exec', command: 'uname -a', cols: 80, rows: 24 }),
  sessionData({ channelId: 1, data: new TextEncoder().encode('Linux wsh 6.1\n') }),
  ping({ id: 7 }),
  exit({ channelId: 1, code: 0 }),
];

// Concatenate all frames into one continuous byte stream, as a transport would.
const frames = outgoing.map(frameEncode);
const stream = new Uint8Array(frames.reduce((n, f) => n + f.length, 0));
let offset = 0;
for (const f of frames) { stream.set(f, offset); offset += f.length; }

console.log(`encoded ${outgoing.length} messages into ${stream.length} bytes`);

// Spec check: every frame starts with a be32 length prefix.
const firstLen = new DataView(frames[0].buffer).getUint32(0);
assert.equal(firstLen, frames[0].length - 4);
console.log(`first frame: ${firstLen}-byte CBOR payload after 4-byte be32 prefix`);

// ── Deliver the stream in hostile fragment sizes ──────────────────────

// Worst cases: 1-byte drips (splits every length prefix) and a split that
// lands mid-payload.
for (const chunkSize of [1, 3, 5, 1024]) {
  const decoder = new FrameDecoder();
  const received = [];
  for (let i = 0; i < stream.length; i += chunkSize) {
    received.push(...decoder.feed(stream.subarray(i, i + chunkSize)));
  }

  assert.equal(received.length, outgoing.length);
  assert.equal(decoder.pending, 0); // no leftover bytes
  assert.equal(received[0].type, MSG.HELLO);
  assert.equal(received[0].username, 'demo');
  assert.equal(received[4].type, MSG.EXIT);
  assert.equal(received[4].code, 0);
  console.log(
    `chunk size ${String(chunkSize).padStart(4)}: ` +
    `${received.length}/${outgoing.length} messages reassembled ` +
    `(${received.map((m) => msgName(m.type)).join(' → ')})`
  );
}

// Binary payloads survive too: SESSION_DATA carries raw bytes.
const decoder = new FrameDecoder();
const [roundTripped] = decoder.feed(frameEncode(outgoing[2]));
assert.equal(new TextDecoder().decode(roundTripped.data), 'Linux wsh 6.1\n');
console.log('binary SESSION_DATA payload round-tripped byte-for-byte');

console.log('ok: frames survive fragmented delivery');
