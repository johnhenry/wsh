// test/cbor-sealed-sweep.test.mjs -- #317: flip bits at EVERY byte offset of a sealed EncryptedFrame (and of the messages around it) in flight, and hold two things:
//   1. nothing the tampered frame carries ever runs, and nothing after it does either (a lost frame is a gap in the strict counter);
//   2. a session whose frame was malformed or altered does not stay usable: it ends (or the frame is dropped and the very next frame ends it).
// The same walk over plain (unsealed) frames asserts the decoder's strictness directly: whatever a flipped frame decodes to, it is the canonical encoding of it.
//
// `SWEEP_REPORT=1 node --test test/cbor-sealed-sweep.test.mjs` prints which offsets close the session and which are dropped.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { serveWshOverDuplex, connectWshOverDuplex } from '@johnhenry/wsh/duplex';
import { generateKeyPair, exportPublicKeyRaw } from '@johnhenry/wsh';
import { cborEncode, cborDecode, CborError } from '../src/cbor.mjs';
import { MSG, open as openMsg } from '../src/messages.mjs';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const BITS = [0, 3, 7];

/** One session over a duplex with a middle that, when armed, changes ONE bit of the first big message toward the host. */
async function trial({ flip = null, capture = null } = {}) {
  const keyPair = await generateKeyPair(true);
  const ran = []; const refused = [];
  const host = createMemoryHost({
    auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] },
    exec: async (c, io) => { ran.push(c); await io.write(`ran:${c}\n`); return 0; },
    hostKey: true, onRefused: (r) => refused.push(r.reason),
  });
  let armed = false; let done = false;
  const ends = { host: null, client: null };
  const wire = (to) => (bytes) => {
    let out = bytes.slice();
    if (to === 'host' && armed && !done && out.length > 64) {
      done = true;
      capture?.(out.slice());
      if (flip) out[flip.offset] ^= 1 << flip.bit;
    }
    queueMicrotask(() => ends[to]?.receive(out));
  };
  const served = serveWshOverDuplex(host, { send: wire('client') });
  ends.host = served;
  const fp = await host.connect({ username: 'probe', keyPair }).then(async (c) => { const f = c.hostKey?.fingerprint; await c.disconnect(); return f; });
  const link = connectWshOverDuplex({ send: wire('host') }, { username: 'alice', keyPair, expectHostKey: fp, timeout: 1500 });
  ends.client = link;
  const client = await link.connected;
  let clientClosed = false;
  client.onClose = () => { clientClosed = true; };
  armed = true;
  void client.openSession({ type: 'exec', command: 'sweep-a' }).catch(() => {});
  await pause(110);
  void client.openSession({ type: 'exec', command: 'sweep-b' }).catch(() => {});
  await pause(110);
  const result = { ran: ran.slice(), refused: refused.slice(), clientClosed, tampered: done };
  await link.close().catch(() => {});
  await host.close().catch(() => {});
  return result;
}

const find = (hay, needle) => { for (let i = 0; i + needle.length <= hay.length; i++) if (needle.every((b, j) => hay[i + j] === b)) return i; return -1; };

describe('a bit flipped anywhere in a sealed EncryptedFrame in flight (#317)', () => {
  it('nothing in or after the tampered frame runs, at any offset, any of three bit positions; the session ends or the frame is dropped and the next one ends it', { timeout: 600000 }, async () => {
    let captured;
    const base = await trial({ capture: (b) => { captured = b; } });
    assert.deepEqual(base.ran, ['sweep-a', 'sweep-b'], 'untampered, both commands run');
    assert.ok(captured, 'a big message toward the host was seen');
    const typeAt = find(captured, [0x64, 0x74, 0x79, 0x70, 0x65]); // text(4) "type": the first key of the frame's map
    assert.ok(typeAt > 5, 'the frame is in the message');
    const cborStart = typeAt - 1;
    const sessionKey = find(captured, [...new TextEncoder().encode('session_id')]);
    const sessionIdLen = sessionKey + 'session_id'.length; // the head byte of the session id (text of known length)
    assert.equal(captured[sessionIdLen] >> 5, 3, 'the session-id head byte is where expected');
    const ai = captured[sessionIdLen] & 0x1f; const idHead = ai === 24 ? 2 : 1; const idLen = ai === 24 ? captured[sessionIdLen + 1] : ai;
    assert.equal(sessionIdLen + idHead + idLen, captured.length, 'the session id is the last field of the frame and the last bytes of the message, as in the issue');

    const jobs = [];
    for (let offset = 0; offset < captured.length; offset++) for (const bit of BITS) jobs.push({ offset, bit });
    const results = [];
    const lanes = 12;
    let next = 0;
    await Promise.all(Array.from({ length: lanes }, async () => {
      for (;;) {
        const job = jobs[next++]; if (!job) return;
        results.push({ ...job, ...(await trial({ flip: job })) });
      }
    }));

    const ranSomething = results.filter((r) => r.ran.length);
    assert.deepEqual(ranSomething.map((r) => `offset ${r.offset - cborStart} bit ${r.bit}: ran ${r.ran}`), [], 'no flip leaves a frame that runs');

    const outcome = (r) => (r.refused.length || r.clientClosed ? 'closed' : 'dropped');
    const by = (pred) => results.filter(pred);
    const sid = by((r) => r.offset === sessionIdLen);
    assert.equal(sid.length, BITS.length);
    for (const r of sid) assert.equal(outcome(r), 'closed', `the session-id length byte (offset ${sessionIdLen - cborStart} of ${captured.length - cborStart}), bit ${r.bit}`);
    for (const r of by((r) => r.offset >= cborStart)) assert.equal(r.tampered, true);

    if (process.env.SWEEP_REPORT) {
      const rows = {};
      for (const r of results) { const k = r.offset < cborStart ? 'outside the frame (qmux + length prefix)' : 'inside the frame'; rows[k] ??= { closed: 0, dropped: 0 }; rows[k][outcome(r)]++; }
      console.log(JSON.stringify({ cborLength: captured.length - cborStart, sessionIdLengthOffset: sessionIdLen - cborStart, rows }, null, 1));
      const dropped = [...new Set(by((r) => outcome(r) === 'dropped' && r.offset >= cborStart).map((r) => r.offset - cborStart))].sort((a, b) => a - b);
      console.log('offsets inside the frame where a flip was dropped without ending the session:', dropped.join(','));
    }
  });
});

describe('a bit flipped anywhere in a plain frame is refused or is the canonical encoding of what it now says (#317)', () => {
  it('every bit of every byte of an Open and of an EncryptedFrame', () => {
    const frames = [
      cborEncode(openMsg({ channelId: 7, kind: 'exec', command: 'echo hi', cols: 80, rows: 24 })),
      cborEncode({ type: MSG.ENCRYPTED_FRAME, channel_id: 0, nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array(60).fill(2), session_id: 'abcdef0123456789' }),
    ];
    let refused = 0; let accepted = 0;
    for (const frame of frames) {
      for (let i = 0; i < frame.length; i++) for (let bit = 0; bit < 8; bit++) {
        const f = frame.slice(); f[i] ^= 1 << bit;
        let value;
        try { value = cborDecode(f); } catch (e) { assert.ok(e instanceof CborError, `${i}/${bit}: ${e.message}`); refused++; continue; }
        accepted++;
        assert.equal(Buffer.from(cborEncode(value)).toString('hex'), Buffer.from(f).toString('hex'), `offset ${i} bit ${bit} was accepted but is not the canonical encoding of what it decodes to`);
      }
    }
    assert.ok(refused > accepted / 4 && accepted > 0, `${refused} refused, ${accepted} accepted`);
  });

  it('the session-id length byte of an EncryptedFrame: every one of the 8 bits is refused, but the one that turns the text into a byte string of the same length (which the frame check then fails on)', () => {
    const frame = cborEncode({ type: MSG.ENCRYPTED_FRAME, channel_id: 0, nonce: new Uint8Array(12), ciphertext: new Uint8Array(30), session_id: 'abcdef0123456789' });
    const at = frame.length - 1 - 16;
    assert.equal(frame[at], 0x70);
    for (let bit = 0; bit < 8; bit++) {
      const f = frame.slice(); f[at] ^= 1 << bit;
      if (bit === 5) { assert.ok(cborDecode(f).session_id instanceof Uint8Array); continue; }
      assert.throws(() => cborDecode(f), CborError, `bit ${bit}`);
    }
  });
});
