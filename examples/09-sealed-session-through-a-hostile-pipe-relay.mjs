/**
 * A sealed session through a hostile pipe relay (wsh #118, #155).
 *
 * A pipe relay pairs a host with an operator and copies bytes between them; it is a third party you may not trust.
 * Here the REAL relay runs in-process (`createInProcessPipeRelay` from `@johnhenry/wsh/testing`): its `recorded` list and `tap`
 * hook see every byte it copies, and may rewrite it. The host requires a sealed session, the operator pins the host key, and the exchange is
 * hybrid X25519 + ML-KEM-768 end to end. We then show (1) the relay's record holds no command or output, only the
 * pre-login handshake, (2) a relay that flips one bit in transit makes the session fail closed, and (3) a relay
 * that substitutes its own host is refused by the operator's pinned host key.
 */

import assert from 'node:assert/strict';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw } from '@johnhenry/wsh';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { pipeUrl, newRendezvousId } from '@johnhenry/wsh/pipe-relay';
import { createInProcessPipeRelay } from '@johnhenry/wsh/testing';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const keyPair = await generateKeyPair(true);
const raw = await exportPublicKeyRaw(keyPair.publicKey);

/** One host and one operator meeting through a relay whose `tap` is given. Returns what the operator needs. */
async function meet(tap, { pinTo } = {}) {
  const relay = await createInProcessPipeRelay({ tap });
  const ran = []; const logs = [];
  const host = createMemoryHost({
    auth: { authorizedKeys: [raw] }, hostKey: true, dataStreams: false, sealSession: 'require', onLog: (l) => logs.push(l),
    exec: async (command, io) => { ran.push(command); await io.write(`output-of:${command}\n`); return 0; },
  });
  const hostFingerprint = await host.hostFingerprint;   // the host made its own key; this is what an operator pins
  const pin = pinTo ?? hostFingerprint;
  const id = newRendezvousId();
  void host.accept(new relay.WebSocket(pipeUrl('ws://relay.test', id, 'host')), { remote: { address: 'pipe' } });
  const client = new WshClient({ transportFactories: {
    ws: () => new WebSocketTransport({ WebSocket: relay.WebSocket }), wt: () => { throw new Error('no webtransport'); },
  } });
  const connect = () => client.connect(pipeUrl('ws://relay.test', id), {
    transport: 'ws', username: 'alice', keyPair, sealSession: true,          // seal or fail: never talk in the clear
    expectHostKey: pin,                                                        // and pin who we are talking to
  });
  const close = async () => { await client.disconnect().catch(() => {}); await host.close(); await relay.close(); };
  return { relay, host, client, connect, ran, logs, close, hostFingerprint };
}

// ── 1. An honest-but-curious relay: it records, it cannot read ─────────

console.log('1. a relay that records everything it copies');
const a = await meet(null);
await a.connect();
assert.equal(a.client.sessionSealed, true);
const out = [];
const session = await a.client.openSession({ type: 'exec', command: 'transfer-secret-4242' });
session.onData = (d) => out.push(Buffer.from(d));
for (let i = 0; i < 100 && !Buffer.concat(out).toString().includes('output-of:'); i++) await sleep(10);
assert.match(Buffer.concat(out).toString(), /output-of:transfer-secret-4242/, 'the operator got its answer');
const seen = Buffer.concat(a.relay.recorded.map((r) => Buffer.from(r.bytes))).toString('latin1');
console.log(`   relay copied ${a.relay.recorded.length} messages, ${seen.length} bytes`);
console.log(`   relay saw the command?  ${seen.includes('transfer-secret-4242')}   the output? ${seen.includes('output-of')}`);
assert.ok(!seen.includes('transfer-secret-4242'), 'REFUSED: the relay never saw the command');
assert.ok(!seen.includes('output-of'), 'REFUSED: the relay never saw the output');
console.log(`   relay saw the login name before sealing began? ${seen.includes('alice')} (the pre-login handshake is not secret)`);
await a.close();

// ── 2. A tampering relay: one flipped bit and the session fails closed ──

console.log('2. a relay that flips one bit of the first message to the host after login');
let armed = false; let flipped = 0;
const tap = ({ to, bytes }) => {
  if (!armed || to !== 'host' || flipped) return undefined;
  flipped++;
  const bad = Uint8Array.from(bytes); bad[bad.length >> 1] ^= 1;
  return bad;
};
const b = await meet(tap);
await b.connect();                                // login and key exchange pass untouched
const closed = new Promise((r) => { b.client.onClose = r; });
armed = true;
const victim = await b.client.openSession({ type: 'exec', command: 'transfer-secret-4242' }).catch((e) => e);
const how = await Promise.race([closed.then(() => 'connection closed'), sleep(1500).then(() => 'timed out')]);
console.log(`   the open ${victim instanceof Error ? 'failed' : 'was sent'}; ${how}; host ran ${JSON.stringify(b.ran)}`);
assert.equal(flipped, 1, 'the tap altered one message');
assert.deepEqual(b.ran, [], 'REFUSED: nothing the host could not authenticate was executed');
assert.ok(b.logs.some((l) => /sealed frame did not open/.test(l)), 'the host named why it closed');
assert.equal(b.client.state, 'closed');
await b.close();

// ── 3. An impostor at the far end: the pinned host key does not match ───

console.log('3. a relay that puts its own host in place of the real one');
const c = await meet(null, { pinTo: a.hostFingerprint });   // this host has another key; we pinned the REAL host's fingerprint
const refusal = await c.connect().then(() => null, (e) => e);
console.log(`   REFUSED: ${refusal?.message}`);
assert.ok(refusal, 'a host key that is not the pinned one is never accepted');
assert.deepEqual(c.ran, []);
await c.close();

console.log('ok: the relay copied bytes it could not read, and a bit it changed killed the session instead of altering it');
