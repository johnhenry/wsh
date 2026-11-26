/**
 * A whole wsh session over an arbitrary duplex (wsh #220, spec/duplex-binding.md).
 *
 * `@johnhenry/wsh/duplex` needs nothing but two functions per side: `send(bytes)` and `receive(bytes)`. Here the
 * duplex is a `MessageChannel` (the same shape as a worker, an iframe `MessagePort`, or a mesh data channel):
 * no WebSocket, no URL, no relay. Login, host-key proof, the sealed session and an `exec` channel all run over it.
 * The duplex is deliberately small (`maxMessageBytes: 512`), so a long output is cut into many messages and reassembled.
 */

import assert from 'node:assert/strict';
import { generateKeyPair, exportPublicKeyRaw, fingerprint } from '@johnhenry/wsh';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { serveWshOverDuplex, connectWshOverDuplex } from '@johnhenry/wsh/duplex';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const keyPair = await generateKeyPair(true);
const hostPair = await generateKeyPair(true);
const hostFingerprint = await fingerprint(await exportPublicKeyRaw(hostPair.publicKey));
const MAX = 512;

/** A host that serves one session over one MessageChannel; returns the client's end and what travelled. */
function wire() {
  const { port1: hostPort, port2: clientPort } = new MessageChannel();
  const traffic = { messages: 0, biggest: 0 };
  const count = (bytes) => { traffic.messages++; traffic.biggest = Math.max(traffic.biggest, bytes.length); };
  return {
    traffic,
    hostEnd: { send: (b) => { count(b); hostPort.postMessage(b); }, close: () => hostPort.close(), maxMessageBytes: MAX },
    clientEnd: { send: (b) => { count(b); clientPort.postMessage(b); }, close: () => clientPort.close(), maxMessageBytes: MAX },
    hostPort, clientPort,
  };
}
const feed = (port, target) => { port.onmessage = (e) => target.receive(e.data); port.unref?.(); };

const host = createMemoryHost({
  auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] }, hostKey: hostPair,
  exec: async (command, io) => { await io.write(`${command}: ${'x'.repeat(3000)}\n`); return 0; },
});

// ── 1. The session ────────────────────────────────────────────────────

console.log('1. a client logs in and runs a command over a MessageChannel');
const w = wire();
const served = serveWshOverDuplex(host, w.hostEnd);
feed(w.hostPort, served);
const link = connectWshOverDuplex(w.clientEnd, { username: 'alice', keyPair, expectHostKey: hostFingerprint, timeout: 5000 });
feed(w.clientPort, link);
const client = await link.connected;
assert.equal(client.sessionSealed, true, 'a duplex session is sealed or it is not served');
console.log(`   authenticated as alice; sealed: ${client.sessionSealed}; host key pinned: ${hostFingerprint.slice(0, 16)}...`);

const chunks = [];
const session = await client.openSession({ type: 'exec', command: 'build' });
session.onData = (d) => chunks.push(Buffer.from(d));
for (let i = 0; i < 100 && Buffer.concat(chunks).length < 3000; i++) await sleep(10);
const text = Buffer.concat(chunks).toString();
assert.ok(text.startsWith('build: xxx') && text.trimEnd().length >= 3000);
console.log(`   ALLOWED: ${text.length} bytes of output arrived intact in ${w.traffic.messages} duplex messages (largest ${w.traffic.biggest} bytes <= ${MAX})`);
assert.ok(w.traffic.biggest <= MAX);
await link.close();

// ── 2. What it refuses ────────────────────────────────────────────────

console.log('2. a client that does not name the host key');
const nothing = wire();
assert.throws(() => connectWshOverDuplex(nothing.clientEnd, { username: 'alice', keyPair }), (e) => {
  console.log(`   REFUSED before anything is sent: ${e.message.slice(0, 78)}...`);
  return e instanceof TypeError;
});
nothing.hostPort.close(); nothing.clientPort.close();

console.log('3. a client that names the WRONG host key');
const w3 = wire();
feed(w3.hostPort, serveWshOverDuplex(host, w3.hostEnd));
const wrong = connectWshOverDuplex(w3.clientEnd, { username: 'alice', keyPair, expectHostKey: 'ab'.repeat(32), timeout: 2000 });
feed(w3.clientPort, wrong);
const why3 = await wrong.connected.then(() => null, (e) => e);
console.log(`   REFUSED: ${String(why3?.message).slice(0, 90)}`);
assert.ok(why3);
await wrong.close().catch(() => {});

await host.close();
console.log('ok: a sealed, host-bound wsh session ran over a plain message channel');
process.exit(0);   // the MessagePorts are closed, but make the exit explicit
