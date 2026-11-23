// test/gateway-endpoints.test.mjs -- #120: named virtual endpoints. A host with no file system (the memory host, a
// browser tab) registers `endpoints: { name: (duplex, who) => ... }`; a client reaches one with OpenEndpoint.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { generateKeyPair, exportPublicKeyRaw, exportPublicKeySSH, MSG } from '@johnhenry/wsh';
import { GatewayError } from '../src/gateway-client.mjs';

const enc = new TextEncoder();
const dec = new TextDecoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function readText(duplex) {
  const r = duplex.readable.getReader(); let s = '';
  for (;;) { const { value, done } = await r.read(); if (done) break; s += dec.decode(value, { stream: true }); }
  return s;
}

describe('named virtual endpoints (memory host)', () => {
  let keyPair; let raw; let host; const whos = [];
  before(async () => {
    keyPair = await generateKeyPair(true);
    raw = await exportPublicKeyRaw(keyPair.publicKey);
    host = createMemoryHost({
      auth: { authorizedKeys: [raw] },
      endpoints: {
        // a tiny "HTTP API": reads a request line, answers, closes
        api: async (duplex, who) => {
          whos.push(who);
          const r = duplex.readable.getReader(); const w = duplex.writable.getWriter();
          const { value } = await r.read();
          await w.write(enc.encode(`200 ${dec.decode(value)} for ${who.username}`));
          await w.close();
        },
        echo: async (duplex) => { const r = duplex.readable.getReader(); const w = duplex.writable.getWriter(); for (;;) { const { value, done } = await r.read(); if (done) break; await w.write(value); } await w.close(); },
        // a source faster than any reader: writes until the connection stops accepting
        firehose: async (duplex) => { const w = duplex.writable.getWriter(); const chunk = new Uint8Array(65536); try { for (;;) await w.write(chunk); } catch { /* closed */ } },
        vip: { authorize: (who) => who.username === 'alice', open: async (duplex) => { await duplex.writable.getWriter().close(); } },
        broken: () => { throw new Error('nope'); },
      },
    });
  });
  after(() => host.close());

  it('advertises endpoints and credit, but not TCP, DNS or unix sockets', async () => {
    const client = await host.connect({ username: 'alice', keyPair });
    try {
      assert.ok(client.hasFeature('gateway-endpoints'));
      assert.ok(client.hasFeature('gateway-credit'));
      assert.equal(client.hasFeature('gateway'), false);
      assert.equal(client.hasFeature('gateway-unix'), false);
      await assert.rejects(client.openTcp('example.com', 80), /did not advertise/);
      await assert.rejects(client.openUnix('/tmp/x'), /did not advertise/);
    } finally { await client.disconnect(); }
  });

  it('reaches a named endpoint with the same message flow, and the endpoint sees who is calling', async () => {
    const client = await host.connect({ username: 'alice', keyPair });
    try {
      const d = await client.openEndpoint('api');
      await d.writable.getWriter().write(enc.encode('GET /v1/status'));
      assert.equal(await readText(d), '200 GET /v1/status for alice');
      const who = whos.at(-1);
      assert.equal(who.username, 'alice');
      assert.equal(typeof who.fingerprint, 'string');
      assert.ok(who.fingerprint.length > 8);
    } finally { await client.disconnect(); }
  });

  it('only registered names exist (an allow-list by construction), and an unknown name is a policy refusal', async () => {
    const client = await host.connect({ username: 'alice', keyPair });
    try {
      for (const name of ['nothing', '__proto__', 'constructor', 'toString', 'api/../echo', 'API', '']) {
        await assert.rejects(client.openEndpoint(name || 'x'), (e) => e instanceof GatewayError && e.code === 4, name);
      }
      // the raw message too
      const inbox = []; client.onGatewayMessage = (m) => inbox.push(m);
      await client.sendControl({ type: MSG.OPEN_ENDPOINT, gateway_id: 5, name: '' });
      await sleep(50);
      assert.equal(inbox.find((m) => m.type === MSG.GATEWAY_FAIL)?.code, 4);
      // a memory host has no file system: OpenUnix, OpenTcp and ListenUnix are refused
      for (const msg of [{ type: MSG.OPEN_UNIX, gateway_id: 6, path: '/etc/passwd' }, { type: MSG.OPEN_TCP, gateway_id: 7, host: '127.0.0.1', port: 80 }]) await client.sendControl(msg);
      await client.sendControl({ type: MSG.LISTEN_UNIX, listener_id: 8, path: '/tmp/x' });
      await until(() => inbox.filter((m) => m.type === MSG.GATEWAY_FAIL).length >= 3 && inbox.some((m) => m.type === MSG.LISTEN_FAIL));
      assert.equal(inbox.some((m) => m.type === MSG.GATEWAY_OK), false);
    } finally { await client.disconnect(); }
  });

  it('lets the embedder authorise per call, and refuse by throwing', async () => {
    const bob = await generateKeyPair(true);
    const bobRaw = await exportPublicKeyRaw(bob.publicKey);
    const h2 = createMemoryHost({
      auth: { authorizedKeys: [raw, bobRaw] },
      endpoints: { vip: { authorize: (who) => who.username === 'alice', open: async (d) => { await d.writable.getWriter().close(); } }, broken: () => { throw new Error('nope'); } },
    });
    try {
      const a = await h2.connect({ username: 'alice', keyPair });
      const b = await h2.connect({ username: 'bob', keyPair: bob });
      (await a.openEndpoint('vip')).destroy();
      await assert.rejects(b.openEndpoint('vip'), (e) => e instanceof GatewayError && e.code === 4 && /refused/.test(e.message));
      await assert.rejects(a.openEndpoint('broken'), (e) => e instanceof GatewayError && e.code === 4);
      await a.disconnect(); await b.disconnect();
    } finally { await h2.close(); }
  });

  it('moves data both ways with backpressure: a large echo, and a stalled reader stops the endpoint', async () => {
    const client = await host.connect({ username: 'alice', keyPair });
    try {
      const d = await client.openEndpoint('echo');
      const w = d.writable.getWriter(); const r = d.readable.getReader();
      const payload = new Uint8Array(6 * 1024 * 1024).map((_, i) => i % 251);
      const writing = (async () => { for (let o = 0; o < payload.length; o += 100_000) await w.write(payload.subarray(o, o + 100_000)); await w.close(); })();
      const chunks = [];
      for (;;) { const { value, done } = await r.read(); if (done) break; chunks.push(value); }
      await writing;
      assert.deepEqual(Buffer.concat(chunks), Buffer.from(payload));
      // A firehose endpoint writes as fast as it can; with the client not reading, it must be held back.
      const f = await client.openEndpoint('firehose');
      await sleep(400);
      const before = process.memoryUsage().arrayBuffers;
      await sleep(600);
      assert.ok(process.memoryUsage().arrayBuffers - before < 16 * 1024 * 1024, 'the stalled reader holds the endpoint back; nothing piles up');
      f.destroy();
    } finally { await client.disconnect(); }
  });

  it('a client disconnect ends the endpoint\'s connection', async () => {
    let closedSeen;
    const seen = new Promise((r) => { closedSeen = r; });
    const h = createMemoryHost({ auth: { authorizedKeys: [raw] }, endpoints: { idle: (duplex) => { duplex.closed.then(closedSeen); } } });
    try {
      const c = await h.connect({ username: 'alice', keyPair });
      await c.openEndpoint('idle');
      await c.disconnect();
      await Promise.race([seen, sleep(3000).then(() => assert.fail('endpoint was never told the connection ended'))]);
    } finally { await h.close(); }
  });

  it('validates the option: names, handlers, and that it is its own option', () => {
    assert.throws(() => createMemoryHost({ endpoints: { 'bad name': () => {} } }), /endpoint name/);
    assert.throws(() => createMemoryHost({ endpoints: { ok: 'not a function' } }), /handler/);
    assert.throws(() => createMemoryHost({ endpoints: [] }), /object/);
    assert.doesNotThrow(() => createMemoryHost({ endpoints: {} }));
  });

  it('also works on the Node host, next to its TCP and unix rules', async () => {
    const kp = await generateKeyPair(true);
    const line = `${await exportPublicKeySSH(kp.publicKey)} alice`;
    const server = createWshServer({ auth: { authorizedKeys: line }, gateway: { allow: [], endpoints: { hello: async (d, who) => { const w = d.writable.getWriter(); await w.write(enc.encode(`hi ${who.username}`)); await w.close(); } } } });
    const { port } = await server.listen();
    const { WshClient } = await import('@johnhenry/wsh');
    const client = new WshClient();
    try {
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair: kp });
      assert.equal(await readText(await client.openEndpoint('hello')), 'hi alice');
    } finally { await client.disconnect(); await server.close(); }
  });
});

async function until(cond, ms = 3000) {
  const t0 = Date.now();
  while (!cond()) { if (Date.now() - t0 > ms) throw new Error('timed out'); await sleep(10); }
}
