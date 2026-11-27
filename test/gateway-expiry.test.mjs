// test/gateway-expiry.test.mjs -- #297: a grant's `expires` ends the gateway connections its holder already has open.
//
// A key's `expires` (an authorized_keys option), the `expires` of what `authorize()` returns, and the `expires` of what a reverse host's
// `accept()` returns were all checked per request, so a connection opened a second before the expiry went on for as long as its two ends
// liked. Now the host ends them when the expiry passes: one timer for the holder of the grant (not one per gateway connection) that,
// when it fires, ends every gateway connection and listener of that connection with GatewayClose "key expired". A GatewayClose is a half-close
// to a peer that predates this, and the second one ("discarded", the documented "I lost my reader") frees a peer that knows it at once.
//
// Nothing is slept for: each wait is for the very event under test (the close arriving), bounded.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG } from '@johnhenry/wsh';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 8000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
const enc = new TextEncoder();
/** An instant a second or two ahead, in whole seconds (an expiry has no finer grain). */
const soon = () => (Math.floor(Date.now() / 1000) + 2) * 1000;
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');
const closes = (inbox, id) => inbox.filter((m) => m.type === MSG.GATEWAY_CLOSE && m.gateway_id === id);
const refusedConnect = (port) => new Promise((resolve) => {
  const s = net.connect({ port, host: '127.0.0.1' }); s.once('connect', () => { s.destroy(); resolve(false); }); s.once('error', () => resolve(true));
});

describe('a grant that expires ends the gateway connections it holds open (#297)', () => {
  const servers = []; const clients = []; const nets = []; const hosts = [];
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const h of hosts.splice(0)) await h.close().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
    for (const n of nets.splice(0)) n.close();
  });

  /** An origin that echoes, and remembers each connection and whether it was closed. */
  async function origin() {
    const sockets = [];
    const server = net.createServer((s) => { sockets.push(s); s.on('data', (d) => s.write(Buffer.concat([Buffer.from('echo:'), d]))); s.on('error', () => {}); });
    const port = await listen(server); nets.push(server);
    return { port, sockets };
  }
  async function connect(url, name, keyPair) {
    const c = new WshClient();
    await c.connect(url, { username: name, keyPair });
    clients.push(c);
    const inbox = [];
    c.onGatewayMessage = (m) => inbox.push(m);
    return { c, inbox };
  }
  async function openEcho(c, inbox, id, port) {
    await c.sendControl({ type: MSG.OPEN_TCP, gateway_id: id, host: '127.0.0.1', port });
    await until(() => inbox.find((m) => m.type === MSG.GATEWAY_OK && m.gateway_id === id), `GatewayOk ${id}`);
    await c.sendControl({ type: MSG.GATEWAY_DATA, gateway_id: id, data: enc.encode('hi') });
    await until(() => inbox.find((m) => m.type === MSG.GATEWAY_DATA && m.gateway_id === id), `echo ${id}`);
  }

  describe('the Node server', () => {
    it('a key line `expires`: the open connection of that key is closed with the reason when it passes; another key is untouched', async () => {
      const o = await origin();
      const alice = await generateKeyPair(true); const bob = await generateKeyPair(true);
      const at = soon();
      const server = createWshServer({
        auth: { authorizedKeys: `expires="${iso(at)}" ${await exportPublicKeySSH(alice.publicKey)} alice\n${await exportPublicKeySSH(bob.publicKey)} bob` },
        gateway: { allow: [`127.0.0.1:${o.port}`], reverse: {} },
      });
      const { port } = await server.listen(); servers.push(server);
      const a = await connect(`ws://127.0.0.1:${port}`, 'alice', alice);
      const b = await connect(`ws://127.0.0.1:${port}`, 'bob', bob);
      await openEcho(a.c, a.inbox, 1, o.port);
      await openEcho(a.c, a.inbox, 2, o.port);
      await openEcho(b.c, b.inbox, 1, o.port);
      assert.equal(closes(a.inbox, 1).length, 0, 'open before the expiry');
      // The expiry passes: both of alice's connections end, with the reason, and a second close frees a peer that knows "discarded".
      for (const id of [1, 2]) {
        await until(() => closes(a.inbox, id).length >= 2, `both closes of ${id}`);
        const [first, second] = closes(a.inbox, id);
        assert.equal(first.reason, 'key expired');
        assert.equal(second.reason, 'discarded');
      }
      assert.ok(Date.now() >= at - 50, 'not before the expiry');
      await until(() => o.sockets.filter((s) => s.destroyed).length >= 2, 'the origin to see its two connections end');
      assert.equal(closes(b.inbox, 1).length, 0, 'bob has no expiry and is not touched');
      await b.c.sendControl({ type: MSG.GATEWAY_DATA, gateway_id: 1, data: enc.encode('again') });
      await until(() => b.inbox.filter((m) => m.type === MSG.GATEWAY_DATA).length >= 2, 'bob\'s connection still echoes');
      // The expired key is refused afresh, as before.
      await a.c.sendControl({ type: MSG.OPEN_TCP, gateway_id: 3, host: '127.0.0.1', port: o.port });
      const refused = await until(() => a.inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 3), 'the refusal');
      assert.match(refused.message, /expired/);
    });

    it('the `expires` of what authorize() returns does the same, and also stops a reverse tunnel the grant had open', async () => {
      const o = await origin();
      const kp = await generateKeyPair(true);
      const raw = await exportPublicKeyRaw(kp.publicKey);
      const at = soon();
      const server = createWshServer({
        auth: { authorizedKeys: [raw], authorize: () => ({ capabilities: ['gateway:tcp:*:*', 'gateway:listen:tcp:*'], expires: new Date(at) }) },
        gateway: { allow: [`127.0.0.1:${o.port}`], reverse: {} },
      });
      const { port } = await server.listen(); servers.push(server);
      const { c, inbox } = await connect(`ws://127.0.0.1:${port}`, 'alice', kp);
      await openEcho(c, inbox, 1, o.port);
      const handle = await c.listenTcp(0, { onConnection() {} });
      assert.equal(await refusedConnect(handle.port), false, 'listening');
      await until(() => closes(inbox, 1).length >= 1, 'the close');
      assert.equal(closes(inbox, 1)[0].reason, 'key expired');
      await until(() => refusedConnect(handle.port), 'the listener to stop');
    });

    it('one timer for the holder, not one per connection', async () => {
      const o = await origin();
      const kp = await generateKeyPair(true);
      const at = soon();
      const server = createWshServer({ auth: { authorizedKeys: `expires="${iso(at)}" ${await exportPublicKeySSH(kp.publicKey)} alice` }, gateway: { allow: [`127.0.0.1:${o.port}`] } });
      const { port } = await server.listen(); servers.push(server);
      const { c, inbox } = await connect(`ws://127.0.0.1:${port}`, 'alice', kp);
      // A timer that is set for the expiry (a second or two out), counted while twenty connections open.
      const real = globalThis.setTimeout; let expiryTimers = 0;
      globalThis.setTimeout = function counting(fn, ms, ...rest) { if (ms > 100 && ms <= at - Date.now() + 1000 && ms >= at - Date.now() - 1000) expiryTimers++; return real(fn, ms, ...rest); };
      try {
        for (let id = 1; id <= 20; id++) await openEcho(c, inbox, id, o.port);
      } finally { globalThis.setTimeout = real; }
      assert.ok(expiryTimers <= 1, `${expiryTimers} timers armed for the expiry of 20 connections`);
      await until(() => closes(inbox, 20).length >= 1, 'the last connection to be ended too');
    });

    it('a key with no expiry is never touched', async () => {
      const o = await origin();
      const kp = await generateKeyPair(true);
      const server = createWshServer({ auth: { authorizedKeys: `${await exportPublicKeySSH(kp.publicKey)} alice` }, gateway: { allow: [`127.0.0.1:${o.port}`] } });
      const { port } = await server.listen(); servers.push(server);
      const { c, inbox } = await connect(`ws://127.0.0.1:${port}`, 'alice', kp);
      await openEcho(c, inbox, 1, o.port);
      await sleep(2500); // there is nothing to wait for: the absence of a close is the assertion, and the longest expiry used elsewhere here is 2 s
      assert.equal(closes(inbox, 1).length, 0);
    });
  });

  describe('the memory host', () => {
    it('ends the open endpoint connection of a grant that expires, and the endpoint hears it', async () => {
      const kp = await generateKeyPair(true);
      const at = soon();
      let ended; const endedSeen = new Promise((r) => { ended = r; });
      const host = createMemoryHost({
        auth: { authorize: () => ({ capabilities: ['endpoint:idle'], expires: new Date(at) }) },
        endpoints: { idle: (duplex) => { duplex.closed.then(ended); } },
      });
      hosts.push(host);
      const c = await host.connect({ username: 'alice', keyPair: kp });
      clients.push(c);
      const duplex = await c.openEndpoint('idle');
      await Promise.race([endedSeen, sleep(8000).then(() => assert.fail('the endpoint was never told'))]);
      await Promise.race([duplex.closed, sleep(8000).then(() => assert.fail('the client was never told'))]);
    });
  });

  describe('a reverse host behind a relay', () => {
    it('ends an operator\'s open gateway connection when the grant accept() returned expires', async () => {
      const o = await origin();
      const hostKey = await generateKeyPair(true); const opKey = await generateKeyPair(true);
      const hostFp = await fingerprint(await exportPublicKeyRaw(hostKey.publicKey));
      const authorizedKeys = `${await exportPublicKeySSH(hostKey.publicKey)} host\n${await exportPublicKeySSH(opKey.publicKey)} op`;
      const server = createWshServer({ auth: { authorizedKeys }, relay: { canRegister: (w) => w.username === 'host', canConnect: (f) => f.username !== 'host' } });
      const { port } = await server.listen(); servers.push(server);
      const url = `ws://127.0.0.1:${port}`;
      const at = soon();
      const h = createReverseHost({
        url, username: 'host', keyPair: hostKey, exec: true, pty: false, reconnect: false, reportFeatures: true,
        accept: () => ({ capabilities: ['gateway:tcp:*:*'], expires: new Date(at) }),
        gateway: { trustRelayIdentity: true, allow: [`127.0.0.1:${o.port}`] },
      });
      await h.start(); hosts.push(h);
      await until(() => server.peerFingerprints().includes(hostFp), 'the host to register');
      const { c, inbox } = await connect(url, 'op', opKey);
      const accepted = await c.reverseConnect(hostFp);
      assert.equal(accepted.type, MSG.REVERSE_ACCEPT, accepted.reason);
      await openEcho(c, inbox, 1, o.port);
      await until(() => closes(inbox, 1).length >= 2, 'both closes');
      assert.equal(closes(inbox, 1)[0].reason, 'key expired');
      await until(() => o.sockets[0].destroyed, 'the origin to see its connection end');
    });
  });
});
