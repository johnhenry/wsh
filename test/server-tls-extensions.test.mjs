// test/server-tls-extensions.test.mjs -- `tls` (wss:// on the WebSocket listener), `extensions`
// (application-defined string-typed messages) and `relay.onUnreachable` of `@johnhenry/wsh/server`.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer } from '@johnhenry/wsh/server';
import { generateSelfSignedCertificate } from '../src/server/self-signed.mjs';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG } from '@johnhenry/wsh';

const dec = new TextDecoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 4000) {
  const t0 = Date.now();
  for (;;) {
    const v = await cond();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(10);
  }
}

describe('tls / extensions / relay.onUnreachable', () => {
  const servers = []; const clients = [];
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
  });
  async function key(name) {
    const keyPair = await generateKeyPair(true);
    return { name, keyPair, line: `${await exportPublicKeySSH(keyPair.publicKey)} ${name}`, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)) };
  }
  async function login(url, k, opts = {}) {
    const c = new WshClient();
    await c.connect(url, { username: k.name, keyPair: k.keyPair, ...opts });
    clients.push(c);
    return c;
  }

  it('serves wss:// with the given certificate and runs a command; plain ws:// is refused', async () => {
    const alice = await key('alice');
    const cert = generateSelfSignedCertificate();
    const server = createWshServer({ auth: { authorizedKeys: alice.line }, exec: true, tls: { cert: cert.cert, key: cert.privKey } });
    const { port } = await server.listen();
    servers.push(server);
    const prev = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    try {
      const client = await login(`wss://127.0.0.1:${port}`, alice);
      const session = await client.openSession({ type: 'exec', command: 'echo secure' });
      const out = await new Promise((resolve) => { const ch = []; session.onData = (d) => ch.push(d); session.onClose = () => resolve(dec.decode(Buffer.concat(ch))); });
      assert.equal(out.trim(), 'secure');
      await assert.rejects(new WshClient().connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair: alice.keyPair, timeout: 1500 }));
    } finally {
      if (prev === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = prev;
    }
  });

  it('close() also releases the TLS listener', async () => {
    const cert = generateSelfSignedCertificate();
    const server = createWshServer({ tls: { cert: cert.cert, key: cert.privKey } });
    await server.listen();
    await server.close();
    assert.equal(server.address(), null);
  });

  it('extensions: a string-typed message from an authenticated client reaches its handler with the connection identity', async () => {
    const alice = await key('alice');
    const seen = [];
    const server = createWshServer({
      auth: { authorizedKeys: alice.line },
      extensions: {
        hello: (msg, ctx) => { seen.push({ msg, username: ctx.username, fingerprint: ctx.fingerprint }); },
        boom: () => { throw new Error('nope'); },
      },
    });
    const { port } = await server.listen();
    servers.push(server);
    const client = await login(`ws://127.0.0.1:${port}`, alice);
    await client.sendRelayControl({ type: 'boom' });
    await client.sendRelayControl({ type: 'hello', n: 7 });
    await client.sendRelayControl({ type: 'unregistered' });
    await until(() => seen.length === 1, 'the extension to run');
    assert.equal(seen[0].msg.n, 7);
    assert.equal(seen[0].username, 'alice');
    assert.equal(seen[0].fingerprint, alice.fp);
  });

  it('relay.onUnreachable fires when the target is not registered, and the operator is still rejected', async () => {
    const bob = await key('bob');
    const calls = [];
    const server = createWshServer({
      auth: { authorizedKeys: bob.line },
      relay: { canRegister: () => true, canConnect: () => true, onUnreachable: (from, target, req) => { calls.push({ from, target, req }); throw new Error('ignored'); } },
    });
    const { port } = await server.listen();
    servers.push(server);
    const client = await login(`ws://127.0.0.1:${port}`, bob);
    const ghost = 'SHA256:' + 'A'.repeat(43);
    const answer = await client.reverseConnect(ghost, 2000);
    assert.equal(answer.type, MSG.REVERSE_REJECT);
    assert.match(answer.reason, /no such peer/);
    await until(() => calls.length === 1, 'onUnreachable');
    assert.equal(calls[0].from.fingerprint, bob.fp);
    assert.equal(calls[0].target, ghost);
  });
});
