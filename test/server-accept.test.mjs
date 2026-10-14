// test/server-accept.test.mjs -- createWshServer().accept(): serve a pre-upgraded transport, no loopback listener (#101).
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createWshServer } from '@johnhenry/wsh/server';
import { createSocketPair } from '@johnhenry/wsh/memory';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

const dec = new TextDecoder();

describe('createWshServer accept() (#101)', () => {
  let keyPair; let authorizedKeys;
  const servers = []; const clients = [];
  before(async () => {
    keyPair = await generateKeyPair(true);
    authorizedKeys = await exportPublicKeySSH(keyPair.publicKey);
  });
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
  });

  // A client whose WebSocket is one end of an in-memory pair, the other end handed to accept().
  async function connected(server, remote) {
    const client = new WshClient({
      transportFactories: {
        ws: () => new WebSocketTransport({
          WebSocket: class { constructor() { const [c, s] = createSocketPair(); void server.accept(s, { remote }); return c; } },
        }),
      },
    });
    await client.connect('ws://unused/', { username: 'alice', keyPair, transport: 'ws' });
    clients.push(client);
    return client;
  }

  it('serves a connection without ever calling listen()', async () => {
    const server = createWshServer({ auth: { authorizedKeys }, exec: true });
    servers.push(server);
    const client = await connected(server);
    assert.equal(server.address(), null);
    const session = await client.openSession({ type: 'exec', command: 'echo accepted' });
    const out = await new Promise((resolve) => {
      const chunks = [];
      session.onData = (d) => chunks.push(d);
      session.onClose = () => resolve(dec.decode(Buffer.concat(chunks)));
    });
    assert.equal(out, 'accepted\n');
  });

  it('enforces the same auth as a listening connection', async () => {
    const server = createWshServer({ auth: { authorizedKeys }, exec: true });
    servers.push(server);
    const stranger = await generateKeyPair(true);
    const client = new WshClient({
      transportFactories: { ws: () => new WebSocketTransport({ WebSocket: class { constructor() { const [c, s] = createSocketPair(); void server.accept(s); return c; } } }) },
    });
    await assert.rejects(client.connect('ws://unused/', { username: 'alice', keyPair: stranger, transport: 'ws' }), /Authentication failed/);
  });

  it('accepts a real upgraded ws socket from the embedder\'s own HTTP server (no wsh listener)', async () => {
    const { WebSocketServer } = await import('ws');
    const server = createWshServer({ auth: { authorizedKeys }, exec: true });
    servers.push(server);
    const httpServer = http.createServer();
    const wss = new WebSocketServer({ server: httpServer });
    wss.on('connection', (ws, req) => { void server.accept(ws, { remote: { address: req.socket.remoteAddress, headers: req.headers } }); });
    await new Promise((r) => httpServer.listen(0, '127.0.0.1', r));
    try {
      const { port } = httpServer.address();
      const { stdout, exitCode } = await WshClient.exec(`ws://127.0.0.1:${port}`, 'echo upgraded', { username: 'alice', keyPair, timeout: 5000 });
      assert.equal(dec.decode(stdout), 'upgraded\n');
      assert.equal(exitCode, 0);
      assert.equal(server.address(), null, 'wsh itself opened no listener');
    } finally {
      for (const c of wss.clients) c.terminate();
      await new Promise((r) => wss.close(r));
      await new Promise((r) => httpServer.close(r));
    }
  });

  it('close() drops accepted sockets', async () => {
    const server = createWshServer({ auth: { authorizedKeys }, exec: true });
    const client = await connected(server);
    await server.close();
    await new Promise((r) => setTimeout(r, 50));
    assert.notEqual(client.state, 'authenticated');
  });

  it('listen() and accept() share one server; listen() still works as before', async () => {
    const server = createWshServer({ auth: { authorizedKeys }, exec: true });
    servers.push(server);
    const { port } = await server.listen();
    const viaSocket = await connected(server);
    assert.ok(viaSocket);
    const { stdout } = await WshClient.exec(`ws://127.0.0.1:${port}`, 'echo both', { username: 'alice', keyPair, timeout: 5000 });
    assert.equal(dec.decode(stdout), 'both\n');
    await server.close();
    assert.equal(server.address(), null);
    await server.listen(); // re-listen after close
    assert.ok(server.address().port > 0);
  });

  it('rejects something that is not a socket', async () => {
    const server = createWshServer({ auth: { authorizedKeys } });
    await assert.rejects(server.accept({}), /WebSocket-like/);
    await assert.rejects(server.accept(null), /WebSocket-like/);
  });
});
