// test/memory-host-rpc-sessions.test.mjs -- `rpc` and `sessions` on the browser-safe memory host (#99 follow-up):
// the same protocol and limits as `createWshServer`, with no Node.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { WebSocketTransport } from '../src/transport-ws.mjs';
import { WshClient, MSG, RpcError, RPC_ERROR, RPC_FEATURE, rpcProtocolFeature, generateKeyPair, exportPublicKeyRaw } from '@johnhenry/wsh';

const dec = new TextDecoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 4000) {
  const t0 = Date.now();
  for (;;) {
    const v = await cond();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(5);
  }
}
function record(session) {
  const rec = { text: '', exit: undefined, closed: false };
  session.onData = (d) => { rec.text += dec.decode(d); };
  session.onExit = (c) => { rec.exit = c; };
  session.onClose = () => { rec.closed = true; };
  return rec;
}

describe('createMemoryHost rpc', () => {
  let keyPair; let raw;
  const hosts = [];
  before(async () => { keyPair = await generateKeyPair(true); raw = await exportPublicKeyRaw(keyPair.publicKey); });
  afterEach(async () => { for (const h of hosts.splice(0)) await h.close(); });
  const make = (opts) => { const h = createMemoryHost({ auth: { authorizedKeys: [raw] }, ...opts }); hosts.push(h); return h; };

  it('negotiates rpc and round-trips a request, a notification and an error', async () => {
    const seen = [];
    const host = make({
      rpc: {
        calc: (channel, ctx) => {
          assert.equal(ctx.protocol, 'calc');
          assert.equal(ctx.user, 'alice');
          channel.onRequest('add', ({ a, b }) => ({ sum: a + b }));
          channel.onRequest('boom', () => { throw new RpcError(RPC_ERROR.INVALID_PARAMS, 'nope'); });
          channel.onNotification('note', (p) => seen.push(p));
        },
      },
    });
    const client = await host.connect({ username: 'alice', keyPair });
    try {
      assert.ok(client.hasFeature(RPC_FEATURE));
      assert.ok(client.hasFeature(rpcProtocolFeature('calc')));
      assert.ok(client.hasFeature('rpc-max-message:1048576'));
      const rpc = await client.openRpc('calc');
      assert.deepEqual(await rpc.request('add', { a: 2, b: 40 }), { sum: 42 });
      await assert.rejects(rpc.request('boom', {}), (e) => e instanceof RpcError && e.code === RPC_ERROR.INVALID_PARAMS && /nope/.test(e.message));
      await assert.rejects(rpc.request('missing', {}), (e) => e.code === RPC_ERROR.METHOD_NOT_FOUND);
      rpc.notify('note', { hi: 1 });
      await until(() => seen.length === 1, 'the notification');
      assert.deepEqual(seen[0], { hi: 1 });
      await rpc.close();
    } finally { await client.disconnect(); }
  });

  it('refuses an unadvertised protocol, and advertises no rpc when the option is absent', async () => {
    const withRpc = make({ rpc: { calc: () => {} } });
    const c1 = await withRpc.connect({ username: 'alice', keyPair });
    await assert.rejects(c1.openRpc('other'), (e) => e.code === RPC_ERROR.UNSUPPORTED_PROTOCOL);
    await c1.disconnect();
    const without = make({});
    const c2 = await without.connect({ username: 'alice', keyPair });
    assert.ok(!c2.hasFeature(RPC_FEATURE));
    await assert.rejects(c2.openRpc('calc'), (e) => e.code === RPC_ERROR.UNSUPPORTED_PROTOCOL);
    await c2.disconnect();
  });

  it('honours rpcMaxMessageBytes and validates the option', async () => {
    const host = make({ rpc: { calc: () => {} }, rpcMaxMessageBytes: 4096 });
    const c = await host.connect({ username: 'alice', keyPair });
    assert.ok(c.hasFeature('rpc-max-message:4096'));
    await c.disconnect();
    assert.throws(() => createMemoryHost({ rpc: { 'bad name': () => {} } }), /not allowed/);
    assert.throws(() => createMemoryHost({ rpc: { 'wsh-host': true } }), /handler function/);
    assert.throws(() => createMemoryHost({ rpc: { x: () => {} }, rpcMaxMessageBytes: 10 }), /at least 256/);
    assert.throws(() => createMemoryHost({ rpc: [] }), /object/);
  });
});

describe('createMemoryHost sessions', () => {
  let keyPair; let raw; let other; let otherRaw;
  const hosts = [];
  const clients = [];
  const transports = new WeakMap();
  before(async () => {
    keyPair = await generateKeyPair(true); raw = await exportPublicKeyRaw(keyPair.publicKey);
    other = await generateKeyPair(true); otherRaw = await exportPublicKeyRaw(other.publicKey);
  });
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const h of hosts.splice(0)) await h.close();
  });

  /** A runner whose output is produced on demand: `io.write` of each line the test releases, then exit with 4. */
  function controlled() {
    const gates = [];
    const runner = async (command, io) => {
      await io.write(`started ${command}\n`);
      for (let i = 0; i < 3; i++) {
        await new Promise((resolve) => gates.push(resolve));
        await io.write(`line ${i}\n`);
      }
      return 4;
    };
    return { runner, release: async () => { await until(() => gates.length, 'the runner'); gates.shift()(); } };
  }
  const make = (opts) => {
    const h = createMemoryHost({ auth: { authorizedKeys: [raw, otherRaw] }, ...opts });
    hosts.push(h);
    return h;
  };
  async function connect(host, key = keyPair, username = 'alice') {
    const transport = new WebSocketTransport({ WebSocket: host.WebSocket });
    const client = new WshClient({ transportFactories: { ws: () => transport } });
    await client.connect(host.url, { username, keyPair: key, transport: 'ws' });
    transports.set(client, transport);
    clients.push(client);
    return client;
  }
  /** The link goes away with no Close/Detach message. */
  const drop = (client) => transports.get(client).close();

  it('drop, then resume from a fresh client: only the bytes after last_seq arrive, and the exit is reported', async () => {
    const { runner, release } = controlled();
    const host = make({ exec: runner, sessions: true });
    const c1 = await connect(host);
    const s1 = await c1.openSession({ type: 'exec', command: 'job' });
    const r1 = record(s1);
    await until(() => r1.text === 'started job\n', 'the first output');
    assert.equal(s1.seq, r1.text.length);
    const { sessionId, resumeToken } = s1;
    const lastSeq = s1.seq;
    await drop(c1);
    await sleep(20);
    await release(); await release();            // two lines are produced while nobody is attached

    const c2 = await connect(host);
    const presence = await c2.resumeSession(sessionId, resumeToken, { lastSeq });
    assert.equal(presence.type, MSG.PRESENCE);
    const s2 = presence.session;
    assert.equal(s2.sessionId, sessionId);
    assert.equal(s2.seq, lastSeq);
    const r2 = record(s2);
    await until(() => r2.text === 'line 0\nline 1\n', 'the replay');
    await release();                              // live output after the resume reaches the new attachment
    await until(() => r2.exit !== undefined, 'the exit');
    assert.equal(r2.text, 'line 0\nline 1\nline 2\n', 'nothing before last_seq is repeated');
    assert.equal(r2.exit, 4);
  });

  it('detach() keeps the session, and it can be resumed; without `sessions` a dropped link ends it', async () => {
    const { runner, release } = controlled();
    const host = make({ exec: runner, sessions: true });
    const c1 = await connect(host);
    const s1 = await c1.openSession({ type: 'exec', command: 'job' });
    const r1 = record(s1);
    await until(() => r1.text === 'started job\n', 'the first output');
    await c1.detach(s1.sessionId);
    await release();
    const { session } = await c1.resumeSession(s1.sessionId, s1.resumeToken, { lastSeq: s1.seq });
    const r2 = record(session);
    await until(() => r2.text === 'line 0\n', 'the replay after detach');

    const plain = make({ exec: async (cmd, io) => { await io.write('hi\n'); await new Promise((r) => setTimeout(r, 200)); return 0; } });
    const c3 = await connect(plain);
    const s3 = await c3.openSession({ type: 'exec', command: 'x' });
    await until(() => s3.seq === 3, 'output');
    await drop(c3);
    const c4 = await connect(plain);
    await assert.rejects(c4.resumeSession(s3.sessionId, s3.resumeToken, { lastSeq: 3 }), /Failed to resume/);
  });

  it('refuses an unknown session, a bad token, another principal and a position the session never reached', async () => {
    const { runner } = controlled();
    const host = make({ exec: runner, sessions: true });
    const c1 = await connect(host);
    const s1 = await c1.openSession({ type: 'exec', command: 'a' });
    const s2 = await c1.openSession({ type: 'exec', command: 'b' });
    await until(() => s1.seq > 0 && s2.seq > 0, 'output');
    const c2 = await connect(host);
    await assert.rejects(c2.resumeSession('no-such-session', s1.resumeToken, { lastSeq: 0 }), /Failed to resume: unknown session or not authorized/);
    await assert.rejects(c2.resumeSession(s1.sessionId, new Uint8Array(40), { lastSeq: 0 }), /Failed to resume/);
    await assert.rejects(c2.resumeSession(s1.sessionId, new Uint8Array(3), { lastSeq: 0 }), /Failed to resume/);
    await assert.rejects(c2.resumeSession(s1.sessionId, s2.resumeToken, { lastSeq: 0 }), /Failed to resume/, "another session's token");
    const bent = Uint8Array.from(s1.resumeToken); bent[39] ^= 1;
    await assert.rejects(c2.resumeSession(s1.sessionId, bent, { lastSeq: 0 }), /Failed to resume/);
    await assert.rejects(c2.resumeSession(s1.sessionId, s1.resumeToken, { lastSeq: 9999 }), /ahead of the session/);
    // The right token from a different key is still not the owner.
    const stranger = await connect(host, other, 'mallory');
    await assert.rejects(stranger.resumeSession(s1.sessionId, s1.resumeToken, { lastSeq: 0 }), /Failed to resume/);
    // The owner with the right token works.
    await drop(c1);
    const c3 = await connect(host);
    assert.ok((await c3.resumeSession(s1.sessionId, s1.resumeToken, { lastSeq: 0 })).session);
  });

  it('an expired session (detachTtlMs) can no longer be resumed; detachTtlMs: 0 expires it at once', async () => {
    const { runner } = controlled();
    const host = make({ exec: runner, sessions: { detachTtlMs: 80 } });
    const c1 = await connect(host);
    const s1 = await c1.openSession({ type: 'exec', command: 'a' });
    await until(() => s1.seq > 0, 'output');
    await drop(c1);
    await sleep(250);
    const c2 = await connect(host);
    await assert.rejects(c2.resumeSession(s1.sessionId, s1.resumeToken, { lastSeq: s1.seq }), /Failed to resume: unknown session/);

    const zero = make({ exec: runner, sessions: { detachTtlMs: 0 } });
    const c3 = await connect(zero);
    const s3 = await c3.openSession({ type: 'exec', command: 'a' });
    await until(() => s3.seq > 0, 'output');
    await drop(c3);
    await sleep(30);
    const c4 = await connect(zero);
    await assert.rejects(c4.resumeSession(s3.sessionId, s3.resumeToken, { lastSeq: s3.seq }), /Failed to resume/);
  });

  it('bounds the replay buffer: a resume past the ring is a gap, an attach gets the retained tail', async () => {
    let go;
    const gate = new Promise((r) => { go = r; });
    const runner = async (cmd, io) => {
      await io.write('ready\n');
      await gate;
      for (let i = 0; i < 20; i++) await io.write('123456789\n');   // 200 bytes
      await new Promise(() => {});
      return 0;
    };
    const host = make({ exec: runner, sessions: { ringBytes: 64 } });
    const c1 = await connect(host);
    const s1 = await c1.openSession({ type: 'exec', command: 'a' });
    const r1 = record(s1);
    await until(() => r1.text === 'ready\n', 'ready');
    const lastSeq = s1.seq;
    await drop(c1);
    await sleep(20);
    go();
    await sleep(100);
    const c2 = await connect(host);
    await assert.rejects(c2.resumeSession(s1.sessionId, s1.resumeToken, { lastSeq }), /Failed to resume: output gap: .*starts at seq 142.*last_seq is 6/);
    const { session } = await c2.attachSession(s1.sessionId, { token: s1.resumeToken });
    assert.equal(session.seq, 142, '206 bytes produced, 64 kept');
    const r2 = record(session);
    await until(() => Buffer.byteLength(r2.text) === 64, 'the retained tail');
    assert.equal(session.seq, 206);
  });

  it('bounds the session count: beyond maxDetached the longest-detached session is dropped', async () => {
    const { runner } = controlled();
    const host = make({ exec: runner, sessions: { maxDetached: 2, detachTtlMs: 60_000 } });
    const opened = [];
    for (let i = 0; i < 3; i++) {
      const c = await connect(host);
      const s = await c.openSession({ type: 'exec', command: `j${i}` });
      await until(() => s.seq > 0, 'output');
      opened.push(s);
      await drop(c);
      await sleep(20);
    }
    const c = await connect(host);
    await assert.rejects(c.resumeSession(opened[0].sessionId, opened[0].resumeToken, { lastSeq: opened[0].seq }), /Failed to resume/);
    assert.ok((await c.resumeSession(opened[1].sessionId, opened[1].resumeToken, { lastSeq: opened[1].seq })).session);
    const c2 = await connect(host);
    assert.ok((await c2.resumeSession(opened[2].sessionId, opened[2].resumeToken, { lastSeq: opened[2].seq })).session);
  });

  it('closing the host ends its sessions, and the options are validated', async () => {
    const { runner } = controlled();
    const host = make({ exec: runner, sessions: true });
    const c1 = await connect(host);
    const s1 = await c1.openSession({ type: 'exec', command: 'a' });
    await until(() => s1.seq > 0, 'output');
    await host.close();
    assert.throws(() => createMemoryHost({ sessions: { ringBytes: 0 } }), /ringBytes/);
    assert.throws(() => createMemoryHost({ sessions: { maxDetached: -1 } }), /maxDetached/);
    assert.throws(() => createMemoryHost({ sessions: { detachTtlMs: -5 } }), /detachTtlMs/);
    assert.throws(() => createMemoryHost({ sessions: [] }), /sessions must be/);
  });

  it('stays exec-free: sessions without `exec` open nothing', async () => {
    const host = make({ sessions: true });
    const c = await connect(host);
    await assert.rejects(c.openSession({ type: 'exec', command: 'id' }), /exec is not enabled/);
  });
});
