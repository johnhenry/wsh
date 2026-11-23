// test/memory-host-backends.test.mjs -- injected backends of createMemoryHost (#114), the data-stream switch (#132),
// and "no Buffer on a path a browser host can reach" (#133).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost, createSocketPair } from '@johnhenry/wsh/memory';
import { createConnectionFactory, bindSocket, resolveBackends, resolveHostKey } from '@johnhenry/wsh/host';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw, sign, fingerprint, WshFileTransfer } from '@johnhenry/wsh';

const dec = new TextDecoder();
const enc = new TextEncoder();

/** A pty a page could have (no node-pty): echoes input back, records what it was given. */
function fakePty() {
  const log = { spawns: [], writes: [], resizes: [] };
  let dataCb; let exitCb;
  const spawn = (file, args, o) => {
    log.spawns.push({ file, args, cols: o.cols, rows: o.rows });
    return {
      onData: (cb) => { dataCb = cb; },
      onExit: (cb) => { exitCb = cb; },
      write: (d) => { log.writes.push(d); dataCb(d instanceof Uint8Array ? `echo:${dec.decode(d)}` : `echo:${d}`); },
      resize: (c, r) => log.resizes.push([c, r]),
      kill: () => exitCb({ exitCode: 0 }),
    };
  };
  return { spawn, log, exit: (code) => exitCb({ exitCode: code }) };
}

/** An in-memory file backend: an object of operations, no root path. */
function memoryFs(initial = {}) {
  const files = new Map(Object.entries(initial).map(([k, v]) => [k, enc.encode(v)]));
  const fail = (m) => Object.assign(new Error(m), { wsh: true });
  const backend = {
    maxFileBytes: 1024,
    files,
    async operate(op, path, { offset, length, newPath } = {}) {
      switch (op) {
        case 'list': return { entries: [...files].map(([name, d]) => ({ name: name.replace(/^\//, ''), size: d.byteLength, modified: 0, type: 'file' })), metadata: { path } };
        case 'stat': { const d = files.get(path); if (!d) throw fail('no such file'); return { metadata: { name: path, size: d.byteLength, modified: 0, type: 'file' } }; }
        case 'read': { const d = files.get(path); if (!d) throw fail('no such file'); return { metadata: { data: d.subarray(offset ?? 0, (offset ?? 0) + (length ?? d.byteLength)), size: d.byteLength } }; }
        case 'rename': { files.set(newPath, files.get(path)); files.delete(path); return { metadata: { renamed: path, to: newPath } }; }
        case 'remove': files.delete(path); return { metadata: { removed: path } };
        default: throw fail(`${op} is not offered`);
      }
    },
    async readWhole(path) { const d = files.get(path); if (!d) throw fail('no such file'); return d; },
    async writeWhole(path, data) { files.set(path, data.slice()); },
    async writeAt(path, data) { files.set(path, data.slice()); },
  };
  return backend;
}

describe('createMemoryHost injected backends (#114)', () => {
  let keyPair; let raw;
  before(async () => { keyPair = await generateKeyPair(true); raw = await exportPublicKeyRaw(keyPair.publicKey); });

  it('serves a pty from an injected node-pty-shaped spawn: output, input, resize, exit', async () => {
    const pty = fakePty();
    const host = createMemoryHost({ auth: { authorizedKeys: [raw] }, pty: { spawn: pty.spawn, shell: 'sh' } });
    const client = await host.connect({ username: 'alice', keyPair });
    try {
      const session = await client.openSession({ type: 'pty', cols: 100, rows: 30 });
      assert.equal(session.dataMode, 'virtual');
      const got = new Promise((r) => { session.onData = (d) => r(dec.decode(d)); });
      await session.write('ls\n');
      assert.equal(await got, 'echo:ls\n');
      assert.ok(pty.log.writes[0] instanceof Uint8Array, 'stdin reaches the pty as bytes');
      await session.resize(120, 40);
      await new Promise((r) => setTimeout(r, 50));
      assert.deepEqual(pty.log.resizes, [[120, 40]]);
      assert.deepEqual(pty.log.spawns[0], { file: 'sh', args: [], cols: 100, rows: 30 });
      const exited = new Promise((r) => { session.onExit = r; });
      pty.exit(5);
      assert.equal(await exited, 5);
    } finally { await client.disconnect(); await host.close(); }
  });

  it('pty stdin works with no Buffer global at all (#133)', async () => {
    const pty = fakePty();
    const host = createMemoryHost({ auth: { authorizedKeys: [raw] }, pty: { spawn: pty.spawn } });
    const client = await host.connect({ username: 'alice', keyPair });
    const BufferGlobal = globalThis.Buffer;
    try {
      const session = await client.openSession({ type: 'pty' });
      const got = new Promise((r) => { session.onData = (d) => r(dec.decode(d)); });
      delete globalThis.Buffer; // a browser has none
      assert.equal(typeof globalThis.Buffer, 'undefined');
      await session.write('whoami\n');
      assert.equal(await got, 'echo:whoami\n');
    } finally { globalThis.Buffer = BufferGlobal; await client.disconnect(); await host.close(); }
  });

  it('a pty that throws on write is logged, not swallowed (#133)', async () => {
    const lines = [];
    const spawn = () => ({ onData() {}, onExit() {}, write() { throw new Error('boom'); }, resize() {}, kill() {} });
    const host = createMemoryHost({ auth: { authorizedKeys: [raw] }, pty: { spawn }, onLog: (l) => lines.push(l) });
    const client = await host.connect({ username: 'alice', keyPair });
    try {
      const session = await client.openSession({ type: 'pty' });
      await session.write('x');
      await new Promise((r) => setTimeout(r, 50));
      assert.ok(lines.some((l) => /input not written: boom/.test(l)), lines.join('\n'));
    } finally { await client.disconnect(); await host.close(); }
  });

  it('serves file transfer from an injected object of operations', async () => {
    const fs = memoryFs({ '/a.txt': 'hello file' });
    const host = createMemoryHost({ auth: { authorizedKeys: [raw] }, fs });
    const client = await host.connect({ username: 'alice', keyPair });
    try {
      const files = new WshFileTransfer(client);
      assert.deepEqual((await files.list('/')).map((e) => e.name), ['a.txt']);
      assert.equal(dec.decode(await client.download('/a.txt')), 'hello file');
      await client.upload(enc.encode('uploaded'), '/b.txt');
      assert.equal(dec.decode(fs.files.get('/b.txt')), 'uploaded');
      await assert.rejects(() => client.download('/missing'), /no such file/);
      await client.upload(new Uint8Array(2000), '/big').then(() => assert.fail('over maxFileBytes'), (e) => assert.match(e.message, /Upload failed/));
    } finally { await client.disconnect(); await host.close(); }
  });

  it('refuses a root path, a missing operation, exec: true and a bad pty at construction', () => {
    assert.throws(() => createMemoryHost({ fs: { root: '/tmp' } }), /needs Node.*@johnhenry\/wsh\/server/);
    assert.throws(() => createMemoryHost({ fs: { operate() {} } }), /fs\.readWhole must be a function/);
    assert.throws(() => createMemoryHost({ fs: { ...memoryFs(), maxFileBytes: 0 } }), /maxFileBytes/);
    assert.throws(() => createMemoryHost({ exec: true }), /no shell/);
    assert.throws(() => createMemoryHost({ pty: {} }), /pty\.spawn must be a function/);
    assert.throws(() => createMemoryHost({ dataStreams: 'no' }), /dataStreams must be true or false/);
  });

  it('presents a host key held non-extractable, and a signer; clients can pin either', async () => {
    const hostPair = await generateKeyPair(false);
    assert.equal(hostPair.privateKey.extractable, false);
    const hostRaw = await exportPublicKeyRaw(hostPair.publicKey);
    const wantFp = await fingerprint(hostRaw);
    for (const hostKey of [hostPair, { publicKey: hostRaw, sign: (d) => sign(hostPair.privateKey, d) }, hostPair.publicKey && { publicKey: hostPair.publicKey, sign: (d) => sign(hostPair.privateKey, d) }]) {
      const host = createMemoryHost({ auth: { authorizedKeys: [raw] }, exec: async () => 0, hostKey });
      const client = host.createClient();
      try {
        await client.connect(host.url, { username: 'alice', keyPair, transport: 'ws', expectHostKey: wantFp });
        assert.equal(client.hostKey.fingerprint, wantFp);
        assert.equal(client.hostKey.status, 'pinned');
      } finally { await client.disconnect(); await host.close(); }
    }
    // a different pin is refused before any credential is sent
    const host = createMemoryHost({ auth: { authorizedKeys: [raw] }, exec: async () => 0, hostKey: hostPair });
    const other = host.createClient();
    await assert.rejects(() => other.connect(host.url, { username: 'alice', keyPair, transport: 'ws', expectHostKey: 'ab'.repeat(32) }), /host key|fingerprint|pin/i);
    await host.close();
    await assert.rejects(() => resolveHostKey('nope'), /hostKey must be/);
    assert.equal((await resolveHostKey(true)).publicKey.byteLength, 32);
  });
});

describe('dataStreams: false (#132)', () => {
  let keyPair; let raw;
  before(async () => { keyPair = await generateKeyPair(true); raw = await exportPublicKeyRaw(keyPair.publicKey); });
  const run = async (client, command) => {
    const session = await client.openSession({ type: 'exec', command });
    const chunks = [];
    session.onData = (d) => chunks.push(d);
    const code = await new Promise((r) => { session.onExit = r; });
    return { out: chunks.map((c) => dec.decode(c)).join(''), code, mode: session.dataMode };
  };
  const echo = async (command, io) => { await io.write(`ran:${command}\n`); return 4; };

  it('offers stream data mode by default and virtual data mode with the option', async () => {
    const streams = createMemoryHost({ auth: { authorizedKeys: [raw] }, exec: echo });
    const virtual = createMemoryHost({ auth: { authorizedKeys: [raw] }, exec: echo, dataStreams: false });
    const a = await streams.connect({ username: 'alice', keyPair });
    const b = await virtual.connect({ username: 'alice', keyPair });
    try {
      assert.ok(a.hasFeature('stream-announce'));
      assert.deepEqual(await run(a, 'x'), { out: 'ran:x\n', code: 4, mode: 'stream' });
      assert.ok(!b.hasFeature('stream-announce'));
      assert.deepEqual(await run(b, 'x'), { out: 'ran:x\n', code: 4, mode: 'virtual' });
    } finally { await a.disconnect(); await b.disconnect(); await streams.close(); await virtual.close(); }
  });

  it('does not offer rpc without data streams, and accept() can choose per connection', async () => {
    const host = createMemoryHost({ auth: { authorizedKeys: [raw] }, exec: echo, rpc: { demo: () => {} }, dataStreams: false });
    const c1 = await host.connect({ username: 'alice', keyPair });
    try { assert.ok(!c1.hasFeature('rpc')); } finally { await c1.disconnect(); }
    // one connection through accept() with streams on, though the host default is off
    const c2 = new WshClient({ transportFactories: { ws: () => new WebSocketTransport({
      WebSocket: class { constructor() { const [c, s] = createSocketPair(); void host.accept(s, { dataStreams: true }); return c; } },
    }) } });
    await c2.connect('ws://x/', { username: 'alice', keyPair, transport: 'ws' });
    try { assert.ok(c2.hasFeature('rpc')); assert.ok(c2.hasFeature('stream-announce')); } finally { await c2.disconnect(); await host.close(); }
  });
});

describe('@johnhenry/wsh/host: the exported connection factory (#115)', () => {
  it('serves a socket with a hand-wired factory, no createMemoryHost involved', async () => {
    const keyPair = await generateKeyPair(true);
    const raw = await exportPublicKeyRaw(keyPair.publicKey);
    const backends = resolveBackends({ exec: async (command, io) => { await io.write(`hi ${command}`); return 0; } });
    const attach = createConnectionFactory({ authorize: async (who) => who.username === 'alice', methods: { pubkey: true, password: null }, ...backends });
    const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport({
      WebSocket: class { constructor() { const [c, s] = createSocketPair(); void bindSocket(s, Promise.resolve(attach), { dataStreams: false }); return c; } },
    }) } });
    await client.connect('ws://x/', { username: 'alice', keyPair, transport: 'ws' });
    try {
      const session = await client.openSession({ type: 'exec', command: 'there' });
      const out = new Promise((r) => { session.onData = (d) => r(dec.decode(d)); });
      assert.equal(await out, 'hi there');
    } finally { await client.disconnect(); }
    assert.equal(raw.byteLength, 32);
  });

  it('requires authorize: a host with no authorizer would let everyone in', () => {
    assert.throws(() => createConnectionFactory({}), /authorize\(who\) is required/);
    assert.throws(() => createConnectionFactory(), /authorize/);
  });
});

describe('accept() of a socket that is still connecting (#115)', () => {
  it('holds the host\'s first bytes (its QMux handshake) until the socket opens, instead of dropping them', async () => {
    const { WebSocketServer } = await import('ws');
    const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    await new Promise((r) => wss.on('listening', r));
    const first = new Promise((resolve) => wss.on('connection', (peer) => peer.once('message', (data) => resolve(data))));
    const host = createMemoryHost({ auth: { authorizedKeys: [] }, exec: async () => 0 });
    try {
      const socket = new WebSocket(`ws://127.0.0.1:${wss.address().port}`); // CONNECTING
      assert.equal(socket.readyState, 0);
      await host.accept(socket);
      const data = await Promise.race([first, new Promise((_, rej) => setTimeout(() => rej(new Error('the host never spoke')), 3000))]);
      assert.ok(data.byteLength > 0);
    } finally { await host.close(); wss.close(); }
  });
});
