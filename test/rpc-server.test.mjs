// wsh #85: typed RPC channels end to end -- negotiation, wsh-host, wsh-fs, custom protocols -- stock client vs
// `@johnhenry/wsh/server`.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, mkdir, symlink, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createWshServer } from '@johnhenry/wsh/server';
import {
  WshClient, WshTransport, MSG, RpcChannel, RpcError, RPC_ERROR, RPC_FEATURE, rpcProtocolFeature,
  generateKeyPair, exportPublicKeySSH,
} from '@johnhenry/wsh';

const dec = new TextDecoder();
let keyPair; let authorizedKeys;
before(async () => {
  keyPair = await generateKeyPair(true);
  authorizedKeys = await exportPublicKeySSH(keyPair.publicKey);
});

async function start(opts, connectOpts = {}) {
  const server = createWshServer({ auth: { authorizedKeys }, ...opts });
  const { port } = await server.listen();
  const client = new WshClient();
  await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair, ...connectOpts });
  return { server, client, port, stop: async () => { await client.disconnect(); await server.close(); } };
}

describe('negotiation', () => {
  it('advertises rpc, one rpc-protocol:<name> per protocol, and rpc-max-message', async () => {
    const { client, stop } = await start({ rpc: { 'wsh-host': true, custom: () => {} }, rpcMaxMessageBytes: 4096 });
    try {
      assert.ok(client.hasFeature(RPC_FEATURE));
      assert.ok(client.hasFeature(rpcProtocolFeature('wsh-host')));
      assert.ok(client.hasFeature(rpcProtocolFeature('custom')));
      assert.ok(client.hasFeature('rpc-max-message:4096'));
      assert.ok(!client.hasFeature(rpcProtocolFeature('mcp')));
    } finally { await stop(); }
  });

  it('a server with no rpc option advertises nothing, and the client refuses before sending any bytes', async () => {
    const { client, stop } = await start({});
    try {
      assert.ok(!client.hasFeature(RPC_FEATURE));
      for (const attempt of [() => client.openRpc('wsh-host'), () => client.openSession({ type: 'rpc', protocol: 'wsh-host' })]) {
        await assert.rejects(attempt(), (e) => e instanceof RpcError && e.code === RPC_ERROR.UNSUPPORTED_PROTOCOL && e.reason === 'UNSUPPORTED_PROTOCOL');
      }
    } finally { await stop(); }
  });

  it('an unadvertised protocol is refused client-side, with no Open frame on the wire', async () => {
    const keys = await generateKeyPair(true);
    const sent = [];
    class Spy extends WshTransport {
      async _doConnect() {}
      async _doClose() {}
      async _doOpenStream() { throw new Error('unused'); }
      async _doSendControl(msg) {
        sent.push(msg.type);
        const reply = (m) => setTimeout(() => this._emitControl(m), 0);
        if (msg.type === MSG.HELLO) {
          reply({ type: MSG.SERVER_HELLO, session_id: 's', features: ['rpc', 'rpc-protocol:wsh-host'] });
          reply({ type: MSG.CHALLENGE, nonce: new Uint8Array(32), session_id: 's' });
        } else if (msg.type === MSG.AUTH) reply({ type: MSG.AUTH_OK, session_id: 's' });
      }
    }
    const client = new WshClient();
    await client.connectWithTransport(new Spy(), 'wsh://x/', { username: 'alice', keyPair: keys });
    const before_ = sent.length;
    await assert.rejects(client.openRpc('mcp'), (e) => e.code === RPC_ERROR.UNSUPPORTED_PROTOCOL && /mcp/.test(e.message));
    assert.equal(sent.length, before_, 'nothing was sent');
  });

  it('a client that skips the check is refused by the server (OpenFail)', async () => {
    const { client, stop } = await start({ rpc: { 'wsh-host': true } });
    try {
      // Pretend the host advertised mcp.
      client.hasFeature = () => true;
      await assert.rejects(client.openRpc('mcp'), /UNSUPPORTED_PROTOCOL|not supported|not enabled/i);
    } finally { await stop(); }
  });

  it('createWshServer rejects bad rpc configuration up front', () => {
    assert.throws(() => createWshServer({ rpc: { 'wsh-fs': true } }), /fs/);
    assert.throws(() => createWshServer({ rpc: { mcp: true } }), /mcp/);
    assert.throws(() => createWshServer({ rpc: { 'bad name': () => {} } }), /protocol name/);
    assert.throws(() => createWshServer({ rpc: { x: 42 } }), /handler/);
  });
});

describe('wsh-host', () => {
  it('host.info matches the ServerHello this connection received; host.ping answers', async () => {
    const { client, server, stop } = await start({ rpc: { 'wsh-host': true }, hostKey: true }, {});
    try {
      const rpc = await client.openRpc('wsh-host');
      const info = await rpc.request('host.info');
      assert.deepEqual(info.features, client.features);
      assert.equal(info.hostFingerprint, server.hostKey().fingerprint);
      assert.equal(info.user, 'alice');
      assert.match(info.version, /^\d+\.\d+\.\d+/);
      assert.deepEqual(info.rpc.protocols, ['wsh-host']);
      const pong = await rpc.request('host.ping');
      assert.equal(typeof pong.time, 'number');
      await assert.rejects(rpc.request('host.nope'), (e) => e.code === RPC_ERROR.METHOD_NOT_FOUND);
      await rpc.close();
    } finally { await stop(); }
  });
});

describe('custom protocols', () => {
  it('server handler gets (channel, ctx); both sides request each other; close propagates', async () => {
    let seenCtx; let serverChannel; let closedReason = null;
    const { client, stop } = await start({
      rpc: {
        custom: (channel, ctx) => {
          seenCtx = ctx; serverChannel = channel;
          channel.onRequest('add', ({ a, b }) => a + b);
          channel.onRequest('ask-back', async () => channel.request('client.name'));
          channel.onClose = (r) => { closedReason = r; };
        },
      },
    });
    try {
      const rpc = await client.openRpc('custom');
      rpc.onRequest('client.name', () => 'alice-client');
      assert.equal(await rpc.request('add', { a: 2, b: 3 }), 5);
      assert.equal(await rpc.request('ask-back'), 'alice-client');
      assert.equal(seenCtx.user, 'alice');
      assert.equal(seenCtx.protocol, 'custom');
      await rpc.close();
      await new Promise((r) => setTimeout(r, 50));
      assert.equal(serverChannel.closed, true);
      assert.ok(closedReason);
    } finally { await stop(); }
  });

  it('a server-side close ends the client channel and rejects its pending requests', async () => {
    const { client, stop } = await start({
      rpc: { custom: (channel) => { channel.onRequest('die', () => { setTimeout(() => channel.close('bye'), 10); return new Promise(() => {}); }); } },
    });
    try {
      const rpc = await client.openRpc('custom');
      const closed = new Promise((r) => { rpc.onClose = r; });
      await assert.rejects(rpc.request('die'), (e) => e.code === RPC_ERROR.CANCELLED && e.reason === 'channel-closed');
      await closed;
      assert.equal(rpc.closed, true);
    } finally { await stop(); }
  });

  it('many concurrent channels and requests do not cross-talk', async () => {
    const { client, stop } = await start({ rpc: { custom: (c) => c.onRequest('id', async (p) => { await new Promise((r) => setTimeout(r, Math.random() * 20)); return p; }) } });
    try {
      const chans = await Promise.all([1, 2, 3].map(() => client.openRpc('custom')));
      const results = await Promise.all(chans.flatMap((c, ci) => [0, 1, 2, 3].map((n) => c.request('id', { ci, n }))));
      let i = 0;
      for (let ci = 0; ci < 3; ci++) for (let n = 0; n < 4; n++) assert.deepEqual(results[i++], { ci, n });
      await Promise.all(chans.map((c) => c.close()));
    } finally { await stop(); }
  });

  it('a handler that throws closes its channel without hurting the connection', async () => {
    const { client, stop } = await start({ rpc: { bad: () => { throw new Error('init failed'); }, ok: (c) => c.onRequest('x', () => 1) } });
    try {
      const bad = await client.openRpc('bad');
      await assert.rejects(bad.request('x'), (e) => e.code === RPC_ERROR.CANCELLED);
      const ok = await client.openRpc('ok');
      assert.equal(await ok.request('x'), 1);
    } finally { await stop(); }
  });

  it('connection teardown closes server channels', async () => {
    let chan;
    const { client, server } = await start({ rpc: { custom: (c) => { chan = c; } } });
    const rpc = await client.openRpc('custom');
    await rpc.request('noop').catch(() => {});
    await client.disconnect();
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(chan.closed, true);
    await server.close();
  });
});

describe('wsh-fs', () => {
  let root; let outside; let ctx;
  before(async () => {
    outside = await mkdtemp(path.join(tmpdir(), 'wsh-rpc-out-'));
    root = await mkdtemp(path.join(tmpdir(), 'wsh-rpc-fs-'));
    await writeFile(path.join(outside, 'secret.txt'), 'top secret');
    await writeFile(path.join(root, 'one.txt'), 'first file');
    await mkdir(path.join(root, 'sub'));
    await writeFile(path.join(root, 'sub', 'deep.txt'), 'deep');
    await symlink(outside, path.join(root, 'escape'));
    ctx = await start({ rpc: { 'wsh-fs': { root, maxFileBytes: 1_000_000 } } });
  });
  after(async () => {
    await ctx.stop();
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });

  const open = () => ctx.client.openRpc('wsh-fs');
  const readAll = async (rpc, params) => {
    const parts = [];
    const result = await rpc.request('read', params, { onProgress: (c) => parts.push(c) });
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
    return { out, parts, result };
  };

  it('stat, list, mkdir, rename, remove', async () => {
    const rpc = await open();
    const st = await rpc.request('stat', { path: 'one.txt' });
    assert.equal(st.name, 'one.txt'); assert.equal(st.size, 10); assert.equal(st.type, 'file');
    const ls = await rpc.request('list', { path: '/' });
    assert.deepEqual(ls.entries.map((e) => e.name).sort(), ['escape', 'one.txt', 'sub']);
    await rpc.request('mkdir', { path: 'made/nested' });
    assert.ok((await readdir(path.join(root, 'made'))).includes('nested'));
    await rpc.request('rename', { path: 'one.txt', newPath: 'renamed.txt' });
    assert.equal(dec.decode(await readFile(path.join(root, 'renamed.txt'))), 'first file');
    await assert.rejects(rpc.request('rename', { path: 'renamed.txt', newPath: 'sub' }), (e) => /exists/.test(e.message));
    await rpc.request('rename', { path: 'renamed.txt', newPath: 'one.txt' });
    await rpc.request('remove', { path: 'made/nested' });
    await rpc.request('remove', { path: 'made' });
    await assert.rejects(rpc.request('stat', { path: 'made' }), (e) => e instanceof RpcError);
    await rpc.close();
  });

  it('write / upload (chunked) / read round-trip, in-place offset writes', async () => {
    const rpc = await open();
    await rpc.request('write', { path: 'w.bin', data: new Uint8Array([1, 2, 3, 4]) });
    await rpc.request('write', { path: 'w.bin', data: new Uint8Array([9]), offset: 1 });
    assert.deepEqual([...await readFile(path.join(root, 'w.bin'))], [1, 9, 3, 4]);
    const big = new Uint8Array(250_000).map((_, i) => i % 253);
    await rpc.request('upload', { path: 'up/big.bin', data: big.subarray(0, 100_000) });
    await rpc.request('upload', { path: 'up/big.bin', data: big.subarray(100_000, 200_000), offset: 100_000 });
    await rpc.request('upload', { path: 'up/big.bin', data: big.subarray(200_000), offset: 200_000 });
    assert.deepEqual(new Uint8Array(await readFile(path.join(root, 'up', 'big.bin'))), big);
    await rpc.close();
  });

  it('read streams chunks via $/progress and ends with a summary result', async () => {
    const rpc = await open();
    const { out, parts, result } = await readAll(rpc, { path: 'up/big.bin' });
    assert.ok(parts.length > 1, `expected several progress chunks, got ${parts.length}`);
    assert.ok(parts.every((p) => p instanceof Uint8Array && p.length <= 64 * 1024));
    assert.equal(out.length, 250_000);
    assert.equal(result.size, 250_000);
    assert.equal(result.length, 250_000);
    const ranged = await readAll(rpc, { path: 'up/big.bin', offset: 70_000, length: 1000 });
    assert.equal(ranged.out.length, 1000);
    assert.equal(ranged.out[0], 70_000 % 253);
    const dl = await rpc.request('download', { path: 'sub/deep.txt' }, { onProgress: () => {} });
    assert.equal(dl.size, 4);
    await rpc.close();
  });

  it('cancelling a chunked read stops the stream', async () => {
    const rpc = await open();
    let n = 0;
    const big = new Uint8Array(900_000).fill(5);
    await rpc.request('upload', { path: 'huge.bin', data: big });
    const p = rpc.request('read', { path: 'huge.bin' }, { onProgress: () => { if (++n === 2) p.cancel(); } });
    await assert.rejects(p, (e) => e.code === RPC_ERROR.CANCELLED);
    await new Promise((r) => setTimeout(r, 100));
    assert.ok(n < 14, `read kept streaming after cancel (${n} chunks)`);
    await rpc.close();
  });

  it('confinement: traversal, absolute paths, and symlink escapes are refused', async () => {
    const rpc = await open();
    for (const p of ['../' + path.basename(outside) + '/secret.txt', 'escape/secret.txt', 'sub/../../x']) {
      await assert.rejects(rpc.request('stat', { path: p }), (e) => e.code === RPC_ERROR.UNAUTHORIZED && /escapes/.test(e.message), p);
      await assert.rejects(rpc.request('read', { path: p }, { onProgress: () => {} }), (e) => e.code === RPC_ERROR.UNAUTHORIZED, p);
      await assert.rejects(rpc.request('write', { path: p, data: new Uint8Array(1) }), (e) => e.code === RPC_ERROR.UNAUTHORIZED, p);
    }
    await assert.rejects(rpc.request('write', { path: 'escape/new.txt', data: new Uint8Array(1) }), (e) => e.code === RPC_ERROR.UNAUTHORIZED);
    assert.deepEqual(await readdir(outside), ['secret.txt']);
    await assert.rejects(rpc.request('read', { path: '/etc/passwd' }, { onProgress: () => {} }), (e) => e instanceof RpcError); // resolved inside root: absent
    await assert.rejects(rpc.request('stat', {}), (e) => e.code === RPC_ERROR.INVALID_PARAMS);
    await assert.rejects(rpc.request('chmod', { path: 'x' }), (e) => e.code === RPC_ERROR.METHOD_NOT_FOUND);
    await rpc.close();
  });

  it('maxFileBytes bounds uploads and whole-file reads', async () => {
    const rpc = await open();
    await assert.rejects(rpc.request('upload', { path: 'toobig.bin', data: new Uint8Array(500_000), offset: 600_000 }), (e) => /limit/.test(e.message));
    await rpc.close();
    const tiny = await start({ rpc: { 'wsh-fs': { root, maxFileBytes: 100 } } });
    try {
      const small = await tiny.client.openRpc('wsh-fs');
      await assert.rejects(small.request('read', { path: 'up/big.bin' }, { onProgress: () => {} }), (e) => /limit/.test(e.message));
      await assert.rejects(small.request('download', { path: 'up/big.bin' }, { onProgress: () => {} }), (e) => /limit/.test(e.message));
      const part = await small.request('read', { path: 'up/big.bin', length: 50 }, { onProgress: () => {} });
      assert.equal(part.length, 50);
    } finally { await tiny.stop(); }
  });

  it('a single message over rpc-max-message is refused locally', async () => {
    const small = await start({ rpc: { 'wsh-fs': { root } }, rpcMaxMessageBytes: 2048 });
    try {
      const rpc = await small.client.openRpc('wsh-fs');
      await assert.rejects(rpc.request('write', { path: 'x', data: new Uint8Array(5000) }), (e) => e.reason === 'message-too-large');
    } finally { await small.stop(); }
  });

  it('readOnly refuses every mutation with -32003 but reads fine', async () => {
    const ro = await start({ rpc: { 'wsh-fs': { root, readOnly: true } } });
    try {
      const rpc = await ro.client.openRpc('wsh-fs');
      assert.equal((await rpc.request('stat', { path: 'sub' })).type, 'directory');
      for (const [m, p] of [['write', { path: 'n', data: new Uint8Array(1) }], ['upload', { path: 'n', data: new Uint8Array(1) }], ['mkdir', { path: 'd' }],
        ['remove', { path: 'sub/deep.txt' }], ['rename', { path: 'sub/deep.txt', newPath: 'z' }]]) {
        await assert.rejects(rpc.request(m, p), (e) => e.code === RPC_ERROR.UNAUTHORIZED && /read-only/.test(e.message), m);
      }
      assert.equal(dec.decode(await readFile(path.join(root, 'sub', 'deep.txt'))), 'deep');
    } finally { await ro.stop(); }
  });

  it('`true` shares the server-level fs option', async () => {
    const shared = await start({ fs: { root, readOnly: true }, rpc: { 'wsh-fs': true } });
    try {
      const rpc = await shared.client.openRpc('wsh-fs');
      assert.equal((await rpc.request('stat', { path: 'sub' })).type, 'directory');
      await assert.rejects(rpc.request('mkdir', { path: 'q' }), (e) => e.code === RPC_ERROR.UNAUTHORIZED);
    } finally { await shared.stop(); }
  });

  describe('the stock file API prefers wsh-fs when advertised', () => {
    it('fileStat/fileList/fileRead/fileWrite/fileRename/fileMkdir/fileRemove work with no FileOp backend at all', async () => {
      const { client } = ctx; // server has no top-level `fs`, so FileOp would fail: success proves the rpc path
      assert.equal((await client.fileStat('sub/deep.txt')).metadata.name, 'deep.txt');
      assert.deepEqual((await client.fileList('sub')).entries.map((e) => e.name), ['deep.txt']);
      assert.equal(dec.decode((await client.fileRead('sub/deep.txt', 0, 100)).metadata.data), 'deep');
      const big = new Uint8Array(600_000).fill(3);
      assert.equal((await client.fileWrite('viarpc/big.bin', big)).metadata.written, 600_000);
      assert.equal((await readFile(path.join(root, 'viarpc', 'big.bin'))).length, 600_000);
      assert.equal((await client.fileWrite('viarpc/big.bin', new Uint8Array([7]), 5)).success, true);
      assert.equal((await readFile(path.join(root, 'viarpc', 'big.bin')))[5], 7);
      assert.equal((await client.fileRename('viarpc/big.bin', 'viarpc/moved.bin')).success, true);
      assert.equal((await client.fileMkdir('viarpc/d')).success, true);
      assert.equal((await client.fileRemove('viarpc/d')).success, true);
      const bad = await client.fileStat('escape/secret.txt');
      assert.equal(bad.success, false);
      assert.match(bad.error_message, /escapes/);
    });

    it('falls back to FileOp when wsh-fs is not advertised, or when preferRpcFiles is off', async () => {
      const plain = await start({ fs: { root } });
      try {
        assert.equal((await plain.client.fileStat('sub')).metadata.name, 'sub');
      } finally { await plain.stop(); }
      // Two different roots tell the two paths apart.
      const other = await mkdtemp(path.join(tmpdir(), 'wsh-rpc-other-'));
      await writeFile(path.join(other, 'only-rpc.txt'), 'r');
      await writeFile(path.join(root, 'only-fileop.txt'), 'f');
      const both = await start({ fs: { root }, rpc: { 'wsh-fs': { root: other } } });
      try {
        assert.equal((await both.client.fileStat('only-rpc.txt')).success, true, 'prefers wsh-fs by default');
        assert.equal((await both.client.fileStat('only-fileop.txt')).success, false);
        both.client.preferRpcFiles = false;
        assert.equal((await both.client.fileStat('only-fileop.txt')).success, true, 'opted out: FileOp');
        assert.equal((await both.client.fileStat('only-rpc.txt')).success, false);
      } finally { await both.stop(); await rm(other, { recursive: true, force: true }); }
    });
  });
});
