// test/server.test.mjs -- `@johnhenry/wsh/server` driven by the stock client.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, mkdir, symlink, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createWshServer, parseAuthorizedKeys } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH, WshFileTransfer } from '@johnhenry/wsh';

const dec = new TextDecoder();
const enc = new TextEncoder();

async function start(opts) {
  const server = createWshServer(opts);
  const { port } = await server.listen();
  return { server, url: `ws://127.0.0.1:${port}` };
}

async function connect(url, keyPair, username = 'alice') {
  const client = new WshClient();
  await client.connect(url, { username, keyPair });
  return client;
}

const collect = (session) => new Promise((resolve) => {
  const chunks = [];
  session.onData = (d) => chunks.push(d);
  session.onClose = () => resolve(dec.decode(Buffer.concat(chunks)));
});

describe('package boundary', () => {
  it('the browser-safe root entry never imports the Node server', async () => {
    const src = await readFile(new URL('../src/index.mjs', import.meta.url), 'utf8');
    assert.ok(!/server\//.test(src.replace(/\/\/.*$/gm, '')), 'src/index.mjs must not reference src/server');
    const root = await import('@johnhenry/wsh');
    assert.equal('createWshServer' in root, false);
  });
});

describe('createWshServer', () => {
  let keyPair;
  let otherKey;
  let authorizedKeys;
  before(async () => {
    keyPair = await generateKeyPair(true);
    otherKey = await generateKeyPair(true);
    authorizedKeys = `# comment\n${await exportPublicKeySSH(keyPair.publicKey)} alice@test\nnot a key\n`;
  });

  it('parseAuthorizedKeys skips comments and malformed lines', async () => {
    assert.equal(parseAuthorizedKeys(authorizedKeys).length, 1);
  });

  it('listens on an OS-assigned port, reports address(), and closes', async () => {
    const server = createWshServer();
    assert.equal(server.address(), null);
    const bound = await server.listen();
    assert.equal(bound.address, '127.0.0.1');
    assert.ok(bound.port > 0);
    assert.deepEqual(server.address(), bound);
    await server.close();
    assert.equal(server.address(), null);
  });

  describe('exec', () => {
    let ctx;
    before(async () => { ctx = await start({ auth: { authorizedKeys }, exec: true }); });
    after(() => ctx.server.close());

    it('the consumer scenario: static exec of `echo hello` with no primer', async () => {
      const { stdout, exitCode } = await WshClient.exec(ctx.url, 'echo hello', { username: 'alice', keyPair, timeout: 5000 });
      assert.equal(dec.decode(stdout), 'hello\n');
      assert.equal(exitCode, 0);
    });

    it('advertises stream-announce and the stock client then writes no primer', async () => {
      const client = await connect(ctx.url, keyPair);
      try {
        assert.ok(client.hasFeature('stream-announce'));
        const session = await client.openSession({ type: 'exec', command: 'read -r x; echo "got:$x"' });
        const out = collect(session);
        await session.write('abc\n');
        // `got:abc` and nothing before it proves no stray 0x00 reached stdin.
        assert.equal(await out, 'got:abc\n');
      } finally { await client.disconnect(); }
    });

    it('#65: an un-primed client (primer: false, nothing ever written) still gets its output', async () => {
      // The issue's scenario: a stream-mode exec whose client never writes a byte.
      // The transport's empty-STREAM-frame announce is what lets the host bind it.
      const { stdout, exitCode } = await WshClient.exec(ctx.url, 'echo hello', { username: 'alice', keyPair, primer: false, timeout: 5000 });
      assert.equal(dec.decode(stdout), 'hello\n');
      assert.equal(exitCode, 0);
      const client = await connect(ctx.url, keyPair);
      try {
        const session = await client.openSession({ type: 'exec', command: 'echo hi', primer: false });
        assert.equal(session.dataMode, 'stream');
        assert.equal(await collect(session), 'hi\n');
      } finally { await client.disconnect(); }
    });

    it('drops a lone leading 0x00 from a client that primes anyway', async () => {
      const client = await connect(ctx.url, keyPair);
      try {
        const session = await client.openSession({ type: 'exec', command: 'read -r x; echo "got:$x"', primer: false });
        const out = collect(session);
        await session.write(new Uint8Array([0]));
        await session.write('abc\n');
        assert.equal(await out, 'got:abc\n');
      } finally { await client.disconnect(); }
    });

    it('propagates exit codes and stderr', async () => {
      const client = await connect(ctx.url, keyPair);
      try {
        const session = await client.openSession({ type: 'exec', command: 'echo oops >&2; exit 3' });
        const exited = new Promise((r) => { session.onExit = r; });
        const out = collect(session);
        assert.equal(await out, 'oops\n');
        assert.equal(await exited, 3);
      } finally { await client.disconnect(); }
    });

    it('applies client env and handles several concurrent sessions', async () => {
      const client = await connect(ctx.url, keyPair);
      try {
        const sessions = await Promise.all([1, 2, 3].map((n) =>
          client.openSession({ type: 'exec', command: 'echo "$N"', env: { N: String(n) } })));
        const outs = await Promise.all(sessions.map(collect));
        assert.deepEqual(outs, ['1\n', '2\n', '3\n']);
      } finally { await client.disconnect(); }
    });

    it('closing a session kills a long-running command', async () => {
      const client = await connect(ctx.url, keyPair);
      try {
        const session = await client.openSession({ type: 'exec', command: 'sleep 30' });
        const closed = new Promise((r) => { session.onClose = r; });
        await session.signal('TERM');
        await closed;
      } finally { await client.disconnect(); }
    });

    it('pty and file channels are refused when not enabled', async () => {
      const client = await connect(ctx.url, keyPair);
      try {
        await assert.rejects(() => client.openSession({ type: 'pty' }), /not enabled/);
        await assert.rejects(() => client.download('x'), /not enabled/);
        const r = await client.fileList('/');
        assert.equal(r.success, false);
      } finally { await client.disconnect(); }
    });
  });

  describe('auth', () => {
    it('refuses a key that is not on the allowlist', async () => {
      const { server, url } = await start({ auth: { authorizedKeys }, exec: true });
      try {
        await assert.rejects(() => connect(url, otherKey));
      } finally { await server.close(); }
    });

    it('refuses everyone when no auth is configured', async () => {
      const { server, url } = await start({ exec: true });
      try {
        await assert.rejects(() => connect(url, keyPair));
      } finally { await server.close(); }
    });

    it('supports a custom authorize() policy, including the username', async () => {
      const seen = [];
      const { server, url } = await start({ exec: true, auth: (who) => { seen.push(who.username); return who.username === 'alice'; } });
      try {
        const ok = await connect(url, keyPair, 'alice');
        await ok.disconnect();
        await assert.rejects(() => connect(url, keyPair, 'mallory'));
        assert.deepEqual(seen, ['alice', 'mallory']);
      } finally { await server.close(); }
    });

    it('refuses exec when exec is not enabled', async () => {
      const { server, url } = await start({ auth: { authorizedKeys } });
      try {
        const client = await connect(url, keyPair);
        await assert.rejects(() => client.openSession({ type: 'exec', command: 'echo hi' }), /not enabled/);
        await client.disconnect();
      } finally { await server.close(); }
    });
  });

  describe('custom exec runner', () => {
    it('runs a restricted host with no shell', async () => {
      const { server, url } = await start({
        auth: { authorizedKeys },
        exec: { run: async (command, io) => { await io.write(`<${io.user}:${command}>`); return 7; } },
      });
      try {
        const { stdout, exitCode } = await WshClient.exec(url, 'anything', { username: 'alice', keyPair, timeout: 5000 });
        assert.equal(dec.decode(stdout), '<alice:anything>');
        assert.equal(exitCode, 7);
      } finally { await server.close(); }
    });
  });

  describe('pty', () => {
    it('bridges an injected pty implementation (virtual data mode, input, resize, exit)', async () => {
      const calls = [];
      let dataCb; let exitCb;
      const fakeSpawn = (file, args, o) => {
        calls.push(['spawn', file, args, o.cols, o.rows]);
        return {
          onData: (cb) => { dataCb = cb; },
          onExit: (cb) => { exitCb = cb; },
          write: (d) => { calls.push(['write', dec.decode(d)]); dataCb(`echo:${dec.decode(d)}`); },
          resize: (c, r) => calls.push(['resize', c, r]),
          kill: () => exitCb({ exitCode: 0 }),
        };
      };
      const { server, url } = await start({ auth: { authorizedKeys }, pty: { spawn: fakeSpawn, shell: '/bin/sh' } });
      const client = await connect(url, keyPair);
      try {
        const session = await client.openSession({ type: 'pty', cols: 100, rows: 30 });
        assert.equal(session.dataMode, 'virtual');
        const got = new Promise((r) => { session.onData = (d) => r(dec.decode(d)); });
        await session.write('ls\n');
        assert.equal(await got, 'echo:ls\n');
        await session.resize(120, 40);
        await new Promise((r) => setTimeout(r, 100));
        const exited = new Promise((r) => { session.onExit = r; });
        exitCb({ exitCode: 5 });
        assert.equal(await exited, 5);
        assert.deepEqual(calls[0], ['spawn', '/bin/sh', [], 100, 30]);
        assert.ok(calls.some((c) => c[0] === 'resize' && c[1] === 120 && c[2] === 40));
      } finally { await client.disconnect(); await server.close(); }
    });
  });

  describe('fs', () => {
    let root; let outside; let ctx; let client;
    before(async () => {
      root = await mkdtemp(path.join(tmpdir(), 'wsh-fs-'));
      outside = await mkdtemp(path.join(tmpdir(), 'wsh-outside-'));
      await writeFile(path.join(root, 'a.txt'), 'hello file');
      await mkdir(path.join(root, 'sub'));
      await writeFile(path.join(outside, 'secret'), 'nope');
      await symlink(outside, path.join(root, 'escape'));
      ctx = await start({ auth: { authorizedKeys }, fs: { root, maxFileBytes: 1024 } });
      client = await connect(ctx.url, keyPair);
    });
    after(async () => {
      await client.disconnect();
      await ctx.server.close();
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    });

    it('lists, stats and reads', async () => {
      const files = new WshFileTransfer(client);
      const list = await files.list('/');
      assert.deepEqual(list.map((e) => [e.name, e.type]).sort(), [['a.txt', 'file'], ['escape', 'symlink'], ['sub', 'directory']]);
      const st = await client.fileStat('a.txt');
      assert.equal(st.success, true);
      assert.equal(st.metadata.size, 10);
      const rd = await client.fileRead('a.txt', 6, 4);
      assert.equal(dec.decode(rd.metadata.data), 'file');
    });

    it('uploads then downloads, byte for byte', async () => {
      const payload = enc.encode('uploaded bytes');
      await client.upload(payload, 'sub/up.bin');
      assert.equal(await readFile(path.join(root, 'sub/up.bin'), 'utf8'), 'uploaded bytes');
      assert.deepEqual(await client.download('sub/up.bin'), payload);
    });

    it('mkdir and remove work', async () => {
      assert.equal((await client.fileMkdir('made/deep')).success, true);
      assert.ok((await stat(path.join(root, 'made/deep'))).isDirectory());
      assert.equal((await client.fileRemove('made/deep')).success, true);
    });

    it('refuses traversal, absolute escapes and symlink escapes', async () => {
      for (const p of ['../' + path.basename(outside) + '/secret', 'escape/secret', 'escape']) {
        const r = await client.fileStat(p);
        assert.equal(r.success, false, p);
        await assert.rejects(() => client.download(p), undefined, p);
      }
      await assert.rejects(() => client.upload(enc.encode('x'), 'escape/new'));
      await assert.rejects(() => stat(path.join(outside, 'new')));
      const abs = await client.fileStat(path.join(outside, 'secret'));
      assert.equal(abs.success, false);
    });

    it('enforces maxFileBytes on upload', async () => {
      await assert.rejects(() => client.upload(new Uint8Array(2048), 'big.bin'), /exit code 1/);
      await assert.rejects(() => stat(path.join(root, 'big.bin')));
    });

    it('readOnly refuses writes', async () => {
      const ro = await start({ auth: { authorizedKeys }, fs: { root, readOnly: true } });
      const c = await connect(ro.url, keyPair);
      try {
        assert.equal((await c.fileMkdir('nope')).success, false);
        await assert.rejects(() => c.upload(enc.encode('x'), 'ro.txt'));
        assert.equal(dec.decode(await c.download('a.txt')), 'hello file');
      } finally { await c.disconnect(); await ro.server.close(); }
    });
  });
});
