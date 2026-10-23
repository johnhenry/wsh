// test/exec-stdin.test.mjs -- WshClient.exec({ stdin }) and WshSession.closeStdin() (#104).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer, parseAuthorizedKeys } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

const dec = new TextDecoder();
const enc = new TextEncoder();

describe('exec stdin + EOF (#104)', () => {
  let keyPair, server, url;
  before(async () => {
    keyPair = await generateKeyPair(true);
    const authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} alice@test\n`;
    server = createWshServer({ auth: { authorizedKeys }, exec: true });
    const { port } = await server.listen();
    url = `ws://127.0.0.1:${port}`;
  });
  after(() => server.close());

  const run = (cmd, opts = {}) =>
    WshClient.exec(url, cmd, { username: 'alice', keyPair, timeout: 10000, ...opts });

  it('string stdin reaches `cat` and ends with EOF', async () => {
    const { stdout, exitCode } = await run('cat', { stdin: 'a\nb\n' });
    assert.equal(dec.decode(stdout), 'a\nb\n');
    assert.equal(exitCode, 0);
  });

  it('Uint8Array stdin: `wc -c` counts 1000 bytes', async () => {
    const { stdout, exitCode } = await run('wc -c', { stdin: new Uint8Array(1000) });
    assert.equal(dec.decode(stdout).trim(), '1000');
    assert.equal(exitCode, 0);
  });

  it('ReadableStream stdin is piped in order and then closed', async () => {
    const stdin = new ReadableStream({
      start(c) { c.enqueue(enc.encode('one\n')); c.enqueue('two\n'); c.enqueue(enc.encode('three\n')); c.close(); },
    });
    const { stdout } = await run('cat', { stdin });
    assert.equal(dec.decode(stdout), 'one\ntwo\nthree\n');
  });

  it('async iterable stdin works too', async () => {
    async function* gen() { yield 'x'; yield enc.encode('y\n'); }
    const { stdout } = await run('cat', { stdin: gen() });
    assert.equal(dec.decode(stdout), 'xy\n');
  });

  it('empty stdin still delivers EOF', async () => {
    const { stdout, exitCode } = await run('wc -c', { stdin: '' });
    assert.equal(dec.decode(stdout).trim(), '0');
    assert.equal(exitCode, 0);
  });

  it('`sh -s` runs a script supplied on stdin', async () => {
    const { stdout } = await run('sh -s', { stdin: 'echo from-stdin\nexit 4\n' });
    assert.equal(dec.decode(stdout), 'from-stdin\n');
  });

  it('large stdin (4 MiB) is delivered intact', async () => {
    const big = new Uint8Array(4 * 1024 * 1024).fill(97);
    const { stdout } = await run('wc -c', { stdin: big });
    assert.equal(dec.decode(stdout).trim(), String(big.length));
  });

  it('works with a legacy-primer client path (primer: true, explicit)', async () => {
    const { stdout } = await run('cat', { stdin: 'p\n', primer: true });
    assert.equal(dec.decode(stdout), 'p\n');
  });

  it('without stdin behaviour is unchanged', async () => {
    const { stdout, exitCode } = await run('echo hello');
    assert.equal(dec.decode(stdout), 'hello\n');
    assert.equal(exitCode, 0);
  });

  it('rejects an unsupported stdin type', async () => {
    await assert.rejects(run('cat', { stdin: 42 }), /stdin/);
  });

  describe('session.closeStdin()', () => {
    it('sends EOF without closing the session; output still arrives and exit is reported', async () => {
      const client = new WshClient();
      await client.connect(url, { username: 'alice', keyPair });
      try {
        const session = await client.openSession({ type: 'exec', command: 'cat' });
        const chunks = [];
        session.onData = (d) => chunks.push(d);
        const exited = new Promise((r) => { session.onExit = r; });
        const closed = new Promise((r) => { session.onClose = r; });
        await session.write('hi\n');
        await session.closeStdin();
        assert.equal(await exited, 0);
        await closed;
        assert.equal(dec.decode(Buffer.concat(chunks)), 'hi\n');
      } finally { await client.disconnect(); }
    });

    it('is idempotent and write-after-closeStdin rejects', async () => {
      const client = new WshClient();
      await client.connect(url, { username: 'alice', keyPair });
      try {
        const session = await client.openSession({ type: 'exec', command: 'cat' });
        const closed = new Promise((r) => { session.onClose = r; });
        await session.closeStdin();
        await session.closeStdin();
        await assert.rejects(session.write('late'), /stdin/i);
        await closed;
      } finally { await client.disconnect(); }
    });
  });
});
