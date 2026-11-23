// test/client-env.test.mjs -- #126: a client may set only an allow-list of environment variables by default.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer } from '@johnhenry/wsh/server';
import { clientEnvFilter } from '../src/server/client-env.mjs';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

const dec = new TextDecoder();
const SHOW = 'echo "T=$COLORTERM L=$LC_ALL X=$EVIL P=$BASH_ENV"';

describe('clientEnvFilter', () => {
  it('defaults to TERM, COLORTERM, LANG, LANGUAGE and LC_*', () => {
    const f = clientEnvFilter(undefined);
    assert.deepEqual(f({ TERM: 'xterm', LANG: 'C', LC_ALL: 'C', LC_CTYPE: 'C', COLORTERM: 'truecolor', LANGUAGE: 'en', PATH: '/x', LD_PRELOAD: '/x', BASH_ENV: '/x', LCX: '1' }),
      { TERM: 'xterm', LANG: 'C', LC_ALL: 'C', LC_CTYPE: 'C', COLORTERM: 'truecolor', LANGUAGE: 'en' });
  });
  it('true accepts everything valid, false nothing, a list or predicate what it names', () => {
    const env = { A: '1', B: '2', 'bad name': 'x', C: 3 };
    assert.deepEqual(clientEnvFilter(true)(env), { A: '1', B: '2' });
    assert.deepEqual(clientEnvFilter(false)(env), {});
    assert.deepEqual(clientEnvFilter(['A', 'B*'])({ A: '1', BB: '2', C: '3' }), { A: '1', BB: '2' });
    assert.deepEqual(clientEnvFilter((n, v) => n === 'A' && v === '1')({ A: '1', B: '2' }), { A: '1' });
    assert.deepEqual(clientEnvFilter(() => { throw new Error('x'); })({ A: '1' }), {});
  });
  it('bounds what it looks at and rejects non-objects', () => {
    const f = clientEnvFilter(true);
    assert.deepEqual(f(null), {});
    assert.deepEqual(f([['A', '1']]), {});
    assert.deepEqual(f({ A: 'x\0y', B: 'ok' }), { B: 'ok' });
    assert.equal(Object.keys(f(Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`V${i}`, 'x'])))).length, 64);
    assert.throws(() => clientEnvFilter('yes'), /clientEnv/);
  });
});

describe('clientEnv on a host', () => {
  let keyPair;
  let authorizedKeys;
  before(async () => {
    keyPair = await generateKeyPair(true);
    authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} alice@test\n`;
  });

  async function run(exec, env) {
    const base = { env: { PATH: process.env.PATH } }; // a clean base, so the host's own TERM does not leak in
    const server = createWshServer({ auth: { authorizedKeys }, exec: exec === true ? base : { ...base, ...exec } });
    const { port } = await server.listen();
    const client = new WshClient();
    try {
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
      const s = await client.openSession({ type: 'exec', command: SHOW, env });
      const chunks = [];
      await new Promise((resolve) => { s.onData = (d) => chunks.push(d); s.onClose = resolve; });
      return dec.decode(Buffer.concat(chunks));
    } finally { await client.disconnect(); await server.close(); }
  }

  const ask = { COLORTERM: 'vt100', LC_ALL: 'C', EVIL: 'yes', BASH_ENV: '/tmp/evil' };

  it('drops everything outside the allow-list by default', async () => {
    assert.equal(await run(true, ask), 'T=vt100 L=C X= P=\n');
  });
  it('clientEnv: true accepts everything', async () => {
    assert.equal(await run({ clientEnv: true }, ask), 'T=vt100 L=C X=yes P=/tmp/evil\n');
  });
  it('clientEnv: false accepts nothing, a list or function what it names', async () => {
    assert.equal(await run({ clientEnv: false }, ask), 'T= L= X= P=\n');
    assert.equal(await run({ clientEnv: ['EVIL'] }, ask), 'T= L= X=yes P=\n');
    assert.equal(await run({ clientEnv: (n) => n === 'LC_ALL' }, ask), 'T= L=C X= P=\n');
  });
  it('a custom exec function sees only the allowed variables', async () => {
    let seen;
    const server = createWshServer({ auth: { authorizedKeys }, exec: async (_cmd, io) => { seen = io.env; return 0; } });
    const { port } = await server.listen();
    const client = new WshClient();
    try {
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
      const s = await client.openSession({ type: 'exec', command: 'x', env: ask });
      await new Promise((resolve) => { s.onClose = resolve; });
      assert.deepEqual(seen, { COLORTERM: 'vt100', LC_ALL: 'C' });
    } finally { await client.disconnect(); await server.close(); }
  });
  it('the pty shell gets the same filter', async () => {
    let spawnEnv;
    const spawn = (_f, _a, o) => {
      spawnEnv = o.env;
      return { onData() {}, onExit(cb) { setTimeout(() => cb({ exitCode: 0 }), 10); }, write() {}, resize() {}, kill() {} };
    };
    const server = createWshServer({ auth: { authorizedKeys }, pty: { spawn, shell: '/bin/sh', env: { BASE: '1' } } });
    const { port } = await server.listen();
    const client = new WshClient();
    try {
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
      const s = await client.openSession({ type: 'pty', env: ask });
      await new Promise((resolve) => { s.onClose = resolve; });
      assert.equal(spawnEnv.BASE, '1');
      assert.equal(spawnEnv.LC_ALL, 'C');
      assert.equal(spawnEnv.EVIL, undefined);
      assert.equal(spawnEnv.BASH_ENV, undefined);
    } finally { await client.disconnect(); await server.close(); }
  });
});
