// test/objects-types-cli.test.mjs -- `wsh-objects-types` (#219): a child process that connects to a host, asks what its key may do on a root, and writes the declarations
// (to standard output, or to --out only when asked). HOME is a scratch directory; the only key is the one this test makes.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createWshServer } from '@johnhenry/wsh/server';
import { generateKeyPair, exportPublicKeySSH, exportPrivateKeyPKCS8 } from '@johnhenry/wsh';
import { exposeObjects } from '@johnhenry/wsh/objects';
import { describeRootTypes } from '@johnhenry/wsh/objects-types';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'wsh-objects-types.mjs');
const ALLOW = { get: ['window.document.title', 'window.app.cart.items'], call: ['window.app.cart.add'], set: ['window.document.title'], on: ['window.app.bus@ready'] };
const TYPES = { 'window.document.title': { value: 'string' }, 'window.app.cart.add': { args: '[item: { sku: string }]', result: 'number' } };

describe('wsh-objects-types: the declarations of what this key may do', () => {
  let scratch; let keyPair; let identity; let keyLine;
  const cleanups = [];
  before(async () => {
    scratch = await mkdtemp(path.join(tmpdir(), 'wsh-types-'));
    await mkdir(path.join(scratch, 'keys'));
    keyPair = await generateKeyPair(true);
    keyLine = await exportPublicKeySSH(keyPair.publicKey);
    const pkcs8 = await exportPrivateKeyPKCS8(keyPair.privateKey);
    identity = path.join(scratch, 'keys', 'default.pem');
    await writeFile(identity, `-----BEGIN PRIVATE KEY-----\n${Buffer.from(pkcs8).toString('base64')}\n-----END PRIVATE KEY-----\n`, { mode: 0o600 });
  });
  after(async () => {
    for (const c of cleanups.splice(0).reverse()) await c().catch(() => {});
    await rm(scratch, { recursive: true, force: true });
  });

  async function host({ capabilities, roots } = {}) {
    const server = createWshServer({
      auth: { authorizedKeys: `${capabilities ? `capabilities="${capabilities}" ` : ''}${keyLine} alice@test\n` },
      rpc: { 'wsh-objects': exposeObjects({ roots: roots ?? { window: {} }, allow: ALLOW, types: TYPES, eventFields: { '*': ['detail'] } }) },
    });
    const { port } = await server.listen();
    cleanups.push(() => server.close());
    return `ws://127.0.0.1:${port}`;
  }
  const run = (args) => new Promise((resolve) => {
    const proc = spawn(process.execPath, [BIN, ...args], { env: { PATH: process.env.PATH, HOME: scratch, USERPROFILE: scratch, XDG_CONFIG_HOME: path.join(scratch, '.config'), USER: 'alice' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    proc.stdout.on('data', (d) => { stdout += d; });
    proc.stderr.on('data', (d) => { stderr += d; });
    proc.once('close', (code) => resolve({ code, stdout, stderr })); // 'close', not 'exit': 'exit' can fire before the last of stdout/stderr has been read
    cleanups.push(async () => { proc.kill('SIGKILL'); });
  });
  const expected = (extra = {}, options) => describeRootTypes({ root: 'window', allow: ALLOW, eventFields: { '*': ['detail'] }, types: TYPES, ...extra }, options);

  it('prints the declarations of the only root the key may use, and writes no file unless --out is given', async () => {
    const url = await host();
    const before = await readdir(scratch);
    const r = await run(['--identity', identity, '--user', 'alice', url]);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, expected());
    assert.deepEqual(await readdir(scratch), before, 'nothing was written');
  });

  it('--out writes the file and refuses to overwrite it without --force; --name names the type', async () => {
    const url = await host();
    const out = path.join(scratch, 'window-remote.d.ts');
    const a = await run(['--identity', identity, '--user', 'alice', '--name', 'ShopWindow', '--out', out, url]);
    assert.equal(a.code, 0, a.stderr);
    assert.equal(await readFile(out, 'utf8'), expected({}, { name: 'ShopWindow' }));
    const b = await run(['--identity', identity, '--user', 'alice', '--out', out, url]);
    assert.equal(b.code, 2);
    assert.match(b.stderr, /exists \(--force overwrites it\)/);
    assert.equal(await readFile(out, 'utf8'), expected({}, { name: 'ShopWindow' }), 'the existing file is untouched');
    const c = await run(['--identity', identity, '--user', 'alice', '--force', '--out', out, url]);
    assert.equal(c.code, 0, c.stderr);
    assert.equal(await readFile(out, 'utf8'), expected());
  });

  it('the file says only what this key may do: a key that may only read gets no call, set or event in it', async () => {
    const url = await host({ capabilities: 'objects:window:get' });
    const r = await run(['--identity', identity, '--user', 'alice', url]);
    assert.equal(r.code, 0, r.stderr);
    const body = r.stdout.slice(r.stdout.indexOf('export type'));
    assert.match(body, /title/);
    assert.doesNotMatch(body, /RemoteCall|WithSet|WithEvents|add|bus/);
  });

  it('several roots need --root; an unknown one is refused; a bad name is refused; nothing is printed on failure', async () => {
    const url = await host({ roots: { window: {}, store: {} } });
    const many = await run(['--identity', identity, '--user', 'alice', url]);
    assert.equal(many.code, 2);
    assert.match(many.stderr, /several roots.*--root/);
    assert.equal(many.stdout, '');
    const wrong = await run(['--identity', identity, '--user', 'alice', '--root', 'nope', url]);
    assert.equal(wrong.code, 2);
    assert.equal(wrong.stdout, '');
    const one = await run(['--identity', identity, '--user', 'alice', '--root', 'window', url]);
    assert.equal(one.code, 0, one.stderr);
    const badName = await run(['--identity', identity, '--user', 'alice', '--root', 'window', '--name', 'class', url]);
    assert.equal(badName.code, 2);
    assert.match(badName.stderr, /usable type name/);
  });

  it('usage errors and a host that cannot be reached exit with status 2 and a sentence', async () => {
    assert.equal((await run([])).code, 2);
    const bad = await run(['--identity', identity, 'ftp://x']);
    assert.equal(bad.code, 2);
    assert.match(bad.stderr, /expected a ws/);
    const gone = await run(['--identity', identity, '--user', 'alice', '--timeout', '1500', 'ws://127.0.0.1:9']);
    assert.equal(gone.code, 2);
    const help = await run(['--help']);
    assert.equal(help.code, 0);
    assert.match(help.stdout, /Usage: wsh-objects-types/);
  });
});
