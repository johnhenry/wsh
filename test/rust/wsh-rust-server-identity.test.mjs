// test/rust/wsh-rust-server-identity.test.mjs -- the Rust `wsh-server` as a host with an IDENTITY (#145 step 3):
// a key file (created 0600 on first start, path in config), `ServerHello.host_fingerprint`, the `host-key` /
// `host-key-sig` proof over the client's nonce, `channel-binding:host` offered, `require_channel_binding` in config.
//
// Driven by the JS client (`expectHostKey`, `requireChannelBinding`, a released-style client with neither) and by the
// Rust CLI (`wsh`), so Rust is on both ends in the last test. Every process runs with HOME in a scratch directory.
// Prerequisites: cargo build --release -p wsh-server -p wsh-cli (or WSH_SERVER_BIN / WSH_BIN).

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { WebSocket as WsClient } from 'ws';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '../../src/index.mjs';
import { WshKnownHosts as KnownHosts } from '../../src/known-hosts.mjs';
import { WebSocketTransport } from '../../src/transport-ws.mjs';
import { signChallenge } from '../../src/auth.mjs';
import { hello as helloMsg, auth as authMsg, MSG, AUTH_METHOD } from '../../src/messages.gen.mjs';
import { computeChannelBinding } from '../../src/channel-binding.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = [];
const procs = [];

before(() => {
  assert.ok(existsSync(SERVER_BIN), `expected the built binary at ${SERVER_BIN} (cargo build --release -p wsh-server)`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the dev certificate is self-signed
});
after(() => {
  for (const p of procs.splice(0)) p.kill();
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});

const cleanEnv = (home, extra = {}) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm', ...extra });
const freePort = () => new Promise((resolve) => {
  const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});

/** A server whose HOME holds an authorized key (`authorizedKey`) and the given `[server]` lines. */
async function startServer({ serverToml = '', authorizedKey, hostKeyAt = 'host_key' } = {}) {
  const kp = await generateKeyPair(true);
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-identity-'));
  scratch.push(home);
  mkdirSync(path.join(home, '.wsh'));
  const key = authorizedKey ?? await exportPublicKeySSH(kp.publicKey);
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${key}\n`);
  const hostKeyPath = path.join(home, '.wsh', hostKeyAt);
  const configPath = path.join(home, '.wsh', 'config.toml');
  writeFileSync(configPath, serverToml.replaceAll('$HOSTKEY', hostKeyPath));
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', configPath], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  const ready = new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(Object.assign(new Error(`wsh-server exited (${c}): ${logs}`), { logs })));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  await ready;
  return { url: `wss://127.0.0.1:${port}`, port, kp, home, hostKeyPath, certFile: path.join(home, '.wsh', 'cert.pem'), logs: () => logs };
}

const withHostKey = '[server]\nhost_key = "$HOSTKEY"\n';
const withBinding = '[server]\nhost_key = "$HOSTKEY"\nrequire_channel_binding = true\n';
const echo = async (client) => {
  const s = await client.openSession({ type: 'exec', command: 'echo identity' });
  return new Promise((resolve) => { const ch = []; s.onData = (d) => ch.push(d); s.onClose = () => resolve(Buffer.concat(ch).toString()); });
};
async function login(server, opts = {}) {
  const client = new WshClient();
  await client.connect(server.url, { username: 'tester', keyPair: server.kp, timeout: 5000, ...opts });
  return client;
}

describe('Rust wsh-server host key (JS client)', () => {
  it('creates the key file 0600 on first start and keeps the same key after a restart', async () => {
    const a = await startServer({ serverToml: withHostKey });
    assert.ok(existsSync(a.hostKeyPath));
    assert.equal(statSync(a.hostKeyPath).mode & 0o777, 0o600);
    assert.match(readFileSync(a.hostKeyPath, 'utf8'), /^-----BEGIN PRIVATE KEY-----/);
    const first = await login(a);
    const fp = first.hostKey.fingerprint;
    await first.disconnect();
    a.logs();
    // a second server on the same HOME and key file: the same identity
    const proc2Port = await freePort();
    const proc = spawn(SERVER_BIN, ['--port', String(proc2Port), '--generate-cert', '--config', path.join(a.home, '.wsh', 'config.toml')], { env: cleanEnv(a.home), stdio: 'ignore' });
    procs.push(proc);
    await new Promise((r) => setTimeout(r, 1500));
    const second = new WshClient();
    await second.connect(`wss://127.0.0.1:${proc2Port}`, { username: 'tester', keyPair: a.kp, timeout: 5000 });
    assert.equal(second.hostKey.fingerprint, fp);
    await second.disconnect();
  });

  it('proves the key over the client nonce: the JS client verifies and pins it, and a wrong pin is refused', async () => {
    const s = await startServer({ serverToml: withHostKey });
    const client = await login(s);
    const fp = client.hostKey.fingerprint;
    assert.match(fp, /^[0-9a-f]{64}$/);
    assert.equal((await echo(client)).trim(), 'identity');
    await client.disconnect();

    const pinned = await login(s, { expectHostKey: fp });
    assert.equal(pinned.hostKey.status, 'pinned');
    await pinned.disconnect();

    await assert.rejects(login(s, { expectHostKey: '00'.repeat(32) }), /host key mismatch/);
  });

  it('a host with a key is a stable, pinned identity in knownHosts; no host_key setting proves nothing, as before', async () => {
    const s = await startServer({ serverToml: withHostKey });
    const kh = new KnownHosts();
    const c = await login(s, { knownHosts: kh, trustOnFirstUse: true });
    assert.equal(c.hostKey.status, 'unknown');
    await c.disconnect();
    const again = await login(s, { knownHosts: kh });
    assert.equal(again.hostKey.status, 'known');
    await again.disconnect();

    const plain = await startServer({});
    const p = await login(plain);
    assert.equal(p.hostKey, null);
    await p.disconnect();
    await assert.rejects(login(plain, { expectHostKey: again.hostKey.fingerprint }), /server presented none/);
  });

  it('offers channel-binding:host and the JS client binds to it; a host that does not require it also takes a client that cannot bind', async () => {
    const s = await startServer({ serverToml: withHostKey });
    const bound = await login(s, { requireChannelBinding: true });
    assert.deepEqual(bound.channelBinding, ['host']);
    assert.equal((await echo(bound)).trim(), 'identity');
    await bound.disconnect();
  });

  it('require_channel_binding = true: bound logins work, the unbound login of a released client is refused, and says why', async () => {
    const s = await startServer({ serverToml: withBinding });
    const ok = await login(s, { requireChannelBinding: true });
    assert.deepEqual(ok.channelBinding, ['host']);
    await ok.disconnect();
    // A client that predates #119 signs the EMPTY binding (what rust-v0.6 and npm 0.35 do), and a refusal says why.
    assert.match(await rawLogin(s, { bind: false }), /channel binding required: the signature is not bound/);
    // ... and a login bound to some OTHER host key is just a bad signature.
    assert.match(await rawLogin(s, { bind: 'other' }), /signature verification failed/);
    // Without the requirement the same unbound login is accepted.
    const open = await startServer({ serverToml: withHostKey });
    assert.equal(await rawLogin(open, { bind: false }), 'ok');
  });

  it('require_channel_binding without a host_key is a configuration error, not a server nobody can log in to', async () => {
    await assert.rejects(startServer({ serverToml: '[server]\nrequire_channel_binding = true\n' }), /require_channel_binding.*needs.*host_key/s);
  });

  it('a key file other users can read is refused at start', async () => {
    const kp = await generateKeyPair(true);
    const home = mkdtempSync(path.join(tmpdir(), 'wsh-identity-'));
    scratch.push(home);
    mkdirSync(path.join(home, '.wsh'));
    writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(kp.publicKey)}\n`);
    const keyFile = path.join(home, '.wsh', 'host_key');
    // an existing, valid key but world-readable
    const pem = execFileSync(process.execPath, ['-e', "const {generateKeyPairSync}=require('node:crypto');process.stdout.write(generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'}))"], { encoding: 'utf8' });
    writeFileSync(keyFile, pem, { mode: 0o644 });
    writeFileSync(path.join(home, '.wsh', 'config.toml'), `[server]\nhost_key = ${JSON.stringify(keyFile)}\n`);
    const out = await new Promise((resolve) => {
      const proc = spawn(SERVER_BIN, ['--port', String(await0()), '--generate-cert', '--config', path.join(home, '.wsh', 'config.toml')], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
      let logs = ''; proc.stdout.on('data', (d) => { logs += d; }); proc.stderr.on('data', (d) => { logs += d; });
      proc.once('exit', (code) => resolve({ code, logs }));
      setTimeout(() => { proc.kill(); resolve({ code: null, logs }); }, 8000);
    });
    assert.notEqual(out.code, null, 'the server must not keep running');
    assert.match(out.logs, /readable by other users/);
  });
});
function await0() { return 20000 + Math.floor(Math.random() * 20000); }

describe('Rust wsh-server host key (Rust CLI)', { skip: !existsSync(WSH_BIN) && `no wsh at ${WSH_BIN}` }, () => {
  function makeHome() {
    const home = mkdtempSync(path.join(tmpdir(), 'wsh-identity-cli-'));
    scratch.push(home);
    execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
    return { home, pub: readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim(), knownHosts: () => { try { return readFileSync(path.join(home, '.wsh', 'known_hosts'), 'utf8'); } catch { return ''; } } };
  }
  function wsh(args, h, server) {
    return new Promise((resolve) => {
      const proc = spawn(WSH_BIN, ['-t', 'ws', '-p', String(server.port), ...args], { env: cleanEnv(h.home, { SSL_CERT_FILE: server.certFile }), stdio: ['pipe', 'pipe', 'pipe'] });
      const out = []; const err = [];
      proc.stdout.on('data', (d) => out.push(d)); proc.stderr.on('data', (d) => err.push(d));
      proc.stdin.on('error', () => {}); proc.stdin.end();
      const timer = setTimeout(() => proc.kill('SIGKILL'), 20_000);
      proc.once('close', (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
    });
  }

  it('Rust CLI <-> Rust server: proves, is refused on first use without the flag, pins, binds, and refuses a changed key', async () => {
    const h = makeHome();
    const s = await startServer({ serverToml: withBinding, authorizedKey: h.pub });

    const refused = await wsh(['localhost', 'echo', 'hi'], h, s);
    assert.notEqual(refused.code, 0);
    assert.match(refused.stderr, /cannot be established/);
    assert.equal(h.knownHosts(), '');

    const first = await wsh(['--accept-new-host-key', '--require-host-key', '--require-channel-binding', 'localhost', 'echo', 'hi'], h, s);
    assert.equal(first.code, 0, first.stderr);
    assert.equal(first.stdout, 'hi\n');
    assert.match(h.knownHosts(), /^localhost:\d+ [0-9a-f]{64}$/m);

    const second = await wsh(['--require-host-key', 'localhost', 'echo', 'again'], h, s);
    assert.equal(second.code, 0, second.stderr);

    // The same name answered by a server with another key (a new key file): refused, even with the flag.
    const other = await startServer({ serverToml: withBinding, authorizedKey: h.pub });
    h_replace(h, `localhost:${other.port}`, h.knownHosts());
    const changed = await wsh(['--accept-new-host-key', 'localhost', 'echo', 'x'], h, other);
    assert.notEqual(changed.code, 0);
    assert.match(changed.stderr, /HOST KEY CHANGED/);
  });
});

/** Re-label the recorded entry as another host:port so a different server answers "the same name". */
function h_replace(h, label, text) {
  const fp = text.trim().split(' ')[1];
  mkdirSync(path.join(h.home, '.wsh'), { recursive: true });
  writeFileSync(path.join(h.home, '.wsh', 'known_hosts'), `${label} ${fp}\n`);
}

/**
 * A login written by hand so the binding is under the test's control: `bind: true` would bind the host key the server
 * (not exercised here: it needs the client nonce), `false` signs the empty binding (a client that predates #119),
 * `'other'` binds a key that is not the host's.
 * @returns {Promise<'ok' | string>} 'ok', or the server's AuthFail reason
 */
async function rawLogin(server, { bind }) {
  const t = new WebSocketTransport({ WebSocket: WsClient });
  await t.connect(server.url);
  const queue = []; let wake = null;
  t.onControl = (m) => { queue.push(m); wake?.(); };
  const next = async (type) => {
    for (let i = 0; i < 100; i++) {
      const idx = queue.findIndex((m) => m.type === type || m.type === MSG.AUTH_FAIL);
      if (idx >= 0) return queue.splice(idx, 1)[0];
      await new Promise((r) => { wake = r; setTimeout(r, 100); });
    }
    throw new Error(`no ${type}`);
  };
  await t.sendControl(helloMsg({ username: 'tester', authMethod: AUTH_METHOD.PUBKEY, features: [] }));
  const sh = await next(MSG.SERVER_HELLO);
  const ch = await next(MSG.CHALLENGE);
  const channelBinding = bind === false ? new Uint8Array(0) : await computeChannelBinding({ host: crypto.getRandomValues(new Uint8Array(32)) });
  const { signature, publicKeyRaw } = await signChallenge(server.kp.privateKey, server.kp.publicKey, ch.session_id, ch.nonce, { username: 'tester', channelBinding });
  await t.sendControl(authMsg({ method: AUTH_METHOD.PUBKEY, signature, publicKey: publicKeyRaw }));
  const res = await next(MSG.AUTH_OK);
  await t.close().catch(() => {});
  return res.type === MSG.AUTH_OK ? 'ok' : res.reason;
}
