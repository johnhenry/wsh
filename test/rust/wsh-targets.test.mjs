// test/rust/wsh-targets.test.mjs -- execution targets (#121) with Rust on one end:
//
//   Rust CLI (`wsh --target NAME`, `wsh targets`)  ->  a JS host with two targets (`createWshServer({ targets })`): a key allowed on
//     one is refused on the other, and each key lists only what it may use.
//   JS client and Rust CLI  ->  the Rust `wsh-server`, which has no targets: it states no `targets` feature, a client does not send
//     one, and one that does anyway is refused (never run on the server itself).
//
// Every binary runs with HOME in a scratch directory. Prerequisites: cargo build --release -p wsh-cli -p wsh-server
// (or WSH_BIN / WSH_SERVER_BIN).

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createServer as createHttpsServer } from 'node:https';
import { WebSocketServer } from 'ws';
import { buildAuthorizer, authMethods, FailureLimiter } from '../../src/server/auth.mjs';
import { buildBackends } from '../../src/server/backends.mjs';
import { createConnectionFactory } from '../../src/server/connection.mjs';
import { generateSelfSignedCertificate } from '../../src/server/self-signed.mjs';
import { WshClient, generateKeyPair, fingerprint, MSG, TARGETS_FEATURE, open as openMsg, fileOp, listTargets } from '@johnhenry/wsh';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = [];
const procs = [];
const closers = [];

before(() => {
  assert.ok(existsSync(WSH_BIN), `expected the built wsh at ${WSH_BIN}`);
  assert.ok(existsSync(SERVER_BIN), `expected the built wsh-server at ${SERVER_BIN}`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the Rust server's dev certificate is self-signed
});
after(async () => {
  for (const c of closers.splice(0).reverse()) await c().catch(() => {});
  for (const p of procs.splice(0)) p.kill('SIGKILL');
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});

const cleanEnv = (home, extra = {}) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm', ...extra });
const freePort = () => new Promise((resolve) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });

/** A scratch HOME holding a Rust `wsh` identity: its SSH line and fingerprint. */
async function rustIdentity(name) {
  const home = mkdtempSync(path.join(tmpdir(), `wsh-targets-${name}-`));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const ssh = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  const wire = Buffer.from(ssh.split(/\s+/)[1], 'base64');
  const raw = new Uint8Array(wire.subarray(wire.length - 32));
  return { name, home, ssh, fp: await fingerprint(raw) };
}

/** Run `wsh` and collect its result. `extraEnv.SSL_CERT_FILE` makes it trust a self-signed host certificate. */
function wsh(args, home, { timeoutMs = 20_000, env = {} } = {}) {
  return new Promise((resolve) => {
    const proc = spawn(WSH_BIN, args, { env: cleanEnv(home, env), stdio: ['pipe', 'pipe', 'pipe'] });
    const out = []; const err = [];
    proc.stdout.on('data', (d) => out.push(d));
    proc.stderr.on('data', (d) => err.push(d));
    proc.stdin.on('error', () => {});
    proc.stdin.end();
    const timer = setTimeout(() => proc.kill('SIGKILL'), timeoutMs);
    proc.once('close', (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
}

describe('Rust CLI and a JS host with two targets (#121)', () => {
  let alice; let bob; let port; let trust;
  before(async () => {
    [alice, bob] = await Promise.all([rustIdentity('alice'), rustIdentity('bob')]);
    const cert = generateSelfSignedCertificate({ hosts: ['localhost', '127.0.0.1'] });
    const certDir = mkdtempSync(path.join(tmpdir(), 'wsh-targets-cert-'));
    scratch.push(certDir);
    const certFile = path.join(certDir, 'host-cert.pem');
    writeFileSync(certFile, cert.cert);
    trust = { env: { SSL_CERT_FILE: certFile } };
    // `createWshServer().listen()` declares exec sessions `data_mode: "stream"`, which the Rust client's WebSocket transport does
    // not open; a host that carries session data as SessionData (`dataStreams: false`) is driven through the same connection
    // factory `createWshServer` uses, behind a WebSocket listener of our own (as test/rust/fixtures/cli-host.mjs does).
    const authorizedKeys = [alice.ssh, bob.ssh].join('\n');
    const backends = buildBackends({
      targets: {
        web: { description: 'the web container', exec: true },
        db: { description: 'the database VM', exec: true, authorize: (who) => who.fingerprint === bob.fp },
      },
    });
    const attach = createConnectionFactory({
      authorize: await buildAuthorizer({ authorizedKeys }), ...backends, bindTimeoutMs: 3000,
      methods: authMethods({ authorizedKeys }), hostKey: null,
      rateLimit: { limiter: new FailureLimiter({}), key: () => 'test', failureDelayMs: 0 },
    });
    const httpsServer = createHttpsServer({ cert: cert.cert, key: cert.privKey });
    const wss = new WebSocketServer({ server: httpsServer });
    wss.on('connection', (ws) => {
      const conn = attach({ send: (b) => { if (ws.readyState === 1) ws.send(b); }, remote: { address: '127.0.0.1', headers: {} }, dataStreams: false, closeTransport: () => ws.close(1000) });
      ws.on('message', (d) => { const buf = Array.isArray(d) ? Buffer.concat(d) : Buffer.isBuffer(d) ? d : Buffer.from(d); conn.receive(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)); });
      ws.on('close', () => conn.close());
      ws.on('error', () => {});
    });
    await new Promise((resolve) => httpsServer.listen(0, '127.0.0.1', resolve));
    port = httpsServer.address().port;
    closers.push(async () => { wss.close(); httpsServer.close(); });
  });
  const args = (...rest) => ['-t', 'ws', '-p', String(port), ...rest];

  it('wsh targets lists only what the key may use, as a table and as JSON', async () => {
    const a = await wsh(args('targets', 'tester@localhost'), alice.home, trust);
    assert.equal(a.code, 0, a.stderr);
    assert.match(a.stdout, /web\s+exec\s+the web container/);
    assert.doesNotMatch(a.stdout, /db/);
    const b = await wsh(args('targets', '--json', 'tester@localhost'), bob.home, trust);
    assert.equal(b.code, 0, b.stderr);
    assert.deepEqual(JSON.parse(b.stdout).map((t) => t.name), ['web', 'db']);
    assert.deepEqual(JSON.parse(b.stdout)[1], { name: 'db', description: 'the database VM', capabilities: ['exec'] });
  });

  it('wsh --target NAME runs a command on that target; a key refused on a target gets the same answer as for one that does not exist', async () => {
    const ok = await wsh(args('--target', 'web', 'tester@localhost', 'echo', 'on-web'), alice.home, trust);
    assert.equal(ok.code, 0, ok.stderr);
    assert.match(ok.stdout, /on-web/);
    const refused = await wsh(args('--target', 'db', 'tester@localhost', 'echo', 'nope'), alice.home, trust);
    const missing = await wsh(args('--target', 'nowhere', 'tester@localhost', 'echo', 'nope'), alice.home, trust);
    assert.notEqual(refused.code, 0);
    assert.match(refused.stderr, /no such target/);
    assert.doesNotMatch(refused.stdout, /nope/);
    assert.match(missing.stderr, /no such target/);
    const both = await wsh(args('--target', 'db', 'tester@localhost', 'echo', 'on-db'), bob.home, trust);
    assert.equal(both.code, 0, both.stderr);
    assert.match(both.stdout, /on-db/);
  });

  it('without --target the host\'s own default is used, as before (here: no exec of its own)', async () => {
    const r = await wsh(args('tester@localhost', 'echo', 'plain'), alice.home, trust);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /exec is not enabled/);
  });
});

describe('--target is refused where it would not apply, and never ignored', () => {
  let home;
  before(async () => { home = (await rustIdentity('misc')).home; });
  for (const [what, extra] of [
    ['scp', ['scp', 'a', 'b']], ['ls', ['ls', 'tester@127.0.0.1:/']], ['sftp', ['sftp', 'tester@127.0.0.1']],
    ['-L', ['-L', '8080:localhost:80', 'tester@127.0.0.1']], ['-N', ['-N', 'tester@127.0.0.1']], ['reverse-connect', ['reverse-connect', 'abc', 'relay']],
  ]) {
    it(`${what}`, async () => {
      const r = await wsh(['--target', 'web', ...extra], home);
      assert.equal(r.code, 2);
      assert.match(r.stderr, /--target applies to/);
    });
  }
});

describe('the Rust wsh-server has no targets', () => {
  let url; let alice; let certFile;
  before(async () => {
    alice = await rustIdentity('alice');
    const serverHome = mkdtempSync(path.join(tmpdir(), 'wsh-targets-server-'));
    scratch.push(serverHome);
    mkdirSync(path.join(serverHome, '.wsh'));
    writeFileSync(path.join(serverHome, '.wsh', 'authorized_keys'), `${alice.ssh}\n`);
    const p = await freePort();
    const proc = spawn(SERVER_BIN, ['--port', String(p), '--generate-cert', '--config', '/dev/null/none'], { env: cleanEnv(serverHome), stdio: ['ignore', 'pipe', 'pipe'] });
    procs.push(proc);
    let logs = '';
    await new Promise((resolve, reject) => {
      const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
      proc.stdout.on('data', onData); proc.stderr.on('data', onData);
      proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
      setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
    });
    url = `wss://127.0.0.1:${p}`;
    certFile = path.join(serverHome, '.wsh', 'cert.pem');
  });

  it('does not state the feature, and the Rust CLI refuses to send a target to it, saying why', async () => {
    const wsPort = new URL(url).port;
    const base = ['-t', 'ws', '-p', wsPort];
    const env = { SSL_CERT_FILE: certFile };
    const run = (more) => new Promise((resolve) => {
      const proc = spawn(WSH_BIN, [...base, ...more], { env: cleanEnv(alice.home, env), stdio: ['pipe', 'pipe', 'pipe'] });
      const out = []; const err = [];
      proc.stdout.on('data', (d) => out.push(d)); proc.stderr.on('data', (d) => err.push(d));
      proc.stdin.on('error', () => {}); proc.stdin.end();
      const timer = setTimeout(() => proc.kill('SIGKILL'), 20_000);
      proc.once('close', (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
    });
    const t = await run(['targets', 'tester@localhost']);
    assert.notEqual(t.code, 0);
    assert.match(t.stderr, /does not advertise "targets"/);
    const x = await run(['--target', 'web', 'tester@localhost', 'echo', 'hi']);
    assert.notEqual(x.code, 0);
    assert.match(x.stderr, /does not advertise "targets"/);
    assert.doesNotMatch(x.stdout, /hi/);
  });

  it('a client that sends a target anyway is refused: OpenFail, a failed FileResult and an Error, never the server\'s own shell or files', async () => {
    // A client key the server trusts: reuse alice's by connecting the JS client with a key pair registered in authorized_keys.
    const serverHome = mkdtempSync(path.join(tmpdir(), 'wsh-targets-server2-'));
    scratch.push(serverHome);
    mkdirSync(path.join(serverHome, '.wsh'));
    const keyPair = await generateKeyPair(true);
    const { exportPublicKeySSH } = await import('@johnhenry/wsh');
    writeFileSync(path.join(serverHome, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(keyPair.publicKey)} js\n`);
    const p = await freePort();
    const proc = spawn(SERVER_BIN, ['--port', String(p), '--generate-cert', '--config', '/dev/null/none'], { env: cleanEnv(serverHome), stdio: ['ignore', 'pipe', 'pipe'] });
    procs.push(proc);
    let logs = '';
    await new Promise((resolve, reject) => {
      const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
      proc.stdout.on('data', onData); proc.stderr.on('data', onData);
      proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
      setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
    });
    const c = new WshClient();
    closers.push(() => c.disconnect());
    await c.connect(`wss://127.0.0.1:${p}`, { username: 'js', keyPair, transport: 'ws' });
    assert.equal(c.hasFeature(TARGETS_FEATURE), false);
    await assert.rejects(c.openSession({ type: 'exec', command: 'echo x', target: 'web' }), /does not advertise "targets"/);
    const got = [];
    c.addControlListener((m) => got.push(m));
    const until = async (pred) => { for (let i = 0; i < 200; i += 1) { const m = got.find(pred); if (m) return m; await new Promise((r) => setTimeout(r, 25)); } throw new Error('no reply'); };
    await c._transport.sendControl(openMsg({ kind: 'exec', command: 'echo should-not-run', target: 'web' }));
    assert.match((await until((m) => m.type === MSG.OPEN_FAIL)).reason, /no targets/);
    await c._transport.sendControl(fileOp({ channelId: 9, op: 'list', path: '/', target: 'web' }));
    const fr = await until((m) => m.type === MSG.FILE_RESULT && m.channel_id === 9);
    assert.equal(fr.success, false);
    assert.match(fr.error_message, /no targets/);
    await c._transport.sendControl(listTargets());
    assert.match((await until((m) => m.type === MSG.ERROR)).message, /no targets/);
  });
});
