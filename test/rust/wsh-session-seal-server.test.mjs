// test/rust/wsh-session-seal-server.test.mjs -- #155 stage c, PR 2: the Rust `wsh-server` as the RESPONDER of a sealed session
// (`[server] seal_session = "off" | "offer" | "require"`), driven by the JS client (`sealSession`) and the Rust CLI (`--sealed`).
//
//   off     nothing changes for any client (the default; the feature strings are not advertised)
//   offer   a client that asks gets a sealed session; every other client is served as before
//   require nothing is served on a session that is not sealed: no password login, no WebTransport, no plain messages
//
// A relay that records and tampers (test/helpers/hostile-relay.mjs) sits in front of the server: sealed, it finds no plaintext marker
// (control run: it does), a flipped bit or a replayed frame closes the session, a plain message it injects is not heard.
// Every process runs with HOME in a scratch directory. Prerequisite: cargo build --release -p wsh-server -p wsh-cli (or
// WSH_SERVER_BIN / WSH_BIN).

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { WshClient, generateKeyPair, exportPublicKeySSH, MSG, cborEncode } from '../../src/index.mjs';
import { hostileRelay } from '../helpers/hostile-relay.mjs';
import { WebTransport as RealWebTransport, quicheLoaded } from '@fails-components/webtransport';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const MARKER = 'SECRET-MARKER-ZEBRA-7731';

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = [];
const procs = [];
const closers = [];
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
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, what, ms = 8000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
};
const cleanEnv = (home, extra = {}) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm', ...extra });
const freePort = () => new Promise((resolve) => {
  const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});

/** A TCP echo server (the gateway's destination); `seen()` is how many connections it took. */
async function echoServer() {
  let count = 0;
  const sockets = new Set();
  const server = net.createServer((s) => { count += 1; sockets.add(s); s.on('close', () => sockets.delete(s)); s.on('error', () => {}); s.pipe(s); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  closers.push(() => new Promise((r) => { server.close(() => r()); for (const s of sockets) s.destroy(); }));
  return { port: server.address().port, seen: () => count };
}

/** A wsh-server whose HOME holds an authorized key and `[server] seal_session = <seal>` (and a host key, and the gateway). */
async function startServer({ seal, sealTimeoutSecs, authorizedKey, extraToml = '' } = {}) {
  const kp = await generateKeyPair(true);
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-seal-srv-'));
  scratch.push(home);
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${authorizedKey ?? await exportPublicKeySSH(kp.publicKey)}\n`);
  const hostKeyPath = path.join(home, '.wsh', 'host_key');
  const configPath = path.join(home, '.wsh', 'config.toml');
  writeFileSync(configPath, `[server]\nhost_key = ${JSON.stringify(hostKeyPath)}\n${seal ? `seal_session = "${seal}"\n` : ''}${sealTimeoutSecs === undefined ? '' : `seal_timeout_secs = ${sealTimeoutSecs}\n`}\n[gateway]\nenabled = true\nallowed_destinations = ["127.0.0.1"]\n${extraToml}`);
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', configPath], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(Object.assign(new Error(`wsh-server exited (${c}): ${logs}`), { logs })));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  return { url: `wss://127.0.0.1:${port}`, port, kp, home, certFile: path.join(home, '.wsh', 'cert.pem'), logs: () => logs };
}

async function viaRelay(server, hooks = {}) {
  const relay = await hostileRelay(server.url, hooks);
  closers.push(() => relay.close());
  return relay;
}

async function login(server, url, opts = {}) {
  const client = new WshClient();
  closers.push(() => client.disconnect());
  await client.connect(url ?? server.url, { username: 'tester', keyPair: server.kp, transport: 'ws', timeout: 8000, ...opts });
  return client;
}

async function roundTrip(client, port, text) {
  const d = await client.openTcp('127.0.0.1', port);
  const reader = d.readable.getReader(); const writer = d.writable.getWriter();
  await writer.write(new TextEncoder().encode(text));
  const chunks = []; let got = 0;
  while (got < text.length) { const { value, done } = await reader.read(); if (done) break; chunks.push(value); got += value.length; }
  d.destroy();
  return Buffer.concat(chunks).toString();
}
const execEcho = (client, text) => client.openSession({ type: 'exec', command: `echo ${text}` }).then((s) => new Promise((resolve) => { const ch = []; s.onData = (d) => ch.push(d); s.onClose = () => resolve(Buffer.concat(ch).toString()); }));

const wire = (relay) => relay.seen.map((e) => ({ dir: e.dir, type: e.msg.type, bytes: Buffer.from(cborEncode(e.msg)) }));
const hasText = (relay, text) => wire(relay).some((w) => w.bytes.includes(Buffer.from(text)));

describe('seal_session = "off" (the default): nothing changes', () => {
  it('advertises no e2e-session feature, serves a plain client, and a client that insists on sealing is refused before any credential', async () => {
    for (const seal of [undefined, 'off']) {
      const s = await startServer({ seal });
      const echo = await echoServer();
      const relay = await viaRelay(s);
      const c = await login(s, relay.url);
      assert.equal(c.hasFeature('e2e-session'), false);
      assert.equal(c.hasFeature('e2e-session-required'), false);
      assert.equal(await roundTrip(c, echo.port, MARKER), MARKER);
      assert.ok(hasText(relay, MARKER), 'plain, as before');
      await c.disconnect();
      await assert.rejects(login(s, relay.url, { sealSession: true }), /does not offer "e2e-session"/);
    }
  });
});

describe('seal_session = "offer"', () => {
  it('JS client with sealSession: true: sealed; TCP gateway data and an exec session cross a recording relay with no plaintext marker', async () => {
    const s = await startServer({ seal: 'offer' });
    const echo = await echoServer();
    const relay = await viaRelay(s);
    const c = await login(s, relay.url, { sealSession: true });
    assert.equal(c.hasFeature('e2e-session'), true);
    assert.equal(c.hasFeature('e2e-session-required'), false);
    assert.equal(c.sessionSealed, true);
    assert.equal(await roundTrip(c, echo.port, MARKER), MARKER);
    assert.equal((await execEcho(c, MARKER)).trim(), MARKER);
    assert.ok(!hasText(relay, MARKER), 'the data crossed the relay in the clear');
    assert.ok(!hasText(relay, '127.0.0.1'), 'the destination crossed the relay in the clear');
    const authOk = relay.seen.findIndex((e) => e.dir === 'to-client' && e.msg.type === MSG.AUTH_OK);
    const after = relay.seen.slice(authOk + 1).map((e) => e.msg.type);
    assert.ok(after.length > 4);
    for (const t of after) assert.ok([MSG.KEY_EXCHANGE, MSG.ENCRYPTED_FRAME, MSG.PING, MSG.PONG].includes(t), `a plain message of type ${t} crossed after the login`);
    assert.match(s.logs(), /session sealed/);
  });

  it('an old client (no sealSession; or one that opts out) is served as before: it sees the offer and the data is readable', async () => {
    const s = await startServer({ seal: 'offer' });
    const echo = await echoServer();
    const relay = await viaRelay(s);
    for (const opts of [{ sealSession: false }, {}]) {
      const c = await login(s, relay.url, opts);
      assert.equal(c.sessionSealed, false);
      assert.equal(await roundTrip(c, echo.port, MARKER), MARKER);
      assert.equal((await execEcho(c, 'old')).trim(), 'old');
      await c.disconnect();
    }
    assert.ok(hasText(relay, MARKER));
  });

  it('a 3 MiB transfer both ways stays intact on a sealed session (gateway credit works through the frames)', async () => {
    const s = await startServer({ seal: 'offer' });
    const echo = await echoServer();
    const c = await login(s, undefined, { sealSession: true });
    const payload = Buffer.alloc(3 * 1024 * 1024);
    for (let i = 0; i < payload.length; i += 1) payload[i] = (i * 31) & 0xff;
    const d = await c.openTcp('127.0.0.1', echo.port);
    const reader = d.readable.getReader(); const writer = d.writable.getWriter();
    const got = []; let total = 0;
    const reading = (async () => { while (total < payload.length) { const { value, done } = await reader.read(); if (done) break; got.push(value); total += value.length; } })();
    for (let i = 0; i < payload.length; i += 16384) await writer.write(payload.subarray(i, i + 16384));
    await reading;
    d.destroy();
    assert.ok(Buffer.concat(got).equals(payload));
  });

  it('typed rpc channels are offered in virtual data mode while sealing is (#191): `rpc-virtual`, never `rpc` (test/rust/wsh-rpc-virtual.test.mjs drives them)', async () => {
    const s = await startServer({ seal: 'offer' });
    const c = await login(s, undefined, { sealSession: false });
    assert.ok(c.serverFeatures.includes('rpc-virtual'), c.serverFeatures.join(','));
    assert.ok(!c.serverFeatures.includes('rpc'), 'a client that only knows stream-mode rpc is never offered one it cannot carry');
    assert.doesNotMatch(s.logs(), /typed rpc channels .* are not offered/);
  });

  it('a flipped bit in a frame toward the server closes the session; nothing is delivered', async () => {
    let armed = false;
    const s = await startServer({ seal: 'offer' });
    const echo = await echoServer();
    const relay = await viaRelay(s, { toRelay: (m) => { if (armed && m.type === MSG.ENCRYPTED_FRAME) { armed = false; const ct = new Uint8Array(m.ciphertext); ct[ct.length - 1] ^= 1; return { ...m, ciphertext: ct }; } return m; } });
    const c = await login(s, relay.url, { sealSession: true });
    let closed = false; c.onClose = () => { closed = true; };
    assert.equal(await roundTrip(c, echo.port, 'warm'), 'warm');
    const before = echo.seen();
    armed = true;
    await c.openTcp('127.0.0.1', echo.port, { timeoutMs: 3000 }).catch(() => {});
    await until(() => /did not open/.test(s.logs()), `the server to refuse the frame: ${s.logs()}`);
    await until(() => closed, 'the client to learn the session is over');
    assert.equal(echo.seen(), before, 'the tampered request opened nothing');
  });

  it('a flipped bit in a frame toward the client closes the client', async () => {
    let armed = false;
    const s = await startServer({ seal: 'offer' });
    const echo = await echoServer();
    const relay = await viaRelay(s, { toClient: (m) => { if (armed && m.type === MSG.ENCRYPTED_FRAME) { armed = false; const ct = new Uint8Array(m.ciphertext); ct[0] ^= 1; return { ...m, ciphertext: ct }; } return m; } });
    const c = await login(s, relay.url, { sealSession: true });
    let closed = false; c.onClose = () => { closed = true; };
    assert.equal(await roundTrip(c, echo.port, 'warm'), 'warm');
    armed = true;
    await roundTrip(c, echo.port, MARKER).catch(() => null);
    await until(() => closed, 'the client to close after a frame that does not open');
  });

  it('a replayed frame closes the session', async () => {
    let last = null; let replay = false;
    const s = await startServer({ seal: 'offer' });
    const echo = await echoServer();
    const relay = await viaRelay(s, { toRelay: (m) => { if (m.type === MSG.ENCRYPTED_FRAME) { if (replay) { replay = false; return [m, last]; } last = m; } return m; } });
    const c = await login(s, relay.url, { sealSession: true });
    assert.equal(await roundTrip(c, echo.port, 'warm'), 'warm');
    replay = true;
    await c.openTcp('127.0.0.1', echo.port, { timeoutMs: 3000 }).catch(() => {});
    await until(() => /did not open/.test(s.logs()), `the server to refuse the replay: ${s.logs()}`);
  });

  it('a plain message injected toward the server after the key exchange is not heard (nothing is opened), and the session carries on', async () => {
    const s = await startServer({ seal: 'offer' });
    const echo = await echoServer();
    const relay = await viaRelay(s);
    const c = await login(s, relay.url, { sealSession: true });
    assert.equal(await roundTrip(c, echo.port, 'hi'), 'hi');
    const before = echo.seen();
    await relay.context().injectToRelay({ type: MSG.OPEN_TCP, gateway_id: 99, host: '127.0.0.1', port: echo.port });
    await sleep(400);
    assert.equal(echo.seen(), before, 'the plain OpenTcp was not heard');
    assert.match(s.logs(), /plaintext message/);
    assert.equal(await roundTrip(c, echo.port, 'still up'), 'still up');
  });

  it('a plain message injected toward the client is not heard either', async () => {
    const s = await startServer({ seal: 'offer' });
    const echo = await echoServer();
    const relay = await viaRelay(s);
    const c = await login(s, relay.url, { sealSession: true });
    let closed = false; c.onClose = () => { closed = true; };
    assert.equal(await roundTrip(c, echo.port, 'hi'), 'hi');
    relay.context().injectToClient({ type: MSG.SHUTDOWN, reason: 'injected by the relay' });
    await sleep(300);
    assert.equal(closed, false);
    assert.equal(await roundTrip(c, echo.port, 'still up'), 'still up');
  });

  it('a relay that strips the e2e-session feature cannot make sealSession: true talk in the clear: refused before a credential is sent', async () => {
    const s = await startServer({ seal: 'offer' });
    const relay = await viaRelay(s, { toClient: (m) => (m.type === MSG.SERVER_HELLO ? { ...m, features: m.features.filter((f) => !f.startsWith('e2e-session')) } : m) });
    await assert.rejects(login(s, relay.url, { sealSession: true }), /does not offer "e2e-session"/);
    assert.ok(!relay.seen.some((e) => e.dir === 'to-relay' && e.msg.type === MSG.AUTH));
  });

  it('a relay that answers the key exchange with a key of its own is refused (the host key signs the reply)', async () => {
    const s = await startServer({ seal: 'offer' });
    const relay = await viaRelay(s, { toClient: (m) => (m.type === MSG.KEY_EXCHANGE ? { ...m, signature: new Uint8Array(64) } : m) });
    await assert.rejects(login(s, relay.url, { sealSession: true, timeout: 4000 }), /does not verify|did not sign|E2E_PEER/);
  });

  it('a key exchange the login key did not sign is refused by the server (a relay cannot seal a session for the operator)', async () => {
    const s = await startServer({ seal: 'offer' });
    const echo = await echoServer();
    const relay = await viaRelay(s, { toRelay: (m) => (m.type === MSG.KEY_EXCHANGE && m.signature ? { ...m, signature: new Uint8Array(64) } : m) });
    await assert.rejects(login(s, relay.url, { sealSession: true, timeout: 4000 }));
    await until(() => /key exchange was refused|did not verify|does not verify/.test(s.logs()), `the server to refuse it: ${s.logs()}`);
    assert.equal(echo.seen(), 0);
  });

  it('a key exchange with the initiator signature stripped is refused too (a relay cannot seal a session without the operator)', async () => {
    const s = await startServer({ seal: 'offer' });
    const echo = await echoServer();
    const relay = await viaRelay(s, { toRelay: (m) => { if (m.type === MSG.KEY_EXCHANGE && m.signature) { const { signature, ...rest } = m; return rest; } return m; } });
    await assert.rejects(login(s, relay.url, { sealSession: true, timeout: 4000 }));
    await until(() => /key exchange was refused|did not verify|does not verify|without the initiator signature/.test(s.logs()), `the server to refuse it: ${s.logs()}`);
    assert.equal(echo.seen(), 0);
  });

  it('sealSession: true over WebTransport is refused before a credential (the feature is advertised on WebSocket only)', async () => {
    const s = await startServer({ seal: 'offer' });
    const restore = await pinWebTransport(s);
    try {
      const c = new WshClient();
      closers.push(() => c.disconnect());
      await assert.rejects(c.connect(`https://127.0.0.1:${s.port}`, { username: 'tester', keyPair: s.kp, transport: 'wt', sealSession: true, timeout: 6000 }), /does not offer "e2e-session"/);
      // and a plain client still gets WebTransport as before
      const plain = new WshClient();
      closers.push(() => plain.disconnect());
      await plain.connect(`https://127.0.0.1:${s.port}`, { username: 'tester', keyPair: s.kp, transport: 'wt', sealSession: false, timeout: 6000 });
    } finally { restore(); }
  });
});

describe('seal_session = "require"', () => {
  it('advertises e2e-session-required; a JS client seals on its own (auto) and is served', async () => {
    const s = await startServer({ seal: 'require' });
    const echo = await echoServer();
    const relay = await viaRelay(s);
    const c = await login(s, relay.url);
    assert.equal(c.hasFeature('e2e-session-required'), true);
    assert.equal(c.sessionSealed, true);
    assert.equal(await roundTrip(c, echo.port, MARKER), MARKER);
    assert.ok(!hasText(relay, MARKER));
  });

  it('an old client that does not seal is refused: the server says why, closes, and serves nothing', async () => {
    const s = await startServer({ seal: 'require' });
    const echo = await echoServer();
    const c = await login(s, undefined, { sealSession: false });
    let closed = false; c.onClose = () => { closed = true; };
    await assert.rejects(c.openTcp('127.0.0.1', echo.port, { timeoutMs: 2000 }));
    await until(() => closed, 'the server to close the connection');
    assert.equal(echo.seen(), 0, 'nothing was served');
    assert.match(s.logs(), /requires a sealed session/);
  });

  it('#244: a client that logs in and never seals is closed at seal_timeout_secs, the server says why; a client that sealed, and a server that only offers, are not touched', async () => {
    // 1 s, the smallest the key takes: every wait below is for an event (the close), never for a count of milliseconds.
    const req = await startServer({ seal: 'require', sealTimeoutSecs: 1 });
    const offer = await startServer({ seal: 'offer', sealTimeoutSecs: 1 });
    const echo = await echoServer();
    const offered = await login(offer, undefined, { sealSession: false });
    const sealed = await login(req);
    assert.equal(sealed.sessionSealed, true);
    const silent = await login(req, undefined, { sealSession: false });
    let closed = false; silent.onClose = () => { closed = true; };
    await until(() => closed, 'the server to close the silent connection', 6000);
    assert.match(req.logs(), /not sealed in time/);
    // The other two outlived the deadline (they were connected before the silent one, so it has passed for them too).
    assert.equal(await roundTrip(sealed, echo.port, MARKER), MARKER);
    assert.equal((await execEcho(offered, 'still-here')).trim(), 'still-here');
    assert.doesNotMatch(offer.logs(), /not sealed in time/);
  });

  it('#244: seal_timeout_secs = 0 turns the deadline off; a value that is not a whole number of seconds is refused at start', async () => {
    const off = await startServer({ seal: 'require', sealTimeoutSecs: 0 });
    const c = await login(off, undefined, { sealSession: false });
    let closed = false; c.onClose = () => { closed = true; };
    await sleep(1500); // one real wait, to show the key is not enforced: 0 must not mean "at once" either
    assert.equal(closed, false);
    assert.doesNotMatch(off.logs(), /not sealed in time/);
    await assert.rejects(startServer({ seal: 'require', sealTimeoutSecs: -1 }), /seal_timeout_secs|invalid|exited/i);
  });

  it('a password login is refused (it has no key to authenticate the exchange with)', async () => {
    const scratchHome = mkdtempSync(path.join(tmpdir(), 'wsh-seal-hash-'));
    scratch.push(scratchHome);
    const hash = execFileSync(SERVER_BIN, ['--hash-password'], { input: 'pw', encoding: 'utf8', env: cleanEnv(scratchHome) }).trim();
    const s = await startServer({ seal: 'require', extraToml: `\n[auth]\nallow_password = true\n[auth.password_hashes]\ntester = '${hash}'\n` });
    const c = new WshClient();
    closers.push(() => c.disconnect());
    await assert.rejects(c.connect(s.url, { username: 'tester', password: 'pw', transport: 'ws', sealSession: false, timeout: 5000 }), /requires a sealed session, which needs a key login/);
    // and a client that insists on sealing says so itself, before sending the password
    const d = new WshClient();
    closers.push(() => d.disconnect());
    await assert.rejects(d.connect(s.url, { username: 'tester', password: 'pw', transport: 'ws', sealSession: true, timeout: 5000 }), /key login/);
  });

  it('WebTransport is refused (it cannot be sealed), not served in the clear', async () => {
    const s = await startServer({ seal: 'require' });
    const restore = await pinWebTransport(s);
    try {
      const c = new WshClient();
      closers.push(() => c.disconnect());
      await assert.rejects(c.connect(`https://127.0.0.1:${s.port}`, { username: 'tester', keyPair: s.kp, transport: 'wt', sealSession: false, timeout: 4000 }));
      await until(() => /refused a WebTransport connection/.test(s.logs()), `the server to say so: ${s.logs()}`);
    } finally { restore(); }
  });

  it('a plain message injected before the key exists is answered with the refusal, not served', async () => {
    const s = await startServer({ seal: 'require' });
    const echo = await echoServer();
    const relay = await viaRelay(s);
    const c = await login(s, relay.url, { sealSession: true });
    assert.equal(await roundTrip(c, echo.port, 'hi'), 'hi');
    const before = echo.seen();
    await relay.context().injectToRelay({ type: MSG.OPEN_TCP, gateway_id: 77, host: '127.0.0.1', port: echo.port });
    await sleep(400);
    assert.equal(echo.seen(), before);
  });
});

describe('Rust CLI against wsh-server', { skip: !existsSync(WSH_BIN) && `no wsh at ${WSH_BIN}` }, () => {
  function makeHome() {
    const home = mkdtempSync(path.join(tmpdir(), 'wsh-seal-cli-'));
    scratch.push(home);
    execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
    return { home, pub: readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim() };
  }
  function wsh(args, h, server) {
    return new Promise((resolve) => {
      const proc = spawn(WSH_BIN, ['-t', 'ws', '-p', String(server.port), '--accept-new-host-key', ...args], { env: cleanEnv(h.home, { SSL_CERT_FILE: server.certFile }), stdio: ['pipe', 'pipe', 'pipe'] });
      const out = []; const err = [];
      proc.stdout.on('data', (d) => out.push(d)); proc.stderr.on('data', (d) => err.push(d));
      proc.stdin.on('error', () => {}); proc.stdin.end();
      const timer = setTimeout(() => proc.kill('SIGKILL'), 20_000);
      proc.once('close', (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
    });
  }

  it('wsh --sealed seals against an offering server (Rust on both ends); a plain wsh is served as before', async () => {
    const h = makeHome();
    const s = await startServer({ seal: 'offer', authorizedKey: h.pub });
    const sealed = await wsh(['--sealed', 'localhost', 'echo', 'hi'], h, s);
    assert.equal(sealed.code, 0, sealed.stderr);
    assert.equal(sealed.stdout, 'hi\n');
    assert.match(s.logs(), /session sealed/);
    const plain = await wsh(['localhost', 'echo', 'again'], h, s);
    assert.equal(plain.code, 0, plain.stderr);
    assert.equal(plain.stdout, 'again\n');
  });

  it('wsh seals on its own against a server that requires it, and --sealed against a server that does not offer it fails with a sentence', async () => {
    const h = makeHome();
    const req = await startServer({ seal: 'require', authorizedKey: h.pub });
    const auto = await wsh(['localhost', 'echo', 'auto'], h, req);
    assert.equal(auto.code, 0, auto.stderr);
    assert.equal(auto.stdout, 'auto\n');
    assert.match(req.logs(), /session sealed/);

    const off = await startServer({ authorizedKey: h.pub });
    const refused = await wsh(['--sealed', 'localhost', 'echo', 'x'], h, off);
    assert.notEqual(refused.code, 0);
    assert.match(refused.stderr, /does not offer "e2e-session"/);
  });
});

/** A WebTransport global that pins the server's self-signed dev certificate (the client calls the constructor with no options). */
async function pinWebTransport(server) {
  await quicheLoaded;
  const fp = execFileSync('openssl', ['x509', '-in', server.certFile, '-noout', '-fingerprint', '-sha256']).toString().split('=')[1].trim();
  const bytes = Uint8Array.from(fp.split(':').map((h) => parseInt(h, 16)));
  const original = globalThis.WebTransport;
  globalThis.WebTransport = class extends RealWebTransport {
    constructor(url) { super(url, { serverCertificateHashes: [{ algorithm: 'sha-256', value: bytes }] }); }
  };
  return () => { if (original === undefined) delete globalThis.WebTransport; else globalThis.WebTransport = original; };
}
