// test/rust/wsh-cli-identity.test.mjs -- the built Rust `wsh` and host identity (#145, parts of #59, #117, #119):
//   step 1: the host-key PROOF (the client sends `host-key-nonce:`, the host answers `host-key:` / `host-key-sig:`),
//           first use that is explicit, a changed key always refused, known_hosts written only after the proof;
//   step 2: channel binding (the login signature bound to the host key that proved itself).
//
// Hosts are the real JS ones: a Node host (`createWshServer().accept(ws)`) and a page-shaped host
// (`createMemoryHost().accept(ws)`), both dialling a real `createPipeRelay` as `host`, so the CLI goes `--via`; and a
// byte-level intermediary (`intermediary()`) that sits on a direct `ws://` URL to play the impostor, the replayer and the
// stripper. Prerequisite: `cargo build --release -p wsh-cli` (or WSH_BIN). Every `wsh` runs with HOME in a scratch dir.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocket as WsClient, WebSocketServer } from 'ws';

import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { createWshServer } from '@johnhenry/wsh/server';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { QMuxConnection } from '../../src/qmux-connection.mjs';
import { FrameDecoder, frameEncode } from '../../src/cbor.mjs';
import { MSG } from '../../src/messages.gen.mjs';
import { WebSocketTransport } from '../../src/transport-ws.mjs';
import { HOST_KEY_PREFIX, HOST_KEY_SIG_PREFIX, hostKeyProofMessage, findClientNonce, toHex } from '../../src/host-key.mjs';
import { loadHostKey } from '../../src/server/host-key.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');

const scratch = [];
const closers = [];

before(() => {
  assert.ok(existsSync(WSH_BIN), `expected the built wsh binary at ${WSH_BIN} (cargo build --release -p wsh-cli, or set WSH_BIN)`);
});
after(async () => {
  for (const close of closers.splice(0)) await close().catch(() => {});
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
});

const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm' });

function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-cli-identity-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const pub = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  const khPath = path.join(home, '.wsh', 'known_hosts');
  return {
    home, pub,
    knownHosts: () => { try { return readFileSync(khPath, 'utf8'); } catch { return ''; } },
    seedKnownHosts: (text) => { mkdirSync(path.dirname(khPath), { recursive: true }); writeFileSync(khPath, text); },
  };
}

/** stdin is a pipe (never a terminal), so a first use must be allowed by a flag. */
function wsh(args, { home, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve) => {
    const proc = spawn(WSH_BIN, args, { env: cleanEnv(home), stdio: ['pipe', 'pipe', 'pipe'] });
    const out = []; const err = [];
    proc.stdout.on('data', (d) => out.push(d));
    proc.stderr.on('data', (d) => err.push(d));
    proc.stdin.on('error', () => {});
    proc.stdin.end();
    const timer = setTimeout(() => proc.kill('SIGKILL'), timeoutMs);
    proc.once('close', (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
}

async function startRelay() {
  const relay = createPipeRelay({ rendezvousTimeoutMs: 15_000 });
  const { port } = await relay.listen();
  closers.push(() => relay.close());
  return { relay, url: `ws://127.0.0.1:${port}`, port };
}

async function dialHost(relayUrl, id, serve) {
  const ws = new WsClient(pipeUrl(relayUrl, id, 'host'));
  ws.on('error', () => {});
  closers.push(async () => ws.terminate());
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  await serve(ws);
  return ws;
}

const makeExec = (ran) => async (command, io) => {
  ran.push(command);
  const [word, ...rest] = command.trim().split(/\s+/);
  if (word === 'echo') { await io.write(`${rest.join(' ')}\n`); return 0; }
  await io.write(`unknown: ${command}\n`);
  return 127;
};

function nodeHost(h, { ran = [], ...opts } = {}) {
  const server = createWshServer({ auth: { authorizedKeys: h.pub }, exec: makeExec(ran), ...opts });
  closers.push(() => server.close());
  return { ran, serve: (ws) => server.accept(ws, { dataStreams: false }), server };
}
function pageHost(h, { ran = [], ...opts } = {}) {
  const host = createMemoryHost({ auth: { authorizedKeys: h.pub }, exec: makeExec(ran), dataStreams: false, ...opts });
  closers.push(() => host.close());
  return { ran, serve: (ws) => host.accept(ws), host };
}

/** Serve `host` behind a fresh pipe relay; returns the `--via` URL. */
async function viaRelay(host) {
  const relay = await startRelay();
  const id = newRendezvousId();
  await dialHost(relay.url, id, host.serve);
  return pipeUrl(relay.url, id);
}

/** A fingerprint the way the host advertises it. */
const fingerprintOf = (host) => host.server.hostKey().fingerprint;

/**
 * A byte-level intermediary on a plain `ws://` port: a wsh "server" to the client, a client to the real host, forwarding
 * every control message and tampering with ServerHello as told:
 *   swapKey -- present its OWN host key with a valid proof for this connection (an impostor);
 *   bare    -- keep `host_fingerprint` but drop `host-key` / `host-key-sig` (a fingerprint someone copied);
 *   replay  -- present the ServerHello (key, proof, session id) recorded from an earlier connection;
 *   strip   -- remove the host's `channel-binding*` offers.
 */
async function intermediary(upstream, { swapKey = false, bare = false, replay = null, strip = false } = {}) {
  const own = swapKey ? await loadHostKey(true) : null;
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  const port = await new Promise((resolve) => wss.once('listening', () => resolve(wss.address().port)));
  const recorded = [];
  wss.on('connection', (ws) => {
    const qmux = new QMuxConnection({ isClient: false, send: (b) => { if (ws.readyState === 1) ws.send(b); } });
    const decoder = new FrameDecoder();
    let control = null; let username = ''; let nonce = null;
    const back = new WebSocketTransport({ WebSocket: WsClient });
    const ready = back.connect(upstream);
    back.onControl = async (m) => {
      let out = m;
      if (m.type === MSG.SERVER_HELLO) {
        recorded.push(m);
        let features = (m.features ?? []).filter((f) => !(strip && f.startsWith('channel-binding')));
        if (own) {
          features = features.filter((f) => !f.startsWith(HOST_KEY_PREFIX) && !f.startsWith(HOST_KEY_SIG_PREFIX));
          const sig = await own.sign(hostKeyProofMessage({ sessionId: m.session_id, clientNonce: nonce, username }));
          features.push(HOST_KEY_PREFIX + toHex(own.publicKey), HOST_KEY_SIG_PREFIX + toHex(sig));
          out = { ...m, features, host_fingerprint: own.fingerprint };
        } else if (bare) {
          out = { ...m, features: features.filter((f) => !f.startsWith(HOST_KEY_PREFIX) && !f.startsWith(HOST_KEY_SIG_PREFIX)) };
        } else if (replay) {
          out = replay();
        } else out = { ...m, features };
      }
      await control?.write(frameEncode(out));
    };
    qmux.onStreamOpen = (s) => {
      if (s.id !== 0) return;
      control = s;
      s.onData = (d) => {
        for (const m of decoder.feed(d)) {
          if (m.type === MSG.HELLO) { username = m.username; nonce = findClientNonce(m.features); }
          ready.then(() => back.sendControl(m));
        }
      };
    };
    qmux.sendHandshake();
    ws.on('message', (d) => qmux.receiveBytes(new Uint8Array(d)));
    ws.on('close', () => back.close().catch(() => {}));
  });
  const handle = { url: `ws://127.0.0.1:${port}/`, label: `127.0.0.1:${port}`, recorded, close: async () => { for (const c of wss.clients) c.terminate(); await new Promise((r) => wss.close(r)); } };
  closers.push(handle.close);
  return handle;
}

/** A Node host reachable on a real `ws://` port (control-only is enough: these tests stop at the handshake or run `echo`). */
async function directHost(h, opts = {}) {
  const ran = [];
  const server = createWshServer({ auth: { authorizedKeys: h.pub }, exec: makeExec(ran), ...opts });
  const { port } = await server.listen();
  closers.push(() => server.close());
  return { ran, server, url: `ws://127.0.0.1:${port}/` };
}

const ACCEPT = '--accept-new-host-key';

describe('step 1: the host-key proof, through a pipe relay', () => {
  it('a first use is refused without --accept-new-host-key: nothing is sent, nothing recorded, the fingerprint is shown', async () => {
    const h = makeHome();
    const host = nodeHost(h, { hostKey: true });
    const url = await viaRelay(host);
    const r = await wsh(['--via', url, 'alice@build.example.com', 'echo', 'hi'], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /authenticity of host 'build\.example\.com:4422' cannot be established/);
    assert.ok(r.stderr.includes(fingerprintOf(host)), r.stderr);
    assert.match(r.stderr, /--accept-new-host-key/);
    assert.deepEqual(host.ran, []);
    assert.equal(h.knownHosts(), '', 'no known_hosts entry for a key nobody accepted');
  });

  it('--accept-new-host-key records the PROVEN key under user@host:port, and the next run needs no flag', async () => {
    const h = makeHome();
    const host = nodeHost(h, { hostKey: true });
    const url = await viaRelay(host);
    const first = await wsh([ACCEPT, '--via', url, 'alice@build.example.com', 'echo', 'one'], { home: h.home });
    assert.equal(first.code, 0, first.stderr);
    assert.equal(first.stdout, 'one\n');
    assert.match(first.stderr, /Permanently added 'build\.example\.com:4422'/);
    assert.equal(h.knownHosts().trim(), `build.example.com:4422 ${fingerprintOf(host)}`);

    const second = await wsh(['--via', await viaRelay(host), 'alice@build.example.com', 'echo', 'two'], { home: h.home });
    assert.equal(second.code, 0, second.stderr);
    assert.equal(second.stdout, 'two\n');
    assert.doesNotMatch(second.stderr, /Permanently added/);
  });

  it('a CHANGED key is refused even with --accept-new-host-key, and the recorded key is untouched', async () => {
    const h = makeHome();
    const a = nodeHost(h, { hostKey: true });
    assert.equal((await wsh([ACCEPT, '--via', await viaRelay(a), 'alice@build.example.com', 'echo', '1'], { home: h.home })).code, 0);
    const recorded = h.knownHosts();
    const impostor = nodeHost(h, { hostKey: true });
    const r = await wsh([ACCEPT, '--via', await viaRelay(impostor), 'alice@build.example.com', 'echo', '2'], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /HOST KEY CHANGED/);
    assert.deepEqual(impostor.ran, []);
    assert.equal(h.knownHosts(), recorded);
  });

  it('a page-shaped host (createMemoryHost) with a host key proves it too', async () => {
    const h = makeHome();
    const host = pageHost(h, { hostKey: true });
    const r = await wsh([ACCEPT, '--via', await viaRelay(host), 'alice@page.example.com', 'echo', 'from the page'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, 'from the page\n');
    assert.match(h.knownHosts(), /^page\.example\.com:4422 [0-9a-f]{64}$/m);
  });

  it('a host with no host key still works (released peers), records nothing, and --require-host-key refuses it before logging in', async () => {
    const h = makeHome();
    const host = nodeHost(h);
    const ok = await wsh(['--via', await viaRelay(host), 'alice@nokey.example.com', 'echo', 'plain'], { home: h.home });
    assert.equal(ok.code, 0, ok.stderr);
    assert.equal(ok.stdout, 'plain\n');
    assert.equal(h.knownHosts(), '');
    // stderr is a pipe here: the unverified-host note is for terminals only

    const strict = nodeHost(h);
    const r = await wsh(['--require-host-key', '--via', await viaRelay(strict), 'alice@nokey.example.com', 'echo', 'x'], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /HOST KEY REQUIRED/);
    assert.deepEqual(strict.ran, []);
  });

  it('--require-host-key accepts a host that proves its key', async () => {
    const h = makeHome();
    const host = nodeHost(h, { hostKey: true });
    const r = await wsh([ACCEPT, '--require-host-key', '--via', await viaRelay(host), 'alice@k.example.com', 'echo', 'ok'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
  });
});

describe('step 1: impostors on a direct ws:// connection', () => {
  it('an impostor with its own key (and a valid proof for this connection) is a CHANGED key for a known host', async () => {
    const h = makeHome();
    const real = await directHost(h, { hostKey: true });
    const imp = await intermediary(real.url, { swapKey: true });
    // The host was pinned (under the impostor's address) as the real key first:
    const realFp = real.server.hostKey().fingerprint;
    h.seedKnownHosts(`${imp.label} ${realFp}\n`);
    const r = await wsh([ACCEPT, `alice@${imp.url}`, 'echo', 'x'], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /HOST KEY CHANGED/);
    assert.deepEqual(real.ran, []);
    assert.equal(h.knownHosts().trim(), `${imp.label} ${realFp}`);
  });

  it('a bare host_fingerprint with no proof is "no host key": refused by --require-host-key, and as a downgrade for a pinned host', async () => {
    const h = makeHome();
    const real = await directHost(h, { hostKey: true });
    const copied = await intermediary(real.url, { bare: true });
    const strict = await wsh(['--require-host-key', `alice@${copied.url}`, 'echo', 'x'], { home: h.home });
    assert.notEqual(strict.code, 0);
    assert.match(strict.stderr, /HOST KEY REQUIRED/);

    h.seedKnownHosts(`${copied.label} ${real.server.hostKey().fingerprint}\n`);
    const down = await wsh([ACCEPT, `alice@${copied.url}`, 'echo', 'x'], { home: h.home });
    assert.notEqual(down.code, 0);
    assert.match(down.stderr, /HOST KEY MISSING/);
    assert.deepEqual(real.ran, []);
  });

  it('a ServerHello replayed from another session is refused before any credential is sent', async () => {
    const h = makeHome();
    const real = await directHost(h, { hostKey: true });
    let first = null;
    const proxy = await intermediary(real.url, { replay: () => first });
    // Connection 1 (genuine, passes through) so the proxy has recorded a genuine ServerHello ...
    const spy = await intermediary(real.url);
    await wsh([ACCEPT, '--require-host-key', `alice@${spy.url}`, 'echo', 'warm'], { home: h.home, timeoutMs: 3000 });
    assert.ok(spy.recorded.length >= 1);
    first = spy.recorded[0];
    // ... connection 2 replays it to a client that sent a different nonce.
    const fresh = makeHome();
    const r = await wsh([ACCEPT, `alice@${proxy.url}`, 'echo', 'x'], { home: fresh.home });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /HOST KEY INVALID/);
    assert.equal(fresh.knownHosts(), '', 'nothing recorded for a proof that did not verify');
    assert.deepEqual(real.ran.filter((c) => c !== 'echo warm'), []);
  });
});

describe('step 2: channel binding', () => {
  it('the login is bound to the proven host key: a host that REQUIRES a binding accepts the Rust client', async () => {
    const h = makeHome();
    const host = nodeHost(h, { hostKey: true, requireChannelBinding: true });
    const r = await wsh([ACCEPT, '--require-channel-binding', '--via', await viaRelay(host), 'alice@bound.example.com', 'echo', 'bound'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, 'bound\n');
  });

  it('without a host key there is nothing to bind: --require-channel-binding signs nothing, and a requiring host says why', async () => {
    const h = makeHome();
    const plain = nodeHost(h);
    const r = await wsh(['--require-channel-binding', '--via', await viaRelay(plain), 'alice@a.example.com', 'echo', 'x'], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /channel binding required but not available/);

    const requiring = nodeHost(h, { requireChannelBinding: true });
    const r2 = await wsh(['--via', await viaRelay(requiring), 'alice@b.example.com', 'echo', 'x'], { home: h.home });
    assert.notEqual(r2.code, 0);
    assert.match(r2.stderr, /channel binding is required by the host but not available/);
    assert.deepEqual(requiring.ran, []);
  });

  it('a host that does not require it still accepts the Rust client, which binds whenever it is offered', async () => {
    const h = makeHome();
    const host = nodeHost(h, { hostKey: true });
    const r = await wsh([ACCEPT, '--via', await viaRelay(host), 'alice@c.example.com', 'echo', 'unrequired'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
  });

  it('an intermediary that strips the host\'s binding offer is caught by --require-channel-binding, and by a requiring host', async () => {
    const h = makeHome();
    const real = await directHost(h, { hostKey: true, requireChannelBinding: true });
    const stripper = await intermediary(real.url, { strip: true });
    const r = await wsh([ACCEPT, '--require-channel-binding', `alice@${stripper.url}`, 'echo', 'x'], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /channel binding required but not available/);
    const r2 = await wsh([ACCEPT, `alice@${stripper.url}`, 'echo', 'x'], { home: h.home });
    assert.notEqual(r2.code, 0, 'the host requires a binding the stripped client did not make');
    assert.deepEqual(real.ran, []);
  });

  it('an intermediary presenting its own host key gets a signature bound to ITS key, which the real host refuses', async () => {
    const h = makeHome();
    const real = await directHost(h, { hostKey: true, requireChannelBinding: true });
    const imp = await intermediary(real.url, { swapKey: true });
    const r = await wsh([ACCEPT, `alice@${imp.url}`, 'echo', 'x'], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.deepEqual(real.ran, [], 'nothing ran for a login bound to the wrong key');
  });
});
