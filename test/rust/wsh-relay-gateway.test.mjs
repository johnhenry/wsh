// test/rust/wsh-relay-gateway.test.mjs -- the gateway through a relay (#289) across the implementations: the JS reverse host behind the Rust
// relay, the Rust CLI reverse host on a sealed bridge, and what a relay that does not carry the gateway does.
//
// (The Rust CLI host behind both relays, and the half-close, large-answer and flow-control behaviour, are in
// `wsh-reverse-host-half-close.test.mjs`; the JS relay with the JS host is in `test/relay-gateway.test.mjs`.)
//
// Every `wsh` and `wsh-server` runs with HOME, USERPROFILE and XDG_CONFIG_HOME in a scratch directory.
// Prerequisite: `cargo build --release -p wsh-cli -p wsh-server` (or WSH_BIN and WSH_SERVER_BIN).

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG, RELAY_GATEWAY_FEATURE } from '@johnhenry/wsh';
import { openTcp, resolveDns } from '../../src/messages.gen.mjs';
import { freePort } from '../helpers/free-port.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 10_000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
const cleanEnv = (home, extra = {}) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm', ...extra });
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
const dec = new TextDecoder();

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = []; const procs = []; const closers = [];
before(() => {
  assert.ok(existsSync(WSH_BIN), `expected the built wsh binary at ${WSH_BIN} (cargo build --release -p wsh-cli, or WSH_BIN)`);
  assert.ok(existsSync(SERVER_BIN), `expected the built wsh-server binary at ${SERVER_BIN} (cargo build --release -p wsh-server, or WSH_SERVER_BIN)`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the Rust relay's dev certificate is self-signed
});
after(() => {
  for (const p of procs.splice(0)) p.kill('SIGKILL');
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const scratchHome = () => { const d = mkdtempSync(path.join(tmpdir(), 'wsh-rgw-')); scratch.push(d); return d; };

async function rustHostIdentity() {
  const home = scratchHome();
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const pub = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  const wire = Buffer.from(pub.split(/\s+/)[1], 'base64');
  return { home, pub, fp: await fingerprint(new Uint8Array(wire.subarray(wire.length - 32))) };
}

async function jsRelay(authorizedKeys, { carry = true } = {}) {
  const server = createWshServer({ auth: { authorizedKeys }, relay: { canRegister: () => true, canConnect: () => true, connectTimeoutMs: 8000, carryGateway: carry } });
  const { port } = await server.listen();
  closers.push(() => server.close());
  return { url: `ws://127.0.0.1:${port}`, host: (home) => ({ target: `ws://127.0.0.1:${port}/`, env: cleanEnv(home) }) };
}

async function rustRelay(authorizedKeys, { carry = true, maxOperators = 1 } = {}) {
  const home = scratchHome();
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${authorizedKeys}\n`);
  const configPath = path.join(home, 'wsh-server.toml');
  writeFileSync(configPath, `[relay]\ncarry_gateway = ${carry}\nmax_operators_per_peer = ${maxOperators}\n`);
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--enable-relay', '--config', configPath], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  const certFile = path.join(home, '.wsh', 'cert.pem');
  return { url: `wss://127.0.0.1:${port}`, host: (h) => ({ target: `wss://localhost:${port}/`, env: cleanEnv(h, { SSL_CERT_FILE: certFile }) }) };
}

/** With `--relay-gateway-allow`, the owner's other two choices come with it: the operator named, and (unless proof is required) the relay's word trusted. */
async function gatewayChoices(extra, operatorKeyPair) {
  if (!extra.includes('--relay-gateway-allow') || !operatorKeyPair) return extra;
  const fp = await fingerprint(await exportPublicKeyRaw(operatorKeyPair.publicKey));
  return [...extra, '--allow-operator', fp, ...(extra.includes('--require-operator-proof') ? [] : ['--relay-gateway-trust-relay'])];
}

async function startRustHost(relay, host, extraIn = [], operatorKeyPair = null) {
  const extra = await gatewayChoices(extraIn, operatorKeyPair);
  const h = relay.host(host.home);
  const proc = spawn(WSH_BIN, ['-t', 'ws', '--accept-new-host-key', ...extra, 'reverse', h.target, '--capability', 'exec', '--capability', 'gateway'], { env: h.env, stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(proc);
  let out = ''; let err = '';
  proc.stdout.on('data', (d) => { out += d; }); proc.stderr.on('data', (d) => { err += d; });
  proc.stdin.on('error', () => {});
  await until(() => /Registered as peer/.test(out) || /error|failed/i.test(err), `the host to register (${err})`);
  assert.match(out, /Registered as peer/, err);
  return { logs: () => `${out}${err}` };
}

async function echoOrigin() {
  const sockets = [];
  const server = net.createServer((s) => { sockets.push(s); s.on('data', (d) => s.write(Buffer.concat([Buffer.from('echo:'), d]))); s.on('error', () => {}); });
  const port = await listen(server);
  closers.push(async () => { for (const s of sockets) s.destroy(); server.close(); });
  return { port, sockets };
}

async function roundTrip(d, text) {
  const writer = d.writable.getWriter();
  await writer.write(new TextEncoder().encode(text));
  const { value } = await d.readable.getReader().read();
  d.destroy();
  return dec.decode(value);
}

describe('the JS reverse host behind the Rust relay', () => {
  const hostKeys = {};
  async function jsHost(relay, hostOptions) {
    const keyPair = await generateKeyPair(true);
    const opKeyPair = await generateKeyPair(true);
    const hostFp = await fingerprint(await exportPublicKeyRaw(keyPair.publicKey));
    hostKeys.value = { keyPair, opKeyPair, hostFp };
    return { keyPair, opKeyPair, hostFp, authorized: `${await exportPublicKeySSH(keyPair.publicKey)} host\n${await exportPublicKeySSH(opKeyPair.publicKey)} op`, hostOptions };
  }
  async function start(relayMaker, relayOptions, hostOptions) {
    const keys = await jsHost(null, hostOptions);
    const relay = await relayMaker(keys.authorized, relayOptions);
    const host = createReverseHost({
      url: relay.url, username: 'host', keyPair: keys.keyPair, exec: true, pty: false, reconnect: false,
      accept: () => ({ capabilities: ['exec', 'gateway:tcp:*:*'] }), ...hostOptions,
      ...(hostOptions.gateway ? { gateway: { ...(hostOptions.requireOperatorProof ? {} : { trustRelayIdentity: true }), ...hostOptions.gateway } } : {}),
    });
    await host.start();
    closers.push(() => host.close());
    const op = new WshClient();
    await op.connect(relay.url, { username: 'op', keyPair: keys.opKeyPair });
    closers.push(() => op.disconnect());
    await until(async () => (await op.listPeers()).length, 'the host in the peer list');
    return { op, relay, keys };
  }

  it('an operator uses its gateway through the Rust relay', async () => {
    const origin = await echoOrigin();
    const { op, keys } = await start(rustRelay, {}, { gateway: { allow: ['127.0.0.1'] } });
    const res = await op.reverseConnect(keys.hostFp);
    assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
    assert.ok(res.features.includes(RELAY_GATEWAY_FEATURE));
    assert.equal(await roundTrip(await op.openTcp('127.0.0.1', origin.port), 'through rust'), 'echo:through rust');
  });

  it('a host that REFUSES a second operator does not stop the first one\'s gateway (the Rust relay keeps what the accept said)', async () => {
    const origin = await echoOrigin();
    const keys = await jsHost(null, {});
    const op2KeyPair = await generateKeyPair(true);
    const authorized = `${keys.authorized}\n${await exportPublicKeySSH(op2KeyPair.publicKey)} op2`;
    const relay = await rustRelay(authorized, { maxOperators: 2 });
    const host = createReverseHost({
      url: relay.url, username: 'host', keyPair: keys.keyPair, exec: true, pty: false, reconnect: false, maxOperators: 2,
      gateway: { allow: ['127.0.0.1'], trustRelayIdentity: true },
      accept: (who) => (who.username === 'op' ? { capabilities: ['exec', 'gateway:tcp:*:*'] } : false),
    });
    await host.start();
    closers.push(() => host.close());
    const a = new WshClient();
    await a.connect(relay.url, { username: 'op', keyPair: keys.opKeyPair });
    closers.push(() => a.disconnect());
    await until(async () => (await a.listPeers()).length, 'the host in the peer list');
    assert.equal((await a.reverseConnect(keys.hostFp)).type, MSG.REVERSE_ACCEPT);
    assert.equal(await roundTrip(await a.openTcp('127.0.0.1', origin.port), 'one'), 'echo:one');
    // A second operator is refused by the HOST (its accept said no).
    const b = new WshClient();
    await b.connect(relay.url, { username: 'op2', keyPair: op2KeyPair });
    closers.push(() => b.disconnect());
    assert.equal((await b.reverseConnect(keys.hostFp)).type, MSG.REVERSE_REJECT);
    // The first operator's gateway still crosses, and is still the host's (the origin is on the host's network and is dialled by it).
    assert.equal(await roundTrip(await a.openTcp('127.0.0.1', origin.port), 'two'), 'echo:two');
    assert.equal(origin.sockets.length, 2);
  });

  it('a saturated relay: thirty connections to an operator that reads nothing for a while, every one byte-exact and in order afterwards', async () => {
    // Thirty: more than the old 64-deep queue to the operator holds in flight (4 frames each), so a relay that skipped what it could not
    // queue, or a stream that interleaved concurrent writers, would show here as a short or garbled answer.
    const CONNS = 30; const SIZE = 3 * 1024 * 1024;
    const stalled = new Array(CONNS).fill(0);
    let accepted = 0;
    const origin = net.createServer((s) => {
      const id = accepted++;
      s.on('error', () => {});
      const chunk = Buffer.alloc(64 * 1024);
      let n = 0;
      const pump = () => { while (n < SIZE) { const piece = Buffer.alloc(65536, (n / 65536) % 251); n += piece.length; stalled[id] = n; if (!s.write(piece)) { s.once('drain', pump); return; } } s.end(); };
      pump();
    });
    const originPort = await listen(origin);
    closers.push(async () => origin.close());
    const { op, keys } = await start(rustRelay, {}, { gateway: { allow: ['127.0.0.1'], maxConnections: CONNS } });
    const res = await op.reverseConnect(keys.hostFp);
    assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
    const duplexes = [];
    for (let i = 0; i < CONNS; i++) duplexes.push(await op.openTcp('127.0.0.1', originPort));
    // Nobody reads: every origin stops within the credit window (plus socket buffers), the relay holds what is in flight and no more.
    let last = -1;
    await until(async () => { await sleep(200); const total = stalled.reduce((a, b) => a + b, 0); const same = total === last; last = total; return same && total > 0; }, 'the origins to stall');
    // Now read everything: each stream is exactly what its origin wrote, in order (a frame lost or reordered in the relay would show).
    const results = await Promise.all(duplexes.map(async (d) => {
      const reader = d.readable.getReader();
      let n = 0; let ok = true;
      for (;;) { const { value, done } = await reader.read(); if (done) break; for (let i = 0; i < value.length; i += 997) { if (value[i] !== Math.floor((n + i) / 65536) % 251) ok = false; } n += value.length; }
      return { n, ok };
    }));
    for (const r of results) { assert.equal(r.n, SIZE); assert.ok(r.ok, 'bytes in order'); }
  });

  // ONE connection proves both halves (a TCP origin that merely exits cleanly is reported by the kernel only after about a minute, so a reset is what is
  // provable in bounded time; it follows the operator's last byte read).
  it('gateway-lossless-close crosses the Rust relay to the JS host (#286): a 3 MiB answer arrives byte-exact and the connection is released by itself when the origin vanishes', async () => {
    const SIZE = 3 * 1024 * 1024;
    const gone = [];
    const origin = net.createServer((s) => { s.on('error', () => {}); gone.push(s); const b = Buffer.alloc(SIZE); for (let i = 0; i < SIZE; i += 4096) b.writeUInt32LE(i, i); s.end(b); });
    const port = await listen(origin);
    closers.push(async () => { origin.close(); for (const s of gone) s.destroy(); });
    const { op, keys } = await start(rustRelay, {}, { gateway: { allow: ['127.0.0.1'], halfCloseIdleMs: 0, halfCloseProbeMs: 50 } });
    const res = await op.reverseConnect(keys.hostFp);
    assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
    assert.ok(res.features.includes('gateway-lossless-close') && res.features.includes('gateway-lossless-close-ack'), `${res.features}`);
    const v = await op.openTcp('127.0.0.1', port);
    assert.equal(v.lossless, true);
    const reader = v.readable.getReader();
    let n = 0; let ok = true; let chunks = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      for (let i = 0; i < value.length; i += 4096) { if ((n + i) % 4096 === 0 && Buffer.from(value.buffer, value.byteOffset, value.length).readUInt32LE(i) !== (n + i)) ok = false; }
      n += value.length;
      if (++chunks % 8 === 0) await sleep(1);
    }
    assert.equal(n, SIZE);
    assert.ok(ok, 'in order, byte-exact');
    gone[0].resetAndDestroy();
    assert.equal(await Promise.race([v.closed, sleep(20_000).then(() => 'open')]), 'released');
  });

  it('with the bridge sealed, through the Rust relay', async () => {
    const origin = await echoOrigin();
    const { op, keys } = await start(rustRelay, {}, { gateway: { allow: ['127.0.0.1'] }, requireOperatorProof: true });
    const res = await op.reverseConnect(keys.hostFp, undefined, { sealed: true });
    assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
    assert.equal(await roundTrip(await op.openTcp('127.0.0.1', origin.port), 'sealed through rust'), 'echo:sealed through rust');
  });

  it('a Rust relay that does not carry it ([relay] carry_gateway = false): the host states no gateway and nothing is carried', async () => {
    const origin = await echoOrigin();
    const { op, keys } = await start(rustRelay, { carry: false }, { gateway: { allow: ['127.0.0.1'] } });
    const res = await op.reverseConnect(keys.hostFp);
    assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
    assert.ok(!res.features.includes(RELAY_GATEWAY_FEATURE) && !res.features.includes('gateway'), `${res.features}`);
    await assert.rejects(op.openTcp('127.0.0.1', origin.port), /does not support TCP egress/);
    assert.equal(origin.sockets.length, 0);
  });

  it('a host that claims relay-gateway on a Rust relay that does not carry it is still not sent the requests', async () => {
    const origin = await echoOrigin();
    const keys = await jsHost(null, {});
    const relay = await rustRelay(keys.authorized, { carry: false });
    const fake = new WshClient();
    await fake.connectReverse(relay.url, { username: 'host', keyPair: keys.keyPair, expose: { exec: true } });
    closers.push(() => fake.disconnect());
    const delivered = [];
    fake.onRelayMessage = (m) => delivered.push(m.type);
    fake.onReverseConnect = async (req) => {
      fake.trustRelayPeer(req.from_fingerprint);
      await fake.sendRelayControl({ type: MSG.REVERSE_ACCEPT, target_fingerprint: keys.hostFp, username: 'host', capabilities: ['exec'], peer_type: 'host', shell_backend: 'exec-only', supports_attach: false, supports_replay: false, supports_echo: false, supports_term_sync: false, features: [RELAY_GATEWAY_FEATURE, 'gateway', 'gateway-credit'] });
    };
    const op = new WshClient();
    await op.connect(relay.url, { username: 'op', keyPair: keys.opKeyPair });
    closers.push(() => op.disconnect());
    await until(async () => (await op.listPeers()).length, 'the fake host in the peer list');
    const res = await op.reverseConnect(keys.hostFp);
    assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
    await assert.rejects(op.openTcp('127.0.0.1', origin.port), /this relay does not state "relay-gateway"/);
    await op.sendControl(openTcp({ gatewayId: 5, host: '127.0.0.1', port: origin.port })); // as a client that ignores features would
    await sleep(200); // the relay has nothing to answer with; a carried request would have been delivered by now
    assert.deepEqual(delivered, [], 'nothing reached the host');
  });
});

for (const [kind, makeRelay] of [['JS', jsRelay], ['Rust', rustRelay]]) {
  describe(`the Rust CLI reverse host on a sealed bridge, behind the ${kind} relay`, () => {
    it('--require-operator-proof: the gateway works for an operator that proved itself and sealed the bridge', async () => {
      const host = await rustHostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const origin = await echoOrigin();
      await startRustHost(relay, host, ['--require-operator-proof', '--relay-gateway-allow', '127.0.0.1'], keyPair);
      const op = new WshClient();
      await op.connect(relay.url, { username: 'op', keyPair });
      closers.push(() => op.disconnect());
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp, undefined, { sealed: true });
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      assert.ok(res.features.includes(RELAY_GATEWAY_FEATURE) && res.features.includes('e2e-sealed'));
      assert.equal(await roundTrip(await op.openTcp('127.0.0.1', origin.port), 'sealed to the cli'), 'echo:sealed to the cli');
    });

    it('name lookups and reverse tunnels (the answers that are not on the old forwardable list) travel sealed too', async () => {
      const host = await rustHostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      await startRustHost(relay, host, ['--require-operator-proof', '--relay-gateway-allow', '127.0.0.0/8', '--relay-gateway-dns', '--relay-gateway-listen'], keyPair);
      const op = new WshClient();
      await op.connect(relay.url, { username: 'op', keyPair });
      closers.push(() => op.disconnect());
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp, undefined, { sealed: true });
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      const inbox = [];
      op.onGatewayMessage = (m) => inbox.push(m);
      await op.sendControl(resolveDns({ gatewayId: 61, name: 'localhost' }));
      const dns = await until(() => inbox.find((m) => m.type === MSG.DNS_RESULT && m.gateway_id === 61), 'the DnsResult (sealed)');
      assert.ok(dns.addresses.includes('127.0.0.1'), `${dns.addresses}`);
      // A reverse tunnel: ListenOk and InboundOpen are the host's, sealed; a caller of the host's loopback port reaches the operator.
      const seen = new Promise((resolve, reject) => {
        op.listenTcp(0, {
          onConnection: async (duplex) => {
            try {
              const { value } = await duplex.readable.getReader().read();
              const writer = duplex.writable.getWriter();
              await writer.write(new TextEncoder().encode(`back:${dec.decode(value)}`));
              duplex.close();
              resolve();
            } catch (e) { reject(e); }
          },
        }).then(async (l) => {
          const caller = net.connect(l.port, '127.0.0.1');
          caller.on('error', () => {});
          caller.write('knock');
          let answer = '';
          caller.on('data', (d) => { answer += d; });
          await until(() => answer === 'back:knock', 'the answer through the sealed tunnel');
          caller.destroy();
          await l.close();
        }).catch(reject);
      });
      await seen;
    });

    it('the host\'s own refusals still hold on a sealed bridge: a destination no rule names', async () => {
      const host = await rustHostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const origin = await echoOrigin();
      await startRustHost(relay, host, ['--require-operator-proof', '--relay-gateway-allow', 'db.example.invalid:5432'], keyPair);
      const op = new WshClient();
      await op.connect(relay.url, { username: 'op', keyPair });
      closers.push(() => op.disconnect());
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp, undefined, { sealed: true });
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      await assert.rejects(op.openTcp('127.0.0.1', origin.port), (e) => e.code === 4);
      assert.equal(origin.sockets.length, 0);
    });
  });
}

describe('a JS relay that tampers with the sealed bridge of the Rust CLI host', () => {
  for (const [mode, expectedDials] of [['alter', 0], ['replay', 1], ['reorder', 0]]) {
    it(`${mode}: the host does not act on it and ends the bridge; nothing more is served over it`, async () => {
      const host = await rustHostIdentity();
      const keyPair = await generateKeyPair(true);
      const opFp = await fingerprint(await exportPublicKeyRaw(keyPair.publicKey));
      const relay = await jsRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const origin = await echoOrigin();
      await startRustHost(relay, host, ['--require-operator-proof', '--relay-gateway-allow', '127.0.0.1'], keyPair);
      const op = new WshClient();
      await op.connect(relay.url, { username: 'op', keyPair });
      closers.push(() => op.disconnect());
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp, undefined, { sealed: true });
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      // tamper with what the operator sends from here on
      const { RelayHub } = await import('../../src/server/relay.mjs');
      const original = RelayHub.prototype.forward;
      let held = null; let n = 0;
      RelayHub.prototype.forward = function patched(handle, msg) {
        if (msg.type !== MSG.ENCRYPTED_FRAME || msg.channel_id !== 0 || handle.fingerprint !== opFp) return original.call(this, handle, msg);
        const index = n++;
        if (mode === 'alter' && index === 0) { const ciphertext = Uint8Array.from(msg.ciphertext); ciphertext[0] ^= 1; return original.call(this, handle, { ...msg, ciphertext }); }
        if (mode === 'replay' && index === 0) { const r = original.call(this, handle, msg); original.call(this, handle, msg); return r; }
        if (mode === 'reorder') {
          if (index === 0) { held = msg; return true; }
          const r = original.call(this, handle, msg);
          if (index === 1) original.call(this, handle, held);
          return r;
        }
        return original.call(this, handle, msg);
      };
      closers.push(async () => { RelayHub.prototype.forward = original; });
      const attempts = [op.openTcp('127.0.0.1', origin.port, { timeoutMs: 2500 }), op.openTcp('127.0.0.1', origin.port, { timeoutMs: 2500 })].map((p) => p.then((d) => { d.destroy(); return 'ok'; }, () => 'failed'));
      const results = await Promise.all(attempts);
      assert.ok(results.includes('failed'), `${results}`);
      assert.ok(origin.sockets.length <= expectedDials, `${origin.sockets.length} connections dialled for ${mode}`);
      // The bridge is over: a request after it, untampered, is not served either.
      RelayHub.prototype.forward = original;
      await assert.rejects(op.openTcp('127.0.0.1', origin.port, { timeoutMs: 2500 }));
      assert.ok(origin.sockets.length <= expectedDials);
    });
  }
});

describe('the Rust CLI reverse host behind a relay that does not carry the gateway', () => {
  for (const [kind, makeRelay] of [['JS', jsRelay], ['Rust', rustRelay]]) {
    it(`${kind} relay with carry off: the host (flag given) states nothing and nothing is carried`, async () => {
      const host = await rustHostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`, { carry: false });
      const origin = await echoOrigin();
      await startRustHost(relay, host, ['--relay-gateway-allow', '127.0.0.1'], keyPair);
      const op = new WshClient();
      await op.connect(relay.url, { username: 'op', keyPair });
      closers.push(() => op.disconnect());
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp);
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      assert.ok(!(res.features ?? []).includes(RELAY_GATEWAY_FEATURE), `${res.features}`);
      await assert.rejects(op.openTcp('127.0.0.1', origin.port));
      assert.equal(origin.sockets.length, 0);
    });
  }

  const OP = '0123456789abcdef';
  for (const [name, flags, capability, pattern] of [
    ['the flag without the capability', ['--relay-gateway-allow', '127.0.0.1', '--allow-operator', OP, '--relay-gateway-trust-relay'], 'exec', /--capability gateway/],
    ['a rule that is not one', ['--relay-gateway-allow', '10.0.0.0/33', '--allow-operator', OP, '--relay-gateway-trust-relay'], 'gateway', /not a destination rule/],
    ['a gateway with no operator named (even with proof required)', ['--relay-gateway-allow', '127.0.0.1', '--require-operator-proof'], 'gateway', /--allow-operator/],
    ['a gateway with neither proof nor the explicit trust of the relay', ['--relay-gateway-allow', '127.0.0.1', '--allow-operator', OP], 'gateway', /--require-operator-proof.*--relay-gateway-trust-relay|--relay-gateway-trust-relay.*--require-operator-proof/],
    ['a gateway for several operators without the explicit trust (they cannot seal)', ['--relay-gateway-allow', '127.0.0.1', '--allow-operator', OP, '--require-operator-proof', '--max-operators', '2'], 'gateway', /--max-operators|--require-operator-proof/],
    ['the gateway switches without a rule', ['--relay-gateway-udp'], 'gateway', /--relay-gateway-allow/],
  ]) {
    it(`${name} is refused at start, not ignored`, async () => {
      const { home } = await rustHostIdentity();
      const r = spawn(WSH_BIN, [...flags, 'reverse', 'ws://127.0.0.1:1/', '--capability', capability], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
      procs.push(r);
      let err = '';
      r.stderr.on('data', (d) => { err += d; });
      const code = await new Promise((res) => r.once('exit', res));
      assert.notEqual(code, 0);
      assert.match(err, pattern);
    });
  }
});
