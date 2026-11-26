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

async function rustRelay(authorizedKeys, { carry = true } = {}) {
  const home = scratchHome();
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${authorizedKeys}\n`);
  const configPath = path.join(home, 'wsh-server.toml');
  writeFileSync(configPath, `[relay]\ncarry_gateway = ${carry}\n`);
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

async function startRustHost(relay, host, extra = []) {
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
      await startRustHost(relay, host, ['--require-operator-proof', '--relay-gateway-allow', '127.0.0.1']);
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
      await startRustHost(relay, host, ['--require-operator-proof', '--relay-gateway-allow', '127.0.0.0/8', '--relay-gateway-dns', '--relay-gateway-listen']);
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
      await startRustHost(relay, host, ['--require-operator-proof', '--relay-gateway-allow', 'db.example.invalid:5432']);
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

describe('the Rust CLI reverse host behind a relay that does not carry the gateway', () => {
  for (const [kind, makeRelay] of [['JS', jsRelay], ['Rust', rustRelay]]) {
    it(`${kind} relay with carry off: the host (flag given) states nothing and nothing is carried`, async () => {
      const host = await rustHostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`, { carry: false });
      const origin = await echoOrigin();
      await startRustHost(relay, host, ['--relay-gateway-allow', '127.0.0.1']);
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

  it('the flag without the capability is refused at start, not ignored', async () => {
    const { home } = await rustHostIdentity();
    const r = spawn(WSH_BIN, ['--relay-gateway-allow', '127.0.0.1', 'reverse', 'ws://127.0.0.1:1/', '--capability', 'exec'], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
    procs.push(r);
    let err = '';
    r.stderr.on('data', (d) => { err += d; });
    const code = await new Promise((res) => r.once('exit', res));
    assert.notEqual(code, 0);
    assert.match(err, /--capability gateway/);
  });

  it('a rule that is not one is refused at start', async () => {
    const { home } = await rustHostIdentity();
    const r = spawn(WSH_BIN, ['--relay-gateway-allow', '10.0.0.0/33', 'reverse', 'ws://127.0.0.1:1/', '--capability', 'gateway'], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
    procs.push(r);
    let err = '';
    r.stderr.on('data', (d) => { err += d; });
    const code = await new Promise((res) => r.once('exit', res));
    assert.notEqual(code, 0);
    assert.match(err, /not a destination rule/);
  });
});
