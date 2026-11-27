// test/rust/wsh-reverse-host-half-close.test.mjs -- what an operator can reach on the Rust CLI's REVERSE HOST (`wsh reverse`) through a
// relay, as far as the gateway goes (#285, #289).
//
// Since #289 the gateway's requests (OpenTcp, OpenUdp, ResolveDns, ListenRequest) are carried to a reverse host that turned the gateway on
// (`--relay-gateway-allow RULE`, needs `--capability gateway`) and said `relay-gateway`; they are not carried to one that did not (this file
// used to pin that they were never carried). Both halves are asserted here, behind BOTH relays, against the real `wsh` binary:
//   - without the flag the host does not state the feature, the relay carries nothing, and nothing is dialled -- even though the host
//     has the `gateway` capability;
//   - with it the connection works, and the half-close rule of the host's gateway holds end to end (the #285 symptom): the operator
//     half-closes first and still gets the whole large answer from an origin that closes completely at once; an origin's end of file
//     leaves what the operator sends afterwards deliverable; a slow reader is bounded by the credit window, not by memory.
//
// The check of absence is ordered, not timed: the operator sends the OpenTcp, then a message that IS carried (an exec) and waits for the
// host's answer to that. Messages cross in order and the host serves them in order, so an OpenTcp that had been carried would have
// been answered or acted on (the origin dialled) before the exec's answer came back.
//
// Every `wsh` runs with HOME, USERPROFILE and XDG_CONFIG_HOME in a scratch directory; the Rust relay with its own.
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

import { createWshServer } from '@johnhenry/wsh/server';
import { RelayHub } from '../../src/server/relay.mjs';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG, RELAY_GATEWAY_FEATURE } from '@johnhenry/wsh';
import { openTcp, openUdp, resolveDns, listenRequest } from '../../src/messages.gen.mjs';
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

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = [];
const procs = [];
const closers = [];
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

const scratchHome = () => { const d = mkdtempSync(path.join(tmpdir(), 'wsh-rhhc-')); scratch.push(d); return d; };

/** The Rust host's identity: a scratch HOME with a key, its public line and fingerprint. */
async function hostIdentity() {
  const home = scratchHome();
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const pub = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  const wire = Buffer.from(pub.split(/\s+/)[1], 'base64');
  return { home, pub, fp: await fingerprint(new Uint8Array(wire.subarray(wire.length - 32))) };
}

async function jsRelay(authorizedKeys, relayOptions = {}) {
  const server = createWshServer({ auth: { authorizedKeys }, relay: { canRegister: () => true, canConnect: () => true, connectTimeoutMs: 8000, ...relayOptions } });
  const { port } = await server.listen();
  closers.push(() => server.close());
  return { url: `ws://127.0.0.1:${port}`, host: (home) => ({ target: `ws://127.0.0.1:${port}/`, env: cleanEnv(home) }) };
}

async function rustRelay(authorizedKeys) {
  const home = scratchHome();
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${authorizedKeys}\n`);
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--enable-relay', '--config', '/dev/null/none'], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
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

/** Start `wsh reverse` against the relay with `extra` arguments; resolves once it registered. */
async function startHost(relay, host, extraIn = [], operatorKeyPair = null) {
  // The owner's other two choices come with the gateway: the operator named, and the relay's word trusted (no proof here).
  // (`--require-operator-proof`, #318: a SEALED host: the operator is proven and named, the relay's word is not trusted)
  const sealedHost = extraIn.includes('--require-operator-proof');
  const extra = extraIn.includes('--relay-gateway-allow') && operatorKeyPair
    ? [...extraIn, '--allow-operator', await fingerprint(await exportPublicKeyRaw(operatorKeyPair.publicKey)), ...(sealedHost ? [] : ['--relay-gateway-trust-relay'])]
    : extraIn;
  const h = relay.host(host.home);
  const proc = spawn(WSH_BIN, ['-t', 'ws', '--accept-new-host-key', ...extra, 'reverse', h.target, '--capability', 'exec', '--capability', 'gateway'], { env: h.env, stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(proc);
  let out = ''; let err = '';
  proc.stdout.on('data', (d) => { out += d; }); proc.stderr.on('data', (d) => { err += d; });
  proc.stdin.on('error', () => {});
  await until(() => /Registered as peer/.test(out) || /error|failed/i.test(err), `the host to register (${err})`);
  assert.match(out, /Registered as peer/, err);
  return { proc, logs: () => `${out}${err}` };
}

async function connectOperator(relay, host, keyPair) {
  const op = new WshClient();
  await op.connect(relay.url, { username: 'op', keyPair });
  closers.push(() => op.disconnect());
  await until(async () => (await op.listPeers()).length, 'the host in the peer list');
  const res = await op.reverseConnect(host.fp);
  assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
  return { op, res };
}

for (const [kind, makeRelay] of [['JS', jsRelay], ['Rust', rustRelay]]) {
  describe(`the Rust CLI as a reverse host, behind the ${kind} relay`, () => {
    it('without --relay-gateway-allow the gateway is off: the feature is not stated, OpenTcp, OpenUdp, ResolveDns and ListenRequest are not carried, nothing is dialled; what is carried is served', async () => {
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const dialled = [];
      const origin = net.createServer((s) => { dialled.push(s); s.on('error', () => {}); });
      const originPort = await listen(origin);
      closers.push(async () => { for (const s of dialled) s.destroy(); origin.close(); });

      await startHost(relay, host); // the capability is there; the owner did not turn the gateway on
      const { op, res } = await connectOperator(relay, host, keyPair);
      assert.ok(!(res.features ?? []).includes(RELAY_GATEWAY_FEATURE), `no relay-gateway in ${res.features}`);
      assert.ok(!(res.features ?? []).includes('gateway'));
      const heard = [];
      op.onGatewayMessage = (m) => { heard.push(m); };

      await op.sendControl(openTcp({ gatewayId: 1, host: '127.0.0.1', port: originPort }));
      await op.sendControl(openUdp({ gatewayId: 2, host: '127.0.0.1', port: 9 }));
      await op.sendControl(resolveDns({ gatewayId: 3, name: 'localhost' }));
      await op.sendControl(listenRequest({ listenerId: 4, port: 0 }));
      // The canary: carried, and served in order after the four above.
      const session = await op.openSession({ type: 'exec', command: 'echo canary' });
      assert.ok(session, 'the host served what is carried');
      session.close?.();

      // A relay with a gateway of its own (the Rust one) may refuse the opens itself; what must never come back is a success.
      assert.deepEqual(heard.map((m) => m.type).filter((t) => t !== MSG.GATEWAY_FAIL && t !== MSG.LISTEN_FAIL), [], 'no open was granted');
      // ... and none of the refusals is the HOST's: the relay did not carry the four to it (a host that was sent them says "not enabled on this reverse host").
      assert.deepEqual(heard.filter((m) => /reverse host/.test(`${m.message ?? m.reason ?? ''}`)), [], 'the host was never sent the requests');
      assert.equal(dialled.length, 0, 'the origin was never dialled');
    });

    it('with --relay-gateway-allow the host states relay-gateway and an operator behind the relay opens a connection to an origin on the host\'s network', async () => {
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const origin = net.createServer((s) => { s.on('data', (d) => s.write(Buffer.concat([Buffer.from('echo:'), d]))); s.on('error', () => {}); });
      const originPort = await listen(origin);
      closers.push(async () => origin.close());
      await startHost(relay, host, ['--relay-gateway-allow', '127.0.0.1'], keyPair);
      const { op, res } = await connectOperator(relay, host, keyPair);
      for (const f of [RELAY_GATEWAY_FEATURE, 'gateway', 'gateway-credit']) assert.ok(res.features.includes(f), `${f} in ${res.features}`);
      const d = await op.openTcp('127.0.0.1', originPort);
      const writer = d.writable.getWriter();
      await writer.write(new TextEncoder().encode('hello'));
      const { value } = await d.readable.getReader().read();
      assert.equal(new TextDecoder().decode(value), 'echo:hello');
      d.destroy();
    });

    it('a destination no rule names is refused by the host; UDP, DNS and listening are each off until turned on', async () => {
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const origin = net.createServer((s) => { s.on('error', () => {}); });
      const originPort = await listen(origin);
      closers.push(async () => origin.close());
      await startHost(relay, host, ['--relay-gateway-allow', 'db.example.invalid:5432'], keyPair);
      const { op } = await connectOperator(relay, host, keyPair);
      await assert.rejects(op.openTcp('127.0.0.1', originPort), (e) => e.code === 4);
      await assert.rejects(op.openUdp('db.example.invalid', 5432), (e) => e.code === 4 && /UDP is not enabled/.test(e.message));
      await assert.rejects(op.listenTcp(0, { onConnection() {} }), (e) => e.code === 4);
      const inbox = [];
      op.onGatewayMessage = (m) => inbox.push(m);
      await op.sendControl(resolveDns({ gatewayId: 77, name: 'db.example.invalid' }));
      const f = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 77), 'the refusal');
      assert.match(f.message, /name resolution is not enabled/);
    });

    it('half-close: an operator that half-closed first still gets the whole large answer of an origin that closes completely at once, however slowly it reads', async () => {
      const SIZE = 3 * 1024 * 1024;
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      let request = '';
      const origin = net.createServer({ allowHalfOpen: true }, (s) => {
        s.on('error', () => {});
        s.on('data', (d) => { request += d; });
        s.once('end', () => { s.end(Buffer.alloc(SIZE, 9), () => s.destroy()); });
      });
      const originPort = await listen(origin);
      closers.push(async () => origin.close());
      await startHost(relay, host, ['--relay-gateway-allow', '127.0.0.1'], keyPair);
      const { op } = await connectOperator(relay, host, keyPair);
      const d = await op.openTcp('127.0.0.1', originPort);
      const writer = d.writable.getWriter();
      await writer.write(new TextEncoder().encode('the request'));
      await writer.close(); // the operator's half-close
      const reader = d.readable.getReader();
      let n = 0; let chunks = 0;
      for (;;) { const { value, done } = await reader.read(); if (done) break; n += value.length; if (++chunks % 8 === 0) await sleep(1); }
      assert.equal(n, SIZE, 'the whole answer');
      assert.equal(request, 'the request');
    });

    // #286: the host's origins are watched where the operator and the host both state `gateway-lossless-close` (the operator in ReverseConnect, the host
    // in ReverseAccept; both relays carry it). A vanished origin releases the operator's connection by itself, and a server that closed completely loses nothing.
    // ONE connection proves both halves. (A TCP origin that merely exits and closes cleanly is reported by the kernel only after about a minute, so
    // that is not provable in bounded time; a reset is, so the origin resets once the operator has read the whole answer.)
    it('lossless close through the relay: a 3 MiB answer arrives byte-exact and the connection is released by itself when the origin vanishes', async () => {
      const SIZE = 3 * 1024 * 1024;
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const gone = [];
      const origin = net.createServer((s) => { s.on('error', () => {}); gone.push(s); const b = Buffer.alloc(SIZE); for (let i = 0; i < SIZE; i += 4096) b.writeUInt32LE(i, i); s.end(b); });
      const port = await listen(origin);
      closers.push(async () => { origin.close(); for (const s of gone) s.destroy(); });
      await startHost(relay, host, ['--relay-gateway-allow', '127.0.0.1'], keyPair);
      const { op, res } = await connectOperator(relay, host, keyPair);
      assert.ok(res.features.includes('gateway-lossless-close') && res.features.includes('gateway-lossless-close-ack'), `the host states and acknowledges it: ${res.features}`);
      const v = await op.openTcp('127.0.0.1', port);
      assert.equal(v.lossless, false, 'unsealed bridge: best-effort, no guarantee (#318)');
      assert.equal(v.releasable, true);
      const reader = v.readable.getReader();
      let n = 0; let ok = true; let chunks = 0;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        for (let i = 0; i < value.length; i += 4096) { if ((n + i) % 4096 === 0 && Buffer.from(value.buffer, value.byteOffset, value.length).readUInt32LE(i) !== (n + i)) ok = false; }
        n += value.length;
        if (++chunks % 8 === 0) await sleep(1);
      }
      assert.equal(n, SIZE, 'every byte');
      assert.ok(ok, 'in order, byte-exact');
      assert.equal(await Promise.race([v.closed, sleep(400).then(() => 'open')]), 'open', 'a half-closed origin that is alive is held');
      gone[0].resetAndDestroy(); // the origin vanishes: a reset reaches the host
      assert.equal(await Promise.race([v.closed, sleep(20_000).then(() => 'open')]), 'released');
    });

    // The relay is the JS one, in this process, so it can be made to drop the operator's statement (as a released JS relay does for a host without
    // operator proof, or a hostile one): the host never sees it, so it does not acknowledge it, and neither side watches or releases.
    (kind === 'JS' ? it : it.skip)('lossless close through the relay: a relay that strips the operator\'s statement leaves both sides on the earlier behaviour', async () => {
      const original = RelayHub.prototype.connect;
      RelayHub.prototype.connect = function stripping(operator, msg) { const m = { ...msg }; delete m.features; return original.call(this, operator, m); };
      closers.push(async () => { RelayHub.prototype.connect = original; });
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const gone = [];
      const vanishing = net.createServer((s) => { s.on('error', () => {}); gone.push(s); s.end('bye'); });
      const port = await listen(vanishing);
      closers.push(async () => { vanishing.close(); for (const s of gone) s.destroy(); });
      await startHost(relay, host, ['--relay-gateway-allow', '127.0.0.1'], keyPair);
      const { op, res } = await connectOperator(relay, host, keyPair);
      assert.ok(!res.features.includes('gateway-lossless-close-ack'), `nothing was acknowledged: ${res.features}`);
      const v = await op.openTcp('127.0.0.1', port);
      assert.equal(v.lossless, false);
      const vr = v.readable.getReader();
      for (;;) { const { done } = await vr.read(); if (done) break; }
      await until(() => gone.length === 1, 'the origin to have been dialled');
      gone[0].resetAndDestroy();
      assert.equal(await Promise.race([v.closed, sleep(1500).then(() => 'open')]), 'open', 'not watched: held, as before');
      v.destroy();
    });

    // #318: the guarantee holds on a SEALED bridge only. On a sealed Rust host (--require-operator-proof) the statement is what the operator signed in its
    // proof: a relay that ADDS it for an operator that declined it is not believed (no acknowledgement, no watching); an operator that signed it gets the
    // release and reports the guarantee. An unsealed host stays best-effort as in rust-v0.26 (the relay's list is taken).
    (kind === 'JS' ? it : it.skip)('lossless close through the relay (#318): a SEALED host does not believe a statement a relay added for an operator that declined it', async () => {
      const original = RelayHub.prototype.connect;
      RelayHub.prototype.connect = function adding(operator, msg) { return original.call(this, operator, { ...msg, features: [...(msg.features ?? []), 'gateway-lossless-close'] }); };
      closers.push(async () => { RelayHub.prototype.connect = original; });
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const gone = [];
      const vanishing = net.createServer((s) => { s.on('error', () => {}); gone.push(s); s.end('bye'); });
      const port = await listen(vanishing);
      closers.push(async () => { vanishing.close(); for (const s of gone) s.destroy(); });
      await startHost(relay, host, ['--require-operator-proof', '--relay-gateway-allow', '127.0.0.1'], keyPair);
      const op = new WshClient();
      await op.connect(relay.url, { username: 'op', keyPair, gatewayLosslessClose: false });
      closers.push(() => op.disconnect());
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp, undefined, { sealed: true });
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      assert.ok(!res.features.includes('gateway-lossless-close-ack'), `the host did not believe the relay: ${res.features}`);
      const v = await op.openTcp('127.0.0.1', port);
      const vr = v.readable.getReader();
      for (;;) { const { done } = await vr.read(); if (done) break; }
      await until(() => gone.length === 1, 'the origin to have been dialled');
      gone[0].resetAndDestroy();
      assert.equal(await Promise.race([v.closed, sleep(1500).then(() => 'open')]), 'open', 'not watched: held, as before');
      v.destroy();
    });

    it('lossless close through the relay (#318): a SEALED Rust host reads the signed statement: acknowledged, the vanished origin releases the connection, and the operator reports the guarantee', async () => {
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const gone = [];
      const vanishing = net.createServer((s) => { s.on('error', () => {}); gone.push(s); s.end('bye'); });
      const port = await listen(vanishing);
      closers.push(async () => { vanishing.close(); for (const s of gone) s.destroy(); });
      await startHost(relay, host, ['--require-operator-proof', '--relay-gateway-allow', '127.0.0.1'], keyPair);
      const op = new WshClient();
      await op.connect(relay.url, { username: 'op', keyPair });
      closers.push(() => op.disconnect());
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp, undefined, { sealed: true });
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      assert.ok(res.features.includes('gateway-lossless-close-ack'), `${res.features}`);
      const v = await op.openTcp('127.0.0.1', port);
      assert.equal(v.lossless, true);
      const vr = v.readable.getReader();
      for (;;) { const { done } = await vr.read(); if (done) break; }
      await until(() => gone.length === 1, 'the origin to have been dialled');
      gone[0].resetAndDestroy();
      assert.equal(await Promise.race([v.closed, sleep(15000).then(() => 'open')]), 'released');
    });

    it('the Rust host lists `gateway-lossless-close-signed` in its record; an UNSEALED bridge stays best-effort: the unsigned statement is acknowledged, and no guarantee is reported (#318)', async () => {
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      await startHost(relay, host, ['--relay-gateway-allow', '127.0.0.1'], keyPair);
      const { op, res } = await connectOperator(relay, host, keyPair);
      assert.ok((await op.listPeers())[0].capabilities.includes('gateway-lossless-close-signed'));
      assert.ok(res.features.includes('gateway-lossless-close-ack'), `${res.features}`);
    });

    it('lossless close through the relay: an operator that did not state the feature: the origin is not watched, as before', async () => {
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const gone = [];
      const vanishing = net.createServer((s) => { s.on('error', () => {}); gone.push(s); s.end('bye'); });
      const port = await listen(vanishing);
      closers.push(async () => { vanishing.close(); for (const s of gone) s.destroy(); });
      await startHost(relay, host, ['--relay-gateway-allow', '127.0.0.1'], keyPair);
      const op = new WshClient();
      await op.connect(relay.url, { username: 'op', keyPair, gatewayLosslessClose: false });
      closers.push(() => op.disconnect());
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      assert.equal((await op.reverseConnect(host.fp)).type, MSG.REVERSE_ACCEPT);
      const v = await op.openTcp('127.0.0.1', port);
      const vr = v.readable.getReader();
      for (;;) { const { done } = await vr.read(); if (done) break; }
      await until(() => gone.length === 1, 'the origin to have been dialled');
      gone[0].resetAndDestroy();
      assert.equal(await Promise.race([v.closed, sleep(1500).then(() => 'open')]), 'open', 'not noticed: held, as before');
      v.destroy();
    });

    it('half-close the other way: the origin finishes first and what the operator sends afterwards still reaches it', async () => {
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      let got = '';
      const origin = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.on('data', (x) => { got += x; }); s.end('bye'); });
      const originPort = await listen(origin);
      closers.push(async () => origin.close());
      await startHost(relay, host, ['--relay-gateway-allow', '127.0.0.1'], keyPair);
      const { op } = await connectOperator(relay, host, keyPair);
      const d = await op.openTcp('127.0.0.1', originPort);
      const reader = d.readable.getReader();
      let text = '';
      for (;;) { const { value, done } = await reader.read(); if (done) break; text += new TextDecoder().decode(value); }
      assert.equal(text, 'bye');
      const writer = d.writable.getWriter();
      await writer.write(new TextEncoder().encode('afterwards'));
      await until(() => got === 'afterwards', 'what the operator sent after the origin finished');
      d.destroy();
    });

    it('a slow reader stops the origin: the host holds only the credit window, not the whole answer', async () => {
      const SIZE = 16 * 1024 * 1024;
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      let written = 0;
      const origin = net.createServer((s) => {
        s.on('error', () => {});
        const chunk = Buffer.alloc(64 * 1024, 5);
        const pump = () => { while (written < SIZE) { written += chunk.length; if (!s.write(chunk)) { s.once('drain', pump); return; } } s.end(); };
        pump();
      });
      const originPort = await listen(origin);
      closers.push(async () => origin.close());
      await startHost(relay, host, ['--relay-gateway-allow', '127.0.0.1'], keyPair);
      const { op } = await connectOperator(relay, host, keyPair);
      const d = await op.openTcp('127.0.0.1', originPort);
      let last = -1;
      await until(async () => { await sleep(150); const now = written; const stalled = now === last && now > 0; last = now; return stalled; }, 'the origin to stall');
      assert.ok(written < 8 * 1024 * 1024, `the origin got ${written} bytes ahead of a reader that read nothing (the window is 256 KiB)`);
      const reader = d.readable.getReader();
      let n = 0;
      for (;;) { const { value, done } = await reader.read(); if (done) break; n += value.length; }
      assert.equal(n, SIZE);
    });
  });
}
