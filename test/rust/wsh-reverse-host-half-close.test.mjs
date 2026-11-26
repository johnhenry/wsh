// test/rust/wsh-reverse-host-half-close.test.mjs -- what an operator can reach on the Rust CLI's REVERSE HOST (`wsh reverse`) through a
// relay, as far as the gateway goes (#285).
//
// The host has handlers for `OpenTcp`, `OpenUdp`, `ResolveDns` and `ListenRequest` (with the `gateway` capability), and the half-close
// rule of those connections is tested where they live: the Rust unit tests in `crates/wsh-cli/src/commands/reverse_host.rs`.
// This file pins what no unit test can: those messages are not on the spec's relay-forwardable list, so NEITHER shipped relay carries
// them to a reverse host, and the host's own client drops them inside a `RelayForward`. An operator that asks gets no answer and
// nothing is dialled. If the spec ever makes them forwardable this test fails, which is the moment to read the half-close tests.
//
// The check is ordered, not timed: the operator sends the OpenTcp, then a message that IS carried (an exec) and waits for the
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
import { WshClient, generateKeyPair, exportPublicKeySSH, fingerprint, MSG } from '@johnhenry/wsh';
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

async function jsRelay(authorizedKeys) {
  const server = createWshServer({ auth: { authorizedKeys }, relay: { canRegister: () => true, canConnect: () => true, connectTimeoutMs: 8000 } });
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

for (const [kind, makeRelay] of [['JS', jsRelay], ['Rust', rustRelay]]) {
  describe(`the Rust CLI as a reverse host, behind the ${kind} relay`, () => {
    it('OpenTcp, OpenUdp, ResolveDns and ListenRequest are not carried: no answer, nothing dialled; what is carried is served', async () => {
      const host = await hostIdentity();
      const keyPair = await generateKeyPair(true);
      const relay = await makeRelay(`${host.pub}\n${await exportPublicKeySSH(keyPair.publicKey)} op`);
      const dialled = [];
      const origin = net.createServer((s) => { dialled.push(s); s.on('error', () => {}); });
      await new Promise((r) => origin.listen(0, '127.0.0.1', r));
      closers.push(async () => { for (const s of dialled) s.destroy(); origin.close(); });

      const h = relay.host(host.home);
      const proc = spawn(WSH_BIN, ['-t', 'ws', '--accept-new-host-key', 'reverse', h.target, '--capability', 'exec', '--capability', 'gateway'], { env: h.env, stdio: ['pipe', 'pipe', 'pipe'] });
      procs.push(proc);
      let out = ''; let err = '';
      proc.stdout.on('data', (d) => { out += d; }); proc.stderr.on('data', (d) => { err += d; });
      proc.stdin.on('error', () => {});
      await until(() => /Registered as peer/.test(out) || /error|failed/i.test(err), `the host to register (${err})`);
      assert.match(out, /Registered as peer/, err);

      const op = new WshClient();
      await op.connect(relay.url, { username: 'op', keyPair });
      closers.push(() => op.disconnect());
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp);
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      const heard = [];
      op.onGatewayMessage = (m) => { heard.push(m.type); };

      await op.sendControl(openTcp({ gatewayId: 1, host: '127.0.0.1', port: origin.address().port }));
      await op.sendControl(openUdp({ gatewayId: 2, host: '127.0.0.1', port: 9 }));
      await op.sendControl(resolveDns({ gatewayId: 3, name: 'localhost' }));
      await op.sendControl(listenRequest({ listenerId: 4, port: 0 }));
      // The canary: carried, and served in order after the four above.
      const session = await op.openSession({ type: 'exec', command: 'echo canary' });
      assert.ok(session, 'the host served what is carried');
      session.close?.();

      // A relay with a gateway of its own (the Rust one) may refuse the opens itself; what must never come back is a success.
      assert.deepEqual(heard.filter((t) => t !== MSG.GATEWAY_FAIL && t !== MSG.LISTEN_FAIL), [], 'no open was granted');
      assert.equal(dialled.length, 0, 'the origin was never dialled');
    });
  });
}
