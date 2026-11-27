// test/rust/wsh-relay-peer-left.test.mjs -- #297: when the peer of a bridge on the Rust relay leaves, the operator bridged to it is told the
// bridge is over (a Shutdown with the reason, then its connection is closed, as the JS relay closes it) for a peer that carried a gateway:
// its gateway connections would otherwise wait on their own half-close bounds, with nothing to say the host is gone. A peer that did not
// state `relay-gateway` is left as it always was (the operator stays connected; documented since #93).
//
// The Rust relay is the real `wsh-server --enable-relay`, the peer a JS reverse host, the operator this repo's JS client; HOME is a scratch
// directory. Prerequisite: cargo build -p wsh-server, then WSH_SERVER_BIN=<path> if it is not target/release/wsh-server.
import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createReverseHost } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG } from '@johnhenry/wsh';
import { freePort } from '../helpers/free-port.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 10_000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = []; const procs = []; const closers = [];
before(() => {
  assert.ok(existsSync(SERVER_BIN), `expected the built wsh-server binary at ${SERVER_BIN}`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
});
after(() => {
  for (const p of procs.splice(0)) p.kill('SIGKILL');
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

async function rustRelay(authorizedKeys) {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-peerleft-')); scratch.push(home);
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${authorizedKeys}\n`);
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--enable-relay'], {
    env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  procs.push(proc);
  let logs = '';
  await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  return { url: `wss://127.0.0.1:${port}` };
}

async function setup({ gateway }) {
  const hostKey = await generateKeyPair(true); const opKey = await generateKeyPair(true);
  const hostFp = await fingerprint(await exportPublicKeyRaw(hostKey.publicKey));
  const relay = await rustRelay(`${await exportPublicKeySSH(hostKey.publicKey)} host\n${await exportPublicKeySSH(opKey.publicKey)} op`);
  const host = createReverseHost({
    url: relay.url, username: 'host', keyPair: hostKey, exec: true, pty: false, reconnect: false, reportFeatures: true,
    accept: () => ({ capabilities: ['exec', 'gateway:tcp:*:*'] }),
    ...(gateway ? { gateway: { trustRelayIdentity: true, allow: ['127.0.0.1'] } } : {}),
  });
  await host.start();
  const op = new WshClient();
  const closed = new Promise((r) => { op.onClose = (info) => r(info); });
  await op.connect(relay.url, { username: 'op', keyPair: opKey });
  closers.push(() => op.disconnect());
  await until(async () => (await op.listPeers()).length, 'the host in the peer list');
  const accepted = await op.reverseConnect(hostFp);
  assert.equal(accepted.type, MSG.REVERSE_ACCEPT, accepted.reason);
  return { op, host, closed };
}

describe('the Rust relay and a peer that leaves (#297)', () => {
  it('an operator bridged to a peer that carried a gateway is told the bridge is over, and its connection is closed', async () => {
    const origin = net.createServer((s) => { s.on('data', (d) => s.write(d)); s.on('error', () => {}); });
    await new Promise((r) => origin.listen(0, '127.0.0.1', r)); closers.push(async () => origin.close());
    const { op, host, closed } = await setup({ gateway: true });
    const duplex = await op.openTcp('127.0.0.1', origin.address().port);
    const w = duplex.writable.getWriter(); await w.write(new TextEncoder().encode('x'));
    await duplex.readable.getReader().read();
    await host.close(); // the peer goes
    // The Shutdown says why; a client that gets one ends its own connection (and does not call onClose for what it ended itself).
    await until(() => op.state !== 'authenticated', 'the operator to be told the bridge is over');
    await until(() => duplex.closed.then(() => true), 'the gateway connection to end');
    assert.ok(closed);
  });

  it('a peer that did not carry a gateway leaves its operator connected, as before', async () => {
    const { op, host, closed } = await setup({ gateway: false });
    await host.close();
    let ended = false;
    closed.then(() => { ended = true; });
    assert.equal(op.state, 'authenticated');
    // The relay has dealt with the peer's departure once the peer is gone from its list (it unregisters last), and answering this at all
    // proves the operator's connection is up.
    await until(async () => (await op.listPeers()).length === 0, 'the peer to be gone from the relay');
    assert.equal(ended, false, 'the operator is still connected');
    assert.equal(op.state, 'authenticated');
  });
});
