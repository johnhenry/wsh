// test/rust/wsh-login-deadline.test.mjs -- #248: the Rust `wsh-server` closes a connection that does not complete its login (the TLS handshake,
// the WebSocket upgrade, Hello and Auth) within `[server] login_timeout_secs` (default 60, 0 = no deadline), counted from the moment it
// accepted the connection. The JS hosts do the same with `loginTimeoutMs` (test/login-deadline.test.mjs).
//
// 1 s is the smallest the key takes: every wait below is for an event (the close of a connection), never for a count of milliseconds, and
// "not closed" is shown by a connection opened BEFORE the one whose close was awaited, so the deadline has passed for it too.
// Every process runs with HOME in a scratch directory. Prerequisite: cargo build --release -p wsh-server (or WSH_SERVER_BIN).

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';

import { WshClient, generateKeyPair, exportPublicKeySSH } from '../../src/index.mjs';
import { listeningPort } from './helpers/listening.mjs'; // the server binds port 0 and prints the port it got (#320)

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

const scratch = [];
const procs = [];
const closers = [];
const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
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

const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm' });

/** A wsh-server whose HOME holds an authorized key and `[server] login_timeout_secs = <loginTimeoutSecs>` (left out when undefined). */
async function startServer({ loginTimeoutSecs } = {}) {
  const kp = await generateKeyPair(true);
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-login-srv-'));
  scratch.push(home);
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(kp.publicKey)}\n`);
  const configPath = path.join(home, '.wsh', 'config.toml');
  writeFileSync(configPath, `[server]\n${loginTimeoutSecs === undefined ? '' : `login_timeout_secs = ${loginTimeoutSecs}\n`}`);
  const proc = spawn(SERVER_BIN, ['--port', '0', '--generate-cert', '--config', configPath], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  const port = await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; const p = listeningPort(logs); if (p) resolve(p); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(Object.assign(new Error(`wsh-server exited (${c}): ${logs}`), { logs })));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  return { url: `wss://127.0.0.1:${port}`, port, kp, logs: () => logs };
}

/** A WebSocket that completed the upgrade and has said nothing. `closed` resolves on its close event. */
function silentWebSocket(server) {
  const ws = new WebSocket(server.url);
  closers.push(async () => ws.terminate());
  const state = { open: false, closed: false };
  const opened = new Promise((resolve, reject) => { ws.once('open', () => { state.open = true; resolve(); }); ws.once('error', reject); });
  const closed = new Promise((resolve) => { ws.once('close', () => { state.closed = true; resolve(); }); });
  ws.on('error', () => {});
  return { ws, state, opened, closed };
}

/** A TCP connection that never starts the TLS handshake. `closed` resolves when the server ends it. */
function silentTcp(server) {
  const socket = net.connect(server.port, '127.0.0.1');
  closers.push(async () => socket.destroy());
  const state = { closed: false };
  socket.on('error', () => {});
  const connected = new Promise((resolve) => socket.once('connect', resolve));
  const closed = new Promise((resolve) => { socket.once('close', () => { state.closed = true; resolve(); }); });
  return { socket, state, connected, closed };
}

describe('[server] login_timeout_secs (#248)', () => {
  it('closes a connection that upgrades and never logs in, and one that never finishes the TLS handshake; a client that logs in promptly is untouched', async () => {
    const s = await startServer({ loginTimeoutSecs: 1 });
    // Connected before the silent ones, so the deadline has passed for it by the time they are closed.
    const client = new WshClient();
    closers.push(() => client.disconnect());
    await client.connect(s.url, { username: 'tester', keyPair: s.kp, transport: 'ws', timeout: 8000 });
    const silentWs = silentWebSocket(s);
    const silentTls = silentTcp(s);
    await Promise.all([silentWs.opened, silentTls.connected]);
    await silentWs.closed;
    await silentTls.closed;
    assert.match(s.logs(), /login-timeout/);
    assert.equal(client.state, 'authenticated', 'a login that completed in time is not closed by the deadline');
    const session = await client.openSession({ type: 'exec', command: 'echo still-here' });
    const out = await new Promise((resolve) => { const ch = []; session.onData = (d) => ch.push(d); session.onClose = () => resolve(Buffer.concat(ch).toString()); });
    assert.equal(out.trim(), 'still-here');
  });

  it('login_timeout_secs = 0 turns the deadline off: a silent connection outlives one that the default-off server would have closed', async () => {
    const on = await startServer({ loginTimeoutSecs: 1 });
    const off = await startServer({ loginTimeoutSecs: 0 });
    const keptOpen = silentWebSocket(off); // opened first
    const closedByDeadline = silentWebSocket(on);
    await Promise.all([keptOpen.opened, closedByDeadline.opened]);
    await closedByDeadline.closed; // the event that proves the deadline has passed for the one on the other server too
    assert.equal(keptOpen.state.closed, false);
    assert.doesNotMatch(off.logs(), /login-timeout/);
  });

  it('a value that is not a whole number of seconds is refused at start', async () => {
    await assert.rejects(startServer({ loginTimeoutSecs: -1 }), /login_timeout_secs|invalid|exited/i);
  });
});
