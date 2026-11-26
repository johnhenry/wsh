// test/rust/wsh-half-close-probe.test.mjs -- #282: a local peer that half-closed and was then killed is noticed by the Rust
// implementation too, with the far side silent and the idle bound off, and the existing "discarded" close tells the other end.
//
//   - the Rust `wsh -L` (a local unix socket and a local TCP port) forwarding to a named endpoint of a Node host: a child
//     process connects, half-closes and is SIGKILLed by pid; the endpoint's stream must end as "discarded" by itself.
//   - the Rust `wsh-server`: a CALLER of its reverse listener (a unix socket and a TCP port) that half-closed and is SIGKILLed;
//     the JS client's connection must end as "discarded" by itself. An ORIGIN the server dialled is deliberately not watched: one
//     that sent everything and closed completely is the normal end of a response and must not cut the client's reading short.
//
// The measured detection times are printed. A unix peer is noticed at once (the kernel's hang-up). A TCP peer that exits
// with nothing unread leaves a socket its kernel keeps for about a minute (60 s by default on Linux and macOS) and is
// noticed then (the Node file covers that minute); one killed with data unread is reset, and noticed at once. Bounds below are
// generous for a loaded runner.
//
// Nothing touches the user's home: every wsh / wsh-server runs with HOME, USERPROFILE and XDG_CONFIG_HOME in a scratch directory.
// Prerequisite: `cargo build --release -p wsh-cli -p wsh-server` (or WSH_BIN and WSH_SERVER_BIN).

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync, mkdirSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';

import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '../../src/index.mjs';
import { freePort } from '../helpers/free-port.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const CHILD = path.join(REPO_ROOT, 'test', 'half-close-probe-child.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 10_000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
}
const stateAfter = (closed, ms) => Promise.race([closed, sleep(ms).then(() => 'open')]);
// A loaded runner can stall a process for seconds; the expected time is a fraction of a second. Only so a regression fails by name.
const BOUND_MS = 30_000;

const scratch = [];
const closers = [];
const procs = [];

before(() => {
  assert.ok(existsSync(WSH_BIN), `expected the built wsh binary at ${WSH_BIN} (cargo build --release -p wsh-cli, or WSH_BIN)`);
  assert.ok(existsSync(SERVER_BIN), `expected the built wsh-server binary at ${SERVER_BIN} (cargo build --release -p wsh-server, or WSH_SERVER_BIN)`);
});
after(async () => {
  for (const p of procs.splice(0)) p.kill('SIGKILL');
  for (const close of closers.splice(0).reverse()) await close().catch(() => {});
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
});

const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm' });
const scratchDir = (prefix) => { const d = realpathSync(mkdtempSync(path.join('/tmp', `${prefix}-`))); scratch.push(d); return d; };

/** A child process of the test (test/half-close-probe-child.mjs); resolves once it printed a line containing `until`. */
async function startChild(args, until) {
  const child = spawn(process.execPath, [CHILD, ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
  procs.push(child);
  const lines = [];
  let buf = '';
  await new Promise((resolve, reject) => {
    child.stdout.on('data', (d) => {
      buf += d;
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1); }
      if (lines.some((l) => l.includes(until))) resolve();
    });
    child.once('exit', () => reject(new Error(`the child exited early (${lines.join(' | ')})`)));
  });
  child.removeAllListeners('exit');
  return { child, lines };
}
const kill = (child) => new Promise((r) => { child.once('exit', r); child.kill('SIGKILL'); });
async function handUnread(duplex) {
  // More than a Node process takes into its own buffers unasked, so some is left unread in the kernel (see test/half-close-probe.test.mjs).
  const w = duplex.writable.getWriter();
  await Promise.race([w.write(new Uint8Array(300_000)).catch(() => {}), sleep(3000)]);
}

// ── the Rust CLI's -L ────────────────────────────────────────────────

function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-hcp-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  return { home, pub: readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim() };
}

/** A Node host whose named endpoint "quiet" never says anything; each stream is recorded. Returns the `ws://` target. */
async function quietHost(h) {
  const seen = [];
  const server = createWshServer({
    auth: { authorizedKeys: h.pub }, hostKey: true,
    gateway: { allow: [], tcp: false, halfCloseIdleMs: 0, endpoints: { quiet: (d) => { seen.push(d); } } },
  });
  closers.push(() => server.close());
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  wss.on('connection', (ws) => { void server.accept(ws, { dataStreams: false }); });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  return { seen, target: `alice@ws://127.0.0.1:${wss.address().port}` };
}

async function wshForward(args, { home, ready = /forwarding|listening/ }) {
  const proc = spawn(WSH_BIN, ['--accept-new-host-key', ...args], { env: cleanEnv(home), stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(proc);
  let stderr = '';
  proc.stderr.on('data', (d) => { stderr += d; });
  proc.stdin.on('error', () => {}); proc.stdin.end();
  const exited = new Promise((resolve) => proc.once('close', (code, signal) => resolve({ code, signal })));
  await Promise.race([
    until(() => ready.test(stderr), `wsh to say ${ready}; stderr: ${stderr}`),
    exited.then((r) => { throw new Error(`wsh exited early (${JSON.stringify(r)}): ${stderr}`); }),
  ]);
  return { proc, port: () => Number([...stderr.matchAll(/forwarding 127\.0\.0\.1:(\d+) ->/g)][0]?.[1]), stderr: () => stderr };
}

describe('the Rust wsh -L: a local program that half-closed and was killed is noticed with the far side silent', () => {
  it('a local unix socket: the endpoint stream ends as "discarded" by itself', async (t) => {
    const h = makeHome();
    const { seen, target } = await quietHost(h);
    const sock = path.join(scratchDir('hcu'), 'e.sock');
    await wshForward(['-N', '-L', `${sock}:endpoint=quiet`, target], { home: h.home });
    const { child } = await startChild(['client', 'unix', sock], 'half-closed');
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    assert.equal(await stateAfter(seen[0].closed, 1500), 'open', 'a live half-closed peer is held (the idle bound is off)');
    const t0 = Date.now();
    await kill(child);
    const state = await stateAfter(seen[0].closed, BOUND_MS);
    t.diagnostic(`wsh -L unix: ended as ${JSON.stringify(state)} ${Date.now() - t0} ms after the kill`);
    assert.equal(state, 'discarded');
  });

  it('a local TCP port, peer killed with data unread (reset): noticed at once', async (t) => {
    const h = makeHome();
    const { seen, target } = await quietHost(h);
    const fwd = await wshForward(['-N', '-L', '0:endpoint=quiet', target], { home: h.home });
    const { child } = await startChild(['client', 'tcp', String(fwd.port()), 'paused'], 'half-closed');
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    await handUnread(seen[0]);
    const t0 = Date.now();
    await kill(child);
    const state = await stateAfter(seen[0].closed, BOUND_MS);
    t.diagnostic(`wsh -L tcp, unread data: ended as ${JSON.stringify(state)} ${Date.now() - t0} ms after the kill`);
    assert.equal(state, 'discarded');
  });

  it('a half-closed peer that is alive and reading for several keep-alive intervals is not cut, and gets the answer whole', async () => {
    const h = makeHome();
    const { seen, target } = await quietHost(h);
    const fwd = await wshForward(['-N', '-L', '0:endpoint=quiet', target], { home: h.home });
    const { lines } = await startChild(['client', 'tcp', String(fwd.port())], 'half-closed');
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    await sleep(7000); // three of the CLI's two-second keep-alive intervals, with the far side silent
    assert.equal(await stateAfter(seen[0].closed, 0), 'open');
    const w = seen[0].writable.getWriter();
    await w.write(new Uint8Array(500_000).fill(3));
    await w.close();
    await until(() => lines.includes('got 500000') && lines.includes('end'), 'the whole answer and the end');
  });
});

// ── the Rust wsh-server's origins ────────────────────────────────────

async function startServer(config) {
  const kp = await generateKeyPair(true);
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-hcps-'));
  scratch.push(home);
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(kp.publicKey)}\n`);
  const configPath = path.join(home, '.wsh', 'config.toml');
  writeFileSync(configPath, config);
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', configPath], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  const client = new WshClient();
  await client.connect(`wss://127.0.0.1:${port}`, { username: 'tester', keyPair: kp });
  closers.push(() => client.disconnect());
  return { client };
}

describe('the Rust wsh-server: a caller that finished sending and was killed is noticed with the client silent; an origin that finished and closed is not discarded', () => {
  const tls = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  before(() => { process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; }); // the dev certificate is self-signed
  after(() => { if (tls === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = tls; });

  const callerConfig = (dir, extra = '') => `[gateway]\nenabled = true\nallowed_destinations = []\nunix_listen = [${JSON.stringify(`${dir}/`)}]\nhalf_close_idle_secs = 0\n${extra}`;

  it('a CALLER of the server\'s reverse unix listener that half-closed and was killed: the client\'s connection ends as "discarded"', async (t) => {
    const dir = scratchDir('hcl');
    const hostSock = path.join(dir, 'l.sock');
    const { client } = await startServer(callerConfig(dir));
    const seen = [];
    await client.listenUnix(hostSock, { onConnection: (duplex) => { seen.push(duplex); } });
    const { child } = await startChild(['client', 'unix', hostSock], 'half-closed');
    await until(() => seen.length === 1, 'the client to be handed the caller');
    assert.equal(await stateAfter(seen[0].closed, 1500), 'open', 'held while the caller is alive');
    const t0 = Date.now();
    await kill(child);
    const state = await stateAfter(seen[0].closed, BOUND_MS);
    t.diagnostic(`wsh-server unix caller: ended as ${JSON.stringify(state)} ${Date.now() - t0} ms after the kill`);
    assert.equal(state, 'discarded');
  });

  it('a TCP caller of a reverse listener reset after half-closing is noticed at once', async (t) => {
    const { client } = await startServer(`[gateway]\nenabled = true\nallowed_destinations = ["*"]\nenable_reverse_tunnels = true\nhalf_close_idle_secs = 0\n`);
    const seen = [];
    const l = await client.listenTcp(0, { onConnection: (duplex) => { seen.push(duplex); } });
    const { child } = await startChild(['client', 'tcp', String(l.port), 'paused'], 'half-closed');
    await until(() => seen.length === 1, 'the client to be handed the caller');
    await handUnread(seen[0]);
    const t0 = Date.now();
    await kill(child);
    const state = await stateAfter(seen[0].closed, BOUND_MS);
    t.diagnostic(`wsh-server tcp caller, unread data: ended as ${JSON.stringify(state)} ${Date.now() - t0} ms after the kill`);
    assert.equal(state, 'discarded');
  });

  it('with half_close_probe_secs = 0 the watch is off: a killed caller is not noticed by itself', async () => {
    const dir = scratchDir('hco');
    const hostSock = path.join(dir, 'l.sock');
    const { client } = await startServer(callerConfig(dir, 'half_close_probe_secs = 0\n'));
    const seen = [];
    await client.listenUnix(hostSock, { onConnection: (duplex) => { seen.push(duplex); } });
    const { child } = await startChild(['client', 'unix', hostSock], 'half-closed');
    await until(() => seen.length === 1, 'the client to be handed the caller');
    await kill(child);
    // Nothing can notice it; this bounds how long we look.
    assert.equal(await stateAfter(seen[0].closed, 2000), 'open');
  });

  // An ORIGIN the server dialled is not watched: one that sent its whole answer and closed completely is the normal end of a response,
  // and the client may still be reading it (the discard a watch would send drops what it has received and not yet read).
  it('a unix origin that sent everything and closed completely is not discarded: a slow client still gets all of it', async () => {
    const dir = scratchDir('hcs');
    const sock = path.join(dir, 'o.sock');
    const SIZE = 3 * 1024 * 1024;
    const origin = net.createServer((s) => { s.on('error', () => {}); s.end(Buffer.alloc(SIZE, 5), () => s.destroy()); });
    await new Promise((r) => origin.listen(sock, r));
    closers.push(async () => origin.close());
    const { client } = await startServer(`[gateway]\nenabled = true\nallowed_destinations = []\nunix_connect = ["${sock}"]\nhalf_close_idle_secs = 0\n`);
    const d = await client.openUnix(sock);
    await sleep(1000); // the origin is long gone; what it sent is mostly unread
    assert.equal(await stateAfter(d.closed, 0), 'open', 'held for the reader');
    const r = d.readable.getReader();
    let n = 0;
    for (;;) { const { value, done } = await r.read(); if (done) break; n += value.length; await sleep(10); } // a slow reader
    assert.equal(n, SIZE);
    await d.writable.getWriter().close();
    assert.notEqual(await d.closed, 'discarded');
  });
});

void net;
