// test/rust/wsh-reverse-forward-full-close.test.mjs -- the Rust CLI's `wsh -R`: a local service that answers at length and closes
// COMPLETELY at once, after the caller had already half-closed, delivers the whole answer (the Rust counterpart of
// test/reverse-forward-full-close.test.mjs). Against a Node host and against the Rust `wsh-server`.
//
// The caller connects to the host's unix socket, sends a request, half-closes and reads slowly (so that when the service is long
// gone most of the answer is still queued). The service sends 3 MiB and closes its socket for good in the same breath.
//
// Nothing touches the user's home: every wsh / wsh-server runs with HOME, USERPROFILE and XDG_CONFIG_HOME in a scratch directory.
// Prerequisite: `cargo build --release -p wsh-cli -p wsh-server` (or WSH_BIN and WSH_SERVER_BIN).

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, existsSync, realpathSync } from 'node:fs';
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
const SIZE = 3 * 1024 * 1024;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 10_000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
}

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

const cleanEnv = (home, extra = {}) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm', ...extra });
const scratchDir = (prefix) => { const d = realpathSync(mkdtempSync(path.join('/tmp', `${prefix}-`))); scratch.push(d); return d; };

function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-rffc-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  return { home, pub: readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim() };
}

async function startWsh(args, { home, env = {} }) {
  const proc = spawn(WSH_BIN, ['--accept-new-host-key', ...args], { env: cleanEnv(home, env), stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(proc);
  let stderr = '';
  proc.stderr.on('data', (d) => { stderr += d; });
  proc.stdin.on('error', () => {}); proc.stdin.end();
  const exited = new Promise((resolve) => proc.once('close', (code) => resolve(code)));
  await Promise.race([
    until(() => /host is listening/.test(stderr), `wsh to say the host is listening; stderr: ${stderr}`),
    exited.then((c) => { throw new Error(`wsh exited early (${c}): ${stderr}`); }),
  ]);
  return { proc, stderr: () => stderr };
}

/** A Node host reached over a plain WebSocket, with room to listen on unix sockets under `dir`. */
async function nodeHost(h, dir) {
  const server = createWshServer({ auth: { authorizedKeys: h.pub }, hostKey: true, gateway: { allow: [], unix: { listen: [`${dir}/`] }, halfCloseIdleMs: 0 } });
  closers.push(() => server.close());
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  wss.on('connection', (ws) => { void server.accept(ws, { dataStreams: false }); });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  return { args: [], target: `alice@ws://127.0.0.1:${wss.address().port}`, env: {} };
}

/** The Rust `wsh-server` with a gateway that may listen on unix sockets under `dir`. */
async function rustHost(h, dir) {
  const port = await freePort();
  const serverHome = mkdtempSync(path.join(tmpdir(), 'wsh-rffc-server-'));
  scratch.push(serverHome);
  mkdirSync(path.join(serverHome, '.wsh'));
  writeFileSync(path.join(serverHome, '.wsh', 'authorized_keys'), `${h.pub}\n`);
  const config = path.join(serverHome, '.wsh', 'config.toml');
  writeFileSync(config, `[gateway]\nenabled = true\nunix_listen = [${JSON.stringify(`${dir}/`)}]\nhalf_close_idle_secs = 0\n`);
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', config], { env: cleanEnv(serverHome), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  await new Promise((resolve, reject) => {
    let seen = '';
    const onData = (d) => { seen += d; if (seen.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited early (${c}): ${seen}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${seen}`)), 10_000);
  });
  return { args: ['-t', 'ws', '-p', String(port)], target: 'localhost', env: { SSL_CERT_FILE: path.join(serverHome, '.wsh', 'cert.pem') } };
}

describe('the Rust wsh-server with this repo\'s JS client: the same two shapes', () => {
  const tls = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  before(() => { process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; }); // the dev certificate is self-signed
  after(() => { if (tls === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = tls; });

  async function login(dir, extra = '') {
    const kp = await generateKeyPair(true);
    const home = mkdtempSync(path.join(tmpdir(), 'wsh-rffc-js-'));
    scratch.push(home);
    mkdirSync(path.join(home, '.wsh'));
    writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(kp.publicKey)}\n`);
    const config = path.join(home, '.wsh', 'config.toml');
    writeFileSync(config, `[gateway]\nenabled = true\nallowed_destinations = ["127.0.0.1"]\nunix_listen = [${JSON.stringify(`${dir}/`)}]\nhalf_close_idle_secs = 0\n${extra}`);
    const port = await freePort();
    const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', config], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
    procs.push(proc);
    await new Promise((resolve, reject) => {
      let seen = '';
      const onData = (d) => { seen += d; if (seen.includes('WebSocket TLS listener started')) resolve(); };
      proc.stdout.on('data', onData); proc.stderr.on('data', onData);
      proc.once('exit', (c) => reject(new Error(`wsh-server exited early (${c}): ${seen}`)));
      setTimeout(() => reject(new Error(`wsh-server not ready: ${seen}`)), 10_000);
    });
    const client = new WshClient();
    await client.connect(`wss://127.0.0.1:${port}`, { username: 'tester', keyPair: kp });
    closers.push(() => client.disconnect());
    return client;
  }

  it('a JS reverse forward on the server: the caller half-closed, the service answers at length and closes completely', async () => {
    const dir = scratchDir('rffcj');
    const client = await login(dir);
    // The service reads the whole request before it answers (as in the Node-host tests): one that answers and closes at once is reset by the kernel when the
    // request reaches it, and the reset discards the unread tail of the answer (128000 of 3 MiB here), with no wsh code involved.
    const service = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.once('end', () => s.end(Buffer.alloc(SIZE, 7), () => s.destroy())); s.resume(); });
    await new Promise((r) => service.listen(0, '127.0.0.1', r));
    closers.push(async () => service.close());
    const remote = path.join(dir, 'r.sock');
    const fwd = await client.forwardUnix({ local: `127.0.0.1:${service.address().port}`, remote, reverse: true });
    closers.push(() => fwd.close());
    const caller = net.connect({ path: remote, allowHalfOpen: true });
    caller.on('error', () => {});
    let n = 0;
    const ended = new Promise((r) => caller.once('close', r));
    caller.on('data', (b) => { n += b.length; caller.pause(); setTimeout(() => caller.resume(), 5); });
    caller.end('request');
    const verdict = await Promise.race([ended.then(() => 'ended'), sleep(30_000).then(() => 'still open')]);
    caller.destroy();
    assert.equal(verdict, 'ended', `the caller's stream did not end; it had ${n} of ${SIZE} bytes`);
    assert.equal(n, SIZE);
  });

  it('a TCP origin the server dialled: the client half-closed first, the origin answers at length and closes completely', async () => {
    const dir = scratchDir('rffco');
    const client = await login(dir);
    const origin = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.once('end', () => s.end(Buffer.alloc(SIZE, 5), () => s.destroy())); s.resume(); });
    await new Promise((r) => origin.listen(0, '127.0.0.1', r));
    closers.push(async () => origin.close());
    const d = await client.openTcp('127.0.0.1', origin.address().port);
    await d.writable.getWriter().close();
    const r = d.readable.getReader();
    let n = 0;
    for (;;) { const { value, done } = await r.read(); if (done) break; n += value.length; await sleep(2); }
    assert.equal(n, SIZE);
  });
});

for (const [label, makeHost] of [['a Node host', nodeHost], ['the Rust wsh-server', rustHost]]) {
  describe(`wsh -R against ${label}: a service that answers at length and closes completely, after the caller half-closed`, () => {
    it('every byte arrives at a slow caller', async () => {
      const h = makeHome();
      const dir = scratchDir('rffc');
      const host = await makeHost(h, dir);
      // The service reads the caller's whole request (up to its end of file) before it answers, as a service does. One that answers and closes without
      // reading it is reset by the kernel when the request reaches it, and a reset throws away what the reader has not yet read (so many bytes of the
      // 3 MiB depending on timing: a plain Node client and server lose them too, and no gateway can bring them back). This was the flake of this test.
      const service = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.once('end', () => s.end(Buffer.alloc(SIZE, 7), () => s.destroy())); s.resume(); });
      await new Promise((r) => service.listen(0, '127.0.0.1', r));
      closers.push(async () => service.close());
      const remote = path.join(dir, 'r.sock');
      await startWsh([...host.args, '-N', '-R', `${remote}:127.0.0.1:${service.address().port}`, host.target], { home: h.home, env: host.env });

      const caller = net.connect({ path: remote, allowHalfOpen: true });
      caller.on('error', () => {});
      let n = 0;
      const ended = new Promise((r) => caller.once('close', r));
      caller.on('data', (b) => { n += b.length; caller.pause(); setTimeout(() => caller.resume(), 5); }); // a slow reader
      caller.end('request'); // half-closed from the start
      const verdict = await Promise.race([ended.then(() => 'ended'), sleep(30_000).then(() => 'still open')]);
      caller.destroy();
      assert.equal(verdict, 'ended', `the caller's stream did not end; it had ${n} of ${SIZE} bytes`);
      assert.equal(n, SIZE);
    });

    // #286: with `gateway-lossless-close` stated by both ends (a Rust client states it, both hosts state it) the local service of a `-R` is
    // watched once half-closed. A UNIX service's complete close is a hang-up at once, so the release really happens here, and
    // the caller still gets every byte; a service that half-closed and was killed is noticed, which frees the host's connection.
    it('a unix service that answers at length and closes completely is watched (#286): every byte arrives at a slow caller', async () => {
      const h = makeHome();
      const dir = scratchDir('rffc');
      const host = await makeHost(h, dir);
      const svc = path.join(dir, 'svc.sock');
      const service = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.end(Buffer.alloc(SIZE, 7), () => s.destroy()); });
      await new Promise((r) => service.listen(svc, r));
      closers.push(async () => service.close());
      const remote = path.join(dir, 'ru.sock');
      await startWsh([...host.args, '-N', '-R', `${remote}:${svc}`, host.target], { home: h.home, env: host.env });
      // The caller does NOT half-close. Its `end` comes on the service's FIRST close, with or without any watch, and proves only that the bytes
      // arrived. What proves the service was watched and released is that the host then closes the connection COMPLETELY by itself, with the
      // caller still open: a write from the caller then fails (a mere half-close at the host would leave it succeeding), and the tail the caller
      // had not read when the service vanished is still all there (a discard would have dropped it).
      const caller = net.connect({ path: remote, allowHalfOpen: true });
      caller.on('error', () => {});
      let n = 0;
      const ended = new Promise((r) => caller.once('end', r));
      caller.on('data', (b) => { n += b.length; caller.pause(); setTimeout(() => caller.resume(), 5); });
      caller.write('request');
      const verdict = await Promise.race([ended.then(() => 'ended'), sleep(30_000).then(() => 'still open')]);
      assert.equal(verdict, 'ended', `the caller's stream did not end; it had ${n} of ${SIZE} bytes`);
      assert.equal(n, SIZE);
      await until(() => { if (!caller.destroyed) caller.write('x', () => {}); return caller.destroyed; }, 'the host to close the connection completely');
      caller.destroy();
    });

    it('with --no-half-close-probe-answers the service of a -R is not watched, as before (#286): the same exchange loses nothing either', async () => {
      const h = makeHome();
      const dir = scratchDir('rffc');
      const host = await makeHost(h, dir);
      const svc = path.join(dir, 'svcn.sock');
      const service = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.end(Buffer.alloc(SIZE, 7), () => s.destroy()); });
      await new Promise((r) => service.listen(svc, r));
      closers.push(async () => service.close());
      const remote = path.join(dir, 'rn.sock');
      await startWsh(['--no-half-close-probe-answers', ...host.args, '-N', '-R', `${remote}:${svc}`, host.target], { home: h.home, env: host.env });
      const caller = net.connect({ path: remote, allowHalfOpen: true });
      caller.on('error', () => {});
      let n = 0;
      const ended = new Promise((r) => caller.once('close', r));
      caller.on('data', (b) => { n += b.length; caller.pause(); setTimeout(() => caller.resume(), 5); });
      caller.end('request');
      const verdict = await Promise.race([ended.then(() => 'ended'), sleep(30_000).then(() => 'still open')]);
      caller.destroy();
      assert.equal(verdict, 'ended');
      assert.equal(n, SIZE);
    });
  });
}
