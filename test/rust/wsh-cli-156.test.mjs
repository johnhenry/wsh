// test/rust/wsh-cli-156.test.mjs -- #156, the released Rust CLI driven from an embedder's tests:
//   (a) `wsh -N -L ...` exits when the host drops the session (non-zero, one sentence, local sockets removed);
//   (b) the CLI never prints a rendezvous id (the `/r/<id>` of a `--via` URL is a capability): no stderr/stdout line on any
//       failure path, with or without --verbose, contains it.
//
// Prerequisite: `cargo build --release -p wsh-cli` (or WSH_BIN). Every `wsh` runs with HOME in a scratch directory.

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, existsSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocket as WsClient, WebSocketServer } from 'ws';

import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { createMemoryHost } from '@johnhenry/wsh/memory';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 10_000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
}

const scratch = [];
const closers = [];
const procs = [];

before(() => {
  assert.ok(existsSync(WSH_BIN), `expected the built wsh binary at ${WSH_BIN} (cargo build --release -p wsh-cli, or set WSH_BIN)`);
});

after(async () => {
  for (const p of procs.splice(0)) p.kill('SIGKILL');
  for (const close of closers.splice(0).reverse()) await close().catch(() => {});
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
});

const cleanEnv = (home, extra = {}) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm', ...extra });

function tmpDir() {
  const d = realpathSync(mkdtempSync(path.join('/tmp', 'wsh156-')));
  scratch.push(d);
  return d;
}

function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-cli-156-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const pub = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  return { home, pub };
}

/** Run `wsh` to completion (stdin closed). */
function wsh(args, { home, env = {}, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve) => {
    const proc = spawn(WSH_BIN, ['--accept-new-host-key', ...args], { env: cleanEnv(home, env), stdio: ['pipe', 'pipe', 'pipe'] });
    const out = []; const err = [];
    proc.stdout.on('data', (d) => out.push(d)); proc.stderr.on('data', (d) => err.push(d));
    proc.stdin.on('error', () => {}); proc.stdin.end();
    const timer = setTimeout(() => proc.kill('SIGKILL'), timeoutMs);
    proc.once('close', (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
}

/** A long-running `wsh` (stdin held open, like a terminal). Resolves once `ready` matched stderr. */
async function wshBackground(args, { home, ready = /forwarding|listening/ }) {
  const proc = spawn(WSH_BIN, ['--accept-new-host-key', ...args], { env: cleanEnv(home), stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(proc);
  let stderr = '';
  proc.stderr.on('data', (d) => { stderr += d; });
  proc.stdout.resume();
  proc.stdin.on('error', () => {});
  const exited = new Promise((resolve) => proc.once('close', (code, signal) => resolve({ code, signal, at: Date.now() })));
  await Promise.race([
    until(() => ready.test(stderr), `wsh to say ${ready}; stderr: ${stderr}`),
    exited.then((r) => { throw new Error(`wsh exited early (${JSON.stringify(r)}): ${stderr}`); }),
  ]);
  return { proc, exited, stderr: () => stderr };
}

function pageHost(h) {
  const host = createMemoryHost({
    auth: { authorizedKeys: h.pub }, exec: async () => 0, hostKey: true, dataStreams: false,
    endpoints: { echo: (duplex) => duplex.readable.pipeTo(duplex.writable).catch(() => {}) },
  });
  closers.push(() => host.close());
  return host;
}

async function startRelay(opts = {}) {
  const relay = createPipeRelay({ rendezvousTimeoutMs: 15_000, ...opts });
  const { port } = await relay.listen();
  closers.push(() => relay.close());
  return { relay, url: `ws://127.0.0.1:${port}` };
}

async function dialHost(relayUrl, id, host) {
  const ws = new WsClient(pipeUrl(relayUrl, id, 'host'));
  ws.on('error', () => {});
  closers.push(async () => ws.terminate());
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  await host.accept(ws);
  return ws;
}

/** A plain byte pipe: a WebSocket listener; the sockets it accepted are kept so a test can drop them. */
async function directPipe(host) {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  wss.on('connection', (ws) => { void host.accept(ws); });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  return { target: `alice@ws://127.0.0.1:${wss.address().port}`, wss };
}

// ── (a) the host goes away ────────────────────────────────────────────

describe('wsh -N -L exits when the host drops the session (#156 a)', () => {
  const modes = [
    ['the host closes the socket cleanly', (ws) => ws.close(1000, 'bye')],
    ['the host dies (the socket is torn down)', (ws) => ws.terminate()],
  ];
  const routes = [
    ['--via a pipe relay', async (host) => {
      const relay = await startRelay();
      const id = newRendezvousId();
      const ws = await dialHost(relay.url, id, host);
      return { args: ['--via', pipeUrl(relay.url, id)], target: 'alice@tab.example', dropAll: (how) => how(ws) };
    }],
    ['a direct ws:// connection', async (host) => {
      const { target, wss } = await directPipe(host);
      return { args: [], target, dropAll: (how) => { for (const c of wss.clients) how(c); } };
    }],
  ];
  for (const [routeName, route] of routes) {
    for (const [modeName, how] of modes) {
      it(`${routeName}: ${modeName}`, async () => {
        const h = makeHome();
        const r = await route(pageHost(h));
        const sock = path.join(tmpDir(), 'echo.sock');
        const fwd = await wshBackground([...r.args, '-N', '-L', `${sock}:endpoint=echo`, '-L', '0:endpoint=echo', r.target], { home: h.home });
        assert.equal(existsSync(sock), true, 'the local socket is up');
        const t0 = Date.now();
        r.dropAll(how);
        const exit = await Promise.race([fwd.exited, sleep(8_000).then(() => 'timeout')]);
        assert.notEqual(exit, 'timeout', `wsh still running 8 s after the host dropped the session; stderr: ${fwd.stderr()}`);
        assert.ok(exit.at - t0 < 6_000, `exit took ${exit.at - t0} ms`);
        assert.notEqual(exit.code, 0, 'non-zero: the session did not end by the operator’s choice');
        assert.equal(existsSync(sock), false, 'the local socket is removed');
        const last = fwd.stderr().trim().split('\n').pop();
        assert.match(last, /connection to the host was lost/, fwd.stderr());
      });
    }
  }
});

// ── (b) the rendezvous id is never printed ────────────────────────────

describe('the rendezvous id of a --via URL is never printed (#156 b)', () => {
  const dials = [
    ['a relay that is not there', async () => ({ relayUrl: 'ws://127.0.0.1:9' })],
    ['a relay where no host ever dials in (rendezvous timeout)', async () => ({ relayUrl: (await startRelay({ rendezvousTimeoutMs: 1_500 })).url })],
    ['a host that refuses this key', async () => {
      const relay = await startRelay();
      return { relayUrl: relay.url, serve: (id) => dialHost(relay.url, id, pageHost(makeHome())) };
    }],
    ['a relay that answers with something that is not a wsh host', async () => {
      const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
      await new Promise((r) => wss.once('listening', r));
      wss.on('connection', (ws) => { ws.send('hello'); setTimeout(() => ws.close(), 100); });
      closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
      return { relayUrl: `ws://127.0.0.1:${wss.address().port}` };
    }],
  ];
  const commands = [
    ['exec', (target) => [target, 'echo', 'x']],
    ['connect', (target) => ['connect', target]],
    ['ls', (target) => ['ls', target, '/']],
    ['copy-id', (target) => ['copy-id', target]],
    ['-N -L', (target) => ['-N', '-L', '0:endpoint=echo', target]],
  ];
  for (const [dialName, dial] of dials) {
    it(`${dialName}: nothing the CLI prints contains the id, with and without --verbose`, async () => {
      const h = makeHome();
      const d = await dial();
      let checked = 0;
      for (const verbose of [false, true]) {
        for (const [cmdName, build] of commands) {
          const id = newRendezvousId();
          if (d.serve) await d.serve(id);
          const r = await wsh([...(verbose ? ['--verbose'] : []), '--via', pipeUrl(d.relayUrl, id), ...build('alice@tab.example')], { home: h.home, timeoutMs: 15_000 });
          const all = `${r.stdout}\n${r.stderr}`;
          assert.doesNotMatch(all, new RegExp(id), `${cmdName}${verbose ? ' --verbose' : ''} printed the rendezvous id:\n${all}`);
          assert.notEqual(r.code, 0, `${cmdName}: expected a failure\n${all}`);
          checked += 1;
        }
      }
      assert.equal(checked, 2 * commands.length);
    });
  }

  it('the URL as the target (no --via) is redacted too, and the relay host is still shown', async () => {
    const h = makeHome();
    const id = newRendezvousId();
    const r = await wsh(['--verbose', `alice@${pipeUrl('ws://127.0.0.1:9', id)}`, 'echo', 'x'], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.doesNotMatch(`${r.stdout}${r.stderr}`, new RegExp(id));
    assert.match(r.stderr, /127\.0\.0\.1:9/, 'the relay host is named');
  });

  it('a short form of the id (its first characters and an ellipsis) is shown, never the whole of it', async () => {
    const h = makeHome();
    const id = newRendezvousId();
    const r = await wsh(['--via', pipeUrl('ws://127.0.0.1:9', id), 'alice@tab.example', 'echo', 'x'], { home: h.home });
    assert.match(r.stderr, new RegExp(`/r/${id.slice(0, 4)}\\.\\.\\.`), r.stderr);
  });

  it('a successful session does not print it either', async () => {
    const h = makeHome();
    const relay = await startRelay();
    const id = newRendezvousId();
    await dialHost(relay.url, id, pageHost(h));
    const r = await wsh(['--verbose', '--via', pipeUrl(relay.url, id), 'alice@tab.example', 'ls', '/'], { home: h.home });
    assert.doesNotMatch(`${r.stdout}${r.stderr}`, new RegExp(id));
  });
});
