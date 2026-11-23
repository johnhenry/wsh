// test/rust/wsh-cli-forward.test.mjs -- #145: `wsh -L` / `-R` / `-N` (the built Rust CLI) against
//   - a Node host with a unix-socket gateway (`createWshServer({ gateway: { unix } })`), and
//   - a page-shaped host that offers NAMED ENDPOINTS (`createMemoryHost({ endpoints })`),
// reached through the real `createPipeRelay` with `--via`, and through a plain byte pipe (a WebSocket straight to the host).
//
// The "Docker daemon" is a fake HTTP server (here: inside an endpoint, or on a unix socket in a temp directory) answering
// a request made with Node's http over the forwarded local socket: the shape of `DOCKER_HOST=unix://... docker version`,
// without Docker. Nothing touches a real daemon or anything under the user's home: every `wsh` runs with HOME,
// USERPROFILE and XDG_CONFIG_HOME in a scratch directory.
//
// Prerequisite: `cargo build --release -p wsh-cli` (or WSH_BIN).

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import { Duplex } from 'node:stream';
import { mkdtempSync, mkdirSync, rmSync, readFileSync, existsSync, statSync, writeFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocket as WsClient, WebSocketServer } from 'ws';

import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { createWshServer } from '@johnhenry/wsh/server';
import { createMemoryHost } from '@johnhenry/wsh/memory';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const MiB = 1024 * 1024;
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 10_000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
}
const bigBody = () => { const b = Buffer.alloc(20 * MiB); for (let i = 0; i < b.length; i += 4096) b.writeUInt32LE(i, i); return b; };

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

/** A scratch directory short enough for a socket path (resolved, so it matches what realpath says). */
function tmpDir(prefix = 'wcf') {
  const d = realpathSync(mkdtempSync(path.join('/tmp', `${prefix}-`)));
  scratch.push(d);
  return d;
}

/** A scratch $HOME with a fresh `default` identity. */
function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-cli-fwd-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const pub = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  return { home, pub };
}

/** Run `wsh` to completion. */
function wsh(args, { home, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve) => {
    const proc = spawn(WSH_BIN, args, { env: cleanEnv(home), stdio: ['pipe', 'pipe', 'pipe'] });
    const out = []; const err = [];
    proc.stdout.on('data', (d) => out.push(d)); proc.stderr.on('data', (d) => err.push(d));
    proc.stdin.on('error', () => {}); proc.stdin.end();
    const timer = setTimeout(() => proc.kill('SIGKILL'), timeoutMs);
    proc.once('close', (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
}

/** Start a long-running `wsh` (forwarding) and wait until `ready` matched its stderr. */
async function wshBackground(args, { home, env = {}, ready = /forwarding|listening/ }) {
  const proc = spawn(WSH_BIN, args, { env: cleanEnv(home, env), stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(proc);
  let stderr = ''; let stdout = '';
  proc.stderr.on('data', (d) => { stderr += d; }); proc.stdout.on('data', (d) => { stdout += d; });
  proc.stdin.on('error', () => {}); proc.stdin.end();
  const exited = new Promise((resolve) => proc.once('close', (code, signal) => resolve({ code, signal })));
  await Promise.race([
    until(() => ready.test(stderr), `wsh to say ${ready}; stderr: ${stderr}`),
    exited.then((r) => { throw new Error(`wsh exited early (${JSON.stringify(r)}): ${stderr}`); }),
  ]);
  return {
    proc, exited, stderr: () => stderr, stdout: () => stdout,
    /** The port of the n-th "forwarding 127.0.0.1:PORT" line. */
    port: (n = 0) => Number([...stderr.matchAll(/forwarding 127\.0\.0\.1:(\d+) ->/g)][n]?.[1]),
    stop: async (sig = 'SIGINT') => { proc.kill(sig); return Promise.race([exited, sleep(10_000).then(() => { proc.kill('SIGKILL'); return exited; })]); },
  };
}

// ── hosts ────────────────────────────────────────────────────────────

async function startRelay() {
  const relay = createPipeRelay({ rendezvousTimeoutMs: 15_000 });
  const { port } = await relay.listen();
  closers.push(() => relay.close());
  return { relay, url: `ws://127.0.0.1:${port}` };
}

async function dialHost(relayUrl, id, serve) {
  const ws = new WsClient(pipeUrl(relayUrl, id, 'host'));
  ws.on('error', () => {});
  closers.push(async () => ws.terminate());
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  await serve(ws);
  return ws;
}

/** `exec` for the host: `hold` runs until it is signalled (so a `wsh -L ... host hold` stays up), `echo` echoes. */
const exec = async (command, io) => {
  const [word, ...rest] = command.trim().split(/\s+/);
  if (word === 'echo') { await io.write(`${rest.join(' ')}\n`); return 0; }
  if (word === 'hold') {
    return new Promise((resolve) => {
      io.onSignal(async (name) => { await io.write(`signal:${name}\n`); resolve(0); });
      io.signal.addEventListener('abort', () => resolve(143), { once: true });
    });
  }
  await io.write(`unknown: ${command}\n`);
  return 127;
};

const toDuplex = (d) => Duplex.fromWeb({ readable: d.readable, writable: d.writable });

/** The fake daemon: HTTP spoken inside an endpoint's duplex. */
function daemonEndpoints() {
  const server = http.createServer((req, res) => {
    if (req.url === '/version') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ Version: '27.0.0-fake', ApiVersion: '1.46', Os: 'linux' })); return; }
    if (req.url === '/containers/json') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify([{ Id: 'abc123', Names: ['/fake'] }])); return; }
    if (req.url === '/big') { res.end(bigBody()); return; }
    if (req.method === 'POST' && req.url === '/echo') { req.pipe(res); return; }
    res.statusCode = 404; res.end('nope');
  });
  const seen = { opened: 0 };
  const endpoints = {
    docker: (duplex) => { seen.opened += 1; server.emit('connection', toDuplex(duplex)); },
    // Writes as fast as flow control lets it, until the connection ends.
    firehose: async (duplex) => {
      const w = duplex.writable.getWriter();
      const chunk = new Uint8Array(64 * 1024).fill(0x5a);
      let over = false;
      duplex.closed.then(() => { over = true; });
      try { while (!over) await w.write(chunk); } catch { /* closed */ }
    },
    // Never reads: a client that sends past its credit is the client's problem.
    mute: () => {},
    locked: { open: () => {}, authorize: () => false },
  };
  closers.push(async () => { server.closeAllConnections?.(); server.close(); });
  return { endpoints, seen };
}

/** A page-shaped host: no file system, named endpoints only. */
function pageHost(h, { endpoints, ran = [] } = {}) {
  const host = createMemoryHost({ auth: { authorizedKeys: h.pub }, exec: async (c, io) => { ran.push(c); return exec(c, io); }, hostKey: true, dataStreams: false, endpoints });
  closers.push(() => host.close());
  return { ran, serve: (ws) => host.accept(ws) };
}

/** A Node host with a gateway (unix sockets). */
function nodeHost(h, gateway, { ran = [] } = {}) {
  const server = createWshServer({ auth: { authorizedKeys: h.pub }, exec: async (c, io) => { ran.push(c); return exec(c, io); }, hostKey: true, gateway });
  closers.push(() => server.close());
  return { ran, serve: (ws) => server.accept(ws, { dataStreams: false }) };
}

/** `--via` args for a host served through a real pipe relay. */
async function viaRelay(serve) {
  const relay = await startRelay();
  const id = newRendezvousId();
  await dialHost(relay.url, id, serve);
  return ['--via', pipeUrl(relay.url, id)];
}

/** A plain byte pipe: a WebSocket listener handing each socket straight to `serve`. Returns the target URL. */
async function directPipe(serve) {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  wss.on('connection', (ws) => { void serve(ws); });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  return `alice@ws://127.0.0.1:${wss.address().port}`;
}

const httpGet = (opts) => new Promise((resolve, reject) => {
  http.get({ ...opts, agent: false }, (res) => { const cs = []; res.on('data', (c) => cs.push(c)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(cs) })); }).on('error', reject);
});
const rss = (pid) => Number(execFileSync('ps', ['-o', 'rss=', '-p', String(pid)], { encoding: 'utf8' }).trim()) / 1024;

// ── named endpoints (a host with no file system) ─────────────────────

for (const [label, connectArgs] of [
  ['through a real pipe relay (--via)', async (serve) => ({ args: await viaRelay(serve), target: 'alice@tab.example' })],
  ['over a plain byte pipe (ws:// straight to the host)', async (serve) => ({ args: [], target: await directPipe(serve) })],
]) {
  describe(`wsh -L ...:endpoint=NAME against an in-page host, ${label}`, () => {
    it('answers an HTTP request made over the local socket (the shape of `docker version` without Docker); the socket is 0600 and removed on exit', async () => {
      const h = makeHome();
      const { endpoints } = daemonEndpoints();
      const { args, target } = await connectArgs(pageHost(h, { endpoints }).serve);
      const dir = tmpDir();
      const sock = path.join(dir, 'docker.sock');
      const fwd = await wshBackground([...args, '-N', '-L', `${sock}:endpoint=docker`, target], { home: h.home });
      assert.equal(statSync(sock).isSocket(), true);
      assert.equal(statSync(sock).mode & 0o777, 0o600, 'a local socket is private');
      const v = await httpGet({ socketPath: sock, path: '/version' });
      assert.equal(v.status, 200);
      assert.equal(JSON.parse(v.body).Version, '27.0.0-fake');
      assert.equal(JSON.parse((await httpGet({ socketPath: sock, path: '/containers/json' })).body)[0].Id, 'abc123');
      assert.equal((await httpGet({ socketPath: sock, path: '/missing' })).status, 404);
      const r = await fwd.stop();
      assert.equal(r.code, 0, fwd.stderr());
      assert.equal(existsSync(sock), false, 'the socket is unlinked on exit');
    });

    it('moves a large transfer both ways intact (20 MiB down, 12 MiB up), through a local TCP port that binds loopback', async () => {
      const h = makeHome();
      const { endpoints } = daemonEndpoints();
      const { args, target } = await connectArgs(pageHost(h, { endpoints }).serve);
      const fwd = await wshBackground([...args, '-N', '-L', '0:endpoint=docker', target], { home: h.home });
      const port = fwd.port();
      assert.ok(port > 0, fwd.stderr());
      const down = await httpGet({ host: '127.0.0.1', port, path: '/big' });
      assert.equal(down.body.length, 20 * MiB);
      assert.equal(sha(down.body), sha(bigBody()));
      const payload = crypto.randomBytes(12 * MiB);
      const up = await new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, path: '/echo', method: 'POST', agent: false }, (res) => { const cs = []; res.on('data', (c) => cs.push(c)); res.on('end', () => resolve(Buffer.concat(cs))); });
        req.on('error', reject); req.end(payload);
      });
      assert.equal(sha(up), sha(payload));
      await fwd.stop();
    });

    it('a stalled reader holds the host\'s writer back, not memory: the CLI\'s footprint stays flat, and reading resumes the flow', async () => {
      const h = makeHome();
      const { endpoints } = daemonEndpoints();
      const { args, target } = await connectArgs(pageHost(h, { endpoints }).serve);
      const fwd = await wshBackground([...args, '-N', '-L', '0:endpoint=firehose', target], { home: h.home });
      const sock = net.connect(fwd.port(), '127.0.0.1');
      sock.on('error', () => {});
      await new Promise((r) => sock.once('connect', r));
      sock.pause(); // read nothing
      await sleep(700);
      const before = rss(fwd.proc.pid);
      await sleep(3000);
      const growth = rss(fwd.proc.pid) - before;
      assert.ok(growth < 24, `wsh grew by ${growth.toFixed(1)} MiB while the local reader was stalled`);
      let got = 0;
      await new Promise((resolve) => { sock.on('data', (d) => { got += d.length; if (got >= 4 * MiB) resolve(); }); sock.resume(); });
      assert.ok(got >= 4 * MiB);
      sock.destroy();
      await fwd.stop();
    });

    it('says why a connection is refused: an unknown endpoint, and one that refuses this caller', async () => {
      const h = makeHome();
      const { endpoints } = daemonEndpoints();
      const { args, target } = await connectArgs(pageHost(h, { endpoints }).serve);
      const fwd = await wshBackground([...args, '-N', '-L', '0:endpoint=nope', '-L', '0:endpoint=locked', target], { home: h.home });
      for (const n of [0, 1]) {
        const s = net.connect(fwd.port(n), '127.0.0.1'); s.on('error', () => {});
        await new Promise((r) => s.once('close', r)); // the CLI closes the local connection
      }
      await until(() => /no such endpoint/.test(fwd.stderr()) && /refused this caller/.test(fwd.stderr()), `readable refusals in stderr: ${fwd.stderr()}`);
      assert.match(fwd.stderr(), /endpoint nope/);
      assert.match(fwd.stderr(), /policy/);
      await fwd.stop();
    });

    it('with a command: the forwards are up while it runs and the socket goes away when it ends', async () => {
      const h = makeHome();
      const { endpoints } = daemonEndpoints();
      const { args, target } = await connectArgs(pageHost(h, { endpoints }).serve);
      const dir = tmpDir();
      const sock = path.join(dir, 'd.sock');
      const fwd = await wshBackground([...args, '-L', `${sock}:endpoint=docker`, target, 'hold'], { home: h.home });
      assert.equal(JSON.parse((await httpGet({ socketPath: sock, path: '/version' })).body).ApiVersion, '1.46');
      const r = await fwd.stop('SIGTERM'); // forwarded to `hold`, which ends
      assert.equal(r.code, 0, fwd.stderr());
      assert.equal(existsSync(sock), false, 'unlinked when the command ended');
    });
  });
}

describe('wsh -L: what a host that cannot do it says', () => {
  it('an in-page host has no TCP and no unix sockets; the refusal is readable, not a hang', async () => {
    const h = makeHome();
    const { endpoints } = daemonEndpoints();
    const args = await viaRelay(pageHost(h, { endpoints }).serve);
    const fwd = await wshBackground([...args, '-N', '-L', '0:db.internal:5432', '-L', '0:/var/run/docker.sock', 'alice@tab.example'], { home: h.home });
    for (const n of [0, 1]) {
      const s = net.connect(fwd.port(n), '127.0.0.1'); s.on('error', () => {});
      await new Promise((r) => s.once('close', r));
    }
    await until(() => /does not offer TCP forwarding/.test(fwd.stderr()) && /does not offer unix-socket forwarding/.test(fwd.stderr()), `stderr: ${fwd.stderr()}`);
    await fwd.stop();
  });

  it('a host without named endpoints says so', async () => {
    const h = makeHome();
    const dir = tmpDir();
    const args = await viaRelay(nodeHost(h, { allow: [], unix: { connect: [`${dir}/`] } }).serve);
    const fwd = await wshBackground([...args, '-N', '-L', '0:endpoint=docker', 'alice@node.example'], { home: h.home });
    const s = net.connect(fwd.port(), '127.0.0.1'); s.on('error', () => {});
    await new Promise((r) => s.once('close', r));
    await until(() => /does not offer named endpoints/.test(fwd.stderr()), `stderr: ${fwd.stderr()}`);
    await fwd.stop();
  });
});

// ── unix sockets and TCP on a Node host ──────────────────────────────

describe('wsh -L / -R against a Node host with a unix-socket gateway', () => {
  /** A fake docker daemon on a unix socket in `dir`. */
  async function fakeDaemon(dir) {
    const sock = path.join(dir, 'daemon.sock');
    const server = http.createServer((req, res) => {
      if (req.url === '/version') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ Version: '27.0.0-fake' })); return; }
      if (req.url === '/big') { res.end(bigBody()); return; }
      res.statusCode = 404; res.end('nope');
    });
    await new Promise((r) => server.listen(sock, r));
    closers.push(async () => { server.closeAllConnections?.(); server.close(); });
    return sock;
  }

  it('-L /local.sock:/remote.sock, -L 127.0.0.1:PORT:/remote.sock and -L /local.sock:host:port in one invocation', async () => {
    const h = makeHome();
    const dir = tmpDir();
    const daemon = await fakeDaemon(dir);
    // A TCP service on loopback for the third forward (the host reaches it because a rule names it).
    const svc = net.createServer((s) => { s.on('data', (d) => s.write(Buffer.concat([Buffer.from('svc:'), d]))); s.on('error', () => {}); });
    await new Promise((r) => svc.listen(0, '127.0.0.1', r)); closers.push(async () => svc.close());
    const svcPort = svc.address().port;
    const args = await viaRelay(nodeHost(h, { allow: [`127.0.0.1:${svcPort}`], unix: { connect: [daemon] } }).serve);
    const local1 = path.join(dir, 'l1.sock'); const local2 = path.join(dir, 'l2.sock');
    const fwd = await wshBackground([...args, '-N', '-L', `${local1}:${daemon}`, '-L', `127.0.0.1:0:${daemon}`, '-L', `${local2}:127.0.0.1:${svcPort}`, 'alice@node.example'], { home: h.home });
    assert.equal(JSON.parse((await httpGet({ socketPath: local1, path: '/version' })).body).Version, '27.0.0-fake');
    assert.equal(JSON.parse((await httpGet({ host: '127.0.0.1', port: fwd.port(), path: '/version' })).body).Version, '27.0.0-fake');
    const down = await httpGet({ socketPath: local1, path: '/big' });
    assert.equal(sha(down.body), sha(bigBody()));
    const echoed = await new Promise((resolve, reject) => { const s = net.connect(local2); s.on('connect', () => s.write('ping')); s.on('data', (d) => { resolve(d.toString()); s.destroy(); }); s.on('error', reject); });
    assert.equal(echoed, 'svc:ping');
    await fwd.stop();
    assert.equal(existsSync(local1) || existsSync(local2), false, 'both local sockets are gone');
  });

  it('a path the host does not list is refused with the host\'s own reason', async () => {
    const h = makeHome();
    const dir = tmpDir();
    const daemon = await fakeDaemon(dir);
    const args = await viaRelay(nodeHost(h, { allow: [], unix: { connect: [`${dir}/allowed/`] } }).serve);
    const local = path.join(dir, 'l.sock');
    const fwd = await wshBackground([...args, '-N', '-L', `${local}:${daemon}`, 'alice@node.example'], { home: h.home });
    const r = await httpGet({ socketPath: local, path: '/version' }).catch((e) => ({ error: e }));
    assert.ok(r.error || r.status !== 200, 'nothing is served');
    await until(() => /not allowed by the gateway policy/.test(fwd.stderr()), `stderr: ${fwd.stderr()}`);
    await fwd.stop();
  });

  it('-R /remote.sock:127.0.0.1:PORT: the host listens, connections come back here', async () => {
    const h = makeHome();
    const dir = tmpDir();
    const svc = net.createServer((s) => { s.on('data', (d) => s.write(Buffer.concat([Buffer.from('local:'), d]))); s.on('error', () => {}); });
    await new Promise((r) => svc.listen(0, '127.0.0.1', r)); closers.push(async () => svc.close());
    const remote = path.join(dir, 'rev.sock');
    const args = await viaRelay(nodeHost(h, { allow: [], unix: { listen: [`${dir}/`] } }).serve);
    const fwd = await wshBackground([...args, '-N', '-R', `${remote}:127.0.0.1:${svc.address().port}`, 'alice@node.example'], { home: h.home, ready: /host is listening/ });
    assert.equal(statSync(remote).mode & 0o777, 0o600, 'the host made it private');
    const answer = await new Promise((resolve, reject) => { const s = net.connect(remote); s.on('connect', () => s.write('hello')); s.on('data', (d) => { resolve(d.toString()); s.destroy(); }); s.on('error', reject); });
    assert.equal(answer, 'local:hello');
    await fwd.stop();
    await until(() => !existsSync(remote), 'the host removed its socket');
  });

  it('-R is refused readably by a host that does not list the path', async () => {
    const h = makeHome();
    const dir = tmpDir();
    const args = await viaRelay(nodeHost(h, { allow: [], unix: { listen: [`${dir}/ok/`] } }).serve);
    const r = await wsh([...args, '-N', '-R', `${dir}/no.sock:127.0.0.1:9`, 'alice@node.example'], { home: h.home, timeoutMs: 15_000 });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /-R .*no\.sock/);
    assert.match(r.stderr, /not allowed by the gateway policy/);
    assert.equal(existsSync(`${dir}/no.sock`), false);
  });
});

// ── local sockets, and mistakes ──────────────────────────────────────

describe('wsh -L: local sockets and command-line mistakes', () => {
  it('an existing local socket file is refused unless --replace-socket, which replaces only a stale one', async () => {
    const h = makeHome();
    const { endpoints } = daemonEndpoints();
    const dir = tmpDir();
    // A rendezvous serves one connection, so each invocation gets its own.
    // (and its own identity: a new host key under a name already recorded would be refused).
    const fresh = async () => { const x = makeHome(); return { x, args: await viaRelay(pageHost(x, { endpoints }).serve) }; };
    const sock = path.join(dir, 'd.sock');

    // A live socket (some other process listening) is never replaced.
    const live = net.createServer(); await new Promise((r) => live.listen(sock, r)); closers.push(async () => live.close());
    const fa = await fresh();
    const a = await wsh([...fa.args, '-N', '-L', `${sock}:endpoint=docker`, 'alice@tab.example'], { home: fa.x.home });
    assert.notEqual(a.code, 0);
    assert.match(a.stderr, /already exists.*--replace-socket/s);
    const fb = await fresh();
    const b = await wsh([...fb.args, '-N', '--replace-socket', '-L', `${sock}:endpoint=docker`, 'alice@tab.example'], { home: fb.x.home });
    assert.notEqual(b.code, 0);
    assert.match(b.stderr, /in use/);
    live.close(); // closes the listener; the file is removed by node on close

    // A regular file is never touched.
    const file = path.join(dir, 'precious');
    writeFileSync(file, 'keep');
    const fc = await fresh();
    const c = await wsh([...fc.args, '-N', '--replace-socket', '-L', `${file}:endpoint=docker`, 'alice@tab.example'], { home: fc.x.home });
    assert.notEqual(c.code, 0);
    assert.match(c.stderr, /not a socket/);
    assert.equal(readFileSync(file, 'utf8'), 'keep');
  });

  it('a stale socket (nothing listening) is replaced with --replace-socket and the forward works', async () => {
    const h = makeHome();
    const { endpoints } = daemonEndpoints();
    const dir = tmpDir();
    const args = await viaRelay(pageHost(h, { endpoints }).serve);
    const sock = path.join(dir, 's.sock');
    // Leave a socket file behind with nothing listening: a child that listens and is SIGKILLed.
    const child = spawn(process.execPath, ['-e', "require('node:net').createServer().listen(process.argv[1], () => process.kill(process.pid, 'SIGKILL'))", sock], { stdio: 'ignore' });
    await new Promise((r) => child.on('exit', r));
    assert.equal(statSync(sock).isSocket(), true);
    const fwd = await wshBackground([...args, '-N', '--replace-socket', '-L', `${sock}:endpoint=docker`, 'alice@tab.example'], { home: h.home });
    assert.equal(JSON.parse((await httpGet({ socketPath: sock, path: '/version' })).body).Os, 'linux');
    await fwd.stop();
  });

  it('refuses malformed forwards and misplaced flags before connecting anywhere', async () => {
    const h = makeHome();
    const cases = [
      [['-L', 'nope', 'alice@h'], /-L nope.*expected/s],
      [['-L', '8080:db:0', 'alice@h'], /remote port/],
      [['-L', '/x.sock:endpoint=bad name', 'alice@h'], /endpoint name/],
      [['-R', '9000:endpoint=x', 'alice@h'], /cannot listen/],
      [['-N', 'alice@h'], /-N has nothing to do/],
      [['-N', '-L', '8080:db:5432', 'alice@h', 'echo'], /-N takes just the host/],
      [['-L', '8080:db:5432', 'keys'], /apply to/],
      [['-L', '8080:db:5432', 'ls', 'alice@h:/'], /apply to/],
    ];
    for (const [args, re] of cases) {
      const r = await wsh(args, { home: h.home, timeoutMs: 10_000 });
      assert.equal(r.code, 2, `${args.join(' ')} -> ${r.stderr}`);
      assert.match(r.stderr, re, args.join(' '));
    }
  });

  it('a local TCP bind other than loopback is the user\'s explicit choice, and is warned about', async () => {
    const h = makeHome();
    const { endpoints } = daemonEndpoints();
    const args = await viaRelay(pageHost(h, { endpoints }).serve);
    const fwd = await wshBackground([...args, '-N', '-L', '0.0.0.0:0:endpoint=docker', 'alice@tab.example'], { home: h.home, ready: /warning/ });
    assert.match(fwd.stderr(), /other machines can reach/);
    await fwd.stop();
  });
});

// ── Rust CLI <-> Rust server ─────────────────────────────────────────

const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

/** A `wsh-server` with a scratch HOME that authorizes `h`'s key and the given [gateway] config. */
async function startRustServer(h, gatewayToml) {
  const port = await new Promise((resolve) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
  const serverHome = mkdtempSync(path.join(tmpdir(), 'wsh-cli-fwd-server-'));
  scratch.push(serverHome);
  mkdirSync(path.join(serverHome, '.wsh'));
  writeFileSync(path.join(serverHome, '.wsh', 'authorized_keys'), `${h.pub}\n`);
  const config = path.join(serverHome, '.wsh', 'config.toml');
  writeFileSync(config, gatewayToml);
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', config], { env: cleanEnv(serverHome), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  await new Promise((resolve, reject) => {
    let seen = '';
    const onData = (d) => { seen += d; if (seen.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited early (${c}): ${seen}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${seen}`)), 10_000);
  });
  return { port, certFile: path.join(serverHome, '.wsh', 'cert.pem') };
}

describe('wsh -L / -R against the Rust wsh-server (Rust on both ends)', { skip: !existsSync(SERVER_BIN) && `no wsh-server at ${SERVER_BIN}` }, () => {
  it('-L /local.sock:/remote.sock and -L PORT:/remote.sock reach a fake daemon on the host; the large transfer is intact', async () => {
    const h = makeHome();
    const dir = tmpDir();
    const daemon = path.join(dir, 'daemon.sock');
    const server = http.createServer((req, res) => {
      if (req.url === '/version') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ Version: '27.0.0-fake' })); return; }
      if (req.url === '/big') { res.end(bigBody()); return; }
      res.statusCode = 404; res.end('nope');
    });
    await new Promise((r) => server.listen(daemon, r));
    closers.push(async () => { server.closeAllConnections?.(); server.close(); });
    const { port, certFile } = await startRustServer(h, `[gateway]\nenabled = true\nunix_connect = [${JSON.stringify(daemon)}]\n`);
    const local = path.join(dir, 'l.sock');
    const fwd = await wshBackground(['-t', 'ws', '-p', String(port), '-N', '-L', `${local}:${daemon}`, '-L', `0:${daemon}`, 'localhost'], { home: h.home, env: { SSL_CERT_FILE: certFile } });
    assert.equal(JSON.parse((await httpGet({ socketPath: local, path: '/version' })).body).Version, '27.0.0-fake');
    assert.equal(JSON.parse((await httpGet({ host: '127.0.0.1', port: fwd.port(), path: '/version' })).body).Version, '27.0.0-fake');
    assert.equal(sha((await httpGet({ socketPath: local, path: '/big' })).body), sha(bigBody()));
    await fwd.stop();
    assert.equal(existsSync(local), false);
  });

  it('a socket the server does not list is refused with its reason; the server\'s own gateway-unix advertisement is what the client checks', async () => {
    const h = makeHome();
    const dir = tmpDir();
    const { port, certFile } = await startRustServer(h, `[gateway]\nenabled = true\nunix_connect = [${JSON.stringify(`${dir}/ok/`)}]\n`);
    const local = path.join(dir, 'l.sock');
    const fwd = await wshBackground(['-t', 'ws', '-p', String(port), '-N', '-L', `${local}:/etc/passwd`, 'localhost'], { home: h.home, env: { SSL_CERT_FILE: certFile } });
    await httpGet({ socketPath: local, path: '/' }).catch(() => {});
    await until(() => /not allowed by the gateway policy/.test(fwd.stderr()), `stderr: ${fwd.stderr()}`);
    await fwd.stop();
    // A server with no unix sockets configured does not advertise gateway-unix at all.
    const h2 = makeHome();
    const plain = await startRustServer(h2, '[gateway]\nenabled = true\n');
    const fwd2 = await wshBackground(['-t', 'ws', '-p', String(plain.port), '-N', '-L', `${local}:/var/run/docker.sock`, 'localhost'], { home: h2.home, env: { SSL_CERT_FILE: plain.certFile } });
    await httpGet({ socketPath: local, path: '/' }).catch(() => {});
    await until(() => /does not offer unix-socket forwarding/.test(fwd2.stderr()), `stderr: ${fwd2.stderr()}`);
    await fwd2.stop();
  });

  it('-R /remote.sock:127.0.0.1:PORT: the server listens (0600) and connections come back to a local service', async () => {
    const h = makeHome();
    const dir = tmpDir();
    const svc = net.createServer((s) => { s.on('data', (d) => s.write(Buffer.concat([Buffer.from('local:'), d]))); s.on('error', () => {}); });
    await new Promise((r) => svc.listen(0, '127.0.0.1', r)); closers.push(async () => svc.close());
    const remote = path.join(dir, 'rev.sock');
    const { port, certFile } = await startRustServer(h, `[gateway]\nenabled = true\nunix_listen = [${JSON.stringify(`${dir}/`)}]\n`);
    const fwd = await wshBackground(['-t', 'ws', '-p', String(port), '-N', '-R', `${remote}:127.0.0.1:${svc.address().port}`, 'localhost'], { home: h.home, env: { SSL_CERT_FILE: certFile }, ready: /host is listening/ });
    assert.equal(statSync(remote).mode & 0o777, 0o600);
    const answer = await new Promise((resolve, reject) => { const s = net.connect(remote); s.on('connect', () => s.write('hello')); s.on('data', (d) => { resolve(d.toString()); s.destroy(); }); s.on('error', reject); });
    assert.equal(answer, 'local:hello');
    await fwd.stop();
    await until(() => !existsSync(remote), 'the server removed its socket');
  });
});
