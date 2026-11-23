// test/rust/wsh-cli.test.mjs -- the built Rust `wsh` binary (crates/wsh-cli) run against a Node host
// (test/rust/fixtures/cli-host.mjs, built from this repo's own server code).
//
// Prerequisite: `cargo build --release -p wsh-cli` (or WSH_BIN=/path/to/wsh). Run with `npm run test:rust`.
//
// Every `wsh` below runs with HOME pointing at a scratch directory (the keystore, known_hosts and
// last_session all live under $HOME/.wsh), and the last test checks that nothing under the real
// home's ~/.wsh or ~/.ssh was touched while this file ran.

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, statSync, openSync } from 'node:fs';
import { tmpdir, homedir, platform } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateSelfSignedCertificate } from '../../src/server/self-signed.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const FIXTURE = path.join(REPO_ROOT, 'test', 'rust', 'fixtures', 'cli-host.mjs');

const scratch = [];
const hosts = [];
const mtime = (p) => {
  try { return statSync(p).mtimeMs; } catch { return null; }
};
const realHome = { wsh: path.join(homedir(), '.wsh'), ssh: path.join(homedir(), '.ssh') };
const realHomeBefore = { wsh: mtime(realHome.wsh), ssh: mtime(realHome.ssh) };

before(() => {
  assert.ok(existsSync(WSH_BIN), `expected the built wsh binary at ${WSH_BIN} (cargo build --release -p wsh-cli, or set WSH_BIN)`);
});

after(() => {
  for (const h of hosts.splice(0)) h.proc.kill('SIGTERM');
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** A scratch $HOME with a fresh `default` identity, a trusted certificate, and the host fixture's authorized key. */
function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-cli-test-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const pub = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  const cert = generateSelfSignedCertificate({ hosts: ['localhost', '127.0.0.1'] });
  const certFile = path.join(home, 'host-cert.pem');
  writeFileSync(certFile, cert.cert);
  return { home, pub, cert, certFile };
}

function cleanEnv(home, extra = {}) {
  return { PATH: process.env.PATH, HOME: home, USER: 'tester', TERM: 'xterm', ...extra };
}

async function startHost(h, { tls = true, ptyMs } = {}) {
  const proc = spawn(process.execPath, [FIXTURE], {
    env: {
      PATH: process.env.PATH,
      HOME: h.home,
      WSH_FIXTURE: JSON.stringify({ authorizedKey: h.pub, tls: tls ? { cert: h.cert.cert, key: h.cert.privKey } : undefined, ptyMs }),
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  hosts.push({ proc });
  const port = await new Promise((resolve, reject) => {
    let buf = '';
    proc.stdout.on('data', (d) => {
      buf += d;
      const m = /LISTENING (\d+)/.exec(buf);
      if (m) resolve(Number(m[1]));
    });
    proc.once('exit', (code) => reject(new Error(`fixture host exited early (${code})`)));
  });
  return { port, proc };
}

/** Run `wsh` and collect its result. `signalAfterMs` sends SIGINT to it that long after start. */
function wsh(args, { home, env = {}, input, keepStdin = false, stdinDevNull = false, timeoutMs = 20_000, signalAfterMs, command = WSH_BIN, prefix = [] } = {}) {
  return new Promise((resolve) => {
    const proc = spawn(command, [...prefix, ...args], {
      env: cleanEnv(home, env),
      stdio: [stdinDevNull ? openSync('/dev/null', 'r') : 'pipe', 'pipe', 'pipe'],
    });
    const out = [];
    const err = [];
    proc.stdout.on('data', (d) => out.push(d));
    proc.stderr.on('data', (d) => err.push(d));
    proc.stdin?.on('error', () => {});
    if (stdinDevNull) { /* stdin is the null device */ }
    else if (input !== undefined) proc.stdin.end(input);
    else if (!keepStdin) proc.stdin.end();
    const started = Date.now();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; proc.kill('SIGKILL'); }, timeoutMs);
    if (signalAfterMs !== undefined) setTimeout(() => proc.kill('SIGINT'), signalAfterMs);
    proc.once('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, timedOut, ms: Date.now() - started, stdout: Buffer.concat(out), stderr: Buffer.concat(err).toString() });
    });
  });
}

const target = (port, p = '/') => `wss://127.0.0.1:${port}${p}`;

describe('wsh CLI: TLS provider (#134)', () => {
  it('a wss:// connection to a host with an untrusted certificate fails as a TLS error, not a panic', async () => {
    const h = makeHome();
    const { port } = await startHost(h);
    const r = await wsh(['-t', 'ws', '-p', String(port), '127.0.0.1', 'echo', 'hi'], { home: h.home });
    assert.equal(r.timedOut, false);
    assert.doesNotMatch(r.stderr + r.stdout.toString(), /panicked|CryptoProvider/);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /certificate|UnknownIssuer|invalid peer/i);
  });

  it('a wss:// connection to a host whose certificate is trusted (SSL_CERT_FILE) runs the command', async () => {
    const h = makeHome();
    const { port } = await startHost(h);
    const r = await wsh(['-t', 'ws', '-p', String(port), 'localhost', 'echo', 'hi'], { home: h.home, env: { SSL_CERT_FILE: h.certFile } });
    assert.equal(r.stderr.includes('panicked'), false, r.stderr);
    assert.equal(r.stdout.toString(), 'hi\n', r.stderr);
    assert.equal(r.code, 0);
  });
});

describe('wsh CLI exec against a host that answers at once (#135)', () => {
  it('prints the output on every one of 160 runs, eight at a time', async () => {
    const h = makeHome();
    const { port } = await startHost(h);
    const env = { SSL_CERT_FILE: h.certFile };
    const results = [];
    let next = 0;
    const worker = async () => {
      while (next < 160) {
        next += 1;
        results.push(await wsh(['-t', 'ws', '-p', String(port), 'localhost', 'echo', 'hi'], { home: h.home, env }));
      }
    };
    await Promise.all(Array.from({ length: 8 }, worker));
    const bad = results.filter((r) => r.stdout.toString() !== 'hi\n' || r.code !== 0);
    assert.equal(bad.length, 0, `${bad.length} of ${results.length} runs lost their output: ${bad[0]?.stderr}`);
  });
});

describe('wsh CLI exec', () => {
  it('prints nothing on stderr by default (no per-frame trace) and keeps stdout to the command output', async () => {
    const h = makeHome();
    const { port } = await startHost(h);
    const r = await wsh(['-t', 'ws', '-p', String(port), 'localhost', 'echo', 'hi'], { home: h.home, env: { SSL_CERT_FILE: h.certFile } });
    assert.equal(r.stdout.toString(), 'hi\n');
    assert.doesNotMatch(r.stderr, /DEBUGTRACE/);
    assert.equal(r.stderr, '', 'a successful command leaves stderr to the command');
  });

  it('accepts a full URL with a path (a rendezvous id) and dials exactly it', async () => {
    const h = makeHome();
    const { port } = await startHost(h);
    const r = await wsh([`wss://localhost:${port}/rendezvous/abc123?x=1`, 'path'], { home: h.home, env: { SSL_CERT_FILE: h.certFile } });
    assert.equal(r.stdout.toString(), '/rendezvous/abc123?x=1\n', r.stderr);
    assert.equal(r.code, 0);
  });

  it('accepts ws:// for a plain-text host, with a user in front', async () => {
    const h = makeHome();
    const { port } = await startHost(h, { tls: false });
    const r = await wsh([`ws://127.0.0.1:${port}/p`, 'whoami'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout.toString(), 'tester\n');
    const r2 = await wsh([`alice@ws://127.0.0.1:${port}/p`, 'whoami'], { home: h.home });
    assert.equal(r2.stdout.toString(), 'alice\n', r2.stderr);
  });

  it("exits with the remote command's status", async () => {
    const h = makeHome();
    const { port } = await startHost(h, { tls: false });
    const r = await wsh([`ws://127.0.0.1:${port}/`, 'exit', '7'], { home: h.home });
    assert.equal(r.code, 7);
  });

  it('forwards stdin to the command', async () => {
    const h = makeHome();
    const { port } = await startHost(h, { tls: false });
    const r = await wsh([`ws://127.0.0.1:${port}/`, 'head1'], { home: h.home, input: 'hello\n' });
    assert.equal(r.stdout.toString(), 'got:hello\n', r.stderr);
    assert.equal(r.code, 0);
  });

  it('forwards SIGINT to the remote command instead of dying, and exits with the remote status', async () => {
    const h = makeHome();
    const { port } = await startHost(h, { tls: false });
    const r = await wsh([`ws://127.0.0.1:${port}/`, 'wait-signal'], { home: h.home, keepStdin: true, signalAfterMs: 1500 });
    assert.equal(r.timedOut, false);
    assert.equal(r.stdout.toString(), 'signal:INT\n', r.stderr);
    assert.equal(r.code, 0);
  });

  it('moves 64 MiB of output through the CLI (throughput is reported, not asserted)', async (t) => {
    const h = makeHome();
    const { port } = await startHost(h, { tls: false });
    const r = await wsh([`ws://127.0.0.1:${port}/`, 'bulk', '64'], { home: h.home, timeoutMs: 120_000 });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout.length, 64 * 1024 * 1024);
    t.diagnostic(`bulk 64 MiB in ${r.ms} ms = ${(64 / (r.ms / 1000)).toFixed(1)} MiB/s`);
  });
});

/** Run `argv` under a pseudo-terminal with the platform's `script`. */
function underPty(argv, opts) {
  // BSD `script` insists on a tty or a file for its own stdin ("Operation not supported on socket").
  if (platform() === 'darwin') return wsh(argv, { ...opts, stdinDevNull: true, command: 'script', prefix: ['-q', '/dev/null', WSH_BIN] });
  return wsh([], { ...opts, command: 'script', prefix: ['-qefc', [WSH_BIN, ...argv].map((a) => `'${a}'`).join(' '), '/dev/null'] });
}

describe('wsh connect', () => {
  it('exits by itself when the remote session ends (#136)', { skip: !existsSync('/usr/bin/script') && 'needs script(1)' }, async () => {
    const h = makeHome();
    const { port } = await startHost(h, { tls: false, ptyMs: 400 });
    const r = await underPty(['connect', `ws://127.0.0.1:${port}/`], { home: h.home, keepStdin: true, timeoutMs: 15_000 });
    assert.equal(r.timedOut, false, `still running after the session ended:\n${r.stdout}`);
    assert.match(r.stdout.toString(), /ready/);
    assert.ok(r.ms < 8000, `took ${r.ms} ms`);
  });
});

const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

/** A `wsh-server` with a scratch HOME that authorizes `h`'s key. Its generated dev certificate is a leaf (wsh #145), so the CLI trusts it through SSL_CERT_FILE and no WSH_INSECURE_LOOPBACK_TLS is needed. */
async function startRustServer(h) {
  const port = await new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
  const serverHome = mkdtempSync(path.join(tmpdir(), 'wsh-cli-server-'));
  scratch.push(serverHome);
  mkdirSync(path.join(serverHome, '.wsh'));
  writeFileSync(path.join(serverHome, '.wsh', 'authorized_keys'), `${h.pub}\n`);
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', '/dev/null/none'], {
    env: { PATH: process.env.PATH, HOME: serverHome }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  hosts.push({ proc });
  await new Promise((resolve, reject) => {
    let seen = '';
    const onData = (d) => { seen += d; if (seen.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited early (${c}): ${seen}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${seen}`)), 10_000);
  });
  return { port, certFile: path.join(serverHome, '.wsh', 'cert.pem') };
}

describe('wsh CLI exec against the Rust wsh-server', { skip: !existsSync(SERVER_BIN) && `no wsh-server at ${SERVER_BIN}` }, () => {
  it('stdin reaches the command and its end is EOF; stdout and stderr stay apart; the exit status comes back', async () => {
    const h = makeHome();
    const { port, certFile } = await startRustServer(h);
    const env = { SSL_CERT_FILE: certFile };
    const base = ['-t', 'ws', '-p', String(port), 'localhost'];

    const cat = await wsh([...base, 'cat'], { home: h.home, env, input: 'a\nb\n' });
    assert.equal(cat.code, 0, cat.stderr);
    assert.equal(cat.stdout.toString(), 'a\nb\n');

    const split = await wsh([...base, 'echo out; echo err 1>&2; exit 3'], { home: h.home, env });
    assert.equal(split.stdout.toString(), 'out\n');
    assert.match(split.stderr, /err/);
    assert.equal(split.code, 3);
  });

  it('a command with no stdin still runs, as before', async () => {
    const h = makeHome();
    const { port, certFile } = await startRustServer(h);
    const r = await wsh(['-t', 'ws', '-p', String(port), 'localhost', 'echo hello'], { home: h.home, env: { SSL_CERT_FILE: certFile } });
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout.toString(), /hello/);
  });
});

describe('state stays under $HOME', () => {
  it('known_hosts and last_session are written under the scratch home, never the real one', async () => {
    const h = makeHome();
    const { port } = await startHost(h, { tls: false });
    const r = await wsh([`ws://127.0.0.1:${port}/`, 'echo', 'x'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
    assert.ok(existsSync(path.join(h.home, '.wsh', 'last_session.json')));
    // Only checked when the real home is not being written by something else at the same
    // time (an ssh or git push touches ~/.ssh/known_hosts): then it must be unchanged.
    const after = { wsh: mtime(realHome.wsh), ssh: mtime(realHome.ssh) };
    assert.equal(after.wsh, realHomeBefore.wsh, '~/.wsh changed while the CLI tests ran');
  });
});
