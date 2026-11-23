// test/rust/wsh-cli-pipe.test.mjs -- the built Rust `wsh` dialling the operator side of a pipe relay (#118, #145):
// `wsh --via wss://relay/r/<id> user@host ...`, through the real JS `createPipeRelay`, to
//   - a Node host (`createWshServer().accept(ws)`), and
//   - a page-shaped host (`createMemoryHost().accept(ws)`, `dataStreams: false` as the released Rust client needs),
// both dialling the relay out as `pipeUrl(relay, id, 'host')`.
//
// What the host key is recorded under is the point of `--via`: the relay's address says nothing about who is at the other
// end, so known_hosts has `user@host`'s own `host:port`, and a different host behind the same name is refused.
//
// Prerequisite: `cargo build --release -p wsh-cli` (or WSH_BIN). Every `wsh` runs with HOME in a scratch directory.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocket as WsClient } from 'ws';

import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { createWshServer } from '@johnhenry/wsh/server';
import { createMemoryHost } from '@johnhenry/wsh/memory';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');

const scratch = [];
const closers = [];

before(() => {
  assert.ok(existsSync(WSH_BIN), `expected the built wsh binary at ${WSH_BIN} (cargo build --release -p wsh-cli, or set WSH_BIN)`);
});

after(async () => {
  for (const close of closers.splice(0)) await close().catch(() => {});
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
});

const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm' });

/** A scratch $HOME with a fresh `default` identity. */
function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-cli-pipe-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const pub = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  return { home, pub, knownHosts: () => { try { return readFileSync(path.join(home, '.wsh', 'known_hosts'), 'utf8'); } catch { return ''; } } };
}

function wsh(args, { home, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve) => {
    const proc = spawn(WSH_BIN, ['--accept-new-host-key', ...args], { env: cleanEnv(home), stdio: ['pipe', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    proc.stdout.on('data', (d) => out.push(d));
    proc.stderr.on('data', (d) => err.push(d));
    proc.stdin.on('error', () => {});
    proc.stdin.end();
    const timer = setTimeout(() => proc.kill('SIGKILL'), timeoutMs);
    proc.once('close', (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
}

async function startRelay() {
  const relay = createPipeRelay({ rendezvousTimeoutMs: 15_000 });
  const { port } = await relay.listen();
  closers.push(() => relay.close());
  return { relay, url: `ws://127.0.0.1:${port}`, port };
}

/** The host side: dial the relay as `host` and serve the socket. Resolves once serving. */
async function dialHost(relayUrl, id, serve) {
  const ws = new WsClient(pipeUrl(relayUrl, id, 'host'));
  ws.on('error', () => {});
  closers.push(async () => ws.terminate());
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  await serve(ws);
  return ws;
}

/** An exec that echoes what it is told and records what ran. */
const makeExec = (ran) => async (command, io) => {
  ran.push(command);
  const [word, ...rest] = command.trim().split(/\s+/);
  if (word === 'echo') { await io.write(`${rest.join(' ')}\n`); return 0; }
  if (word === 'whoami') { await io.write(`${io.user}\n`); return 0; }
  await io.write(`unknown: ${command}\n`);
  return 127;
};

/** A Node host (`createWshServer`) that serves sockets handed to accept(); `hostKey` is its identity. */
function nodeHost(h, { ran = [], hostKey = true } = {}) {
  const server = createWshServer({ auth: { authorizedKeys: h.pub }, exec: makeExec(ran), hostKey });
  closers.push(() => server.close());
  return { ran, serve: (ws) => server.accept(ws, { dataStreams: false }), server };
}

/** A page-shaped host (`createMemoryHost`): no listener of its own, the socket is handed to accept(). */
function pageHost(h, { ran = [], hostKey = true } = {}) {
  const host = createMemoryHost({ auth: { authorizedKeys: h.pub }, exec: makeExec(ran), hostKey, dataStreams: false });
  closers.push(() => host.close());
  return { ran, serve: (ws) => host.accept(ws), host };
}

const via = (relay, id) => pipeUrl(relay.url, id);

describe('wsh --via: through a pipe relay to a Node host', () => {
  it('runs a command and records the host key under user@host, not under the relay', async () => {
    const h = makeHome();
    const relay = await startRelay();
    const host = nodeHost(h);
    const id = newRendezvousId();
    await dialHost(relay.url, id, host.serve);

    const r = await wsh(['--via', via(relay, id), 'alice@build.example.com', 'echo', 'through', 'the', 'pipe'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, 'through the pipe\n');
    assert.deepEqual(host.ran, ['echo through the pipe']);

    const known = h.knownHosts();
    assert.match(known, /^build\.example\.com:4422 /m, known);
    assert.doesNotMatch(known, new RegExp(`127\\.0\\.0\\.1:${relay.port}`), 'the relay is not the host');
  });

  it('keeps the user of user@host as the login name', async () => {
    const h = makeHome();
    const relay = await startRelay();
    const host = nodeHost(h);
    const id = newRendezvousId();
    await dialHost(relay.url, id, host.serve);
    const r = await wsh(['--via', via(relay, id), 'carol@somewhere', 'whoami'], { home: h.home });
    assert.equal(r.stdout, 'carol\n', r.stderr);
  });

  it('does not write the rendezvous id (a capability) to last_session.json', async () => {
    const h = makeHome();
    const relay = await startRelay();
    const host = nodeHost(h);
    const id = newRendezvousId();
    await dialHost(relay.url, id, host.serve);
    const r = await wsh(['--via', via(relay, id), 'alice@build.example.com', 'echo', 'x'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
    const last = readFileSync(path.join(h.home, '.wsh', 'last_session.json'), 'utf8');
    assert.doesNotMatch(last, new RegExp(id));
    assert.match(last, /build\.example\.com/);
  });

  it('refuses a different host behind the same name, before running anything, whichever relay carried it', async () => {
    const h = makeHome();
    const relay1 = await startRelay();
    const relay2 = await startRelay();

    // First contact (trust on first use): host A is recorded for build.example.com:4422.
    const a = nodeHost(h);
    const id1 = newRendezvousId();
    await dialHost(relay1.url, id1, a.serve);
    const first = await wsh(['--via', via(relay1, id1), 'alice@build.example.com', 'echo', 'one'], { home: h.home });
    assert.equal(first.code, 0, first.stderr);
    const recorded = h.knownHosts();

    // An impostor with its own key answers the same name through another relay: refused, nothing run.
    const impostor = nodeHost(h);
    const id2 = newRendezvousId();
    await dialHost(relay2.url, id2, impostor.serve);
    const refused = await wsh(['--via', via(relay2, id2), 'alice@build.example.com', 'echo', 'two'], { home: h.home });
    assert.notEqual(refused.code, 0);
    assert.match(refused.stderr, /HOST KEY CHANGED/);
    assert.equal(refused.stdout, '');
    assert.deepEqual(impostor.ran, [], 'no command reached the impostor');
    assert.equal(h.knownHosts(), recorded, 'the recorded key is untouched');

    // The same host again, through the other relay, is the host it was: accepted (the pin follows the name).
    const id3 = newRendezvousId();
    await dialHost(relay2.url, id3, a.serve);
    const again = await wsh(['--via', via(relay2, id3), 'alice@build.example.com', 'echo', 'three'], { home: h.home });
    assert.equal(again.code, 0, again.stderr);
    assert.equal(again.stdout, 'three\n');
  });

  it('a host recorded under one name is a stranger under another', async () => {
    const h = makeHome();
    const relay = await startRelay();
    const a = nodeHost(h);
    const id1 = newRendezvousId();
    await dialHost(relay.url, id1, a.serve);
    assert.equal((await wsh(['--via', via(relay, id1), 'alice@one.example.com', 'echo', '1'], { home: h.home })).code, 0);
    const b = nodeHost(h);
    const id2 = newRendezvousId();
    await dialHost(relay.url, id2, b.serve);
    // A different name is a different identity: first use of two.example.com, not a change.
    const r = await wsh(['--via', via(relay, id2), 'alice@two.example.com', 'echo', '2'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
    assert.match(h.knownHosts(), /^one\.example\.com:4422 /m);
    assert.match(h.knownHosts(), /^two\.example\.com:4422 /m);
  });
});

describe('wsh --via: through a pipe relay to a page-shaped host (createMemoryHost)', () => {
  it('runs a command', async () => {
    const h = makeHome();
    const relay = await startRelay();
    const host = pageHost(h);
    const id = newRendezvousId();
    await dialHost(relay.url, id, host.serve);
    const r = await wsh(['--via', via(relay, id), 'alice@tab.example', 'echo', 'from', 'a', 'page'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, 'from a page\n');
    assert.match(h.knownHosts(), /^tab\.example:4422 /m);
  });

  it('refuses a page host whose key is not the one recorded for that name', async () => {
    const h = makeHome();
    const relay = await startRelay();
    const real = pageHost(h);
    const id1 = newRendezvousId();
    await dialHost(relay.url, id1, real.serve);
    assert.equal((await wsh(['--via', via(relay, id1), 'alice@tab.example', 'echo', '1'], { home: h.home })).code, 0);

    const fake = pageHost(h);
    const id2 = newRendezvousId();
    await dialHost(relay.url, id2, fake.serve);
    const r = await wsh(['--via', via(relay, id2), 'alice@tab.example', 'echo', '2'], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /HOST KEY CHANGED/);
    assert.deepEqual(fake.ran, []);
  });

  it('a host that is not authorized for this key refuses the login (the host still authenticates the operator)', async () => {
    const h = makeHome();
    const other = makeHome();
    const relay = await startRelay();
    const host = pageHost(other);
    const id = newRendezvousId();
    await dialHost(relay.url, id, host.serve);
    const r = await wsh(['--via', via(relay, id), 'alice@tab.example', 'echo', 'x'], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.deepEqual(host.ran, []);
  });
});

describe('wsh: the rendezvous URL as the target, and --via mistakes', () => {
  it('a URL target on its own also reaches the host (and is pinned under the relay address, which --via avoids)', async () => {
    const h = makeHome();
    const relay = await startRelay();
    const host = nodeHost(h);
    const id = newRendezvousId();
    await dialHost(relay.url, id, host.serve);
    const r = await wsh([`alice@${via(relay, id)}`, 'echo', 'bare', 'url'], { home: h.home });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, 'bare url\n');
    assert.match(h.knownHosts(), new RegExp(`^127\\.0\\.0\\.1:${relay.port} `, 'm'));
  });

  it('refuses the host side of the pipe, a URL with no id, a bad id, and --via together with a URL target', async () => {
    const h = makeHome();
    const id = newRendezvousId();
    const cases = [
      [['--via', `${pipeUrl('ws://127.0.0.1:9', id, 'host')}`, 'alice@h', 'echo', 'x'], /HOST side|role/i],
      [['--via', 'ws://127.0.0.1:9', 'alice@h', 'echo', 'x'], /\/r\/<rendezvous id>/],
      [['--via', 'ws://127.0.0.1:9/r/short', 'alice@h', 'echo', 'x'], /\/r\/<rendezvous id>/],
      [['--via', 'https://relay.example/r/' + id, 'alice@h', 'echo', 'x'], /WebSocket/],
      [['--via', pipeUrl('ws://relay.example.com', id), 'alice@h', 'echo', 'x'], /plain-text/],
      [['--via', pipeUrl('ws://127.0.0.1:9', id), `alice@${pipeUrl('ws://127.0.0.1:9', id)}`, 'echo', 'x'], /user@host/],
    ];
    for (const [args, message] of cases) {
      const r = await wsh(args, { home: h.home });
      assert.equal(r.code, 1, `${args.join(' ')}: ${r.stderr}`);
      assert.match(r.stderr, message, args.join(' '));
    }
  });

  it('--via on a command that does not dial one host is an error, not silently ignored', async () => {
    const h = makeHome();
    const r = await wsh(['--via', pipeUrl('ws://127.0.0.1:9', newRendezvousId()), 'keys'], { home: h.home });
    assert.equal(r.code, 2);
    assert.match(r.stderr, /--via applies to/);
  });
});
