// test/rust/wsh-session-seal.test.mjs -- #155: a SEALED SESSION on a pipe-relayed connection, the Rust CLI against an in-page host
// (`createMemoryHost({ sealSession })`), with a relay that records everything it forwards and one that tampers.
//
//   wsh --via <relay>/r/<id> --sealed -N -L /sock:endpoint=NAME user@host     (the embedder's case)
//
// The recording relay is the point: with the session sealed it finds neither the data nor the endpoint name; without it (control
// run) it finds both. A flipped bit closes the session; a plain message injected after the key exchange is not heard; a host that
// requires sealing serves nobody who has not sealed; `--sealed` against a host that does not offer it fails and sends nothing.
// Every `wsh` runs with HOME in a scratch directory. Prerequisite: cargo build --release -p wsh-cli (or WSH_BIN).

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import crypto from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync, existsSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer, WebSocket as WsClient } from 'ws';

import { createMemoryHost } from '@johnhenry/wsh/memory';
import { newRendezvousId } from '@johnhenry/wsh/pipe-relay';
import { generateKeyPair, exportPublicKeySSH, MSG } from '@johnhenry/wsh';
import { hostileRelay } from '../helpers/hostile-relay.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const MiB = 1024 * 1024;
const MARKER = 'SECRET-MARKER-ZEBRA-7731';
const ENDPOINT = 'zebra-endpoint-name';

const scratch = [];
const closers = [];
const procs = [];
before(() => { assert.ok(existsSync(WSH_BIN), `expected the built wsh at ${WSH_BIN} (cargo build --release -p wsh-cli, or set WSH_BIN)`); });
after(() => { for (const p of procs.splice(0)) p.kill('SIGKILL'); for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true }); });
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 10_000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
}
const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm' });
const tmpDir = () => { const d = realpathSync(mkdtempSync(path.join('/tmp', 'wss-'))); scratch.push(d); return d; };

function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-seal-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  return { home, pub: readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim() };
}

/**
 * A pipe relay that copies bytes and does what the test tells it: `seen` is every byte it forwarded, `tap(dir, data)` observes,
 * `mutate(dir, data, count)` may return other bytes (or null to drop), `inject(dir, data)` writes to a side on its own.
 */
async function copyingRelay() {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  const pending = new Map();
  const relay = { seen: [], counts: { toHost: 0, toOperator: 0 }, mutate: null, sockets: {}, url: `ws://127.0.0.1:${wss.address().port}` };
  const bytes = () => Buffer.concat(relay.seen);
  relay.text = () => bytes().toString('latin1');
  wss.on('connection', (ws, req) => {
    const u = new URL(req.url, 'ws://x');
    const id = u.pathname.split('/').pop();
    const role = u.searchParams.get('role') === 'host' ? 'host' : 'operator';
    const other = pending.get(id);
    if (!other) { pending.set(id, { ws, role }); return; }
    pending.delete(id);
    const [host, operator] = role === 'host' ? [ws, other.ws] : [other.ws, ws];
    relay.sockets = { host, operator };
    const wire = (from, to, dir) => from.on('message', (data, isBinary) => {
      let out = Buffer.from(data);
      relay.counts[dir] += 1;
      relay.seen.push(out);
      if (relay.mutate) { const r = relay.mutate(dir, out, relay.counts[dir]); if (r === null) return; out = r; }
      if (to.readyState === 1) to.send(out, { binary: isBinary });
    });
    wire(operator, host, 'toHost');
    wire(host, operator, 'toOperator');
    for (const [a, b] of [[host, operator], [operator, host]]) a.on('close', () => { if (b.readyState === 1) b.close(); });
  });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  return relay;
}

async function pageHost(h, relay, { sealSession, endpoints, logs = [] } = {}) {
  const host = createMemoryHost({
    auth: { authorizedKeys: h.pub }, exec: async () => 0, hostKey: true, dataStreams: false, requireChannelBinding: true, sealSession,
    endpoints: endpoints ?? { [ENDPOINT]: (d) => { d.readable.pipeTo(d.writable).catch(() => {}); }, probe: (d) => { counters.probe += 1; d.destroy(); } },
    onLog: (l) => logs.push(l),
  });
  closers.push(() => host.close());
  const id = newRendezvousId();
  const ws = new WsClient(`${relay.url}/r/${id}?role=host`);
  ws.on('error', () => {});
  closers.push(async () => ws.terminate());
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  await host.accept(ws);
  return { host, id, logs };
}
const counters = { probe: 0 };

function wsh(args, { home }) {
  const proc = spawn(WSH_BIN, ['--accept-new-host-key', ...args], { env: cleanEnv(home), stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(proc);
  let stderr = ''; let stdout = '';
  proc.stderr.on('data', (d) => { stderr += d; }); proc.stdout.on('data', (d) => { stdout += d; });
  proc.stdin.on('error', () => {}); proc.stdin.end();
  const exited = new Promise((resolve) => proc.once('close', (code, signal) => resolve({ code, signal })));
  closers.push(async () => proc.kill('SIGKILL'));
  return { proc, exited, stderr: () => stderr, stdout: () => stdout, port: () => Number([...stderr.matchAll(/forwarding 127\.0\.0\.1:(\d+) ->/g)][0]?.[1]) };
}

/** `wsh --via <relay>/r/<id> [--sealed] -N -L 0:endpoint=NAME alice@tab.example`, forwarding up. */
async function forward(h, relay, id, { sealed = true, endpoint = ENDPOINT } = {}) {
  const p = wsh(['--via', `${relay.url}/r/${id}`, ...(sealed ? ['--sealed'] : []), '-N', '-L', `0:endpoint=${endpoint}`, 'alice@tab.example'], h);
  const up = await Promise.race([until(() => p.port() > 0, `the forward to come up: ${p.stderr()}`), p.exited.then((r) => { throw new Error(`wsh exited early (${JSON.stringify(r)}): ${p.stderr()}`); })]);
  return { p, port: p.port(), up };
}

const roundTrip = (port, payload) => new Promise((resolve, reject) => {
  const s = net.connect(port, '127.0.0.1'); const cs = []; let got = 0;
  s.on('data', (c) => { cs.push(c); got += c.length; if (got >= payload.length) { s.destroy(); resolve(Buffer.concat(cs)); } });
  s.on('error', reject); s.on('close', () => { if (got < payload.length) reject(new Error(`closed after ${got} of ${payload.length} bytes`)); });
  s.write(payload);
});

describe('a sealed session through a pipe relay that copies bytes', () => {
  it('control: UNSEALED, the relay reads the endpoint name and the data (what #155 reports)', async () => {
    const h = makeHome(); const relay = await copyingRelay();
    const { id } = await pageHost(h, relay, { sealSession: 'offer' });
    const f = await forward(h, relay, id, { sealed: false });
    assert.equal((await roundTrip(f.port, Buffer.from(MARKER))).toString(), MARKER);
    assert.ok(relay.text().includes(MARKER), 'the relay saw the data');
    assert.ok(relay.text().includes(ENDPOINT), 'the relay saw the endpoint name');
  });

  it('SEALED: the data comes back intact, and the relay sees neither the data nor the endpoint name', async () => {
    const h = makeHome(); const relay = await copyingRelay(); const logs = [];
    const { id } = await pageHost(h, relay, { sealSession: 'offer', logs });
    const f = await forward(h, relay, id, { sealed: true });
    assert.equal((await roundTrip(f.port, Buffer.from(MARKER))).toString(), MARKER);
    assert.ok(logs.some((l) => /session sealed/.test(l)), `the host sealed: ${logs.join(' | ')}`);
    assert.ok(!relay.text().includes(MARKER), 'the data crossed the relay in the clear');
    assert.ok(!relay.text().includes(ENDPOINT), 'the endpoint name crossed the relay in the clear');
    assert.match(f.p.stderr(), /sealed/i);
  });

  it('SEALED: a 6 MiB transfer both ways stays intact, and flow-control credit still works', async () => {
    const h = makeHome(); const relay = await copyingRelay();
    const { id } = await pageHost(h, relay, { sealSession: 'offer' });
    const f = await forward(h, relay, id);
    const payload = crypto.randomBytes(6 * MiB);
    const echoed = await roundTrip(f.port, payload);
    assert.equal(crypto.createHash('sha256').update(echoed).digest('hex'), crypto.createHash('sha256').update(payload).digest('hex'));
  });

  it('a flipped bit in a frame closes the session: nothing is delivered, the host says why, and `-N` exits instead of waiting', async () => {
    const h = makeHome(); const relay = await copyingRelay(); const logs = [];
    const { id } = await pageHost(h, relay, { sealSession: 'offer', logs });
    const f = await forward(h, relay, id);
    assert.equal((await roundTrip(f.port, Buffer.from('warm up'))).toString(), 'warm up');
    relay.mutate = (dir, data) => { if (dir === 'toHost' && data.length > 40) { relay.mutate = null; const d = Buffer.from(data); d[d.length - 9] ^= 1; return d; } return data; };
    const echoed = await roundTrip(f.port, Buffer.from(MARKER)).then((b) => b.toString(), () => null);
    assert.notEqual(echoed, MARKER, 'a tampered frame delivered nothing');
    await until(() => logs.some((l) => /did not open/.test(l)), `the host to refuse the frame: ${logs.join(' | ')}`);
    const r = await Promise.race([f.p.exited, sleep(8000).then(() => 'still running')]);
    assert.notEqual(r, 'still running', `-N must exit when the host goes away: ${f.p.stderr()}`);
    assert.notEqual(r.code, 0);
    assert.match(f.p.stderr(), /connection to the host was lost/);
    assert.ok(!relay.text().includes(MARKER));
  });

  it('a plain message injected into a sealed session is not heard (a relay that speaks QMux can write one)', async () => {
    const h = makeHome(); const logs = [];
    counters.probe = 0;
    const host = createMemoryHost({ auth: { authorizedKeys: h.pub }, exec: async () => 0, hostKey: true, dataStreams: false, requireChannelBinding: true, sealSession: 'offer', onLog: (l) => logs.push(l),
      endpoints: { [ENDPOINT]: (d) => { d.readable.pipeTo(d.writable).catch(() => {}); }, probe: (d) => { counters.probe += 1; d.destroy(); } } });
    closers.push(() => host.close());
    const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise((r) => wss.once('listening', r));
    wss.on('connection', (ws) => { void host.accept(ws); });
    closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
    const mitm = await hostileRelay(`ws://127.0.0.1:${wss.address().port}`, {});
    closers.push(() => mitm.close());
    const p = wsh(['-t', 'ws', '--sealed', '-N', '-L', `0:endpoint=${ENDPOINT}`, `alice@${mitm.url.replace('ws://', 'ws://')}`], h);
    await Promise.race([until(() => p.port() > 0, `the forward to come up: ${p.stderr()}`), p.exited.then((r) => { throw new Error(`wsh exited early (${JSON.stringify(r)}): ${p.stderr()}`); })]);
    assert.equal((await roundTrip(p.port(), Buffer.from('hi'))).toString(), 'hi');
    await mitm.context().injectToRelay({ type: MSG.OPEN_ENDPOINT, gateway_id: 99, name: 'probe' });
    await sleep(600);
    assert.equal(counters.probe, 0, 'the plain OpenEndpoint was not heard');
    assert.ok(logs.some((l) => /plaintext message/.test(l)), logs.join(' | '));
    assert.equal((await roundTrip(p.port(), Buffer.from('still up'))).toString(), 'still up', 'and the session carries on');
  });

  it('a host that REQUIRES sealing: the CLI seals on its own, and a plain client gets nothing', async () => {
    const h = makeHome(); const relay = await copyingRelay(); const logs = [];
    const { id, host } = await pageHost(h, relay, { sealSession: 'require', logs });
    const f = await forward(h, relay, id, { sealed: false }); // no --sealed: the host's e2e-session-required is enough
    assert.equal((await roundTrip(f.port, Buffer.from(MARKER))).toString(), MARKER);
    assert.ok(!relay.text().includes(MARKER));
    assert.ok(logs.some((l) => /session sealed/.test(l)));
    // a plain client (the JS client seals on its own against `require` since #155 stage c, so this one opts out): refused, and nothing opens
    const kp = await generateKeyPair(true);
    const h2 = createMemoryHost({ auth: { authorizedKeys: `${await exportPublicKeySSH(kp.publicKey)} u` }, exec: async () => 0, hostKey: true, dataStreams: false, sealSession: 'require', endpoints: { probe: () => { counters.probe += 1; } } });
    closers.push(() => h2.close());
    const c = await h2.connect({ username: 'u', keyPair: kp, sealSession: false });
    await assert.rejects(c.openEndpoint('probe', { timeoutMs: 1500 }));
    assert.equal(counters.probe, 0, 'the endpoint was never opened');
    void host;
  });

  it('--sealed against a host that does not offer it fails with a sentence, and nothing is opened', async () => {
    const h = makeHome(); const relay = await copyingRelay();
    counters.probe = 0;
    const { id } = await pageHost(h, relay, { sealSession: false, endpoints: { probe: () => { counters.probe += 1; } } });
    const p = wsh(['--via', `${relay.url}/r/${id}`, '--sealed', '-N', '-L', '0:endpoint=probe', 'alice@tab.example'], h);
    const r = await Promise.race([p.exited, sleep(10_000).then(() => 'still running')]);
    assert.notEqual(r, 'still running', p.stderr());
    assert.notEqual(r.code, 0);
    assert.match(p.stderr(), /does not offer "e2e-session"/);
    assert.equal(counters.probe, 0);
  });
});
