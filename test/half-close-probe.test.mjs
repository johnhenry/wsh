// test/half-close-probe.test.mjs -- #282: a local peer that half-closed (sent its FIN, still reading) and then went away is noticed
// by the side holding the other end of the socket, with nothing written to it and nothing added to the wire.
//
// Before: the kernel tells a socket whose peer half-closed and then died nothing until something is written to it, so a forward whose
// local program was killed after its half-close held the host's connection and slot until the far side next sent (never, with a
// quiet far side and `halfCloseIdleMs: 0`). Now the side that holds the socket probes it while it is half-closed (a zero-length
// write: it delivers nothing to a live peer and fails with EPIPE on a dead unix peer; TCP also gets a short keep-alive schedule so
// the kernel eventually learns), and treats a dead peer as a destroyed socket: the existing second GatewayClose "discarded".
//
// The local programs are real child processes (test/half-close-probe-child.mjs), SIGKILLed by pid. What is asserted is a STATE (the
// host's stream ended as "discarded", the slot was freed) with a generous bound; the measured detection time is printed.
//
// TCP: a peer that half-closed and exits leaves a socket in the kernel that answers everything but data until the kernel drops it
// (60 s by default on Linux and macOS), so a TCP peer killed with nothing unread is noticed about a minute later (that test takes
// that long); one killed with data unread is reset at once and noticed within a probe interval.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createWshServer } from '@johnhenry/wsh/server';
import { generateKeyPair, exportPublicKeySSH, WshClient } from '@johnhenry/wsh';
import { halfCloseWatchCount, watchHalfClosed, LOCAL_PEER_GONE } from '../src/half-close-watch.mjs';
import { fixture, until, sleep, listen } from './gateway-fixture.mjs';

const CHILD = fileURLToPath(new URL('./half-close-probe-child.mjs', import.meta.url));
// A loaded CI runner can stall a process for seconds: the bound is far above the expected time (about two probe intervals) and exists
// only so a regression fails with a message instead of hanging.
const BOUND_MS = 30_000;
// A TCP peer killed with nothing unread: the kernel's own 60 s orphan timeout, plus the keep-alive schedule, plus a probe interval.
const TCP_SLOW_BOUND_MS = 170_000;
const SLOW = { timeout: 200_000 };
const stateAfter = (closed, ms) => Promise.race([closed, sleep(ms).then(() => 'open')]);
/**
 * Send 300 kB towards a program that never reads (a Node process takes some of it into its own buffers before it is asked, so a
 * small amount is not "unread"). The write may stall once every buffer on the way is full, which is the state wanted; so it is not
 * waited for beyond a few seconds, and what is still in flight when the program dies fails (nobody awaits it).
 */
async function handUnread(duplex) {
  const w = duplex.writable.getWriter();
  await Promise.race([w.write(new Uint8Array(300_000)).catch(() => {}), sleep(3000)]);
}

/**
 * A host that listens on a unix socket for callers, with room for ONE connection; and a client forwarding the callers to a local
 * service (a reverse forward). `slotFree()` says whether the host's only slot is free (an open that reaches its TCP origin means it was).
 */
async function reverseHost({ fx, tmp, forwards }, hostOptions = {}) {
  const hostSock = path.join(tmp(), `r${Math.random().toString(36).slice(2, 6)}.sock`);
  const services = [];
  // allowHalfOpen: the service keeps its side open after the caller's end of file, as a service that answers later does.
  const service = net.createServer({ allowHalfOpen: true }, (s) => { services.push(s); fx.cleanups.push(async () => s.destroy()); s.on('error', () => {}); s.resume(); });
  const servicePort = await listen(service); fx.nets.push(service);
  const origin = net.createServer((s) => { s.on('error', () => {}); fx.cleanups.push(async () => s.destroy()); });
  const originPort = await listen(origin); fx.nets.push(origin);
  const { client } = await fx.setup({ allow: [`127.0.0.1:${originPort}`], unix: { listen: [hostSock] }, halfCloseIdleMs: 0, halfCloseProbeMs: 200, maxConnections: 1, ...hostOptions });
  const fwd = await client.forwardUnix({ local: `127.0.0.1:${servicePort}`, remote: hostSock, reverse: true });
  forwards.push(fwd);
  const slotFree = async () => { try { (await client.openTcp('127.0.0.1', originPort)).destroy(); return true; } catch (e) { if (/too many/.test(e.message)) return false; throw e; } };
  return { hostSock, services, fwd, slotFree };
}

describe('a half-closed local peer that is killed is noticed with the far side silent (idle bound 0)', () => {
  let dir; const procs = []; const forwards = [];
  const fx = fixture();
  const tmp = () => { dir ??= fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-hp-')); return fs.realpathSync(dir); };
  afterEach(async () => {
    for (const p of procs.splice(0)) p.kill('SIGKILL');
    for (const f of forwards.splice(0)) await f.close().catch(() => {});
    await fx.teardown();
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; } // a directory this test made
  });

  /** Start the child and wait for a line containing `until`; returns { child, lines }. */
  async function start(args, until) {
    const child = spawn(process.execPath, [CHILD, ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
    procs.push(child);
    const lines = [];
    let resolveSeen; let buf = '';
    const seen = new Promise((resolve, reject) => {
      resolveSeen = resolve;
      child.once('exit', () => reject(new Error(`the child exited early (${lines.join(' | ')})`)));
    });
    child.stdout.on('data', (d) => {
      buf += d;
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1); }
      if (lines.some((l) => l.includes(until))) resolveSeen();
    });
    await seen;
    child.removeAllListeners('exit');
    return { child, lines };
  }
  const kill = (child) => new Promise((r) => { child.once('exit', r); child.kill('SIGKILL'); });

  async function quietEndpointHost(gateway = {}) {
    const keyPair = await generateKeyPair(true);
    const authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} u`;
    const seen = [];
    const server = createWshServer({ auth: { authorizedKeys }, gateway: { allow: [], tcp: false, halfCloseIdleMs: 0, endpoints: { quiet: (d) => { seen.push(d); } }, ...gateway } });
    const { port } = await server.listen();
    fx.servers.push(server);
    const client = new WshClient();
    await client.connect(`ws://127.0.0.1:${port}`, { username: 'u', keyPair });
    fx.clients.push(client);
    return { client, seen };
  }

  /** Kill `child`, then say how the host's stream ended and how long that took (nothing is written by the far side). */
  async function killAndMeasure(t, label, child, closed, bound = BOUND_MS) {
    const t0 = Date.now();
    await kill(child);
    const state = await stateAfter(closed, bound);
    t.diagnostic(`${label}: ended as ${JSON.stringify(state)} ${Date.now() - t0} ms after the kill`);
    return state;
  }

  it('forwardEndpoint over a unix socket: the endpoint stream ends as "discarded" by itself', async (t) => {
    const { client, seen } = await quietEndpointHost();
    const local = path.join(tmp(), 'e.sock');
    forwards.push(await client.forwardEndpoint({ local, endpoint: 'quiet', halfCloseProbeMs: 200 }));
    const { child } = await start(['client', 'unix', local], 'half-closed');
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    assert.equal(await stateAfter(seen[0].closed, 600), 'open', 'a half-closed peer that is alive is held (the idle bound is off)');
    assert.equal(await killAndMeasure(t, 'unix forward', child, seen[0].closed), 'discarded');
  });

  it('the default probe interval does it too (about two seconds)', async (t) => {
    const { client, seen } = await quietEndpointHost();
    const local = path.join(tmp(), 'd.sock');
    forwards.push(await client.forwardEndpoint({ local, endpoint: 'quiet' }));
    const { child } = await start(['client', 'unix', local], 'half-closed');
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    assert.equal(await killAndMeasure(t, 'unix forward, default interval', child, seen[0].closed), 'discarded');
  });

  it('forwardUnix over a local TCP port, peer killed with data unread (reset at once): noticed within a probe interval', async (t) => {
    const { client, seen } = await quietEndpointHost();
    const fwd = await client.forwardUnix({ local: '127.0.0.1:0', remote: 'endpoint=quiet', halfCloseProbeMs: 200 });
    forwards.push(fwd);
    const { child } = await start(['client', 'tcp', String(fwd.address.port), 'paused'], 'half-closed');
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    // The far side hands the child more than a Node process takes into its own buffers without being asked, so some is left unread
    // in the kernel and the kernel resets the connection when the child dies.
    await handUnread(seen[0]);
    assert.equal(await stateAfter(seen[0].closed, 600), 'open');
    assert.equal(await killAndMeasure(t, 'tcp forward, unread data', child, seen[0].closed), 'discarded');
  });

  it('a local TCP program half-closed and killed with nothing unread: noticed when the kernel drops the socket (about a minute), then by a keep-alive probe', SLOW, async (t) => {
    const { client, seen } = await quietEndpointHost();
    const fwd = await client.forwardUnix({ local: '127.0.0.1:0', remote: 'endpoint=quiet', halfCloseProbeMs: 1000 });
    forwards.push(fwd);
    const { child } = await start(['client', 'tcp', String(fwd.address.port)], 'half-closed');
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    assert.equal(await killAndMeasure(t, 'tcp forward, nothing unread', child, seen[0].closed, TCP_SLOW_BOUND_MS), 'discarded');
  });

  it('a CALLER of the host\'s reverse listener that half-closed and was killed: the host frees its slot by itself', async (t) => {
    const { hostSock, services, fwd, slotFree } = await reverseHost({ fx, tmp, forwards });
    const { child } = await start(['client', 'unix', hostSock], 'half-closed');
    await until(() => fwd.connections === 1 && services.length === 1, 'the service to take the connection');
    assert.equal(await slotFree(), false, 'the caller holds the host\'s only slot');
    const t0 = Date.now();
    await kill(child);
    await until(() => slotFree(), 'the host to free the slot', BOUND_MS);
    t.diagnostic(`reverse caller: the host's slot was free ${Date.now() - t0} ms after the kill`);
  });

  // The two places where the DEAD party would be a data producer that finished (an origin the host dialled, the local service of a
  // reverse forward) used to be deliberately not watched: a server that sends its whole answer and then closes completely is the normal
  // end of a response, and the `discarded` close a watch would send drops what the reader has received and not yet read. Since #286 they
  // ARE watched when both ends state `gateway-lossless-close`: the close is then `released`, which delivers what was sent first, so the
  // two tests below changed from "not watched" to "watched, and every byte arrives" (the old behaviour, against a side that did not state
  // the feature, is pinned in test/gateway-lossless-close.test.mjs).
  const SIZE = 3 * 1024 * 1024;
  // A slow reader: a pause after every chunk, so that when the end of the answer reaches it a good part of what is left is still queued.
  const readAll = async (d) => { const r = d.readable.getReader(); let n = 0; for (;;) { const { value, done } = await r.read(); if (done) return n; n += value.length; await sleep(10); } };

  it('a unix ORIGIN of the host that sent everything and closed completely is watched, and a slow client still gets all of it (#286)', async () => {
    const sock = path.join(tmp(), 'o.sock');
    const origin = net.createServer((s) => { s.on('error', () => {}); s.end(Buffer.alloc(SIZE, 5), () => s.destroy()); });
    await new Promise((r) => origin.listen(sock, r)); fx.nets.push(origin);
    const { client } = await fx.setup({ allow: [], unix: { connect: [sock] }, halfCloseIdleMs: 0, halfCloseProbeMs: 50 });
    const d = await client.openUnix(sock);
    await sleep(1000); // the origin is long gone; what it sent is mostly unread
    assert.equal(await stateAfter(d.closed, 0), 'open', 'held for the reader');
    const reading = readAll(d);
    await until(() => halfCloseWatchCount() >= 1, 'the origin to be watched (the watch starts when the host has read its end of file)');
    assert.equal(await reading, SIZE);
    assert.equal(await stateAfter(d.closed, BOUND_MS), 'released', 'and the host, which noticed the origin was gone, ended the connection by itself');
  });

  it('the local service of a reverse forward that sent everything and closed completely is watched, and a slow caller still gets all of it (#286)', async () => {
    const hostSock = path.join(tmp(), 'r2.sock');
    const svcSock = path.join(tmp(), 's2.sock'); // a unix service: its complete close is seen at once, so the release really happens
    const service = net.createServer((s) => { s.on('error', () => {}); s.end(Buffer.alloc(SIZE, 6), () => s.destroy()); });
    await new Promise((r) => service.listen(svcSock, r)); fx.nets.push(service);
    const { client } = await fx.setup({ allow: [], unix: { listen: [hostSock] }, halfCloseIdleMs: 0, halfCloseProbeMs: 50 });
    forwards.push(await client.forwardUnix({ local: svcSock, remote: hostSock, reverse: true, halfCloseProbeMs: 50 }));
    const caller = net.connect({ path: hostSock, allowHalfOpen: true });
    caller.on('error', () => {});
    caller.pause();
    await sleep(1000); // the service is long gone; what it sent is mostly unread by the caller
    let n = 0;
    // a slow reader (see readAll above)
    caller.on('data', (b) => { n += b.length; caller.pause(); setTimeout(() => caller.resume(), 10); });
    const ended = new Promise((r) => caller.once('end', r));
    caller.resume();
    await ended;
    assert.equal(n, SIZE);
    caller.destroy();
  });

  it('the forward reports it as a local peer that went away after finishing its side (not a failure of the forward)', async () => {
    const { client, seen } = await quietEndpointHost();
    const local = path.join(tmp(), 'r.sock');
    const errors = [];
    forwards.push(await client.forwardEndpoint({ local, endpoint: 'quiet', halfCloseProbeMs: 200, onError: (e) => errors.push(e) }));
    const { child } = await start(['client', 'unix', local], 'half-closed');
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    await kill(child);
    await seen[0].closed;
    await until(() => errors.length > 0, 'the report');
    assert.equal(errors.length, 1);
    assert.equal(errors[0].code, 'WSH_LOCAL_PEER_GONE');
    assert.match(errors[0].message, /local peer went away after finishing its side/);
  });

  it('a client that simply closes (both sides finish) is not reported', async () => {
    const { client, seen } = await quietEndpointHost();
    const local = path.join(tmp(), 'n.sock');
    const errors = [];
    const fwd = await client.forwardEndpoint({ local, endpoint: 'quiet', halfCloseProbeMs: 100, onError: (e) => errors.push(e) });
    forwards.push(fwd);
    const peer = net.connect({ path: local, allowHalfOpen: true });
    peer.on('error', () => {}); peer.resume();
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    peer.end('hi'); // half-close
    await until(() => halfCloseWatchCount() === 1, 'the probe to be armed');
    await seen[0].writable.getWriter().close();
    await new Promise((r) => peer.once('close', r));
    await until(() => fwd.connections === 0 && halfCloseWatchCount() === 0, 'everything to be released');
    await sleep(300);
    assert.deepEqual(errors, []);
  });
});

describe('a half-closed peer that is alive and reading is never cut by the probe', () => {
  let dir; const procs = []; const forwards = [];
  const fx = fixture();
  const tmp = () => { dir ??= fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-hl-')); return fs.realpathSync(dir); };
  afterEach(async () => {
    for (const p of procs.splice(0)) p.kill('SIGKILL');
    for (const f of forwards.splice(0)) await f.close().catch(() => {});
    await fx.teardown();
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; }
  });
  async function startClient(args) {
    const child = spawn(process.execPath, [CHILD, 'client', ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
    procs.push(child);
    const lines = [];
    let buf = '';
    child.stdout.on('data', (d) => { buf += d; for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1); } });
    await until(() => lines.includes('half-closed'), 'the child to half-close');
    return { child, lines };
  }
  async function host() {
    const keyPair = await generateKeyPair(true);
    const authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} u`;
    const seen = [];
    const server = createWshServer({ auth: { authorizedKeys }, gateway: { allow: [], tcp: false, halfCloseIdleMs: 0, endpoints: { quiet: (d) => { seen.push(d); } } } });
    const { port } = await server.listen();
    fx.servers.push(server);
    const client = new WshClient();
    await client.connect(`ws://127.0.0.1:${port}`, { username: 'u', keyPair });
    fx.clients.push(client);
    return { client, seen };
  }

  for (const kind of ['unix', 'tcp']) {
    it(`${kind}: it half-closes, keeps reading for thirty probe intervals while the far side is silent, then receives what the far side sends, whole`, async () => {
      const { client, seen } = await host();
      const fwd = kind === 'unix'
        ? await client.forwardEndpoint({ local: path.join(tmp(), 'a.sock'), endpoint: 'quiet', halfCloseProbeMs: 40 })
        : await client.forwardUnix({ local: '127.0.0.1:0', remote: 'endpoint=quiet', halfCloseProbeMs: 40 });
      forwards.push(fwd);
      const { lines } = await startClient([kind, kind === 'unix' ? fwd.address : String(fwd.address.port)]);
      await until(() => seen.length === 1, 'the endpoint to see the connection');
      await until(() => halfCloseWatchCount() === 1, 'the probe to be armed');
      await sleep(30 * 40); // thirty probe intervals, with the far side silent
      assert.equal(await stateAfter(seen[0].closed, 0), 'open', 'the live half-closed peer was not cut');
      assert.equal(fwd.connections, 1);
      const w = seen[0].writable.getWriter();
      const size = 600_000;
      await w.write(new Uint8Array(size).fill(7));
      await w.close();
      await until(() => lines.includes(`got ${size}`) && lines.includes('end'), 'the child to receive all of it and the end');
      assert.equal(lines.filter((l) => l.startsWith('got ')).length > 0, true);
    });
  }

  it('a reverse listener\'s caller that is alive and half-closed keeps its connection across thirty of the host\'s probe intervals, then gets the answer whole', async () => {
    const { hostSock, services, fwd, slotFree } = await reverseHost({ fx, tmp, forwards }, { halfCloseProbeMs: 40 });
    const { lines } = await startClient(['unix', hostSock]);
    await until(() => services.length === 1 && fwd.connections === 1, 'the service to take the connection');
    await sleep(30 * 40);
    assert.equal(await slotFree(), false, 'the live half-closed caller was not cut: it still holds the host\'s slot');
    // (The service keeps its socket open: one that sends a large answer and closes completely while the caller has already half-closed
    // loses the tail of it to the client's own teardown, which is older than this change and is not what is tested here.)
    services[0].write(Buffer.alloc(400_000, 4));
    await until(() => lines.includes('got 400000'), 'the whole answer');
    assert.equal(lines.includes('end'), false, 'and the connection is still open for the caller');
  });
});

describe('the probe is off when asked, and costs nothing when there is nothing to watch', () => {
  let dir; const procs = []; const forwards = [];
  const fx = fixture();
  afterEach(async () => {
    for (const p of procs.splice(0)) p.kill('SIGKILL');
    for (const f of forwards.splice(0)) await f.close().catch(() => {});
    await fx.teardown();
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; }
  });
  async function host() {
    const keyPair = await generateKeyPair(true);
    const authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} u`;
    const seen = [];
    const server = createWshServer({ auth: { authorizedKeys }, gateway: { allow: [], tcp: false, halfCloseIdleMs: 0, endpoints: { quiet: (d) => { seen.push(d); } } } });
    const { port } = await server.listen();
    fx.servers.push(server);
    const client = new WshClient();
    await client.connect(`ws://127.0.0.1:${port}`, { username: 'u', keyPair });
    fx.clients.push(client);
    return { client, seen };
  }

  it('halfCloseProbeMs: 0 keeps the old behaviour: a killed half-closed peer is not noticed by itself', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-h0-'));
    const { client, seen } = await host();
    const local = path.join(fs.realpathSync(dir), 'z.sock');
    forwards.push(await client.forwardEndpoint({ local, endpoint: 'quiet', halfCloseProbeMs: 0 }));
    const child = spawn(process.execPath, [CHILD, 'client', 'unix', local], { stdio: ['ignore', 'pipe', 'inherit'] });
    procs.push(child);
    await new Promise((r) => child.stdout.once('data', r));
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    assert.equal(halfCloseWatchCount(), 0);
    await new Promise((r) => { child.once('exit', r); child.kill('SIGKILL'); });
    // Nothing can notice it; this bounds how long we look, it does not wait for anything to happen.
    assert.equal(await stateAfter(seen[0].closed, 1500), 'open');
  });

  it('a timer exists only while a connection is half-closed, one per connection, and none remains after they close (many at once)', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-hm-'));
    const { client, seen } = await host();
    const local = path.join(fs.realpathSync(dir), 'm.sock');
    const fwd = await client.forwardEndpoint({ local, endpoint: 'quiet', halfCloseProbeMs: 50, maxConnections: 100 });
    forwards.push(fwd);
    const N = 30; // under the host's default of 32 connections
    const peers = [];
    for (let i = 0; i < N; i++) { const s = net.connect({ path: local, allowHalfOpen: true }); s.on('error', () => {}); s.resume(); peers.push(s); }
    await until(() => seen.length === N && fwd.connections === N, `${N} connections`);
    assert.equal(halfCloseWatchCount(), 0, 'connections that are not half-closed are not watched');
    for (const s of peers) s.end(); // half-close all of them
    await until(() => halfCloseWatchCount() === N, `${N} probes armed`);
    await sleep(200); // several probe intervals: live peers, nothing changes
    assert.equal(fwd.connections, N);
    assert.equal(halfCloseWatchCount(), N);
    for (const s of peers) s.destroy();
    await until(() => fwd.connections === 0 && halfCloseWatchCount() === 0, 'every probe to be released');
    await Promise.all(seen.map((d) => d.closed));
  });

  it('a normal close leaves no probe behind', async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-hn-'));
    const { client, seen } = await host();
    const local = path.join(fs.realpathSync(dir), 'c.sock');
    const fwd = await client.forwardEndpoint({ local, endpoint: 'quiet', halfCloseProbeMs: 50 });
    forwards.push(fwd);
    const peer = net.connect({ path: local });
    peer.on('error', () => {});
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    peer.destroy();
    await seen[0].closed;
    assert.equal(halfCloseWatchCount(), 0);
    assert.equal(fwd.connections, 0);
  });
});

describe('watchHalfClosed on a real socket pair: what it touches, and when', () => {
  /** A connected pair over a TCP port: `mine` is the side being watched, `theirs` the peer. */
  async function pair() {
    let mine;
    const server = net.createServer({ allowHalfOpen: true }, (s) => { mine = s; });
    const port = await listen(server);
    const theirs = net.connect({ host: '127.0.0.1', port, allowHalfOpen: true });
    theirs.on('error', () => {});
    await new Promise((r) => theirs.once('connect', r));
    await until(() => mine, 'the accept');
    mine.on('error', () => {});
    return { mine, theirs, close: () => { mine.destroy(); theirs.destroy(); server.close(); } };
  }

  it('TCP keep-alive is changed only once the peer has half-closed, never on an ordinary connection', async () => {
    const { mine, theirs, close } = await pair();
    try {
      const calls = [];
      const real = mine.setKeepAlive.bind(mine);
      mine.setKeepAlive = (...a) => { calls.push(a); return real(...a); };
      watchHalfClosed(mine, 50);
      mine.resume();
      theirs.write('data'); // traffic, still not half-closed
      await sleep(200);
      assert.deepEqual(calls, [], 'an ordinary connection is untouched');
      assert.equal(halfCloseWatchCount(), 0);
      theirs.end(); // the FIN
      await until(() => calls.length === 1, 'keep-alive to be set');
      assert.deepEqual(calls[0], [true, 1000, 1000, 3], 'whole seconds (at least one), three probes');
      assert.equal(halfCloseWatchCount(), 1);
    } finally { close(); }
  });

  it('a zero-length probe is never written while a real write is queued or the socket is draining, and resumes after', async () => {
    const { mine, theirs, close } = await pair();
    try {
      const zero = [];
      const realWrite = mine.write.bind(mine);
      mine.write = (chunk, ...rest) => { if (chunk?.length === 0) zero.push({ queued: mine.writableLength, needDrain: mine.writableNeedDrain }); return realWrite(chunk, ...rest); };
      watchHalfClosed(mine, 20);
      mine.resume();
      theirs.pause(); // the peer reads nothing: what we write piles up behind the kernel's buffers
      theirs.end();   // and it has half-closed
      await until(() => halfCloseWatchCount() === 1, 'the probe to be armed');
      await until(() => zero.length > 0, 'a probe on an idle socket');
      const before = zero.length;
      mine.write(Buffer.alloc(32 * 1024 * 1024)); // far more than the kernel takes: stays queued
      assert.ok(mine.writableLength > 0);
      const during = zero.length;
      await sleep(300); // fifteen probe intervals
      assert.equal(zero.length, during, `no probe while a write is queued (${before} before, ${zero.length - during} during)`);
      assert.ok(zero.every((z) => z.queued === 0 && z.needDrain === false), 'every probe saw an idle socket');
      theirs.resume(); // drains
      await until(() => mine.writableLength === 0, 'the queue to drain');
      await until(() => zero.length > during, 'probes to resume');
    } finally { close(); }
  });

  it('a probe delivers nothing to a live peer', async () => {
    // THEIRS half-closes and keeps reading; MINE is probed for a long time.
    const p = await pair();
    try {
      let got = 0;
      p.theirs.on('data', (d) => { got += d.length; });
      let ended = false; p.theirs.on('end', () => { ended = true; });
      watchHalfClosed(p.mine, 20);
      p.mine.resume();
      p.theirs.end(); // theirs half-closes (it still reads)
      await until(() => halfCloseWatchCount() === 1, 'armed');
      await sleep(400); // twenty probes
      assert.equal(got, 0, 'not one byte reached the live peer');
      assert.equal(ended, false, 'and no end of file either');
    } finally { p.close(); }
  });

  it('reports once, with the code, and destroys the socket; close() stops the probe', async () => {
    const { mine, theirs, close } = await pair();
    try {
      const reports = [];
      watchHalfClosed(mine, 20, (e) => reports.push(e));
      mine.resume();
      theirs.end();
      await until(() => halfCloseWatchCount() === 1, 'armed');
      // The FIN must have been sent before the reset: libuv refuses to reset a stream whose shutdown is still in flight.
      await until(() => theirs.writableFinished, 'the FIN to be sent');
      theirs.resetAndDestroy(); // gone, with a reset (a TCP peer that exited with nothing unread is only noticed after the kernel's minute)
      await until(() => reports.length > 0, 'the peer to be noticed');
      await until(() => mine.destroyed && halfCloseWatchCount() === 0, 'the socket to be destroyed and the probe released');
      await sleep(100);
      assert.equal(reports.length, 1, 'reported once');
      assert.equal(reports[0].code, LOCAL_PEER_GONE);
      assert.match(reports[0].message, /local peer went away after finishing its side/);
    } finally { close(); }
  });
});

describe('halfCloseProbeMs is validated like the other millisecond options', () => {
  const bad = [-1, 1.5, '2000', 2 ** 31, NaN, Infinity, null];
  it('forwardUnix, forwardEndpoint', async () => {
    const fx = fixture();
    try {
      const { client } = await fx.setup({ allow: [] });
      for (const v of bad) {
        await assert.rejects(client.forwardUnix({ local: '127.0.0.1:0', remote: '127.0.0.1:1', halfCloseProbeMs: v }), { name: 'TypeError', message: /halfCloseProbeMs/ }, String(v));
        await assert.rejects(client.forwardEndpoint({ local: '127.0.0.1:0', endpoint: 'x', halfCloseProbeMs: v }), { name: 'TypeError', message: /halfCloseProbeMs/ }, String(v));
      }
    } finally { await fx.teardown(); }
  });
  it('the Node server\'s gateway', () => {
    for (const v of bad) assert.throws(() => createWshServer({ auth: { authorizedKeys: '' }, gateway: { allow: [], halfCloseProbeMs: v } }), { name: 'TypeError', message: /halfCloseProbeMs/ }, String(v));
    for (const v of [0, 1, 2000, 2 ** 31 - 1, undefined]) createWshServer({ auth: { authorizedKeys: '' }, gateway: { allow: [], halfCloseProbeMs: v } });
  });
});

void listen;
