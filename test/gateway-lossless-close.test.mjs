// test/gateway-lossless-close.test.mjs -- #286: `gateway-lossless-close`, the lossless way to say "I will read nothing more and send nothing more;
// deliver what you already have, in order, then finish" (the reason `released` on a GatewayClose), and what it makes possible: the side that holds an
// ANSWERING socket (an origin the host dialled, the local service of a reverse forward) is watched like the caller side is (#282), and a connection whose
// answering peer half-closed and vanished is freed, while one that sent its whole answer and closed completely loses nothing.
//
// This file: the channel (the rule itself, on a mocked clock where time matters), the negotiation, the host and the client against real sockets
// (unix and TCP, a slow reader, 3 MiB), and the pairings with a side that did not state the feature. The relays are in test/relay-gateway.test.mjs and
// test/rust/*; the converted regression tests of #283 are in test/half-close-probe.test.mjs.
import { describe, it, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createWshServer } from '@johnhenry/wsh/server';
import { normalizeGateway } from '@johnhenry/wsh/gateway';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { GatewayChannel, GATEWAY_RELEASED, GATEWAY_DISCARDED, GATEWAY_LOSSLESS_FEATURE } from '../src/gateway-channel.mjs';
import { halfCloseWatchCount, watchHalfClosed, answeringKeepAliveMs } from '../src/half-close-watch.mjs';
import { until, listen } from './gateway-fixture.mjs';

const CHILD = fileURLToPath(new URL('./half-close-probe-child.mjs', import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const bytes = (n, v = 1) => new Uint8Array(n).fill(v);

function make(o = {}) {
  const sent = { data: [], close: [], credit: [] };
  const ch = new GatewayChannel({
    id: 1, credit: false, writeAfterRemoteClose: true, lossless: true,
    sendData: async (b) => { sent.data.push(b); },
    sendCredit: (n) => { sent.credit.push(n); },
    sendClose: (r) => { sent.close.push(r); },
    ...o,
  });
  return { ch, sent };
}
async function readAll(ch) {
  const reader = ch.streams().readable.getReader();
  const got = [];
  for (;;) { const { value, done } = await reader.read(); if (done) break; got.push(value); }
  return got;
}

describe('the feature and the reason', () => {
  it('are named as the spec says', () => {
    assert.equal(GATEWAY_LOSSLESS_FEATURE, 'gateway-lossless-close');
    assert.equal(GATEWAY_RELEASED, 'released');
  });
});

describe('GatewayChannel: a peer that released the connection', () => {
  it('as a second close: what it had sent is still delivered, in order, then the connection ends; nothing goes back and writes fail', async () => {
    const { ch, sent } = make();
    ch.receive(bytes(10, 1)); ch.receive(bytes(20, 2)); ch.receive(bytes(30, 3));
    ch.remoteClosed(undefined); // the peer's end of file: a half-close
    ch.remoteClosed(GATEWAY_RELEASED); // and then it released the connection
    await assert.rejects(ch.write(bytes(1)), /closed/, 'it reads nothing more: our writes fail');
    const got = await readAll(ch);
    assert.deepEqual(got.map((c) => [c.length, c[0]]), [[10, 1], [20, 2], [30, 3]]);
    assert.equal(await ch.closedPromise, GATEWAY_RELEASED);
    assert.deepEqual(sent.close, [], 'nothing is sent back');
  });

  it('after a first close of "discarded" a second one with "released" changes nothing (the connection stays a discard)', async () => {
    let graceful;
    const { ch } = make({ onClose: (_r, g) => { graceful = g; } });
    ch.receive(bytes(10));
    ch.remoteClosed(GATEWAY_DISCARDED);
    ch.remoteClosed(GATEWAY_RELEASED);
    await readAll(ch);
    assert.notEqual(await ch.closedPromise, GATEWAY_RELEASED);
    assert.equal(graceful, false, 'not a graceful finish');
  });

  it('as a first close: the same', async () => {
    const { ch, sent } = make();
    ch.receive(bytes(5, 9));
    ch.remoteClosed(GATEWAY_RELEASED);
    await assert.rejects(ch.write(bytes(1)), /closed/);
    assert.deepEqual((await readAll(ch)).map((c) => c.length), [5]);
    assert.equal(await ch.closedPromise, GATEWAY_RELEASED);
    assert.deepEqual(sent.close, []);
  });

  it('with nothing queued it ends at once', async () => {
    const { ch } = make();
    ch.remoteClosed(undefined);
    ch.remoteClosed(GATEWAY_RELEASED);
    assert.equal(await ch.closedPromise, GATEWAY_RELEASED);
  });

  it('a slow reader gets the whole tail: a second close does not drop what was received and not yet read', async () => {
    const { ch } = make();
    for (let i = 0; i < 50; i++) ch.receive(bytes(1000, i % 250));
    ch.remoteClosed(undefined);
    ch.remoteClosed(GATEWAY_RELEASED);
    const reader = ch.streams().readable.getReader();
    let n = 0;
    for (;;) { const { value, done } = await reader.read(); if (done) break; n += value.length; await sleep(1); }
    assert.equal(n, 50_000);
  });

  it('is what `discarded` is not: the same second close with "discarded" drops the queue', async () => {
    const { ch } = make();
    ch.receive(bytes(100));
    ch.remoteClosed(undefined);
    ch.remoteClosed(GATEWAY_DISCARDED);
    assert.equal(await ch.closedPromise, GATEWAY_DISCARDED);
    assert.equal(ch.queuedBytes, 0);
  });

  it('a side that did not state the feature treats it as an ordinary close: a half-close first, nothing as a second', async () => {
    const { ch, sent } = make({ lossless: false });
    ch.receive(bytes(10));
    ch.remoteClosed(GATEWAY_RELEASED);
    await ch.write(bytes(3)); // still writable: a half-close
    assert.equal(sent.data.length, 1);
    ch.remoteClosed(GATEWAY_RELEASED); // a repeated close with an unknown reason is ignored
    assert.equal(ch.closed, false);
    ch.end();
    assert.deepEqual(await readAll(ch).then((c) => c.map((x) => x.length)), [10]);
  });

  it('a reader that never reads does not hold the connection for ever: the idle bound ends it', async () => {
    mock.timers.reset();
    mock.timers.enable({ apis: ['setTimeout', 'Date'] });
    try {
      const { ch } = make({ halfCloseIdleMs: 60_000 });
      ch.receive(bytes(10));
      ch.remoteClosed(undefined);
      ch.remoteClosed(GATEWAY_RELEASED);
      assert.equal(ch.closed, false, 'still delivering');
      mock.timers.tick(61_000);
      assert.equal(ch.closed, true);
    } finally { mock.timers.reset(); }
  });
});

describe('GatewayChannel: releasing a connection', () => {
  afterEach(() => mock.timers.reset());

  it('after our own end of file: one more close with the reason, and the connection is over', async () => {
    const { ch, sent } = make();
    ch.end(); // the answering side's end of file, passed on as a half-close
    assert.deepEqual(sent.close, [undefined]);
    ch.release();
    assert.deepEqual(sent.close, [undefined, GATEWAY_RELEASED]);
    assert.equal(await ch.closedPromise, GATEWAY_RELEASED);
    ch.release(); ch.destroy();
    assert.equal(sent.close.length, 2, 'nothing more');
  });

  it('before any close of ours: the reason goes as the first close', async () => {
    const { ch, sent } = make();
    ch.release();
    assert.deepEqual(sent.close, [GATEWAY_RELEASED]);
    assert.equal(await ch.closedPromise, GATEWAY_RELEASED);
  });

  it('when the peer has closed too: the connection is over and nothing is sent', async () => {
    const { ch, sent } = make();
    ch.end();
    ch.remoteClosed(undefined);
    assert.equal(ch.closed, true);
    ch.release();
    assert.deepEqual(sent.close, [undefined]);
  });

  it('against a peer that did not state the feature it is a discard, as it always was (and is never what a caller does)', async () => {
    const { ch, sent } = make({ lossless: false });
    ch.end();
    ch.release();
    assert.deepEqual(sent.close, [undefined, GATEWAY_DISCARDED]);
  });
});

// ── a remote answering socket gets a longer keep-alive than a loopback or unix one ──────────────────────────────────────────────────────
describe('the keep-alive of a half-closed answering socket (#286)', () => {
  const fake = (remoteAddress) => {
    const calls = [];
    const handlers = {};
    return {
      calls, remoteAddress, readableEnded: false, destroyed: false, writableEnded: false, connecting: false, writableLength: 0, writableNeedDrain: false,
      on(ev, fn) { handlers[ev] = fn; return this; }, once(ev, fn) { handlers[ev] = fn; return this; },
      setKeepAlive(...a) { calls.push(a); }, write(_b, cb) { cb?.(); }, destroy() { this.destroyed = true; },
      emit(ev) { handlers[ev]?.(); },
    };
  };

  it('a loopback or unix socket keeps the short schedule, a remote one the longer; only once it is half-closed', () => {
    for (const [addr, remote, want] of [['127.0.0.1', 30_000, 2000], ['::1', 30_000, 2000], ['::ffff:127.0.0.1', 30_000, 2000], [undefined, 30_000, 2000], ['203.0.113.7', 30_000, 30_000], ['2001:db8::1', 45_000, 45_000]]) {
      assert.equal(answeringKeepAliveMs({ remoteAddress: addr }, 2000, remote), want, `${addr}`);
      const s = fake(addr);
      watchHalfClosed(s, 2000, undefined, answeringKeepAliveMs(s, 2000, remote));
      assert.deepEqual(s.calls, [], 'nothing is touched before the peer half-closes');
      s.emit('end');
      if (addr === undefined) assert.deepEqual(s.calls, [], 'a unix socket has no keep-alive');
      else assert.deepEqual(s.calls, [[true, want, want, 3]]);
    }
  });

  it('is an option of the host and of a reverse forward, validated like the other millisecond options', () => {
    assert.equal(normalizeGateway({ allow: [] }).halfCloseProbeRemoteMs, 30_000);
    assert.equal(normalizeGateway({ allow: [], halfCloseProbeRemoteMs: 90_000 }).halfCloseProbeRemoteMs, 90_000);
    assert.throws(() => normalizeGateway({ allow: [], halfCloseProbeRemoteMs: -1 }), /halfCloseProbeRemoteMs/);
    assert.throws(() => normalizeGateway({ allow: [], halfCloseProbeRemoteMs: 1.5 }), /halfCloseProbeRemoteMs/);
  });
});

// ── the host and the client against real sockets ──────────────────────────────────────────────────────────────────────────────────────

describe('the answering side is watched, and nothing is lost (#286)', () => {
  let dir; const procs = []; const nets = []; const servers = []; const clients = []; const forwards = [];
  const tmp = () => { dir ??= fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-ll-')); return fs.realpathSync(dir); };
  afterEach(async () => {
    for (const p of procs.splice(0)) p.kill('SIGKILL');
    for (const f of forwards.splice(0)) await f.close().catch(() => {});
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
    for (const n of nets.splice(0)) n.close();
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; } // a directory this test made
  });
  const SIZE = 3 * 1024 * 1024;
  const stateAfter = (p, ms) => Promise.race([p, sleep(ms).then(() => 'open')]);
  const BOUND = 30_000;

  /** A host with `gateway`, and a client of it with `connectOptions`. */
  async function setup(gateway, connectOptions = {}) {
    const keyPair = await generateKeyPair(true);
    const server = createWshServer({ auth: { authorizedKeys: `${await exportPublicKeySSH(keyPair.publicKey)} u` }, gateway: { halfCloseIdleMs: 0, halfCloseProbeMs: 50, ...gateway } });
    const { port } = await server.listen(); servers.push(server);
    const client = new WshClient();
    await client.connect(`ws://127.0.0.1:${port}`, { username: 'u', keyPair, ...connectOptions });
    clients.push(client);
    return { client, server };
  }
  /** A slow reader: a pause after every chunk, so that when the end of the answer reaches it much of what is left is still queued. */
  const readAllSlow = async (d) => { const r = d.readable.getReader(); let n = 0; for (;;) { const { value, done } = await r.read(); if (done) return n; n += value.length; await sleep(10); } };
  /** A child process that is an origin which half-closes at once (an origin that finished); see test/half-close-probe-child.mjs. */
  async function childOrigin(kind, target, flag) {
    const child = spawn(process.execPath, [CHILD, 'server', kind, ...(target ? [target] : []), ...(flag ? [flag] : [])], { stdio: ['ignore', 'pipe', 'inherit'] });
    procs.push(child);
    const lines = []; let buf = '';
    const listening = new Promise((resolve) => child.stdout.on('data', (d) => { buf += d; for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1); } if (lines.some((l) => l.startsWith('listening'))) resolve(); }));
    await listening;
    return { child, lines, endpoint: lines.find((l) => l.startsWith('listening')).split(' ')[1] };
  }
  const kill = (child) => new Promise((r) => { child.once('exit', r); child.kill('SIGKILL'); });

  it('the feature is stated by the host and the client, and a side can decline to state it', async () => {
    const { client } = await setup({ allow: [] });
    assert.ok(client.hasFeature(GATEWAY_LOSSLESS_FEATURE));
    const declined = await setup({ allow: [], losslessClose: false });
    assert.equal(declined.client.hasFeature(GATEWAY_LOSSLESS_FEATURE), false);
    assert.throws(() => normalizeGateway({ allow: [], losslessClose: 'yes' }), /losslessClose must be a boolean/);
    assert.throws(() => normalizeGateway({ allow: [], halfCloseProbeAnswers: 1 }), /halfCloseProbeAnswers must be a boolean/);
    await assert.rejects(new WshClient().connect('ws://127.0.0.1:1', { username: 'u', keyPair: await generateKeyPair(true), gatewayLosslessClose: 'no' }), /gatewayLosslessClose must be a boolean/);
  });

  it('a unix ORIGIN that sent everything and closed completely: a slow client gets every byte, and the connection is freed by itself afterwards', async () => {
    const sock = path.join(tmp(), 'o.sock');
    const origin = net.createServer((s) => { s.on('error', () => {}); s.end(Buffer.alloc(SIZE, 5), () => s.destroy()); });
    await new Promise((r) => origin.listen(sock, r)); nets.push(origin);
    const { client } = await setup({ allow: [], unix: { connect: [sock] } });
    const d = await client.openUnix(sock);
    await sleep(1000); // the origin is long gone; what it sent is mostly unread
    assert.equal(await stateAfter(d.closed, 0), 'open', 'held for the reader');
    // The host reads the origin only as fast as the client takes it, so its end of file (which starts the watch) comes while the client is reading.
    const reading = readAllSlow(d);
    await until(() => halfCloseWatchCount() >= 1, 'the origin to be watched');
    assert.equal(await reading, SIZE, 'every byte');
    // Nobody closed it: the host noticed the origin was gone and released the connection once the client had taken what was sent.
    assert.equal(await stateAfter(d.closed, BOUND), GATEWAY_RELEASED);
  });

  // A TCP origin that sends 3 MiB and then CLOSES CLEANLY cannot be proved released in bounded time: its kernel keeps the half-closed socket for about a
  // minute before a keep-alive probe reports it (the Node probe test file covers that minute). A reset is reported at once, so the same connection proves both
  // halves: every byte arrives (a slow reader), and when the origin then resets the host releases the connection by itself.
  it('a TCP ORIGIN that sent 3 MiB: every byte arrives, and when it then vanishes with a reset the connection is released by itself', async () => {
    const socks = [];
    const origin = net.createServer((s) => { s.on('error', () => {}); socks.push(s); s.end(Buffer.alloc(SIZE, 6)); });
    const port = await listen(origin); nets.push(origin);
    const { client } = await setup({ allow: [`127.0.0.1:${port}`] });
    const d = await client.openTcp('127.0.0.1', port);
    await sleep(500);
    assert.equal(await readAllSlow(d), SIZE);
    assert.equal(await stateAfter(d.closed, 300), 'open', 'a half-closed origin that is alive is held');
    socks[0].resetAndDestroy();
    assert.equal(await stateAfter(d.closed, BOUND), GATEWAY_RELEASED);
  });

  it('a unix origin that half-closed and then vanished (killed) is noticed within the probe bound and the connection freed; the slot is usable again', async () => {
    const sock = path.join(tmp(), 'k.sock');
    const { child, lines } = await childOrigin('unix', sock);
    const { client } = await setup({ allow: [], unix: { connect: [sock] }, maxConnections: 1 });
    const d = await client.openUnix(sock);
    await until(() => lines.includes('accepted'), 'the origin to have accepted and half-closed');
    assert.equal(await stateAfter(d.closed, 400), 'open', 'a half-closed origin that is alive is held');
    const t0 = Date.now();
    await kill(child);
    assert.equal(await stateAfter(d.closed, BOUND), GATEWAY_RELEASED, `released ${Date.now() - t0} ms after the kill`);
    // the host's only slot is free again
    const child2 = await childOrigin('unix', path.join(tmp(), 'k2.sock'));
    assert.ok(child2.child);
  });

  it('a TCP origin killed with data unread (reset at once) is noticed within a probe interval', async () => {
    const { child, lines, endpoint } = await childOrigin('tcp', undefined, 'paused');
    const { client } = await setup({ allow: [`127.0.0.1:${endpoint}`] });
    const d = await client.openTcp('127.0.0.1', Number(endpoint));
    await until(() => lines.includes('accepted'), 'the origin to have accepted and half-closed');
    const w = d.writable.getWriter();
    await Promise.race([w.write(new Uint8Array(300_000)).catch(() => {}), sleep(3000)]); // unread by the origin
    await kill(child);
    assert.equal(await stateAfter(d.closed, BOUND), GATEWAY_RELEASED);
  });

  for (const [what, gateway, connectOptions] of [
    ['a client that did not state the feature', {}, { gatewayLosslessClose: false }],
    ['a host that did not state the feature', { losslessClose: false }, {}],
    ['halfCloseProbeAnswers: false on the host (negotiated, and switched off)', { halfCloseProbeAnswers: false }, {}],
    ['halfCloseProbeMs: 0 (every probe off)', { halfCloseProbeMs: 0 }, {}],
  ]) {
    it(`${what}: exactly today's behaviour: the origin is not watched, a vanished one is held, and one that closed completely loses nothing`, async () => {
      const sock = path.join(tmp(), 'u.sock');
      const { child, lines } = await childOrigin('unix', sock);
      const { client } = await setup({ allow: [], unix: { connect: [sock] }, ...gateway }, connectOptions);
      const before = halfCloseWatchCount();
      const d = await client.openUnix(sock);
      await until(() => lines.includes('accepted'), 'the origin to have accepted and half-closed');
      await kill(child);
      assert.equal(await stateAfter(d.closed, 1500), 'open', 'not noticed: held until the idle bound or the client');
      assert.equal(halfCloseWatchCount(), before, 'nothing was probed');
      // and a server that sent everything and closed completely: every byte
      const sock2 = path.join(tmp(), 'v.sock');
      const origin = net.createServer((s) => { s.on('error', () => {}); s.end(Buffer.alloc(SIZE, 7), () => s.destroy()); });
      await new Promise((r) => origin.listen(sock2, r)); nets.push(origin);
      const other = await setup({ allow: [], unix: { connect: [sock2] }, ...gateway }, connectOptions);
      const d2 = await other.client.openUnix(sock2);
      await sleep(500);
      assert.equal(await readAllSlow(d2), SIZE);
      d2.destroy();
      d.destroy();
    });
  }

  it('a client that released the connection: what it sent is delivered to the caller of its reverse listener whole, whatever the caller sends after the release', async () => {
    const hostSock = path.join(tmp(), 'lr.sock');
    const { client } = await setup({ allow: [], unix: { listen: [hostSock] } });
    const opened = [];
    await client.listenUnix(hostSock, { onConnection: (d) => { opened.push(d); } });
    const caller = net.connect({ path: hostSock, allowHalfOpen: true });
    caller.on('error', () => {});
    caller.pause(); // reads nothing yet: what the host writes to it queues on the host beyond the kernel's buffers
    await until(() => opened.length === 1, 'the connection');
    const w = opened[0].writable.getWriter();
    let sent = 0;
    for (let i = 0; i < 4; i++) { await w.write(new Uint8Array(64 * 1024).fill(i + 1)); sent += 64 * 1024; } // the whole credit window
    opened[0].release(); // the client's service is gone: nothing more is read or sent
    caller.write('x'); // the caller's request body, still uploading
    await sleep(300); // the host reads it and (before the fix) destroyed the socket with the tail unflushed
    let got = 0;
    const ended = new Promise((r) => caller.once('end', r));
    caller.on('data', (b) => { got += b.length; });
    caller.resume();
    assert.equal(await stateAfter(ended, BOUND).then((v) => (v === 'open' ? 'open' : 'ended')), 'ended');
    assert.equal(got, sent, 'every byte the client sent reached the caller');
    caller.destroy();
  });

  describe('the local service of a reverse forward', () => {
    it('that sent everything and closed completely: a slow caller gets every byte and the connection ends by itself', async () => {
      const hostSock = path.join(tmp(), 'r.sock');
      // a unix service: its complete close is a hang-up at once (a TCP service's is only seen a minute later), so the release really happens
      const svcSock = path.join(tmp(), 'svc1.sock');
      const service = net.createServer((s) => { s.on('error', () => {}); s.end(Buffer.alloc(SIZE, 8), () => s.destroy()); });
      await new Promise((r) => service.listen(svcSock, r)); nets.push(service);
      const { client } = await setup({ allow: [], unix: { listen: [hostSock] } });
      forwards.push(await client.forwardUnix({ local: svcSock, remote: hostSock, reverse: true, halfCloseProbeMs: 50 }));
      const caller = net.connect({ path: hostSock, allowHalfOpen: true });
      caller.on('error', () => {});
      caller.pause();
      await sleep(1000);
      let n = 0;
      caller.on('data', (b) => { n += b.length; caller.pause(); setTimeout(() => caller.resume(), 10); });
      const ended = new Promise((r) => caller.once('end', r));
      caller.resume();
      await ended;
      assert.equal(n, SIZE);
      // The caller's `end` also comes on the service's FIRST close, watched or not. What the release adds, and what proves the service WAS watched, is that
      // the host then ends the connection by itself: it closes its socket completely (a mere half-close would leave a write from the caller succeeding).
      await until(() => { if (!caller.destroyed) caller.write('x', () => {}); return caller.destroyed; }, 'the host to close the connection completely', BOUND);
      caller.destroy();
    });

    it('that half-closed and then vanished is noticed, and its caller is told by the connection ending (what it was sent is delivered first)', async () => {
      const hostSock = path.join(tmp(), 'r2.sock');
      const svcSock = path.join(tmp(), 's.sock');
      const { child, lines } = await childOrigin('unix', svcSock);
      // the host's only connection slot is the caller's: a slot that is free again says the host released the caller's connection
      const other = net.createServer((s) => { s.on('error', () => {}); s.resume(); });
      const otherPort = await listen(other); nets.push(other);
      const { client } = await setup({ allow: [`127.0.0.1:${otherPort}`], unix: { listen: [hostSock] }, maxConnections: 1 });
      const slotFree = async () => { try { (await client.openTcp('127.0.0.1', otherPort)).destroy(); return true; } catch (e) { if (/too many/.test(e.message)) return false; throw e; } };
      forwards.push(await client.forwardUnix({ local: svcSock, remote: hostSock, reverse: true, halfCloseProbeMs: 50 }));
      const caller = net.connect({ path: hostSock, allowHalfOpen: true });
      caller.on('error', () => {});
      caller.resume();
      await until(() => lines.includes('accepted'), 'the service to have taken the connection and half-closed');
      await sleep(400);
      assert.equal(await slotFree(), false, 'a half-closed service that is alive is held: the caller still holds the host\'s slot');
      await kill(child);
      await until(() => slotFree(), 'the host to release the connection', BOUND);
      caller.destroy();
    });

    it('against a host that did not state the feature, or with halfCloseProbeAnswers: false: not watched, as before', async () => {
      for (const [gateway, forwardOptions] of [[{ losslessClose: false }, {}], [{}, { halfCloseProbeAnswers: false }]]) {
        const hostSock = path.join(tmp(), `n${Math.random().toString(36).slice(2, 6)}.sock`);
        const service = net.createServer((s) => { s.on('error', () => {}); s.end(Buffer.alloc(SIZE, 9), () => s.destroy()); });
        const servicePort = await listen(service); nets.push(service);
        const { client } = await setup({ allow: [], unix: { listen: [hostSock] }, ...gateway });
        const before = halfCloseWatchCount();
        forwards.push(await client.forwardUnix({ local: `127.0.0.1:${servicePort}`, remote: hostSock, reverse: true, halfCloseProbeMs: 50, ...forwardOptions }));
        const caller = net.connect({ path: hostSock, allowHalfOpen: true });
        caller.on('error', () => {});
        let n = 0;
        const ended = new Promise((r) => caller.once('end', r));
        caller.on('data', (b) => { n += b.length; });
        await ended;
        assert.equal(n, SIZE);
        assert.equal(halfCloseWatchCount(), before, 'the service was not probed');
        caller.destroy();
      }
    });
  });
});
