// test/half-close-watch-unhandled.test.mjs -- #319: the half-close watch (src/half-close-watch.mjs) leaves nothing unhandled when its socket is gone.
//
// The watch holds one interval timer, a zero-length probe write whose callback arrives later, and a keep-alive call, all on a socket that
// can be destroyed by somebody else at any moment. Whatever the order (the socket closes while the probe write is held, the timer fires
// after the socket is destroyed but before 'close', the write throws, the caller's `onGone` throws or rejects), the process must see no
// `unhandledRejection` and no `uncaughtException`, `onGone` must run at most once and never after the socket closed, and no timer may
// outlive the watch. The test runner starts every file with `--unhandled-rejections=strict`, so a miss here also ends this process.
//
// Fake sockets with mocked interval timers where the order matters (the exact moment is the point); real unix and TCP sockets, with the
// peer killed, for the end to end behaviour; `pipe` (src/forward-node.mjs) for the chain of a held write behind a vanished peer.
import { describe, it, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { watchHalfClosed, halfCloseWatchCount, LOCAL_PEER_GONE } from '../src/half-close-watch.mjs';
import { pipe } from '../src/forward-node.mjs';
import { fixture, sleep, listen } from './gateway-fixture.mjs';

/** Run `fn` with a process-wide hook on `unhandledRejection`/`uncaughtException`; resolve with what was raised after a few macrotasks. */
async function raised(fn) {
  const seen = [];
  const hook = (e) => seen.push(e);
  process.on('unhandledRejection', hook);
  process.on('uncaughtException', hook);
  try {
    await fn();
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    await new Promise((r) => setTimeout(r, 30));
  } finally {
    process.off('unhandledRejection', hook);
    process.off('uncaughtException', hook);
  }
  return seen;
}
const tick = () => new Promise((r) => setImmediate(r));
const coded = (code) => Object.assign(new Error(code), { code });

/** The members of a `net.Socket` the watch reads, with the probe write held until the test settles it. */
function fakeSocket({ remoteAddress } = {}) {
  const s = new EventEmitter();
  Object.assign(s, { destroyed: false, writableEnded: false, connecting: false, writableLength: 0, writableNeedDrain: false, readableEnded: false, remoteAddress });
  s.writes = [];
  s.keepAlive = [];
  s.destroys = 0;
  s.write = (buf, cb) => { s.writes.push({ buf, cb }); return true; };
  s.setKeepAlive = (...a) => { s.keepAlive.push(a); };
  s.destroy = () => { s.destroys++; if (s.destroyed) return s; s.destroyed = true; setImmediate(() => s.emit('close')); return s; };
  /** The socket closes (somebody else destroyed it): destroyed at once, 'close' as the event. */
  s.vanish = () => { s.destroyed = true; s.emit('close'); };
  return s;
}

describe('the half-close watch with a fake socket and mocked interval timers (#319)', () => {
  afterEach(() => { mock.timers.reset(); });
  const arm = (s, probeMs, onGone, keepAliveMs) => { watchHalfClosed(s, probeMs, onGone, keepAliveMs); s.emit('end'); };

  it('the socket closes while the probe write is held, then the write fails with EPIPE: onGone is not called, nothing is raised, nothing is left running', async () => {
    mock.timers.enable({ apis: ['setInterval'] });
    const s = fakeSocket(); const gone = [];
    const seen = await raised(async () => {
      arm(s, 50, (e) => gone.push(e));
      assert.equal(halfCloseWatchCount(), 1);
      mock.timers.tick(50);
      assert.equal(s.writes.length, 1, 'the probe write is held');
      s.vanish();
      assert.equal(halfCloseWatchCount(), 0);
      s.writes[0].cb(coded('EPIPE'));
      await tick();
      mock.timers.tick(500);
    });
    assert.deepEqual(seen, []);
    assert.deepEqual(gone, []);
    assert.equal(s.writes.length, 1, 'no probe after the close');
    assert.equal(s.destroys, 0);
  });

  it('the probe write fails with EPIPE or ECONNRESET while the socket is open: onGone once, WSH_LOCAL_PEER_GONE, socket destroyed once; a second failure and later ticks do nothing', async () => {
    for (const code of ['EPIPE', 'ECONNRESET']) {
      mock.timers.enable({ apis: ['setInterval'] });
      const s = fakeSocket(); const gone = [];
      const seen = await raised(async () => {
        arm(s, 50, (e) => gone.push(e));
        mock.timers.tick(50);
        s.writes[0].cb(coded(code));
        s.writes[0].cb(coded(code)); // a duplicate callback
        await tick();
        mock.timers.tick(500);
      });
      assert.deepEqual(seen, [], code);
      assert.equal(gone.length, 1, code);
      assert.equal(gone[0].code, LOCAL_PEER_GONE);
      assert.equal(gone[0].cause.code, code);
      assert.equal(s.destroys, 1, code);
      assert.equal(s.writes.length, 1, `${code}: no probe after the verdict`);
      assert.equal(halfCloseWatchCount(), 0);
      mock.timers.reset();
    }
  });

  it('a probe failure that says "already closed" (ERR_STREAM_DESTROYED, ERR_STREAM_WRITE_AFTER_END) is somebody else\'s doing: no onGone, no destroy', async () => {
    mock.timers.enable({ apis: ['setInterval'] });
    const s = fakeSocket(); const gone = [];
    const seen = await raised(async () => {
      arm(s, 50, (e) => gone.push(e));
      mock.timers.tick(50);
      s.writes[0].cb(coded('ERR_STREAM_DESTROYED'));
      s.writes[0].cb(coded('ERR_STREAM_WRITE_AFTER_END'));
      await tick();
    });
    assert.deepEqual(seen, []);
    assert.deepEqual(gone, []);
    assert.equal(s.destroys, 0);
    s.vanish();
  });

  it('the write throws in the timer callback (EPIPE-coded, or not coded at all): contained, never an uncaughtException', async () => {
    for (const thrown of [coded('EPIPE'), new Error('boom'), 'a string']) {
      mock.timers.enable({ apis: ['setInterval'] });
      const s = fakeSocket(); const gone = [];
      s.write = () => { throw thrown; };
      const seen = await raised(async () => {
        arm(s, 50, (e) => gone.push(e));
        mock.timers.tick(50);
        await tick();
      });
      assert.deepEqual(seen, [], String(thrown));
      assert.equal(gone.length, thrown?.code === 'EPIPE' ? 1 : 0, String(thrown));
      s.vanish();
      mock.timers.reset();
    }
  });

  it('the timer fires after the socket was destroyed but before its close event: no write, the watch ends, no timer is left', async () => {
    mock.timers.enable({ apis: ['setInterval'] });
    const s = fakeSocket(); const gone = [];
    const seen = await raised(async () => {
      arm(s, 50, (e) => gone.push(e));
      s.destroyed = true; // destroyed, 'close' still to come
      mock.timers.tick(50);
      assert.equal(halfCloseWatchCount(), 0);
      mock.timers.tick(500);
      s.emit('close');
    });
    assert.deepEqual(seen, []);
    assert.deepEqual(gone, []);
    assert.equal(s.writes.length, 0);
  });

  it('the peer\'s end of file arrives after the socket closed or was destroyed: nothing is armed (no timer, no keep-alive)', async () => {
    mock.timers.enable({ apis: ['setInterval'] });
    const closed = fakeSocket({ remoteAddress: '127.0.0.1' });
    const destroyed = fakeSocket({ remoteAddress: '127.0.0.1' });
    const seen = await raised(async () => {
      watchHalfClosed(closed, 50, () => {}); closed.vanish(); closed.emit('end');
      watchHalfClosed(destroyed, 50, () => {}); destroyed.destroyed = true; destroyed.emit('end');
      mock.timers.tick(500);
    });
    assert.deepEqual(seen, []);
    assert.equal(halfCloseWatchCount(), 0);
    assert.deepEqual(closed.keepAlive, []);
    assert.deepEqual(destroyed.keepAlive, []);
    assert.equal(closed.writes.length + destroyed.writes.length, 0);
  });

  it('setKeepAlive throws (the platform refused, or the handle is gone): the probe still runs and nothing is raised', async () => {
    mock.timers.enable({ apis: ['setInterval'] });
    const s = fakeSocket({ remoteAddress: '127.0.0.1' }); const gone = [];
    s.setKeepAlive = () => { throw new Error('EBADF'); };
    const seen = await raised(async () => {
      arm(s, 50, (e) => gone.push(e));
      mock.timers.tick(50);
      assert.equal(s.writes.length, 1);
      s.writes[0].cb(coded('ECONNRESET'));
    });
    assert.deepEqual(seen, []);
    assert.equal(gone.length, 1);
  });

  it('onGone throws: contained, and the socket is still destroyed', async () => {
    mock.timers.enable({ apis: ['setInterval'] });
    const s = fakeSocket();
    const seen = await raised(async () => {
      arm(s, 50, () => { throw new Error('the caller\'s callback threw'); });
      mock.timers.tick(50);
      s.writes[0].cb(coded('EPIPE'));
    });
    assert.deepEqual(seen, []);
    assert.equal(s.destroys, 1);
  });

  it('onGone is an async function that rejects (what a caller\'s onError may be): the rejection is contained, the socket is still destroyed', async () => {
    mock.timers.enable({ apis: ['setInterval'] });
    const s = fakeSocket();
    const seen = await raised(async () => {
      arm(s, 50, async () => { throw new Error('the caller\'s async callback rejected'); });
      mock.timers.tick(50);
      s.writes[0].cb(coded('EPIPE'));
    });
    assert.deepEqual(seen, []);
    assert.equal(s.destroys, 1);
  });

  it('a probe that is skipped (a write is queued, the socket needs drain, is ended or connecting) writes nothing and raises nothing', async () => {
    mock.timers.enable({ apis: ['setInterval'] });
    const s = fakeSocket();
    const seen = await raised(async () => {
      arm(s, 50, () => {});
      for (const patch of [{ writableLength: 5 }, { writableNeedDrain: true }, { writableEnded: true }, { connecting: true }]) {
        Object.assign(s, { writableLength: 0, writableNeedDrain: false, writableEnded: false, connecting: false }, patch);
        mock.timers.tick(50);
      }
    });
    assert.deepEqual(seen, []);
    assert.equal(s.writes.length, 0);
    s.vanish();
  });
});

describe('the half-close watch on real sockets, the peer going away (#319)', () => {
  const cleanup = [];
  afterEach(() => { for (const f of cleanup.splice(0)) { try { f(); } catch { /* already gone */ } } });

  /** A connected pair over a unix socket or TCP loopback; `server` is the side that is watched (half-open allowed, its own 'error' handled, as every caller does). */
  async function pair(kind) {
    let dir; let target;
    if (kind === 'unix') { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-319-')); target = { path: path.join(dir, 's.sock') }; }
    const srv = net.createServer({ allowHalfOpen: true });
    const accepted = new Promise((r) => srv.once('connection', r));
    await new Promise((r) => srv.listen(kind === 'unix' ? target : { port: 0, host: '127.0.0.1' }, r));
    const client = net.connect(kind === 'unix' ? target : { port: srv.address().port, host: '127.0.0.1' });
    client.on('error', () => {});
    const server = await accepted;
    server.on('error', () => {});
    cleanup.push(() => { client.destroy(); server.destroy(); srv.close(); if (dir) fs.rmSync(dir, { recursive: true, force: true }); });
    return { client, server };
  }

  for (const kind of ['unix', 'tcp']) {
    it(`${kind}: the peer half-closes and is killed: onGone once, the socket is destroyed, no timer remains, nothing is raised`, async () => {
      const { client, server } = await pair(kind);
      const gone = [];
      const seen = await raised(async () => {
        // TCP: a peer is only reported at once when it dies with data unread (it answers a reset), so the server sends something the client never reads.
        if (kind === 'tcp') server.write(Buffer.alloc(100_000));
        server.pause();
        await new Promise((r) => client.end(r));
        watchHalfClosed(server, 20, (e) => gone.push(e));
        server.resume(); // reads the end of file: the watch starts
        await new Promise((r) => setTimeout(r, 60));
        assert.equal(halfCloseWatchCount(), 1, 'watching');
        if (kind === 'tcp') client.resetAndDestroy(); else client.destroy();
        const t0 = Date.now();
        while (!server.destroyed && Date.now() - t0 < 10_000) await new Promise((r) => setTimeout(r, 10));
        assert.ok(server.destroyed, 'the watched socket was destroyed');
        await new Promise((r) => setTimeout(r, 100)); // several probe intervals: a timer left running would show here
      });
      assert.deepEqual(seen, []);
      assert.equal(gone.length, 1);
      assert.equal(gone[0].code, LOCAL_PEER_GONE);
      assert.equal(halfCloseWatchCount(), 0);
    });
  }

  it('the watched socket is destroyed by its owner at the moment the probe is due: nothing is raised, the watch is gone', async () => {
    const { client, server } = await pair('unix');
    const gone = [];
    const seen = await raised(async () => {
      watchHalfClosed(server, 5, (e) => gone.push(e));
      server.resume();
      await new Promise((r) => client.end(r));
      for (let i = 0; i < 20; i++) { await new Promise((r) => setTimeout(r, 1)); }
      server.destroy();
      await new Promise((r) => setTimeout(r, 40));
    });
    assert.deepEqual(seen, []);
    assert.deepEqual(gone, []);
    assert.equal(halfCloseWatchCount(), 0);
  });
});

describe('forward-node pipe: the chain behind a half-closed socket whose peer went away (#319)', () => {
  const cleanup = [];
  afterEach(() => { for (const f of cleanup.splice(0)) { try { f(); } catch { /* already gone */ } } });

  /** A gateway duplex whose writes are held until the test settles them. */
  function heldDuplex() {
    const writes = []; const calls = [];
    const duplex = {
      readable: new ReadableStream({ pull() { return new Promise(() => {}); } }),
      writable: new WritableStream({ write() { return new Promise((resolve, reject) => { writes.push({ resolve, reject }); }); } }),
      closed: new Promise(() => {}),
      peerReleased: false,
      destroy: () => { calls.push('destroy'); },
      release: () => { calls.push('release'); },
    };
    return { duplex, writes, calls };
  }

  it('a chunk is being written to the host (held), the local socket is reset, then the write fails: the connection is destroyed once, nothing is raised', async () => {
    const srv = net.createServer({ allowHalfOpen: true });
    const accepted = new Promise((r) => srv.once('connection', r));
    await new Promise((r) => srv.listen({ port: 0, host: '127.0.0.1' }, r));
    const client = net.connect({ port: srv.address().port, host: '127.0.0.1' });
    client.on('error', () => {});
    const sock = await accepted;
    cleanup.push(() => { client.destroy(); sock.destroy(); srv.close(); });
    const { duplex, writes, calls } = heldDuplex();
    const reports = [];
    const seen = await raised(async () => {
      pipe(sock, duplex, { probeMs: 10, onGone: (e) => reports.push(e) });
      client.write('hello');
      const t0 = Date.now();
      while (writes.length === 0 && Date.now() - t0 < 5000) await new Promise((r) => setTimeout(r, 5));
      assert.equal(writes.length, 1, 'the write to the host is held');
      client.end();
      await new Promise((r) => setTimeout(r, 30));
      client.resetAndDestroy();
      await new Promise((r) => setTimeout(r, 60));
      writes[0].reject(new Error('transport closed'));
      await new Promise((r) => setTimeout(r, 40));
    });
    assert.deepEqual(seen, []);
    assert.deepEqual(calls, ['destroy']);
    assert.equal(halfCloseWatchCount(), 0);
  });

  it('answering, the local service finished and vanished while the write is held, then the write fails: released at most once, nothing is raised', async () => {
    const srv = net.createServer({ allowHalfOpen: true });
    const accepted = new Promise((r) => srv.once('connection', r));
    await new Promise((r) => srv.listen({ port: 0, host: '127.0.0.1' }, r));
    const client = net.connect({ port: srv.address().port, host: '127.0.0.1' });
    client.on('error', () => {});
    const sock = await accepted;
    cleanup.push(() => { client.destroy(); sock.destroy(); srv.close(); });
    const { duplex, writes, calls } = heldDuplex();
    const seen = await raised(async () => {
      pipe(sock, duplex, { probeMs: 10, answering: true });
      client.write('hello');
      const t0 = Date.now();
      while (writes.length === 0 && Date.now() - t0 < 5000) await new Promise((r) => setTimeout(r, 5));
      client.end();
      await new Promise((r) => setTimeout(r, 30));
      client.resetAndDestroy();
      await new Promise((r) => setTimeout(r, 60));
      writes[0].resolve();
      await new Promise((r) => setTimeout(r, 40));
    });
    assert.deepEqual(seen, []);
    assert.ok(calls.length <= 1 && calls.every((c) => c === 'release' || c === 'destroy'), JSON.stringify(calls));
  });
});

describe('forward: an async onError that rejects does not take the process down (#319)', () => {
  const fx = fixture();
  const forwards = []; const socks = [];
  afterEach(async () => {
    for (const s of socks.splice(0)) s.destroy();
    for (const f of forwards.splice(0)) await f.close().catch(() => {});
    await fx.teardown();
  });

  it('the host refuses the connection (the forward reports it) and then the local peer is killed after a half-close: both reports go to an async onError that rejects; nothing is raised', async () => {
    // An origin the host may reach, which never answers: the forward is up, then the local program half-closes and dies.
    const origin = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.resume(); });
    const oport = await listen(origin); fx.nets.push(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${oport}`] });
    const reports = [];
    const onError = async (e) => { reports.push(e); throw new Error('the caller\'s async onError rejected'); };
    const seen = await raised(async () => {
      // 1. A refused destination: open() rejects, the forward reports it.
      const refused = await client.forwardUnix({ local: '127.0.0.1:0', remote: '127.0.0.1:9', onError, halfCloseProbeMs: 20 });
      forwards.push(refused);
      const a = net.connect({ host: '127.0.0.1', port: refused.address.port }); a.on('error', () => {}); socks.push(a);
      const t0 = Date.now();
      while (reports.length === 0 && Date.now() - t0 < 5000) await sleep(10);
      assert.ok(reports.length >= 1, 'the refusal was reported');
      // 2. A local program that half-closes and is reset: the watch reports it through the same callback.
      const ok = await client.forwardUnix({ local: '127.0.0.1:0', remote: `127.0.0.1:${oport}`, onError, halfCloseProbeMs: 20 });
      forwards.push(ok);
      const b = net.connect({ host: '127.0.0.1', port: ok.address.port }); b.on('error', () => {}); socks.push(b);
      await new Promise((r) => b.once('connect', r));
      b.write(Buffer.alloc(1000));
      await sleep(100);
      b.end();
      await sleep(100);
      b.resetAndDestroy();
      await sleep(300);
    });
    assert.deepEqual(seen, []);
  });
});
