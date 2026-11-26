// test/forward-pipe-flush.test.mjs -- the forward's pipe between a local socket and a gateway connection (src/forward-node.mjs) never
// drops what it has already READ from the local socket.
//
// A reverse forward's local service that answers at length and then goes away (its complete close, or a reset when the caller's
// request reached it after it had closed) can have its socket end while the last chunks it sent are still waiting for credit
// towards the host. The socket's 'close' used to destroy the gateway connection at once, which dropped those chunks; on Linux
// the reset comes as soon as the caller's request is forwarded to a service that has already closed, so the tail was lost there
// (test/reverse-forward-full-close.test.mjs failed on CI, timing dependent). The gateway side is a fake here, with its writes held
// until the test releases them, so the order is what the test controls and nothing depends on a clock or a kernel.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pipe } from '../src/forward-node.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 5000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(5); }
}

describe('pipe: what was read from the local socket is delivered before the connection is destroyed', () => {
  let dir; const socks = [];
  afterEach(() => { for (const s of socks.splice(0)) s.destroy(); if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; } });

  /** A local socket (the forward's end, `local`) and the service behind it (`service`), and a fake gateway duplex whose writes wait for `release()`. */
  async function setup() {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-pf-'));
    const server = net.createServer({ allowHalfOpen: true }); // TCP: a reset (resetAndDestroy) is a TCP thing
    const accepted = new Promise((r) => server.once('connection', r));
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const local = net.connect({ port: server.address().port, host: '127.0.0.1', allowHalfOpen: true });
    await new Promise((r) => local.once('connect', r));
    const service = await accepted;
    server.close();
    service.on('error', () => {});
    socks.push(local, service);
    let release; const gate = new Promise((r) => { release = r; });
    const got = []; const events = [];
    let pushIn;
    const readable = new ReadableStream({ start(c) { pushIn = c; } });
    const writable = new WritableStream({
      async write(chunk) { await gate; got.push(Buffer.from(chunk)); },
      close() { events.push('half-close'); },
    });
    const duplex = { readable, writable, destroy() { events.push('destroy'); }, closed: new Promise(() => {}) };
    return { local, service, duplex, got, events, release, hostCloses: () => pushIn.close(), hostSends: (b) => pushIn.enqueue(new Uint8Array(b)) };
  }

  it('the host\'s data reaches the pipe after the service is gone: the connection is not destroyed over a chunk still waiting', async () => {
    const t = await setup();
    pipe(t.local, t.duplex);
    t.local.resume();
    await new Promise((r) => t.service.write(Buffer.alloc(1000, 4), r));
    await until(() => t.local.isPaused(), 'the pipe to read the chunk and pause for the host');
    t.service.resetAndDestroy(); // the service is gone
    await until(() => t.local.destroyed, 'the local socket to close');
    // What the caller sends now (its request, forwarded after the service closed) reaches the pipe with the socket gone.
    t.hostSends(Buffer.from('late request'));
    await sleep(50); // a negative needs a moment to be seen; the assertion below is the order, not the time
    assert.deepEqual(t.events, [], 'not destroyed while the chunk the service sent is still waiting for the host');
    t.release();
    await until(() => t.events.includes('destroy'), 'the connection to be destroyed');
    assert.equal(t.got.reduce((n, b) => n + b.length, 0), 1000, 'the chunk reached the host first');
  });

  it('a socket that is reset after it sent a chunk: the chunk is still delivered, and then the connection is destroyed', async () => {
    const t = await setup();
    pipe(t.local, t.duplex);
    t.local.resume();
    const sent = new Promise((r) => t.service.write(Buffer.alloc(1000, 9), r));
    await sent;
    await until(() => t.local.isPaused(), 'the pipe to read the chunk and pause for the host');
    t.service.resetAndDestroy();
    await until(() => t.local.destroyed, 'the local socket to close');
    assert.deepEqual(t.events, [], 'nothing destroyed while the chunk waits for the host');
    t.release();
    await until(() => t.events.includes('destroy'), 'the connection to be destroyed');
    assert.equal(t.got.reduce((n, b) => n + b.length, 0), 1000, 'the chunk reached the host first');
    assert.ok(t.got.length > 0);
  });
});
