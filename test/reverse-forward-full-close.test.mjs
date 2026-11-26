// test/reverse-forward-full-close.test.mjs -- a reverse forward whose local service answers at length and then closes
// COMPLETELY at once, after the caller had already half-closed, delivers the whole answer.
//
// Before: the forward's local socket closing for good (its end of file read, its own write side ended because the host's
// close had arrived) was taken as "the connection is gone" and the connection was destroyed, which drops what is still
// queued for the host (data waiting for credit) and what the caller has not read yet: the caller saw a clean end of the
// stream, short by the tail of the answer.
//
// Nothing is slept for: the service sends its answer and closes, the caller reads slowly (so the answer is mostly queued when
// the service is long gone) and the assertion is the number of bytes that arrived.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fixture, sleep, until, listen } from './gateway-fixture.mjs';

const SIZE = 3 * 1024 * 1024;

describe('a reverse forward whose service answers at length and closes completely, after the caller half-closed', () => {
  let dir; const forwards = [];
  const fx = fixture();
  const tmp = () => { dir ??= fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-rf-')); return fs.realpathSync(dir); };
  afterEach(async () => {
    for (const f of forwards.splice(0)) await f.close().catch(() => {});
    await fx.teardown();
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; }
  });

  /**
   * `serve(socket)` is the service; the caller connects to the host's unix socket, sends `request`, half-closes and reads the
   * whole answer slowly. Resolves with the bytes it got and how its stream ended.
   */
  async function run({ serve, probe }) {
    const hostSock = path.join(tmp(), 'r.sock');
    const service = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); serve(s); });
    const servicePort = await listen(service); fx.nets.push(service);
    const { client } = await fx.setup({ allow: [], unix: { listen: [hostSock] }, halfCloseIdleMs: 0, halfCloseProbeMs: probe });
    forwards.push(await client.forwardUnix({ local: `127.0.0.1:${servicePort}`, remote: hostSock, reverse: true, halfCloseProbeMs: probe }));
    const caller = net.connect({ path: hostSock, allowHalfOpen: true });
    caller.on('error', () => {});
    let n = 0;
    const ended = new Promise((r) => caller.once('close', r));
    caller.on('data', (b) => { n += b.length; caller.pause(); setTimeout(() => caller.resume(), 5); }); // a slow reader
    caller.end('request'); // the caller has nothing more to send: half-closed from the start
    // Bounded so that a regression fails with the byte count instead of hanging.
    const verdict = await Promise.race([ended.then(() => 'ended'), sleep(20_000).then(() => 'still open')]);
    caller.destroy();
    assert.equal(verdict, 'ended', `the caller's stream did not end; it had ${n} of ${SIZE} bytes`);
    return n;
  }

  // The service closes at once, with everything written: its FIN follows the data, then the socket goes.
  const sendAndClose = (s) => { s.end(Buffer.alloc(SIZE, 7), () => s.destroy()); };

  it('every byte arrives (the probe on)', async () => {
    assert.equal(await run({ serve: sendAndClose, probe: 200 }), SIZE);
  });

  it('every byte arrives (the probe off)', async () => {
    assert.equal(await run({ serve: sendAndClose, probe: 0 }), SIZE);
  });

  it('every byte arrives when the service waits for the request first', async () => {
    const serve = (s) => { s.once('end', () => sendAndClose(s)); s.resume(); };
    assert.equal(await run({ serve, probe: 0 }), SIZE);
  });

  it('a service that is reset in the middle of its answer ends the connection and the caller does not hang', async () => {
    const serve = (s) => { s.write(Buffer.alloc(200_000, 1), () => s.resetAndDestroy()); };
    const n = await run({ serve, probe: 0 });
    assert.ok(n <= 200_000, `got ${n}`);
  });

  it('the same holds for an origin the host dialled: the client half-closed, the origin sends everything and closes completely', async () => {
    const origin = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.once('end', () => sendAndClose(s)); s.resume(); });
    const originPort = await listen(origin); fx.nets.push(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${originPort}`], halfCloseIdleMs: 0 });
    const d = await client.openTcp('127.0.0.1', originPort);
    await d.writable.getWriter().close(); // half-closed: the origin answers on seeing it
    const r = d.readable.getReader();
    let n = 0;
    for (;;) { const { value, done } = await r.read(); if (done) break; n += value.length; await sleep(5); } // a slow reader
    assert.equal(n, SIZE);
  });

  it('the caller going away ends the connection and the service is closed (nothing is held)', async () => {
    const hostSock = path.join(tmp(), 'g.sock');
    const served = [];
    const service = net.createServer({ allowHalfOpen: true }, (s) => { served.push(s); s.on('error', () => {}); s.on('end', () => s.end()); s.resume(); });
    const servicePort = await listen(service); fx.nets.push(service);
    const { client } = await fx.setup({ allow: [], unix: { listen: [hostSock] }, halfCloseIdleMs: 0, halfCloseProbeMs: 0 });
    const fwd = await client.forwardUnix({ local: `127.0.0.1:${servicePort}`, remote: hostSock, reverse: true, halfCloseProbeMs: 0 });
    forwards.push(fwd);
    const caller = net.connect({ path: hostSock });
    caller.on('error', () => {});
    await new Promise((r) => caller.once('connect', r));
    await until(() => served.length, 'the service to be dialled');
    caller.destroy();
    await until(() => fwd.connections === 0, 'the connection to be released');
    assert.equal(served[0].destroyed, true);
  });
});
