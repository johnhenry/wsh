// test/gateway-settle-socket.test.mjs -- a gateway connection that both sides finished by themselves closes its socket only once the
// socket's peer has taken what was handed to it, and not for ever if the peer takes nothing (the half-close idle bound).
//
// `settleSocket` is the host's end of a finished connection (src/server/gateway.mjs): before it, the socket was destroyed at once,
// which dropped what was still queued for a slow caller.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { settleSocket } from '../src/server/gateway.mjs';
import { GatewayChannel, GATEWAY_DISCARDED } from '../src/gateway-channel.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe('GatewayChannel onClose(reason, graceful)', () => {
  const make = (extra = {}) => {
    const closes = [];
    const channel = new GatewayChannel({ id: 1, sendData: () => {}, sendCredit: () => {}, sendClose: () => {}, onData: () => {}, onClose: (reason, graceful) => closes.push({ reason, graceful }), ...extra });
    return { channel, closes };
  };

  it('both sides finished by themselves: graceful, whichever closed first', () => {
    const a = make();
    a.channel.end(); a.channel.remoteClosed();
    assert.deepEqual(a.closes, [{ reason: undefined, graceful: true }]);
    const b = make();
    b.channel.remoteClosed(); b.channel.end();
    assert.deepEqual(b.closes, [{ reason: undefined, graceful: true }]);
  });

  it('a destroy, an error, the idle bound and a repeated discard are not graceful', () => {
    const a = make(); a.channel.destroy();
    const b = make(); b.channel.destroy('buffer limit exceeded');
    const c = make(); c.channel.end(); c.channel.remoteClosed(); // finished by itself ...
    const d = make(); d.channel.remoteClosed(); d.channel.remoteClosed(GATEWAY_DISCARDED); // ... a second close discarded after a half-close
    assert.deepEqual([a, b, d].map((x) => x.closes[0].graceful), [false, false, false]);
    assert.equal(c.closes[0].graceful, true);
  });

  it('a first close "discarded" is not graceful', () => {
    const { channel, closes } = make();
    channel.remoteClosed(GATEWAY_DISCARDED);
    assert.deepEqual(closes, [{ reason: GATEWAY_DISCARDED, graceful: false }]);
  });
});

describe('settleSocket', () => {
  let dir; const socks = [];
  afterEach(() => {
    for (const s of socks.splice(0)) s.destroy();
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; }
  });

  /** A connected pair over a unix socket: `host` is the side that settles, `peer` the other. */
  async function pair() {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-ss-'));
    const sock = path.join(dir, 's.sock');
    const server = net.createServer({ allowHalfOpen: true });
    const accepted = new Promise((r) => server.once('connection', r));
    await new Promise((r) => server.listen(sock, r));
    const peer = net.connect({ path: sock, allowHalfOpen: true });
    peer.on('error', () => {});
    await new Promise((r) => peer.once('connect', r));
    const host = await accepted;
    host.on('error', () => {});
    server.close();
    socks.push(host, peer);
    return { host, peer };
  }

  it('what was handed to the socket reaches a slow peer, and only then is the socket closed', async () => {
    const { host, peer } = await pair();
    const size = 4 * 1024 * 1024;
    host.write(Buffer.alloc(size, 1));
    assert.ok(host.writableLength > 0, 'a good part of it is still queued on this side');
    const closed = new Promise((r) => host.once('close', r));
    settleSocket(host, 0);
    assert.equal(host.destroyed, false, 'not destroyed with data queued');
    let n = 0;
    const ended = new Promise((r) => peer.once('end', r));
    peer.on('data', (b) => { n += b.length; peer.pause(); setTimeout(() => peer.resume(), 2); });
    await ended;
    assert.equal(n, size);
    await closed;
    assert.equal(host.destroyed, true);
  });

  it('a socket with nothing queued is closed at once', async () => {
    const { host } = await pair();
    host.write('x');
    await new Promise((r) => setTimeout(r, 20));
    settleSocket(host, 0);
    await new Promise((r) => host.once('close', r));
  });

  it('a peer that takes nothing is not waited for beyond the idle bound', async () => {
    const { host, peer } = await pair();
    peer.pause(); // reads nothing
    host.write(Buffer.alloc(8 * 1024 * 1024, 2));
    settleSocket(host, 150);
    const verdict = await Promise.race([new Promise((r) => host.once('close', () => r('closed'))), sleep(15_000).then(() => 'held')]);
    assert.equal(verdict, 'closed');
  });

  it('a peer that keeps taking data, however slowly, is not cut by the bound', async () => {
    const { host, peer } = await pair();
    const size = 512 * 1024;
    for (let i = 0; i < size; i += 65536) host.write(Buffer.alloc(65536, 3)); // as the gateway hands it over: a frame at a time
    // The bound is a fraction of the whole transfer at this pace (about a megabyte a second), but something moves inside every interval.
    settleSocket(host, 100);
    let n = 0;
    const ended = new Promise((r) => peer.once('end', r));
    peer.on('data', (b) => { n += b.length; peer.pause(); setTimeout(() => peer.resume(), 40); });
    await ended;
    assert.equal(n, size);
  });
});
