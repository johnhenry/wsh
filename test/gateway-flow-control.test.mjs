// test/gateway-flow-control.test.mjs -- #123: gateway data is flow controlled in both directions, so a slow reader on
// either side stops its peer instead of making the host buffer without bound.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { MSG } from '@johnhenry/wsh';
import { GatewayChannel, GATEWAY_CREDIT_WINDOW, GATEWAY_MAX_FRAME } from '../src/gateway-channel.mjs';
import { GatewayConnections } from '../src/gateway-client.mjs';
import { normalizeGateway, createGatewaySession } from '../src/server/gateway.mjs';
import { fixture, until, sleep, listen } from './gateway-fixture.mjs';

const MiB = 1024 * 1024;
const frame = (n, fill = 1) => new Uint8Array(n).fill(fill);

describe('GatewayChannel (credit)', () => {
  const mk = (o = {}) => {
    const sent = { data: [], credit: [], close: [] };
    const ch = new GatewayChannel({
      id: 1, credit: true, sendData: (b) => { sent.data.push(b.byteLength); }, sendCredit: (n) => { sent.credit.push(n); }, sendClose: (r) => { sent.close.push(r); }, ...o,
    });
    return { ch, sent };
  };

  it('a writer stops at the credit it holds and resumes when the peer grants more', async () => {
    const { ch, sent } = mk({ window: 100_000 });
    let done = false;
    const w = ch.write(frame(250_000)).then(() => { done = true; });
    await sleep(30);
    assert.equal(sent.data.reduce((a, b) => a + b, 0), 100_000, 'only the window went out');
    assert.equal(done, false);
    ch.grant(100_000); await sleep(10);
    assert.equal(sent.data.reduce((a, b) => a + b, 0), 200_000);
    ch.grant(50_000); await w;
    assert.equal(sent.data.reduce((a, b) => a + b, 0), 250_000);
    assert.ok(sent.data.every((n) => n <= GATEWAY_MAX_FRAME));
  });

  it('returns credit only as the application consumes what it received', async () => {
    const { ch, sent } = mk({ window: 100_000 });
    const reader = ch.streams().readable.getReader();
    ch.receive(frame(40_000)); ch.receive(frame(40_000));
    await sleep(10);
    assert.deepEqual(sent.credit, [], 'nothing consumed yet, no credit returned');
    const a = await reader.read(); assert.equal(a.value.length, 40_000);
    assert.deepEqual(sent.credit, [], 'under half the window consumed');
    await reader.read();
    assert.deepEqual(sent.credit, [80_000], 'consumed past half the window: credit returned');
  });

  it('closes the connection of a peer that sends more than the credit it was given', () => {
    const { ch, sent } = mk({ window: 100_000 });
    ch.streams();
    ch.receive(frame(60_000)); ch.receive(frame(60_000));
    assert.equal(ch.closed, true);
    assert.deepEqual(sent.close, ['peer exceeded its credit']);
  });

  it('without credit it still bounds what a peer makes it hold, per connection and per client', () => {
    const budget = { used: 0, max: 150_000 };
    const a = mk({ credit: false, maxQueued: 100_000, budget, onData() {} });
    const b = mk({ credit: false, maxQueued: 100_000, budget, onData() {} });
    a.ch.receive(frame(90_000));
    a.ch.receive(frame(20_000));
    assert.equal(a.ch.closed, true, 'per-connection cap');
    assert.equal(budget.used, 0, 'a closed connection returns its share');
    b.ch.receive(frame(90_000));
    const c = mk({ credit: false, maxQueued: 100_000, budget, onData() {} });
    c.ch.receive(frame(90_000));
    assert.equal(c.ch.closed, true, 'per-client cap');
    assert.equal(b.ch.closed, false);
  });

  it('GatewayClose is a half-close: the closer keeps receiving until the peer closes too', async () => {
    const { ch, sent } = mk();
    const reader = ch.streams().readable.getReader();
    ch.end();
    assert.deepEqual(sent.close, [undefined]);
    await assert.rejects(ch.write(frame(10)), /closed/);
    ch.receive(frame(5));
    assert.equal((await reader.read()).value.length, 5);
    assert.equal(ch.closed, false);
    ch.remoteClosed();
    assert.equal((await reader.read()).done, true);
    assert.equal(ch.closed, true);
  });

  it('a write waiting for credit rejects when the connection ends', async () => {
    const { ch } = mk({ window: 1000 });
    const w = ch.write(frame(5000));
    await sleep(10);
    ch.destroy();
    await assert.rejects(w, /closed/);
  });
});

describe('GatewayConnections without "gateway-credit" (an older host)', () => {
  it('sends unmetered and never sends GatewayCredit', async () => {
    const sent = [];
    const gc = new GatewayConnections({ send: async (m) => { sent.push(m); }, hasFeature: (f) => f === 'gateway-unix' });
    const p = gc.openUnix('/x.sock');
    const open = sent.find((m) => m.type === MSG.OPEN_UNIX);
    gc.handle({ type: MSG.GATEWAY_OK, gateway_id: open.gateway_id });
    const d = await p;
    const w = d.writable.getWriter();
    await w.write(frame(GATEWAY_CREDIT_WINDOW * 3));
    assert.equal(sent.filter((m) => m.type === MSG.GATEWAY_DATA).reduce((a, m) => a + m.data.length, 0), GATEWAY_CREDIT_WINDOW * 3);
    const r = d.readable.getReader();
    gc.handle({ type: MSG.GATEWAY_DATA, gateway_id: open.gateway_id, data: frame(GATEWAY_CREDIT_WINDOW) });
    await r.read();
    assert.equal(sent.some((m) => m.type === MSG.GATEWAY_CREDIT), false);
  });
});

describe('host buffering is bounded', () => {
  const fx = fixture();
  afterEach(() => fx.teardown());

  it('a fast origin and a stalled client: the origin is held back and memory stays flat (host -> client)', async () => {
    let written = 0;
    let originSock;
    const origin = net.createServer((s) => {
      originSock = s; s.on('error', () => {});
      const chunk = Buffer.alloc(64 * 1024, 7);
      const pump = () => { while (written < 2048 * MiB && s.write(chunk)) written += chunk.length; if (written < 2048 * MiB) { written += chunk.length; s.once('drain', pump); } };
      pump();
    });
    const originPort = await listen(origin); fx.nets.push(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${originPort}`] });
    const before = process.memoryUsage();
    const duplex = await client.openTcp('127.0.0.1', originPort);
    // The client never reads `duplex.readable`.
    await sleep(1500);
    const w1 = written;
    await sleep(1000);
    const w2 = written;
    const after = process.memoryUsage();
    assert.ok(w2 - w1 < 1 * MiB, `the origin made no progress while the client was stalled (${w2 - w1} bytes in 1s)`);
    assert.ok(w2 < 24 * MiB, `the origin could push only what buffers hold: ${(w2 / MiB).toFixed(1)} MiB of 2048`);
    const grown = (after.rss - before.rss) / MiB;
    assert.ok(grown < 80, `memory stayed flat: rss grew ${grown.toFixed(1)} MiB`);
    assert.ok(after.arrayBuffers - before.arrayBuffers < 40 * MiB, 'buffers stayed flat');
    // Reading resumes the flow.
    const reader = duplex.readable.getReader();
    let got = 0;
    while (got < 8 * MiB) { const { value, done } = await reader.read(); if (done) break; got += value.length; }
    assert.ok(got >= 8 * MiB, 'reading drains it, and the origin makes progress again');
    assert.ok(written > w2, 'origin progressed after the client read');
    duplex.destroy(); originSock?.destroy();
  });

  it('a stalled origin and a fast client: the client is held back and the host buffers little (client -> host)', async () => {
    const origin = net.createServer((s) => { s.pause(); s.on('error', () => {}); }); // accepts and never reads
    const originPort = await listen(origin); fx.nets.push(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${originPort}`] });
    const duplex = await client.openTcp('127.0.0.1', originPort);
    const writer = duplex.writable.getWriter();
    let sent = 0;
    let stalled = false;
    const chunk = frame(64 * 1024);
    const before = process.memoryUsage();
    const pumping = (async () => { for (let i = 0; i < 32768 && !stalled; i++) { await writer.write(chunk); sent += chunk.length; } })().catch(() => {});
    await sleep(1500);
    const s1 = sent;
    await sleep(1000);
    stalled = sent === s1;
    const after = process.memoryUsage();
    assert.equal(stalled, true, 'the client\'s writes block once the host has no credit to give');
    assert.ok(sent < 32 * MiB, `only what the kernel and the window hold went through: ${(sent / MiB).toFixed(1)} MiB of 2048`);
    assert.ok((after.rss - before.rss) / MiB < 80, 'memory stayed flat');
    duplex.destroy();
    await pumping;
  });

  /** A gateway session talking to a fake peer that does not offer credit (an older client). */
  async function oldPeerSession(extra = {}, send = null) {
    const out = [];
    const cfg = normalizeGateway({ allow: ['127.0.0.1'], allowPrivate: ['127.0.0.0/8'], ...extra });
    const s = createGatewaySession(cfg, send ?? ((m) => { out.push(m); }), () => {});
    s.setPeerFeatures([]);
    return { s, out };
  }

  it('an older client (no credit) and a slow link: the origin is held back by the transport instead of buffered', async () => {
    let written = 0;
    const origin = net.createServer((sock) => {
      sock.on('error', () => {});
      const chunk = Buffer.alloc(64 * 1024, 3);
      const pump = () => { while (written < 2048 * MiB && sock.write(chunk)) written += chunk.length; if (written < 2048 * MiB) { written += chunk.length; sock.once('drain', pump); } };
      pump();
    });
    const originPort = await listen(origin); fx.nets.push(origin);
    let frames = 0;
    const { s } = await oldPeerSession({}, (m) => { if (m.type === MSG.GATEWAY_DATA) { frames++; return new Promise(() => {}); } return undefined; }); // the transport never accepts
    await s.handle({ type: MSG.OPEN_TCP, gateway_id: 1, host: '127.0.0.1', port: originPort });
    await sleep(1200);
    assert.equal(frames, 1, 'one frame is waiting on the transport; nothing else was read from the origin to queue behind it');
    assert.ok(written < 24 * MiB, `origin held back: ${(written / MiB).toFixed(1)} MiB`);
    s.close();
  });

  it('an older client (no credit) cannot make the host buffer past the caps: the connection is closed', async () => {
    const origin = net.createServer((sock) => { sock.pause(); sock.on('error', () => {}); });
    const originPort = await listen(origin); fx.nets.push(origin);
    const { s, out } = await oldPeerSession({ maxBufferedBytes: GATEWAY_CREDIT_WINDOW, maxClientBufferedBytes: GATEWAY_CREDIT_WINDOW });
    await s.handle({ type: MSG.OPEN_TCP, gateway_id: 1, host: '127.0.0.1', port: originPort });
    assert.ok(out.find((m) => m.type === MSG.GATEWAY_OK));
    const chunk = frame(64 * 1024);
    let peak = 0;
    for (let i = 0; i < 4096 && !out.some((m) => m.type === MSG.GATEWAY_CLOSE); i++) {
      await s.handle({ type: MSG.GATEWAY_DATA, gateway_id: 1, data: chunk });
      peak = Math.max(peak, s.bufferedBytes);
      if (i % 16 === 0) await sleep(1); // let the kernel buffers fill
    }
    const close = out.find((m) => m.type === MSG.GATEWAY_CLOSE);
    assert.ok(close, 'the host closed the connection');
    assert.equal(close.reason, 'buffer limit exceeded');
    assert.ok(peak <= GATEWAY_CREDIT_WINDOW, `buffered at most the cap (${peak})`);
    assert.equal(s.size, 0);
  });

  it('with credit, a peer that ignores it is closed (host side)', async () => {
    const origin = net.createServer((sock) => { sock.on('error', () => {}); sock.resume(); });
    const originPort = await listen(origin); fx.nets.push(origin);
    const out = [];
    const s = createGatewaySession(normalizeGateway({ allow: ['127.0.0.1'], allowPrivate: ['127.0.0.0/8'] }), (m) => { out.push(m); }, () => {});
    s.setPeerFeatures(['gateway-credit']);
    await s.handle({ type: MSG.OPEN_TCP, gateway_id: 1, host: '127.0.0.1', port: originPort });
    for (let i = 0; i < 8; i++) await s.handle({ type: MSG.GATEWAY_DATA, gateway_id: 1, data: frame(64 * 1024) }); // 512 KiB > the 256 KiB window
    const close = out.find((m) => m.type === MSG.GATEWAY_CLOSE);
    assert.equal(close?.reason, 'peer exceeded its credit');
  });

  it('with credit, the host returns credit as the origin takes data, so a large transfer completes', async () => {
    const total = 24 * MiB;
    let received = 0;
    const origin = net.createServer((sock) => { sock.on('data', (d) => { received += d.length; }); sock.on('error', () => {}); });
    const originPort = await listen(origin); fx.nets.push(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${originPort}`] });
    const duplex = await client.openTcp('127.0.0.1', originPort);
    const w = duplex.writable.getWriter();
    const chunk = frame(256 * 1024, 9);
    for (let n = 0; n < total; n += chunk.length) await w.write(chunk);
    await until(() => received >= total, 'origin to receive everything', 15000);
    assert.equal(received, total);
    duplex.destroy();
  });

  it('the cap options are validated', () => {
    assert.throws(() => normalizeGateway({ allow: ['*'], maxBufferedBytes: 1000 }), /maxBufferedBytes/);
    assert.throws(() => normalizeGateway({ allow: ['*'], maxBufferedBytes: 4 * MiB, maxClientBufferedBytes: 1 * MiB }), /maxClientBufferedBytes/);
  });
});
