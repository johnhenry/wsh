// test/gateway-udp.test.mjs -- #98 / #124 (the part that needs no WebTransport): OpenUdp on the Node host over the
// existing reliable control stream, with the same destination policy as TCP. One GatewayData is one datagram.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { MSG } from '@johnhenry/wsh';
import { GatewayError } from '../src/gateway-client.mjs';
import { fixture, until, sleep } from './gateway-fixture.mjs';

describe('OpenUdp on the Node host', () => {
  const fx = fixture();
  const socks = [];
  afterEach(async () => { for (const s of socks.splice(0)) { try { s.close(); } catch { /* closed */ } } await fx.teardown(); });

  async function udpServer(onMessage) {
    const s = dgram.createSocket('udp4'); socks.push(s);
    await new Promise((r) => s.bind(0, '127.0.0.1', r));
    s.on('message', (msg, rinfo) => onMessage(msg, rinfo, s));
    return s.address().port;
  }
  const echo = () => udpServer((msg, r, s) => s.send(msg, r.port, r.address));
  const readOne = async (reader) => (await reader.read()).value;

  it('round-trips a DNS-sized query and a QUIC-sized datagram, one chunk per datagram', async () => {
    const port = await echo();
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`] });
    const d = await client.openUdp('127.0.0.1', port);
    const w = d.writable.getWriter(); const r = d.readable.getReader();
    const query = Uint8Array.from({ length: 33 }, (_, i) => i);
    await w.write(query);
    assert.deepEqual(await readOne(r), query);
    const quic = Uint8Array.from({ length: 1252 }, (_, i) => (i * 7) & 255);
    await w.write(quic);
    assert.deepEqual(await readOne(r), quic);
    // Boundaries are kept: two writes are two datagrams are two reads.
    await w.write(Uint8Array.of(1, 2, 3)); await w.write(Uint8Array.of(4, 5));
    assert.deepEqual(await readOne(r), Uint8Array.of(1, 2, 3));
    assert.deepEqual(await readOne(r), Uint8Array.of(4, 5));
    d.destroy();
  });

  it('carries a large datagram, and drops one that cannot be a datagram without hurting the flow', async () => {
    const port = await echo();
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`] });
    const d = await client.openUdp('127.0.0.1', port);
    const w = d.writable.getWriter(); const r = d.readable.getReader();
    const big = new Uint8Array(8192).fill(5); // macOS loopback refuses datagrams over 9216 bytes; Linux takes 65507
    await w.write(big);
    assert.equal((await readOne(r)).length, 8192);
    await w.write(new Uint8Array(65508)); // longer than any datagram: dropped by the host
    await w.write(new Uint8Array(100)); // a normal one still works afterwards
    assert.equal((await readOne(r)).length, 100);
    d.destroy();
  });

  it('has the same destination policy as TCP: default deny, resolved address checked, no SOCKS', async () => {
    const port = await echo();
    const none = await fx.setup({ allow: ['other.example:53'] });
    await assert.rejects(none.client.openUdp('127.0.0.1', port), (e) => e instanceof GatewayError && e.code === 4);
    const star = await fx.setup({ allow: ['*'] }); // loopback is not public: refused although "*" matches the name
    await assert.rejects(star.client.openUdp('127.0.0.1', port), (e) => e instanceof GatewayError && e.code === 4);
    await assert.rejects(star.client.openUdp('localhost', port), (e) => e instanceof GatewayError && e.code === 4);
    const lit = await fx.setup({ allow: ['*'], allowPrivate: ['127.0.0.0/8'] });
    (await lit.client.openUdp('127.0.0.1', port)).destroy();
    const viaSocks = await fx.setup({ allow: ['*'], allowPrivate: ['127.0.0.0/8'], socks: '127.0.0.1:1' });
    await assert.rejects(viaSocks.client.openUdp('127.0.0.1', port), (e) => e instanceof GatewayError && /SOCKS/.test(e.message));
  });

  it('counts against maxConnections, closes idle flows, and closes when the client does', async () => {
    const port = await echo();
    const { client, inbox } = await fx.setup({ allow: [`127.0.0.1:${port}`], maxConnections: 1, udpIdleMs: 150 });
    const d = await client.openUdp('127.0.0.1', port);
    await assert.rejects(client.openUdp('127.0.0.1', port), (e) => e.code === 7);
    await Promise.race([d.closed, sleep(2000).then(() => assert.fail('idle flow was not closed'))]);
    // the slot is free again
    const d2 = await client.openUdp('127.0.0.1', port);
    d2.destroy();
    void inbox;
  });

  it('drops datagrams a stalled client cannot take instead of buffering them', async () => {
    let origin;
    const port = await udpServer((msg, r, s) => { origin = { port: r.port, address: r.address, s }; });
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`] });
    const d = await client.openUdp('127.0.0.1', port);
    await d.writable.getWriter().write(Uint8Array.of(1)); // so the origin learns the flow's address
    await until(() => origin, 'origin to see the flow');
    const before = process.memoryUsage().arrayBuffers;
    const blob = Buffer.alloc(1400, 1);
    for (let i = 0; i < 20000; i++) { origin.s.send(blob, origin.port, origin.address); if (i % 200 === 0) await sleep(1); }
    await sleep(500);
    assert.ok(process.memoryUsage().arrayBuffers - before < 40 * 1024 * 1024, 'bounded');
    d.destroy();
  });

  it('answers a raw OpenUdp to a client that does not use the high-level API (the netway shape)', async () => {
    const port = await echo();
    const { client, inbox } = await fx.setup({ allow: [`127.0.0.1:${port}`] });
    await client.sendControl({ type: MSG.OPEN_UDP, gateway_id: 3, host: '127.0.0.1', port });
    const ok = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_OK), 'ok');
    assert.equal(ok.resolved_addr, '127.0.0.1');
    await client.sendControl({ type: MSG.GATEWAY_DATA, gateway_id: 3, data: Uint8Array.of(9, 9) });
    const got = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_DATA), 'datagram');
    assert.deepEqual([...got.data], [9, 9]);
  });
});
