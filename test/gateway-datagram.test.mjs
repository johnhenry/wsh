// test/gateway-datagram.test.mjs -- #124: UDP flows as WebTransport datagrams. A real HTTP/3 connection from the stock client to the Node
// host, a real UDP echo server on loopback. Needs the optional native WebTransport packages (skipped, with the reason, where
// they cannot run). The datagram format and the limiter are unit-tested first (no network).
import { describe, it, afterEach, after } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { GatewayConnections, GatewayError } from '../src/gateway-client.mjs';
import { encodeDatagram, decodeDatagram, TokenBucket, DATAGRAM_HEADER_BYTES, GATEWAY_DATAGRAM_FEATURE } from '../src/gateway-datagram.mjs';
import { WebTransportTransport } from '../src/transport.mjs';
import { normalizeGateway } from '../src/server/gateway.mjs';
import { generateSelfSignedCertificate } from '../src/server/self-signed.mjs';
import { until, sleep } from './gateway-fixture.mjs';

describe('datagram format and limiter', () => {
  it('a datagram is a 4-byte big-endian flow id and then the payload', () => {
    const d = encodeDatagram(0x40000001, Uint8Array.of(1, 2, 3));
    assert.deepEqual([...d], [0x40, 0, 0, 1, 1, 2, 3]);
    assert.equal(DATAGRAM_HEADER_BYTES, 4);
    const back = decodeDatagram(d);
    assert.equal(back.id, 0x40000001);
    assert.deepEqual([...back.payload], [1, 2, 3]);
    assert.deepEqual([...decodeDatagram(encodeDatagram(7, new Uint8Array(0))).payload], [], 'an empty UDP payload is a valid datagram');
    assert.equal(decodeDatagram(Uint8Array.of(1, 2, 3)), null, 'shorter than the header');
    assert.equal(decodeDatagram('x'), null);
  });

  it('a token bucket allows its burst, refuses beyond it, and refills with time', () => {
    let t = 0;
    const b = new TokenBucket(10, 5, () => t);
    for (let i = 0; i < 5; i++) assert.equal(b.take(), true);
    assert.equal(b.take(), false);
    t += 100; assert.equal(b.take(), true); assert.equal(b.take(), false); // 10/s: one token per 100 ms
    t += 10_000; for (let i = 0; i < 5; i++) assert.equal(b.take(), true); assert.equal(b.take(), false, 'never above the burst');
    assert.equal(new TokenBucket(Infinity).take(1e9), true);
    assert.equal(new TokenBucket(100, 100, () => 0).take(101), false, 'a cost above the burst never passes');
  });

  it('the gateway.udp options are validated', () => {
    const udp = (o) => normalizeGateway({ allow: [], udp: o }).udp;
    assert.equal(udp(undefined).maxFlows, 16);
    assert.equal(udp({}).oversize, 'reliable');
    for (const bad of [{ maxFlows: -1 }, { oversize: 'x' }, { packetsPerSecondPerFlow: 0 }, { bytesPerSecondPerClient: NaN }]) assert.throws(() => udp(bad), /gateway\.udp/);
    assert.equal(udp({ packetsPerSecondPerFlow: Infinity }).packetsPerSecondPerFlow, Infinity);
  });
});

let wtLib = null;
let skipReason = false;
try {
  wtLib = await import('@fails-components/webtransport');
  await wtLib.quicheLoaded;
  const probe = generateSelfSignedCertificate();
  const s = new wtLib.Http3Server({ port: 0, host: '127.0.0.1', secret: 'probe', cert: probe.cert, privKey: probe.privKey });
  s.startServer();
  await s.ready;
  s.stopServer();
} catch (err) {
  skipReason = `the native WebTransport packages are unavailable (${String(err?.message ?? err).split('\n')[0]})`;
}
if (skipReason) console.log(`# gateway-datagram: network tests skipped: ${skipReason}`);

const savedWT = globalThis.WebTransport;
if (wtLib) globalThis.WebTransport = wtLib.WebTransport; // Node has no WebTransport global; the stock client uses the platform one
after(() => { globalThis.WebTransport = savedWT; });

describe('UDP over WebTransport datagrams', { skip: skipReason }, () => {
  const servers = []; const clients = []; const socks = [];
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
    for (const s of socks.splice(0)) { try { s.close(); } catch { /* closed */ } }
  });

  /** A UDP server on loopback; `reply(msg)` decides the answer (default: the same bytes). */
  async function udpServer(reply = (m) => m) {
    const s = dgram.createSocket('udp4'); socks.push(s);
    await new Promise((r) => s.bind(0, '127.0.0.1', r));
    s.on('message', (msg, r) => { const a = reply(msg); if (a) s.send(a, r.port, r.address); });
    return s.address().port;
  }

  async function setup(gateway, { transport = 'wt', onLog = () => {} } = {}) {
    const keyPair = await generateKeyPair(true);
    const line = `${await exportPublicKeySSH(keyPair.publicKey)} alice`;
    const server = createWshServer({ auth: { authorizedKeys: line }, gateway, webTransport: { selfSigned: true }, onLog });
    const { port } = await server.listen(); servers.push(server);
    const wt = server.webTransport();
    const client = new WshClient();
    if (transport === 'wt') {
      await client.connect(wt.url, { username: 'alice', keyPair, transport: 'wt', webTransport: { serverCertificateHashes: [{ algorithm: 'sha-256', value: wt.certificateHash }] } });
    } else {
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
    }
    clients.push(client);
    return { client, server };
  }
  const readOne = async (flow) => { const r = flow.readable.getReader(); const v = (await r.read()).value; r.releaseLock(); return v; };
  const pattern = (n, k = 7) => Uint8Array.from({ length: n }, (_, i) => (i * k) & 255);

  it('is negotiated on WebTransport only, and the flow says which path it uses', async () => {
    const port = await udpServer();
    const wt = await setup({ allow: [`127.0.0.1:${port}`] });
    assert.ok(wt.client.hasFeature(GATEWAY_DATAGRAM_FEATURE));
    const flow = await wt.client.openUdp('127.0.0.1', port);
    assert.equal(flow.transport, 'datagram');
    assert.ok(flow.maxDatagramSize > 500 && flow.maxDatagramSize < 65507, `reads maxDatagramSize from the transport, not an assumed MTU: ${flow.maxDatagramSize}`);
    flow.destroy();
    const ws = await setup({ allow: [`127.0.0.1:${port}`] }, { transport: 'ws' });
    assert.equal(ws.client.hasFeature(GATEWAY_DATAGRAM_FEATURE), false, 'a WebSocket connection has no datagrams');
    const f2 = await ws.client.openUdp('127.0.0.1', port);
    assert.equal(f2.transport, 'stream');
    f2.destroy();
  });

  it('a host with datagrams switched off, or an older client, keeps the reliable path', async () => {
    const port = await udpServer();
    const off = await setup({ allow: [`127.0.0.1:${port}`], udp: { datagrams: false } });
    assert.equal(off.client.hasFeature(GATEWAY_DATAGRAM_FEATURE), false);
    const f = await off.client.openUdp('127.0.0.1', port);
    assert.equal(f.transport, 'stream');
    await f.send(Uint8Array.of(1, 2, 3));
    assert.deepEqual([...await readOne(f)], [1, 2, 3]);
    f.destroy();
  });

  it('round-trips a DNS-sized query and answer as datagrams, then a datagram near the datagram limit', async () => {
    const port = await udpServer();
    const { client, server } = await setup({ allow: [`127.0.0.1:${port}`] });
    const flow = await client.openUdp('127.0.0.1', port);
    const query = pattern(33);
    assert.equal(await flow.send(query), true);
    assert.deepEqual(await readOne(flow), query);
    const big = pattern(flow.maxDatagramSize); // as large as one datagram can carry
    await flow.send(big);
    assert.deepEqual(await readOne(flow), big);
    const s = server.gatewayStats().udp;
    assert.equal(s.datagramsFromClient, 2); assert.equal(s.datagramsToClient, 2);
    assert.equal(s.reliableFromClient + s.reliableToClient, 0, 'nothing used the control stream');
    assert.deepEqual([flow.stats.sent, flow.stats.received, flow.stats.sentReliable], [2, 2, 0]);
    flow.destroy();
  });

  it('a 1252-byte QUIC-sized datagram round-trips whichever way it has to travel (a datagram if it fits, else the reliable stream)', async () => {
    const port = await udpServer();
    const { client, server } = await setup({ allow: [`127.0.0.1:${port}`] });
    const flow = await client.openUdp('127.0.0.1', port);
    const quic = pattern(1252, 13);
    await flow.send(quic);
    assert.deepEqual(await readOne(flow), quic);
    const s = server.gatewayStats().udp;
    if (flow.maxDatagramSize >= 1252) assert.equal(s.oversizeReliable, 0); else assert.ok(s.oversizeReliable >= 1 && flow.stats.sentReliable === 1, JSON.stringify([s, flow.stats]));
    flow.destroy();
  });

  it('a payload over the datagram limit goes on the reliable stream by default, both directions, and arrives intact', async () => {
    const port = await udpServer();
    const { client, server } = await setup({ allow: [`127.0.0.1:${port}`] });
    const flow = await client.openUdp('127.0.0.1', port);
    const big = pattern(flow.maxDatagramSize + 500, 5);
    await flow.send(big);
    assert.deepEqual(await readOne(flow), big);
    assert.equal(flow.stats.sentReliable, 1);
    assert.equal(server.gatewayStats().udp.oversizeReliable, 1);
    flow.destroy();
  });

  it('with oversize "drop": the sender gets a RangeError, and an oversize reply is dropped and counted', async () => {
    const port = await udpServer((m) => (m.length === 1 ? Buffer.alloc(4000, 9) : m));
    const { client, server } = await setup({ allow: [`127.0.0.1:${port}`], udp: { oversize: 'drop' } });
    const flow = await client.openUdp('127.0.0.1', port, { oversize: 'drop' });
    await assert.rejects(flow.send(new Uint8Array(flow.maxDatagramSize + 1)), RangeError);
    assert.equal(flow.stats.sendDropped, 1);
    await assert.rejects(flow.send(new Uint8Array(65508)), RangeError, 'nothing is larger than a UDP payload');
    await flow.send(Uint8Array.of(1)); // the origin answers with 4000 bytes: no datagram holds that
    await until(() => server.gatewayStats().udp.oversizeDropped === 1, 'the oversize reply to be dropped');
    await flow.send(Uint8Array.of(1, 2)); // the flow is fine
    assert.deepEqual([...await readOne(flow)], [1, 2]);
    flow.destroy();
  });

  it('loss on one flow does not delay or disturb another (datagrams are dropped by a shim, nothing is retransmitted)', async () => {
    const port = await udpServer();
    const { client } = await setup({ allow: [`127.0.0.1:${port}`] });
    const lossy = await client.openUdp('127.0.0.1', port);
    const clean = await client.openUdp('127.0.0.1', port);
    // The shim: every datagram of `lossy` coming back from the host is lost.
    const orig = GatewayConnections.prototype.handleDatagram;
    const lostId = lossy.channel.id;
    let lost = 0;
    GatewayConnections.prototype.handleDatagram = function (bytes) {
      if (decodeDatagram(bytes)?.id === lostId) { lost++; return; }
      return orig.call(this, bytes);
    };
    try {
      const reader = clean.readable.getReader();
      for (let i = 0; i < 20; i++) await lossy.send(Uint8Array.of(i));
      const rtts = [];
      for (let i = 0; i < 20; i++) {
        const t0 = performance.now();
        await clean.send(Uint8Array.of(100 + i));
        const { value } = await reader.read();
        rtts.push(performance.now() - t0);
        assert.deepEqual([...value], [100 + i]);
      }
      assert.ok(Math.max(...rtts) < 1000, `the clean flow is never held up (slowest ${Math.max(...rtts).toFixed(1)} ms)`);
      await until(() => lost === 20, 'all lossy replies to be lost');
      assert.equal(lossy.stats.received, 0, 'and none of them were retransmitted to the lossy flow');
      await sleep(300);
      assert.equal(lost, 20, 'no retransmissions arrived');
    } finally { GatewayConnections.prototype.handleDatagram = orig; }
    lossy.destroy(); clean.destroy();
  });

  it('loss toward the host (client datagrams dropped on the way) loses exactly those datagrams', async () => {
    const seen = [];
    const port = await udpServer((m) => { seen.push(m[0]); return m; });
    const { client } = await setup({ allow: [`127.0.0.1:${port}`] });
    const flow = await client.openUdp('127.0.0.1', port);
    const orig = WebTransportTransport.prototype.sendDatagram;
    WebTransportTransport.prototype.sendDatagram = function (bytes) { return bytes[4] % 2 === 0 ? false : orig.call(this, bytes); }; // the even ones are lost
    try {
      for (let i = 0; i < 10; i++) { await flow.send(Uint8Array.of(i)); await sleep(5); }
      await until(() => seen.length >= 5, 'the surviving datagrams to arrive');
      await sleep(200);
      assert.deepEqual(seen, [1, 3, 5, 7, 9]);
      assert.equal(flow.stats.sendDropped, 5, 'the sender is told (false) about each local drop');
    } finally { WebTransportTransport.prototype.sendDatagram = orig; }
    flow.destroy();
  });

  describe('bounds', () => {
    it('rate-limits a flow: a burst beyond packetsPerSecondPerFlow is dropped and counted, not queued', async () => {
      const port = await udpServer();
      const { client, server } = await setup({ allow: [`127.0.0.1:${port}`], udp: { packetsPerSecondPerFlow: 10 } });
      const flow = await client.openUdp('127.0.0.1', port);
      for (let i = 0; i < 300; i++) await flow.send(Uint8Array.of(i & 255));
      await sleep(500);
      const s = server.gatewayStats().udp;
      assert.ok(s.rateDropped > 200, `most of a 300-datagram burst is dropped at 10/s (dropped ${s.rateDropped})`);
      assert.ok(s.datagramsFromClient < 100);
      flow.destroy();
    });

    it('rate-limits a client across flows (packets), and bounds bytes per second, in both directions', async () => {
      const port = await udpServer();
      const a = await setup({ allow: [`127.0.0.1:${port}`], udp: { packetsPerSecondPerClient: 20 } });
      const f1 = await a.client.openUdp('127.0.0.1', port); const f2 = await a.client.openUdp('127.0.0.1', port);
      for (let i = 0; i < 100; i++) { await f1.send(Uint8Array.of(1)); await f2.send(Uint8Array.of(2)); }
      await sleep(400);
      assert.ok(a.server.gatewayStats().udp.rateDropped > 100, JSON.stringify(a.server.gatewayStats().udp));
      const bigPort = await udpServer(() => Buffer.alloc(1000, 1)); // a 1-byte query makes a 1000-byte answer: amplification
      const b = await setup({ allow: [`127.0.0.1:${bigPort}`], udp: { bytesPerSecondPerClient: 20_000, packetsPerSecondPerClient: Infinity, packetsPerSecondPerFlow: Infinity } });
      const f3 = await b.client.openUdp('127.0.0.1', bigPort);
      let answers = 0;
      const reader = f3.readable.getReader();
      (async () => { for (;;) { const r = await reader.read(); if (r.done) break; answers++; } })();
      for (let i = 0; i < 200; i++) { await f3.send(Uint8Array.of(1)); }
      await sleep(600);
      assert.ok(answers * 1000 < 65_536 + 20_000, `bytes toward the client are bounded (${answers} answers of 1000 bytes arrived out of 200)`);
      assert.ok(b.server.gatewayStats().udp.rateDropped > 0);
      f1.destroy(); f2.destroy(); f3.destroy();
    });

    it('limits flows per client', async () => {
      const port = await udpServer();
      const { client } = await setup({ allow: [`127.0.0.1:${port}`], udp: { maxFlows: 2 } });
      const a = await client.openUdp('127.0.0.1', port); await client.openUdp('127.0.0.1', port);
      await assert.rejects(client.openUdp('127.0.0.1', port), (e) => e instanceof GatewayError && e.code === 7 && /too many UDP flows \(limit 2\)/.test(e.message));
      a.destroy();
      await until(async () => { try { (await client.openUdp('127.0.0.1', port)); return true; } catch { return false; } }, 'a slot to free');
    });

    it('closes an idle flow', async () => {
      const port = await udpServer();
      const { client } = await setup({ allow: [`127.0.0.1:${port}`], udpIdleMs: 200 });
      const flow = await client.openUdp('127.0.0.1', port);
      assert.equal(await Promise.race([flow.closed.then(() => 'closed'), sleep(3000).then(() => 'open')]), 'closed');
      await assert.rejects(flow.send(Uint8Array.of(1)));
    });
  });

  describe('policy: one destination, never an open relay', () => {
    it('refuses a loopback destination by default (the address policy), and a name that is not allowed', async () => {
      const port = await udpServer();
      const { client } = await setup({ allow: ['*'] });
      await assert.rejects(client.openUdp('127.0.0.1', port), (e) => e instanceof GatewayError && e.code === 4, 'loopback is not a public address');
      const { client: c2 } = await setup({ allow: ['example.com:53'] });
      await assert.rejects(c2.openUdp('127.0.0.1', port), (e) => e instanceof GatewayError && e.code === 4);
      const { client: c3 } = await setup({ allow: [], allowPrivate: ['127.0.0.0/8'] });
      await assert.rejects(c3.openUdp('127.0.0.1', port), (e) => e instanceof GatewayError && e.code === 4, 'a private allowance without an allow rule is still default deny');
    });

    it('a flow is for ONE destination: a third party sending to the flow\'s socket is not delivered', async () => {
      const lines = [];
      const port = await udpServer();
      const { client } = await setup({ allow: [`127.0.0.1:${port}`] }, { onLog: (l) => lines.push(l) });
      const flow = await client.openUdp('127.0.0.1', port);
      const local = Number(/local port (\d+)/.exec(lines.join('\n'))?.[1]);
      assert.ok(local > 0, `the host logs the flow's local port: ${lines.join(' | ')}`);
      const intruder = dgram.createSocket('udp4'); socks.push(intruder);
      await new Promise((r) => intruder.send(Buffer.from('spoof'), local, '127.0.0.1', r));
      await sleep(300);
      assert.equal(flow.stats.received, 0, 'datagram from another address/port was not forwarded');
      await flow.send(Uint8Array.of(7));
      assert.deepEqual([...await readOne(flow)], [7], 'the real destination still works');
      flow.destroy();
    });

    it('a datagram naming a flow the client does not have is dropped and counted', async () => {
      const port = await udpServer();
      const { client, server } = await setup({ allow: [`127.0.0.1:${port}`] });
      const flow = await client.openUdp('127.0.0.1', port);
      const orig = WebTransportTransport.prototype.sendDatagram;
      WebTransportTransport.prototype.sendDatagram = function (bytes) { const b = bytes.slice(); b[0] ^= 0xff; return orig.call(this, b); }; // another flow's id
      try {
        await flow.send(Uint8Array.of(1));
        await until(() => server.gatewayStats().udp.unknownFlow === 1, 'the stray datagram to be counted');
        assert.equal(server.gatewayStats().udp.datagramsFromClient, 0, 'and not delivered anywhere');
      } finally { WebTransportTransport.prototype.sendDatagram = orig; }
      flow.destroy();
    });
  });
});
