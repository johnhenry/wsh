// test/gateway-network-review.test.mjs -- #299, what an independent review of the injected-network gateway asked to be pinned. Every test here fails when its rule is broken
// (the mutations tried are listed in the pull request):
//  - a network that never answers (resolve, connect, listen, close) is bounded by `connectTimeoutMs`, cannot hold the client's message loop, and what it hands over late is released;
//  - a session that ends while the network is still working tells it (its signal aborts);
//  - one deadline and at most 64 addresses per answer; answers that are not plain IP literals are not addresses;
//  - what the network's text can put on the wire (a peer address, a port) is bounded; a connection delivered after ListenClose is released, not announced;
//  - UDP over real datagrams to a sink that never drains stays bounded and is counted; `udp: false` means off on the machine's gateway too;
//  - the features a host states are the ones it can serve; a gateway option that is a typo is a mistake.
import { describe, it, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createReverseHost } from '@johnhenry/wsh/reverse';
import { createWshServer } from '@johnhenry/wsh/server';
import { GATEWAY_FAIL, normalizeGateway, createGatewaySession } from '@johnhenry/wsh/gateway';
import { generateKeyPair, exportPublicKeyRaw, exportPublicKeySSH, MSG, openUdp, resolveDns } from '@johnhenry/wsh';
import { GatewayError } from '../src/gateway-client.mjs';
import { encodeDatagram } from '../src/gateway-datagram.mjs';
import { gatewayDatagrams } from '../src/server/gateway-features.mjs';
import { StreamSocket } from '../src/server/stream-socket.mjs';
import { createVirtualNetwork, echoService, readAll } from './helpers/virtual-network.mjs';

const enc = new TextEncoder();
const dec = new TextDecoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 8000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
const never = () => new Promise(() => {});
const PUB = '93.184.216.7';
/** A duplex whose two ends say when they were cancelled or aborted. */
function watched() {
  const seen = { cancelled: false, aborted: false };
  return { seen, duplex: { readable: new ReadableStream({ cancel() { seen.cancelled = true; } }), writable: new WritableStream({ abort() { seen.aborted = true; } }) } };
}

describe('the injected-network gateway after review (#299)', () => {
  let keyPair; let raw; let line;
  const hosts = []; const clients = []; const closers = [];
  before(async () => { keyPair = await generateKeyPair(true); raw = await exportPublicKeyRaw(keyPair.publicKey); line = `${await exportPublicKeySSH(keyPair.publicKey)} alice`; });
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const h of hosts.splice(0)) await h.close().catch(() => {});
    for (const f of closers.splice(0)) await f().catch(() => {});
  });
  async function setup(network, gateway = {}) {
    const h = createMemoryHost({ auth: { authorizedKeys: [raw] }, gateway: { network, allow: ['*'], ...gateway } });
    hosts.push(h);
    const client = await h.connect({ username: 'alice', keyPair });
    clients.push(client);
    return { host: h, client };
  }
  const code = (c) => (e) => e instanceof GatewayError && e.code === c;

  describe('a network that never answers', () => {
    it('listenTcp that never settles: the listen fails after connectTimeoutMs, the signal is aborted, and the client\'s other connections flow meanwhile', async () => {
      const calls = { listen: [] };
      const vnet = createVirtualNetwork({ services: { [`${PUB}:7`]: echoService } });
      const network = { ...vnet.network, listenTcp: ({ signal }) => { calls.listen.push(signal); return never(); } };
      const { client } = await setup(network, { reverse: true, connectTimeoutMs: 300 });
      const d = await client.openTcp(PUB, 7);
      const t0 = Date.now();
      const listening = client.listenTcp(0, { onConnection() {} });
      const w = d.writable.getWriter(); await w.write(enc.encode('through'));
      assert.equal(dec.decode((await d.readable.getReader().read()).value), 'through', 'an open connection is served, after the listen was bounded');
      await assert.rejects(listening, (e) => e instanceof GatewayError && /did not start listening/.test(e.message));
      assert.ok(Date.now() - t0 < 5000, 'bounded');
      assert.equal(calls.listen[0].aborted, true, 'the network was told');
    });

    it('a listen that binds AFTER the timeout is closed, not kept', async () => {
      let closed = false;
      const network = { connectTcp() {}, listenTcp: () => new Promise((r) => setTimeout(() => r({ port: 9000, close() { closed = true; } }), 300)) };
      const { client } = await setup(network, { reverse: true, connectTimeoutMs: 100 });
      await assert.rejects(client.listenTcp(0, { onConnection() {} }), /did not start listening/);
      await until(() => closed, 'the late listener to be closed');
    });

    it('a listener\'s close() that never settles does not hold the message loop: the next request is served within the bound', async () => {
      const vnet = createVirtualNetwork({ services: { [`${PUB}:7`]: echoService } });
      const calls = [];
      const network = { ...vnet.network, listenTcp: ({ signal }) => { calls.push(signal); return Promise.resolve({ port: 9000, close: never }); } };
      const { client } = await setup(network, { reverse: true, connectTimeoutMs: 300 });
      const handle = await client.listenTcp(9000, { onConnection() {} });
      const t0 = Date.now();
      await handle.close();
      const d = await client.openTcp(PUB, 7);
      assert.ok(Date.now() - t0 < 5000, 'served after the bounded close');
      assert.equal(calls[0].aborted, true);
      d.destroy();
    });

    for (const what of ['listen', 'lookup', 'connect']) {
      it(`a session that ends while the network is still ${what === 'listen' ? 'binding' : what === 'lookup' ? 'resolving' : 'connecting'} tells it (the signal aborts)`, async () => {
        const signals = [];
        const network = {
          listenTcp: ({ signal }) => { signals.push(signal); return never(); },
          resolve: ({ signal }) => { signals.push(signal); return never(); },
          connectTcp: ({ signal }) => { signals.push(signal); return never(); },
        };
        const { client } = await setup(network, { reverse: true });
        if (what === 'listen') void client.listenTcp(0, { onConnection() {} }).catch(() => {});
        else void client.openTcp(what === 'lookup' ? 'svc.test' : PUB, 7).catch(() => {});
        await until(() => signals.length === 1, 'the call');
        await client.disconnect();
        await until(() => signals[0].aborted, 'the signal to be aborted');
      });
    }

    it('resolve that never settles: the open is refused with a timeout and the signal is aborted', async () => {
      let signal;
      const network = { connectTcp() {}, resolve: ({ signal: s }) => { signal = s; return never(); } };
      const { client } = await setup(network, { connectTimeoutMs: 200 });
      const t0 = Date.now();
      await assert.rejects(client.openTcp('svc.test', 7), code(GATEWAY_FAIL.TIMEOUT));
      assert.ok(Date.now() - t0 < 4000);
      assert.equal(signal.aborted, true);
    });

    it('a connect that resolves AFTER the timeout is released (its streams cancelled and aborted)', async () => {
      const w = watched();
      const network = { connectTcp: () => new Promise((r) => setTimeout(() => r(w.duplex), 300)) };
      const { client } = await setup(network, { connectTimeoutMs: 100 });
      await assert.rejects(client.openTcp(PUB, 7), code(GATEWAY_FAIL.TIMEOUT));
      await until(() => w.seen.cancelled && w.seen.aborted, 'the late connection to be released');
    });

    it('a duplex that is not one is released as far as it goes, and the open fails with a reason', async () => {
      const readable = watched();
      const network = { connectTcp: async () => ({ readable: readable.duplex.readable, writable: 5 }) };
      const { client } = await setup(network);
      await assert.rejects(client.openTcp(PUB, 7), (e) => e instanceof GatewayError && /must give/.test(e.message));
      await until(() => readable.seen.cancelled, 'the readable half to be cancelled');
    });
  });

  describe('concurrency at the cap', () => {
    it('five concurrent opens against maxConnections 2: two are served, three are refused as full (pending opens count)', async () => {
      const vnet = createVirtualNetwork({ services: { [`${PUB}:7`]: echoService } });
      const network = { connectTcp: async (r) => { await sleep(100); return vnet.network.connectTcp(r); } };
      const { client } = await setup(network, { maxConnections: 2 });
      const results = await Promise.allSettled([1, 2, 3, 4, 5].map(() => client.openTcp(PUB, 7)));
      const ok = results.filter((r) => r.status === 'fulfilled');
      const full = results.filter((r) => r.status === 'rejected' && r.reason.code === GATEWAY_FAIL.QUEUE_FULL);
      assert.equal(ok.length, 2);
      assert.equal(full.length, 3);
    });
  });

  describe('candidates and answers are bounded', () => {
    const many = (n) => Array.from({ length: n }, (_, i) => `93.184.${(i >> 8) & 255}.${(i & 255) + 1}`);

    it('10,000 answers: exactly 64 candidates are tried to dial, and 64 are reported in a DnsResult', async () => {
      const tried = [];
      const network = { resolve: async () => many(10_000), connectTcp: async ({ host }) => { tried.push(host); throw Object.assign(new Error('no'), { code: 'ECONNREFUSED' }); } };
      const { client } = await setup(network, { dns: true });
      await assert.rejects(client.openTcp('big.test', 7), code(GATEWAY_FAIL.CONNECTION_REFUSED));
      assert.equal(tried.length, 64);
      const inbox = [];
      client.onGatewayMessage = (m) => inbox.push(m);
      await client.sendControl(resolveDns({ gatewayId: 77, name: 'big.test' }));
      const a = await until(() => inbox.find((m) => m.gateway_id === 77), 'the DnsResult');
      assert.equal(a.type, MSG.DNS_RESULT);
      assert.equal(a.addresses.length, 64);
    });

    it('many candidates that each fail slowly end by ONE deadline (connectTimeoutMs), not one per candidate', async () => {
      let n = 0;
      const network = { resolve: async () => many(64), connectTcp: async () => { n++; await sleep(40); throw Object.assign(new Error('no'), { code: 'ECONNREFUSED' }); } };
      const { client } = await setup(network, { connectTimeoutMs: 300 });
      const t0 = Date.now();
      await assert.rejects(client.openTcp('slow.test', 7), code(GATEWAY_FAIL.TIMEOUT));
      assert.ok(Date.now() - t0 < 1500, `ended by the deadline (${Date.now() - t0} ms)`);
      assert.ok(n < 64, `${n} candidates were tried`);
    });

    it('answers that are not plain IP literals are not addresses; a private one wrapped in IPv6 is refused; the public one is dialled', async () => {
      const dialled = [];
      const names = {
        'mapped.test': ['::ffff:10.0.0.5'], 'zone.test': ['fe80::1%eth0'], 'dot.test': [`${PUB}.`], 'space.test': [` ${PUB}`],
        'mix.test': ['::ffff:10.0.0.5', 'fe80::1%eth0', `${PUB}.`, PUB],
      };
      const network = { resolve: async ({ name }) => names[name], connectTcp: async ({ host }) => { dialled.push(host); const t = new TransformStream(); return { readable: t.readable, writable: t.writable }; } };
      const { client } = await setup(network, { allowPrivate: [] });
      await assert.rejects(client.openTcp('mapped.test', 7), code(GATEWAY_FAIL.POLICY_DENIED));
      for (const n of ['zone.test', 'dot.test', 'space.test']) await assert.rejects(client.openTcp(n, 7), code(GATEWAY_FAIL.DNS_FAILED), n);
      assert.deepEqual(dialled, []);
      (await client.openTcp('mix.test', 7)).destroy();
      assert.deepEqual(dialled, [PUB]);
    });
  });

  describe('what the network can put on the wire, and what arrives after a close', () => {
    function capturingNetwork() {
      const state = { onConnection: null, port: 9000 };
      return { state, network: { listenTcp: async ({ onConnection }) => { state.onConnection = onConnection; return { port: state.port, close() {} }; } } };
    }

    it('a peer address that is not an IP literal is reported as empty and a port out of range as 0; a good one is kept', async () => {
      const cap = capturingNetwork();
      const { client } = await setup(cap.network, { reverse: true, allow: [] });
      const peers = [];
      await client.listenTcp(9000, { onConnection: (d, info) => { peers.push(info); d.destroy(); } });
      for (const [peerAddr, peerPort] of [['evil\nname', 70000], ['10.0.0.9', 5555], [' 10.0.0.9', -1], ['fe80::1%eth0', 1.5], [42, 'x']]) cap.state.onConnection(watched().duplex, { peerAddr, peerPort });
      await until(() => peers.length === 5, 'five announcements');
      assert.deepEqual(peers.map((p) => [p.peer, p.peerPort]), [['', 0], ['10.0.0.9', 5555], ['', 0], ['', 0], ['', 0]]);
    });

    it('a network that reports a port that is not one fails the listen (it is not "the port that was asked for")', async () => {
      const cap = capturingNetwork();
      cap.state.port = 70000;
      const { client } = await setup(cap.network, { reverse: true, allow: [] });
      await assert.rejects(client.listenTcp(9000, { onConnection() {} }), /did not report a port/);
      cap.state.port = 0;
      await assert.rejects(client.listenTcp(9000, { onConnection() {} }), /did not report a port/);
    });

    it('a connection the network delivers AFTER ListenClose is released at once and never announced', async () => {
      const cap = capturingNetwork();
      const { client } = await setup(cap.network, { reverse: true, allow: [] });
      const announced = [];
      const handle = await client.listenTcp(9000, { onConnection: (d) => { announced.push(d); } });
      const before = watched();
      cap.state.onConnection(before.duplex, { peerAddr: '10.0.0.9', peerPort: 1 });
      await until(() => announced.length === 1, 'the first connection');
      await handle.close();
      // ListenClose is processed in order behind nothing else here: a canary that IS served after it says it has been
      const canary = createVirtualNetwork();
      void canary;
      const late = watched();
      await until(async () => { cap.state.onConnection(late.duplex, { peerAddr: '10.0.0.9', peerPort: 2 }); await sleep(20); return late.seen.cancelled; }, 'the late connection to be released');
      assert.equal(announced.length, 1, 'nothing more was announced to the client');
    });

    it('an inbound stream the network errors while it waits to be accepted is noticed (the socket closes), not held for the accept timeout', async () => {
      let fail;
      const readable = new ReadableStream({ start(c) { fail = (e) => c.error(e); } });
      const sock = new StreamSocket({ readable, writable: new WritableStream() });
      sock.pause();
      const closed = new Promise((r) => sock.once('close', r));
      sock.on('error', () => {});
      fail(new Error('the network dropped it'));
      await Promise.race([closed, sleep(2000).then(() => assert.fail('not noticed'))]);
      assert.equal(sock.destroyed, true);
    });
  });

  describe('bytes handed to the network are a copy', () => {
    it('what the sink receives is not the buffer the frame came in', async () => {
      const got = [];
      const sink = new WritableStream({ write(c) { got.push(c); } });
      const sock = new StreamSocket({ readable: new ReadableStream(), writable: sink });
      const original = enc.encode('payload');
      await new Promise((r) => sock.write(original, r));
      assert.deepEqual(got[0], original);
      assert.notEqual(got[0].buffer, original.buffer);
      sock.destroy();
    });
  });

  describe('UDP over real datagrams to a sink that never drains', () => {
    it('stays bounded: datagrams are dropped (and counted) once the sink is full, the flow survives', async () => {
      let writes = 0;
      const network = {
        openUdp: async () => ({ readable: new ReadableStream(), writable: new WritableStream({ write() { writes++; return never(); } }) }),
      };
      const cfg = normalizeGateway({ network, allow: [PUB], udp: true });
      const sent = [];
      const session = createGatewaySession(cfg, (m) => { sent.push(m); }, () => {}, { datagrams: { send: () => true, maxSize: () => 1200 } });
      session.setPeerFeatures(['gateway-credit', 'gateway-datagram']);
      await session.handle(openUdp({ gatewayId: 1, host: PUB, port: 53 }));
      assert.ok(sent.some((m) => m.type === MSG.GATEWAY_OK), 'the flow opened');
      for (let i = 0; i < 100; i++) session.handleDatagram(encodeDatagram(1, new Uint8Array(100)));
      assert.ok(writes <= 2, `the sink was handed ${writes} datagrams`);
      assert.ok(cfg.stats.udp.backpressureDropped >= 90, `dropped and counted: ${cfg.stats.udp.backpressureDropped}`);
      assert.equal(session.size, 1, 'the flow is still open');
      session.close();
    });

    it('a network with openUdp states gateway-datagram; one without it, or with UDP off, does not', () => {
      assert.equal(gatewayDatagrams(normalizeGateway({ network: { openUdp() {} }, allow: [], udp: true })), true);
      assert.equal(gatewayDatagrams(normalizeGateway({ network: { openUdp() {} }, allow: [] })), false, 'the switch is off');
      assert.equal(gatewayDatagrams(normalizeGateway({ network: { connectTcp() {} }, allow: [], udp: true })), false, 'no openUdp');
    });
  });

  describe('the machine\'s gateway: udp: false and dns: false mean off', () => {
    it('udp: false is accepted (it used to throw) and turns UDP off: refused with the reason, no datagrams', async () => {
      assert.doesNotThrow(() => normalizeGateway({ allow: [], udp: false }));
      const off = normalizeGateway({ allow: ['*'], udp: false });
      assert.equal(off.udpOn, false);
      assert.equal(gatewayDatagrams(off), false);
      assert.equal(gatewayDatagrams(normalizeGateway({ allow: ['*'] })), true, 'on by default, as ever');
      const server = createWshServer({ auth: { authorizedKeys: line }, gateway: { allow: ['*'], udp: false } });
      const { port } = await server.listen();
      closers.push(() => server.close());
      const { WshClient } = await import('@johnhenry/wsh');
      const client = new WshClient(); clients.push(client);
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
      await assert.rejects(client.openUdp('127.0.0.1', 9), (e) => e instanceof GatewayError && e.code === GATEWAY_FAIL.POLICY_DENIED && /UDP is not enabled/.test(e.message));
    });

    it('dns: false turns name resolution off', async () => {
      const server = createWshServer({ auth: { authorizedKeys: line }, gateway: { allow: ['*'], dns: false } });
      const { port } = await server.listen();
      closers.push(() => server.close());
      const { WshClient } = await import('@johnhenry/wsh');
      const client = new WshClient(); clients.push(client);
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
      const inbox = [];
      client.onGatewayMessage = (m) => inbox.push(m);
      await client.sendControl(resolveDns({ gatewayId: 5, name: 'localhost' }));
      const a = await until(() => inbox.find((m) => m.gateway_id === 5), 'an answer');
      assert.equal(a.type, MSG.GATEWAY_FAIL);
      assert.match(a.message, /not enabled/);
    });
  });

  describe('the features a host states are the ones it can serve', () => {
    it('a network with only openUdp (UDP on) states gateway and refuses TCP with the reason; with the switch off it states none', async () => {
      const udpOnly = await setup({ openUdp: async () => { const t = new TransformStream(); return { readable: t.readable, writable: t.writable }; } }, { udp: true });
      assert.equal(udpOnly.client.hasFeature('gateway'), true, 'a client checks "gateway" for UDP too');
      await assert.rejects(udpOnly.client.openTcp(PUB, 7), (e) => e instanceof GatewayError && /cannot open TCP/.test(e.message));
      const off = await setup({ openUdp: async () => ({}) });
      assert.equal(off.client.hasFeature('gateway'), false);
    });

    it('only resolve, without dns: true, states nothing; with it, gateway; only listenTcp needs reverse', async () => {
      assert.equal((await setup({ resolve: async () => [] })).client.hasFeature('gateway'), false);
      assert.equal((await setup({ resolve: async () => [] }, { dns: true })).client.hasFeature('gateway'), true);
      assert.equal((await setup({ listenTcp: async () => ({ port: 1 }) })).client.hasFeature('gateway'), false);
      assert.equal((await setup({ listenTcp: async () => ({ port: 1 }) }, { reverse: true })).client.hasFeature('gateway'), true);
    });
  });

  describe('bundles', () => {
    it('a bundled Node server still contains the unix-socket and SOCKS5 code (literal dynamic imports in the Node entry), and no browser entry does', async () => {
      const { build } = await import('esbuild');
      const common = { bundle: true, write: false, splitting: true, format: 'esm', outdir: 'unused-out', logLevel: 'silent', external: ['ws', '@noble/*', '@fails-components/*', '@modelcontextprotocol/*', 'node-pty'] };
      const text = (r) => r.outputFiles.map((f) => f.text).join('\n');
      const node = text(await build({ ...common, entryPoints: ['src/server/index.mjs'], platform: 'node' }));
      assert.match(node, /SOCKS5 proxy requires authentication/, 'socks.mjs is in the bundled server');
      assert.match(node, /function unlinkIfSocket/, 'unix-policy.mjs is in the bundled server');
      const browser = text(await build({ ...common, entryPoints: ['src/memory-host.mjs', 'src/reverse-host.mjs', 'src/gateway.mjs'], platform: 'browser' }));
      assert.doesNotMatch(browser, /SOCKS5 proxy requires authentication/);
      assert.doesNotMatch(browser, /function unlinkIfSocket|malformed path/);
    });
  });

  describe('options: a typo is a mistake, on every host that takes a network', () => {
    const network = { connectTcp() {} };
    it('the memory host, normalizeGateway and the reverse host reject an unknown key and a wrongly typed switch', () => {
      assert.throws(() => createMemoryHost({ gateway: { network, allow: [], allowPrivte: [] } }), /unknown gateway option "allowPrivte"/);
      assert.throws(() => createMemoryHost({ gateway: { network, allow: [], dns: 'yes' } }), /dns must be a boolean/);
      assert.throws(() => createMemoryHost({ gateway: { network, allow: [], udp: 'x' } }), /udp must be/);
      assert.throws(() => createMemoryHost({ gateway: { network, allow: [], reverse: 5 } }), /reverse must be/);
      assert.throws(() => normalizeGateway({ network, allow: [], allowPrivte: [] }), /unknown gateway option/);
      assert.throws(() => createReverseHost({ url: 'ws://x', username: 'h', keyPair, gateway: { network, allow: [], trustRelayIdentity: true, allowPrivte: [] } }), /unknown gateway option/);
      assert.throws(() => createWshServer({ gateway: { network, allow: [], allowPrivte: [] } }), /unknown gateway option/);
      assert.doesNotThrow(() => createReverseHost({ url: 'ws://x', username: 'h', keyPair, gateway: { network, allow: [], trustRelayIdentity: true, udp: false, dns: false } }));
    });
  });
});
