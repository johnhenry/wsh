// test/gateway-network.test.mjs -- #299: a host that lives in a page (`createMemoryHost`) serves the gateway over a NETWORK THE EMBEDDER SUPPLIES.
//
// The same session, destination policy, credit flow control, half-close rules and bounds that the Node host applies to its machine's sockets
// run here over a fake network: a map of "address:port" to a handler (`test/helpers/virtual-network.mjs`, which also runs in the browser spec).
// Each rule has a test that fails when the rule is broken (the mutations tried are listed in the pull request):
//  - nothing is on unless the embedder passes a gateway, and a gateway without a network is a mistake;
//  - the destination policy runs before the network is called, on the address the NETWORK resolved, which is the address it is then given
//    (one lookup); a private-looking address of the network's own is refused until the embedder names it; a name the network cannot resolve is refused;
//  - UDP, DNS and listening each need the switch AND the network method;
//  - the connection cap and the credit window are the Node path's; a client that goes away closes the network's stream and aborts its signal.
import { describe, it, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { WebSocket as WsClient } from 'ws';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createReverseHost } from '@johnhenry/wsh/reverse';
import { createWshServer } from '@johnhenry/wsh/server';
import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { GATEWAY_FAIL, normalizeGateway } from '@johnhenry/wsh/gateway';
import {
  WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG, resolveDns,
} from '@johnhenry/wsh';
import { GatewayError } from '../src/gateway-client.mjs';
import { halfCloseWatchCount } from '../src/half-close-watch.mjs';
import { createVirtualNetwork, echoService, readAll, concatBytes } from './helpers/virtual-network.mjs';

const enc = new TextEncoder();
const dec = new TextDecoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 8000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
/** A refusal by the host's policy (code 4) whose text matches. */
const refused = (p, re) => assert.rejects(p, (e) => e instanceof GatewayError && e.code === GATEWAY_FAIL.POLICY_DENIED && re.test(e.message), `expected a policy refusal matching ${re}`);
const chunkOf = (i, size) => { const b = new Uint8Array(size); let x = (i * 2654435761) >>> 0; for (let k = 0; k < size; k++) { x = (Math.imul(x, 1664525) + 1013904223) >>> 0; b[k] = x >>> 24; } return b; };

describe('the gateway over a network the embedder supplies (#299)', () => {
  let keyPair; let raw; let line;
  const hosts = []; const clients = []; const closers = [];
  before(async () => { keyPair = await generateKeyPair(true); raw = await exportPublicKeyRaw(keyPair.publicKey); line = `${await exportPublicKeySSH(keyPair.publicKey)} alice`; });
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const h of hosts.splice(0)) await h.close().catch(() => {});
    for (const f of closers.splice(0)) await f().catch(() => {});
  });

  /** A memory host with a gateway over `vnet`, and a client of it (directly, in this realm). */
  async function setup(vnet, gateway = {}, { auth = { authorizedKeys: [raw] }, host = {}, connect = true } = {}) {
    const h = createMemoryHost({ auth, gateway: { network: vnet.network, allow: ['*'], ...gateway }, ...host });
    hosts.push(h);
    if (!connect) return { host: h };
    const client = await h.connect({ username: 'alice', keyPair });
    clients.push(client);
    return { host: h, client };
  }

  describe('off unless given, and a mistake without a network', () => {
    it('a host without a gateway offers none: no feature, nothing to open', async () => {
      const h = createMemoryHost({ auth: { authorizedKeys: [raw] }, endpoints: { e: () => {} } });
      hosts.push(h);
      const client = await h.connect({ username: 'alice', keyPair });
      clients.push(client);
      assert.equal(client.hasFeature('gateway'), false);
      await assert.rejects(client.openTcp('93.184.216.7', 80), /does not support/);
    });

    it('a gateway needs a network (a page cannot dial sockets) and an explicit allow list', () => {
      for (const bad of [true, {}, { allow: ['*'] }, { network: {} }, { network: { connectTcp: 'x' } }, { network: { connectTcp() {} }, allow: 'x' }]) {
        assert.throws(() => createMemoryHost({ gateway: bad }), TypeError, JSON.stringify(bad));
      }
      assert.throws(() => createMemoryHost({ gateway: { allow: ['*'] } }), /network/);
      assert.throws(() => createMemoryHost({ gateway: { network: { connectTcp() {} } } }), /allow/);
    });

    it('socks and unix belong to the machine, not to an injected network', () => {
      const network = { connectTcp() {} };
      assert.throws(() => createMemoryHost({ gateway: { network, allow: ['*'], socks: '127.0.0.1:9050' } }), /socks/);
      assert.throws(() => createMemoryHost({ gateway: { network, allow: ['*'], unix: { connect: ['/x'] } } }), /unix/);
      assert.throws(() => normalizeGateway({ network, allow: ['*'], tcp: false, endpoints: {} }), /tcp/);
    });

    it('states the gateway features and credit, and not unix sockets', async () => {
      const { client } = await setup(createVirtualNetwork());
      assert.ok(client.hasFeature('gateway'));
      assert.ok(client.hasFeature('gateway-credit'));
      assert.equal(client.hasFeature('gateway-unix'), false);
    });

    it('named endpoints and a network gateway live side by side', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService } });
      const { client } = await setup(vnet, {}, { host: { endpoints: { hello: async (d) => { const w = d.writable.getWriter(); await w.write(enc.encode('hi')); await w.close(); } } } });
      assert.ok(client.hasFeature('gateway-endpoints'));
      assert.equal(dec.decode(await readAll((await client.openEndpoint('hello')).readable)), 'hi');
      const tcp = await client.openTcp('93.184.216.7', 7);
      const w = tcp.writable.getWriter(); await w.write(enc.encode('x')); await w.close();
      assert.equal(dec.decode(await readAll(tcp.readable)), 'x');
    });
  });

  describe('TCP over the network', () => {
    it('a byte-exact exchange both ways, the caller half-closing first and the origin still answering', async () => {
      let seen;
      const vnet = createVirtualNetwork({ services: {
        // reads until the caller's end of stream, then answers with what it read: the half-close reached the origin and the way back stayed open
        '93.184.216.7:9000': async ({ readable, writable }) => {
          const got = await readAll(readable); seen = got;
          const w = writable.getWriter(); await w.write(enc.encode(`got ${got.byteLength} ${sha(got)}`)); await w.close();
        },
      } });
      const { client } = await setup(vnet);
      const d = await client.openTcp('93.184.216.7', 9000);
      const body = concatBytes([0, 1, 2, 3].map((i) => chunkOf(i, 100_000)));
      const w = d.writable.getWriter();
      for (let o = 0; o < body.byteLength; o += 70_000) await w.write(body.subarray(o, o + 70_000));
      await w.close();
      assert.equal(dec.decode(await readAll(d.readable)), `got ${body.byteLength} ${sha(body)}`);
      assert.deepEqual(seen, body);
    });

    it('the origin half-closes first and the caller can still send: nothing is lost either way', async () => {
      let late;
      const vnet = createVirtualNetwork({ services: {
        '93.184.216.7:9001': async ({ readable, writable }) => {
          const w = writable.getWriter(); await w.write(enc.encode('hello')); await w.close();
          late = dec.decode(await readAll(readable));
        },
      } });
      const { client } = await setup(vnet);
      const d = await client.openTcp('93.184.216.7', 9001);
      assert.equal(dec.decode(await readAll(d.readable)), 'hello');
      const w = d.writable.getWriter(); await w.write(enc.encode('late reply')); await w.close();
      await until(() => late !== undefined, 'the origin to hear the late bytes');
      assert.equal(late, 'late reply');
    });

    it('a connection of an injected network is never probed, even where gateway-lossless-close is negotiated: it ends when the network closes the stream (#286)', async () => {
      const heldOpen = [];
      const vnet = createVirtualNetwork({ services: {
        // finishes sending and keeps its end open: a socket would be watched for a vanished peer, a network's stream has no kernel to ask
        '93.184.216.7:9002': async ({ readable, writable }) => {
          const w = writable.getWriter(); await w.write(enc.encode('answer')); await w.close();
          heldOpen.push(readable);
        },
      } });
      const { client } = await setup(vnet);
      assert.ok(client.hasFeature('gateway-lossless-close'), 'negotiated');
      const d = await client.openTcp('93.184.216.7', 9002);
      assert.equal(dec.decode(await readAll(d.readable)), 'answer');
      await until(() => heldOpen.length === 1, 'the service to have finished');
      await sleep(400); // longer than the default probe interval of a socket would need to show itself
      assert.equal(halfCloseWatchCount(), 0, 'no probe, no timer');
      assert.equal(await Promise.race([d.closed, sleep(100).then(() => 'open')]), 'open', 'held until the caller (or the network) closes it');
      await d.writable.getWriter().close();
      assert.notEqual(await d.closed, 'discarded');
    });

    it('moves 12 MiB each way intact (credit-metered)', async () => {
      const COUNT = 192; const SIZE = 64 * 1024; // 12 MiB
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService } });
      const { client } = await setup(vnet);
      const d = await client.openTcp('93.184.216.7', 7);
      const sent = crypto.createHash('sha256'); const got = crypto.createHash('sha256');
      const writing = (async () => { const w = d.writable.getWriter(); for (let i = 0; i < COUNT; i++) { const c = chunkOf(i, SIZE); sent.update(c); await w.write(c); } await w.close(); })();
      let total = 0;
      const r = d.readable.getReader();
      for (;;) { const { done, value } = await r.read(); if (done) break; got.update(value); total += value.byteLength; }
      await writing;
      assert.equal(total, COUNT * SIZE);
      assert.equal(got.digest('hex'), sent.digest('hex'));
    });

    it('a reader that reads nothing holds the origin back: memory stays bounded (the credit window)', async () => {
      let acked = 0; let stopped = false;
      const vnet = createVirtualNetwork({ services: {
        '93.184.216.7:7': async ({ writable }) => {
          const w = writable.getWriter(); const c = new Uint8Array(65536);
          try { while (!stopped) { await w.write(c); acked += c.byteLength; } } catch { /* the caller went away */ }
        },
      } });
      const { client } = await setup(vnet);
      const d = await client.openTcp('93.184.216.7', 7);
      await until(() => acked >= 65536, 'the origin to start');
      await sleep(300);
      const first = acked;
      await sleep(300);
      assert.ok(acked < 2 * 1024 * 1024, `the origin was held back by credit (${acked} bytes accepted from a 16 MiB source nobody reads)`);
      assert.ok(acked - first < 65536 * 2, 'and it is not creeping on');
      // reading frees it again
      const r = d.readable.getReader(); let read = 0;
      while (read < 3 * 1024 * 1024) read += (await r.read()).value.byteLength;
      assert.ok(acked > first, 'reading releases the origin');
      stopped = true; d.destroy();
    });

    it('a slow origin sink: what the caller sends waits for the origin to take it (the host does not buffer without bound)', async () => {
      const taken = { n: 0 }; let release;
      const gate = new Promise((r) => { release = r; });
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': async ({ readable }) => { await gate; const r = readable.getReader(); for (;;) { const { done, value } = await r.read(); if (done) break; taken.n += value.byteLength; } } } });
      const { client, host } = await setup(vnet, { maxBufferedBytes: 262144 * 2 });
      void host;
      const d = await client.openTcp('93.184.216.7', 7);
      const w = d.writable.getWriter();
      let written = 0; let blocked = false;
      const pump = (async () => { for (let i = 0; i < 400; i++) { await w.write(new Uint8Array(65536)); written += 65536; } await w.close(); })();
      await until(() => written > 0, 'first write');
      await sleep(300);
      blocked = written < 400 * 65536;
      assert.ok(blocked && written < 4 * 1024 * 1024, `the caller is held back while the origin takes nothing (${written} bytes written)`);
      release();
      await pump;
      await until(() => taken.n === 400 * 65536, 'the origin to take everything');
    });
  });

  describe('the destination policy runs before the network is called', () => {
    it('a destination not on the allow list is refused and the network is never asked', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:9000': echoService }, names: { 'svc.test': ['93.184.216.7'] } });
      const { client } = await setup(vnet, { allow: ['93.184.216.7:9000'] });
      await refused(client.openTcp('93.184.216.7', 9001), /not allowed by the gateway policy/);
      await refused(client.openTcp('svc.test', 9000), /not allowed by the gateway policy/);
      assert.deepEqual([vnet.calls.connect.length, vnet.calls.resolve.length], [0, 0]);
    });

    it('with no allow entries nothing is reachable', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService } });
      const { client } = await setup(vnet, { allow: [] });
      await refused(client.openTcp('93.184.216.7', 7), /not allowed/);
      assert.equal(vnet.calls.connect.length, 0);
    });

    it('the network is asked ONCE, and is given the address it answered with (never the name)', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:80': echoService }, names: { 'svc.test': ['93.184.216.7'] } });
      const { client } = await setup(vnet, { allow: ['svc.test:80'] });
      const d = await client.openTcp('svc.test', 80);
      const w = d.writable.getWriter(); await w.write(enc.encode('ping')); await w.close();
      assert.equal(dec.decode(await readAll(d.readable)), 'ping');
      assert.equal(vnet.calls.resolve.length, 1);
      assert.equal(vnet.calls.resolve[0].name, 'svc.test');
      assert.deepEqual(vnet.calls.connect.map((c) => [c.host, c.port]), [['93.184.216.7', 80]]);
    });

    it('an address the network resolves to that is not public is refused, and nothing is dialled, until the embedder names it', async () => {
      const vnet = createVirtualNetwork({ services: { '10.0.0.5:80': echoService }, names: { 'svc.test': ['10.0.0.5'] } });
      const closed = await setup(vnet, { allow: ['svc.test'] });
      await refused(closed.client.openTcp('svc.test', 80), /address this name resolves to is not permitted/);
      assert.equal(vnet.calls.connect.length, 0, 'the network was not asked to connect');
      const open = await setup(vnet, { allow: ['svc.test'], allowPrivate: ['10.0.0.0/8'] });
      const d = await open.client.openTcp('svc.test', 80);
      d.destroy();
      assert.deepEqual(vnet.calls.connect.map((c) => c.host), ['10.0.0.5']);
    });

    it('a private-looking literal is refused unless named: "*" does not name it, an explicit literal rule does', async () => {
      const vnet = createVirtualNetwork({ services: { '10.0.0.5:80': echoService, '127.0.0.1:80': echoService } });
      const star = await setup(vnet, { allow: ['*'] });
      await refused(star.client.openTcp('10.0.0.5', 80), /not permitted/);
      await refused(star.client.openTcp('127.0.0.1', 80), /not permitted/);
      assert.equal(vnet.calls.connect.length, 0);
      const literal = await setup(vnet, { allow: ['10.0.0.5:80'] });
      (await literal.client.openTcp('10.0.0.5', 80)).destroy();
      await refused(literal.client.openTcp('10.0.0.6', 80), /not allowed/);
      assert.deepEqual(vnet.calls.connect.map((c) => c.host), ['10.0.0.5']);
    });

    it('a name that resolves to a mix: only the permitted addresses are tried, in the network\'s order', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.9:80': echoService }, names: { 'svc.test': ['10.0.0.5', '93.184.216.8', '93.184.216.9'] } });
      const { client } = await setup(vnet, { allow: ['svc.test'] });
      (await client.openTcp('svc.test', 80)).destroy();
      assert.deepEqual(vnet.calls.connect.map((c) => c.host), ['93.184.216.8', '93.184.216.9'], 'the private one was never offered; the first that answered won');
    });

    it('answers that are not IP addresses are not addresses: the name is refused as not found', async () => {
      const vnet = createVirtualNetwork({ services: {}, names: { 'svc.test': ['not-an-ip'], 'empty.test': [] } });
      const { client } = await setup(vnet, { allow: ['*'] });
      for (const name of ['svc.test', 'empty.test', 'nobody.test']) {
        await assert.rejects(client.openTcp(name, 80), (e) => e instanceof GatewayError && e.code === GATEWAY_FAIL.DNS_FAILED, name);
      }
      assert.equal(vnet.calls.connect.length, 0);
    });

    it('a network that cannot resolve names refuses names, with the reason, and still takes literals', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:80': echoService }, methods: ['connectTcp'] });
      const { client } = await setup(vnet, { allow: ['*'] });
      await refused(client.openTcp('svc.test', 80), /cannot resolve names/);
      (await client.openTcp('93.184.216.7', 80)).destroy();
      assert.equal(vnet.calls.connect.length, 1);
    });

    it('a network that cannot open TCP refuses it, with the reason', async () => {
      const vnet = createVirtualNetwork({ methods: ['resolve'], names: { 'svc.test': ['93.184.216.7'] } });
      const { client } = await setup(vnet, { allow: ['*'], dns: true });
      await refused(client.openTcp('93.184.216.7', 80), /cannot open TCP/);
      assert.equal(vnet.calls.resolve.length, 0);
    });

    it('an error of the network reaches the caller as the matching gateway code', async () => {
      const vnet = createVirtualNetwork({ services: {} });
      const { client } = await setup(vnet, { allow: ['*'] });
      await assert.rejects(client.openTcp('93.184.216.7', 80), (e) => e instanceof GatewayError && e.code === GATEWAY_FAIL.CONNECTION_REFUSED);
    });

    it('a connect that never answers times out (connectTimeoutMs) and the network is told through the signal', async () => {
      let signal;
      const network = { connectTcp: ({ signal: s }) => new Promise((_, reject) => { signal = s; s.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { code: 'ABORT_ERR' })), { once: true }); }) };
      const { client } = await setup({ network }, { allow: ['*'], connectTimeoutMs: 100 });
      await assert.rejects(client.openTcp('93.184.216.7', 80), (e) => e instanceof GatewayError && e.code === GATEWAY_FAIL.TIMEOUT);
      assert.equal(signal.aborted, true);
    });
  });

  describe('bounds', () => {
    it('maxConnections is the Node path\'s cap, and a slot frees when a connection ends', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService } });
      const { client } = await setup(vnet, { maxConnections: 2 });
      const a = await client.openTcp('93.184.216.7', 7);
      await client.openTcp('93.184.216.7', 7);
      await assert.rejects(client.openTcp('93.184.216.7', 7), (e) => e instanceof GatewayError && e.code === GATEWAY_FAIL.QUEUE_FULL);
      a.destroy();
      await until(async () => { try { (await client.openTcp('93.184.216.7', 7)).destroy(); return true; } catch { return false; } }, 'a freed slot');
    });
  });

  describe('when the caller goes away the network is told', () => {
    it('destroying a connection cancels the origin\'s stream and aborts the signal the network was given', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': async ({ writable }) => { const w = writable.getWriter(); try { for (;;) await w.write(new Uint8Array(1024)); } catch { /* gone */ } } } });
      const { client } = await setup(vnet);
      const d = await client.openTcp('93.184.216.7', 7);
      const rec = vnet.conns[0];
      assert.equal(rec.signalAborted, false);
      d.destroy();
      // the origin's readable is cancelled (it can write no more), the writable closed or aborted, and the signal aborted
      await until(() => rec.signalAborted && rec.serviceCancelled && (rec.clientClosed || rec.clientAborted), 'the network to be told');
    });

    it('a client that disconnects takes every one of its connections down with it', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService } });
      const { client } = await setup(vnet);
      await client.openTcp('93.184.216.7', 7);
      await client.openTcp('93.184.216.7', 7);
      assert.equal(vnet.conns.length, 2);
      await client.disconnect();
      await until(() => vnet.conns.every((r) => r.signalAborted && (r.serviceCancelled || r.clientAborted)), 'both connections to be released');
    });

    it('closing the host releases them too', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService } });
      const { client, host } = await setup(vnet);
      await client.openTcp('93.184.216.7', 7);
      await host.close();
      await until(() => vnet.conns.every((r) => r.signalAborted), 'the connection to be released');
    });
  });

  describe('DNS (needs the switch and the network method)', () => {
    async function ask(client, name, id) {
      const inbox = [];
      client.onGatewayMessage = (m) => inbox.push(m);
      await client.sendControl(resolveDns({ gatewayId: id, name }));
      return until(() => inbox.find((m) => m.gateway_id === id), 'an answer');
    }

    it('is refused unless `dns: true`, whatever the network can do', async () => {
      const vnet = createVirtualNetwork({ names: { 'svc.test': ['93.184.216.7'] } });
      const { client } = await setup(vnet, { allow: ['*'] });
      const a = await ask(client, 'svc.test', 1);
      assert.equal(a.type, MSG.GATEWAY_FAIL);
      assert.equal(a.code, GATEWAY_FAIL.POLICY_DENIED);
      assert.match(a.message, /not enabled/);
      assert.equal(vnet.calls.resolve.length, 0);
    });

    it('is refused when the network has no resolve, with the reason', async () => {
      const vnet = createVirtualNetwork({ methods: ['connectTcp'] });
      const { client } = await setup(vnet, { allow: ['*'], dns: true });
      const a = await ask(client, 'svc.test', 2);
      assert.equal(a.type, MSG.GATEWAY_FAIL);
      assert.match(a.message, /cannot resolve names/);
    });

    it('answers with the network\'s addresses that the policy permits, and only those', async () => {
      const vnet = createVirtualNetwork({ names: { 'svc.test': ['93.184.216.7', '10.0.0.5'], 'inner.test': ['10.0.0.5'] } });
      const { client } = await setup(vnet, { allow: ['svc.test', 'inner.test'], dns: true });
      const a = await ask(client, 'svc.test', 3);
      assert.equal(a.type, MSG.DNS_RESULT);
      assert.deepEqual(a.addresses, ['93.184.216.7']);
      const b = await ask(client, 'inner.test', 4);
      assert.equal(b.type, MSG.GATEWAY_FAIL);
      assert.equal(b.code, GATEWAY_FAIL.POLICY_DENIED);
      const named = await setup(vnet, { allow: ['inner.test'], allowPrivate: ['10.0.0.0/8'], dns: true });
      assert.deepEqual((await ask(named.client, 'inner.test', 5)).addresses, ['10.0.0.5']);
    });

    it('a name that is not on the allow list is not looked up', async () => {
      const vnet = createVirtualNetwork({ names: { 'svc.test': ['93.184.216.7'] } });
      const { client } = await setup(vnet, { allow: ['other.test'], dns: true });
      assert.equal((await ask(client, 'svc.test', 6)).type, MSG.GATEWAY_FAIL);
      assert.equal(vnet.calls.resolve.length, 0);
    });
  });

  describe('UDP (needs the switch and the network method)', () => {
    const echoDatagrams = async ({ readable, writable }) => { const w = writable.getWriter(); const r = readable.getReader(); try { for (;;) { const { done, value } = await r.read(); if (done) break; await w.write(concatBytes([enc.encode('re:'), value])); } } catch { /* gone */ } };

    it('is refused unless `udp` is given, and when the network has no openUdp, each with its reason', async () => {
      const vnet = createVirtualNetwork({ udp: { '93.184.216.7:53': echoDatagrams } });
      const off = await setup(vnet, { allow: ['*'] });
      await refused(off.client.openUdp('93.184.216.7', 53), /UDP is not enabled/);
      const noMethod = await setup(createVirtualNetwork({ methods: ['connectTcp'] }), { allow: ['*'], udp: true });
      await refused(noMethod.client.openUdp('93.184.216.7', 53), /cannot open UDP/);
      assert.equal(vnet.calls.udp.length, 0);
    });

    it('carries datagrams both ways, one payload per datagram', async () => {
      const vnet = createVirtualNetwork({ udp: { '93.184.216.7:53': echoDatagrams } });
      const { client } = await setup(vnet, { allow: ['*'], udp: true });
      const flow = await client.openUdp('93.184.216.7', 53);
      const r = flow.readable.getReader(); const w = flow.writable.getWriter();
      await w.write(enc.encode('one'));
      assert.equal(dec.decode((await r.read()).value), 're:one');
      await w.write(enc.encode('two'));
      assert.equal(dec.decode((await r.read()).value), 're:two');
      flow.close();
    });

    it('applies the destination policy to the resolved address, like TCP', async () => {
      const vnet = createVirtualNetwork({ udp: { '10.0.0.5:53': echoDatagrams }, names: { 'dns.test': ['10.0.0.5'] } });
      const { client } = await setup(vnet, { allow: ['dns.test', '10.0.0.5:53'], udp: true });
      (await client.openUdp('10.0.0.5', 53)).close(); // an explicit literal rule
      await until(() => vnet.calls.udp.length === 1, 'the flow');
      await refused(client.openUdp('dns.test', 53), /not permitted/);
      assert.equal(vnet.calls.udp.length, 1);
    });

    it('bounds the flows per client', async () => {
      const vnet = createVirtualNetwork({ udp: { '93.184.216.7:53': echoDatagrams } });
      const { client } = await setup(vnet, { allow: ['*'], udp: { maxFlows: 1 } });
      await client.openUdp('93.184.216.7', 53);
      await assert.rejects(client.openUdp('93.184.216.7', 53), (e) => e instanceof GatewayError && e.code === GATEWAY_FAIL.QUEUE_FULL);
    });

    it('releases the network\'s flow when the caller goes away', async () => {
      const vnet = createVirtualNetwork({ udp: { '93.184.216.7:53': echoDatagrams } });
      const { client } = await setup(vnet, { allow: ['*'], udp: true });
      const flow = await client.openUdp('93.184.216.7', 53);
      flow.close();
      await until(() => vnet.conns[0].signalAborted, 'the flow to be released');
    });
  });

  describe('listening (needs the switch and the network method)', () => {
    it('is refused unless `reverse` is given, and when the network has no listenTcp, each with its reason', async () => {
      const off = await setup(createVirtualNetwork(), { allow: ['*'] });
      await refused(off.client.listenTcp(0, { onConnection() {} }), /reverse tunnels are not enabled/);
      const noMethod = await setup(createVirtualNetwork({ methods: ['connectTcp'] }), { allow: ['*'], reverse: true });
      await refused(noMethod.client.listenTcp(0, { onConnection() {} }), /cannot listen/);
    });

    it('announces what connects on the network to the caller, who serves it; the port policy and the bind address are wsh\'s', async () => {
      const vnet = createVirtualNetwork();
      const { client } = await setup(vnet, { allow: [], reverse: { bindAddr: '10.0.0.1', ports: [0, '9000-9100'] } });
      await refused(client.listenTcp(80, { onConnection() {} }), /port 80 is not allowed/);
      assert.equal(vnet.calls.listen.length, 0, 'the network was not asked for a port the policy refuses');
      const peers = [];
      const handle = await client.listenTcp(9000, { bindAddr: '0.0.0.0', onConnection: (d, info) => { peers.push(info); void d.readable.pipeTo(d.writable).catch(() => {}); } });
      assert.equal(handle.port, 9000);
      assert.equal(vnet.calls.listen[0].bindAddr, '10.0.0.1', 'the client\'s bind address is ignored unless the operator listed it');
      const far = vnet.connectTo(9000, { address: '10.0.0.9', port: 5555 });
      const w = far.writable.getWriter(); await w.write(enc.encode('knock')); await w.close();
      assert.equal(dec.decode(await readAll(far.readable)), 'knock');
      assert.deepEqual(peers, [{ peer: '10.0.0.9', peerPort: 5555 }]);
      await handle.close();
      await until(() => vnet.calls.listen[0].signal.aborted && vnet.listeners.size === 0, 'the listener to be released');
    });

    it('bounds the connections one listener serves and releases the network\'s listener when the caller goes away', async () => {
      const vnet = createVirtualNetwork();
      const { client } = await setup(vnet, { allow: [], reverse: { maxConnectionsPerListener: 1 } });
      const opened = [];
      const handle = await client.listenTcp(0, { onConnection: (d) => { opened.push(d); } });
      const first = vnet.connectTo(handle.port);
      await until(() => opened.length === 1, 'the first connection');
      const second = vnet.connectTo(handle.port);
      void first; void second;
      await until(() => vnet.conns[1]?.serviceCancelled && vnet.conns[1]?.clientAborted, 'the second to be dropped by the host');
      assert.equal(opened.length, 1, 'and it was never announced');
      await client.disconnect();
      await until(() => vnet.calls.listen[0].signal.aborted, 'the listener to be released');
    });
  });

  describe('the caller\'s capabilities decide who may ask, as they always have', () => {
    it('a key without the gateway capability is refused before any policy or network is consulted; with it, served', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService } });
      const withCap = `capabilities="gateway:tcp:93.184.216.7:7" ${line}`;
      const other = await generateKeyPair(true);
      const noCap = `capabilities="exec" ${await exportPublicKeySSH(other.publicKey)} bob`;
      const h = createMemoryHost({ auth: { authorizedKeys: `${withCap}\n${noCap}` }, gateway: { network: vnet.network, allow: ['*'] } });
      hosts.push(h);
      const ok = await h.connect({ username: 'alice', keyPair }); clients.push(ok);
      (await ok.openTcp('93.184.216.7', 7)).destroy();
      await refused(ok.openTcp('93.184.216.7', 8), /capability/);
      const bad = await h.connect({ username: 'bob', keyPair: other }); clients.push(bad);
      await refused(bad.openTcp('93.184.216.7', 7), /capability/);
      assert.equal(vnet.calls.connect.length, 1);
    });
  });

  describe('through the pipe relay', () => {
    it('a client reaches the host\'s network through a relay that only copies bytes; the policy is the same', async () => {
      const relay = createPipeRelay({ rendezvousTimeoutMs: 5000 });
      const { port } = await relay.listen();
      closers.push(() => relay.close());
      const url = `ws://127.0.0.1:${port}`;
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService, '10.0.0.5:7': echoService }, names: { 'svc.test': ['10.0.0.5'] } });
      const h = createMemoryHost({ auth: { authorizedKeys: [raw] }, gateway: { network: vnet.network, allow: ['93.184.216.7:7', 'svc.test'] } });
      hosts.push(h);
      const id = newRendezvousId();
      const hostSocket = new WsClient(pipeUrl(url, id, 'host'));
      closers.push(async () => hostSocket.terminate());
      await h.accept(hostSocket, { dataStreams: false });
      const client = new WshClient();
      clients.push(client);
      await client.connect(pipeUrl(url, id, 'operator'), { username: 'alice', keyPair, transport: 'ws' });
      const d = await client.openTcp('93.184.216.7', 7);
      const w = d.writable.getWriter(); await w.write(enc.encode('over the relay')); await w.close();
      assert.equal(dec.decode(await readAll(d.readable)), 'over the relay');
      await refused(client.openTcp('svc.test', 7), /not permitted/);
      await refused(client.openTcp('93.184.216.8', 7), /not allowed/);
      assert.deepEqual(vnet.calls.connect.map((c) => c.host), ['93.184.216.7']);
    });
  });

  describe('the Node host takes an injected network too, and its own default is untouched', () => {
    it('createWshServer({ gateway: { network } }) serves the same way (the machine\'s sockets are not used)', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService } });
      const server = createWshServer({ auth: { authorizedKeys: line }, gateway: { network: vnet.network, allow: ['93.184.216.7:7'] } });
      const { port } = await server.listen();
      closers.push(() => server.close());
      const client = new WshClient(); clients.push(client);
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
      const d = await client.openTcp('93.184.216.7', 7);
      const w = d.writable.getWriter(); await w.write(enc.encode('node')); await w.close();
      assert.equal(dec.decode(await readAll(d.readable)), 'node');
      assert.equal(vnet.calls.connect.length, 1);
    });
  });

  describe('a reverse host that runs in a page (the browser-safe createReverseHost)', () => {
    it('serves an operator behind a relay over the injected network; without a network it refuses to start', async () => {
      assert.throws(() => createReverseHost({ url: 'ws://x', username: 'h', keyPair, gateway: { allow: ['*'], trustRelayIdentity: true } }), /network/);
      const keys = {};
      for (const n of ['host', 'op']) { const kp = await generateKeyPair(true); keys[n] = { kp, fp: await fingerprint(await exportPublicKeyRaw(kp.publicKey)), line: `${await exportPublicKeySSH(kp.publicKey)} ${n}` }; }
      const server = createWshServer({ auth: { authorizedKeys: `${keys.host.line}\n${keys.op.line}` }, relay: { canRegister: (w) => w.username === 'host', canConnect: (f) => f.username !== 'host' } });
      const { port } = await server.listen();
      closers.push(() => server.close());
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService }, names: { 'svc.test': ['93.184.216.7'] } });
      const rh = createReverseHost({
        url: `ws://127.0.0.1:${port}`, username: 'host', keyPair: keys.host.kp, reconnect: false,
        accept: () => ({ capabilities: ['gateway:tcp:*:*', 'gateway:udp:*:*'] }),
        gateway: { network: vnet.network, allow: ['93.184.216.7:7', 'svc.test:7'], trustRelayIdentity: true },
      });
      await rh.start();
      closers.push(() => rh.close());
      await until(() => server.peerFingerprints().includes(keys.host.fp), 'the host to register');
      const op = new WshClient(); clients.push(op);
      await op.connect(`ws://127.0.0.1:${port}`, { username: 'op', keyPair: keys.op.kp });
      const accepted = await op.reverseConnect(keys.host.fp);
      assert.equal(accepted.type, MSG.REVERSE_ACCEPT, accepted.reason);
      const d = await op.openTcp('svc.test', 7);
      const w = d.writable.getWriter(); await w.write(enc.encode('behind a relay')); await w.close();
      assert.equal(dec.decode(await readAll(d.readable)), 'behind a relay');
      assert.deepEqual(vnet.calls.connect.map((c) => c.host), ['93.184.216.7']);
      // the owner's separate switches: UDP and DNS were not turned on
      await refused(op.openUdp('93.184.216.7', 53), /UDP is not enabled/);
    });
  });

  describe('the gateway session is loaded only by a host that was given a gateway (lazy import)', () => {
    const child = (mode) => new Promise((resolve, reject) => {
      execFile(process.execPath, [new URL('./helpers/lazy-gateway-child.mjs', import.meta.url).pathname, mode], { env: { ...process.env, NODE_NO_WARNINGS: '1' } }, (err, out, errOut) => {
        if (err) reject(new Error(`${err.message}\n${errOut}`)); else resolve(JSON.parse(out.trim().split('\n').pop()));
      });
    });

    it('a host created WITHOUT a gateway never loads the session module, not even after a client connected', async () => {
      assert.deepEqual(await child('none'), { before: false, afterConnect: false, afterGateway: null });
    });

    it('a host created with one loads it, and has it by the time a connection is served', async () => {
      const seen = await child('gateway');
      assert.equal(seen.afterConnect, true);
      assert.equal(seen.afterGateway, true);
    });

    it('a gateway whose shape is wrong throws at creation, at once', () => {
      assert.throws(() => createMemoryHost({ gateway: { network: { connectTcp: 1 }, allow: [] } }), /connectTcp must be a function/);
      assert.throws(() => createMemoryHost({ gateway: { network: { connect() {} }, allow: [] } }), /not a network method/);
      assert.throws(() => createReverseHost({ url: 'ws://x', username: 'h', keyPair, gateway: { network: {}, allow: [], trustRelayIdentity: true } }), /at least one/);
      assert.throws(() => createReverseHost({ url: 'ws://x', username: 'h', keyPair, gateway: { network: { connectTcp() {} }, allow: [] } }), /requireOperatorProof|trustRelayIdentity/);
    });

    it('a gateway that is invalid in a value fails LOUDLY: host.ready rejects, accept() rejects, a connection is refused at once and onLog is told', async () => {
      const logs = [];
      const h = createMemoryHost({ auth: { authorizedKeys: [raw] }, onLog: (l) => logs.push(l), gateway: { network: { connectTcp() {} }, allow: ['*'], maxConnections: -1 } });
      hosts.push(h);
      await assert.rejects(h.ready, /maxConnections/);
      const [a, b] = h.socketPair();
      await assert.rejects(h.accept(b), /maxConnections/);
      a.close();
      const t0 = Date.now();
      await assert.rejects(h.connect({ username: 'alice', keyPair }));
      assert.ok(Date.now() - t0 < 5000, 'refused, not timed out');
      assert.ok(logs.some((l) => /maxConnections/.test(l)), logs.join('\n'));
    });

    it('a reverse host with an invalid gateway value refuses to start, with the reason, before it dials', async () => {
      const rh = createReverseHost({ url: 'ws://127.0.0.1:1', username: 'host', keyPair, reconnect: false, gateway: { network: { connectTcp() {} }, allow: [], trustRelayIdentity: true, maxConnections: -1 } });
      await assert.rejects(rh.start(), /maxConnections/);
    });

    it('two connections racing the first load both work', async () => {
      const vnet = createVirtualNetwork({ services: { '93.184.216.7:7': echoService } });
      const h = createMemoryHost({ auth: { authorizedKeys: [raw] }, gateway: { network: vnet.network, allow: ['93.184.216.7'] } });
      hosts.push(h);
      const [c1, c2] = await Promise.all([h.connect({ username: 'alice', keyPair }), h.connect({ username: 'alice', keyPair })]);
      clients.push(c1, c2);
      const run = async (c, text) => {
        const d = await c.openTcp('93.184.216.7', 7);
        const w = d.writable.getWriter(); await w.write(enc.encode(text)); await w.close();
        return dec.decode(await readAll(d.readable));
      };
      assert.deepEqual(await Promise.all([run(c1, 'one'), run(c2, 'two')]), ['one', 'two']);
    });
  });
});
