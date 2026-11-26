// test/relay-gateway.test.mjs -- an operator behind a relay uses a reverse host's gateway (#289): the JS relay and the JS reverse host.
//
// What is pinned, each as a test that fails when its rule is broken (see the CHANGELOG for the mutations tried):
//  - nothing is carried unless the host's owner turned the gateway on (the feature is not stated, the relay carries nothing, nothing is dialled);
//  - an operator uses it only with a granted capability; the host's destination policy, UDP / DNS / listen switches and bounds apply;
//  - the relay carries the requests only for a host that stated `relay-gateway`, and only if the relay itself does (`carryGateway`);
//  - every connection is metered (a slow reader stops the sender; nothing grows without bound), half-close works both ways, a large answer arrives whole;
//  - a sealed bridge carries the requests as sealed frames the relay cannot read.
//
// Nothing is slept for as a fix: the ordering checks send a message that IS carried (an exec) after the one under test and wait for its
// answer, since messages cross a bridge in order.
import { describe, it, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import dgram from 'node:dgram';
import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { RelayHub } from '../src/server/relay.mjs';
import {
  WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG, RELAY_GATEWAY_FEATURE,
  openTcp, openUdp, resolveDns, listenRequest,
} from '@johnhenry/wsh';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 8000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
const dec = new TextDecoder();

/** One round trip through an echo duplex, then close it. */
async function roundTrip(duplex, text) {
  const writer = duplex.writable.getWriter();
  await writer.write(new TextEncoder().encode(text));
  const { value } = await duplex.readable.getReader().read();
  duplex.destroy();
  return dec.decode(value);
}

/** Read a duplex until its end; resolves with the total number of bytes (and the first `keep` bytes as text). */
async function drain(duplex, { keep = 0, slowEvery = 0 } = {}) {
  const reader = duplex.readable.getReader();
  let n = 0; let text = ''; let chunks = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    n += value.length;
    if (text.length < keep) text += dec.decode(value);
    if (slowEvery && ++chunks % slowEvery === 0) await sleep(1);
  }
  return { n, text };
}

describe('a relay carries the gateway of a reverse host that turned it on (#289)', () => {
  const keys = {};
  let authorizedKeys;
  const servers = []; const clients = []; const hosts = []; const nets = []; const udps = [];
  const spies = [];
  before(async () => {
    for (const name of ['host', 'op', 'op2']) {
      const keyPair = await generateKeyPair(true);
      keys[name] = { keyPair, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)) };
    }
    authorizedKeys = (await Promise.all(Object.entries(keys).map(async ([n, k]) => `${await exportPublicKeySSH(k.keyPair.publicKey)} ${n}`))).join('\n');
  });
  afterEach(async () => {
    for (const s of spies.splice(0)) s();
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const h of hosts.splice(0)) await h.close().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
    for (const n of nets.splice(0)) n.close();
    for (const u of udps.splice(0)) u.close();
  });

  /** An echo origin ("echo:" + what it got); `sockets` lists every connection it accepted. */
  async function echoOrigin() {
    const sockets = [];
    const server = net.createServer((s) => { sockets.push(s); s.on('data', (d) => s.write(Buffer.concat([Buffer.from('echo:'), d]))); s.on('error', () => {}); });
    const port = await listen(server); nets.push(server);
    return { port, sockets, server };
  }

  /** Count what the relay carries, by inner message type, and the bytes of GatewayData each way. */
  function tapRelay() {
    const seen = []; const types = [];
    const original = RelayHub.prototype.forward;
    RelayHub.prototype.forward = function spy(handle, msg) {
      const forwarded = original.call(this, handle, msg);
      seen.push({ from: handle.fingerprint, type: msg.type, forwarded });
      types.push(msg.type);
      return forwarded;
    };
    spies.push(() => { RelayHub.prototype.forward = original; });
    return { seen, types };
  }

  async function setup({ gateway, accept = () => ({ capabilities: ['exec', 'gateway:tcp:*:*', 'gateway:udp:*:*', 'gateway:listen:tcp:*'] }), relay = {}, host = {}, features = true } = {}) {
    const server = createWshServer({
      auth: { authorizedKeys },
      relay: { canRegister: (w) => w.username === 'host', canConnect: (f) => f.username !== 'host', ...relay },
    });
    const { port } = await server.listen();
    servers.push(server);
    const url = `ws://127.0.0.1:${port}`;
    const h = createReverseHost({
      url, username: 'host', keyPair: keys.host.keyPair, exec: true, pty: false, reconnect: false, accept,
      // A gateway needs the owner to have chosen how identities are taken (proof, or trusting the relay's word): these tests trust it unless they seal.
      ...(gateway === undefined ? {} : { gateway: { ...(host.requireOperatorProof ? {} : { trustRelayIdentity: true }), ...gateway } }), reportFeatures: features, ...host,
    });
    await h.start();
    hosts.push(h);
    await until(() => server.peerFingerprints().includes(keys.host.fp), 'the host to register');
    return { server, url, host: h };
  }
  async function operator(url, { name = 'op', connectOptions } = {}) {
    const c = new WshClient();
    await c.connect(url, { username: name, keyPair: keys[name].keyPair });
    clients.push(c);
    const accepted = await c.reverseConnect(keys.host.fp, undefined, connectOptions);
    assert.equal(accepted.type, MSG.REVERSE_ACCEPT, accepted.reason);
    return { c, accepted };
  }
  /** A message that IS carried, sent after the one under test: its answer says everything before it was served. */
  async function canary(c) {
    const s = await c.openSession({ type: 'exec', command: 'echo canary' });
    assert.ok(s, 'the host served what is carried');
    s.close?.();
  }

  describe('off unless the host turned it on', () => {
    it('a host without a gateway does not state relay-gateway; the relay carries nothing; nothing is dialled', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({}); // no gateway option
      const tap = tapRelay();
      const { c, accepted } = await operator(url);
      assert.ok(!(accepted.features ?? []).includes(RELAY_GATEWAY_FEATURE));
      assert.ok(!(accepted.features ?? []).includes('gateway'));
      // The client refuses to try: the host does not say it serves a gateway.
      await assert.rejects(c.openTcp('127.0.0.1', origin.port), /does not support TCP egress/);
      // Raw messages, as a client that ignores the features would send them: not carried, not answered, nothing dialled.
      const heard = [];
      c.onGatewayMessage = (m) => heard.push(m.type);
      for (const m of [openTcp({ gatewayId: 1, host: '127.0.0.1', port: origin.port }), openUdp({ gatewayId: 2, host: '127.0.0.1', port: 9 }),
        resolveDns({ gatewayId: 3, name: 'localhost' }), listenRequest({ listenerId: 4, port: 0 })]) await c.sendControl(m);
      await canary(c);
      assert.deepEqual(heard, [], 'nothing came back');
      assert.equal(origin.sockets.length, 0, 'the origin was never dialled');
      assert.ok(!tap.seen.some((s) => s.forwarded && [MSG.OPEN_TCP, MSG.OPEN_UDP, MSG.RESOLVE_DNS, MSG.LISTEN_REQUEST].includes(s.type)), 'the relay carried none of the four');
    });

    it('a host that turned it on says so, with the gateway features', async () => {
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'] } });
      const { accepted } = await operator(url);
      for (const f of [RELAY_GATEWAY_FEATURE, 'gateway', 'gateway-credit']) assert.ok(accepted.features.includes(f), `${f} in ${accepted.features}`);
      assert.ok(!accepted.features.includes('gateway-unix') && !accepted.features.includes('gateway-endpoints'), 'only what a relay carries is stated');
    });

    it('a relay that does not carry it (carryGateway: false) is not told by a host, which then states no gateway', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'] }, relay: { carryGateway: false } });
      const { c, accepted } = await operator(url);
      assert.ok(!accepted.features.includes(RELAY_GATEWAY_FEATURE) && !accepted.features.includes('gateway'));
      await assert.rejects(c.openTcp('127.0.0.1', origin.port), /does not support TCP egress/);
    });

    it('relay.carryGateway must be a boolean', () => {
      assert.throws(() => createWshServer({ auth: { authorizedKeys }, relay: { carryGateway: 'yes' } }), /carryGateway must be a boolean/);
    });

    it('gateway options a relay does not carry are refused at construction', () => {
      const t = { trustRelayIdentity: true };
      for (const bad of [{ allow: [], unix: { connect: ['/tmp/x'] } }, { allow: [], endpoints: {} }, { allow: [], tcp: false }, true, { allow: [], bogus: 1 }]) {
        assert.throws(() => createReverseHost({ url: 'ws://x', username: 'h', keyPair: keys.host.keyPair, gateway: bad === true ? bad : { ...t, ...bad } }), TypeError);
      }
      assert.throws(() => createReverseHost({ url: 'ws://x', username: 'h', keyPair: keys.host.keyPair, gateway: { allow: [], ...t }, reportFeatures: false }), /needs reportFeatures/);
    });

    it('a gateway starts only when the owner chose how identities are taken: operator proof (sealed bridge) or an explicit trust of the relay\'s word', () => {
      const base = { url: 'ws://x', username: 'h', keyPair: keys.host.keyPair };
      assert.throws(() => createReverseHost({ ...base, gateway: { allow: ['127.0.0.1'] } }), /requireOperatorProof: true.*trustRelayIdentity: true/);
      assert.throws(() => createReverseHost({ ...base, gateway: { allow: ['127.0.0.1'], trustRelayIdentity: false } }), /trustRelayIdentity/);
      assert.throws(() => createReverseHost({ ...base, gateway: { allow: ['127.0.0.1'], trustRelayIdentity: 'yes' } }), /must be a boolean/);
      assert.doesNotThrow(() => createReverseHost({ ...base, gateway: { allow: ['127.0.0.1'], trustRelayIdentity: true } }));
      assert.doesNotThrow(() => createReverseHost({ ...base, gateway: { allow: ['127.0.0.1'] }, requireOperatorProof: true }));
    });
  });

  describe('forwarded end to end', () => {
    it('TCP: an operator opens a connection through the relay and talks to an origin on the host\'s network', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'] } });
      const { c } = await operator(url);
      const d = await c.openTcp('127.0.0.1', origin.port);
      const writer = d.writable.getWriter();
      await writer.write(new TextEncoder().encode('hello'));
      const reader = d.readable.getReader();
      const { value } = await reader.read();
      assert.equal(dec.decode(value), 'echo:hello');
      writer.releaseLock();
      d.close();
      assert.equal(origin.sockets.length, 1);
    });

    it('DNS: ResolveDns is answered when the owner turned name resolution on', async () => {
      const { url } = await setup({ gateway: { allow: ['localhost'], allowPrivate: ['127.0.0.0/8', '::1/128'], dns: true } });
      const { c } = await operator(url);
      const inbox = [];
      c.onGatewayMessage = (m) => inbox.push(m);
      await c.sendControl(resolveDns({ gatewayId: 31, name: 'localhost' }));
      const r = await until(() => inbox.find((m) => m.type === MSG.DNS_RESULT && m.gateway_id === 31), 'the DnsResult');
      assert.ok(r.addresses.includes('127.0.0.1') || r.addresses.includes('::1'), `${r.addresses}`);
    });

    it('UDP: a flow is opened through the relay when the owner turned UDP on', async () => {
      const udp = dgram.createSocket('udp4');
      udps.push(udp);
      udp.on('message', (msg, rinfo) => udp.send(Buffer.concat([Buffer.from('udp:'), msg]), rinfo.port, rinfo.address));
      await new Promise((r) => udp.bind(0, '127.0.0.1', r));
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'], udp: true } });
      const { c } = await operator(url);
      const d = await c.openUdp('127.0.0.1', udp.address().port);
      const writer = d.writable.getWriter();
      await writer.write(new TextEncoder().encode('ping'));
      const { value } = await d.readable.getReader().read();
      assert.equal(dec.decode(value), 'udp:ping');
      d.destroy?.();
    });

    it('listen: a reverse tunnel is opened through the relay when the owner turned it on, and a caller of the host\'s port reaches the operator', async () => {
      const { url } = await setup({ gateway: { allow: [], reverse: true } });
      const { c } = await operator(url);
      const connected = new Promise((resolve, reject) => {
        c.listenTcp(0, {
          onConnection: async (duplex, info) => {
            try {
              const reader = duplex.readable.getReader();
              const { value } = await reader.read();
              const writer = duplex.writable.getWriter();
              await writer.write(new TextEncoder().encode(`back:${dec.decode(value)}`));
              duplex.close();
              resolve(info);
            } catch (e) { reject(e); }
          },
        }).then(async (l) => {
          const caller = net.connect(l.port, '127.0.0.1');
          caller.on('error', () => {});
          caller.write('knock');
          let answer = '';
          caller.on('data', (d) => { answer += d; });
          await until(() => answer === 'back:knock', 'the answer through the tunnel');
          caller.destroy();
          await l.close();
        }).catch(reject);
      });
      const info = await connected;
      assert.equal(info.peer, '127.0.0.1');
    });
  });

  describe('the host decides', () => {
    it('an operator that accept() did not grant a gateway capability is refused, and nothing is dialled', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'] }, accept: () => true });
      const { c } = await operator(url);
      await assert.rejects(c.openTcp('127.0.0.1', origin.port), (e) => e.code === 4 && /capability/.test(e.message));
      assert.equal(origin.sockets.length, 0);
    });

    it('accept() answering an object that is not a grant (no capabilities, or one that does not parse) refuses the operator, as an object always did', async () => {
      for (const verdict of [{ fingerprint: 'x' }, { capabilities: 'nonsense:cap' }, {}]) {
        const { url } = await setup({ gateway: { allow: ['127.0.0.1'] }, accept: () => verdict });
        const c = new WshClient();
        await c.connect(url, { username: 'op', keyPair: keys.op.keyPair });
        clients.push(c);
        const r = await c.reverseConnect(keys.host.fp);
        assert.equal(r.type, MSG.REVERSE_REJECT, JSON.stringify(verdict));
        await c.disconnect();
        for (const h of hosts.splice(0)) await h.close();
        for (const s of servers.splice(0)) await s.close();
      }
    });

    it('a grant that names another destination does not open this one', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'] }, accept: () => ({ capabilities: [`gateway:tcp:127.0.0.1:${origin.port + 1}`] }) });
      const { c } = await operator(url);
      await assert.rejects(c.openTcp('127.0.0.1', origin.port), (e) => e.code === 4);
      assert.equal(origin.sockets.length, 0);
    });

    it('the destination policy applies: a destination no allow rule names is refused', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({ gateway: { allow: ['example.invalid'] } });
      const { c } = await operator(url);
      await assert.rejects(c.openTcp('127.0.0.1', origin.port), (e) => e.code === 4 && /not allowed/.test(e.message));
      assert.equal(origin.sockets.length, 0);
    });

    it('a name that resolves to a loopback address is refused unless a rule names the address', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({ gateway: { allow: ['localhost'] } });
      const { c } = await operator(url);
      await assert.rejects(c.openTcp('localhost', origin.port), (e) => e.code === 4);
      assert.equal(origin.sockets.length, 0);
    });

    it('UDP, name resolution and reverse tunnels are each off unless the owner turned them on', async () => {
      const { url } = await setup({ gateway: { allow: ['127.0.0.1', 'localhost'], allowPrivate: ['127.0.0.0/8'] } });
      const { c } = await operator(url);
      await assert.rejects(c.openUdp('127.0.0.1', 9), (e) => e.code === 4 && /UDP is not enabled/.test(e.message));
      await assert.rejects(c.listenTcp(0, { onConnection() {} }), (e) => e.code === 4);
      const inbox = [];
      c.onGatewayMessage = (m) => inbox.push(m);
      await c.sendControl(resolveDns({ gatewayId: 41, name: 'localhost' }));
      const f = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 41), 'the refusal');
      assert.equal(f.code, 4);
      assert.match(f.message, /name resolution is not enabled/);
    });

    it('each switch is separate: UDP on does not turn DNS or listening on', async () => {
      const { url } = await setup({ gateway: { allow: ['localhost'], allowPrivate: ['127.0.0.0/8'], udp: true } });
      const { c } = await operator(url);
      const inbox = [];
      c.onGatewayMessage = (m) => inbox.push(m);
      await c.sendControl(resolveDns({ gatewayId: 51, name: 'localhost' }));
      await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 51), 'the refusal');
      await assert.rejects(c.listenTcp(0, { onConnection() {} }), (e) => e.code === 4);
    });

    it('at most maxConnections connections are open at once', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'], maxConnections: 2 } });
      const { c } = await operator(url);
      const a = await c.openTcp('127.0.0.1', origin.port);
      const b = await c.openTcp('127.0.0.1', origin.port);
      await assert.rejects(c.openTcp('127.0.0.1', origin.port), (e) => e.code === 7);
      a.destroy(); b.destroy();
    });
  });

  describe('several operators on one host', () => {
    it('each operator has a gateway of its own: the same connection ids, separate bounds, and one leaving closes only its connections', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'], maxConnections: 2 }, relay: { maxOperatorsPerPeer: 2 }, host: { maxOperators: 2 } });
      const a = (await operator(url, { name: 'op' })).c;
      const b = (await operator(url, { name: 'op2' })).c;
      // Both start their connection ids at the same number; each operator's `max 2` is its own.
      const a1 = await a.openTcp('127.0.0.1', origin.port);
      const a2 = await a.openTcp('127.0.0.1', origin.port);
      await assert.rejects(a.openTcp('127.0.0.1', origin.port), (e) => e.code === 7);
      const b1 = await b.openTcp('127.0.0.1', origin.port);
      assert.equal(await roundTrip(b1, 'from b'), 'echo:from b');
      assert.equal(await roundTrip(a1, 'from a'), 'echo:from a');
      // `a` leaves: `b` keeps working.
      await a.disconnect();
      void a2;
      const b2 = await b.openTcp('127.0.0.1', origin.port);
      assert.equal(await roundTrip(b2, 'still b'), 'echo:still b');
    });
  });

  describe('what the relay holds for a recipient that does not keep up', () => {
    it('delivers in order, one at a time, and past the bound refuses everything (nothing is delivered after a hole)', async () => {
      const { ForwardQueue } = await import('../src/server/relay.mjs');
      const q = new ForwardQueue(100);
      const sent = []; let release;
      const gate = new Promise((r) => { release = r; });
      assert.ok(q.push(async () => { await gate; sent.push(1); }, 40));
      assert.ok(q.push(() => { sent.push(2); }, 40), 'queued behind the first, not run beside it');
      assert.deepEqual(sent, []);
      assert.ok(!q.push(() => { sent.push(3); }, 40), 'over the bound: refused');
      assert.ok(q.dead);
      assert.ok(!q.push(() => { sent.push(4); }, 1), 'and everything after it');
      release();
      await sleep(20);
      assert.deepEqual(sent, [], 'the queue is dead: nothing more is sent, not even what was queued (the recipient is being closed)');
    });
  });

  describe('the relay stays a carrier', () => {
    it('a request is carried only for a host that stated relay-gateway: a host that did not gets nothing, even when asked directly', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({}); // a host with no gateway
      const tap = tapRelay();
      const { c } = await operator(url);
      await c.sendControl(openTcp({ gatewayId: 1, host: '127.0.0.1', port: origin.port }));
      await canary(c);
      const carried = tap.seen.filter((s) => s.type === MSG.OPEN_TCP);
      assert.equal(carried.length, 1);
      assert.equal(carried[0].forwarded, false, 'the relay did not forward it');
    });

    it('with carryGateway: false the relay does not carry them for a host that asks either', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'] }, relay: { carryGateway: false } });
      const tap = tapRelay();
      const { c } = await operator(url);
      await c.sendControl(openTcp({ gatewayId: 1, host: '127.0.0.1', port: origin.port }));
      await canary(c);
      assert.equal(tap.seen.find((s) => s.type === MSG.OPEN_TCP).forwarded, false);
      assert.equal(origin.sockets.length, 0);
    });

    it('a relay does not open anything on the host by itself: with no operator\'s request nothing is dialled', async () => {
      const origin = await echoOrigin();
      await setup({ gateway: { allow: ['127.0.0.1'] } });
      await sleep(50);
      assert.equal(origin.sockets.length, 0);
    });
  });

  describe('an operator sends only where it is carried; a relay carries only what its host and it both state', () => {
    /** A peer that registers and answers a connect with exactly these features, recording what the relay delivers to it. */
    async function fakeHost({ features, relay = {}, serverGateway }) {
      const server = createWshServer({ auth: { authorizedKeys }, ...(serverGateway ? { gateway: serverGateway } : {}), relay: { canRegister: (w) => w.username === 'host', canConnect: (f) => f.username !== 'host', ...relay } });
      const { port } = await server.listen(); servers.push(server);
      const url = `ws://127.0.0.1:${port}`;
      const fake = new WshClient();
      await fake.connectReverse(url, { username: 'host', keyPair: keys.host.keyPair, expose: { exec: true, gateway: true } });
      clients.push(fake);
      const delivered = [];
      fake.onRelayMessage = (m) => delivered.push(m.type);
      fake.onReverseConnect = async (req) => {
        fake.trustRelayPeer(req.from_fingerprint);
        await fake.sendRelayControl({ type: MSG.REVERSE_ACCEPT, target_fingerprint: keys.host.fp, username: 'host', capabilities: ['exec'], peer_type: 'host', shell_backend: 'exec-only', supports_attach: false, supports_replay: false, supports_echo: false, supports_term_sync: false, features });
      };
      await until(() => server.peerFingerprints().includes(keys.host.fp), 'the fake host to register');
      return { url, delivered };
    }

    it('a host that lists "gateway" but not "relay-gateway" is not sent the requests; the operator refuses locally and nothing leaves', async () => {
      // A peer that stated gateway features without the relay feature (a custom or older reverse handler): the operator must not
      // send what the relay would answer itself.
      const { url, delivered } = await fakeHost({ features: ['gateway', 'gateway-credit'] });
      const { c, accepted } = await operator(url);
      assert.ok(accepted.features.includes('gateway') && !accepted.features.includes(RELAY_GATEWAY_FEATURE));
      await assert.rejects(c.openTcp('127.0.0.1', 1), (e) => e.code === 4 && /does not state "relay-gateway"/.test(e.message));
      assert.deepEqual(delivered, [], 'nothing reached the host');
    });

    it('bridged to a host that stated no features, the operator never reaches the RELAY\'s own gateway by accident: it refuses and says why', async () => {
      const origin = await echoOrigin();
      const { url, delivered } = await fakeHost({ features: undefined, serverGateway: { allow: ['127.0.0.1'] } });
      const { c } = await operator(url);
      await assert.rejects(c.openTcp('127.0.0.1', origin.port), (e) => e.code === 4 && /relay-gateway/.test(e.message));
      assert.equal(origin.sockets.length, 0, 'the relay did not dial for it');
      assert.deepEqual(delivered, []);
      // The unbridged API: a client that is NOT bridged reaches the relay's own gateway, as always.
      const direct = new WshClient();
      await direct.connect(url, { username: 'op2', keyPair: keys.op2.keyPair });
      clients.push(direct);
      const d = await direct.openTcp('127.0.0.1', origin.port);
      assert.equal(await roundTrip(d, 'direct'), 'echo:direct');
    });

    it('a host that states relay-gateway on a relay that does not (carryGateway: false) is still not sent them; the operator says why', async () => {
      const { url, delivered } = await fakeHost({ features: [RELAY_GATEWAY_FEATURE, 'gateway', 'gateway-credit'], relay: { carryGateway: false } });
      const tap = tapRelay();
      const { c } = await operator(url);
      await assert.rejects(c.openTcp('127.0.0.1', 1), (e) => e.code === 4 && /this relay does not state "relay-gateway"/.test(e.message));
      // And a client that sends anyway (raw): the relay itself does not carry it.
      await c.sendControl(openTcp({ gatewayId: 9, host: '127.0.0.1', port: 1 }));
      const seen = await until(() => tap.seen.find((s) => s.type === MSG.OPEN_TCP), 'the relay to handle the request');
      assert.equal(seen.forwarded, false);
      assert.ok(!delivered.includes(MSG.OPEN_TCP));
    });

    it('a host that states relay-gateway on a relay that carries it IS sent them (the control for the two above)', async () => {
      const { url, delivered } = await fakeHost({ features: [RELAY_GATEWAY_FEATURE, 'gateway', 'gateway-credit'] });
      const { c } = await operator(url);
      c.openTcp('127.0.0.1', 1).catch(() => {}); // the fake never answers
      await until(() => delivered.includes(MSG.OPEN_TCP), 'the request to reach the host');
    });
  });

  describe('flow control and half-close', () => {
    it('a slow reader stops the origin: what is in flight stays bounded by the credit window, and every byte still arrives', async () => {
      const SIZE = 12 * 1024 * 1024;
      let written = 0; let originSocket = null;
      const server = net.createServer((s) => {
        originSocket = s; s.on('error', () => {});
        const chunk = Buffer.alloc(64 * 1024, 5);
        const pump = () => { while (written < SIZE) { written += chunk.length; if (!s.write(chunk)) { s.once('drain', pump); return; } } s.end(); };
        pump();
      });
      const port = await listen(server); nets.push(server);
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'] } });
      const tap = tapRelay();
      const { c } = await operator(url);
      const d = await c.openTcp('127.0.0.1', port);
      // Not reading: the origin may get only the credit window ahead plus what the sockets hold. Wait until it stops making progress.
      let last = -1;
      await until(async () => { await sleep(100); const now = written; const stalled = now === last && now > 0; last = now; return stalled; }, 'the origin to stall');
      assert.ok(originSocket, 'the origin was dialled');
      assert.ok(written < 8 * 1024 * 1024, `the origin got ${written} bytes ahead of a reader that read nothing (the window is 256 KiB)`);
      const stalledAt = written;
      const dataBeforeReading = tap.types.filter((t) => t === MSG.GATEWAY_DATA).length;
      assert.ok(dataBeforeReading * 1 <= 8, `${dataBeforeReading} GatewayData crossed the relay with nobody reading (credit window is 256 KiB of 64 KiB frames)`);
      const { n } = await drain(d, { slowEvery: 16 });
      assert.equal(n, SIZE);
      assert.ok(written > stalledAt);
    });

    it('a saturated relay: twelve connections to an operator that reads nothing for a while, every one byte-exact and in order afterwards', async () => {
      const CONNS = 12; const SIZE = 3 * 1024 * 1024;
      let accepted = 0;
      const origin = net.createServer((s) => {
        accepted++; s.on('error', () => {});
        const chunk = Buffer.alloc(64 * 1024); let n = 0;
        const pump = () => { while (n < SIZE) { const piece = Buffer.alloc(65536, (n / 65536) % 251); n += piece.length; if (!s.write(piece)) { s.once('drain', pump); return; } } s.end(); };
        pump();
      });
      const port = await listen(origin); nets.push(origin);
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'], maxConnections: CONNS } });
      const { c } = await operator(url);
      const ds = [];
      for (let i = 0; i < CONNS; i++) ds.push(await c.openTcp('127.0.0.1', port));
      await until(() => accepted === CONNS, 'every origin to be dialled');
      await sleep(1500); // nobody reads: what is in flight piles up in the relay and the sockets, bounded by credit
      const results = await Promise.all(ds.map(async (d) => {
        const reader = d.readable.getReader();
        let n = 0; let ordered = true;
        for (;;) { const { value, done } = await reader.read(); if (done) break; for (let i = 0; i < value.length; i += 997) { if (value[i] !== Math.floor((n + i) / 65536) % 251) ordered = false; } n += value.length; }
        return { n, ordered };
      }));
      for (const r of results) { assert.equal(r.n, SIZE); assert.ok(r.ordered, 'in order'); }
    });

    it('half-close both ways: the operator half-closes first and still gets the whole large answer; the origin sees the end of file after the request', async () => {
      const SIZE = 3 * 1024 * 1024;
      let request = '';
      const server = net.createServer({ allowHalfOpen: true }, (s) => {
        s.on('error', () => {});
        s.on('data', (d) => { request += d; });
        s.once('end', () => { s.end(Buffer.alloc(SIZE, 9), () => s.destroy()); }); // answers after the request's end, then closes completely
      });
      const port = await listen(server); nets.push(server);
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'], halfCloseIdleMs: 0 } });
      const { c } = await operator(url);
      const d = await c.openTcp('127.0.0.1', port);
      const writer = d.writable.getWriter();
      await writer.write(new TextEncoder().encode('the request'));
      await writer.close(); // the operator's half-close
      const { n } = await drain(d, { slowEvery: 8 });
      assert.equal(n, SIZE, 'the whole answer');
      assert.equal(request, 'the request');
    });

    it('half-close the other way: the origin finishes, the operator can still send', async () => {
      let got = '';
      const server = net.createServer({ allowHalfOpen: true }, (s) => {
        s.on('error', () => {});
        s.on('data', (d) => { got += d; });
        s.end('bye'); // the origin's end first
      });
      const port = await listen(server); nets.push(server);
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'], halfCloseIdleMs: 0 } });
      const { c } = await operator(url);
      const d = await c.openTcp('127.0.0.1', port);
      const reader = d.readable.getReader();
      let text = '';
      for (;;) { const { value, done } = await reader.read(); if (done) break; text += dec.decode(value); }
      assert.equal(text, 'bye');
      const writer = d.writable.getWriter();
      await writer.write(new TextEncoder().encode('afterwards'));
      await until(() => got === 'afterwards', 'what the operator sent after the origin finished');
      d.destroy();
    });
  });

  describe('a relay that tampers with a sealed bridge is detected, and the bridge ends', () => {
    /** Patch the relay so the operator's sealed frames (bridge-level EncryptedFrames) are altered, replayed or reordered on their way. */
    function tamper(mode) {
      const original = RelayHub.prototype.forward;
      let held = null; let n = 0;
      RelayHub.prototype.forward = function patched(handle, msg) {
        if (msg.type !== MSG.ENCRYPTED_FRAME || msg.channel_id !== 0 || handle.fingerprint !== keys.op.fp) return original.call(this, handle, msg);
        const index = n++;
        if (mode === 'alter' && index === 0) {
          const ciphertext = Uint8Array.from(msg.ciphertext); ciphertext[0] ^= 1;
          return original.call(this, handle, { ...msg, ciphertext });
        }
        if (mode === 'replay' && index === 0) { const r = original.call(this, handle, msg); original.call(this, handle, msg); return r; }
        if (mode === 'reorder') {
          if (index === 0) { held = msg; return true; }
          const r = original.call(this, handle, msg);
          if (index === 1) original.call(this, handle, held);
          return r;
        }
        return original.call(this, handle, msg);
      };
      spies.push(() => { RelayHub.prototype.forward = original; });
    }

    for (const [mode, expectedDials] of [['alter', 0], ['replay', 1], ['reorder', 0]]) {
      it(`${mode}: the host does not act on it, says seal-failed, and ends the bridge`, async () => {
        const origin = await echoOrigin();
        const refusals = [];
        const { url, host } = await setup({ gateway: { allow: ['127.0.0.1'] }, host: { requireOperatorProof: true, proofTimeoutMs: 8000, onRefused: (r) => refusals.push(r.reason) } });
        const { c } = await operator(url, { connectOptions: { sealed: true } });
        tamper(mode);
        // two requests at once, so a reorder has two frames to swap
        const attempts = [c.openTcp('127.0.0.1', origin.port, { timeoutMs: 2000 }), c.openTcp('127.0.0.1', origin.port, { timeoutMs: 2000 })].map((p) => p.then((d) => { d.destroy(); return 'ok'; }, () => 'failed'));
        await until(() => refusals.includes('seal-failed'), 'the host to notice');
        await until(() => host.operators.length === 0, 'the bridge to end');
        const results = await Promise.all(attempts);
        assert.ok(origin.sockets.length <= expectedDials, `${origin.sockets.length} connections dialled for ${mode}`);
        assert.ok(results.includes('failed'), `${results}`);
      });
    }
  });

  describe('a sealed bridge carries them as sealed frames', () => {
    it('with requireOperatorProof the relay sees EncryptedFrames only, and the gateway works', async () => {
      const origin = await echoOrigin();
      const { url } = await setup({ gateway: { allow: ['127.0.0.1'] }, host: { requireOperatorProof: true, proofTimeoutMs: 8000 } });
      const tap = tapRelay();
      const { c } = await operator(url, { connectOptions: { sealed: true } });
      const d = await c.openTcp('127.0.0.1', origin.port);
      const writer = d.writable.getWriter();
      await writer.write(new TextEncoder().encode('sealed hello'));
      const { value } = await d.readable.getReader().read();
      assert.equal(dec.decode(value), 'echo:sealed hello');
      d.close();
      const gatewayTypes = new Set([MSG.OPEN_TCP, MSG.GATEWAY_OK, MSG.GATEWAY_DATA, MSG.GATEWAY_CREDIT, MSG.GATEWAY_CLOSE]);
      assert.ok(!tap.types.some((t) => gatewayTypes.has(t)), `the relay saw gateway messages in the clear: ${tap.types}`);
      assert.ok(tap.types.includes(MSG.ENCRYPTED_FRAME));
    });
  });
});
