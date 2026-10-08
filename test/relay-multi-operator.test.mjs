// test/relay-multi-operator.test.mjs -- several operators per peer (#89): the relay option, the opt-in the peer
// states in ReverseAccept.features, replies addressed with RelayForward.to_fingerprint, the ReverseClose notice
// when one operator leaves, and createReverseHost serving each operator's connection state separately.
import { describe, it, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { RelayHub, BUSY_PEER, BUSY_OPERATOR, busyPeerFull, MULTI_OPERATOR_FEATURE } from '../src/server/relay.mjs';
import {
  WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, cborEncode, cborDecode, MSG,
  reverseAccept, relayForward, sessionData,
} from '@johnhenry/wsh';

const dec = new TextDecoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 5000) {
  const t0 = Date.now();
  for (;;) {
    const v = await cond();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(10);
  }
}

describe('relay: several operators per peer (#89)', () => {
  const keys = {};
  let authorizedKeys;
  const servers = [];
  const clients = [];
  const hosts = [];
  let relayServer = null;

  before(async () => {
    for (const name of ['host', 'bob', 'dave', 'erin']) {
      const keyPair = await generateKeyPair(true);
      keys[name] = { keyPair, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)) };
    }
    authorizedKeys = (await Promise.all(Object.entries(keys).map(async ([n, k]) => `${await exportPublicKeySSH(k.keyPair.publicKey)} ${n}`))).join('\n');
  });
  afterEach(async () => {
    for (const h of hosts.splice(0)) await h.close();
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
  });

  const POLICY = { canRegister: (who) => who.username.startsWith('host'), canConnect: (from) => ['bob', 'dave', 'erin'].includes(from.username) };
  async function startRelay(relay = {}) {
    const server = createWshServer({ auth: { authorizedKeys }, relay: { ...POLICY, ...relay } });
    const { port } = await server.listen();
    servers.push(server);
    relayServer = server;
    return `ws://127.0.0.1:${port}`;
  }
  const registered = (fp = keys.host.fp) => until(() => relayServer.peerFingerprints().includes(fp), 'the peer to register');
  async function login(url, name) {
    const c = new WshClient();
    await c.connect(url, { username: name, keyPair: keys[name].keyPair });
    clients.push(c);
    return c;
  }
  async function startHost(url, opts = {}) {
    const host = createReverseHost({ url, username: 'host', keyPair: keys.host.keyPair, exec: true, accept: () => true, reconnect: false, ...opts });
    await host.start();
    hosts.push(host);
    await registered();
    return host;
  }
  /** A stock-client peer: accepts every operator, states `features`, records what it is sent. */
  async function stockPeer(url, { features } = {}) {
    const c = new WshClient();
    await c.connectReverse(url, { username: 'host', keyPair: keys.host.keyPair, expose: { exec: true } });
    const seen = [];
    c.addControlListener((m) => seen.push(m));
    c.onReverseConnect = async (req) => {
      c.trustRelayPeer(req.from_fingerprint);
      await c.sendRelayControl(reverseAccept({ targetFingerprint: keys.host.fp, username: 'host', features }));
    };
    clients.push(c);
    await registered();
    return { c, seen };
  }
  const run = async (client, command) => {
    const session = await client.openSession({ type: 'exec', command });
    return new Promise((resolve) => {
      const chunks = [];
      session.onData = (d) => chunks.push(d);
      session.onClose = () => resolve(dec.decode(Buffer.concat(chunks)));
    });
  };

  describe('the relay option', () => {
    it('maxOperatorsPerPeer must be a positive integer', () => {
      for (const bad of [0, -1, 1.5, '2', NaN]) {
        assert.throws(() => new RelayHub({ maxOperatorsPerPeer: bad }), /maxOperatorsPerPeer/);
      }
      assert.doesNotThrow(() => new RelayHub({ maxOperatorsPerPeer: 3 }));
      assert.throws(() => createWshServer({ relay: { maxOperatorsPerPeer: 0 } }), /maxOperatorsPerPeer/);
      assert.throws(() => createWshServer({ relay: { maxOperatorsPerPeer: 1.5 } }), /maxOperatorsPerPeer/);
    });

    it('by default a peer that states multi-operator support still gets one operator (the relay opts in)', async () => {
      const url = await startRelay();
      await stockPeer(url, { features: [MULTI_OPERATOR_FEATURE] });
      const bob = await login(url, 'bob');
      assert.equal((await bob.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
      const dave = await login(url, 'dave');
      const refused = await dave.reverseConnect(keys.host.fp);
      assert.equal(refused.reason, BUSY_PEER);
    });

    it('a peer that never stated support keeps one operator even on a multi-operator relay', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 3 });
      await stockPeer(url); // no features at all: a peer written before this existed
      const bob = await login(url, 'bob');
      assert.equal((await bob.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
      const dave = await login(url, 'dave');
      assert.equal((await dave.reverseConnect(keys.host.fp)).reason, BUSY_PEER);
    });

    it('the first operator leaving still closes a peer that cannot handle several (the old rule)', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 3 });
      const { c } = await stockPeer(url);
      const closed = new Promise((r) => { c.onClose = r; });
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      await bob.disconnect();
      await Promise.race([closed, sleep(3000).then(() => { throw new Error('peer was not closed'); })]);
    });
  });

  describe('routing', () => {
    async function bridgeTwo(url) {
      const { c: peer, seen } = await stockPeer(url, { features: [MULTI_OPERATOR_FEATURE] });
      const bob = await login(url, 'bob');
      const dave = await login(url, 'dave');
      assert.equal((await bob.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
      assert.equal((await dave.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
      const got = { bob: [], dave: [] };
      bob.addControlListener((m) => got.bob.push(m));
      dave.addControlListener((m) => got.dave.push(m));
      return { peer, seen, bob, dave, got };
    }
    const toOperator = (op, text) => relayForward({ fromFingerprint: '', toFingerprint: keys[op].fp, inner: cborEncode(sessionData({ channelId: 1, data: new TextEncoder().encode(text) })) });

    it('a peer addresses a reply to one operator with to_fingerprint; only that operator gets it, from the peer', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      const { peer, got } = await bridgeTwo(url);
      await peer.sendRelayControl(toOperator('dave', 'for dave'));
      await until(() => got.dave.some((m) => m.type === MSG.SESSION_DATA), 'dave to receive it');
      await sleep(150);
      assert.deepEqual(got.bob.filter((m) => m.type === MSG.SESSION_DATA), [], 'bob did not');
      assert.equal(dec.decode(got.dave.find((m) => m.type === MSG.SESSION_DATA).data), 'for dave');
      await peer.sendRelayControl(toOperator('bob', 'for bob'));
      await until(() => got.bob.some((m) => m.type === MSG.SESSION_DATA), 'bob to receive it');
      assert.equal(got.dave.filter((m) => m.type === MSG.SESSION_DATA).length, 1, 'dave still only has his own');
    });

    it('the relay stamps the peer as the sender, whatever from_fingerprint the peer wrote', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      const { peer, bob } = await bridgeTwo(url);
      const from = [];
      bob.onRelayMessage = (msg, fromFingerprint) => from.push(fromFingerprint);
      // The peer claims to be dave and addresses bob:
      await peer.sendRelayControl(relayForward({ fromFingerprint: keys.dave.fp, toFingerprint: keys.bob.fp, inner: cborEncode(sessionData({ channelId: 1, data: new Uint8Array([1]) })) }));
      await until(() => from.length === 1, 'delivery');
      assert.deepEqual(from, [keys.host.fp]);
    });

    it('a forward to nobody, to a non-operator, or without an address while two are bridged is dropped, not guessed', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      const { peer, got } = await bridgeTwo(url);
      await peer.sendRelayControl(relayForward({ fromFingerprint: '', toFingerprint: keys.erin.fp, inner: cborEncode(sessionData({ channelId: 1, data: new Uint8Array([1]) })) }));
      await peer.sendRelayControl(relayForward({ fromFingerprint: '', inner: cborEncode(sessionData({ channelId: 1, data: new Uint8Array([2]) })) }));
      await peer.sendRelayControl(sessionData({ channelId: 1, data: new Uint8Array([3]) })); // a bare message: ambiguous with two operators
      await sleep(300);
      assert.deepEqual([...got.bob, ...got.dave].filter((m) => m.type === MSG.SESSION_DATA), []);
    });

    it('with a single operator an unaddressed reply still goes to it (every peer written before this)', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      const { c: peer } = await stockPeer(url, { features: [MULTI_OPERATOR_FEATURE] });
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      const got = [];
      bob.addControlListener((m) => got.push(m));
      await peer.sendRelayControl(sessionData({ channelId: 1, data: new Uint8Array([9]) }));
      await peer.sendRelayControl(relayForward({ fromFingerprint: '', inner: cborEncode(sessionData({ channelId: 1, data: new Uint8Array([8]) })) }));
      await until(() => got.filter((m) => m.type === MSG.SESSION_DATA).length === 2, 'both replies');
    });

    it('the operator cap applies, with a reason that says so; a second connect from a bridged operator is still refused', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      const { bob } = await bridgeTwo(url);
      const erin = await login(url, 'erin');
      const refused = await erin.reverseConnect(keys.host.fp);
      assert.equal(refused.type, MSG.REVERSE_REJECT);
      assert.equal(refused.reason, busyPeerFull(2));
      assert.match(refused.reason, /^busy: .*2 operators/);
      assert.equal((await bob.reverseConnect(keys.host.fp)).reason, BUSY_OPERATOR);
    });

    it('a peer answers one request at a time: a second connect while the first is pending is told to retry', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      const peer = new WshClient();
      await peer.connectReverse(url, { username: 'host', keyPair: keys.host.keyPair, expose: { exec: true } });
      clients.push(peer);
      const requests = [];
      peer.onReverseConnect = (req) => { requests.push(req.from_fingerprint); }; // never answers
      await registered();
      const bob = await login(url, 'bob');
      const dave = await login(url, 'dave');
      const first = bob.reverseConnect(keys.host.fp, 400).catch((e) => e);
      await until(() => requests.length === 1, 'the first request to reach the peer');
      const second = await dave.reverseConnect(keys.host.fp);
      assert.equal(second.type, MSG.REVERSE_REJECT);
      assert.match(second.reason, /^busy: /);
      assert.deepEqual(requests, [keys.bob.fp]);
      await first;
    });
  });

  describe('a bridge ends: ReverseClose to the peer, the others carry on', () => {
    it('the peer is told which operator left and its connection stays up', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      const { c: peer, seen } = await stockPeer(url, { features: [MULTI_OPERATOR_FEATURE] });
      const bob = await login(url, 'bob');
      const dave = await login(url, 'dave');
      await bob.reverseConnect(keys.host.fp);
      await dave.reverseConnect(keys.host.fp);
      await bob.disconnect();
      const notice = await until(() => seen.find((m) => m.type === MSG.REVERSE_CLOSE), 'the ReverseClose notice');
      assert.equal(notice.target_fingerprint, keys.bob.fp);
      await sleep(200);
      assert.ok(relayServer.peerFingerprints().includes(keys.host.fp), 'the peer is still registered');
      // dave is still bridged and bob's slot is free again
      const got = [];
      dave.addControlListener((m) => got.push(m));
      await peer.sendRelayControl(relayForward({ fromFingerprint: '', toFingerprint: keys.dave.fp, inner: cborEncode(sessionData({ channelId: 1, data: new Uint8Array([7]) })) }));
      await until(() => got.some((m) => m.type === MSG.SESSION_DATA), 'dave still served');
      const erin = await login(url, 'erin');
      assert.equal((await erin.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
    });

    it('the peer going away closes every operator', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      const { c: peer } = await stockPeer(url, { features: [MULTI_OPERATOR_FEATURE] });
      const bob = await login(url, 'bob');
      const dave = await login(url, 'dave');
      await bob.reverseConnect(keys.host.fp);
      await dave.reverseConnect(keys.host.fp);
      const closed = Promise.all([bob, dave].map((c) => new Promise((r) => { c.onClose = r; })));
      await peer.disconnect();
      await Promise.race([closed, sleep(3000).then(() => { throw new Error('operators were not closed'); })]);
    });

    it('a multi-operator peer is not dropped when its last operator leaves (no re-registration needed)', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      await stockPeer(url, { features: [MULTI_OPERATOR_FEATURE] });
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      await bob.disconnect();
      await sleep(300);
      assert.ok(relayServer.peerFingerprints().includes(keys.host.fp));
      const dave = await login(url, 'dave');
      assert.equal((await dave.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
    });
  });

  describe('createReverseHost serves each operator separately', () => {
    it('two operators run commands at once; each gets only its own output; the cap and the busy reasons hold', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      await startHost(url, { maxOperators: 2 });
      const bob = await login(url, 'bob');
      const dave = await login(url, 'dave');
      assert.equal((await bob.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
      assert.equal((await dave.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
      const [b, d] = await Promise.all([run(bob, 'echo from-bob; sleep 0.2; echo bob-done'), run(dave, 'echo from-dave; sleep 0.2; echo dave-done')]);
      assert.equal(b, 'from-bob\nbob-done\n');
      assert.equal(d, 'from-dave\ndave-done\n');
      const erin = await login(url, 'erin');
      assert.equal((await erin.reverseConnect(keys.host.fp)).reason, busyPeerFull(2));
    });

    it('each operator is accepted (or not) on its own identity', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 3 });
      await startHost(url, { maxOperators: 3, accept: (op) => op.fingerprint !== keys.dave.fp });
      const bob = await login(url, 'bob');
      const dave = await login(url, 'dave');
      const erin = await login(url, 'erin');
      assert.equal((await bob.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
      assert.equal((await dave.reverseConnect(keys.host.fp)).reason, 'not accepted');
      assert.equal((await erin.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
      assert.equal(await run(erin, 'echo erin'), 'erin\n');
      assert.equal(await run(bob, 'echo bob'), 'bob\n');
    });

    it('when one operator leaves, only its processes are cleaned up and the other keeps working', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      const host = await startHost(url, { maxOperators: 2 });
      const bob = await login(url, 'bob');
      const dave = await login(url, 'dave');
      await bob.reverseConnect(keys.host.fp);
      await dave.reverseConnect(keys.host.fp);
      const daveSession = await dave.openSession({ type: 'exec', command: 'sleep 1; echo dave-survived' });
      const daveOut = [];
      daveSession.onData = (d) => daveOut.push(dec.decode(d));
      const daveClosed = new Promise((r) => { daveSession.onClose = r; });
      await bob.openSession({ type: 'exec', command: 'sleep 30' });
      await bob.disconnect();
      await daveClosed;
      assert.equal(daveOut.join(''), 'dave-survived\n');
      assert.equal(host.connected, true, 'the host stayed on the relay');
      assert.deepEqual(host.operators, [keys.dave.fp]);
    });

    it('closing the host ends every operator\'s processes (they do not outlive it)', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      const host = await startHost(url, { maxOperators: 2 });
      const pids = [];
      for (const name of ['bob', 'dave']) {
        const op = await login(url, name);
        await op.reverseConnect(keys.host.fp);
        const session = await op.openSession({ type: 'exec', command: 'echo $$; exec sleep 30' });
        session.onData = (d) => pids.push(Number(dec.decode(d).trim()));
      }
      await until(() => pids.length === 2, 'both pids');
      await host.close();
      await until(() => pids.every((pid) => { try { process.kill(pid, 0); return false; } catch { return true; } }), 'the processes to be gone');
    });

    it('a host with the default (one operator) behaves as before: busy, and no multi-operator claim', async () => {
      const url = await startRelay({ maxOperatorsPerPeer: 2 });
      await startHost(url);
      const bob = await login(url, 'bob');
      const dave = await login(url, 'dave');
      const accepted = await bob.reverseConnect(keys.host.fp);
      assert.ok(!(accepted.features ?? []).includes(MULTI_OPERATOR_FEATURE));
      assert.equal((await dave.reverseConnect(keys.host.fp)).reason, BUSY_PEER);
    });

    it('maxOperators is validated, and cannot be combined with reportFeatures: false', () => {
      for (const bad of [0, -1, 1.5, '2']) {
        assert.throws(() => createReverseHost({ url: 'ws://x', username: 'h', keyPair: keys.host.keyPair, maxOperators: bad }), /maxOperators/);
      }
      assert.throws(() => createReverseHost({ url: 'ws://x', username: 'h', keyPair: keys.host.keyPair, maxOperators: 2, reportFeatures: false }), /reportFeatures/);
    });
  });
});
