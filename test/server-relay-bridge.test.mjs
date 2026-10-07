// test/server-relay-bridge.test.mjs -- what crosses a relay bridge (#80): operator <-> peer E2E that the relay
// cannot read, the one-operator-per-peer rule with its explicit `busy` reasons, and feature gates that follow
// the bridged host rather than the relay.
import { describe, it, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { RelayHub, BUSY_PEER, BUSY_OPERATOR } from '../src/server/relay.mjs';
import { sealFrame, openFrame, ROLE_TAGS } from '../src/e2e-frame.mjs';
import {
  WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, cborEncode, MSG,
  reverseAccept, encryptedFrame, keyExchange,
} from '@johnhenry/wsh';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 4000) {
  const t0 = Date.now();
  for (;;) {
    const v = await cond();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(10);
  }
}

describe('relay bridge: E2E, one operator per peer, bridged features', () => {
  const keys = {};
  let authorizedKeys;
  const servers = [];
  const clients = [];
  const hosts = [];
  let relayServer = null;

  before(async () => {
    for (const name of ['host', 'host2', 'bob', 'dave']) {
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

  const POLICY = { canRegister: (who) => who.username.startsWith('host'), canConnect: (from) => from.username === 'bob' || from.username === 'dave' };
  async function startRelay(extra = {}) {
    const server = createWshServer({ auth: { authorizedKeys }, relay: POLICY, ...extra });
    const { port } = await server.listen();
    servers.push(server);
    relayServer = server;
    return `ws://127.0.0.1:${port}`;
  }
  const registered = (fp) => until(() => relayServer.peerFingerprints().includes(fp), 'the peer to register');
  async function login(url, name) {
    const c = new WshClient();
    await c.connect(url, { username: name, keyPair: keys[name].keyPair });
    clients.push(c);
    return c;
  }
  /** A stock-client peer that accepts every operator, optionally stating `features`. */
  async function stockPeer(url, name = 'host', { features } = {}) {
    const c = new WshClient();
    await c.connectReverse(url, { username: name, keyPair: keys[name].keyPair, expose: { exec: true } });
    c.onReverseConnect = async (req) => {
      c.trustRelayPeer(req.from_fingerprint);
      await c.sendRelayControl(reverseAccept({ targetFingerprint: keys[name].fp, username: name, features }));
    };
    clients.push(c);
    await registered(keys[name].fp);
    return c;
  }

  describe('E2E through a bridge', () => {
    it('operator and peer derive a key through the relay, and the relay only ever sees ciphertext', async () => {
      const url = await startRelay();
      const peer = await stockPeer(url);
      const bob = await login(url, 'bob');
      assert.equal((await bob.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);

      // Record everything the relay carries across the bridge.
      const seen = [];
      const original = RelayHub.prototype.forward;
      RelayHub.prototype.forward = function spy(handle, msg) { seen.push(msg); return original.call(this, handle, msg); };
      try {
        const sid = 'bridge-session-1';
        const [a, b] = await Promise.all([bob.initiateE2E(sid), peer.initiateE2E(sid)]);
        assert.equal(a.hybrid, false);
        assert.ok(a.sharedSecret && b.sharedSecret);
        assert.deepEqual([...a.peerPublicKey].length, 32);

        const gotAtPeer = [];
        const gotAtBob = [];
        peer.addControlListener((m) => { if (m.type === MSG.ENCRYPTED_FRAME) gotAtPeer.push(m); });
        bob.addControlListener((m) => { if (m.type === MSG.ENCRYPTED_FRAME) gotAtBob.push(m); });

        const secret = 'the-launch-code-is-0451';
        const sealed = await sealFrame(a.sharedSecret, sid, ROLE_TAGS.initiator, 0, new TextEncoder().encode(secret));
        await bob.sendControl(encryptedFrame({ channelId: 1, nonce: sealed.nonce, ciphertext: sealed.ciphertext, sessionId: sid }));
        await until(() => gotAtPeer.length === 1, 'the frame to reach the peer');
        const opened = await openFrame(b.sharedSecret, sid, 0, { nonce: gotAtPeer[0].nonce, ciphertext: gotAtPeer[0].ciphertext, expectedRoleTag: ROLE_TAGS.initiator });
        assert.equal(new TextDecoder().decode(opened), secret);

        // And back the other way.
        const reply = await sealFrame(b.sharedSecret, sid, ROLE_TAGS.responder, 0, new TextEncoder().encode('ack'));
        await peer.sendControl(encryptedFrame({ channelId: 1, nonce: reply.nonce, ciphertext: reply.ciphertext, sessionId: sid }));
        await until(() => gotAtBob.length === 1, 'the reply to reach the operator');
        assert.equal(new TextDecoder().decode(await openFrame(a.sharedSecret, sid, 0, { nonce: gotAtBob[0].nonce, ciphertext: gotAtBob[0].ciphertext, expectedRoleTag: ROLE_TAGS.responder })), 'ack');

        // What the relay forwarded: key exchanges (public values) and sealed frames, never the plaintext.
        assert.ok(seen.some((m) => m.type === MSG.KEY_EXCHANGE), 'KeyExchange crossed the bridge');
        assert.ok(seen.some((m) => m.type === MSG.ENCRYPTED_FRAME), 'EncryptedFrame crossed the bridge');
        for (const m of seen) {
          assert.ok(!Buffer.from(cborEncode(m)).includes(Buffer.from(secret)), 'the relay never held the plaintext');
          assert.ok(!Buffer.from(cborEncode(m)).includes(Buffer.from('ack')) || m.type !== MSG.ENCRYPTED_FRAME, 'nor the reply');
        }
      } finally { RelayHub.prototype.forward = original; }
    });

    it('key exchange is only carried across an established bridge', async () => {
      const url = await startRelay();
      const peer = await stockPeer(url);
      const bob = await login(url, 'bob'); // registered nowhere, bridged to no one
      const got = [];
      peer.addControlListener((m) => got.push(m.type));
      await bob.sendControl(keyExchange({ algorithm: 'X25519', publicKey: new Uint8Array(32), sessionId: 'nope' }));
      await sleep(250);
      assert.deepEqual(got.filter((t) => t === MSG.KEY_EXCHANGE || t === MSG.RELAY_FORWARD), []);
    });
  });

  describe('one operator per peer', () => {
    it('a second operator is refused with a reason that says why', async () => {
      const url = await startRelay();
      await stockPeer(url);
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      const dave = await login(url, 'dave');
      const refused = await dave.reverseConnect(keys.host.fp);
      assert.equal(refused.type, MSG.REVERSE_REJECT);
      assert.equal(refused.reason, BUSY_PEER);
      assert.match(refused.reason, /^busy: .*one operator per peer/);
      assert.equal(dave.bridgedFeatures, null, 'a refused connect changes nothing');
    });

    it('an operator that already has a bridge cannot open a second one, and is told so', async () => {
      const url = await startRelay();
      await stockPeer(url);
      await stockPeer(url, 'host2');
      const bob = await login(url, 'bob');
      assert.equal((await bob.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
      const second = await bob.reverseConnect(keys.host2.fp);
      assert.equal(second.reason, BUSY_OPERATOR);
      assert.match(second.reason, /^busy: you already have a bridge/);
    });

    it('the first operator leaving frees the peer for the next one (the peer re-registers)', async () => {
      const url = await startRelay();
      const host = createReverseHost({ url, username: 'host', keyPair: keys.host.keyPair, exec: true, accept: () => true, reconnect: true });
      await host.start();
      hosts.push(host);
      await registered(keys.host.fp);
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      await bob.disconnect();
      const dave = await login(url, 'dave');
      await until(async () => (await dave.listPeers()).length === 1, 're-registration', 6000);
      assert.equal((await dave.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
    });
  });

  describe('feature gates follow the bridged host', () => {
    let root;
    afterEach(async () => { if (root) await rm(root, { recursive: true, force: true }); root = null; });

    it('a relay with fs in front of a host without it: the gates say what the host can do', async () => {
      root = await mkdtemp(path.join(tmpdir(), 'wsh-relay-feat-'));
      const url = await startRelay({ fs: { root } });
      const bob = await login(url, 'bob');
      assert.equal(bob.hasFeature('file-write'), true, 'before the bridge: the relay itself has fs');
      const host = createReverseHost({ url, username: 'host', keyPair: keys.host.keyPair, exec: true, accept: () => true, reconnect: false });
      await host.start();
      hosts.push(host);
      await registered(keys.host.fp);
      await bob.reverseConnect(keys.host.fp);
      assert.equal(bob.hasFeature('file-write'), false, 'the host has no fs, whatever the relay has');
      assert.equal(bob.hasFeature('file-rename'), false);
      assert.deepEqual(bob.bridgedFeatures, [], 'the host stated an empty list, which is a statement');
      await assert.rejects(() => bob.fileWrite('x.txt', 'x'), /does not support file write/);
    });

    it('a host with fs states file-write / file-rename, and the operator may use them through a relay without fs', async () => {
      root = await mkdtemp(path.join(tmpdir(), 'wsh-relay-feat-'));
      const url = await startRelay();
      const bob = await login(url, 'bob');
      assert.equal(bob.hasFeature('file-write'), false, 'the relay has no fs');
      const host = createReverseHost({ url, username: 'host', keyPair: keys.host.keyPair, fs: { root }, accept: () => true, reconnect: false });
      await host.start();
      hosts.push(host);
      await registered(keys.host.fp);
      await bob.reverseConnect(keys.host.fp);
      assert.ok(bob.bridgedFeatures.includes('file-write') && bob.bridgedFeatures.includes('file-rename'));
      assert.deepEqual(bob.features, bob.bridgedFeatures);
      assert.ok(!bob.features.includes('stream-announce'), 'no client-opened streams cross a bridge');
      assert.equal(bob.serverFeatures.includes('file-write'), false, 'the relay own features are still readable');
      assert.equal((await bob.fileWrite('w.txt', 'hello')).success, true);
    });

    it('a peer that states no features leaves the gates on the relay features, as before', async () => {
      root = await mkdtemp(path.join(tmpdir(), 'wsh-relay-feat-'));
      const url = await startRelay({ fs: { root } });
      await stockPeer(url); // answers ReverseAccept without `features`
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      assert.equal(bob.bridgedFeatures, null);
      assert.equal(bob.hasFeature('file-write'), true);
    });

    it('a host that opts out of reporting (older Rust relays) behaves the same way', async () => {
      const url = await startRelay();
      const host = createReverseHost({ url, username: 'host', keyPair: keys.host.keyPair, exec: true, accept: () => true, reconnect: false, reportFeatures: false });
      await host.start();
      hosts.push(host);
      await registered(keys.host.fp);
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      assert.equal(bob.bridgedFeatures, null);
    });

    it('the relay bounds what a peer claims: an absurd feature list is dropped, not forwarded', async () => {
      const url = await startRelay();
      await stockPeer(url, 'host', { features: Array.from({ length: 100 }, (_, i) => `f${i}`) });
      const bob = await login(url, 'bob');
      const accepted = await bob.reverseConnect(keys.host.fp);
      assert.equal(accepted.type, MSG.REVERSE_ACCEPT);
      assert.equal(accepted.features, undefined);
      assert.equal(bob.bridgedFeatures, null);
    });

    it('the bridged features are forgotten when the connection ends', async () => {
      const url = await startRelay();
      await stockPeer(url, 'host', { features: ['mcp-call-id'] });
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      assert.deepEqual(bob.bridgedFeatures, ['mcp-call-id']);
      await bob.disconnect();
      assert.equal(bob.bridgedFeatures, null);
    });
  });
});
