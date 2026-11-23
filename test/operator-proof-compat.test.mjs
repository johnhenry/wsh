// test/operator-proof-compat.test.mjs -- released Rust hosts (rust-v0.6 to v0.8) cannot decode `ReverseConnect.features`
// (their generated types deny unknown fields: the connection drops), so a JS operator or relay that sends the field
// unconditionally gets a silent timeout. The field is sent only to a peer whose registered record lists `operator-proof`.
import { describe, it, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG } from '@johnhenry/wsh';
import { reverseAccept } from '../src/messages.gen.mjs';
import { hostileRelay } from './helpers/hostile-relay.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 5000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}

describe('operator proof is offered only to a peer that advertises it', () => {
  const keys = {};
  let authorizedKeys;
  const closers = [];
  before(async () => {
    for (const name of ['host', 'old', 'bob']) {
      const keyPair = await generateKeyPair(true);
      const raw = await exportPublicKeyRaw(keyPair.publicKey);
      keys[name] = { keyPair, raw, fp: await fingerprint(raw) };
    }
    authorizedKeys = (await Promise.all(Object.entries(keys).map(async ([n, k]) => `${await exportPublicKeySSH(k.keyPair.publicKey)} ${n}`))).join('\n');
  });
  afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

  async function relay() {
    const server = createWshServer({
      auth: { authorizedKeys },
      relay: { canRegister: (w) => w.username !== 'bob', canConnect: (f) => f.username === 'bob', connectTimeoutMs: 1500 },
    });
    const { port } = await server.listen();
    closers.push(() => server.close());
    return { server, url: `ws://127.0.0.1:${port}` };
  }

  /**
   * A peer as the released Rust hosts behave: registered without `operator-proof`, and the connection drops when a
   * ReverseConnect carries a field it does not know.
   */
  async function oldPeer(url, { dropOnUnknown = true } = {}) {
    const c = new WshClient();
    const seen = [];
    await c.connectReverse(url, { username: 'old', keyPair: keys.old.keyPair, expose: { exec: true }, operatorProof: false });
    c.onReverseConnect = async (req) => {
      seen.push(req);
      if (dropOnUnknown && 'features' in req) { await c.disconnect(); return; }
      await c.sendRelayControl(reverseAccept({ targetFingerprint: keys.old.fp, username: 'old', capabilities: ['exec'], peerType: 'host', shellBackend: 'exec-only' }));
    };
    closers.push(() => c.disconnect());
    return { c, seen };
  }
  async function bob(url) {
    const c = new WshClient();
    await c.connect(url, { username: 'bob', keyPair: keys.bob.keyPair });
    closers.push(() => c.disconnect());
    return c;
  }
  const registered = (server, fp) => until(() => server.peerFingerprints?.().includes(fp), 'the peer to register');

  it('an operator reaches a peer that drops on unknown fields without a timeout', async () => {
    const r = await relay();
    const peer = await oldPeer(r.url);
    await registered(r.server, keys.old.fp);
    const op = await bob(r.url);
    const t0 = Date.now();
    const res = await op.reverseConnect(keys.old.fp, 5000);
    assert.equal(res.type, MSG.REVERSE_ACCEPT);
    assert.ok(Date.now() - t0 < 2000, 'answered, not timed out');
    assert.equal('features' in peer.seen[0], false, 'the field never reached the peer');
  });

  it('the relay strips the field itself when the operator sends it to a peer that did not advertise it (an operator that predates this check)', async () => {
    const r = await relay();
    const peer = await oldPeer(r.url);
    await registered(r.server, keys.old.fp);
    const op = await bob(r.url);
    const res = await op.reverseConnect(keys.old.fp, 5000, { proof: true });
    assert.equal(res.type, MSG.REVERSE_ACCEPT, 'forced offer: the relay still protects the peer');
    assert.equal('features' in peer.seen[0], false);
  });

  it('requirePeerProof and sealed against such a peer fail fast, with a sentence, before anything is sent to it', async () => {
    const r = await relay();
    const peer = await oldPeer(r.url);
    await registered(r.server, keys.old.fp);
    const op = await bob(r.url);
    for (const opts of [{ requirePeerProof: true }, { sealed: true }]) {
      const t0 = Date.now();
      await assert.rejects(op.reverseConnect(keys.old.fp, 5000, opts), /does not advertise "operator-proof".*nothing was sent/s);
      assert.ok(Date.now() - t0 < 2000, 'failed fast');
    }
    assert.equal(peer.seen.length, 0, 'the peer was never asked');
  });

  it('a forced offer with requirePeerProof still fails readably (the relay stripped it; the peer answers without a challenge)', async () => {
    const r = await relay();
    await oldPeer(r.url);
    await registered(r.server, keys.old.fp);
    const op = await bob(r.url);
    await assert.rejects(op.reverseConnect(keys.old.fp, 5000, { proof: true, requirePeerProof: true }), /did not prove its identity.*does not advertise "operator-proof"/s);
  });

  it('new to new still proves: a JS host registers the capability and the operator offers', async () => {
    const r = await relay();
    const ran = [];
    const host = createReverseHost({
      url: r.url, username: 'host', keyPair: keys.host.keyPair, exec: async (c, io) => { ran.push(c); io.write('ok\n'); return 0; },
      reconnect: false, accept: (who) => who.fingerprint === keys.bob.fp && who.proven === true,
    });
    await host.start();
    closers.push(() => host.close());
    await registered(r.server, keys.host.fp);
    const op = await bob(r.url);
    const peers = await op.listPeers();
    assert.ok(peers.find((p) => p.username === 'host').capabilities.includes('operator-proof'));
    const res = await op.reverseConnect(keys.host.fp, 5000, { requirePeerProof: true });
    assert.equal(res.type, MSG.REVERSE_ACCEPT);
  });

  it('an operator can forbid the offer (proof: false) and the peer record is not even looked up', async () => {
    const r = await relay();
    const peer = await oldPeer(r.url, { dropOnUnknown: false });
    await registered(r.server, keys.old.fp);
    const op = await bob(r.url);
    const res = await op.reverseConnect(keys.old.fp, 5000, { proof: false });
    assert.equal(res.type, MSG.REVERSE_ACCEPT);
    assert.equal('features' in peer.seen[0], false);
  });

  it('peerCapabilities skips the lookup: the caller already holds the peer record', async () => {
    const r = await relay();
    const peer = await oldPeer(r.url, { dropOnUnknown: false });
    await registered(r.server, keys.old.fp);
    const op = await bob(r.url);
    const res = await op.reverseConnect(keys.old.fp, 5000, { peerCapabilities: ['exec', 'operator-proof'] });
    assert.equal(res.type, MSG.REVERSE_ACCEPT);
    // told the peer can prove, the operator offered; the relay (which knows the registered record) still stripped it
    assert.equal('features' in peer.seen[0], false);
  });

  it('on the wire, the operator itself states the field only to a peer that advertises it (not only the relay strips it)', async () => {
    const r = await relay();
    await oldPeer(r.url, { dropOnUnknown: false });
    const host = createReverseHost({ url: r.url, username: 'host', keyPair: keys.host.keyPair, exec: async () => 0, reconnect: false, accept: () => true });
    await host.start();
    closers.push(() => host.close());
    await registered(r.server, keys.old.fp);
    await registered(r.server, keys.host.fp);
    const mitm = await hostileRelay(r.url);
    closers.push(() => mitm.close());
    const op = await bob(mitm.url);
    const sent = () => mitm.seen.filter((x) => x.msg.type === MSG.REVERSE_CONNECT && x.dir !== 'to-client').map((x) => x.msg);
    await op.reverseConnect(keys.old.fp, 5000);
    assert.equal(sent().length, 1);
    assert.equal('features' in sent()[0], false, 'nothing about operator-proof was sent toward a peer that did not advertise it');
    await op.disconnect();
    const op2 = await bob(mitm.url);
    await op2.reverseConnect(keys.host.fp, 5000);
    assert.deepEqual(sent().at(-1).features, ['operator-proof']);
  });
});
