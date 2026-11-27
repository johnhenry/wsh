// test/gateway-lossless-close-signed.test.mjs -- #318: the operator's `gateway-lossless-close` statement, authenticated.
//
// The statement travels in ReverseConnect.features, which a relay can add to, strip or change. On a bridge where the operator PROVES itself
// (operator-proof, sealed or not) the operator signs the statement into its proof (`wsh-operator-proof-v2`), and the host acts only on what
// the operator signed; it learns that the host can read such a proof from the host's registered capabilities (`gateway-lossless-close-signed`).
// On a bridge with no proof (trustRelayIdentity) there is nothing to sign with, and the earlier behaviour stays.
import { describe, it, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { RelayHub } from '../src/server/relay.mjs';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG } from '@johnhenry/wsh';
import {
  createReverseChallenge, verifyReverseChallenge, createOperatorProof, verifyOperatorProof, proofTranscript, GATEWAY_LOSSLESS_SIGNED_FEATURE,
} from '../src/operator-proof.mjs';
import { resolveSigner } from '../src/auth.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 8000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
async function drain(duplex) {
  const reader = duplex.readable.getReader(); let n = 0;
  for (;;) { const { value, done } = await reader.read(); if (done) break; n += value.length; }
  return n;
}

describe('the operator proof can carry the statement (#318)', () => {
  it('names the host capability', () => { assert.equal(GATEWAY_LOSSLESS_SIGNED_FEATURE, 'gateway-lossless-close-signed'); });

  it('a v2 proof signs the statement: the host learns it from the proof, a relay that adds or removes it from ReverseConnect changes nothing', async () => {
    const peer = await generateKeyPair(true); const op = await generateKeyPair(true);
    const peerSigner = await resolveSigner({ keyPair: peer }); const opSigner = await resolveSigner({ keyPair: op });
    const opFp = await fingerprint(opSigner.publicKeyRaw);
    const issued = await createReverseChallenge({ keyPair: peer }, opFp);
    const challenge = await verifyReverseChallenge({ public_key: issued.fields.publicKey, operator_fingerprint: opFp, nonce: issued.nonce, session_id: issued.sessionId, signature: issued.fields.signature }, { target: (await fingerprint(peerSigner.publicKeyRaw)), ownFingerprint: opFp });
    const asMsg = (f) => ({ public_key: f.publicKey, username: f.username, nonce: f.nonce, session_id: f.sessionId, signature: f.signature });
    const signed = await createOperatorProof(opSigner, challenge, 'op', ['gateway-lossless-close']);
    const plain = await createOperatorProof(opSigner, challenge, 'op');
    assert.deepEqual((await verifyOperatorProof(asMsg(signed), issued)).signedFeatures, ['gateway-lossless-close']);
    assert.deepEqual((await verifyOperatorProof(asMsg(plain), issued)).signedFeatures, [], 'a v1 proof signs no statement');
    // the signature is over the statement: the same fields with the statement removed from the transcript do not verify as a v1 proof
    const tampered = { ...asMsg(signed) };
    assert.notDeepEqual(proofTranscript({ peerPublicKey: issued.peerPublicKey, operatorPublicKey: opSigner.publicKeyRaw, username: 'op', nonce: issued.nonce, sessionId: issued.sessionId }),
      proofTranscript({ peerPublicKey: issued.peerPublicKey, operatorPublicKey: opSigner.publicKeyRaw, username: 'op', nonce: issued.nonce, sessionId: issued.sessionId, features: ['gateway-lossless-close'] }));
    tampered.signature = plain.signature; // a v1 signature is not a v2 one, but verifies as v1: the statement is simply not there
    assert.deepEqual((await verifyOperatorProof(tampered, issued)).signedFeatures, []);
  });
});

describe('lossless close behind a relay on a bridge with an operator proof (#318)', () => {
  const keys = {}; let authorizedKeys;
  const servers = []; const clients = []; const hosts = []; const nets = []; const spies = [];
  before(async () => {
    for (const name of ['host', 'op']) {
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
  });
  async function setup({ gateway = {}, host = {} } = {}) {
    const server = createWshServer({ auth: { authorizedKeys }, relay: { canRegister: (w) => w.username === 'host', canConnect: (f) => f.username !== 'host' } });
    const { port } = await server.listen(); servers.push(server);
    const url = `ws://127.0.0.1:${port}`;
    const h = createReverseHost({
      url, username: 'host', keyPair: keys.host.keyPair, exec: true, pty: false, reconnect: false, reportFeatures: true,
      accept: () => ({ capabilities: ['exec', 'gateway:tcp:*:*'] }),
      gateway: { allow: ['127.0.0.1'], halfCloseIdleMs: 0, halfCloseProbeMs: 50, ...(host.requireOperatorProof ? {} : { trustRelayIdentity: true }), ...gateway }, ...host,
    });
    await h.start(); hosts.push(h);
    await until(() => server.peerFingerprints().includes(keys.host.fp), 'the host to register');
    return { url, host: h };
  }
  async function operator(url, { connectOptions, clientOptions } = {}) {
    const c = new WshClient();
    await c.connect(url, { username: 'op', keyPair: keys.op.keyPair, ...clientOptions }); clients.push(c);
    const accepted = await c.reverseConnect(keys.host.fp, undefined, connectOptions);
    assert.equal(accepted.type, MSG.REVERSE_ACCEPT, accepted.reason);
    return { c, accepted };
  }
  function rewriteConnect(rewrite) {
    const original = RelayHub.prototype.connect;
    RelayHub.prototype.connect = function spy(operator, msg) { return original.call(this, operator, rewrite({ ...msg })); };
    spies.push(() => { RelayHub.prototype.connect = original; });
  }
  function tapCloses() {
    const original = RelayHub.prototype.forward; const closes = [];
    RelayHub.prototype.forward = function spy(handle, msg) { if (msg.type === MSG.GATEWAY_CLOSE) closes.push(msg.reason); return original.call(this, handle, msg); };
    spies.push(() => { RelayHub.prototype.forward = original; });
    return closes;
  }
  async function vanishingOrigin() {
    const gone = []; const server = net.createServer((s) => { s.on('error', () => {}); gone.push(s); s.end('bye'); });
    const port = await listen(server); nets.push(server);
    return { port, gone };
  }
  /** Open a connection to the origin, read its answer, make the origin vanish; resolves with how the connection ended within `ms`. */
  async function vanish(c, { port, gone }, ms) {
    const v = await c.openTcp('127.0.0.1', port);
    const lossless = v.lossless;
    assert.equal(await drain(v), 3, 'the answer arrived');
    await until(() => gone.length === 1, 'the origin to have been dialled');
    gone[0].resetAndDestroy();
    const end = await Promise.race([v.closed, sleep(ms).then(() => 'open')]);
    v.destroy();
    return { lossless, end };
  }

  it('the host lists the capability that says it reads a signed statement', async () => {
    const { url } = await setup();
    const c = new WshClient(); await c.connect(url, { username: 'op', keyPair: keys.op.keyPair }); clients.push(c);
    const peers = await c.listPeers();
    assert.ok(peers[0].capabilities.includes(GATEWAY_LOSSLESS_SIGNED_FEATURE), `${peers[0].capabilities}`);
    const { url: url2 } = await setup({ gateway: { losslessClose: false } });
    const c2 = new WshClient(); await c2.connect(url2, { username: 'op', keyPair: keys.op.keyPair }); clients.push(c2);
    assert.ok(!(await c2.listPeers())[0].capabilities.includes(GATEWAY_LOSSLESS_SIGNED_FEATURE), 'a host that does not state the feature does not list it');
  });

  it('new operator, new host, proven bridge: negotiated, and an origin that vanished releases the connection', async () => {
    const o = await vanishingOrigin();
    const { url } = await setup();
    const { c, accepted } = await operator(url);
    assert.ok(accepted.features.includes('gateway-lossless-close-ack'));
    const r = await vanish(c, o, 15000);
    assert.equal(r.lossless, true); assert.equal(r.end, 'released');
  });

  it('a relay that ADDS the statement the operator never made: the host does not acknowledge, watch or release', async () => {
    rewriteConnect((m) => { m.features = [...(m.features ?? []), 'gateway-lossless-close']; return m; });
    const closes = tapCloses(); const o = await vanishingOrigin();
    const { url } = await setup();
    const { c, accepted } = await operator(url, { clientOptions: { gatewayLosslessClose: false } });
    assert.ok(!accepted.features.includes('gateway-lossless-close-ack'), 'the host did not believe it');
    const r = await vanish(c, o, 1500);
    assert.equal(r.lossless, false); assert.equal(r.end, 'open', 'held, as an operator that never stated it expects');
    assert.ok(!closes.includes('released'), `the host sent no release: ${JSON.stringify(closes)}`);
  });

  it('a relay that adds the statement for an operator that stated it with the unsigned (0.62) form: the host acts on nothing it was not shown signed', async () => {
    // an operator that does not know the host reads a signed statement (the capability is missing from the record it has) states it as before, unsigned
    const closes = tapCloses(); const o = await vanishingOrigin();
    const { url } = await setup();
    const { c, accepted } = await operator(url, { connectOptions: { peerCapabilities: ['exec', 'gateway', 'operator-proof'] } });
    assert.ok(!accepted.features.includes('gateway-lossless-close-ack'), 'an unsigned statement on a proven bridge is not acknowledged');
    const r = await vanish(c, o, 1500);
    assert.equal(r.lossless, false); assert.equal(r.end, 'open');
    assert.ok(!closes.includes('released'));
  });

  it('a relay that strips the whole feature list: both fall back (nothing is proven, nothing is stated), the bridge works', async () => {
    rewriteConnect((m) => { delete m.features; return m; });
    const closes = tapCloses(); const o = await vanishingOrigin();
    const { url } = await setup();
    const { c, accepted } = await operator(url);
    assert.ok(!accepted.features.includes('gateway-lossless-close-ack'));
    const r = await vanish(c, o, 1500);
    assert.equal(r.lossless, false); assert.equal(r.end, 'open');
    assert.ok(!closes.includes('released'));
  });

  it('a relay that strips only the statement: the host still reads it from the operator\'s signature, so the lossless close is not lost to the relay', async () => {
    rewriteConnect((m) => { m.features = (m.features ?? []).filter((f) => f !== 'gateway-lossless-close'); return m; });
    const o = await vanishingOrigin();
    const { url } = await setup();
    const { c } = await operator(url);
    const r = await vanish(c, o, 15000);
    assert.equal(r.lossless, true); assert.equal(r.end, 'released');
  });

  it('a host that declines the feature: no capability, no acknowledgement; a new operator states it as before and falls back', async () => {
    const o = await vanishingOrigin();
    const { url } = await setup({ gateway: { losslessClose: false } });
    const { c, accepted } = await operator(url);
    assert.ok(!accepted.features.includes('gateway-lossless-close-ack'));
    const r = await vanish(c, o, 1500);
    assert.equal(r.lossless, false); assert.equal(r.end, 'open');
  });

  it('a sealed bridge (requireOperatorProof): the same rules; an added statement is not believed, the honest one is', async () => {
    const o = await vanishingOrigin();
    const { url } = await setup({ host: { requireOperatorProof: true, proofTimeoutMs: 8000 }, gateway: {} });
    const { c } = await operator(url, { connectOptions: { sealed: true } });
    const r = await vanish(c, o, 15000);
    assert.equal(r.lossless, true); assert.equal(r.end, 'released');
  });
  it('a sealed bridge, relay adds the statement for an operator that declined: not believed', async () => {
    rewriteConnect((m) => { m.features = [...(m.features ?? []), 'gateway-lossless-close']; return m; });
    const closes = tapCloses(); const o = await vanishingOrigin();
    const { url } = await setup({ host: { requireOperatorProof: true, proofTimeoutMs: 8000 } });
    const { c } = await operator(url, { connectOptions: { sealed: true }, clientOptions: { gatewayLosslessClose: false } });
    const r = await vanish(c, o, 1500);
    assert.equal(r.lossless, false); assert.equal(r.end, 'open');
    assert.ok(!closes.includes('released'));
  });

  describe('a bridge with NO proof (the relay is trusted for identity): the earlier behaviour, unchanged', () => {
    const noProof = (extra = []) => (m) => { m.features = [...extra]; return m; };
    it('the statement is taken as stated: acknowledged, negotiated, released', async () => {
      rewriteConnect(noProof(['gateway-lossless-close']));
      const o = await vanishingOrigin();
      const { url } = await setup();
      const { c, accepted } = await operator(url);
      assert.ok(accepted.features.includes('gateway-lossless-close-ack'));
      const r = await vanish(c, o, 15000);
      assert.equal(r.lossless, true); assert.equal(r.end, 'released');
    });
    it('a relay that adds it still fools the host (documented: no proof, nothing to sign); the operator, which never stated it, holds the connection', async () => {
      rewriteConnect(noProof(['gateway-lossless-close']));
      const closes = tapCloses(); const o = await vanishingOrigin();
      const { url } = await setup();
      const { c } = await operator(url, { clientOptions: { gatewayLosslessClose: false } });
      const r = await vanish(c, o, 1500);
      assert.equal(r.lossless, false);
      await until(() => closes.includes('released'), 'the host to release');
      assert.equal(r.end, 'open');
    });
  });
});
