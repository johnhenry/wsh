// test/gateway-lossless-close-signed.test.mjs -- #318: the operator's `gateway-lossless-close` statement, authenticated.
//
// The guarantee holds on SEALED bridges only (owner decision). The statement travels in ReverseConnect.features, which a relay can add to,
// strip or change; on a SEALED bridge the operator signs it into its proof (`wsh-operator-proof-v2`) and the host acts only on what the operator
// signed, and the operator reports `lossless === true` only then (it saw the host's VERIFIED record list `gateway-lossless-close-signed` and sent
// a v2 proof). On an unsealed bridge no carrier can stop a relay forging or stripping a plain GatewayClose{reason:'released'}: it stays
// best-effort (the host behaves as in 0.62, the operator tolerates a `released` and ends promptly) and NO guarantee is reported.
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
import { gatewayClose } from '../src/messages.gen.mjs';

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

  it('the v2 transcript equals the bytes the Rust implementation produces (shared hex vector)', () => {
    const fill = (n, v) => new Uint8Array(n).fill(v);
    const hex = Buffer.from(proofTranscript({ peerPublicKey: fill(32, 1), operatorPublicKey: fill(32, 3), username: 'alice', nonce: fill(32, 2), sessionId: 'sid', features: ['gateway-lossless-close'] })).toString('hex');
    assert.equal(hex, '7773682d6f70657261746f722d70726f6f662d76320000000020010101010101010101010101010101010101010101010101010101010101010100000020030303030303030303030303030303030303030303030303030303030303030300000005616c6963650000002002020202020202020202020202020202020202020202020202020202020202020000000373696400000016676174657761792d6c6f73736c6573732d636c6f7365');
  });

  it('createOperatorProof refuses to sign a statement it does not know (TypeError)', async () => {
    const op = await generateKeyPair(true); const opSigner = await resolveSigner({ keyPair: op });
    const challenge = { peerPublicKey: new Uint8Array(32).fill(1), nonce: new Uint8Array(32).fill(2), sessionId: 'sid' };
    await assert.rejects(() => createOperatorProof(opSigner, challenge, 'op', ['not-a-statement']), TypeError);
  });
});

describe('lossless close behind a relay: guaranteed on a SEALED bridge only (#318)', () => {
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
  const spy = (obj, name, wrap) => {
    const original = obj[name];
    obj[name] = wrap(original);
    spies.push(() => { obj[name] = original; });
  };
  function rewriteConnect(rewrite) {
    spy(RelayHub.prototype, 'connect', (original) => function (operator, msg) { return original.call(this, operator, rewrite({ ...msg })); });
  }
  function rewriteAccept(rewrite) {
    spy(RelayHub.prototype, 'answer', (original) => function (peer, msg) { return original.call(this, peer, rewrite({ ...msg })); });
  }
  function rewriteList(rewrite) {
    spy(RelayHub.prototype, 'list', (original) => async function (who) { const m = await original.call(this, who); return { ...m, peers: m.peers.map((p) => rewrite({ ...p })) }; });
  }
  function tapCloses() {
    const closes = [];
    spy(RelayHub.prototype, 'forward', (original) => function (handle, msg) { if (msg.type === MSG.GATEWAY_CLOSE) closes.push(msg.reason); return original.call(this, handle, msg); });
    return closes;
  }
  /** The proofs the operator sent: which transcript each signature covers (v1 = no statement, v2 = the statement signed). */
  function tapProofs() {
    const kinds = [];
    spy(RelayHub.prototype, 'proof', (original) => function (handle, msg) {
      (async () => {
        const base = { peerPublicKey: await exportPublicKeyRaw(keys.host.keyPair.publicKey), operatorPublicKey: msg.public_key, username: msg.username, nonce: msg.nonce, sessionId: msg.session_id };
        const key = await crypto.subtle.importKey('raw', msg.public_key, 'Ed25519', false, ['verify']);
        const covers = (features) => crypto.subtle.verify('Ed25519', key, msg.signature, proofTranscript({ ...base, features }));
        kinds.push((await covers(['gateway-lossless-close'])) ? 'v2' : (await covers([])) ? 'v1' : 'invalid');
      })();
      return original.call(this, handle, msg);
    });
    return kinds;
  }
  async function vanishingOrigin() {
    const gone = []; const server = net.createServer((s) => { s.on('error', () => {}); gone.push(s); s.end('bye'); });
    const port = await listen(server); nets.push(server);
    return { port, gone };
  }
  /** An origin that sends its answer and keeps the connection open: nothing ends it but a forged close. */
  async function liveOrigin() {
    const gone = []; const server = net.createServer((s) => { s.on('error', () => {}); gone.push(s); s.write('bye'); });
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
  const SEALED = { requireOperatorProof: true, proofTimeoutMs: 8000 };

  it('the host lists the capability that says it reads a signed statement', async () => {
    const { url } = await setup();
    const c = new WshClient(); await c.connect(url, { username: 'op', keyPair: keys.op.keyPair }); clients.push(c);
    const peers = await c.listPeers();
    assert.ok(peers[0].capabilities.includes(GATEWAY_LOSSLESS_SIGNED_FEATURE), `${peers[0].capabilities}`);
    const { url: url2 } = await setup({ gateway: { losslessClose: false } });
    const c2 = new WshClient(); await c2.connect(url2, { username: 'op', keyPair: keys.op.keyPair }); clients.push(c2);
    assert.ok(!(await c2.listPeers())[0].capabilities.includes(GATEWAY_LOSSLESS_SIGNED_FEATURE), 'a host that does not state the feature does not list it');
  });

  describe('a SEALED bridge: the guarantee', () => {
    it('honest relay: the operator signs the statement (v2 proof), reports lossless, and an origin that vanished releases the connection', async () => {
      const proofs = tapProofs(); const o = await vanishingOrigin();
      const { url } = await setup({ host: SEALED });
      const { c } = await operator(url, { connectOptions: { sealed: true } });
      const r = await vanish(c, o, 15000);
      assert.equal(r.lossless, true); assert.equal(r.end, 'released');
      await until(() => proofs.length, 'the proof'); assert.deepEqual(proofs, ['v2']);
    });
    it('a relay that strips only the statement: it is signed, so the guarantee holds', async () => {
      rewriteConnect((m) => { m.features = (m.features ?? []).filter((f) => f !== 'gateway-lossless-close'); return m; });
      const o = await vanishingOrigin();
      const { url } = await setup({ host: SEALED });
      const { c } = await operator(url, { connectOptions: { sealed: true } });
      const r = await vanish(c, o, 15000);
      assert.equal(r.lossless, true); assert.equal(r.end, 'released');
    });
    it('the unsigned acknowledgement is ignored: a relay that strips it changes nothing', async () => {
      rewriteAccept((m) => { m.features = (m.features ?? []).filter((f) => f !== 'gateway-lossless-close-ack'); return m; });
      const o = await vanishingOrigin();
      const { url } = await setup({ host: SEALED });
      const { c, accepted } = await operator(url, { connectOptions: { sealed: true } });
      assert.ok(!accepted.features.includes('gateway-lossless-close-ack'));
      const r = await vanish(c, o, 15000);
      assert.equal(r.lossless, true); assert.equal(r.end, 'released');
    });
    it('a relay that adds the statement for an operator that declined: not believed, nothing released', async () => {
      rewriteConnect((m) => { m.features = [...(m.features ?? []), 'gateway-lossless-close']; return m; });
      const closes = tapCloses(); const o = await vanishingOrigin();
      const { url } = await setup({ host: SEALED });
      const { c, accepted } = await operator(url, { connectOptions: { sealed: true }, clientOptions: { gatewayLosslessClose: false } });
      assert.ok(!accepted.features.includes('gateway-lossless-close-ack'), 'the host did not believe it');
      const r = await vanish(c, o, 1500);
      assert.equal(r.lossless, false); assert.equal(r.end, 'open');
      assert.ok(!closes.includes('released'));
    });
    it('a relay that strips the proof request and adds the statement: a sealed host refuses the bridge, nothing is stated', async () => {
      rewriteConnect((m) => { m.features = ['gateway-lossless-close']; return m; });
      const { url } = await setup({ host: SEALED });
      const c = new WshClient(); await c.connect(url, { username: 'op', keyPair: keys.op.keyPair }); clients.push(c);
      const answer = await c.reverseConnect(keys.host.fp, 3000, { sealed: true }).catch((e) => ({ type: 'threw', e }));
      assert.notEqual(answer.type, MSG.REVERSE_ACCEPT, 'no bridge without the proof');
    });
    it('an operator told nothing signed (a host whose record lacks the capability): the bridge works, nothing is guaranteed', async () => {
      const o = await vanishingOrigin();
      const { url } = await setup({ host: SEALED, gateway: { losslessClose: false } });
      const { c } = await operator(url, { connectOptions: { sealed: true } });
      const r = await vanish(c, o, 1500);
      assert.equal(r.lossless, false);
    });
  });

  describe('an UNSEALED bridge: best-effort, never reported as a guarantee', () => {
    it('a proven but unsealed bridge: the connection is still released (best-effort, 0.62 behaviour), the operator signs nothing and reports no guarantee', async () => {
      const proofs = tapProofs(); const o = await vanishingOrigin();
      const { url } = await setup();
      const { c, accepted } = await operator(url);
      assert.ok(accepted.features.includes('gateway-lossless-close-ack'));
      const r = await vanish(c, o, 15000);
      assert.equal(r.lossless, false, 'no guarantee on an unsealed bridge'); assert.equal(r.end, 'released');
      await until(() => proofs.length, 'the proof'); assert.deepEqual(proofs, ['v1'], 'nothing is signed where it would guarantee nothing');
    });
    it('A1: a relay strips operator-proof and adds the statement: the operator reports NO guarantee, and the release that follows ends the connection promptly', async () => {
      rewriteConnect((m) => { m.features = ['gateway-lossless-close']; return m; });
      const o = await vanishingOrigin();
      const { url } = await setup();
      const { c } = await operator(url, { clientOptions: { gatewayLosslessClose: false } });
      const r = await vanish(c, o, 15000);
      assert.equal(r.lossless, false, 'the operator must not report a guarantee a relay can manufacture');
      assert.equal(r.end, 'released', 'an unexpected release ends the connection promptly (the #318 symptom was holding it to the idle bound)');
    });
    it('A1 (operator stated it too): the relay stripped the proof request; no guarantee is reported, released still ends it', async () => {
      rewriteConnect((m) => { m.features = (m.features ?? []).filter((f) => f !== 'operator-proof'); return m; });
      const o = await vanishingOrigin();
      const { url } = await setup();
      const { c } = await operator(url);
      const r = await vanish(c, o, 15000);
      assert.equal(r.lossless, false); assert.equal(r.end, 'released');
    });
    it('forged close: a relay injects `released` on a proven unsealed bridge: no guarantee is reported, the connection ends', async () => {
      spy(RelayHub.prototype, 'forward', (original) => function (handle, msg) {
        const r = original.call(this, handle, msg);
        if (msg.type === MSG.GATEWAY_DATA && !this.__forged) { this.__forged = true; original.call(this, handle, gatewayClose({ gatewayId: msg.gateway_id, reason: 'released' })); }
        return r;
      });
      const o = await liveOrigin();
      const { url } = await setup();
      const { c } = await operator(url);
      const v = await c.openTcp('127.0.0.1', o.port);
      assert.equal(v.lossless, false, 'a plain close a relay can forge is no guarantee');
      assert.equal(await drain(v), 3, 'what was sent before the forged close is delivered');
      assert.equal(await Promise.race([v.closed, sleep(5000).then(() => 'open')]), 'released', 'ended promptly, not held to the idle bound');
      v.destroy();
    });
    it('a relay that adds the statement for an operator that declined: the host (best-effort) releases; the operator ends promptly and reports no guarantee', async () => {
      rewriteConnect((m) => { m.features = [...(m.features ?? []), 'gateway-lossless-close']; return m; });
      const o = await vanishingOrigin();
      const { url } = await setup();
      const { c } = await operator(url, { clientOptions: { gatewayLosslessClose: false } });
      const r = await vanish(c, o, 15000);
      assert.equal(r.lossless, false); assert.equal(r.end, 'released');
    });
    it('a relay that strips the statement: best-effort, the host does not release (a relay can always do this); no guarantee', async () => {
      rewriteConnect((m) => { m.features = (m.features ?? []).filter((f) => f !== 'gateway-lossless-close'); return m; });
      const closes = tapCloses(); const o = await vanishingOrigin();
      const { url } = await setup();
      const { c, accepted } = await operator(url);
      assert.ok(!accepted.features.includes('gateway-lossless-close-ack'));
      const r = await vanish(c, o, 1500);
      assert.equal(r.lossless, false); assert.equal(r.end, 'open');
      assert.ok(!closes.includes('released'));
    });
    it('a relay that strips the whole feature list: both fall back, the bridge works', async () => {
      rewriteConnect((m) => { delete m.features; return m; });
      const closes = tapCloses(); const o = await vanishingOrigin();
      const { url } = await setup();
      const { c, accepted } = await operator(url);
      assert.ok(!accepted.features.includes('gateway-lossless-close-ack'));
      const r = await vanish(c, o, 1500);
      assert.equal(r.lossless, false); assert.equal(r.end, 'open');
      assert.ok(!closes.includes('released'));
    });
    it('a host that declines the feature: no capability, no acknowledgement; the operator falls back', async () => {
      const o = await vanishingOrigin();
      const { url } = await setup({ gateway: { losslessClose: false } });
      const { c, accepted } = await operator(url);
      assert.ok(!accepted.features.includes('gateway-lossless-close-ack'));
      const r = await vanish(c, o, 1500);
      assert.equal(r.lossless, false); assert.equal(r.end, 'open');
    });
  });

  describe('the host record: only a VERIFIED one is believed', () => {
    it('a relay serves a record with `gateway-lossless-close-signed` added and a signature that does not verify: no v2 proof is sent', async () => {
      const proofs = tapProofs();
      // the host genuinely does not list the capability; the relay adds it and breaks the record's signature (the record covers the list)
      rewriteList((p) => ({ ...p, capabilities: [...p.capabilities, GATEWAY_LOSSLESS_SIGNED_FEATURE], record_signature: Uint8Array.from(p.record_signature, (b, i) => (i === 0 ? b ^ 1 : b)) }));
      const { url } = await setup({ host: SEALED, gateway: { losslessClose: false } });
      const c = new WshClient(); await c.connect(url, { username: 'op', keyPair: keys.op.keyPair }); clients.push(c);
      const accepted = await c.reverseConnect(keys.host.fp, undefined, { sealed: true, proof: true });
      assert.equal(accepted.type, MSG.REVERSE_ACCEPT, accepted.reason);
      await until(() => proofs.length, 'the proof'); assert.deepEqual(proofs, ['v1'], 'a record that does not verify is not believed');
    });
  });

  describe('a bridge with NO proof (the relay is trusted for identity): best-effort, as before', () => {
    const noProof = (extra = []) => (m) => { m.features = [...extra]; return m; };
    it('the statement is taken as stated: acknowledged, released; the operator reports no guarantee', async () => {
      rewriteConnect(noProof(['gateway-lossless-close']));
      const o = await vanishingOrigin();
      const { url } = await setup();
      const { c, accepted } = await operator(url);
      assert.ok(accepted.features.includes('gateway-lossless-close-ack'));
      const r = await vanish(c, o, 15000);
      assert.equal(r.lossless, false); assert.equal(r.end, 'released');
    });
    it('a relay that adds it still fools the host (documented); the operator, which never stated it, ends promptly and reports none', async () => {
      rewriteConnect(noProof(['gateway-lossless-close']));
      const closes = tapCloses(); const o = await vanishingOrigin();
      const { url } = await setup();
      const { c } = await operator(url, { clientOptions: { gatewayLosslessClose: false } });
      const r = await vanish(c, o, 15000);
      assert.equal(r.lossless, false);
      await until(() => closes.includes('released'), 'the host to release');
      assert.equal(r.end, 'released');
    });
  });
});
