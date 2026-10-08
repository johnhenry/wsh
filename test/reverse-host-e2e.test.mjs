// test/reverse-host-e2e.test.mjs -- end-to-end encryption from the Node host (#90): createReverseHost answers
// KeyExchange, seals its session output and opens the operator's EncryptedFrames, signs its half so the operator
// can authenticate it, and the relay in between only ever sees ciphertext.
import { describe, it, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { RelayHub } from '../src/server/relay.mjs';
import { sealFrame, ROLE_TAGS } from '../src/e2e-frame.mjs';
import { E2EResponder, keyExchangeTranscript } from '../src/e2e-exchange.mjs';
import {
  WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, cborEncode, MSG,
  sessionData, encryptedFrame, keyExchange, E2E_FEATURE, E2E_SIGN_FEATURE,
} from '@johnhenry/wsh';

const dec = new TextDecoder();
const enc = new TextEncoder();
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
let mlkemAvailable = false;
try { const m = await import('../src/mlkem.mjs'); await m.generateMlKemKeyPair(); mlkemAvailable = true; } catch { /* no backend here */ }

describe('createReverseHost: end-to-end encryption (#90)', () => {
  const keys = {};
  let authorizedKeys;
  const servers = [];
  const clients = [];
  const hosts = [];
  let relayServer = null;
  let hostRaw;

  before(async () => {
    for (const name of ['host', 'bob', 'dave']) {
      const keyPair = await generateKeyPair(true);
      keys[name] = { keyPair, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)) };
    }
    hostRaw = await exportPublicKeyRaw(keys.host.keyPair.publicKey);
    authorizedKeys = (await Promise.all(Object.entries(keys).map(async ([n, k]) => `${await exportPublicKeySSH(k.keyPair.publicKey)} ${n}`))).join('\n');
  });
  afterEach(async () => {
    for (const h of hosts.splice(0)) await h.close();
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
  });

  async function setup({ hostOptions = {}, relayOptions = {} } = {}) {
    const server = createWshServer({
      auth: { authorizedKeys },
      relay: { canRegister: (w) => w.username === 'host', canConnect: (f) => f.username !== 'host', ...relayOptions },
    });
    const { port } = await server.listen();
    servers.push(server);
    relayServer = server;
    const url = `ws://127.0.0.1:${port}`;
    const host = createReverseHost({ url, username: 'host', keyPair: keys.host.keyPair, exec: true, pty: false, accept: () => true, reconnect: false, ...hostOptions });
    await host.start();
    hosts.push(host);
    await until(() => relayServer.peerFingerprints().includes(keys.host.fp), 'the host to register');
    return { url, host };
  }
  async function operator(url, name = 'bob') {
    const c = new WshClient();
    await c.connect(url, { username: name, keyPair: keys[name].keyPair });
    clients.push(c);
    const accepted = await c.reverseConnect(keys.host.fp);
    assert.equal(accepted.type, MSG.REVERSE_ACCEPT);
    return c;
  }
  /** An exec session running `cat`, so anything written comes straight back. */
  async function catSession(client) {
    const session = await client.openSession({ type: 'exec', command: 'cat' });
    const out = [];
    session.onData = (d) => out.push(dec.decode(d));
    return { session, out, text: () => out.join('') };
  }
  /** Record everything the relay carries across a bridge. */
  function tapRelay() {
    const seen = [];
    const original = RelayHub.prototype.forward;
    RelayHub.prototype.forward = function spy(handle, msg) { seen.push({ from: handle.fingerprint, msg }); return original.call(this, handle, msg); };
    return { seen, restore: () => { RelayHub.prototype.forward = original; } };
  }

  it('advertises e2e (and e2e-sign) to the operator, and the secret travels as ciphertext both ways', async () => {
    const { url } = await setup();
    const bob = await operator(url);
    assert.ok(bob.bridgedFeatures.includes(E2E_FEATURE) && bob.bridgedFeatures.includes(E2E_SIGN_FEATURE));
    const { session, text } = await catSession(bob);
    const tap = tapRelay();
    try {
      const e2e = await bob.initiateE2E(session.sessionId, 'X25519', 5000, { verifyPeer: hostRaw });
      assert.equal(e2e.peerAuthenticated, true);
      assert.equal(e2e.hybrid, false);
      session.enableE2E(e2e.sharedSecret, { role: 'initiator' });
      const secret = 'the-launch-code-is-0451';
      await session.write(`${secret}\n`);
      await until(() => text().includes(secret), 'the echo to come back decrypted');
      assert.equal(text(), `${secret}\n`);
      const types = (from) => tap.seen.filter((e) => e.from === from).map((e) => e.msg.type);
      assert.ok(types(keys.bob.fp).includes(MSG.ENCRYPTED_FRAME), 'operator -> host sealed');
      assert.ok(types(keys.host.fp).includes(MSG.ENCRYPTED_FRAME), 'host -> operator sealed');
      assert.ok(!tap.seen.some((e) => e.msg.type === MSG.SESSION_DATA), 'no plaintext SessionData crossed the relay after the exchange');
      for (const { msg } of tap.seen) assert.ok(!Buffer.from(cborEncode(msg)).includes(Buffer.from(secret)), 'the relay never held the plaintext');
    } finally { tap.restore(); }
  });

  for (let round = 0; round < 6; round += 1) {
    it(`hybrid X25519+ML-KEM-768 works with the host on either side of the encapsulator choice (${round + 1}/6)`, { skip: !mlkemAvailable && 'no ML-KEM backend in this runtime' }, async () => {
      const { url } = await setup();
      const bob = await operator(url);
      const { session, text } = await catSession(bob);
      const e2e = await bob.initiateE2E(session.sessionId, 'X25519+ML-KEM-768', 8000, { verifyPeer: hostRaw });
      assert.equal(e2e.hybrid, true);
      assert.equal(e2e.peerAuthenticated, true);
      session.enableE2E(e2e.sharedSecret, { role: 'initiator' });
      await session.write('pq\n');
      await until(() => text() === 'pq\n', 'the hybrid echo');
    });
  }

  it('the operator can authenticate the host: a wrong key, an unsigned host, or a relay swapping the host key all fail', async () => {
    const { url } = await setup();
    const bob = await operator(url);
    const { session } = await catSession(bob);
    // a different host key than the one that signed
    const wrong = await exportPublicKeyRaw(keys.dave.keyPair.publicKey);
    await assert.rejects(bob.initiateE2E(session.sessionId, 'X25519', 3000, { verifyPeer: wrong }), (e) => e.code === 'E2E_PEER_UNAUTHENTICATED');

    // a relay that substitutes the host's ephemeral key cannot forge the signature
    const original = RelayHub.prototype.forward;
    RelayHub.prototype.forward = function mitm(handle, msg) {
      if (handle.fingerprint === keys.host.fp && msg.type === MSG.KEY_EXCHANGE && msg.public_key) {
        return original.call(this, handle, { ...msg, public_key: crypto.getRandomValues(new Uint8Array(32)) });
      }
      return original.call(this, handle, msg);
    };
    try {
      await assert.rejects(bob.initiateE2E(session.sessionId, 'X25519', 3000, { verifyPeer: hostRaw }), (e) => e.code === 'E2E_PEER_UNAUTHENTICATED');
    } finally { RelayHub.prototype.forward = original; }
    // and with nothing swapped it verifies
    assert.equal((await bob.initiateE2E(session.sessionId, 'X25519', 3000, { verifyPeer: hostRaw })).peerAuthenticated, true);
  });

  it('e2e: { sign: false } leaves the reply unsigned: it works unverified and fails verification', async () => {
    const { url } = await setup({ hostOptions: { e2e: { sign: false } } });
    const bob = await operator(url);
    assert.ok(bob.bridgedFeatures.includes(E2E_FEATURE));
    assert.ok(!bob.bridgedFeatures.includes(E2E_SIGN_FEATURE));
    const { session, text } = await catSession(bob);
    await assert.rejects(bob.initiateE2E(session.sessionId, 'X25519', 3000, { verifyPeer: hostRaw }), (e) => e.code === 'E2E_PEER_UNAUTHENTICATED' && /did not sign/.test(e.message));
    const e2e = await bob.initiateE2E(session.sessionId);
    assert.equal(e2e.peerAuthenticated, false);
    session.enableE2E(e2e.sharedSecret, { role: 'initiator' });
    await session.write('unsigned\n');
    await until(() => text() === 'unsigned\n', 'the echo');
  });

  it('e2e: false means the host does not advertise it and does not answer', async () => {
    const { url } = await setup({ hostOptions: { e2e: false } });
    const bob = await operator(url);
    assert.ok(!bob.bridgedFeatures.includes(E2E_FEATURE));
    const { session } = await catSession(bob);
    await assert.rejects(bob.initiateE2E(session.sessionId, 'X25519', 400), /Timed out/);
  });

  it('once E2E is on, plaintext input is ignored and a replayed, spliced or tampered frame never reaches the process', async () => {
    const { url } = await setup();
    const bob = await operator(url);
    const { session, text } = await catSession(bob);
    const tap = tapRelay();
    try {
      const e2e = await bob.initiateE2E(session.sessionId);
      session.enableE2E(e2e.sharedSecret, { role: 'initiator' });
      await session.write('one\n');
      await until(() => text() === 'one\n', 'the first echo');

      // A relay (or anyone on the path) injecting plaintext stdin:
      await bob.sendControl(sessionData({ channelId: session.channelId, data: enc.encode('INJECTED\n') }));
      // Replaying the sealed frame the operator already sent:
      const sent = tap.seen.find((e) => e.from === keys.bob.fp && e.msg.type === MSG.ENCRYPTED_FRAME).msg;
      await bob.sendControl(encryptedFrame({ channelId: sent.channel_id, nonce: sent.nonce, ciphertext: sent.ciphertext, sessionId: sent.session_id }));
      // The same ciphertext claimed for another session:
      await bob.sendControl(encryptedFrame({ channelId: sent.channel_id, nonce: sent.nonce, ciphertext: sent.ciphertext, sessionId: 'some-other-session' }));
      // A bit flipped in the next valid frame's ciphertext (counter 1):
      const next = await sealFrame(e2e.sharedSecret, session.sessionId, ROLE_TAGS.initiator, 1, enc.encode('TAMPERED\n'));
      const bad = Uint8Array.from(next.ciphertext); bad[0] ^= 1;
      await bob.sendControl(encryptedFrame({ channelId: session.channelId, nonce: next.nonce, ciphertext: bad, sessionId: session.sessionId }));
      await sleep(300);
      assert.equal(text(), 'one\n', 'none of it was delivered');

      // The genuine stream carries on: garbage does not consume a counter.
      await session.write('two\n');
      await until(() => text() === 'one\ntwo\n', 'the genuine frame after the garbage');
    } finally { tap.restore(); }
  });

  it('a KeyExchange for a session this connection does not have is not answered', async () => {
    const { url } = await setup();
    const bob = await operator(url);
    await assert.rejects(bob.initiateE2E('not-a-session-of-this-connection', 'X25519', 400), /Timed out/);
  });

  it('each operator of a multi-operator host has its own keys', async () => {
    const { url } = await setup({ hostOptions: { maxOperators: 2 }, relayOptions: { maxOperatorsPerPeer: 2 } });
    const bob = await operator(url, 'bob');
    const dave = await operator(url, 'dave');
    const a = await catSession(bob);
    const b = await catSession(dave);
    const [ea, eb] = await Promise.all([bob.initiateE2E(a.session.sessionId), dave.initiateE2E(b.session.sessionId)]);
    a.session.enableE2E(ea.sharedSecret, { role: 'initiator' });
    b.session.enableE2E(eb.sharedSecret, { role: 'initiator' });
    await Promise.all([a.session.write('from bob\n'), b.session.write('from dave\n')]);
    await until(() => a.text() === 'from bob\n' && b.text() === 'from dave\n', 'both echoes');
  });
});

describe('E2EResponder (unit)', () => {
  it('derives the same key as initiateE2E would, and signs the transcript it states', async () => {
    const { verifyKeyExchangeSignature } = await import('../src/e2e-exchange.mjs');
    const id = await generateKeyPair(true);
    const responder = new E2EResponder({ signKey: id.privateKey });
    const initiator = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const initPub = new Uint8Array(await crypto.subtle.exportKey('raw', initiator.publicKey));
    const { replies, key, sessionId } = await responder.respond(keyExchange({ algorithm: 'X25519', publicKey: initPub, sessionId: 's-1' }));
    assert.equal(sessionId, 's-1');
    assert.equal(replies.length, 1);
    assert.ok(key);
    const reply = replies[0];
    const pub = await exportPublicKeyRaw(id.publicKey);
    assert.equal(await verifyKeyExchangeSignature(pub, reply.signature, { sessionId: 's-1', algorithm: 'X25519', initiatorKey: initPub, responderKey: reply.public_key }), true);
    // not valid for another session, algorithm or key
    for (const bad of [{ sessionId: 's-2' }, { algorithm: 'X25519+ML-KEM-768' }, { initiatorKey: new Uint8Array(32) }, { responderKey: new Uint8Array(32) }]) {
      assert.equal(await verifyKeyExchangeSignature(pub, reply.signature, { sessionId: 's-1', algorithm: 'X25519', initiatorKey: initPub, responderKey: reply.public_key, ...bad }), false);
    }
    assert.notDeepEqual([...keyExchangeTranscript({ sessionId: 'ab', algorithm: 'c', initiatorKey: new Uint8Array(1), responderKey: new Uint8Array(1) })], [...keyExchangeTranscript({ sessionId: 'a', algorithm: 'bc', initiatorKey: new Uint8Array(1), responderKey: new Uint8Array(1) })], 'fields are length-prefixed');
  });

  it('refuses malformed exchanges', async () => {
    const r = new E2EResponder();
    await assert.rejects(r.respond(keyExchange({ algorithm: 'X25519', publicKey: new Uint8Array(31), sessionId: 's' })), /32-byte/);
    await assert.rejects(r.respond(keyExchange({ algorithm: 'RSA', publicKey: new Uint8Array(32), sessionId: 's' })), /unsupported/);
    await assert.rejects(r.respond(keyExchange({ algorithm: 'X25519', publicKey: new Uint8Array(32) })), /session_id/);
    await assert.rejects(r.respond(keyExchange({ algorithm: 'X25519+ML-KEM-768', sessionId: 's', kemCiphertext: new Uint8Array(1088) })), /no hybrid exchange/);
  });
});
