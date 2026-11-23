// test/operator-proof.test.mjs -- #117: in reverse mode the operator proves its identity to the PEER, not only to the
// relay; both halves of the end-to-end exchange are signed; and with the option on, nothing that names a command is
// sent before the key exists. The relay in these tests is hostile on purpose.
import { describe, it, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { hostileRelay } from './helpers/hostile-relay.mjs';
import { E2EResponder, initiatorTranscript, keyExchangeTranscript } from '../src/e2e-exchange.mjs';
import {
  challengeTranscript, proofTranscript, createReverseChallenge, verifyReverseChallenge, createOperatorProof, verifyOperatorProof,
} from '../src/operator-proof.mjs';
import { resolveSigner, sign } from '../src/auth.mjs';
import {
  WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, cborEncode, MSG,
  open as openMsg, relayForward, keyExchange,
} from '@johnhenry/wsh';
import { reverseProof } from '../src/messages.gen.mjs';

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
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

describe('operator proof: the messages', () => {
  let peer; let op; let other;
  before(async () => {
    const mk = async () => { const keyPair = await generateKeyPair(true); return { keyPair, raw: await exportPublicKeyRaw(keyPair.publicKey), signer: await resolveSigner({ keyPair }) }; };
    [peer, op, other] = [await mk(), await mk(), await mk()];
    for (const k of [peer, op, other]) k.fp = await fingerprint(k.raw);
  });

  it('a challenge verifies for the operator it names and for the peer asked for, and for nobody else', async () => {
    const { fields, nonce, sessionId } = await createReverseChallenge({ keyPair: peer.keyPair }, op.fp);
    const msg = { public_key: fields.publicKey, operator_fingerprint: op.fp, nonce, session_id: sessionId, signature: fields.signature };
    const ok = await verifyReverseChallenge(msg, { target: peer.fp.slice(0, 12), ownFingerprint: op.fp });
    assert.equal(ok.peerFingerprint, peer.fp);
    await assert.rejects(verifyReverseChallenge(msg, { target: peer.fp, ownFingerprint: other.fp }), /different operator fingerprint/);
    await assert.rejects(verifyReverseChallenge(msg, { target: other.fp.slice(0, 12), ownFingerprint: op.fp }), /not the peer that was asked for/);
    await assert.rejects(verifyReverseChallenge({ ...msg, nonce: new Uint8Array(32) }, { target: peer.fp, ownFingerprint: op.fp }), /signature does not verify/);
    await assert.rejects(verifyReverseChallenge({ ...msg, session_id: 'other' }, { target: peer.fp, ownFingerprint: op.fp }), /signature does not verify/);
  });

  it('a proof verifies once for the challenge it answers; a replay, another nonce, another key, another name do not', async () => {
    const issued = await createReverseChallenge({ keyPair: peer.keyPair }, op.fp);
    const challenge = { peerPublicKey: peer.raw, nonce: issued.nonce, sessionId: issued.sessionId };
    const f = await createOperatorProof(op.signer, challenge, 'bob');
    const msg = { public_key: f.publicKey, username: f.username, nonce: f.nonce, session_id: f.sessionId, signature: f.signature };
    const proven = await verifyOperatorProof(msg, issued);
    assert.equal(proven.fingerprint, op.fp);
    assert.equal(proven.username, 'bob');
    // an old proof against a new challenge
    const next = await createReverseChallenge({ keyPair: peer.keyPair }, op.fp);
    assert.equal(await verifyOperatorProof(msg, next), null);
    assert.equal(await verifyOperatorProof({ ...msg, nonce: next.nonce, session_id: next.sessionId }, next), null, 'the old signature does not cover the new nonce');
    // another key presented with the operator's signature
    assert.equal(await verifyOperatorProof({ ...msg, public_key: other.raw }, issued), null);
    // the same signature claiming another username
    assert.equal(await verifyOperatorProof({ ...msg, username: 'root' }, issued), null);
    // a proof made for another peer
    const forOther = await createOperatorProof(op.signer, { ...challenge, peerPublicKey: other.raw }, 'bob');
    assert.equal(await verifyOperatorProof({ public_key: forOther.publicKey, username: 'bob', nonce: forOther.nonce, session_id: forOther.sessionId, signature: forOther.signature }, issued), null);
  });

  it('the two transcripts and the two key exchange transcripts cannot stand in for each other', async () => {
    const k32 = new Uint8Array(32).fill(1);
    const a = challengeTranscript({ peerPublicKey: k32, operatorFingerprint: 'f', nonce: k32, sessionId: 's' });
    const b = proofTranscript({ peerPublicKey: k32, operatorPublicKey: k32, username: 'f', nonce: k32, sessionId: 's' });
    assert.notDeepEqual(a, b);
    const init = initiatorTranscript({ sessionId: 's', algorithm: 'X25519', initiatorKey: k32, responderIdentity: k32 });
    const resp = keyExchangeTranscript({ sessionId: 's', algorithm: 'X25519', initiatorKey: k32, responderKey: k32 });
    assert.notDeepEqual(init, resp);
  });

  it('a responder that knows the operator key refuses a KeyExchange with no initiator signature, a forged one, or one for another responder', async () => {
    const x = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', x.publicKey));
    const responder = () => new E2EResponder({ signKey: peer.keyPair.privateKey, identity: peer.raw, initiator: { publicKey: op.raw, require: true } });
    const msg = (signature) => ({ type: MSG.KEY_EXCHANGE, algorithm: 'X25519', public_key: pub, session_id: 'sess', signature });
    const goodSig = await op.signer.sign(initiatorTranscript({ sessionId: 'sess', algorithm: 'X25519', initiatorKey: pub, responderIdentity: peer.raw }));
    assert.ok((await responder().respond(msg(goodSig))).key, 'the right signature is accepted');
    await assert.rejects(responder().respond(msg(undefined)), /requires/);
    await assert.rejects(responder().respond(msg(new Uint8Array(64))), /does not verify/);
    const forOther = await op.signer.sign(initiatorTranscript({ sessionId: 'sess', algorithm: 'X25519', initiatorKey: pub, responderIdentity: other.raw }));
    await assert.rejects(responder().respond(msg(forOther)), /does not verify/);
    const byOther = await other.signer.sign(initiatorTranscript({ sessionId: 'sess', algorithm: 'X25519', initiatorKey: pub, responderIdentity: peer.raw }));
    await assert.rejects(responder().respond(msg(byOther)), /does not verify/);
    const otherSession = await op.signer.sign(initiatorTranscript({ sessionId: 'elsewhere', algorithm: 'X25519', initiatorKey: pub, responderIdentity: peer.raw }));
    await assert.rejects(responder().respond(msg(otherSession)), /does not verify/);
    // without a configured initiator the exchange is as before (unauthenticated initiator)
    assert.ok((await new E2EResponder({ signKey: peer.keyPair.privateKey }).respond(msg(undefined))).key);
  });
});

describe('operator proof through a relay', () => {
  const keys = {};
  let authorizedKeys;
  const closers = [];
  before(async () => {
    for (const name of ['host', 'bob', 'mallory', 'dave']) {
      const keyPair = await generateKeyPair(true);
      keys[name] = { keyPair, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)), raw: await exportPublicKeyRaw(keyPair.publicKey) };
    }
    authorizedKeys = (await Promise.all(Object.entries(keys).map(async ([n, k]) => `${await exportPublicKeySSH(k.keyPair.publicKey)} ${n}`))).join('\n');
  });
  afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

  /**
   * A relay, a hostile hop in front of the HOST's relay connection, and the host.
   * @param {object} o
   * @param {object} [o.hop] - hooks for the hostile relay between the host and the relay
   * @param {object} [o.host] - createReverseHost options
   */
  async function world({ hop = {}, host: hostOptions = {}, relay: relayOptions = {}, accepted = [], ran = [] } = {}) {
    const server = createWshServer({
      auth: { authorizedKeys },
      relay: { canRegister: (w) => w.username === 'host', canConnect: (f) => f.username !== 'host', connectTimeoutMs: 3000, ...relayOptions },
    });
    const { port } = await server.listen();
    closers.push(() => server.close());
    const url = `ws://127.0.0.1:${port}`;
    const mitm = await hostileRelay(url, hop);
    closers.push(() => mitm.close());
    const exec = async (command, io) => { ran.push(command); io.write(`ran:${command}\n`); return 0; };
    const host = createReverseHost({
      url: mitm.url, username: 'host', keyPair: keys.host.keyPair, exec, reconnect: false, proofTimeoutMs: 1500,
      accept: (who) => { accepted.push(who); return who.fingerprint === keys.bob.fp; },
      ...hostOptions,
    });
    await host.start();
    closers.push(() => host.close());
    await until(() => server.address() && keys.host.fp && server.peerFingerprints?.().includes(keys.host.fp), 'the host to register');
    return { server, url, mitm, host, accepted, ran };
  }
  async function login(url, name) {
    const c = new WshClient();
    await c.connect(url, { username: name, keyPair: keys[name].keyPair });
    closers.push(() => c.disconnect());
    return c;
  }
  const collect = (session) => new Promise((resolve) => { const ch = []; session.onData = (d) => ch.push(d); session.onClose = () => resolve(dec.decode(Buffer.concat(ch))); });
  const MSGS = (mitm, dir, type) => mitm.seen.filter((s) => s.dir === dir && s.msg.type === type).map((s) => s.msg);

  describe('the ordinary case', () => {
    it('the host verifies the operator before accept runs, and accept hears that it was proven, and by whom', async () => {
      const w = await world();
      const bob = await login(w.url, 'bob');
      const res = await bob.reverseConnect(keys.host.fp);
      assert.equal(res.type, MSG.REVERSE_ACCEPT);
      assert.equal(w.accepted.length, 1);
      assert.deepEqual({ ...w.accepted[0], publicKey: undefined }, { fingerprint: keys.bob.fp, username: 'bob', proven: true, publicKey: undefined });
      assert.ok(same(w.accepted[0].publicKey, keys.bob.raw));
      assert.ok(res.features.includes('e2e-sealed'));
    });

    it('an operator that does not offer proof (no key to sign with is impossible; a client that predates it) is still served by a host that does not require it', async () => {
      const w = await world();
      const bob = await login(w.url, 'bob');
      const res = await bob.reverseConnect(keys.host.fp, 5000, { proof: false });
      assert.equal(res.type, MSG.REVERSE_ACCEPT);
      assert.equal(w.accepted[0].proven, false);
      assert.equal(MSGS(w.mitm, 'to-client', MSG.REVERSE_CHALLENGE).length, 0, 'no challenge was sent to an operator that did not offer');
      const s = await bob.openSession({ type: 'exec', command: 'ls' });
      assert.equal(await collect(s), 'ran:ls\n');
    });

    it('a host that requires operator proof refuses an operator that does not offer it, and says why', async () => {
      const w = await world({ host: { requireOperatorProof: true } });
      const bob = await login(w.url, 'bob');
      const res = await bob.reverseConnect(keys.host.fp, 5000, { proof: false });
      assert.equal(res.type, MSG.REVERSE_REJECT);
      assert.match(res.reason, /operator proof required/);
      assert.equal(w.accepted.length, 0, 'accept never ran');
    });

    it('a sealed bridge: the exec runs, and the relay never sees the command, the output, or an Open', async () => {
      const w = await world({ host: { requireOperatorProof: true } });
      const bob = await login(w.url, 'bob');
      const res = await bob.reverseConnect(keys.host.fp, 5000, { sealed: true });
      assert.equal(res.type, MSG.REVERSE_ACCEPT);
      const s = await bob.openSession({ type: 'exec', command: 'echo SECRET-COMMAND-TEXT' });
      assert.equal(await collect(s), 'ran:echo SECRET-COMMAND-TEXT\n');
      assert.deepEqual(w.ran, ['echo SECRET-COMMAND-TEXT']);
      // What the hostile hop saw: no plaintext Open / OpenOk / SessionData anywhere, and the text is not in any message.
      const everything = w.mitm.seen.map((x) => x.msg);
      for (const t of [MSG.OPEN, MSG.OPEN_OK, MSG.SESSION_DATA, MSG.EXIT]) {
        const plain = everything.filter((m) => m.type === t || (m.type === MSG.RELAY_FORWARD && cborDecodeType(m.inner) === t));
        assert.equal(plain.length, 0, `a plaintext ${t} crossed the relay`);
      }
      const blob = Buffer.concat(everything.map((m) => Buffer.from(cborEncode(m)))).toString('latin1');
      assert.ok(!blob.includes('SECRET-COMMAND-TEXT'), 'the command is not readable by the relay');
      assert.ok(!blob.includes('ran:echo'), 'the output is not readable by the relay');
      // The only bridge-level plaintext is the key exchange itself.
      const plainForwards = everything.filter((m) => m.type === MSG.RELAY_FORWARD).map((m) => cborDecodeType(m.inner));
      assert.ok(plainForwards.every((t) => t === MSG.KEY_EXCHANGE || t === MSG.ENCRYPTED_FRAME), `plaintext types: ${plainForwards}`);
    });

    it('sealed: the operator refuses to send anything naming a command before the key exists', async () => {
      const w = await world({ host: { requireOperatorProof: true } });
      const bob = await login(w.url, 'bob');
      // Hold the host's reply so the bridge is not up: the operator-side gate must refuse a plain Open meanwhile.
      const gate = bob.reverseConnect(keys.host.fp, 5000, { sealed: true });
      await assert.rejects(bob.openSession({ type: 'exec', command: 'echo too-early', timeout: 300 }), /nothing is sent over it before the key exists/);
      await gate;
      assert.deepEqual(w.ran, []);
    });

    it('sealed against a host that does not offer it (or a relay that does not carry the proof): nothing is sent', async () => {
      const w = await world({ host: { e2e: false } });
      const bob = await login(w.url, 'bob');
      await assert.rejects(bob.reverseConnect(keys.host.fp, 3000, { sealed: true }), /does not state "e2e-sealed"/);
      assert.deepEqual(w.ran, []);
      // A relay that does not list operator-proof: the operator will not even try.
      const w2 = await world();
      const stripped = await hostileRelay(w2.url, { toClient: (m) => (m.type === MSG.SERVER_HELLO ? { ...m, features: (m.features ?? []).filter((f) => f !== 'operator-proof') } : m) });
      closers.push(() => stripped.close());
      const bob2 = await login(stripped.url, 'bob');
      await assert.rejects(bob2.reverseConnect(keys.host.fp, 3000, { sealed: true }), /does not carry operator proof/);
      await assert.rejects(bob2.reverseConnect(keys.host.fp, 3000, { requirePeerProof: true }), /does not carry operator proof/);
    });

    it('requirePeerProof: the operator can insist the peer signs its challenge', async () => {
      const w = await world();
      const bob = await login(w.url, 'bob');
      const res = await bob.reverseConnect(keys.host.fp, 5000, { requirePeerProof: true });
      assert.equal(res.type, MSG.REVERSE_ACCEPT);
    });
  });

  describe('a hostile relay in front of a host that requires operator proof', () => {
    const asHost = { requireOperatorProof: true };

    it('rewrites from_fingerprint to an authorized operator: the real operator will not answer a challenge that names someone else, and the host never accepts', async () => {
      // mallory is the one connecting; the relay claims it is bob (whom the host would accept).
      const w = await world({
        host: asHost,
        hop: { toClient: (m) => (m.type === MSG.REVERSE_CONNECT ? { ...m, from_fingerprint: keys.bob.fp } : m) },
      });
      const mallory = await login(w.url, 'mallory');
      const res = await mallory.reverseConnect(keys.host.fp, 3000).catch((e) => e);
      assert.ok(res instanceof Error || res.type === MSG.REVERSE_REJECT, 'the connect did not succeed');
      assert.equal(w.accepted.length, 0, 'accept never ran for a claimed bob');
      assert.deepEqual(w.host.operators, []);
    });

    it('... and a malicious operator that signs anyway is caught: its key is not the one the relay named', async () => {
      const w = await world({
        host: asHost,
        hop: { toClient: (m) => (m.type === MSG.REVERSE_CONNECT ? { ...m, from_fingerprint: keys.bob.fp } : m) },
      });
      const mallory = await login(w.url, 'mallory');
      // Mallory skips the operator-side check and answers whatever challenge arrives, with its own key.
      mallory.addControlListener(() => {});
      const signer = await resolveSigner({ keyPair: keys.mallory.keyPair });
      const challenge = new Promise((resolve) => { mallory.addControlListener((m) => { if (m.type === MSG.REVERSE_CHALLENGE) resolve(m); }); });
      await mallory.sendControl({ type: MSG.REVERSE_CONNECT, target_fingerprint: keys.host.fp, username: '', from_fingerprint: '', features: ['operator-proof'] });
      const c = await challenge;
      const f = await createOperatorProof(signer, { peerPublicKey: c.public_key, nonce: c.nonce, sessionId: c.session_id }, 'mallory');
      await mallory.sendControl(reverseProof({ targetFingerprint: keys.host.fp, ...f }));
      await sleep(400);
      assert.equal(w.accepted.length, 0, 'the proof is by mallory, the relay said bob: refused before accept');
      assert.deepEqual(w.host.operators, []);
    });

    it('replays an old proof (as it was, and with the new nonce pasted in): rejected', async () => {
      let recorded = null;
      let challenges = 0;
      const w = await world({
        host: { ...asHost, reconnect: true },
        hop: {
          toClient: (m, ctx) => {
            if (m.type === MSG.REVERSE_PROOF) { recorded ??= m; if (challenges >= 2) return null; }
            if (m.type === MSG.REVERSE_CONNECT) return m;
            return m;
          },
          toRelay: (m, ctx) => {
            if (m.type === MSG.REVERSE_CHALLENGE) {
              challenges += 1;
              if (challenges === 2) {
                // The second challenge never reaches the operator; the relay answers it from its recording instead.
                const old = recorded;
                setTimeout(() => ctx.injectToClient({ ...old, nonce: m.nonce, session_id: m.session_id }), 20);
                return null;
              }
            }
            return m;
          },
        },
      });
      // First, a legitimate connection by bob (sealed), which the relay records.
      const bob = await login(w.url, 'bob');
      const first = await bob.reverseConnect(keys.host.fp, 5000, { sealed: true });
      assert.equal(first.type, MSG.REVERSE_ACCEPT);
      assert.ok(recorded, 'the hostile hop recorded the proof');
      await bob.disconnect();
      await until(() => w.host.operators.length === 0 && w.server.peerFingerprints().includes(keys.host.fp), 'the host to come back after the first bridge');
      // Then another operator connection, answered from the recording.
      const bob2 = await login(w.url, 'bob');
      const second = await bob2.reverseConnect(keys.host.fp, 3000).catch((e) => e);
      assert.ok(second instanceof Error || second.type === MSG.REVERSE_REJECT, 'refused');
      assert.equal(w.accepted.length, 1, 'accept ran once, for the real first connection; the replay never reached it');
      assert.equal(challenges, 2);
    });

    it('swaps the operator\'s key in the proof: rejected, whether or not it re-signs', async () => {
      for (const resign of [false, true]) {
        const mallorySigner = await resolveSigner({ keyPair: keys.mallory.keyPair });
        let challenged = null;
        const w = await world({
          host: asHost,
          hop: {
            toRelay: (m) => { if (m.type === MSG.REVERSE_CHALLENGE) challenged = m; return m; },
            toClient: async (m) => {
              if (m.type !== MSG.REVERSE_PROOF) return m;
              if (!resign) return { ...m, public_key: keys.mallory.raw, from_fingerprint: keys.mallory.fp };
              const f = await createOperatorProof(mallorySigner, { peerPublicKey: keys.host.raw, nonce: challenged.nonce, sessionId: challenged.session_id }, m.username);
              return { ...m, public_key: f.publicKey, signature: f.signature, from_fingerprint: keys.mallory.fp };
            },
          },
        });
        const bob = await login(w.url, 'bob');
        const res = await bob.reverseConnect(keys.host.fp, 3000).catch((e) => e);
        assert.ok(res instanceof Error || res.type === MSG.REVERSE_REJECT, `resign=${resign}: not bridged`);
        // The host never learned that "bob" was there: either the signature failed, or accept saw mallory (and said no).
        assert.ok(w.accepted.every((a) => a.fingerprint !== keys.bob.fp), `resign=${resign}: accept was never told bob`);
        assert.deepEqual(w.host.operators, [], `resign=${resign}`);
      }
    });

    it('injects an Open stamped with the operator\'s fingerprint: the host does not run it, before or after the bridge is sealed', async () => {
      const w = await world({ host: asHost });
      const bob = await login(w.url, 'bob');
      await bob.reverseConnect(keys.host.fp, 5000, { sealed: true });
      const ctx = w.mitm.context();
      const plain = relayForward({ fromFingerprint: keys.bob.fp, inner: cborEncode(openMsg({ kind: 'exec', command: 'INJECTED-PLAIN' })) });
      await ctx.injectToClient(plain);
      // ... and a replay of the operator's own sealed Open, copied off the wire.
      const s = await bob.openSession({ type: 'exec', command: 'legit' });
      assert.equal(await collect(s), 'ran:legit\n');
      const sealedOpen = w.mitm.seen.filter((x) => x.dir === 'to-client' && x.msg.type === MSG.RELAY_FORWARD && cborDecodeType(x.msg.inner) === MSG.ENCRYPTED_FRAME).map((x) => x.msg)[0];
      assert.ok(sealedOpen, 'the hop saw a sealed frame to replay');
      await ctx.injectToClient(sealedOpen);
      await sleep(300);
      assert.deepEqual(w.ran, ['legit'], 'neither the plain Open nor the replayed frame ran anything');
    });

    it('injects an Open before the operator has connected at all (nobody is bridged): nothing runs', async () => {
      const w = await world({ host: asHost });
      await w.mitm.context().injectToClient(relayForward({ fromFingerprint: keys.bob.fp, inner: cborEncode(openMsg({ kind: 'exec', command: 'NOBODY-HOME' })) }));
      await sleep(200);
      assert.deepEqual(w.ran, []);
    });

    it('LIMIT: a host that does NOT require operator proof still takes a plain Open stamped with an operator\'s fingerprint from a relay (that is what the option is for)', async () => {
      const w = await world();
      const bob = await login(w.url, 'bob');
      await bob.reverseConnect(keys.host.fp, 5000, { proof: false });
      await w.mitm.context().injectToClient(relayForward({ fromFingerprint: keys.bob.fp, inner: cborEncode(openMsg({ kind: 'exec', command: 'INJECTED' })) }));
      await until(() => w.ran.includes('INJECTED'), 'the injected Open to run');
    });

    it('a sealed key exchange whose initiator half is not signed by the proven operator is refused, and the bridge ends', async () => {
      const w = await world({ host: asHost });
      const bob = await login(w.url, 'bob');
      // The operator proves itself, then the "operator" (here: the hop) sends an unsigned key exchange of its own.
      const challenged = new Promise((resolve) => { bob.addControlListener((m) => { if (m.type === MSG.REVERSE_ACCEPT) resolve(m); }); });
      await bob.reverseConnect(keys.host.fp, 5000, { proof: true }); // proven, not sealed: the host still demands sealing
      void challenged;
      const challenge = w.mitm.seen.find((x) => x.dir === 'to-relay' && x.msg.type === MSG.REVERSE_CHALLENGE).msg;
      const x = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
      const pub = new Uint8Array(await crypto.subtle.exportKey('raw', x.publicKey));
      await w.mitm.context().injectToClient(relayForward({ fromFingerprint: keys.bob.fp, inner: cborEncode(keyExchange({ algorithm: 'X25519', publicKey: pub, sessionId: challenge.session_id })) }));
      await until(() => w.host.operators.length === 0, 'the bridge to end');
      assert.deepEqual(w.ran, []);
    });
  });
});

function cborDecodeType(bytes) {
  // The type number is all the test needs from an inner envelope.
  return cborDecodeEnvelope(bytes)?.type;
}
import { cborDecode as cborDecodeEnvelope } from '@johnhenry/wsh';
void sign;
