/**
 * The key-exchange half of wsh's opt-in end-to-end encryption that is not the
 * initiating client: the RESPONDER a host runs when an operator sends it a
 * `KeyExchange` (wsh #90), plus the pieces both sides share -- the hybrid
 * secret combiner, the byte comparison that picks the ML-KEM encapsulator, and
 * the signed transcript that lets a host authenticate its half.
 *
 * `WshClient.initiateE2E()` is the initiator. The two sides derive the same
 * AES-256-GCM key (see `e2e-frame.mjs` for how it is used to seal frames).
 *
 * ── Authenticating the responder ────────────────────────────────────
 * `KeyExchange` carries only ephemeral public keys, so by itself it protects
 * against a relay that observes, not one that substitutes keys. A responder
 * given a signing key therefore signs, with its long-term Ed25519 identity, a
 * transcript binding the label, the session id, the algorithm, and BOTH
 * ephemeral X25519 keys (initiator's first). The initiator verifies it against
 * the host key it meant to reach (`initiateE2E(..., { verifyPeer })`): a relay
 * that swaps either ephemeral key cannot produce a matching signature.
 */

import { sign as signBytes, verify as verifyBytes, importPublicKeyRaw } from './auth.mjs';
import { keyExchange } from './messages.gen.mjs';
import { generateMlKemKeyPair, mlKemEncapsulate, mlKemDecapsulate, MLKEM768_PUBLIC_KEY_LENGTH } from './mlkem.mjs';

export const E2E_ALGORITHM_CLASSICAL = 'X25519';
export const E2E_ALGORITHM_HYBRID = 'X25519+ML-KEM-768';
/** Host feature (in `ReverseAccept.features`): this host answers `KeyExchange` and seals/opens `EncryptedFrame`s. */
export const E2E_FEATURE = 'e2e';
/** Host feature: the host signs its `KeyExchange` reply, so the operator can authenticate it. */
export const E2E_SIGN_FEATURE = 'e2e-sign';

const LABEL = new TextEncoder().encode('wsh-e2e-keyexchange-v1\0');
const enc = new TextEncoder();
const MAX_PENDING = 8;
const PENDING_TTL_MS = 15_000;

/**
 * Lexicographic byte comparison, used by hybrid mode to assign the ML-KEM
 * "encapsulator" role without an extra round trip.
 * @returns {number} <0 if a<b, >0 if a>b, 0 if equal
 */
export function compareBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/**
 * Combine the classical (X25519 ECDH) and post-quantum (ML-KEM-768) outputs
 * into one AES-256-GCM key via HKDF-SHA256, so the final key is only as weak
 * as the *stronger* of the two.
 * @param {Uint8Array} x25519Bits - 32-byte ECDH shared secret
 * @param {Uint8Array} kemSharedSecret - 32-byte ML-KEM-768 shared secret
 * @returns {Promise<Uint8Array>} 32 bytes of combined key material
 */
export async function combineHybridSecret(x25519Bits, kemSharedSecret) {
  const ikm = new Uint8Array(x25519Bits.length + kemSharedSecret.length);
  ikm.set(x25519Bits, 0);
  ikm.set(kemSharedSecret, x25519Bits.length);
  const hkdfKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('wsh-hybrid-e2e-v1') },
    hkdfKey,
    256
  );
  return new Uint8Array(bits);
}

const lp = (bytes) => {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
};

/**
 * The bytes a responder signs: label, session id, the INITIATOR's algorithm string, then the initiator's and
 * responder's ephemeral X25519 public keys, each length-prefixed.
 * @param {{ sessionId: string, algorithm: string, initiatorKey: Uint8Array, responderKey: Uint8Array }} t
 * @returns {Uint8Array}
 */
export function keyExchangeTranscript({ sessionId, algorithm, initiatorKey, responderKey }) {
  const parts = [LABEL, lp(enc.encode(sessionId)), lp(enc.encode(algorithm)), lp(initiatorKey), lp(responderKey)];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/**
 * Verify a responder's `KeyExchange.signature`.
 * @param {Uint8Array | CryptoKey} peerIdentity - the host's raw 32-byte Ed25519 public key (or an imported one)
 * @param {Uint8Array | undefined} signature
 * @param {Parameters<typeof keyExchangeTranscript>[0]} transcript
 * @returns {Promise<boolean>}
 */
export async function verifyKeyExchangeSignature(peerIdentity, signature, transcript) {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
  try {
    const key = peerIdentity instanceof Uint8Array ? await importPublicKeyRaw(peerIdentity) : peerIdentity;
    return await verifyBytes(key, signature, keyExchangeTranscript(transcript));
  } catch {
    return false;
  }
}

/**
 * The responder side of `KeyExchange`, for a host. One instance per connection.
 *
 * `respond(msg)` takes each inbound `KeyExchange` and returns the messages to send back and, once the exchange is
 * complete, the derived key:
 *   - a round-1 message (has `public_key`): generate an ephemeral key, answer, and -- classical, or hybrid with the
 *     host as encapsulator -- derive straight away; as decapsulator it waits for the round-2 ciphertext;
 *   - a round-2 message (only `kem_ciphertext`): finish a pending hybrid exchange.
 */
export class E2EResponder {
  #sign;
  #hybrid;
  /** @type {Map<string, { sharedBits: Uint8Array, localKem: { secretKeySeed: Uint8Array }, timer: any }>} */
  #pending = new Map();

  /**
   * @param {object} [opts]
   * @param {CryptoKey | null} [opts.signKey] - long-term Ed25519 private key; given, the reply is signed
   * @param {boolean} [opts.hybrid=true] - offer X25519+ML-KEM-768 when the initiator asks for it
   */
  constructor({ signKey = null, hybrid = true } = {}) {
    this.#sign = signKey;
    this.#hybrid = hybrid;
  }

  get signs() { return !!this.#sign; }

  /** Forget unfinished exchanges (the connection ended). */
  close() {
    for (const p of this.#pending.values()) clearTimeout(p.timer);
    this.#pending.clear();
  }

  /**
   * `emit(reply)` (optional) is called with each reply as soon as it is ready -- the round-1 reply BEFORE the key
   * derivation and ML-KEM encapsulation, so the peer has it (and has registered for the ciphertext) well before the
   * ciphertext follows. Without `emit` the replies are returned in `replies`.
   *
   * @param {object} msg - a KeyExchange
   * @param {(reply: object) => Promise<void> | void} [emit]
   * @returns {Promise<{ replies: object[], key?: CryptoKey, sessionId: string, hybrid?: boolean }>}
   */
  async respond(msg, emit) {
    const sessionId = msg.session_id;
    if (typeof sessionId !== 'string' || !sessionId) throw new Error('KeyExchange without a session_id');
    if (msg.public_key === undefined && msg.kem_ciphertext !== undefined) return this.#finish(msg, sessionId);
    return this.#begin(msg, sessionId, emit);
  }

  async #begin(msg, sessionId, emit) {
    const replies = [];
    const out = async (reply) => { if (emit) await emit(reply); else replies.push(reply); };
    const algorithm = msg.algorithm;
    if (algorithm !== E2E_ALGORITHM_CLASSICAL && algorithm !== E2E_ALGORITHM_HYBRID) throw new Error(`unsupported E2E algorithm ${JSON.stringify(algorithm)}`);
    const peerPub = msg.public_key;
    if (!(peerPub instanceof Uint8Array) || peerPub.length !== 32) throw new Error('KeyExchange public_key must be a 32-byte X25519 key');
    const peerKem = msg.kem_public_key;
    const wantHybrid = algorithm === E2E_ALGORITHM_HYBRID && this.#hybrid
      && peerKem instanceof Uint8Array && peerKem.length === MLKEM768_PUBLIC_KEY_LENGTH;

    // A fresh exchange for this session replaces an unfinished one.
    this.#drop(sessionId);

    const ephemeral = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const localPub = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
    let localKem = null;
    if (wantHybrid) {
      try { localKem = await generateMlKemKeyPair(); } catch { localKem = null; } // no ML-KEM backend here: fall back to classical
    }
    const hybrid = !!localKem;

    const reply = {
      algorithm: hybrid ? E2E_ALGORITHM_HYBRID : E2E_ALGORITHM_CLASSICAL,
      publicKey: localPub,
      sessionId,
      kemPublicKey: localKem?.publicKey,
    };
    if (this.#sign) {
      reply.signature = await signBytes(this.#sign, keyExchangeTranscript({ sessionId, algorithm, initiatorKey: peerPub, responderKey: localPub }));
    }
    await out(keyExchange(reply));

    const peerKey = await crypto.subtle.importKey('raw', peerPub, { name: 'X25519' }, false, []);
    const sharedBits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: peerKey }, ephemeral.privateKey, 256));

    if (!hybrid) return { replies, key: await toAesKey(sharedBits), sessionId, hybrid: false };

    if (compareBytes(localPub, peerPub) < 0) {
      // The lower key encapsulates against the other side's ML-KEM key.
      const { ciphertext, sharedSecret } = await mlKemEncapsulate(peerKem);
      await new Promise((resolve) => setTimeout(resolve, 0)); // let the round-1 reply land before the ciphertext follows
      await out(keyExchange({ algorithm: E2E_ALGORITHM_HYBRID, sessionId, kemCiphertext: ciphertext }));
      return { replies, key: await toAesKey(await combineHybridSecret(sharedBits, sharedSecret)), sessionId, hybrid: true };
    }
    // The higher key decapsulates: wait for the peer's ciphertext.
    while (this.#pending.size >= MAX_PENDING) this.#drop(this.#pending.keys().next().value);
    const timer = setTimeout(() => this.#drop(sessionId), PENDING_TTL_MS);
    timer.unref?.();
    this.#pending.set(sessionId, { sharedBits, localKem, timer });
    return { replies, sessionId, hybrid: true };
  }

  async #finish(msg, sessionId) {
    const pending = this.#pending.get(sessionId);
    if (!pending) throw new Error('unexpected KeyExchange ciphertext (no hybrid exchange in progress for this session)');
    this.#drop(sessionId);
    const kemSecret = await mlKemDecapsulate(pending.localKem.secretKeySeed, new Uint8Array(msg.kem_ciphertext));
    return { replies: [], key: await toAesKey(await combineHybridSecret(pending.sharedBits, kemSecret)), sessionId, hybrid: true };
  }

  #drop(sessionId) {
    const p = this.#pending.get(sessionId);
    if (p) { clearTimeout(p.timer); this.#pending.delete(sessionId); }
  }
}

function toAesKey(bits) {
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
