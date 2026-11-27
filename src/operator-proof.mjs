/**
 * The operator proves its identity to the PEER (wsh #117).
 *
 * In reverse mode the relay authenticates the operator (its login key) and stamps `from_fingerprint` on what it
 * forwards, so a peer that took `accept({ fingerprint })` at face value trusted the relay for authorization. With
 * proof the peer does not have to:
 *
 *   operator -> relay -> peer   ReverseConnect { features: ['operator-proof'] }
 *   peer -> relay -> operator   ReverseChallenge { public_key, operator_fingerprint, nonce, session_id, signature }
 *   operator -> relay -> peer   ReverseProof { public_key, username, nonce, session_id, signature }
 *   peer: verifies, THEN runs `accept({ fingerprint, username, proven: true })`
 *
 * Both signatures are Ed25519 over a labelled, length-prefixed byte string (not a hash, so nothing is truncated):
 *
 *   challenge = "wsh-reverse-challenge-v1\0" || lp(peer key) || lp(operator fingerprint) || lp(nonce) || lp(session id)
 *   proof     = "wsh-operator-proof-v1\0"    || lp(peer key) || lp(operator key) || lp(username) || lp(nonce) || lp(session id)
 *
 * The peer signs its challenge so the operator knows whom it is proving itself to and that the peer saw the
 * operator's own fingerprint (a relay that rewrote `from_fingerprint` shows). The operator's proof names the peer it
 * is for, the peer's single-use nonce and the bridge's session id: it cannot be replayed to another peer, later, or
 * for another bridge, and a relay that swaps `public_key` cannot sign for the key it put there.
 *
 * #318: an operator that states `gateway-lossless-close` signs it into a v2 proof (see `proofTranscript`), only for a peer that lists
 * `gateway-lossless-close-signed`; the peer acts on the signed statement, never on the unsigned list a relay can edit.
 *
 * What it does NOT do on its own: it proves who was at the other end when the bridge was set up. A relay can still
 * stamp that identity on a plain message afterwards; closing that is the sealed bridge (`bridge-seal.mjs`), which a
 * host that requires operator proof also requires.
 */

import { verify as verifyBytes, importPublicKeyRaw, fingerprint, resolveSigner } from './auth.mjs';

/** `ServerHello.features` of a relay that carries `ReverseChallenge` / `ReverseProof`, and `ReverseConnect.features` of an operator that answers one. */
export const OPERATOR_PROOF_FEATURE = 'operator-proof';
/** `ReverseAccept.features` of a peer that takes a signed initiator half and a sealed bridge. */
export const E2E_SEALED_FEATURE = 'e2e-sealed';

/**
 * What a host lists in its REGISTERED capabilities when it reads a signed statement of `gateway-lossless-close` in an operator's proof (#318): an
 * operator signs the statement (a `wsh-operator-proof-v2` proof) only for a peer that lists this, since a peer that does not would not verify it.
 */
export const GATEWAY_LOSSLESS_SIGNED_FEATURE = 'gateway-lossless-close-signed';
/** The one statement a proof can carry (the string of `gateway-channel.mjs`'s `GATEWAY_LOSSLESS_FEATURE`). */
const SIGNABLE = ['gateway-lossless-close'];

const enc = new TextEncoder();
const CHALLENGE_LABEL = enc.encode('wsh-reverse-challenge-v1\0');
const PROOF_LABEL = enc.encode('wsh-operator-proof-v1\0');
const PROOF_LABEL_V2 = enc.encode('wsh-operator-proof-v2\0');
export const NONCE_LENGTH = 32;

const lp = (bytes) => {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
};
const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};
const isKey = (v) => v instanceof Uint8Array && v.length === 32;
const str = (v, max = 256) => typeof v === 'string' && v.length > 0 && v.length <= max;

/** The bytes a peer signs in a `ReverseChallenge`. */
export function challengeTranscript({ peerPublicKey, operatorFingerprint, nonce, sessionId }) {
  return concat([CHALLENGE_LABEL, lp(peerPublicKey), lp(enc.encode(operatorFingerprint)), lp(nonce), lp(enc.encode(sessionId))]);
}

/**
 * The bytes an operator signs in a `ReverseProof`. With `features` (#318: the statements the operator makes about this bridge, in `SIGNABLE`)
 * the label is `wsh-operator-proof-v2` and the statements follow the session id, each length-prefixed, in sorted order; without, the
 * unchanged v1 bytes.
 */
export function proofTranscript({ peerPublicKey, operatorPublicKey, username, nonce, sessionId, features = [] }) {
  const base = [lp(peerPublicKey), lp(operatorPublicKey), lp(enc.encode(username)), lp(nonce), lp(enc.encode(sessionId))];
  if (!features.length) return concat([PROOF_LABEL, ...base]);
  return concat([PROOF_LABEL_V2, ...base, ...[...features].sort().map((f) => lp(enc.encode(f)))]);
}

async function verifyWith(rawKey, signature, data) {
  if (!isKey(rawKey) || !(signature instanceof Uint8Array) || signature.length !== 64) return false;
  try { return await verifyBytes(await importPublicKeyRaw(rawKey), signature, data); } catch { return false; }
}

/**
 * Peer side: make a challenge for the operator `operatorFingerprint` (as the relay stamped it).
 * @param {{ keyPair?: CryptoKeyPair, signer?: object }} identity - this peer's key
 * @param {string} operatorFingerprint
 * @returns {Promise<{ fields: object, nonce: Uint8Array, sessionId: string, peerPublicKey: Uint8Array }>}
 *   `fields` is what goes into `reverseChallenge({ targetFingerprint, ...fields })`
 */
export async function createReverseChallenge(identity, operatorFingerprint) {
  const signer = await resolveSigner(identity);
  if (!signer) throw new TypeError('createReverseChallenge: a keyPair or signer is required');
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const sessionId = crypto.randomUUID();
  const signature = await signer.sign(challengeTranscript({ peerPublicKey: signer.publicKeyRaw, operatorFingerprint, nonce, sessionId }));
  return {
    fields: { publicKey: signer.publicKeyRaw, operatorFingerprint, nonce, sessionId, signature },
    nonce, sessionId, peerPublicKey: signer.publicKeyRaw,
  };
}

/**
 * Operator side: check a `ReverseChallenge` and return the peer's identity, or throw.
 * @param {object} msg - the decoded message (snake_case)
 * @param {{ target: string, ownFingerprint: string }} expect - the peer fingerprint (or prefix) asked for; this operator's own
 * @returns {Promise<{ peerPublicKey: Uint8Array, peerFingerprint: string, nonce: Uint8Array, sessionId: string }>}
 */
export async function verifyReverseChallenge(msg, { target, ownFingerprint }) {
  const fail = (why) => Object.assign(new Error(`reverse challenge refused: ${why}`), { code: 'REVERSE_CHALLENGE_INVALID' });
  if (!isKey(msg.public_key) || !(msg.nonce instanceof Uint8Array) || msg.nonce.length !== NONCE_LENGTH || !str(msg.session_id) || !str(msg.operator_fingerprint)) throw fail('malformed');
  const peerFingerprint = await fingerprint(msg.public_key);
  if (typeof target !== 'string' || !target || !peerFingerprint.startsWith(target)) throw fail('the key that signed it is not the peer that was asked for');
  if (msg.operator_fingerprint !== ownFingerprint) throw fail('the peer saw a different operator fingerprint than this connection\'s (the relay rewrote it)');
  const ok = await verifyWith(msg.public_key, msg.signature, challengeTranscript({
    peerPublicKey: msg.public_key, operatorFingerprint: msg.operator_fingerprint, nonce: msg.nonce, sessionId: msg.session_id,
  }));
  if (!ok) throw fail('the signature does not verify');
  return { peerPublicKey: msg.public_key, peerFingerprint, nonce: msg.nonce, sessionId: msg.session_id };
}

/**
 * Operator side: answer a verified challenge.
 * @param {{ publicKeyRaw: Uint8Array, sign: (d: Uint8Array) => Promise<Uint8Array> }} signer - from `resolveSigner`
 * @returns {Promise<object>} fields for `reverseProof({ targetFingerprint, ...fields })`
 */
export async function createOperatorProof(signer, challenge, username, features = []) {
  if (!features.every((f) => SIGNABLE.includes(f))) throw new TypeError('createOperatorProof: a proof signs only the statements it knows');
  const signature = await signer.sign(proofTranscript({
    peerPublicKey: challenge.peerPublicKey, operatorPublicKey: signer.publicKeyRaw, username, nonce: challenge.nonce, sessionId: challenge.sessionId, features,
  }));
  return { publicKey: signer.publicKeyRaw, username, nonce: challenge.nonce, sessionId: challenge.sessionId, signature };
}

/**
 * Peer side: check a `ReverseProof` against the challenge it issued.
 * @param {object} msg - the decoded message
 * @param {{ nonce: Uint8Array, sessionId: string, peerPublicKey: Uint8Array }} issued
 * @returns {Promise<{ publicKey: Uint8Array, fingerprint: string, username: string } | null>} null when it does not verify
 */
export async function verifyOperatorProof(msg, issued) {
  if (!isKey(msg.public_key) || !str(msg.username, 64)) return null;
  const same = (a, b) => a instanceof Uint8Array && a.length === b.length && a.every((x, i) => x === b[i]);
  if (!same(msg.nonce, issued.nonce) || msg.session_id !== issued.sessionId) return null;
  // v1 (no statement signed), then v2 with each signable statement: `signedFeatures` is what the operator itself signed, whatever a relay did to
  // `ReverseConnect.features` (#318).
  const base = { peerPublicKey: issued.peerPublicKey, operatorPublicKey: msg.public_key, username: msg.username, nonce: issued.nonce, sessionId: issued.sessionId };
  let signedFeatures = null;
  if (await verifyWith(msg.public_key, msg.signature, proofTranscript(base))) signedFeatures = [];
  else if (await verifyWith(msg.public_key, msg.signature, proofTranscript({ ...base, features: SIGNABLE }))) signedFeatures = [...SIGNABLE];
  return signedFeatures ? { publicKey: msg.public_key, fingerprint: await fingerprint(msg.public_key), username: msg.username, signedFeatures } : null;
}

