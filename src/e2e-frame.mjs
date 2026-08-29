/**
 * EncryptedFrame sealing/opening for wsh's opt-in end-to-end encryption
 * layer (see `client.mjs`'s `initiateE2E`, which derives the AES-256-GCM
 * `CryptoKey` this module seals/opens with, and `spec/wsh-v1.yaml`'s
 * `EncryptedFrame` message).
 *
 * This is PR 1 of a multi-PR E2E rollout: it implements the AEAD
 * primitives and wires them into virtual-mode sessions only (see
 * `session.mjs`'s `enableE2E`). Stream-mode sessions (raw WebTransport
 * byte streams with no message boundaries) are explicitly out of scope
 * here -- they need separate ad hoc chunk-framing design.
 *
 * ── Nonce construction ─────────────────────────────────────────────
 * Nonces are the AES-GCM-mandated 96 bits (12 bytes), built as:
 *
 *   [ 8-byte big-endian monotonic counter ][ 4-byte sender-role tag ]
 *
 * The counter starts at 0 and increments by one for every frame a given
 * sender seals (never reused, per `openFrame`'s strict expected-counter
 * check below). The 4-byte role tag is fixed per sender for the
 * lifetime of one E2E-enabled connection (see `session.mjs`'s
 * `enableE2E({ role })`) and differs between the two peers of a
 * session, so the two directions of one session structurally cannot
 * produce a colliding nonce even under fully concurrent bidirectional
 * traffic -- the 8-byte counter alone would collide if both sides ever
 * reached the same count, but the two peers' tags never match, so the
 * full 12-byte nonces never match either.
 *
 * ── AAD ────────────────────────────────────────────────────────────
 * The frame's `session_id` (UTF-8 bytes) is bound as AES-GCM
 * "additional authenticated data": it's authenticated but never
 * encrypted, so ciphertext can't be spliced from one session onto
 * another by a relay that only ever sees ciphertext (the server, for a
 * genuinely E2E session) -- decryption fails if the session_id supplied
 * to `openFrame` doesn't match the one the ciphertext was sealed under.
 *
 * ── Replay/reorder protection ─────────────────────────────────────
 * `openFrame` requires the frame's nonce counter to be *exactly* the
 * caller-supplied `expectedCounter` -- not merely "not yet seen" or
 * "not too old". This is intentionally strict for v1: any replayed,
 * duplicated, dropped, or reordered frame is rejected outright rather
 * than tolerated or reordered-and-delivered. A later PR can relax this
 * to a sliding window if wsh ever needs to tolerate out-of-order
 * delivery for E2E frames; today's virtual-mode transport already
 * delivers control messages in order, so strict-next-counter is not a
 * practical limitation.
 *
 * ── Key lifetime ───────────────────────────────────────────────────
 * The `key` passed to `sealFrame`/`openFrame` is connection-scoped, not
 * session-scoped: a session that is detached and later Resumed/Attached
 * on a new connection MUST run a fresh `initiateE2E()` and call
 * `enableE2E()` again with the new key. Never persist or reuse a
 * `sharedSecret` (or its counters) across a resume -- see
 * `session.mjs`'s `enableE2E` doc comment.
 */

const NONCE_LENGTH = 12;
const COUNTER_LENGTH = 8;
const ROLE_TAG_LENGTH = 4;

const textEncoder = new TextEncoder();

/**
 * Encode a non-negative integer counter as an 8-byte big-endian value.
 * @param {number} counter
 * @returns {Uint8Array}
 */
function encodeCounter(counter) {
  if (!Number.isInteger(counter) || counter < 0) {
    throw new Error(`e2e-frame: counter must be a non-negative integer, got ${counter}`);
  }
  const bytes = new Uint8Array(COUNTER_LENGTH);
  const view = new DataView(bytes.buffer);
  // DataView.setBigUint64 covers the full 64-bit range; counters here
  // never realistically approach it, but there's no reason to cap early.
  view.setBigUint64(0, BigInt(counter), false);
  return bytes;
}

/**
 * Build the 12-byte nonce for a given (counter, role tag) pair. Exported
 * mainly for tests -- callers should go through `sealFrame`/`openFrame`.
 *
 * @param {number} counter
 * @param {Uint8Array} roleTag - exactly 4 bytes
 * @returns {Uint8Array}
 */
export function buildNonce(counter, roleTag) {
  if (!(roleTag instanceof Uint8Array) || roleTag.length !== ROLE_TAG_LENGTH) {
    throw new Error(`e2e-frame: roleTag must be a ${ROLE_TAG_LENGTH}-byte Uint8Array`);
  }
  const nonce = new Uint8Array(NONCE_LENGTH);
  nonce.set(encodeCounter(counter), 0);
  nonce.set(roleTag, COUNTER_LENGTH);
  return nonce;
}

/**
 * Seal a plaintext frame under an AES-256-GCM key.
 *
 * @param {CryptoKey} key - non-extractable AES-GCM CryptoKey (e.g. from `client.mjs`'s `initiateE2E`)
 * @param {string} sessionId - bound as AAD
 * @param {Uint8Array} roleTag - 4-byte sender role tag, distinct between the two peers of a session
 * @param {number} counter - this sender's next monotonic send counter (0, 1, 2, ...)
 * @param {Uint8Array} plaintext
 * @returns {Promise<{nonce: Uint8Array, ciphertext: Uint8Array}>}
 */
export async function sealFrame(key, sessionId, roleTag, counter, plaintext) {
  if (!key || typeof key !== 'object') {
    throw new Error('e2e-frame: sealFrame requires a CryptoKey');
  }
  const nonce = buildNonce(counter, roleTag);
  const aad = textEncoder.encode(sessionId);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad },
    key,
    plaintext
  ));
  return { nonce, ciphertext };
}

/**
 * Open (decrypt + authenticate) a sealed frame.
 *
 * Throws if:
 *  - the AEAD authentication tag doesn't verify (tampered ciphertext,
 *    wrong key, or `sessionId` mismatch since it's bound as AAD), or
 *  - the frame's nonce counter isn't exactly `expectedCounter` (replay,
 *    reorder, or drop -- see this module's doc comment).
 *
 * @param {CryptoKey} key
 * @param {string} sessionId - must match what the frame was sealed with (bound as AAD)
 * @param {number} expectedCounter - the exact next counter this peer expects from the sender
 * @param {{nonce: Uint8Array, ciphertext: Uint8Array}} frame
 * @returns {Promise<Uint8Array>} plaintext
 */
export async function openFrame(key, sessionId, expectedCounter, { nonce, ciphertext }) {
  if (!key || typeof key !== 'object') {
    throw new Error('e2e-frame: openFrame requires a CryptoKey');
  }
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_LENGTH) {
    throw new Error(`e2e-frame: nonce must be a ${NONCE_LENGTH}-byte Uint8Array`);
  }
  const actualCounter = Number(new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength).getBigUint64(0, false));
  if (actualCounter !== expectedCounter) {
    throw new Error(
      `e2e-frame: replay/reorder detected -- expected counter ${expectedCounter}, got ${actualCounter}`
    );
  }
  const aad = textEncoder.encode(sessionId);
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      key,
      ciphertext
    ));
  } catch (err) {
    throw new Error(`e2e-frame: authentication failed while opening frame (${err.message})`);
  }
}

export const E2E_NONCE_LENGTH = NONCE_LENGTH;
export const E2E_ROLE_TAG_LENGTH = ROLE_TAG_LENGTH;

/**
 * Deterministic 4-byte role tags for the two sides of one E2E-enabled
 * connection. Callers pick a role at `enableE2E()` time -- 'initiator'
 * is naturally the side that called `initiateE2E()` first / sent round-1
 * KeyExchange, 'responder' the other side; any consistent, non-
 * overlapping assignment works since these are just fixed structural
 * tags, not secret values.
 * @type {Record<'initiator'|'responder', Uint8Array>}
 */
export const ROLE_TAGS = Object.freeze({
  initiator: Uint8Array.from([0x69, 0x6e, 0x69, 0x74]), // "init"
  responder: Uint8Array.from([0x72, 0x65, 0x73, 0x70]), // "resp"
});
