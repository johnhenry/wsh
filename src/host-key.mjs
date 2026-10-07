/**
 * Host-key identity for wsh (TOFU / pinning). Browser-safe, shared by the stock
 * client and `@johnhenry/wsh/server`.
 *
 * ## Wire shape (an extension carried in existing frames)
 *
 * The wsh-v1 spec has `ServerHello.host_fingerprint` (SHA-256 of the host's
 * Ed25519 key) but no field for the key itself and no proof the server holds
 * it -- a bare fingerprint can be replayed by anyone. Rather than change the
 * spec, the proof rides in the negotiable `features` string lists:
 *
 *  - client -> server, in `Hello.features`:  `host-key-nonce:<hex>`   (fresh, 16 bytes)
 *  - server -> client, in `ServerHello.features`:
 *      `host-key:<hex>`      the raw 32-byte Ed25519 host public key
 *      `host-key-sig:<hex>`  Ed25519 signature over the proof message below
 *    and `ServerHello.host_fingerprint` = fingerprint of that key.
 *
 * Proof message = `"wsh-host-key-proof-v1" 0x00 session_id 0x00 client_nonce 0x00 username`.
 * The client's fresh nonce makes the proof unreplayable; the session id binds
 * it to this ServerHello. It is checked BEFORE any credential is sent, so a
 * password never goes to a host that fails its pin. Peers that don't know the
 * strings ignore them, so nothing breaks against other implementations.
 *
 * Limit: the proof authenticates the ServerHello, not the byte stream -- on a
 * plain `ws://` link an active attacker can relay a genuine ServerHello and
 * then read/alter the rest. Pinning protects you from talking to the WRONG
 * host; confidentiality still needs `wss://`/WebTransport (or a trusted LAN).
 */

export const HOST_KEY_NONCE_PREFIX = 'host-key-nonce:';
export const HOST_KEY_PREFIX = 'host-key:';
export const HOST_KEY_SIG_PREFIX = 'host-key-sig:';
const PROOF_TAG = 'wsh-host-key-proof-v1';

const enc = new TextEncoder();

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new Error('invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** A refused host key. `code` is one of the `HOST_KEY_*` values below. */
export class HostKeyError extends Error {
  /**
   * @param {'HOST_KEY_MISSING'|'HOST_KEY_INVALID'|'HOST_KEY_MISMATCH'|'HOST_KEY_UNKNOWN'|'HOST_KEY_REJECTED'} code
   * @param {string} message
   * @param {object} [details]
   */
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'HostKeyError';
    this.code = code;
    Object.assign(this, details);
  }
}

/** Fresh client nonce, hex. */
export function newHostKeyNonce() {
  return toHex(crypto.getRandomValues(new Uint8Array(16)));
}

/** Bytes the host signs / the client verifies. */
export function hostKeyProofMessage({ sessionId, clientNonce, username }) {
  return enc.encode(`${PROOF_TAG}\0${sessionId}\0`
    + `${typeof clientNonce === 'string' ? clientNonce : toHex(clientNonce)}\0${username}`);
}

/** Pull the client nonce out of `Hello.features` (server side). Null when absent or malformed. */
export function findClientNonce(features) {
  for (const f of Array.isArray(features) ? features : []) {
    if (typeof f === 'string' && f.startsWith(HOST_KEY_NONCE_PREFIX)) {
      const hex = f.slice(HOST_KEY_NONCE_PREFIX.length);
      if (/^[0-9a-f]{32,128}$/i.test(hex)) return hex.toLowerCase();
    }
  }
  return null;
}

/** Pull the advertised key + signature out of `ServerHello.features` (client side). */
export function findHostKeyAdvert(features) {
  let key = null;
  let sig = null;
  for (const f of Array.isArray(features) ? features : []) {
    if (typeof f !== 'string') continue;
    try {
      if (f.startsWith(HOST_KEY_SIG_PREFIX)) sig = fromHex(f.slice(HOST_KEY_SIG_PREFIX.length));
      else if (f.startsWith(HOST_KEY_PREFIX)) key = fromHex(f.slice(HOST_KEY_PREFIX.length));
    } catch { /* malformed -> treated as absent, then refused as INVALID by the caller */ }
  }
  return key || sig ? { key, sig } : null;
}
