/**
 * Ed25519 key generation, signing, and verification via Web Crypto API.
 * Also builds authentication transcripts for the wsh challenge-response flow.
 */

import { PROTOCOL_VERSION } from './messages.mjs';

// ── Capability detection ──────────────────────────────────────────────

/** @type {Promise<boolean>|null} Memoized: the answer cannot change at runtime. */
let ed25519Support = null;

/**
 * Whether this runtime's WebCrypto implements Ed25519.
 *
 * There is deliberately no pure-JS fallback behind this. A JS
 * implementation needs the private scalar as ordinary bytes, which would
 * quietly give up the property `WshKeyStore` is built around -- keys are
 * non-extractable `CryptoKey` objects by default, so a compromised page
 * can use a key but cannot exfiltrate it. Trading that away on exactly
 * the oldest, least-patched engines is the wrong direction, and doing it
 * silently is worse. So wsh's floor is WebCrypto Ed25519, and this is how
 * an application asks about it before committing to pubkey auth:
 *
 * ```js
 * if (await isEd25519Supported()) {
 *   await client.connect(url, { username, keyPair });
 * } else {
 *   await client.connect(url, { username, password });   // AUTH_METHOD.PASSWORD
 * }
 * ```
 *
 * Measured directly rather than sniffed from a version string: `'Ed25519'`
 * is accepted as an algorithm name by some engines that then fail at
 * `generateKey`, so nothing short of generating a key is conclusive.
 *
 * @returns {Promise<boolean>}
 */
export async function isEd25519Supported() {
  if (ed25519Support === null) {
    ed25519Support = (async () => {
      try {
        await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
        return true;
      } catch {
        return false;
      }
    })();
  }
  return ed25519Support;
}

// ── Key Generation ────────────────────────────────────────────────────

/**
 * Generate a new Ed25519 key pair.
 *
 * Throws where WebCrypto has no Ed25519 -- see `isEd25519Supported()` for
 * why there is no fallback, and for how to check before you get here.
 *
 * @param {boolean} [extractable=false] - Whether private key can be exported
 * @returns {Promise<CryptoKeyPair>} { publicKey, privateKey }
 */
export async function generateKeyPair(extractable = false) {
  try {
    return await crypto.subtle.generateKey('Ed25519', extractable, ['sign', 'verify']);
  } catch (err) {
    // The platform's own message is typically "Unrecognized name" or a
    // bare "Type error", neither of which says which algorithm, which
    // library wanted it, or what a caller might do instead.
    throw new Error(
      'wsh requires WebCrypto Ed25519, which this runtime does not implement ' +
      '(Safari 17+, Chrome/Edge 137+, Firefox 130+, Node 20+). Check ' +
      'isEd25519Supported() first and fall back to password auth, or supply ' +
      `a CryptoKeyPair from elsewhere. (${err?.message || err})`,
      { cause: err }
    );
  }
}

// ── Export / Import ───────────────────────────────────────────────────

/**
 * Export public key as raw 32-byte Ed25519 point.
 * @param {CryptoKey} publicKey
 * @returns {Promise<Uint8Array>}
 */
export async function exportPublicKeyRaw(publicKey) {
  const buf = await crypto.subtle.exportKey('raw', publicKey);
  return new Uint8Array(buf);
}

/**
 * Export public key in SSH wire format: ssh-ed25519 AAAA...
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
export async function exportPublicKeySSH(publicKey) {
  const raw = await exportPublicKeyRaw(publicKey);
  const keyType = 'ssh-ed25519';
  const typeBytes = new TextEncoder().encode(keyType);

  // SSH wire format: [4-byte len][key type string][4-byte len][key data]
  const buf = new Uint8Array(4 + typeBytes.length + 4 + raw.length);
  const view = new DataView(buf.buffer);
  let offset = 0;

  view.setUint32(offset, typeBytes.length);
  offset += 4;
  buf.set(typeBytes, offset);
  offset += typeBytes.length;

  view.setUint32(offset, raw.length);
  offset += 4;
  buf.set(raw, offset);

  return `${keyType} ${base64Encode(buf)}`;
}

/**
 * Import a raw 32-byte Ed25519 public key.
 * @param {Uint8Array} raw
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKeyRaw(raw) {
  return crypto.subtle.importKey('raw', raw, 'Ed25519', true, ['verify']);
}

/**
 * Export private key as PKCS8 bytes.
 * @param {CryptoKey} privateKey - Must have been created with extractable=true
 * @returns {Promise<Uint8Array>}
 */
export async function exportPrivateKeyPKCS8(privateKey) {
  const buf = await crypto.subtle.exportKey('pkcs8', privateKey);
  return new Uint8Array(buf);
}

/**
 * Import a PKCS8-encoded Ed25519 private key.
 * @param {Uint8Array} pkcs8
 * @param {boolean} [extractable=false]
 * @returns {Promise<CryptoKey>}
 */
export async function importPrivateKeyPKCS8(pkcs8, extractable = false) {
  return crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', extractable, ['sign']);
}

// ── Signing / Verification ────────────────────────────────────────────

/**
 * Sign data with an Ed25519 private key.
 * @param {CryptoKey} privateKey
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>} 64-byte signature
 */
export async function sign(privateKey, data) {
  const sig = await crypto.subtle.sign('Ed25519', privateKey, data);
  return new Uint8Array(sig);
}

/**
 * Verify an Ed25519 signature.
 * @param {CryptoKey} publicKey
 * @param {Uint8Array} signature
 * @param {Uint8Array} data
 * @returns {Promise<boolean>}
 */
export async function verify(publicKey, signature, data) {
  return crypto.subtle.verify('Ed25519', publicKey, signature, data);
}

// ── Authentication Transcript ─────────────────────────────────────────

/**
 * Length-prefix a byte string with a 4-byte big-endian length, so two
 * variable-length fields concatenated in sequence can't collide (e.g.
 * username="ab", session="c" must hash differently from username="a",
 * session="bc").
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
function lengthPrefixed(bytes) {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

/**
 * Build the authentication transcript hash for challenge-response signing.
 *
 * transcript = SHA-256(
 *   "wsh-v1\0" || lp(username) || lp(session_id) || nonce || channel_binding
 * )
 *
 * `username` is bound so a signature produced for one username can't be
 * replayed/relabeled as another. `session_id` and `username` are each
 * length-prefixed (lp) since both are variable-length.
 *
 * `channelBinding` is reserved for a transport-layer identity binding (e.g.
 * a TLS exporter value) — no caller currently populates it. Note this is
 * NOT currently a binding to the *server's* identity: the protocol has no
 * server host-identity concept today (SERVER_HELLO.fingerprints lists
 * client keys the server authorizes, not the server's own key), and TLS
 * exporter values aren't obtainable from a browser WebSocket/WebTransport
 * client at all. See the wsh-modernization tracking issue for the
 * follow-up covering server host-identity + TOFU pinning.
 *
 * @param {string} sessionId
 * @param {Uint8Array} nonce - 32-byte server nonce
 * @param {object} [opts]
 * @param {string} [opts.username] - Username this transcript is bound to
 * @param {Uint8Array} [opts.channelBinding] - Optional transport-layer binding
 * @returns {Promise<Uint8Array>} 32-byte SHA-256 hash
 */
export async function buildTranscript(sessionId, nonce, { username = '', channelBinding = new Uint8Array(0) } = {}) {
  const enc = new TextEncoder();
  const versionBytes = enc.encode(PROTOCOL_VERSION + '\0');
  const usernameField = lengthPrefixed(enc.encode(username));
  const sessionField = lengthPrefixed(enc.encode(sessionId));

  const total = versionBytes.length + usernameField.length + sessionField.length
    + nonce.length + channelBinding.length;
  const data = new Uint8Array(total);
  let offset = 0;

  data.set(versionBytes, offset); offset += versionBytes.length;
  data.set(usernameField, offset); offset += usernameField.length;
  data.set(sessionField, offset); offset += sessionField.length;
  data.set(nonce, offset); offset += nonce.length;
  data.set(channelBinding, offset);

  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

/**
 * Perform the full client-side auth signing:
 * 1. Build transcript hash
 * 2. Sign with private key
 * 3. Export public key for sending to server
 *
 * @param {CryptoKey} privateKey
 * @param {CryptoKey} publicKey
 * @param {string} sessionId
 * @param {Uint8Array} nonce
 * @param {object} [opts]
 * @param {string} [opts.username]
 * @param {Uint8Array} [opts.channelBinding]
 * @returns {Promise<{ signature: Uint8Array, publicKeyRaw: Uint8Array }>}
 */
export async function signChallenge(privateKey, publicKey, sessionId, nonce, opts) {
  const transcript = await buildTranscript(sessionId, nonce, opts);
  const [signature, publicKeyRaw] = await Promise.all([
    sign(privateKey, transcript),
    exportPublicKeyRaw(publicKey),
  ]);
  return { signature, publicKeyRaw };
}

/**
 * Server-side: verify a client's challenge response.
 *
 * @param {CryptoKey} publicKey
 * @param {Uint8Array} signature
 * @param {string} sessionId
 * @param {Uint8Array} nonce
 * @param {object} [opts]
 * @param {string} [opts.username]
 * @param {Uint8Array} [opts.channelBinding]
 * @returns {Promise<boolean>}
 */
export async function verifyChallenge(publicKey, signature, sessionId, nonce, opts) {
  const transcript = await buildTranscript(sessionId, nonce, opts);
  return verify(publicKey, signature, transcript);
}

// ── Signed peer records (reverse-mode registration) ────────────────────
//
// libp2p RFC 0002/0003 signed-envelope pattern: a reverse peer signs its
// own registration fields with its identity key, so `ReversePeers`
// entries are verifiable by an operator independent of trusting the
// relay server -- a relay could otherwise misreport (or a malicious one
// forge) a peer's capabilities/type/backend, or replay a stale record
// after a legitimate update. `PEER_RECORD_DOMAIN` intentionally differs
// from the auth-challenge transcript's domain (`PROTOCOL_VERSION`
// above) even though both are typically signed by the same Ed25519
// identity key -- a signature produced for one context must never
// verify in the other.

const PEER_RECORD_DOMAIN = 'wsh-peer-record-v1\0';

/**
 * Build the signed transcript for a peer record.
 *
 * transcript = SHA-256(
 *   "wsh-peer-record-v1\0" || lp(username) || lp(peerType) ||
 *   lp(shellBackend) || lp(capabilities.join(',')) || flags(1 byte) ||
 *   seq(8 BE bytes)
 * )
 *
 * `capabilities` is joined and length-prefixed as a single field rather
 * than iterated element-by-element -- simpler, and sufficient since the
 * only thing that matters is that two different capability sets can't
 * hash identically (true as long as no capability name itself contains
 * the join separator in a way that creates ambiguity across the whole
 * *list*, which none of wsh's fixed capability strings do).
 *
 * @param {object} record
 * @param {string} record.username
 * @param {string} [record.peerType]
 * @param {string} [record.shellBackend]
 * @param {string[]} [record.capabilities]
 * @param {boolean} [record.supportsAttach]
 * @param {boolean} [record.supportsReplay]
 * @param {boolean} [record.supportsEcho]
 * @param {boolean} [record.supportsTermSync]
 * @param {number|bigint} record.seq - the signing peer's own monotonic
 *   counter (in practice, current-time-millis); a verifier must reject a
 *   record whose seq doesn't exceed the last one it accepted for that
 *   fingerprint.
 * @returns {Promise<Uint8Array>} 32-byte SHA-256 hash
 */
export async function buildPeerRecordTranscript(record) {
  const enc = new TextEncoder();
  const domainBytes = enc.encode(PEER_RECORD_DOMAIN);
  const usernameField = lengthPrefixed(enc.encode(record.username ?? ''));
  const peerTypeField = lengthPrefixed(enc.encode(record.peerType ?? 'host'));
  const shellBackendField = lengthPrefixed(enc.encode(record.shellBackend ?? 'pty'));
  const capsField = lengthPrefixed(enc.encode((record.capabilities ?? []).join(',')));
  const flags = new Uint8Array([
    (record.supportsAttach ? 1 : 0) |
    (record.supportsReplay ? 2 : 0) |
    (record.supportsEcho ? 4 : 0) |
    (record.supportsTermSync ? 8 : 0),
  ]);
  const seqBytes = new Uint8Array(8);
  new DataView(seqBytes.buffer).setBigUint64(0, BigInt(record.seq));

  const total = domainBytes.length + usernameField.length + peerTypeField.length
    + shellBackendField.length + capsField.length + flags.length + seqBytes.length;
  const data = new Uint8Array(total);
  let offset = 0;
  data.set(domainBytes, offset); offset += domainBytes.length;
  data.set(usernameField, offset); offset += usernameField.length;
  data.set(peerTypeField, offset); offset += peerTypeField.length;
  data.set(shellBackendField, offset); offset += shellBackendField.length;
  data.set(capsField, offset); offset += capsField.length;
  data.set(flags, offset); offset += flags.length;
  data.set(seqBytes, offset);

  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

/**
 * Client-side: sign a peer record with the identity key pair.
 * @param {CryptoKey} privateKey
 * @param {CryptoKey} publicKey
 * @param {object} record - see `buildPeerRecordTranscript`
 * @returns {Promise<{ signature: Uint8Array, publicKeyRaw: Uint8Array }>}
 */
export async function signPeerRecord(privateKey, publicKey, record) {
  const transcript = await buildPeerRecordTranscript(record);
  const [signature, publicKeyRaw] = await Promise.all([
    sign(privateKey, transcript),
    exportPublicKeyRaw(publicKey),
  ]);
  return { signature, publicKeyRaw };
}

/**
 * Verify a peer record's signature against the claimed record fields.
 * @param {CryptoKey} publicKey
 * @param {Uint8Array} signature
 * @param {object} record - see `buildPeerRecordTranscript`
 * @returns {Promise<boolean>}
 */
export async function verifyPeerRecord(publicKey, signature, record) {
  const transcript = await buildPeerRecordTranscript(record);
  return verify(publicKey, signature, transcript);
}

// ── Fingerprint ───────────────────────────────────────────────────────

/**
 * Compute the SHA-256 fingerprint of a raw public key.
 * @param {Uint8Array} publicKeyRaw - 32-byte raw Ed25519 public key
 * @returns {Promise<string>} hex-encoded fingerprint
 */
export async function fingerprint(publicKeyRaw) {
  const hash = await crypto.subtle.digest('SHA-256', publicKeyRaw);
  return hexEncode(new Uint8Array(hash));
}

/**
 * Compute the base64url-encoded SHA-256 pod ID of a raw public key.
 * This is the BrowserMesh identity format (43 chars).
 * @param {Uint8Array} publicKeyRaw - 32-byte raw Ed25519 public key
 * @returns {Promise<string>} base64url-encoded pod ID
 */
export async function podId(publicKeyRaw) {
  const hash = await crypto.subtle.digest('SHA-256', publicKeyRaw);
  return base64urlEncode(new Uint8Array(hash));
}

/**
 * Convert a hex fingerprint to a base64url pod ID.
 * @param {string} hexFingerprint - 64-char hex fingerprint
 * @returns {string} base64url pod ID
 */
export function fingerprintToPodId(hexFingerprint) {
  const bytes = new Uint8Array(hexFingerprint.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexFingerprint.slice(i * 2, i * 2 + 2), 16);
  }
  return base64urlEncode(bytes);
}

/**
 * Convert a base64url pod ID to a hex fingerprint.
 * @param {string} podIdStr - base64url pod ID
 * @returns {string} hex fingerprint
 */
export function podIdToFingerprint(podIdStr) {
  const bytes = base64urlDecode(podIdStr);
  return hexEncode(bytes);
}

/**
 * Get the shortest unique prefix of a fingerprint within a set.
 * @param {string} fp - Full hex fingerprint
 * @param {string[]} allFingerprints - All fingerprints in the context
 * @param {number} [minLen=4] - Minimum prefix length
 * @returns {string}
 */
export function shortFingerprint(fp, allFingerprints = [], minLen = 4) {
  const others = allFingerprints.filter(f => f !== fp);
  for (let len = minLen; len <= fp.length; len++) {
    const prefix = fp.slice(0, len);
    if (!others.some(f => f.startsWith(prefix))) return prefix;
  }
  return fp;
}

// ── Nonce ─────────────────────────────────────────────────────────────

/**
 * Generate a random 32-byte nonce.
 * @returns {Uint8Array}
 */
export function generateNonce() {
  return crypto.getRandomValues(new Uint8Array(32));
}

// ── Helpers ───────────────────────────────────────────────────────────

function hexEncode(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64urlEncode(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64Encode(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64Decode(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Parse an SSH public key string ("ssh-ed25519 AAAA... comment").
 * @param {string} line
 * @returns {{ type: string, data: Uint8Array, comment: string } | null}
 */
export function parseSSHPublicKey(line) {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 2) return null;
  const [type, b64, ...rest] = parts;
  if (type !== 'ssh-ed25519') return null;
  try {
    const data = base64Decode(b64);
    return { type, data, comment: rest.join(' ') };
  } catch {
    return null;
  }
}

/**
 * Extract the raw 32-byte Ed25519 public key from SSH wire format.
 * @param {Uint8Array} wireData - SSH wire-encoded public key
 * @returns {Uint8Array} 32-byte raw key
 */
export function extractRawFromSSHWire(wireData) {
  const view = new DataView(wireData.buffer, wireData.byteOffset, wireData.byteLength);
  // Skip key type string
  const typeLen = view.getUint32(0);
  const keyOffset = 4 + typeLen + 4;
  const keyLen = view.getUint32(4 + typeLen);
  return wireData.slice(keyOffset, keyOffset + keyLen);
}
