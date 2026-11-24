/**
 * The two names of a key's hash, and the caller identity built from them. Pure functions of strings: no crypto, no Node import, so the
 * object layer, the MCP layer and `@johnhenry/wsh/identity` can all use them without pulling in the key code.
 *
 * A key is named by the SHA-256 of its raw 32-byte Ed25519 public key. wsh writes the 32 bytes as 64 lower-case hex digits (the
 * "fingerprint"); BrowserMesh writes the same 32 bytes as 43 characters of base64url (the "pod id"). They are one name in two
 * spellings, and these functions convert between them and refuse anything that is not exactly such a hash.
 */

const HEX_RE = /^[0-9a-fA-F]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]{43}$/;
const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** @param {string} hex 64 hex digits @returns {string} the 43-character base64url spelling of the same 32 bytes */
function hexToBase64url(hex) {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < hex.length; i += 2) {
    acc = (acc << 8) | parseInt(hex.slice(i, i + 2), 16);
    bits += 8;
    while (bits >= 6) { bits -= 6; out += B64URL_ALPHABET[(acc >> bits) & 63]; }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B64URL_ALPHABET[(acc << (6 - bits)) & 63];
  return out;
}

/** @param {string} id 43 base64url characters @returns {string | null} 64 lower-case hex digits, or null when the last character has bits a 32-byte value cannot have */
function base64urlToHex(id) {
  let hex = '';
  let acc = 0;
  let bits = 0;
  for (const ch of id) {
    acc = (acc << 6) | B64URL_ALPHABET.indexOf(ch);
    bits += 6;
    if (bits >= 8) { bits -= 8; hex += ((acc >> bits) & 255).toString(16).padStart(2, '0'); acc &= (1 << bits) - 1; }
  }
  // 43 characters are 258 bits: the last two must be zero, or two different ids would name the same key
  return acc === 0 ? hex : null;
}

/**
 * Convert a hex fingerprint to a base64url pod id.
 * @param {string} hexFingerprint exactly 64 hex digits (either case): the SHA-256 of a raw public key
 * @returns {string} the 43-character base64url pod id
 */
export function fingerprintToPodId(hexFingerprint) {
  if (typeof hexFingerprint !== 'string' || !HEX_RE.test(hexFingerprint)) {
    throw new TypeError('fingerprintToPodId: expected a fingerprint of exactly 64 hex digits (the SHA-256 of a public key)');
  }
  return hexToBase64url(hexFingerprint.toLowerCase());
}

/**
 * Convert a base64url pod id to a hex fingerprint.
 * @param {string} podIdStr exactly 43 base64url characters (no padding), in the canonical spelling
 * @returns {string} 64 lower-case hex digits
 */
export function podIdToFingerprint(podIdStr) {
  const hex = typeof podIdStr === 'string' && B64URL_RE.test(podIdStr) ? base64urlToHex(podIdStr) : null;
  if (hex === null) throw new TypeError('podIdToFingerprint: expected a pod id of exactly 43 base64url characters (the SHA-256 of a public key)');
  return hex;
}

/**
 * Who a call is from, in the one shape every layer of the package uses: `{ username, fingerprint, podId }`. A caller that arrives over
 * wsh has a login name and a key (the hex `fingerprint`); one that arrives over a mesh has a pod id. Both are the hash of the same
 * kind of key, so whichever is given, the other is derived: an `authorize(who, op)` callback written for one world reads the other's
 * callers the same way, and nobody has to put a pod id in a field named `fingerprint`.
 *
 * An identity that names two different keys, or whose `podId` is not a pod id, is refused. A caller with no key (a password login)
 * has `fingerprint: null` and `podId: null`.
 *
 * @param {{ username?: string | null, fingerprint?: string | null, podId?: string | null } | null | undefined} who
 * @param {{ strict?: boolean, derivePodId?: boolean }} [options] `strict: false` keeps a `fingerprint` that is not a key hash as it was
 *   given (a host may name its callers some other way) and derives no pod id from it; the default refuses it. `derivePodId: false`
 *   derives no pod id from a fingerprint (a `podId` that was given is kept, and always gives the fingerprint): what the object and MCP
 *   layers use, so a caller that came in over wsh keeps the `{ username, fingerprint }` it always had.
 * @returns {{ username: string | null, fingerprint: string | null, podId: string | null }}
 */
export function normalizeIdentity(who, { strict = true, derivePodId = true } = {}) {
  if (who === null || who === undefined) return { username: null, fingerprint: null, podId: null };
  if (typeof who !== 'object' || Array.isArray(who)) throw new TypeError('an identity is an object { username, fingerprint, podId }');
  const { username = null, fingerprint = null, podId = null } = who;
  if (username !== null && typeof username !== 'string') throw new TypeError('identity.username must be a string or null');
  if (fingerprint !== null && typeof fingerprint !== 'string') throw new TypeError('identity.fingerprint must be a string or null');
  if (podId !== null && typeof podId !== 'string') throw new TypeError('identity.podId must be a string or null');
  let fp = fingerprint === null ? null : (HEX_RE.test(fingerprint) ? fingerprint.toLowerCase() : fingerprint);
  if (fp !== null && !HEX_RE.test(fp) && strict) throw new TypeError('identity.fingerprint must be 64 hex digits (the SHA-256 of a public key)');
  let id = podId;
  if (id !== null) {
    const fromId = podIdToFingerprint(id); // throws for something that is not a pod id
    if (fp !== null && HEX_RE.test(fp) && fp !== fromId) throw new TypeError('identity.fingerprint and identity.podId name different keys');
    if (fp !== null && !HEX_RE.test(fp)) throw new TypeError('identity.fingerprint and identity.podId name different keys');
    fp = fromId;
  } else if (derivePodId && fp !== null && HEX_RE.test(fp)) {
    id = fingerprintToPodId(fp);
  }
  return { username, fingerprint: fp, podId: id };
}

/**
 * The identity a layer hands to `authorize(who, op)`, a prompt or an `onCall` callback: what it was given, with `fingerprint` and (when
 * the transport knows it) `podId` agreeing. A caller that arrived over wsh keeps its old shape `{ username, fingerprint }`; one that
 * arrived with only a `podId` (a mesh adapter) also gets the hex `fingerprint`. Extra fields the transport put on it are kept.
 * `undefined` stays `undefined` (no identity given).
 * @param {object | undefined} who
 * @returns {{ username: string | null, fingerprint: string | null, podId?: string } | undefined}
 */
export function callerIdentity(who) {
  if (who === undefined) return undefined;
  const n = normalizeIdentity(who, { strict: false, derivePodId: false });
  return { ...who, username: n.username, fingerprint: n.fingerprint, ...(n.podId !== null ? { podId: n.podId } : {}) };
}
