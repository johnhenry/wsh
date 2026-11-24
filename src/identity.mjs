/**
 * `@johnhenry/wsh/identity` -- a key's identity in its spellings, in one stable, browser-safe module (no Node import).
 *
 * One Ed25519 public key has these names:
 *
 *   raw key        the 32 bytes (`Uint8Array`), what WebCrypto exports as `'raw'`
 *   OpenSSH line   `ssh-ed25519 AAAAC3Nza... comment`: what `authorized_keys` and `ssh-keygen` write
 *   fingerprint    the SHA-256 of the raw key, 64 lower-case hex digits: what wsh logs, pins and passes to `authorize()`
 *   pod id         the same 32 bytes of SHA-256, as 43 characters of base64url: what BrowserMesh calls a pod
 *
 * The fingerprint and the pod id are two spellings of one hash (so they convert in both directions without the key), and both are
 * derived from the raw key (so they cannot be turned back into it). The OpenSSH line and the raw key are one value in two spellings.
 *
 * ```js
 * import { identityOf, authorizedKeyLine } from '@johnhenry/wsh/identity';
 * const { fingerprint, podId } = await identityOf('ssh-ed25519 AAAAC3Nza...');
 * const line = authorizedKeyLine(rawKey, { capabilities: ['objects:window:get'], expires: '2030-01-01T00:00:00Z', comment: 'mesh peer' });
 * ```
 *
 * Everything here refuses what is not exactly what it names (a key that is not 32 bytes, a fingerprint that is not a SHA-256, a line
 * that carries options or a second line) rather than convert it into something else.
 */

import { fingerprint, podId, exportPublicKeyRaw, base64Decode } from './auth.mjs';
import { fingerprintToPodId, podIdToFingerprint, normalizeIdentity } from './key-names.mjs';
import { grantPermissions, parseAuthorizedKeyLine, parseRfc3339 } from './key-options.mjs';

export { fingerprint, podId, fingerprintToPodId, podIdToFingerprint, normalizeIdentity };

const KEY_TYPE = 'ssh-ed25519';
const TYPE_BYTES = new TextEncoder().encode(KEY_TYPE);
const WIRE_LENGTH = 4 + TYPE_BYTES.length + 4 + 32;
// Anything that could end a line or start another: C0 and C1 controls, DEL, and the Unicode line and paragraph separators
// (written with their code points, so that no separator character sits in the source of a regular expression).
const LINE_BREAKING = new RegExp(`[\\u0000-\\u001f\\u007f-\\u009f${String.fromCharCode(0x2028)}${String.fromCharCode(0x2029)}]`);

const isRawKey = (raw) => raw instanceof Uint8Array && raw.byteLength === 32;

function base64(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function checkComment(comment, who) {
  if (comment === undefined || comment === '') return '';
  if (typeof comment !== 'string') throw new TypeError(`${who}: the comment must be a string`);
  if (LINE_BREAKING.test(comment)) throw new TypeError(`${who}: the comment may not contain a control character or a line break (it could start another line)`);
  return comment;
}

/**
 * The OpenSSH `ssh-ed25519` line of a raw public key.
 * @param {Uint8Array} raw exactly 32 bytes
 * @param {string} [comment] appended after the key; no control character or line break
 * @returns {string}
 */
export function rawKeyToOpenSsh(raw, comment) {
  if (!isRawKey(raw)) throw new TypeError('rawKeyToOpenSsh: expected a Uint8Array of exactly 32 bytes (an Ed25519 public key)');
  const note = checkComment(comment, 'rawKeyToOpenSsh');
  const wire = new Uint8Array(WIRE_LENGTH);
  const view = new DataView(wire.buffer);
  view.setUint32(0, TYPE_BYTES.length);
  wire.set(TYPE_BYTES, 4);
  view.setUint32(4 + TYPE_BYTES.length, 32);
  wire.set(raw, 8 + TYPE_BYTES.length);
  return `${KEY_TYPE} ${base64(wire)}${note ? ` ${note}` : ''}`;
}

/**
 * The OpenSSH line of a public `CryptoKey`.
 * @param {CryptoKey} publicKey an extractable Ed25519 public key
 * @param {string} [comment]
 * @returns {Promise<string>}
 */
export async function publicKeyToOpenSsh(publicKey, comment) {
  return rawKeyToOpenSsh(await exportPublicKeyRaw(publicKey), comment);
}

/**
 * Read an OpenSSH `ssh-ed25519` public key line: the raw key and the comment. Only a plain key is read: no options in front (those are
 * `authorized_keys` syntax, see `parseAuthorizedKeyLine`), no other key type, nothing after the 32 bytes of the key inside, one line.
 * @param {string} line `ssh-ed25519 <base64> [comment]`
 * @returns {{ raw: Uint8Array, comment: string }}
 */
export function parseOpenSshKey(line) {
  if (typeof line !== 'string') throw new TypeError('parseOpenSshKey: expected an ssh-ed25519 line');
  const text = line.endsWith('\n') ? line.slice(0, -1) : line;
  if (LINE_BREAKING.test(text)) throw new TypeError('parseOpenSshKey: expected one line with no control character');
  const m = /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: (.*))?$/.exec(text);
  if (!m) throw new TypeError('parseOpenSshKey: expected "ssh-ed25519 <base64> [comment]" (a key with options in front is an authorized_keys line, not a key)');
  let wire;
  try { wire = base64Decode(m[1]); } catch { throw new TypeError('parseOpenSshKey: the key is not base64'); }
  if (base64(wire) !== m[1]) throw new TypeError('parseOpenSshKey: the key is not in the canonical base64 spelling');
  if (wire.byteLength !== WIRE_LENGTH) throw new TypeError('parseOpenSshKey: not an Ed25519 key (the wire form of one is exactly 51 bytes)');
  const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
  const typeLength = view.getUint32(0);
  const typeOk = typeLength === TYPE_BYTES.length && TYPE_BYTES.every((b, i) => wire[4 + i] === b);
  if (!typeOk || view.getUint32(4 + TYPE_BYTES.length) !== 32) throw new TypeError('parseOpenSshKey: the key inside the line is not an ssh-ed25519 key');
  return { raw: wire.slice(8 + TYPE_BYTES.length), comment: m[2] ?? '' };
}

/**
 * The raw 32-byte public key of an OpenSSH `ssh-ed25519` line (what `parseOpenSshKey` reads; the comment is dropped).
 * @param {string} line
 * @returns {Uint8Array}
 */
export function openSshToRawKey(line) {
  return parseOpenSshKey(line).raw;
}

/**
 * One key in every spelling: `{ raw, fingerprint, podId, openssh }`.
 * @param {Uint8Array | string | CryptoKey} key a raw 32-byte key, an OpenSSH `ssh-ed25519` line, or a public `CryptoKey`
 * @returns {Promise<{ raw: Uint8Array, fingerprint: string, podId: string, openssh: string }>}
 */
export async function identityOf(key) {
  let raw;
  if (typeof key === 'string') raw = openSshToRawKey(key);
  else if (isRawKey(key)) raw = key.slice();
  else if (typeof CryptoKey !== 'undefined' && key instanceof CryptoKey) raw = await exportPublicKeyRaw(key);
  else throw new TypeError('identityOf: expected a raw 32-byte key, an ssh-ed25519 line or a public CryptoKey');
  const fp = await fingerprint(raw);
  return { raw, fingerprint: fp, podId: fingerprintToPodId(fp), openssh: rawKeyToOpenSsh(raw) };
}

const LINE_OPTIONS = new Set(['capabilities', 'expires', 'comment', 'allowFullAccess']);

/** `Date | epoch milliseconds | RFC 3339 string` as the canonical `YYYY-MM-DDTHH:MM:SSZ`, or a TypeError. */
function canonicalExpiry(expires) {
  let seconds = null;
  if (typeof expires === 'string') seconds = parseRfc3339(expires);
  else if (expires instanceof Date) seconds = Number.isFinite(expires.getTime()) ? Math.floor(expires.getTime() / 1000) : null;
  else if (typeof expires === 'number') seconds = Number.isFinite(expires) ? Math.floor(expires / 1000) : null;
  // The grammar starts in 1970, and the text of a timestamp holds four digits of year
  if (seconds === null || seconds < 0 || seconds > 253402300799) {
    throw new TypeError('authorizedKeyLine: expires must be an RFC 3339 timestamp such as 2030-01-01T00:00:00Z, a Date, or epoch milliseconds, between 1970 and 9999');
  }
  return new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
}

/**
 * A line for an `authorized_keys` file: `capabilities="..."[,expires="..."] ssh-ed25519 <key> [comment]`. Only what it is asked for
 * is written, and it refuses what could grant more:
 *
 * - `capabilities` is required: a line with no limits at all is a key that may do everything, so that is `allowFullAccess: true`
 *   said out loud (and then `capabilities` must not be given). `[]` is a key that may do nothing.
 * - every capability must be one this package's notation knows (`spec/capabilities.md`): an entry it does not understand, or one that
 *   carries a quote, a comma or whitespace, is refused, naming it, instead of being written for a host to refuse or misread;
 * - `expires` must be a timestamp and is written in UTC, `Z`;
 * - the key must be a plain Ed25519 key (raw bytes or a plain OpenSSH line; the options and the comment of an input line are not
 *   carried over); the comment may not hold a control character or line break;
 * - what it wrote is read back through the same parser a host uses, and must give the same capabilities, the same expiry and no other
 *   option; if not, it throws.
 *
 * @param {Uint8Array | string} key a raw 32-byte public key, or an OpenSSH `ssh-ed25519` line (use `publicKeyToOpenSsh` for a `CryptoKey`)
 * @param {{ capabilities?: string[] | string, expires?: string | Date | number, comment?: string, allowFullAccess?: boolean }} options
 * @returns {string} one line, no trailing newline
 */
export function authorizedKeyLine(key, options) {
  if (options === null || typeof options !== 'object') throw new TypeError('authorizedKeyLine: options { capabilities, expires, comment } are required');
  for (const name of Object.keys(options)) {
    if (!LINE_OPTIONS.has(name)) throw new TypeError(`authorizedKeyLine: unknown option ${JSON.stringify(name)} (this builder writes capabilities, expires and a comment)`);
  }
  const { capabilities, expires, comment, allowFullAccess = false } = options;
  if (allowFullAccess !== true && allowFullAccess !== false) throw new TypeError('authorizedKeyLine: allowFullAccess must be true or false');
  if (capabilities === undefined && !allowFullAccess) {
    throw new TypeError('authorizedKeyLine: capabilities are required (a key line with none may do everything): pass the list, [] for a key that may do nothing, or allowFullAccess: true');
  }
  if (capabilities !== undefined && allowFullAccess) throw new TypeError('authorizedKeyLine: allowFullAccess: true and a capabilities list contradict each other');
  const raw = isRawKey(key) ? key : (typeof key === 'string' ? parseOpenSshKey(key).raw : null);
  if (raw === null) throw new TypeError('authorizedKeyLine: key must be a raw 32-byte Ed25519 key or an ssh-ed25519 line');
  const note = checkComment(comment, 'authorizedKeyLine');
  const written = [];
  let list = null;
  if (capabilities !== undefined) {
    const granted = grantPermissions({ capabilities });
    if (!granted.ok) throw new TypeError(`authorizedKeyLine: ${granted.reason}`);
    list = granted.permissions.capabilities;
    written.push(`capabilities="${list.join(',')}"`);
  }
  const until = expires === undefined ? null : canonicalExpiry(expires);
  if (until !== null) written.push(`expires="${until}"`);
  const line = `${written.length ? `${written.join(',')} ` : ''}${rawKeyToOpenSsh(raw, note)}`;
  // Read it back as a host would.
  const back = parseAuthorizedKeyLine(line);
  const ok = back.permissions
    && back.key.byteLength === 32 && back.key.every((b, i) => b === raw[i])
    && JSON.stringify(back.permissions.capabilities) === JSON.stringify(list)
    && back.permissions.expires === (until === null ? null : parseRfc3339(until))
    && back.permissions.forcedCommand === null && back.permissions.maxSessions === null;
  if (!ok) throw new TypeError('authorizedKeyLine: the line it built does not read back as the grant that was asked for; refusing to write it');
  return line;
}
