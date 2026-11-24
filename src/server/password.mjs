/**
 * Password hashing for hosts that serve password logins (`auth.password`), on Node: scrypt from `node:crypto`,
 * stored as a PHC string (`$scrypt$ln=16,r=8,p=1$<salt>$<hash>`, unpadded standard base64) with a random per-user
 * salt, compared with `timingSafeEqual`. scrypt is memory-hard; it is what the Node entry point can do honestly
 * (WebCrypto has no argon2 and no scrypt, so this module is not part of the browser-safe entry points, and a host
 * running in a page keeps its own `auth.password` callback and its own choice of hash).
 *
 * The Rust `wsh-server` stores Argon2id; a hash written by one is not read by the other, and this is not meant to
 * make them interchangeable.
 */

import { scrypt as nodeScrypt, createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const DEFAULT_PARAMS = Object.freeze({ ln: 16, r: 8, p: 1 });
const SALT_BYTES = 16;
const KEY_BYTES = 32;
/** The most memory a stored hash may ask a login to spend (128 * N * r bytes): a hostile value in a file cannot exhaust the host. */
const MAX_MEMORY = 2 ** 28;

const defaultScrypt = (password, salt, keylen, opts) => new Promise((resolve, reject) => {
  nodeScrypt(password, salt, keylen, opts, (err, key) => (err ? reject(err) : resolve(key)));
});

const b64 = (buf) => Buffer.from(buf).toString('base64').replace(/=+$/, '');
const B64_RE = /^[A-Za-z0-9+/]+$/;
const unb64 = (s) => (typeof s === 'string' && B64_RE.test(s) ? Buffer.from(s, 'base64') : null);

function memoryFor({ ln, r }) { return 128 * (2 ** ln) * r; }

function scryptOptions({ ln, r, p }) {
  return { N: 2 ** ln, r, p, maxmem: memoryFor({ ln, r }) * 2 };
}

/**
 * Hash a password for storage.
 * @param {string} password
 * @param {{ ln?: number, r?: number, p?: number, scrypt?: Function }} [opts]  cost (`ln` is log2 of N); the default is
 *   ln=16, r=8, p=1 (64 MiB). `scrypt` replaces the derivation (tests).
 * @returns {Promise<string>}
 */
export async function hashPassword(password, opts = {}) {
  if (typeof password !== 'string' || password === '') throw new TypeError('hashPassword: a non-empty password string is required');
  const params = { ln: opts.ln ?? DEFAULT_PARAMS.ln, r: opts.r ?? DEFAULT_PARAMS.r, p: opts.p ?? DEFAULT_PARAMS.p };
  if (!validParams(params)) throw new RangeError('hashPassword: cost parameters out of range (ln 10-22, r 1-32, p 1-16, at most 256 MiB)');
  const salt = randomBytes(SALT_BYTES);
  const key = await (opts.scrypt ?? defaultScrypt)(password.normalize('NFKC'), salt, KEY_BYTES, scryptOptions(params));
  return `$scrypt$ln=${params.ln},r=${params.r},p=${params.p}$${b64(salt)}$${b64(key)}`;
}

function validParams({ ln, r, p }) {
  return Number.isInteger(ln) && ln >= 10 && ln <= 22 && Number.isInteger(r) && r >= 1 && r <= 32
    && Number.isInteger(p) && p >= 1 && p <= 16 && memoryFor({ ln, r }) <= MAX_MEMORY;
}

/** @returns {{ params: {ln:number,r:number,p:number}, salt: Buffer, hash: Buffer } | null} */
function parseHash(stored) {
  if (typeof stored !== 'string') return null;
  const parts = stored.split('$');
  if (parts.length !== 5 || parts[0] !== '' || parts[1] !== 'scrypt') return null;
  const m = /^ln=(\d{1,2}),r=(\d{1,2}),p=(\d{1,2})$/.exec(parts[2]);
  if (!m) return null;
  const params = { ln: Number(m[1]), r: Number(m[2]), p: Number(m[3]) };
  if (!validParams(params)) return null;
  const salt = unb64(parts[3]);
  const hash = unb64(parts[4]);
  if (!salt || !hash || salt.length < 8 || salt.length > 64 || hash.length !== KEY_BYTES) return null;
  return { params, salt, hash };
}

/**
 * Does `password` match a hash made by `hashPassword`? False for anything else, including a malformed or oversized
 * value; it never throws on the stored value.
 * @param {string} password
 * @param {string} stored
 * @param {{ scrypt?: Function }} [opts]
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(password, stored, opts = {}) {
  if (typeof password !== 'string') return false;
  const parsed = parseHash(stored);
  if (!parsed) return false;
  const key = await (opts.scrypt ?? defaultScrypt)(password.normalize('NFKC'), parsed.salt, KEY_BYTES, scryptOptions(parsed.params));
  return key.length === parsed.hash.length && timingSafeEqual(key, parsed.hash);
}

// Derived against a password nobody has, with the default cost, for a user the table does not know.
const DECOY_SALT = Buffer.from('wsh-decoy-salt!!');

/**
 * An `auth.password` callback over a table of stored hashes, in the same shape the Rust `wsh-server` serves: an
 * unknown user costs the same derivation as a wrong password (so neither the answer nor the time says which users
 * exist), the table is not consulted through the prototype chain, and an entry that is not a `hashPassword` hash is
 * refused with a warning that names the user (never the stored value).
 *
 * An old unsalted `sha256:<hex>` entry (one SHA-256 of the password: guessable offline at billions per second) is
 * refused, as the Rust server refuses it, unless `allowLegacySha256` is set; it then verifies, in constant time, with
 * a warning naming the user, and should be replaced with `hashPassword`'s output.
 *
 * @param {Record<string,string> | Map<string,string> | ((username: string) => string | undefined | Promise<string | undefined>)} hashes
 * @param {{ allowLegacySha256?: boolean, onWarn?: (message: string) => void, scrypt?: Function }} [opts]
 * @returns {(username: string, password: string) => Promise<boolean>}
 */
export function passwordVerifier(hashes, opts = {}) {
  const { allowLegacySha256 = false, onWarn = (m) => console.warn(m), scrypt = defaultScrypt } = opts;
  const lookup = typeof hashes === 'function' ? hashes
    : hashes instanceof Map ? (u) => hashes.get(u)
      : (u) => (hashes && Object.hasOwn(hashes, u) ? hashes[u] : undefined);
  const warned = new Set();
  const warnOnce = (user, text) => {
    const key = `${user}\0${text}`;
    if (warned.has(key)) return;
    warned.add(key);
    try { onWarn(text); } catch { /* a throwing logger must not decide a login */ }
  };
  const decoy = async (password) => {
    try { await scrypt(password.normalize('NFKC'), DECOY_SALT, KEY_BYTES, scryptOptions(DEFAULT_PARAMS)); } catch { /* the answer is false either way */ }
    return false;
  };

  return async (username, password) => {
    if (typeof username !== 'string' || typeof password !== 'string') return false;
    let stored;
    try { stored = await lookup(username); } catch { stored = undefined; }
    if (typeof stored !== 'string') return decoy(password);

    if (stored.startsWith('sha256:')) {
      const want = /^sha256:([0-9a-f]{64})$/i.exec(stored)?.[1];
      if (!allowLegacySha256 || !want) {
        warnOnce(username, `wsh: password hash for user "${username}" is an unsalted sha256 entry and is refused: replace it with the output of hashPassword() (or pass allowLegacySha256: true to passwordVerifier to keep it working for now)`);
        return decoy(password);
      }
      warnOnce(username, `wsh: password hash for user "${username}" is an unsalted sha256 entry; it is accepted because allowLegacySha256 is set. Replace it with the output of hashPassword()`);
      const got = createHash('sha256').update(password).digest();
      return timingSafeEqual(got, Buffer.from(want, 'hex'));
    }
    if (!parseHash(stored)) {
      warnOnce(username, `wsh: password hash for user "${username}" is not a hashPassword() value and is refused`);
      return decoy(password);
    }
    return verifyPassword(password, stored, { scrypt });
  };
}
