/**
 * Server-side authentication for `@johnhenry/wsh/server`: an allowlist of
 * Ed25519 public keys (SSH `authorized_keys` style) and/or a custom callback.
 */

import {
  parseSSHPublicKey, extractRawFromSSHWire, fingerprint,
} from '../auth.mjs';

/**
 * Parse an `authorized_keys`-style blob (one `ssh-ed25519 AAAA... [comment]`
 * per line; blank lines and `#` comments ignored) into raw 32-byte keys.
 * Malformed lines are skipped rather than failing the whole list.
 *
 * @param {string} text
 * @returns {Uint8Array[]}
 */
export function parseAuthorizedKeys(text) {
  const keys = [];
  for (const raw of String(text ?? '').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    try {
      const parsed = parseSSHPublicKey(line);
      keys.push(extractRawFromSSHWire(parsed.data));
    } catch {
      // skip malformed line
    }
  }
  return keys;
}

/**
 * Normalize the `auth` option into one `authorize()` function.
 *
 * `auth` is an `authorize` function itself, or an object with
 * `authorizedKeys` (a string of `ssh-ed25519` lines, a raw 32-byte
 * `Uint8Array`, or an array of either) and/or `authorize`. A key must be on
 * the list AND pass `authorize` (when both are given). With no `auth` at all
 * every connection is refused -- a server never defaults to open.
 *
 * @param {undefined | Function | {
 *   authorizedKeys?: string | Uint8Array | Array<string | Uint8Array>,
 *   authorize?: (who: {username: string, fingerprint: string, publicKey: Uint8Array}) => boolean | Promise<boolean>,
 * }} auth
 * @returns {Promise<(who: {username: string, fingerprint: string, publicKey: Uint8Array}) => Promise<boolean>>}
 */
export async function buildAuthorizer(auth) {
  if (typeof auth === 'function') return async (who) => (await auth(who)) === true;
  if (!auth) return async () => false;

  /** @type {Set<string> | null} */
  let allowed = null;
  if (auth.authorizedKeys !== undefined) {
    allowed = new Set();
    const items = Array.isArray(auth.authorizedKeys) ? auth.authorizedKeys : [auth.authorizedKeys];
    for (const item of items) {
      const raws = typeof item === 'string' ? parseAuthorizedKeys(item) : [item];
      for (const raw of raws) {
        if (!(raw instanceof Uint8Array) || raw.byteLength !== 32) {
          throw new TypeError('createWshServer: auth.authorizedKeys entries must be ssh-ed25519 lines or raw 32-byte Ed25519 keys');
        }
        allowed.add(await fingerprint(raw));
      }
    }
  }
  const custom = typeof auth.authorize === 'function' ? auth.authorize : null;
  if (!allowed && !custom) return async () => false;

  return async (who) => {
    if (allowed && !allowed.has(who.fingerprint)) return false;
    if (custom) return (await custom(who)) === true;
    return true;
  };
}

/**
 * Whether `auth` allows public-key login at all (an allowlist and/or an
 * `authorize` callback, or the function shorthand) and/or password login.
 *
 * @param {any} auth
 * @returns {{ pubkey: boolean, password: ((user: string, pass: string) => boolean | Promise<boolean>) | null }}
 */
export function authMethods(auth) {
  if (typeof auth === 'function') return { pubkey: true, password: null };
  if (!auth) return { pubkey: false, password: null };
  if (auth.password !== undefined && typeof auth.password !== 'function') {
    throw new TypeError('createWshServer: auth.password must be a function (user, pass) => boolean | Promise<boolean>');
  }
  return {
    pubkey: auth.authorizedKeys !== undefined || typeof auth.authorize === 'function',
    password: auth.password ?? null,
  };
}

/**
 * Failure throttle for password logins, keyed (by default) on the peer's
 * address. After `maxFailures` failures inside `windowMs` the key is locked
 * for `lockoutMs`, during which the password callback is not even called.
 * A success clears the key. In-memory and per-process, by design.
 */
export class FailureLimiter {
  #entries = new Map();
  #now;
  constructor({ maxFailures = 5, windowMs = 60_000, lockoutMs = 60_000, now = Date.now } = {}) {
    this.maxFailures = maxFailures;
    this.windowMs = windowMs;
    this.lockoutMs = lockoutMs;
    this.#now = now;
  }

  /** @returns {number} ms the key is still locked out (0 = free to try) */
  lockedFor(key) {
    const e = this.#entries.get(key);
    if (!e) return 0;
    const t = this.#now();
    if (e.lockedUntil > t) return e.lockedUntil - t;
    if (t - e.first > this.windowMs) this.#entries.delete(key);
    return 0;
  }

  fail(key) {
    const t = this.#now();
    let e = this.#entries.get(key);
    if (!e || t - e.first > this.windowMs) { e = { count: 0, first: t, lockedUntil: 0 }; this.#entries.set(key, e); }
    e.count++;
    if (e.count >= this.maxFailures) e.lockedUntil = t + this.lockoutMs;
    if (this.#entries.size > 10_000) this.#entries.delete(this.#entries.keys().next().value);
  }

  succeed(key) { this.#entries.delete(key); }
}
