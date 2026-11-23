/**
 * Server-side authentication for `@johnhenry/wsh/server`: an allowlist of
 * Ed25519 public keys (SSH `authorized_keys` style) and/or a custom callback.
 */

import { fingerprint } from '../auth.mjs';
import { parseAuthorizedKeyLine } from '../key-options.mjs';

/**
 * Parse an `authorized_keys`-style blob (one `[options] ssh-ed25519 AAAA... [comment]` per line; blank lines and `#` comments
 * ignored) into entries `{ key, options, permissions, line }` (raw 32-byte key, the raw options token or `null`, what the
 * options allow -- see `src/key-options.mjs` -- and the 1-based line number).
 *
 * A line this host cannot make sense of never yields a usable key: one whose options it does not understand is listed in
 * `refused` (`{ line, code, reason, key }`), and a malformed one or another key type is skipped. The same rules and vectors as
 * the Rust server's (`spec/key-options.vectors.json`).
 *
 * @param {string} text
 * @returns {{ entries: Array<{ key: Uint8Array, options: string | null, permissions: object, line: number }>, refused: Array<{ line: number, code: string, reason: string, key: Uint8Array }> }}
 */
export function parseAuthorizedKeyEntries(text) {
  const entries = [];
  const refused = [];
  String(text ?? '').split('\n').forEach((raw, i) => {
    const r = parseAuthorizedKeyLine(raw);
    if (r.refused) refused.push({ line: i + 1, ...r.refused, key: r.key });
    else if (r.key) entries.push({ key: r.key, options: r.options, permissions: r.permissions, line: i + 1 });
  });
  return { entries, refused };
}

/**
 * The raw 32-byte keys of the lines of an `authorized_keys`-style blob that carry NO options. A line with options is not
 * returned (its restrictions would be lost): use `parseAuthorizedKeyEntries` for those. Malformed lines are skipped.
 *
 * @param {string} text
 * @returns {Uint8Array[]}
 */
export function parseAuthorizedKeys(text) {
  return parseAuthorizedKeyEntries(text).entries.filter((e) => e.options === null).map((e) => e.key);
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
 * The function also carries `permissionsFor(fingerprint)`: what the key's `authorized_keys` options allow (`null` for a key
 * without options, a raw key, or a custom `authorize`: full access). A line whose options this host does not understand puts
 * no key on the list and is logged with its reason (`log`).
 *
 * @param {{ log?: (line: string) => void }} [opts]
 * @returns {Promise<((who: {username: string, fingerprint: string, publicKey: Uint8Array}) => Promise<boolean>) & { permissionsFor(fingerprint: string | null | undefined): object | null }>}
 */
export async function buildAuthorizer(auth, { log = () => {} } = {}) {
  /** @type {Map<string, object>} */
  const perms = new Map();
  const withPerms = (fn) => Object.assign(fn, { permissionsFor: (fp) => (fp ? perms.get(fp) ?? null : null) });
  if (typeof auth === 'function') return withPerms(async (who) => (await auth(who)) === true);
  if (!auth) return withPerms(async () => false);

  /** @type {Set<string> | null} */
  let allowed = null;
  if (auth.authorizedKeys !== undefined) {
    allowed = new Set();
    const items = Array.isArray(auth.authorizedKeys) ? auth.authorizedKeys : [auth.authorizedKeys];
    for (const item of items) {
      let list;
      if (typeof item === 'string') {
        const { entries, refused } = parseAuthorizedKeyEntries(item);
        for (const r of refused) log(`authorized_keys line ${r.line}: key refused (${r.code}): ${r.reason}`);
        list = entries;
      } else {
        list = [{ key: item, permissions: null }];
      }
      for (const { key: raw, permissions } of list) {
        if (!(raw instanceof Uint8Array) || raw.byteLength !== 32) {
          throw new TypeError('createWshServer: auth.authorizedKeys entries must be ssh-ed25519 lines or raw 32-byte Ed25519 keys');
        }
        const fp = await fingerprint(raw);
        // The first entry for a key decides what it may do, as on the Rust server.
        if (!allowed.has(fp) && permissions) perms.set(fp, permissions);
        allowed.add(fp);
      }
    }
  }
  const custom = typeof auth.authorize === 'function' ? auth.authorize : null;
  if (!allowed && !custom) return withPerms(async () => false);

  return withPerms(async (who) => {
    if (allowed && !allowed.has(who.fingerprint)) return false;
    if (custom) return (await custom(who)) === true;
    return true;
  });
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
