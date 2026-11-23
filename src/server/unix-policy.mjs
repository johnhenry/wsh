/**
 * Which unix-domain socket paths may a client reach on (or create on) the host? Default deny: nothing unless the
 * operator listed it. Node only (it touches the file system); loaded lazily by the gateway so the browser-safe
 * memory host never imports it.
 *
 * A pattern is an absolute path, exact (`/var/run/docker.sock`) or a directory prefix with a trailing slash
 * (`/run/user/1000/wsh/`), or, for the Linux abstract namespace, `@name` / `@prefix/`. A requested path is accepted
 * only when, AFTER the parent directory has been resolved with `realpath`, it equals an exact pattern or lies under
 * a prefix (patterns are resolved the same way, so `/var/run` and `/private/var/run` agree). The file itself must
 * be a socket and not a symlink. A `..` segment is refused outright. This closes the "allowed directory contains a
 * symlink to somewhere else" escape; it cannot close the window between the check and the connect (the path is
 * connected by its resolved name, which narrows it), so allow only directories no other local user can write to.
 */

import path from 'node:path';

let fsp = null;
const loadFs = async () => (fsp ??= (await import('node:fs/promises')).default);

export const ABSTRACT_PREFIX = '@';
const MAX_PATH = 4096;

/** @param {string[] | undefined} list @param {string} what */
function checkPatterns(list, what) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.some((p) => typeof p !== 'string' || !p)) throw new TypeError(`gateway.unix.${what} must be an array of non-empty strings`);
  for (const p of list) {
    if (p.includes('\0') || p.length > MAX_PATH) throw new TypeError(`gateway.unix.${what}: bad pattern ${JSON.stringify(p.slice(0, 80))}`);
    if (!p.startsWith('/') && !p.startsWith(ABSTRACT_PREFIX)) throw new TypeError(`gateway.unix.${what}: ${JSON.stringify(p)} must be an absolute path or an abstract name starting with "@"`);
    if (p === '/' || p === ABSTRACT_PREFIX || p === `${ABSTRACT_PREFIX}/`) throw new TypeError(`gateway.unix.${what}: ${JSON.stringify(p)} would allow everything; list a specific path or directory`);
    if (p.split('/').includes('..')) throw new TypeError(`gateway.unix.${what}: ${JSON.stringify(p)} must not contain ".."`);
  }
  return [...list];
}

/**
 * @param {object} [opts]
 * @param {string[]} [opts.connect] sockets a client may connect to (`OpenUnix`)
 * @param {string[]} [opts.listen] sockets a client may ask the host to create (`ListenUnix`)
 * @param {boolean} [opts.replaceStale=false] a client may ask to replace a stale socket file (OpenSSH `StreamLocalBindUnlink`)
 * @param {number} [opts.maxListeners=4] unix listeners per client connection
 */
export function normalizeUnixPolicy(opts) {
  if (opts === undefined || opts === null || opts === false) return null;
  if (opts === true || typeof opts !== 'object') throw new TypeError('gateway.unix needs explicit paths (default deny): { connect: [...], listen: [...] }');
  const maxListeners = opts.maxListeners ?? 4;
  if (!Number.isInteger(maxListeners) || maxListeners < 0) throw new TypeError('gateway.unix.maxListeners must be a non-negative integer');
  return {
    connect: checkPatterns(opts.connect, 'connect'),
    listen: checkPatterns(opts.listen, 'listen'),
    replaceStale: opts.replaceStale === true,
    maxListeners,
  };
}

/** Is `target` the pattern, or under it (prefix patterns end with "/")? Both already resolved. */
function matches(pattern, target) {
  return pattern.endsWith('/') ? target.startsWith(pattern) : target === pattern;
}

/** The pattern as the file system sees it today: its parent (or itself, for a prefix) through realpath. */
async function resolvePattern(p) {
  const fs = await loadFs();
  try {
    if (p.endsWith('/')) return `${(await fs.realpath(p)).replace(/\/+$/, '')}/`;
    return path.join(await fs.realpath(path.dirname(p)), path.basename(p));
  } catch { return null; } // a pattern whose directory does not exist matches nothing
}

/**
 * @param {string} requested what the client sent
 * @param {string[]} patterns
 * @returns {Promise<{ ok: true, abstract: boolean, path: string } | { ok: false, reason: string }>}
 *   `path` is what to connect to or bind: the resolved path, or `\0name` for an abstract socket.
 */
export async function checkUnixPath(requested, patterns) {
  if (typeof requested !== 'string' || !requested || requested.length > MAX_PATH || requested.indexOf('\0', 1) !== -1) return { ok: false, reason: 'malformed path' };
  // Abstract namespace: refused unless a pattern lists it; there is no file system to resolve.
  if (requested.startsWith(ABSTRACT_PREFIX) || requested.startsWith('\0')) {
    const name = ABSTRACT_PREFIX + requested.slice(1);
    if (name.length < 2) return { ok: false, reason: 'malformed path' };
    if (name.split('/').includes('..')) return { ok: false, reason: 'malformed path' };
    const listed = patterns.some((p) => p.startsWith(ABSTRACT_PREFIX) && matches(p, name));
    return listed ? { ok: true, abstract: true, path: `\0${name.slice(1)}` } : { ok: false, reason: 'path not allowed by the gateway policy' };
  }
  if (!requested.startsWith('/') || requested.split('/').includes('..')) return { ok: false, reason: 'path must be absolute and without ".."' };
  const base = path.basename(requested);
  if (!base || base === '.' || base === '..' || requested.endsWith('/')) return { ok: false, reason: 'malformed path' };
  const fs = await loadFs();
  let resolved;
  try { resolved = path.join(await fs.realpath(path.dirname(requested)), base); } catch { return { ok: false, reason: 'path not allowed by the gateway policy' }; }
  for (const p of patterns) {
    if (p.startsWith(ABSTRACT_PREFIX)) continue;
    const rp = await resolvePattern(p);
    if (rp && matches(rp, resolved)) return { ok: true, abstract: false, path: resolved };
  }
  return { ok: false, reason: 'path not allowed by the gateway policy' };
}

/** `lstat` of an allowed path: `null` when absent, else `{ socket, ino, dev }` (a symlink is never a socket here). */
export async function statSocket(p) {
  const fs = await loadFs();
  try {
    const st = await fs.lstat(p);
    return { socket: st.isSocket(), ino: st.ino, dev: st.dev };
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

export async function unlinkIfSocket(p, expect) {
  const fs = await loadFs();
  try {
    const st = await fs.lstat(p);
    if (!st.isSocket()) return;
    if (expect && (st.ino !== expect.ino || st.dev !== expect.dev)) return; // someone else's socket now
    await fs.unlink(p);
  } catch { /* already gone */ }
}
