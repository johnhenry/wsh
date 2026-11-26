/**
 * Listen on a unix socket path so that closing removes only what the listener created (Node only).
 *
 * `net.Server` remembers the path it bound and, when it closes, libuv unlinks whatever is at that NAME. A listener that
 * checks the inode of the path before it unlinks protects nothing: if another process replaced the file at the path, the
 * server's own unlink still removes it. So the server is never given the requested name:
 *
 *   1. a private directory (`mkdtemp`, mode 0700) is made next to the requested path, and the server binds `<dir>/s`
 *      there. The directory, not the file mode, keeps every other user out until the socket is `0600`;
 *   2. the socket is hard-linked to the requested name. A hard link, unlike a rename, never replaces: if something
 *      appeared at the name meanwhile the link fails (`EADDRINUSE`) and nothing of it is touched. The name is a real
 *      socket (`lstat` says so, mode `0600`, nothing to follow, so a policy that refuses symbolic links accepts it);
 *      The private name is removed right after the link; the directory stays until `close()`, so the name the server
 *      remembers is one nobody but this process can create anything at;
 *   3. on `close()` the server closes (libuv unlinks `<dir>/s`: nothing there), the requested name is removed only while
 *      it is still the same inode (`removeIfIdentity`), and the private directory is removed.
 *
 * When the private path would not fit an address (`sun_path` is 104 bytes on macOS and the BSDs, 108 on Linux, with the
 * terminating NUL), or the file system cannot make hard links, the server binds the requested name directly, as it did
 * before: it works, and a file put at the name by someone else is then removed by the server's own unlink on close.
 * `staged` on the result says which happened. Windows named pipes and Linux abstract names are passed straight to `listen`.
 */

import fsp from 'node:fs/promises';
import path from 'node:path';

/** The longest unix socket path (bytes) the platform can bind. */
export const MAX_SOCKET_PATH = process.platform === 'linux' ? 107 : 103;
const STAGE_PREFIX = '.w';
const STAGE_RANDOM = 6; // what mkdtemp appends
/** `link` refusals that mean "this file system cannot do it": bind the requested name directly. */
const NO_HARD_LINKS = new Set(['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EXDEV']);

const listen = (server, p) => new Promise((resolve, reject) => { server.once('error', reject); server.listen({ path: p }, () => { server.off('error', reject); resolve(); }); });
const closeServer = (server) => (server.listening ? new Promise((resolve) => { server.close(() => resolve()); }) : Promise.resolve());
const identityOf = (st) => ({ dev: st.dev, ino: st.ino });

/**
 * @typedef {{ path: string, identity: { dev: number, ino: number } | null, staged: boolean, close: () => Promise<void> }} UnixListening
 *   `identity` is the file the listener made at `path` (`null` for an abstract name); `close()` closes the server (and
 *   whatever is connected is the caller's to end first) and removes what the listener created, only that.
 */

/**
 * Listen with `server` on the unix socket `requested`, which must not exist.
 * @param {import('node:net').Server} server
 * @param {string} requested
 * @returns {Promise<UnixListening>}
 */
export async function listenUnixSocket(server, requested) {
  const parent = path.dirname(requested);
  const fits = Buffer.byteLength(path.join(parent, `${STAGE_PREFIX}${'x'.repeat(STAGE_RANDOM)}`, 's')) <= MAX_SOCKET_PATH;
  if (process.platform === 'win32' || requested === '' || requested.startsWith('\0') || !fits) return listenDirect(server, requested);

  const dir = await fsp.mkdtemp(path.join(parent, STAGE_PREFIX));
  const inner = path.join(dir, 's');
  try {
    await listen(server, inner);
    await fsp.chmod(inner, 0o600);
    const identity = identityOf(await fsp.lstat(inner));
    try {
      await fsp.link(inner, requested);
      // One name only from here on. The server still believes it is bound to `inner`: its unlink at close finds nothing,
      // inside a directory nobody else can enter, and never reaches the requested name.
      await fsp.unlink(inner);
    } catch (e) {
      if (e.code === 'EEXIST') throw Object.assign(new Error(`listen EADDRINUSE: address already in use ${requested}`), { code: 'EADDRINUSE', errno: -98, syscall: 'listen', address: requested });
      if (!NO_HARD_LINKS.has(e.code)) throw e;
      await closeServer(server);
      await fsp.rmdir(dir).catch(() => {});
      return listenDirect(server, requested);
    }
    let closing;
    return {
      path: requested, identity, staged: true,
      close() {
        return (closing ??= (async () => {
          await closeServer(server); // libuv unlinks `inner`: a name inside a directory only this process can reach
          await removeIfIdentity(requested, identity);
          await fsp.rmdir(dir).catch(() => {});
        })());
      },
    };
  } catch (e) {
    await closeServer(server);
    await fsp.rmdir(dir).catch(() => {});
    throw e;
  }
}

/** The requested name itself: abstract and Windows names, a path too long to stage, a file system without hard links. */
async function listenDirect(server, requested) {
  const named = process.platform !== 'win32' && requested !== '' && !requested.startsWith('\0');
  // The mode of a socket is the umask at bind time: private from the first instant, then chmod to be sure.
  const old = named ? (() => { try { return process.umask(0o177); } catch { return null; } })() : null;
  try { await listen(server, requested); } finally { if (old !== null) { try { process.umask(old); } catch { /* gone */ } } }
  let identity = null;
  if (named) {
    await fsp.chmod(requested, 0o600);
    identity = identityOf(await fsp.lstat(requested));
  }
  let closing;
  return {
    path: requested, identity, staged: false,
    close() {
      return (closing ??= (async () => {
        await closeServer(server);
        if (identity) await removeIfIdentity(requested, identity);
      })());
    },
  };
}

/**
 * Remove `p` only while it is the socket `identity` names. A file or socket of anyone else is left alone (`false`).
 * Checked first with `lstat`; then, because the name could change between that check and the unlink, the file is moved
 * into a fresh private directory, checked again there and unlinked there. If the second check finds a stranger (it was put
 * at the name in that instant), it is put back without replacing anything newer; it is never deleted.
 * @param {string} p
 * @param {{ dev: number, ino: number }} identity
 * @returns {Promise<boolean>} whether `p` was removed
 */
export async function removeIfIdentity(p, identity) {
  const ours = (st) => st.isSocket() && st.ino === identity.ino && st.dev === identity.dev;
  try { if (!ours(await fsp.lstat(p))) return false; } catch { return false; }
  let aside;
  try { aside = await fsp.mkdtemp(path.join(path.dirname(p), STAGE_PREFIX)); } catch { return false; }
  const held = path.join(aside, 'x');
  try { await fsp.rename(p, held); } catch { await fsp.rmdir(aside).catch(() => {}); return false; }
  let moved;
  try { moved = await fsp.lstat(held); } catch { await fsp.rmdir(aside).catch(() => {}); return false; }
  if (ours(moved)) {
    await fsp.unlink(held);
    await fsp.rmdir(aside).catch(() => {});
    return true;
  }
  try {
    await fsp.link(held, p).catch(async (e) => {
      if (await fsp.lstat(p).then(() => true, () => false)) throw e; // something newer is there: do not replace it
      await fsp.rename(held, p);
    });
    await fsp.unlink(held).catch(() => {});
    await fsp.rmdir(aside).catch(() => {});
  } catch {
    throw new Error(`${p} was replaced while it was being removed; the replacement is kept at ${held}`);
  }
  return false;
}
