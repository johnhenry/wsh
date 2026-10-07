/**
 * File access for `@johnhenry/wsh/server`: FileOp requests (list, stat, read,
 * mkdir, remove) and `upload:`/`download:` file channels, confined to one
 * root directory.
 *
 * Every path a client sends is resolved against `root`; a path that would
 * leave it -- by `..`, an absolute path, or a symlink -- is refused.
 */

import {
  readdir, lstat, stat, readFile, writeFile, mkdir, rmdir, unlink, readlink, realpath, open,
} from 'node:fs/promises';
import path from 'node:path';

export const DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024;
export const FILE_CHUNK_BYTES = 64 * 1024;

/**
 * @param {{ root: string, readOnly?: boolean, maxFileBytes?: number }} opts
 */
export function createFileAccess({ root, readOnly = false, maxFileBytes = DEFAULT_MAX_FILE_BYTES }) {
  if (typeof root !== 'string' || !root) throw new TypeError('createWshServer: fs.root is required');
  const base = path.resolve(root);
  let realBase = null;

  const fail = (message) => Object.assign(new Error(message), { wsh: true });

  /** Resolve a client path to an absolute path inside `root`, or throw. */
  async function resolveInside(clientPath) {
    if (typeof clientPath !== 'string') throw fail('path is required');
    if (clientPath.includes('\0')) throw fail('illegal path');
    realBase ??= await realpath(base);
    const target = path.resolve(base, '.' + path.sep + clientPath.replace(/^[/\\]+/, ''));
    if (target !== base && !target.startsWith(base + path.sep)) throw fail('path escapes the file root');
    // Symlink escape: the deepest existing ancestor must still be inside the real root.
    let probe = target;
    for (;;) {
      try {
        const real = await realpath(probe);
        if (real !== realBase && !real.startsWith(realBase + path.sep)) throw fail('path escapes the file root');
        break;
      } catch (err) {
        if (err.wsh) throw err;
        const parent = path.dirname(probe);
        if (parent === probe) break;
        probe = parent;
      }
    }
    return target;
  }

  const typeOf = (st) => st.isSymbolicLink() ? 'symlink'
    : st.isDirectory() ? 'directory'
      : st.isFile() ? 'file'
        : st.isBlockDevice() || st.isCharacterDevice() ? 'device'
          : st.isFIFO() ? 'pipe'
            : st.isSocket() ? 'socket' : 'file';

  async function entryFor(full, name) {
    const st = await lstat(full);
    const entry = { name, size: st.size, modified: Math.floor(st.mtimeMs / 1000), type: typeOf(st) };
    if (entry.type === 'symlink') {
      try { entry.symlink_target = await readlink(full); } catch { /* raced */ }
    }
    return entry;
  }

  const assertWritable = () => { if (readOnly) throw fail('file root is read-only'); };

  return {
    maxFileBytes,

    /** @returns {Promise<{ metadata?: object, entries?: object[] }>} */
    async operate(op, clientPath, { offset, length } = {}) {
      switch (op) {
        case 'list': {
          const dir = await resolveInside(clientPath || '/');
          const names = await readdir(dir);
          const entries = [];
          for (const name of names.sort()) {
            try { entries.push(await entryFor(path.join(dir, name), name)); } catch { /* raced */ }
          }
          return { entries, metadata: { path: clientPath || '/' } };
        }
        case 'stat': {
          const full = await resolveInside(clientPath);
          return { metadata: await entryFor(full, path.basename(full)) };
        }
        case 'read': {
          const full = await resolveInside(clientPath);
          const st = await stat(full);
          if (!st.isFile()) throw fail('not a regular file');
          const start = Math.max(0, Number(offset ?? 0));
          const want = Math.min(Number(length ?? FILE_CHUNK_BYTES), FILE_CHUNK_BYTES);
          const fh = await open(full, 'r');
          try {
            const buf = new Uint8Array(want);
            const { bytesRead } = await fh.read(buf, 0, want, start);
            return { metadata: { data: buf.subarray(0, bytesRead), size: st.size } };
          } finally { await fh.close(); }
        }
        case 'mkdir': {
          assertWritable();
          await mkdir(await resolveInside(clientPath), { recursive: true });
          return { metadata: {} };
        }
        case 'remove': {
          assertWritable();
          const full = await resolveInside(clientPath);
          if (full === base) throw fail('refusing to remove the file root');
          await ((await lstat(full)).isDirectory() ? rmdir(full) : unlink(full));
          return { metadata: { removed: clientPath } };
        }
        default:
          throw fail(`"${op}" is not offered by this host (list, stat, read, mkdir, remove; use upload/download to write)`);
      }
    },

    async readWhole(clientPath) {
      const full = await resolveInside(clientPath);
      const st = await stat(full);
      if (!st.isFile()) throw fail('not a regular file');
      if (st.size > maxFileBytes) throw fail(`file is ${st.size} bytes; the limit is ${maxFileBytes}`);
      return new Uint8Array(await readFile(full));
    },

    async writeWhole(clientPath, data) {
      assertWritable();
      const full = await resolveInside(clientPath);
      await mkdir(path.dirname(full), { recursive: true });
      await writeFile(full, data);
    },
  };
}
