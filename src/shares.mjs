/**
 * Operator-side shared folders, the HOST half (#159). Browser-safe: it imports nothing from `node:*`.
 *
 * A host that has no disk of its own (a tab) can use directories that live on the OPERATOR's machine for the life of
 * a session: the operator's `wsh --share NAME=/abs/dir[:ro|:rw]` offers them (`ShareOffer`), and this module hands the
 * embedder an object of async file operations per share -- `onShare(name, fs, who)` -- that it can mount. Every
 * operation is a bounded `ShareRequest` this host sends and the operator's client answers (`ShareReply`).
 *
 * The client is the file server and enforces confinement; this side enforces what a host can: the request window the
 * offer promised (`max_inflight`), a per-request deadline, the size of a reply, the shape of what comes back (a client
 * that answers nonsense gets an `EIO`, never a thrown TypeError in the embedder's code), and that nothing is asked
 * before an offer. Share names, counts and limits from the offer are validated and clamped.
 *
 * Negotiation: a host that passes `onShare` lists the feature `shares` in `ServerHello.features`. A client with shares
 * to offer sends ONE `ShareOffer` after login (inside whatever sealing the session has, so a sealed session protects
 * file data with no extra crypto here). A host without `onShare` never lists the feature and ignores an offer.
 */

import { MSG, shareRequest } from './messages.gen.mjs';

/** The `ServerHello` feature of a host that can use shares. */
export const SHARES_FEATURE = 'shares';

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ERRNOS = new Set(['ENOENT', 'EEXIST', 'ENOTDIR', 'EISDIR', 'ENOTEMPTY', 'EACCES', 'EPERM', 'EROFS', 'EINVAL', 'EBADF', 'ELOOP',
  'ENAMETOOLONG', 'ENOSPC', 'EMFILE', 'EBUSY', 'EAGAIN', 'EXDEV', 'EFBIG', 'ENOTSUP', 'ESTALE', 'EIO']);
const MAX_SHARES = 16;
const MAX_ROOT_BYTES = 4096;

/**
 * The advisory root path of each share from `ShareOffer.paths` (#164): an array exactly as long as `shares`, each entry an
 * absolute string of at most 4096 bytes without NUL. Anything else is `undefined` (never an error): the host cannot verify it.
 * @returns {Array<string | undefined>}
 */
function offeredRoots(paths, count) {
  const none = new Array(count).fill(undefined);
  if (!Array.isArray(paths) || paths.length !== count) return none;
  return paths.map((p) => (typeof p === 'string' && p.startsWith('/') && !p.includes('\0') && new TextEncoder().encode(p).length <= MAX_ROOT_BYTES ? p : undefined));
}
const MAX_INFLIGHT = 64;
const MIN_BYTES = 4096;
const MAX_BYTES = 4 * 1024 * 1024;
/** Requests waiting for a slot of the window, per connection; beyond that a call fails with `EAGAIN` at once. */
const QUEUE_LIMIT = 4096;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_LIST_ENTRIES = 2_000_000;

/** An error from the operator's side of a share, with the errno-like code the wire carries (`error.code === error.errno`). */
export class ShareError extends Error {
  constructor(errno, message) {
    super(`${errno}: ${message}`);
    this.name = 'ShareError';
    this.errno = errno;
    this.code = errno;
    this.wsh = true;
  }
}

const clampInt = (v, lo, hi) => Math.min(hi, Math.max(lo, Number.isFinite(v) ? Math.trunc(v) : lo));
const text = (v, max = 200) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max) : '');

/** An attribute map from the wire, as a plain object a caller can rely on. */
function toAttr(a) {
  if (!a || typeof a !== 'object') throw new ShareError('EIO', 'the operator sent no attributes');
  const type = a.type === 'file' || a.type === 'directory' || a.type === 'symlink' ? a.type : null;
  if (!type) throw new ShareError('EIO', 'the operator sent an unknown file type');
  const n = (v) => (Number.isFinite(v) ? Number(v) : 0);
  return {
    type, size: n(a.size), mode: n(a.mode) & 0o777, mtimeMs: n(a.mtime_ms), atimeMs: n(a.atime_ms), ctimeMs: n(a.ctime_ms), nlink: n(a.nlink), ino: n(a.ino),
    isFile: () => type === 'file', isDirectory: () => type === 'directory', isSymbolicLink: () => type === 'symlink',
  };
}

const toBytes = (v, what) => {
  if (v instanceof Uint8Array) return v;
  if (v === undefined || v === null) return new Uint8Array(0);
  throw new ShareError('EIO', `the operator sent ${what} that is not bytes`);
};

/**
 * The per-connection engine: one request window shared by every share of the connection.
 * @param {{ send: (m: object) => unknown, log?: (line: string) => void, timeoutMs?: number }} io
 */
function createCore({ send, log = () => {}, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  let window = 1;
  let maxBytes = MIN_BYTES;
  let nextId = 1;
  let closed = false;
  const inflight = new Map(); // id -> { job, abandoned }
  const queue = [];
  const stats = { requests: 0, replies: 0, errors: 0, bytesDown: 0, bytesUp: 0, timeouts: 0 };

  function pump() {
    while (!closed && inflight.size < window && queue.length) start(queue.shift());
  }

  function start(job) {
    if (job.done) return;
    let id = nextId;
    for (let i = 0; inflight.has(id); i += 1) { id = (id % 0xffffffff) + 1; if (i > 0xffff) { finish(job, new ShareError('EAGAIN', 'no request id free')); return; } }
    nextId = (id % 0xffffffff) + 1;
    job.id = id;
    inflight.set(id, { job, abandoned: false });
    stats.requests += 1;
    if (job.fields.data) stats.bytesUp += job.fields.data.byteLength;
    try {
      Promise.resolve(send(shareRequest({ requestId: id, share: job.share, op: job.op, ...job.fields }))).catch(() => {});
    } catch (e) { inflight.delete(id); finish(job, new ShareError('EIO', `could not send: ${e.message}`)); }
  }

  function finish(job, err, value) {
    if (job.done) return;
    job.done = true;
    clearTimeout(job.timer);
    if (err) job.reject(err); else job.resolve(value);
  }

  return {
    stats,
    get maxBytes() { return maxBytes; },
    configure(offer) { window = offer.maxInflight; maxBytes = offer.maxBytes; pump(); },
    /** Send one request and resolve with the (validated-as-ok) reply. */
    call(share, op, fields = {}) {
      return new Promise((resolve, reject) => {
        if (closed) { reject(new ShareError('EIO', 'the connection to the operator is gone')); return; }
        const job = { share, op, fields, resolve, reject, done: false, id: 0, timer: null };
        if (queue.length >= QUEUE_LIMIT) { reject(new ShareError('EAGAIN', 'too many share requests are waiting')); return; }
        job.timer = setTimeout(() => {
          stats.timeouts += 1;
          const q = queue.indexOf(job);
          if (q >= 0) queue.splice(q, 1);
          // A request already sent keeps its slot until the operator answers (or the connection ends): the window
          // the offer promised is not exceeded because one answer is slow.
          const entry = inflight.get(job.id);
          if (entry) entry.abandoned = true;
          finish(job, new ShareError('EIO', `the operator did not answer ${op} within ${timeoutMs} ms`));
        }, timeoutMs);
        job.timer.unref?.();
        queue.push(job);
        pump();
      });
    },
    reply(m) {
      const entry = inflight.get(m.request_id);
      if (!entry) return; // unknown or already answered: ignored
      inflight.delete(m.request_id);
      stats.replies += 1;
      const { job, abandoned } = entry;
      if (!abandoned) {
        if (m.ok === true) {
          const data = m.data;
          if (data instanceof Uint8Array) {
            stats.bytesDown += data.byteLength;
            if (data.byteLength > maxBytes) { stats.errors += 1; finish(job, new ShareError('EIO', 'the operator sent more data than it offered')); pump(); return; }
          }
          finish(job, null, m);
        } else {
          stats.errors += 1;
          const errno = ERRNOS.has(m.errno) ? m.errno : 'EIO';
          finish(job, new ShareError(errno, text(m.message) || errno));
        }
      }
      pump();
    },
    close() {
      if (closed) return;
      closed = true;
      const gone = () => new ShareError('EIO', 'the connection to the operator is gone');
      for (const { job } of inflight.values()) finish(job, gone());
      inflight.clear();
      for (const job of queue.splice(0)) finish(job, gone());
    },
    get closed() { return closed; },
    log,
  };
}

/** An open file on the operator's machine. */
class ShareFile {
  #core; #share; #handle; #inline; #writable; #closed = false;
  constructor(core, share, handle, attr, { inline = null, writable = false } = {}) {
    this.#core = core; this.#share = share; this.#handle = handle; this.#inline = inline; this.#writable = writable;
    this.attr = attr;
  }

  /** Read up to `length` bytes at `offset`: `{ data, eof }`. */
  async read(offset, length) {
    if (this.#closed) throw new ShareError('EBADF', 'the file is closed');
    if (!(Number.isSafeInteger(offset) && offset >= 0) || !(Number.isSafeInteger(length) && length >= 0)) throw new ShareError('EINVAL', 'read needs a non-negative offset and length');
    if (this.#inline) {
      const data = this.#inline.subarray(offset, offset + length);
      return { data, eof: offset + length >= this.#inline.byteLength };
    }
    const n = Math.min(length, this.#core.maxBytes);
    const r = await this.#core.call(this.#share, 'read', { handle: this.#handle, offset, length: n });
    return { data: toBytes(r.data, 'read data'), eof: r.eof === true };
  }

  /** Write `data` at `offset` (a share offered `:rw`); resolves with the bytes written. */
  async write(offset, data) {
    if (this.#closed) throw new ShareError('EBADF', 'the file is closed');
    if (!this.#writable) throw new ShareError('EBADF', 'the file is not open for writing');
    let done = 0;
    while (done < data.byteLength) {
      const chunk = data.subarray(done, done + this.#core.maxBytes);
      const r = await this.#core.call(this.#share, 'write', { handle: this.#handle, offset: offset + done, data: chunk });
      const w = Number(r.written);
      if (!Number.isSafeInteger(w) || w < 0 || w > chunk.byteLength) throw new ShareError('EIO', 'the operator reported a bad write size');
      done += w;
      if (w === 0) break;
    }
    return done;
  }

  async setattr(changes) {
    if (this.#closed) throw new ShareError('EBADF', 'the file is closed');
    if (!this.#handle) throw new ShareError('EBADF', 'this file is read-only and complete: use fs.setattr(path, ...)');
    const r = await this.#core.call(this.#share, 'setattr', { handle: this.#handle, attr: wireAttr(changes) });
    return toAttr(r.attr);
  }

  async truncate(size) { return this.setattr({ size }); }

  async close() {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#handle) await this.#core.call(this.#share, 'close', { handle: this.#handle }).catch(() => {});
  }
}

function wireAttr(c = {}) {
  const out = {};
  if (c.mode !== undefined) out.mode = c.mode;
  if (c.atimeMs !== undefined) out.atime_ms = c.atimeMs;
  if (c.mtimeMs !== undefined) out.mtime_ms = c.mtimeMs;
  if (c.size !== undefined) out.size = c.size;
  return out;
}

/**
 * The object an embedder mounts: async file operations on one share. Paths are relative to the share root
 * ("/"-separated; a leading "/" means the root); `..` is refused by the operator's client. Errors are `ShareError`s
 * with `.code` an errno-like string (`ENOENT`, `EROFS`, ...).
 */
function createShareFs(core, name, writable, signal, root) {
  const call = (op, fields) => core.call(name, op, fields);
  const norm = (p) => { if (typeof p !== 'string') throw new ShareError('EINVAL', 'a path must be a string'); return p; };
  const maxFileBytes = DEFAULT_MAX_FILE_BYTES;

  const fs = {
    name,
    /** Whether the operator offered writes. */
    writable,
    /** The share's root path on the operator's machine, as the operator typed it, or undefined. ADVISORY and unverified (#164). */
    get root() { return root; },
    maxFileBytes,
    /** Aborted when the connection to the operator ends. */
    signal,
    /** Counters for this connection (requests, replies, errors, bytes each way): the evidence that batching works. */
    get stats() { return { ...core.stats }; },

    async stat(path) { return toAttr((await call('stat', { path: norm(path) })).attr); },
    async lstat(path) { return toAttr((await call('lstat', { path: norm(path) })).attr); },
    async readlink(path) {
      const r = await call('readlink', { path: norm(path) });
      if (typeof r.target !== 'string') throw new ShareError('EIO', 'the operator sent no link target');
      return r.target;
    },

    /** Every entry of a directory WITH its attributes, sorted by name (the pages are followed): `[{ name, type, size, mode, mtimeMs, ..., target? }]`. */
    async readdir(path) {
      const out = [];
      let cursor;
      for (;;) {
        const r = await call('readdir', { path: norm(path), ...(cursor !== undefined ? { cursor } : {}) });
        if (!Array.isArray(r.entries)) throw new ShareError('EIO', 'the operator sent no entries');
        for (const e of r.entries) {
          if (!e || typeof e.name !== 'string' || !e.name || e.name.includes('/') || e.name.includes('\0') || e.name === '.' || e.name === '..') throw new ShareError('EIO', 'the operator sent a bad directory entry');
          const entry = { name: e.name, ...toAttr(e) };
          if (typeof e.target === 'string') entry.target = e.target;
          out.push(entry);
        }
        if (out.length > MAX_LIST_ENTRIES) throw new ShareError('EFBIG', 'directory has too many entries');
        if (r.cursor === undefined || r.cursor === null) break;
        if (typeof r.cursor !== 'string' || (cursor !== undefined && r.cursor <= cursor)) throw new ShareError('EIO', 'the operator\'s directory cursor did not advance');
        cursor = r.cursor;
      }
      return out;
    },

    /** Open a file. `flags`: any of `read`, `write`, `create`, `excl`, `trunc`. */
    async open(path, flags = ['read'], { mode, inlineBytes } = {}) {
      const f = [...flags];
      const wantsWrite = f.includes('write') || f.includes('create') || f.includes('trunc');
      const r = await call('open', { path: norm(path), flags: f, ...(mode !== undefined ? { mode } : {}), ...(inlineBytes !== undefined ? { length: inlineBytes } : {}) });
      const attr = toAttr(r.attr);
      if (r.handle === undefined || r.handle === null) {
        // Whole file, read-only, no handle: it came with the open.
        if (wantsWrite || r.eof !== true || !(r.data instanceof Uint8Array)) throw new ShareError('EIO', 'the operator sent no file handle');
        return new ShareFile(core, name, 0, attr, { inline: r.data });
      }
      if (!Number.isSafeInteger(r.handle) || r.handle <= 0) throw new ShareError('EIO', 'the operator sent a bad handle');
      return new ShareFile(core, name, r.handle, attr, { writable: wantsWrite, inline: r.eof === true && r.data instanceof Uint8Array && !wantsWrite ? r.data : null });
    },

    /** Create a NEW file (`EEXIST` if the name is taken, a link included) and open it for writing. */
    async create(path, { mode } = {}) {
      const r = await call('create', { path: norm(path), ...(mode !== undefined ? { mode } : {}) });
      if (!Number.isSafeInteger(r.handle) || r.handle <= 0) throw new ShareError('EIO', 'the operator sent a bad handle');
      return new ShareFile(core, name, r.handle, toAttr(r.attr), { writable: true });
    },

    /** The whole content of a file: one round trip when it is small (it rides the open), else ranges of the offered size. */
    async readFile(path, { maxBytes = maxFileBytes } = {}) {
      const file = await fs.open(path, ['read'], { inlineBytes: core.maxBytes });
      try {
        if (file.attr.size > maxBytes) throw new ShareError('EFBIG', `the file is ${file.attr.size} bytes, more than ${maxBytes}`);
        const parts = [];
        let offset = 0;
        for (;;) {
          const { data, eof } = await file.read(offset, core.maxBytes);
          if (data.byteLength) parts.push(data);
          offset += data.byteLength;
          if (offset > maxBytes) throw new ShareError('EFBIG', `the file is bigger than ${maxBytes} bytes`);
          if (eof || data.byteLength === 0) break;
        }
        if (parts.length === 1) return parts[0];
        const all = new Uint8Array(offset);
        let at = 0;
        for (const p of parts) { all.set(p, at); at += p.byteLength; }
        return all;
      } finally { await file.close(); }
    },

    /** Replace (or create) a file with `data`. Needs `:rw`. */
    async writeFile(path, data, { mode, truncate = true } = {}) {
      const file = await fs.open(path, ['write', 'create', ...(truncate ? ['trunc'] : [])], { mode });
      try { return await file.write(0, data); } finally { await file.close(); }
    },

    async mkdir(path, { mode } = {}) { return toAttr((await call('mkdir', { path: norm(path), ...(mode !== undefined ? { mode } : {}) })).attr); },
    async unlink(path) { await call('unlink', { path: norm(path) }); },
    async rmdir(path) { await call('rmdir', { path: norm(path) }); },
    async rename(from, to) { await call('rename', { path: norm(from), to: norm(to) }); },
    /** `changes`: any of `mode`, `atimeMs`, `mtimeMs`, `size` (a new size is a truncate). */
    async setattr(path, changes) { return toAttr((await call('setattr', { path: norm(path), attr: wireAttr(changes) })).attr); },
    async truncate(path, size) { return fs.setattr(path, { size }); },
    async chmod(path, mode) { return fs.setattr(path, { mode }); },
    async utimes(path, atimeMs, mtimeMs) { return fs.setattr(path, { atimeMs, mtimeMs }); },

    // ── the shape of an injected `fs` backend (`createMemoryHost({ fs })`, `createWshServer({ fs })`) ───────────────
    // A share can be served onward as a host's own file backend: `createMemoryHost({ fs: share })`.
    async operate(op, clientPath, { offset, length, newPath, data } = {}) {
      const entry = (e, nameOf) => ({ name: nameOf, size: e.size, modified: Math.floor(e.mtimeMs / 1000), type: e.type, ...(e.target !== undefined ? { symlink_target: e.target } : {}) });
      switch (op) {
        case 'list': return { entries: (await fs.readdir(clientPath || '/')).map((e) => entry(e, e.name)), metadata: { path: clientPath || '/' } };
        case 'stat': { const a = await fs.lstat(clientPath); return { metadata: entry(a, String(clientPath).split('/').filter(Boolean).pop() ?? '') }; }
        case 'read': {
          const file = await fs.open(clientPath, ['read']);
          try {
            const want = Math.min(Number(length ?? core.maxBytes), core.maxBytes);
            const { data: bytes } = await file.read(Math.max(0, Number(offset ?? 0)), want);
            return { metadata: { data: bytes, size: file.attr.size } };
          } finally { await file.close(); }
        }
        case 'write': { await fs.writeAt(clientPath, data, offset); return { metadata: { written: data.byteLength } }; }
        case 'mkdir': await fs.mkdir(clientPath); return { metadata: {} };
        case 'remove': { const a = await fs.lstat(clientPath); await (a.isDirectory() ? fs.rmdir(clientPath) : fs.unlink(clientPath)); return { metadata: { removed: clientPath } }; }
        case 'rename': await fs.rename(clientPath, newPath); return { metadata: { renamed: clientPath, to: newPath } };
        default: throw new ShareError('ENOTSUP', `"${op}" is not offered (list, stat, read, write, rename, mkdir, remove)`);
      }
    },
    async readWhole(clientPath) { return fs.readFile(clientPath); },
    async writeWhole(clientPath, bytes) { await fs.writeFile(clientPath, bytes); },
    async writeAt(clientPath, bytes, offset = 0) {
      const file = await fs.open(clientPath, ['write', 'create']);
      try { await file.write(Number(offset), bytes); } finally { await file.close(); }
    },
  };
  return fs;
}

/**
 * The shares of ONE connection. `handle(m)` takes the messages that are about shares; `close()` ends everything.
 * @param {object} io
 * @param {(m: object) => unknown} io.send - send a message to the operator (through the connection's sealing, if any)
 * @param {(name: string, fs: object, who: { username: string | null, fingerprint: string | null }) => unknown} io.onShare
 * @param {() => { username: string | null, fingerprint: string | null }} io.who
 * @param {(line: string) => void} [io.log]
 * @param {number} [io.timeoutMs]
 */
export function createShareSession({ send, onShare, who, log = () => {}, timeoutMs }) {
  const core = createCore({ send, log, timeoutMs });
  const abort = new AbortController();
  let offered = false;
  const shares = new Map();

  function offer(m) {
    if (offered) { log('ignored a second ShareOffer'); return; }
    offered = true;
    const names = Array.isArray(m.shares) ? m.shares : [];
    if (!names.length || names.length > MAX_SHARES || names.some((n) => typeof n !== 'string' || !NAME_RE.test(n)) || new Set(names).size !== names.length) {
      log('ignored a ShareOffer with bad share names');
      return;
    }
    const writable = new Set(Array.isArray(m.writable) ? m.writable.filter((n) => names.includes(n)) : []);
    core.configure({ maxInflight: clampInt(m.max_inflight, 1, MAX_INFLIGHT), maxBytes: clampInt(m.max_bytes, MIN_BYTES, MAX_BYTES) });
    const roots = offeredRoots(m.paths, names.length);
    for (const [i, name] of names.entries()) {
      const fs = createShareFs(core, name, writable.has(name), abort.signal, roots[i]);
      shares.set(name, fs);
      Promise.resolve()
        .then(() => onShare(name, fs, who()))
        .catch((e) => log(`onShare(${JSON.stringify(name)}) threw: ${e?.message ?? e}`));
    }
    log(`shares offered: ${names.map((n) => `${n}${writable.has(n) ? ' (rw)' : ''}`).join(', ')}`);
  }

  return {
    /** The shares offered so far, by name. */
    shares,
    stats: core.stats,
    /** @returns {boolean} whether `m` was about shares (and has been dealt with). */
    handle(m) {
      switch (m.type) {
        case MSG.SHARE_OFFER: offer(m); return true;
        case MSG.SHARE_REPLY: core.reply(m); return true;
        case MSG.SHARE_REQUEST: log('ignored a ShareRequest from the operator (only the host asks)'); return true;
        default: return false;
      }
    },
    close() { abort.abort(); core.close(); },
  };
}

/** Validate an `onShare` option (a function, or absent). */
export function validateOnShare(onShare, who) {
  if (onShare !== undefined && onShare !== null && typeof onShare !== 'function') throw new TypeError(`${who}: onShare must be a function (name, fs, who) => void`);
}
