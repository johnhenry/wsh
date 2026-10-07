/**
 * Session registry for `@johnhenry/wsh/server`: what lets an exec/pty session
 * outlive the connection that opened it (`createWshServer({ sessions })`).
 *
 * The registry is per server and holds a `HostedSession` for every pty/exec
 * session. A connection's channel is an *attachment* to one: output is
 * appended to the session's ring buffer and fanned out to every attachment,
 * so when a socket drops the process keeps running and its newest output keeps
 * accumulating until `detachTtlMs` elapses or a client resumes.
 *
 * `seq` -- the one design question the wire does not answer -- is defined as
 * the cumulative count of output BYTES the host has produced for a session.
 * A client counts what it has received (it sees every byte), passes that as
 * `Resume.last_seq`, and the host replays `ring[last_seq - ringStart ..]`.
 * See spec/wsh-v1.yaml (`Resume`, `AttachmentInfo`).
 */

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

export const DEFAULT_RING_BYTES = 1024 * 1024;
export const DEFAULT_DETACH_TTL_MS = 300_000;
export const DEFAULT_MAX_DETACHED = 16;
export const MAX_ATTACHMENTS = 16;

const NO_EXPIRY = Buffer.alloc(8, 0xff);

/**
 * A bounded byte history addressed by absolute stream position.
 * `start` is the seq of the oldest retained byte, `end` the seq one past the newest.
 */
export class ByteRing {
  #chunks = [];
  #size = 0;
  start = 0;
  end = 0;

  constructor(maxBytes) {
    this.max = maxBytes;
  }

  push(bytes) {
    if (!bytes.byteLength) return;
    this.#chunks.push(Uint8Array.from(bytes));
    this.#size += bytes.byteLength;
    this.end += bytes.byteLength;
    while (this.#size > this.max) {
      const excess = this.#size - this.max;
      const first = this.#chunks[0];
      if (first.byteLength <= excess) {
        this.#chunks.shift();
        this.#size -= first.byteLength;
        this.start += first.byteLength;
      } else {
        this.#chunks[0] = first.subarray(excess);
        this.#size -= excess;
        this.start += excess;
      }
    }
  }

  /** Bytes from absolute position `from` (clamped to `start`) to the end. */
  read(from = this.start) {
    const skip = Math.max(0, from - this.start);
    const out = new Uint8Array(Math.max(0, this.#size - skip));
    let at = 0;
    let seen = 0;
    for (const c of this.#chunks) {
      if (seen + c.byteLength > skip) {
        const part = c.subarray(Math.max(0, skip - seen));
        out.set(part, at);
        at += part.byteLength;
      }
      seen += c.byteLength;
    }
    return out;
  }
}

/**
 * Mint a session token in the spec's format: `[8B expiry][32B HMAC-SHA256(secret, session_id || expiry)]`.
 * A session's lifetime is governed by `detachTtlMs`, not by its token, so the expiry is the maximum.
 */
export function mintToken(secret, sessionId) {
  const mac = createHmac('sha256', secret).update(sessionId).update(NO_EXPIRY).digest();
  return new Uint8Array(Buffer.concat([NO_EXPIRY, mac]));
}

/** Constant-time verification of a token minted by `mintToken` for exactly this session id. */
export function verifyToken(secret, sessionId, token) {
  if (!(token instanceof Uint8Array) || token.byteLength !== 40) return false;
  const buf = Buffer.from(token.buffer, token.byteOffset, token.byteLength);
  const expiry = buf.subarray(0, 8);
  if (expiry.readBigUInt64BE() < BigInt(Math.floor(Date.now() / 1000))) return false;
  const want = createHmac('sha256', secret).update(sessionId).update(expiry).digest();
  return timingSafeEqual(want, buf.subarray(8));
}

/**
 * One attached connection's view of a session; `connection.mjs` builds them.
 * @typedef {object} Attachment
 * @property {number} connId
 * @property {number} channelId
 * @property {'control' | 'readonly'} mode
 * @property {string} username
 * @property {string} principal - who this connection authenticated as (see `principalKey`)
 * @property {(bytes: Uint8Array) => unknown} write - live output
 * @property {(msg: object) => unknown} notify - an ordered control message (e.g. Presence)
 * @property {(code: number) => unknown} exit - the session ended
 */

export class HostedSession {
  /** @type {Set<Attachment>} */
  attachments = new Set();
  state = 'attached';
  exitCode = null;
  createdAt = Date.now();
  lastActivity = Date.now();
  detachedAt = 0;
  name;
  #timer = null;

  constructor(registry, { id, token, owner, kind, command, ringBytes }) {
    this.registry = registry;
    this.id = id;
    this.token = token;
    this.owner = owner;
    this.kind = kind;
    this.command = command;
    this.ring = new ByteRing(ringBytes);
    /** Set by the connection once the process exists: `{ input, inputEnd, resize, signal, kill }`. */
    this.handlers = {};
  }

  /** Output from the process: retained in the ring, delivered to every attachment. */
  push(bytes) {
    this.lastActivity = Date.now();
    this.ring.push(bytes);
    for (const a of this.attachments) a.write(bytes);
  }

  attach(att) {
    this.attachments.add(att);
    this.state = 'attached';
    this.#clearTimer();
    this.broadcastPresence(att);
  }

  detach(att) {
    if (!this.attachments.delete(att)) return;
    this.broadcastPresence();
    if (this.attachments.size === 0) this.#markDetached();
  }

  roster() {
    return [...this.attachments].map((a) => ({ session_id: this.id, mode: a.mode, username: a.username }));
  }

  /** Tell every attachment (except `except`) who is attached now. */
  broadcastPresence(except) {
    if (this.attachments.size === 0) return;
    const msg = { attachments: this.roster() };
    for (const a of this.attachments) if (a !== except) a.notify(msg);
  }

  /** The process ended. Everyone attached hears Exit + Close; the record lingers for late resumes. */
  finish(code) {
    if (this.state === 'exited') return;
    this.exitCode = code;
    this.state = 'exited';
    const att = [...this.attachments];
    this.attachments.clear();
    for (const a of att) a.exit(code);
    this.#markDetached();
  }

  kill() {
    try { this.handlers.kill?.(); } catch { /* already gone */ }
  }

  /** Forget the session (and stop it if it is still running). */
  dispose() {
    this.#clearTimer();
    this.registry._forget(this);
    if (this.state !== 'exited') {
      this.kill();
      this.state = 'exited';
    }
  }

  #markDetached() {
    this.detachedAt = Date.now();
    if (this.state !== 'exited') this.state = 'detached';
    this.#clearTimer();
    const ttl = this.registry.detachTtlMs;
    if (ttl <= 0) { this.dispose(); return; }
    this.#timer = setTimeout(() => {
      this.registry.log(`session ${this.id} expired after ${ttl}ms detached`);
      this.dispose();
    }, ttl);
    this.#timer.unref?.();
    this.registry._enforceMaxDetached(this);
  }

  #clearTimer() {
    clearTimeout(this.#timer);
    this.#timer = null;
  }
}

export class SessionRegistry {
  /** @type {Map<string, HostedSession>} */
  #sessions = new Map();

  constructor({ secret, detachTtlMs = DEFAULT_DETACH_TTL_MS, maxDetached = DEFAULT_MAX_DETACHED, ringBytes = DEFAULT_RING_BYTES, log = () => {} } = {}) {
    this.secret = secret ?? randomBytes(32);
    this.detachTtlMs = detachTtlMs;
    this.maxDetached = maxDetached;
    this.ringBytes = ringBytes;
    this.log = log;
  }

  /** @param {{ owner: { username: string, principal: string, fingerprint: string | null }, kind: 'pty' | 'exec', command?: string }} spec */
  create({ owner, kind, command }) {
    const id = randomUUID();
    const s = new HostedSession(this, { id, token: mintToken(this.secret, id), owner, kind, command, ringBytes: this.ringBytes });
    this.#sessions.set(id, s);
    return s;
  }

  get(id) {
    return typeof id === 'string' ? this.#sessions.get(id) : undefined;
  }

  checkToken(session, token) {
    return verifyToken(this.secret, session.id, token);
  }

  /** Sessions this principal owns. */
  listFor(principal) {
    return [...this.#sessions.values()].filter((s) => s.owner.principal === principal);
  }

  get size() { return this.#sessions.size; }

  /** Kill everything (server shutdown). */
  closeAll() {
    for (const s of [...this.#sessions.values()]) s.dispose();
  }

  _forget(session) {
    this.#sessions.delete(session.id);
  }

  /** Keep at most `maxDetached` unattended sessions: the longest-detached are killed first. */
  _enforceMaxDetached() {
    const detached = [...this.#sessions.values()].filter((s) => s.attachments.size === 0).sort((a, b) => a.detachedAt - b.detachedAt);
    while (detached.length > this.maxDetached) {
      const victim = detached.shift();
      this.log(`session ${victim.id} evicted (more than ${this.maxDetached} detached)`);
      victim.dispose();
    }
  }
}
