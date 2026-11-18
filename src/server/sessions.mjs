/**
 * Session registry for `@johnhenry/wsh/server`: what lets an exec/pty session
 * outlive the connection that opened it (`createWshServer({ sessions })`).
 *
 * The store itself (ring buffer, attachments, TTL, eviction) lives in `../session-registry.mjs`, which has no Node
 * dependency so the in-memory host can use it too. This file adds HMAC-signed session tokens (`node:crypto`).
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { SessionRegistry as CoreSessionRegistry } from '../session-registry.mjs';

export { ByteRing, HostedSession, DEFAULT_RING_BYTES, DEFAULT_DETACH_TTL_MS, DEFAULT_MAX_DETACHED, MAX_ATTACHMENTS } from '../session-registry.mjs';

const NO_EXPIRY = Buffer.alloc(8, 0xff);

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

export class SessionRegistry extends CoreSessionRegistry {
  constructor({ secret, ...rest } = {}) {
    super(rest);
    this.secret = secret ?? randomBytes(32);
  }

  mintToken(sessionId) { return mintToken(this.secret, sessionId); }

  checkToken(session, token) { return verifyToken(this.secret, session.id, token); }
}
