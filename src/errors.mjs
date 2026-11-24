/**
 * Typed errors for a refused login or a failed connection, so a caller branches on a stable `code` instead of matching
 * message text. The messages are unchanged (`Authentication failed: <host's reason>`, `Connection failed across transports (...)`,
 * `Auth handshake timed out ...`): code that matched them keeps working, and `HostKeyError` (`./host-key.mjs`) is the same
 * idea for a refused host key. Browser-safe.
 *
 * The wire carries only the host's human `reason` in `AuthFail`; it does not carry the machine code the host reports to its own
 * `onRefused`. So `refusal` here is derived from the reason text of the hosts this repository ships (the Node host and the
 * Rust `wsh-server`), checked against the Node host's `onRefused` reasons by a test; a host that words its refusal otherwise
 * gives `AUTH_FAILED` with `refusal: null` and the text in `reason`.
 */

export const WSH_ERROR_CODES = Object.freeze({
  /** The host refused the login and the client could not tell why from its words. */
  AUTH_FAILED: 'AUTH_FAILED',
  /** A key the host does not allow, or a wrong password. (`onRefused` reason `unauthorized`.) */
  AUTH_UNAUTHORIZED: 'AUTH_UNAUTHORIZED',
  AUTH_BAD_SIGNATURE: 'AUTH_BAD_SIGNATURE',
  /** The login method (password or key) is not on at the host. */
  AUTH_METHOD_DISABLED: 'AUTH_METHOD_DISABLED',
  AUTH_RATE_LIMITED: 'AUTH_RATE_LIMITED',
  AUTH_KEY_EXPIRED: 'AUTH_KEY_EXPIRED',
  AUTH_BINDING_REQUIRED: 'AUTH_BINDING_REQUIRED',
  AUTH_NOT_SEALED: 'AUTH_NOT_SEALED',
  /** A malformed login: a bad username, an unsupported method, a missing field. */
  AUTH_BAD_REQUEST: 'AUTH_BAD_REQUEST',
  /** No transport could be opened. */
  CONNECTION_FAILED: 'CONNECTION_FAILED',
  /** The host did not answer a step of the login in time. */
  HANDSHAKE_TIMEOUT: 'HANDSHAKE_TIMEOUT',
});

/** Reason text of the shipped hosts, mapped to the `onRefused` reason codes (`REFUSAL_REASONS`). Order matters: first match. */
const REFUSAL_PATTERNS = [
  ['key-expired', /\bexpired\b/i],
  ['binding-required', /channel binding required/i],
  ['not-sealed', /sealed session/i],
  ['rate-limited', /too many (failed )?(auth )?attempts|rate limited/i],
  ['method-disabled', /auth(entication)? (is )?(not enabled|disabled)/i],
  ['bad-signature', /signature (does not verify|verification failed)/i],
  ['unauthorized', /^(key not authorized|authentication failed|invalid password)$/i],
  ['bad-request', /^bad username|^unsupported auth method|^expected (a |an )?(pubkey|password )?auth|^malformed|^missing /i],
];

/**
 * @param {unknown} reason  the `reason` of an `AuthFail`
 * @returns {{ code: string, refusal: string | null }}
 */
export function classifyAuthRefusal(reason) {
  if (typeof reason === 'string') {
    for (const [refusal, re] of REFUSAL_PATTERNS) {
      if (re.test(reason.trim())) return { code: `AUTH_${refusal.toUpperCase().replace(/-/g, '_')}`, refusal };
    }
  }
  return { code: WSH_ERROR_CODES.AUTH_FAILED, refusal: null };
}

/** The host refused the login (`AuthFail`). No credential beyond what the login itself sent was exposed to anyone else. */
export class WshAuthError extends Error {
  /**
   * @param {string} reason  what the host said
   * @param {string} [message]  default `Authentication failed: <reason>`
   */
  constructor(reason, message) {
    super(message ?? `Authentication failed: ${reason}`);
    this.name = 'WshAuthError';
    const { code, refusal } = classifyAuthRefusal(reason);
    /** A `WSH_ERROR_CODES` value starting `AUTH_`. */
    this.code = code;
    /** What the host said, verbatim. */
    this.reason = reason;
    /** The `onRefused` reason code (`REFUSAL_REASONS`) this corresponds to, or null when the wording is not recognised. */
    this.refusal = refusal;
  }
}

/** A connection could not be made or a step of the handshake did not complete. */
export class WshConnectionError extends Error {
  /**
   * @param {'CONNECTION_FAILED' | 'HANDSHAKE_TIMEOUT'} code
   * @param {string} message
   * @param {{ attempts?: string[], cause?: unknown }} [details]
   */
  constructor(code, message, details = {}) {
    super(message, details.cause === undefined ? undefined : { cause: details.cause });
    this.name = 'WshConnectionError';
    this.code = code;
    if (details.attempts) /** One line per transport tried (`wt: ...`, `ws: ...`). */ this.attempts = details.attempts;
  }
}
