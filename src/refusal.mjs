/**
 * `onRefused` (#163): a host tells its embedder that it turned a client (or, on a reverse host, an operator) away, with a
 * stable reason code instead of a log line to parse. Browser-safe; shared by every host.
 *
 * The codes are part of the API (new ones may be added, none is renamed):
 *  - `not-sealed`       the host requires a sealed session (`sealSession: 'require'`, `requireOperatorProof`) and the peer sent
 *                       something that is not sealed, or logged in in a way that cannot seal
 *  - `unauthorized`     a key the host does not allow, a wrong password, or an operator the host's `accept` turned down
 *  - `binding-required` the host requires the login to be bound to the connection (`requireChannelBinding`) and it was not
 *  - `bad-signature`    the login signature does not verify
 *  - `method-disabled`  the login method is not on (password on a key-only host, or the reverse)
 *  - `rate-limited`     too many failed password attempts from that caller
 *  - `bad-request`      a malformed login (bad username, malformed key, the wrong message)
 *  - `seal-failed`      a sealed session's key exchange failed, or one of its frames did not open
 *  - `seal-timeout`     the host requires a sealed session, the peer logged in, and the session was not sealed within `sealTimeoutMs`
 *                       (default 30 s; #244)
 *  - `busy`             (reverse host) it already serves its operators
 *  - `key-expired`      the key is past the `expires` of its `authorized_keys` line (or of what `authorize` returned), at login or on a
 *                       later request (#122)
 *  - `not-permitted`    a request the key's options or capabilities do not allow (`restrict`, `command=`, `capabilities="..."`): an
 *                       `Open`, `FileOp`, MCP call, gateway request, relay request ...; `detail` is `<code>: <reason> (<request>)`, with
 *                       the missing capability named for `capability-missing` (#122). Unlike the login reasons it can come
 *                       any number of times on one connection
 *  - `proof-required`   (reverse host) it requires the operator to prove its identity and the operator offered none
 *  - `proof-failed`     (reverse host) the operator's proof did not arrive, did not verify or names someone else
 */
export const REFUSAL_REASONS = Object.freeze([
  'not-sealed', 'unauthorized', 'binding-required', 'bad-signature', 'method-disabled', 'rate-limited', 'bad-request',
  'seal-failed', 'busy', 'proof-required', 'proof-failed', 'key-expired', 'not-permitted', 'seal-timeout',
]);

/** @throws {TypeError} when `onRefused` is given and is not a function */
export function validateOnRefused(onRefused, where) {
  if (onRefused !== undefined && onRefused !== null && typeof onRefused !== 'function') throw new TypeError(`${where}: onRefused must be a function`);
}

/**
 * A function `(reason, who, detail)` that calls `onRefused({ reason, who, detail })`, dropping the undefined parts of `who`. A
 * callback that throws is logged and does not change what the host does. Returns a no-op when there is no callback.
 * @param {Function | undefined | null} onRefused
 * @param {(line: string) => void} [log]
 */
export function refusalNotifier(onRefused, log = () => {}) {
  if (typeof onRefused !== 'function') return () => {};
  return (reason, who = {}, detail = '') => {
    const clean = {};
    for (const [k, v] of Object.entries(who)) if (v !== undefined && v !== null && v !== '') clean[k] = v;
    try { onRefused({ reason, who: clean, detail: String(detail) }); } catch (e) { log(`onRefused threw: ${e?.message ?? e}`); }
  };
}
