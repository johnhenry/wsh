/**
 * The codes of `GatewayFail` as data, in one place (browser-safe, no Node import). A host puts one of these numbers in `GatewayFail.code`
 * when a gateway request (`OpenTcp`, `OpenUdp`, `ResolveDns`, `OpenEndpoint`, `OpenUnix`) fails; a client reads it back as
 * `GatewayError.code`. The Node gateway, the page host and the memory host send them from this table, and `@johnhenry/browsermesh-netway`
 * decodes them (it keeps a copy by hand: it can import this one instead, the names and numbers are the same).
 *
 * The table is a contract: a code is never reused for something else and a number is never renumbered. A new code is added at the end.
 */

/** Wire codes of `GatewayFail`, by name. */
export const GATEWAY_FAIL = Object.freeze({
  CONNECTION_REFUSED: 1, HOST_UNREACHABLE: 2, DNS_FAILED: 3, POLICY_DENIED: 4, TIMEOUT: 5, CLOSED: 6, QUEUE_FULL: 7,
});

/**
 * The same codes with their meaning. `alsoSentAs` lists a second name a different implementation gives the same number: the Rust
 * `wsh-server` sends `5` for "gateway disabled" (and `spec/wsh-v1.yaml` lists `5=GATEWAY_DISABLED`), where the Node gateway sends it for a
 * timeout. A client that reads `5` therefore should say "timed out or disabled" rather than only one of the two.
 */
export const GATEWAY_FAIL_TABLE = Object.freeze([
  Object.freeze({ name: 'CONNECTION_REFUSED', code: 1, meaning: 'The destination actively refused the connection (nothing listens there).' }),
  Object.freeze({ name: 'HOST_UNREACHABLE', code: 2, meaning: 'The destination could not be reached on the network (no route, connect failed, socket error).' }),
  Object.freeze({ name: 'DNS_FAILED', code: 3, meaning: 'The name did not resolve, or is not a valid name.' }),
  Object.freeze({ name: 'POLICY_DENIED', code: 4, meaning: 'The host refused by policy: the key lacks the capability, the address is not allowed, the endpoint or target does not exist or is not for this caller, or the request was malformed or reused an id.' }),
  Object.freeze({ name: 'TIMEOUT', code: 5, alsoSentAs: Object.freeze(['GATEWAY_DISABLED']), meaning: 'The host did not finish in time. The Rust wsh-server sends this number when its gateway is disabled.' }),
  Object.freeze({ name: 'CLOSED', code: 6, meaning: 'The gateway connection was closed before the operation finished.' }),
  Object.freeze({ name: 'QUEUE_FULL', code: 7, meaning: 'The host holds too many gateway connections or too much unsent data, and takes no more for now.' }),
]);

/**
 * Codes a client gives its own `GatewayError` when it never asked the host: they are not on the wire, and a host never sends them.
 * `UNSUPPORTED`: the host did not advertise the feature the call needs.
 */
export const GATEWAY_FAIL_LOCAL = Object.freeze({ UNSUPPORTED: 0 });

/**
 * The name of a code (wire or client-local), or `null` for a number that is not in the table.
 * @param {number} code
 * @returns {string | null}
 */
export function gatewayFailName(code) {
  for (const row of GATEWAY_FAIL_TABLE) if (row.code === code) return row.name;
  for (const [name, value] of Object.entries(GATEWAY_FAIL_LOCAL)) if (value === code) return name;
  return null;
}
