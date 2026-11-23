/**
 * Policy of the Node host's TCP reverse tunnels (`ListenRequest`, #98): the host binds a port on the client's behalf
 * and hands each inbound connection to the client. This is the dangerous direction (it puts a port of the HOST on the
 * network), so everything here is explicit and bounded:
 *
 *  - OFF unless `gateway.reverse` is given (a separate switch from outbound gateway use: `allow` has no say here).
 *  - The host binds `bindAddr` (default 127.0.0.1). The `bind_addr` the client sends is IGNORED unless it is one of the
 *    addresses the operator listed in `allowBindAddrs`; this matches the Rust server's `reverse_bind_addr`.
 *  - `ports`: which ports a client may ask for, numbers and `"lo-hi"` ranges. The default is `[0, "1024-65535"]`
 *    (ephemeral, or any unprivileged port). A list you give REPLACES the default, so nothing is allowed that it does not
 *    name, and a port below 1024 is allowed only when listed.
 *  - Bounds: `maxListeners` per client, `maxConnectionsPerListener`, `backlog` of the listening socket, `idleMs` of an
 *    accepted connection.
 *
 * Imports no Node built-in (the address parser it uses is pure).
 */

import { parseIp } from './address-guard.mjs';

export const DEFAULT_REVERSE = Object.freeze({
  bindAddr: '127.0.0.1',
  maxListeners: 4,
  maxConnectionsPerListener: 16,
  backlog: 8,
  idleMs: 300_000,
});

const DEFAULT_PORTS = [[0, 0], [1024, 65535]];

function parsePortRule(rule) {
  const bad = () => new TypeError(`gateway.reverse.ports: ${JSON.stringify(rule)} is not a port (0-65535) or a "lo-hi" range`);
  if (typeof rule === 'number') {
    if (!Number.isInteger(rule) || rule < 0 || rule > 65535) throw bad();
    return [rule, rule];
  }
  if (typeof rule !== 'string') throw bad();
  const m = /^\s*(\d{1,5})\s*(?:-\s*(\d{1,5})\s*)?$/.exec(rule);
  if (!m) throw bad();
  const lo = Number(m[1]);
  const hi = m[2] === undefined ? lo : Number(m[2]);
  if (lo > 65535 || hi > 65535 || lo > hi) throw bad();
  return [lo, hi];
}

const positive = (v, what, min = 1) => {
  if (!Number.isInteger(v) || v < min) throw new TypeError(`gateway.reverse.${what} must be an integer of at least ${min}`);
  return v;
};

/**
 * @param {unknown} opts  `gateway.reverse`: `true`, or `{ bindAddr, allowBindAddrs, ports, maxListeners, maxConnectionsPerListener, backlog, idleMs }`
 * @returns {null | { bindAddr: string, allowBindAddrs: string[], ports: Array<[number, number]>, maxListeners: number, maxConnectionsPerListener: number, backlog: number, idleMs: number }}
 */
export function normalizeReverse(opts) {
  if (opts === undefined || opts === null || opts === false) return null;
  if (opts === true) opts = {};
  if (typeof opts !== 'object' || Array.isArray(opts)) throw new TypeError('gateway.reverse must be true or an options object');
  if (opts.enabled === false) return null;
  const bindAddr = opts.bindAddr ?? DEFAULT_REVERSE.bindAddr;
  if (typeof bindAddr !== 'string' || !parseIp(bindAddr)) throw new TypeError('gateway.reverse.bindAddr must be an IP address (e.g. "127.0.0.1"), not a name');
  const allowBindAddrs = opts.allowBindAddrs ?? [];
  if (!Array.isArray(allowBindAddrs) || allowBindAddrs.some((a) => typeof a !== 'string' || !parseIp(a))) {
    throw new TypeError('gateway.reverse.allowBindAddrs must be an array of IP addresses (no names, no wildcard)');
  }
  let ports = DEFAULT_PORTS;
  if (opts.ports !== undefined) {
    if (!Array.isArray(opts.ports)) throw new TypeError('gateway.reverse.ports must be an array of ports and "lo-hi" ranges');
    ports = opts.ports.map(parsePortRule);
  }
  return {
    bindAddr,
    allowBindAddrs: [...allowBindAddrs],
    ports,
    maxListeners: positive(opts.maxListeners ?? DEFAULT_REVERSE.maxListeners, 'maxListeners', 0),
    maxConnectionsPerListener: positive(opts.maxConnectionsPerListener ?? DEFAULT_REVERSE.maxConnectionsPerListener, 'maxConnectionsPerListener'),
    backlog: positive(opts.backlog ?? DEFAULT_REVERSE.backlog, 'backlog'),
    idleMs: positive(opts.idleMs ?? DEFAULT_REVERSE.idleMs, 'idleMs', 0),
  };
}

/** May a client ask for this port? */
export function reversePortAllowed(reverse, port) {
  return Number.isInteger(port) && port >= 0 && port <= 65535 && reverse.ports.some(([lo, hi]) => port >= lo && port <= hi);
}

/** The refusal sentence for a port the policy does not allow. */
export function reversePortRefusal(reverse, port) {
  if (port < 1024 && !reverse.ports.some(([lo, hi]) => lo <= port && port <= hi)) {
    return `port ${port} is not allowed by the reverse-tunnel policy (ports below 1024 must be listed explicitly by the host operator)`;
  }
  return `port ${port} is not allowed by the reverse-tunnel policy`;
}

/** The address to bind: the client's choice only if the operator listed it, else the configured one. */
export function reverseBindAddress(reverse, requested) {
  if (typeof requested === 'string' && reverse.allowBindAddrs.some((a) => a.toLowerCase() === requested.toLowerCase())) return requested;
  return reverse.bindAddr;
}
