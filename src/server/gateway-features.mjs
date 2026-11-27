/**
 * Which gateway-related features a host advertises, apart from `gateway-core.mjs` (the per-connection core) so that code that only states features
 * (`hostFeatures`, in every host) does not pull the core in: a bundler can then keep the core, with the rest of the gateway session, in a chunk that is
 * loaded only when a host is given a gateway (#299). Browser-safe.
 */

import { GATEWAY_CREDIT_FEATURE, assertHalfCloseIdleMs } from '../gateway-channel.mjs';

export const ENDPOINT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** `{ name: handler | { open, authorize } }` -> a Map, or null when there are none. */
export function normalizeEndpoints(endpoints) {
  if (endpoints === undefined || endpoints === null) return null;
  if (typeof endpoints !== 'object' || Array.isArray(endpoints)) throw new TypeError('gateway.endpoints must be an object of { name: handler }');
  const map = new Map();
  for (const [name, h] of Object.entries(endpoints)) {
    if (!ENDPOINT_NAME_RE.test(name)) throw new TypeError(`gateway.endpoints: ${JSON.stringify(name)} is not a valid endpoint name (letters, digits, ".", "_", "-"; at most 64)`);
    const open = typeof h === 'function' ? h : h?.open;
    if (typeof open !== 'function') throw new TypeError(`gateway.endpoints[${JSON.stringify(name)}] needs a handler function (duplex, who) => void, or { open, authorize }`);
    if (h?.authorize !== undefined && typeof h.authorize !== 'function') throw new TypeError(`gateway.endpoints[${JSON.stringify(name)}].authorize must be a function (who) => boolean`);
    // This endpoint's own half-close idle bound (an endpoint with long-lived quiet streams wants a longer one): beats the host's.
    const halfCloseIdleMs = h?.halfCloseIdleMs === undefined || typeof h === 'function' ? undefined : assertHalfCloseIdleMs(h.halfCloseIdleMs, `gateway.endpoints[${JSON.stringify(name)}].halfCloseIdleMs`);
    map.set(name, { open, authorize: h?.authorize ?? null, halfCloseIdleMs });
  }
  return map.size === 0 ? null : map;
}

/**
 * Does this gateway serve anything at all that a client reaches through the `gateway` feature (TCP, UDP, DNS, a listener)? On the machine's network that
 * is `tcp` or reverse tunnels, as ever. On an injected network it is what the network has a method for AND the embedder switched on: a client checks
 * `gateway` for UDP, DNS and listening as well as for TCP (a released client has no feature of its own for them), so `gateway` is stated when any of them
 * can be served and a request for the rest is refused with the reason (never stated for a network that can serve none).
 */
export function gatewayServes(cfg) {
  const n = cfg.network;
  if (!n) return !!(cfg.tcp || cfg.reverse);
  return typeof n.connectTcp === 'function'
    || (!!cfg.udpOn && typeof n.openUdp === 'function')
    || (!!cfg.dnsOn && typeof n.resolve === 'function')
    || (!!cfg.reverse && typeof n.listenTcp === 'function');
}

/** Are UDP flows carried as transport datagrams when the transport has them? Only if this gateway serves UDP (on an injected network: its `openUdp` and the switch). */
export function gatewayDatagrams(cfg) {
  return !!cfg?.tcp && cfg.udpOn !== false && !!cfg.udp?.datagrams && (!cfg.network || typeof cfg.network.openUdp === 'function');
}

/** Which gateway-related features a host with this config advertises (besides what the connection adds). */
export function gatewayFeatures(cfg) {
  const f = [];
  // "gateway" also covers reverse tunnels (the Rust server lists nothing more specific for ListenRequest).
  if (gatewayServes(cfg)) f.push('gateway');
  f.push(GATEWAY_CREDIT_FEATURE);
  if (cfg.unix) f.push('gateway-unix');
  if (cfg.endpoints || cfg.targetEndpoints) f.push('gateway-endpoints');
  return f;
}
