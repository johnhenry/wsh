/**
 * The gateway of a reverse host (#289, #299), built from the browser-safe session (`server/gateway-session.mjs`): the Node
 * `createReverseHost` (`@johnhenry/wsh/server`, which dials the machine's network unless given `gateway.network`) and the browser-safe
 * one (`@johnhenry/wsh/reverse`, which dials only a network its embedder supplies, and loads this module by a dynamic import only when it
 * is given a gateway) share it. No `node:*` import.
 */

import { normalizeGateway, createGatewaySession } from './server/gateway-session.mjs';
import { GATEWAY_FAIL } from './server/gateway-core.mjs';
import { MSG, gatewayFail } from './messages.gen.mjs';
import { checkGatewayShape, checkReverseTrust } from './gateway-shape.mjs';

const GATEWAY_OPTIONS = new Set([
  'allow', 'allowPrivate', 'maxConnections', 'maxBufferedBytes', 'maxClientBufferedBytes', 'connectTimeoutMs', 'halfCloseIdleMs',
  'halfCloseProbeMs', 'socks', 'udp', 'dns', 'reverse', 'udpIdleMs', 'log', 'trustRelayIdentity', 'network',
]);

/**
 * The gateway of a reverse host (#289), or null. Off unless `gateway` is given, and then the same default-deny policy as a
 * `createWshServer` gateway (`allow`, `allowPrivate`, the bounds, `socks`), with these differences: `udp`, `dns` (ResolveDns) and
 * `reverse` (ListenRequest, reverse tunnels) are each OFF unless given (`udp: true | { ...bounds }`, `dns: true`, `reverse: true | { ... }`),
 * and `unix`, `endpoints` and `tcp: false` are refused (the relay carries none of them). With `network` (#299) the host dials that network
 * instead of the machine's, and UDP, DNS and listening each need the owner's switch and the network's method.
 * @param {unknown} opts
 * @param {{ requireOperatorProof?: boolean }} [hostOptions]
 * @param {{ who?: string, requireNetwork?: boolean }} [how]
 */
export function buildReverseGateway(opts, hostOptions = {}, { who = 'createReverseHost', requireNetwork = false } = {}) {
  if (opts === undefined || opts === null || opts === false) return null;
  if (opts === true || typeof opts !== 'object' || Array.isArray(opts)) throw new TypeError(`${who}: gateway needs an explicit allow list (default deny): { allow: ["host:port", ...] }`);
  for (const k of Object.keys(opts)) {
    if (k === 'unix' || k === 'endpoints' || k === 'tcp') throw new TypeError(`${who}: gateway.${k} is not carried by a relay; a reverse host serves TCP, and UDP, DNS and reverse tunnels when turned on`);
    if (!GATEWAY_OPTIONS.has(k)) throw new TypeError(`${who}: unknown gateway option "${k}"`);
  }
  if (requireNetwork) checkGatewayShape(opts, who);
  if (opts.dns !== undefined && typeof opts.dns !== 'boolean') throw new TypeError(`${who}: gateway.dns must be a boolean`);
  if (opts.trustRelayIdentity !== undefined && typeof opts.trustRelayIdentity !== 'boolean') throw new TypeError(`${who}: gateway.trustRelayIdentity must be a boolean`);
  // Who an operator is, on a bridge that is not sealed, is whatever the relay stamps on its messages: a relay can open what any accepted
  // operator could. So a gateway starts only when the owner either has operators PROVE themselves and seal the bridge (`requireOperatorProof`),
  // or says in so many words that they trust the relay's word about who is asking.
  checkReverseTrust(opts, hostOptions, who);
  const udpOn = opts.udp !== undefined && opts.udp !== false && opts.udp !== null;
  const dnsOn = opts.dns === true;
  const { udp, dns, trustRelayIdentity, ...rest } = opts;
  void trustRelayIdentity; void dns;
  const cfg = normalizeGateway({ ...rest, ...(udpOn ? { udp } : {}), dns: dnsOn });
  /** The session of one bridged operator: the shared gateway session, with the owner's separate switches in front of it. */
  const session = (c, send, log, ctx) => {
    const inner = createGatewaySession(c, send, log, ctx);
    const refuse = (m, what) => send(gatewayFail({ gatewayId: m.gateway_id, code: GATEWAY_FAIL.POLICY_DENIED, message: `${what} is not enabled on this reverse host` }));
    const guarded = Object.create(inner); // the session's own members (some are getters) stay as they are
    guarded.handle = async (m) => {
      if (m.type === MSG.OPEN_UDP && !udpOn) { await refuse(m, 'UDP'); return true; }
      if (m.type === MSG.RESOLVE_DNS && !dnsOn) { await refuse(m, 'name resolution'); return true; }
      return inner.handle(m);
    };
    return guarded;
  };
  return { cfg, createGatewaySession: session };
}
