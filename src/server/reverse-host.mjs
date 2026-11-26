/**
 * `createReverseHost` for `@johnhenry/wsh/server`: the browser-safe reverse host (`../reverse-host.mjs`, also
 * `@johnhenry/wsh/reverse`) with the Node-only backends added -- `exec: true` (a shell through child_process)
 * and `fs: { root }` (a directory), the `wsh-host` / `wsh-fs` rpc built-ins, and (#289) a `gateway`: TCP, and
 * when the owner turns them on UDP, DNS and reverse tunnels, from THIS machine for an operator behind the relay.
 * The reverse host itself lives in `../reverse-host.mjs`.
 */

import { createReverseHostWith } from '../reverse-host.mjs';
import { buildBackends } from './backends.mjs';
import { createRpcHost } from './rpc.mjs';
import { normalizeGateway, createGatewaySession } from './gateway.mjs';
import { GATEWAY_FAIL } from './gateway-core.mjs';
import { MSG, gatewayFail } from '../messages.gen.mjs';

const GATEWAY_OPTIONS = new Set([
  'allow', 'allowPrivate', 'maxConnections', 'maxBufferedBytes', 'maxClientBufferedBytes', 'connectTimeoutMs', 'halfCloseIdleMs',
  'halfCloseProbeMs', 'socks', 'udp', 'dns', 'reverse', 'udpIdleMs', 'log', 'trustRelayIdentity',
]);

/**
 * The gateway of a reverse host (#289), or null. Off unless `gateway` is given, and then the same default-deny policy as a
 * `createWshServer` gateway (`allow`, `allowPrivate`, the bounds, `socks`), with these differences: `udp`, `dns` (ResolveDns) and
 * `reverse` (ListenRequest, reverse tunnels) are each OFF unless given (`udp: true | { ...bounds }`, `dns: true`, `reverse: true | { ... }`),
 * and `unix`, `endpoints` and `tcp: false` are refused (the relay carries none of them).
 * @param {unknown} opts
 */
function buildGateway(opts, hostOptions = {}) {
  if (opts === undefined || opts === null || opts === false) return null;
  if (opts === true || typeof opts !== 'object' || Array.isArray(opts)) throw new TypeError('createReverseHost: gateway needs an explicit allow list (default deny): { allow: ["host:port", ...] }');
  for (const k of Object.keys(opts)) {
    if (k === 'unix' || k === 'endpoints' || k === 'tcp') throw new TypeError(`createReverseHost: gateway.${k} is not carried by a relay; a reverse host serves TCP, and UDP, DNS and reverse tunnels when turned on`);
    if (!GATEWAY_OPTIONS.has(k)) throw new TypeError(`createReverseHost: unknown gateway option "${k}"`);
  }
  if (opts.dns !== undefined && typeof opts.dns !== 'boolean') throw new TypeError('createReverseHost: gateway.dns must be a boolean');
  if (opts.trustRelayIdentity !== undefined && typeof opts.trustRelayIdentity !== 'boolean') throw new TypeError('createReverseHost: gateway.trustRelayIdentity must be a boolean');
  // Who an operator is, on a bridge that is not sealed, is whatever the relay stamps on its messages: a relay can open what any accepted
  // operator could. So a gateway starts only when the owner either has operators PROVE themselves and seal the bridge (`requireOperatorProof`),
  // or says in so many words that they trust the relay's word about who is asking.
  if (hostOptions.requireOperatorProof !== true && opts.trustRelayIdentity !== true) {
    throw new TypeError('createReverseHost: a gateway needs requireOperatorProof: true (operators prove themselves and the bridge is sealed), or gateway.trustRelayIdentity: true to say you trust the relay\'s word about who is asking (a relay can then open what an accepted operator could)');
  }
  const udpOn = opts.udp !== undefined && opts.udp !== false && opts.udp !== null;
  const dnsOn = opts.dns === true;
  const { udp, dns, trustRelayIdentity, ...rest } = opts;
  void trustRelayIdentity;
  const cfg = normalizeGateway({ ...rest, ...(udpOn ? { udp: opts.udp } : {}) });
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

/** @param {Parameters<typeof import('../reverse-host.mjs').createReverseHost>[0]} [options] - see `../reverse-host.mjs` */
export function createReverseHost(options = {}) {
  const backends = buildBackends(options);
  const rpc = options.rpc === undefined || options.rpc === null ? null
    : createRpcHost(options.rpc, { files: backends.files, maxMessageBytes: options.rpcMaxMessageBytes, maxInflight: options.rpcMaxInflight });
  return createReverseHostWith(options, { ...backends, rpc, gateway: buildGateway(options.gateway, options) });
}
