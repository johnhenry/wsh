/**
 * `@johnhenry/wsh/gateway` -- the gateway of a wsh host as an entry point of its own, with no `node:*` import (a test bundles it for the
 * browser). It is what `createMemoryHost({ gateway })` and the browser-safe `createReverseHost({ gateway })` serve, for an embedder
 * that builds a host of its own on `@johnhenry/wsh/host` and wants the same gateway: the TCP, DNS, UDP and listen opcodes with the destination
 * policy, the connection cap, credit flow control, half-close rules and UDP bounds, over a NETWORK THE EMBEDDER SUPPLIES (#299):
 *
 * ```js
 * import { createConnectionFactory } from '@johnhenry/wsh/host';
 * import { normalizeGateway, createGatewaySession } from '@johnhenry/wsh/gateway';
 *
 * const gateway = normalizeGateway({
 *   network: {
 *     async connectTcp({ host, port, signal }) { return { readable, writable }; }, // web streams of bytes; `host` is an IP address
 *     async resolve({ name, family, signal }) { return ['10.0.0.5']; },
 *   },
 *   allow: ['db.internal:5432'],
 *   allowPrivate: ['10.0.0.0/8'], // the network's own address space, named by the embedder
 * });
 * const attach = createConnectionFactory({ ...backends, gateway, createGatewaySession });
 * ```
 *
 * The embedder who has no network of its own to supply (a Node process) uses `createWshServer({ gateway })` from `@johnhenry/wsh/server`,
 * whose default network is the machine's.
 */

import { normalizeGateway as normalizeSessionGateway } from './server/gateway-session.mjs';

export {
  normalizeNetwork, createGatewaySession, gatewayFeatures, destinationAllowed, addressPermitted, gatewayPolicy,
  normalizeReverse, reversePortAllowed, normalizeUdp, parseSocks,
} from './server/gateway-session.mjs';

/**
 * Validate and normalise a gateway configuration. Where there are no sockets (a page, a Worker: no `process.versions.node`) the configuration MUST name a
 * `network`: without one the session would reach for the machine's sockets, which are not there, so it is refused up front, in words, instead of failing
 * later at a `node:` import. In Node a configuration without a network is the machine's, as for `createWshServer` (which is what to use there).
 */
export function normalizeGateway(opts) {
  const hasNode = typeof process !== 'undefined' && !!process.versions?.node;
  if (!hasNode && opts && typeof opts === 'object' && (opts.network === undefined || opts.network === null)) {
    throw new TypeError('normalizeGateway: this environment has no sockets to dial, so the gateway needs a network: { network: { connectTcp, resolve, openUdp, listenTcp }, allow: [...] } (see @johnhenry/wsh/gateway)');
  }
  return normalizeSessionGateway(opts);
}
export { GATEWAY_FAIL } from './server/gateway-core.mjs';
export { GATEWAY_FAIL_TABLE, gatewayFailName } from './gateway-errors.mjs';
