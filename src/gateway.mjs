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

export {
  normalizeGateway, normalizeNetwork, createGatewaySession, gatewayFeatures, destinationAllowed, addressPermitted, gatewayPolicy,
  normalizeReverse, reversePortAllowed, normalizeUdp, parseSocks,
} from './server/gateway-session.mjs';
export { GATEWAY_FAIL } from './server/gateway-core.mjs';
export { GATEWAY_FAIL_TABLE, gatewayFailName } from './gateway-errors.mjs';
