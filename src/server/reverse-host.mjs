/**
 * `createReverseHost` for `@johnhenry/wsh/server`: the browser-safe reverse host (`../reverse-host.mjs`, also
 * `@johnhenry/wsh/reverse`) with the Node-only backends added -- `exec: true` (a shell through child_process)
 * and `fs: { root }` (a directory), the `wsh-host` / `wsh-fs` rpc built-ins, and (#289) a `gateway`: TCP, and
 * when the owner turns them on UDP, DNS and reverse tunnels, from THIS machine for an operator behind the relay
 * (or, with `gateway.network`, over a network the embedder supplies, #299).
 * The reverse host itself lives in `../reverse-host.mjs`.
 */

import { createReverseHostWith } from '../reverse-host.mjs';
import { buildBackends } from './backends.mjs';
import { createRpcHost } from './rpc.mjs';
import { buildReverseGateway } from '../reverse-gateway.mjs';

/** @param {Parameters<typeof import('../reverse-host.mjs').createReverseHost>[0]} [options] - see `../reverse-host.mjs` */
export function createReverseHost(options = {}) {
  const backends = buildBackends(options);
  const rpc = options.rpc === undefined || options.rpc === null ? null
    : createRpcHost(options.rpc, { files: backends.files, maxMessageBytes: options.rpcMaxMessageBytes, maxInflight: options.rpcMaxInflight });
  return createReverseHostWith(options, { ...backends, rpc, gateway: buildReverseGateway(options.gateway, options) });
}
