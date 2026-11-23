/**
 * `createReverseHost` for `@johnhenry/wsh/server`: the browser-safe reverse host (`../reverse-host.mjs`, also
 * `@johnhenry/wsh/reverse`) with the Node-only backends added -- `exec: true` (a shell through child_process)
 * and `fs: { root }` (a directory). The reverse host itself lives in `../reverse-host.mjs`.
 */

import { createReverseHostWith } from '../reverse-host.mjs';
import { buildBackends } from './backends.mjs';

/** @param {Parameters<typeof import('../reverse-host.mjs').createReverseHost>[0]} [options] - see `../reverse-host.mjs` */
export function createReverseHost(options = {}) {
  return createReverseHostWith(options, buildBackends(options));
}
