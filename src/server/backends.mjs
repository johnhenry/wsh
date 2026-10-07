/**
 * What a host can do for the client on the other end: shared by
 * `createWshServer` (clients that connect to it) and `createReverseHost`
 * (operators bridged to it by a relay), so the two cannot drift.
 */

import { spawnRunner } from './exec.mjs';
import { normalizePty } from './pty.mjs';
import { createFileAccess } from './fs.mjs';
import { createMcpHost } from './mcp.mjs';

/**
 * @param {{ exec?: true | object | Function, pty?: object, fs?: object, mcp?: object }} options
 * @returns {{ execRunner: Function | null, execOptions: object, pty: object | null, files: object | null, mcp: object | null }}
 */
export function buildBackends({ exec, pty, fs, mcp } = {}) {
  let execRunner = null;
  let execOptions = {};
  if (typeof exec === 'function') {
    execRunner = exec;
  } else if (exec) {
    execOptions = exec === true ? {} : exec;
    execRunner = typeof execOptions.run === 'function' ? execOptions.run : spawnRunner(execOptions);
  }
  return {
    execRunner,
    execOptions,
    pty: pty ? normalizePty(pty) : null,
    files: fs ? createFileAccess(fs) : null,
    mcp: mcp ? createMcpHost(mcp) : null,
  };
}
