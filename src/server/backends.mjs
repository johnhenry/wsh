/**
 * What a host can do for the client on the other end: shared by
 * `createWshServer` (clients that connect to it) and `createReverseHost`
 * (operators bridged to it by a relay), so the two cannot drift.
 *
 * The browser-safe part (injected exec function, pty, file operations, mcp) is `../host-backends.mjs`;
 * this adds what needs Node: `exec: true` / `{ cwd, env, ... }` (a shell through child_process) and
 * `fs: { root }` (a directory).
 */

import { spawnRunner } from './exec.mjs';
import { createFileAccess } from './fs.mjs';
import { resolveBackends, normalizeTargets } from '../host-backends.mjs';

/** The backends of one host (or one target) from `exec`, `pty`, `fs`, `mcp`, with the Node forms (`exec: true`, `fs: { root }`). */
function buildOwnBackends({ exec, pty, fs, mcp } = {}) {
  let hostExec = exec;
  if (exec && typeof exec !== 'function') {
    const execOptions = exec === true ? {} : exec;
    hostExec = typeof execOptions.run === 'function' ? execOptions : { ...execOptions, run: spawnRunner(execOptions) };
  }
  return resolveBackends({ exec: hostExec, pty, fs: fs && typeof fs.root === 'string' ? createFileAccess(fs) : fs, mcp });
}

/**
 * @param {{ exec?: true | object | Function, pty?: object, fs?: object, mcp?: object, targets?: object, requireTarget?: boolean }} options
 * @returns {{ execRunner: Function | null, execOptions: object, pty: object | null, files: object | null, mcp: object | null, targets: Map<string, object> | null, requireTarget: boolean }}
 */
export function buildBackends({ exec, pty, fs, mcp, targets, requireTarget } = {}) {
  return { ...buildOwnBackends({ exec, pty, fs, mcp }), ...normalizeTargets(targets, requireTarget, buildOwnBackends, 'createWshServer') };
}
