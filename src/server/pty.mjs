/**
 * `pty` support for `@johnhenry/wsh/server`.
 *
 * A pseudo-terminal needs a native addon, which this package deliberately
 * does not depend on: the host application injects one. `pty.spawn` is
 * `node-pty`'s `spawn(file, args, options)` (or anything shaped like it):
 * it returns `{ onData(cb), onExit(cb), write(data), resize(cols, rows),
 * kill(signal?) }`.
 */

/**
 * @param {{ spawn: Function, shell?: string, cwd?: string, env?: object, term?: string }} pty
 */
export function normalizePty(pty) {
  if (!pty || typeof pty.spawn !== 'function') {
    throw new TypeError('createWshServer: pty.spawn must be a function (e.g. node-pty\'s spawn)');
  }
  return {
    spawn: pty.spawn,
    shell: pty.shell ?? process.env.SHELL ?? '/bin/sh',
    cwd: pty.cwd,
    env: pty.env,
    term: pty.term ?? 'xterm-256color',
  };
}
