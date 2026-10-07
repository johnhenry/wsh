/**
 * Default `exec` runner for `@johnhenry/wsh/server`: runs the command through
 * a shell with `node:child_process` and wires it to the session `io`.
 *
 * A custom runner has the same shape -- `run(command, io) => Promise<exitCode>`
 * -- so a restricted host (no real shell) can replace this wholesale.
 */

import { spawn } from 'node:child_process';
import { constants } from 'node:os';

/**
 * @param {{ cwd?: string, env?: object, shell?: boolean | string }} [opts]
 * @returns {(command: string, io: ExecIo) => Promise<number>}
 */
export function spawnRunner({ cwd, env, shell = true } = {}) {
  return (command, io) => new Promise((resolve) => {
    let proc;
    try {
      proc = spawn(command, {
        shell,
        cwd,
        env: { ...(env ?? process.env), ...io.env },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (err) {
      io.write(`wsh: ${err.message}\n`).finally(() => resolve(127));
      return;
    }

    const out = (chunk) => { io.write(new Uint8Array(chunk)); };
    proc.stdout.on('data', out);
    proc.stderr.on('data', out);
    proc.stdin.on('error', () => { /* process exited before stdin drained */ });
    io.onInput((bytes) => { try { proc.stdin.write(bytes); } catch { /* exited */ } });
    io.onInputEnd(() => { try { proc.stdin.end(); } catch { /* exited */ } });
    io.onSignal((name) => { try { proc.kill(`SIG${name}`); } catch { /* exited or unknown */ } });
    io.signal.addEventListener('abort', () => { try { proc.kill('SIGTERM'); } catch { /* exited */ } }, { once: true });

    proc.on('error', (err) => {
      io.write(`wsh: ${err.message}\n`).finally(() => resolve(127));
    });
    proc.on('close', (code, signal) => {
      resolve(code ?? (signal ? 128 + (constants.signals[signal] ?? 0) : 0));
    });
  });
}

/**
 * @typedef {object} ExecIo
 * @property {string} user - Authenticated username.
 * @property {Record<string,string>} env - Environment requested by the client.
 * @property {number} cols
 * @property {number} rows
 * @property {AbortSignal} signal - Aborts on client Close, disconnect or timeout.
 * @property {(data: Uint8Array | string) => Promise<void>} write - Send output; resolves when flow control accepts it.
 * @property {(cb: (bytes: Uint8Array) => void) => void} onInput - Client stdin.
 * @property {(cb: () => void) => void} onInputEnd - Client closed stdin.
 * @property {(cb: (name: string) => void) => void} onSignal - Named signal (`INT`, `TERM`, ...).
 */
