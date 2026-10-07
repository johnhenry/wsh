/**
 * `@johnhenry/wsh/server` -- a Node host for the wsh-v1 protocol, built on the
 * same primitives the client is. Node-only (`ws`, `node:child_process`,
 * `node:fs`); the package root stays browser-safe and never imports this.
 *
 * Everything that grants a client access to the machine -- `exec`, `pty`,
 * `fs` -- is OFF unless you pass it, and with no `auth` every connection is
 * refused.
 */

import { buildAuthorizer, parseAuthorizedKeys, authMethods, FailureLimiter } from './auth.mjs';
import { loadHostKey } from './host-key.mjs';
import { spawnRunner } from './exec.mjs';
import { normalizePty } from './pty.mjs';
import { createFileAccess } from './fs.mjs';
import { createMcpHost } from './mcp.mjs';
import { createConnectionFactory, STREAM_ANNOUNCE } from './connection.mjs';

export { parseAuthorizedKeys, STREAM_ANNOUNCE };

/**
 * @param {object} [options]
 * @param {string} [options.host='127.0.0.1']
 * @param {number} [options.port=0] - 0 picks a free port; read it back from `address()`.
 * @param {object | Function} [options.auth] - See `buildAuthorizer`. Omitted = refuse everyone.
 * @param {true | object | Function} [options.exec] - `true` (shell via child_process),
 *   `{ cwd, env, shell, timeoutMs, clientEnv }`, or a custom `run(command, io)` function.
 * @param {{ spawn: Function, shell?: string, cwd?: string, env?: object }} [options.pty]
 * @param {{ root: string, readOnly?: boolean, maxFileBytes?: number }} [options.fs]
 * @param {{ tools?: object[] | object, client?: object, authorize?: Function, maxConcurrent?: number, timeoutMs?: number }} [options.mcp]
 *   MCP tools served over `McpDiscover` / `McpCall`: `tools` (`{ name, description, inputSchema, call(args, { user, signal }) }`),
 *   and/or `client` (an `@modelcontextprotocol/sdk` Client to proxy). Off unless given.
 * @param {true | { file: string } | CryptoKeyPair} [options.hostKey] - The server's own Ed25519
 *   identity, advertised (with proof of possession) so clients can pin it. See `src/host-key.mjs`.
 * @param {object} [options.auth.rateLimit] - Password-failure throttle: `{ maxFailures=5, windowMs=60000,
 *   lockoutMs=60000, failureDelayMs=250, key(info) }` (`key` defaults to the peer address).
 * @param {number} [options.bindTimeoutMs=3000]
 * @param {(line: string) => void} [options.onLog]
 * @returns {{ listen(): Promise<{address: string, port: number}>, close(): Promise<void>, address(): ({address: string, port: number} | null) }}
 */
export function createWshServer({
  host = '127.0.0.1', port = 0, auth, exec, pty, fs, hostKey, mcp, bindTimeoutMs = 3000, onLog = () => {},
} = {}) {
  let wss = null;
  let bound = null;

  let execRunner = null;
  let execOptions = {};
  if (typeof exec === 'function') {
    execRunner = exec;
  } else if (exec) {
    execOptions = exec === true ? {} : exec;
    execRunner = typeof execOptions.run === 'function' ? execOptions.run : spawnRunner(execOptions);
  }
  const ptyConfig = pty ? normalizePty(pty) : null;
  const files = fs ? createFileAccess(fs) : null;
  const mcpHost = mcp ? createMcpHost(mcp) : null;
  const methods = authMethods(auth);
  const rl = auth?.rateLimit ?? {};
  const rateLimit = {
    limiter: new FailureLimiter(rl),
    key: typeof rl.key === 'function' ? rl.key : ({ address }) => String(address ?? 'unknown'),
    failureDelayMs: rl.failureDelayMs ?? 250,
  };
  let host_ = null;

  return {
    async listen() {
      if (wss) throw new Error('createWshServer: already listening');
      let WebSocketServer;
      try {
        ({ WebSocketServer } = await import('ws'));
      } catch (err) {
        throw new Error('@johnhenry/wsh/server needs the "ws" package: npm install ws', { cause: err });
      }
      const authorize = await buildAuthorizer(auth);
      host_ = hostKey ? await loadHostKey(hostKey) : null;
      const attach = createConnectionFactory({
        authorize, execRunner, execOptions, pty: ptyConfig, files, bindTimeoutMs, log: onLog,
        methods, hostKey: host_, rateLimit, mcp: mcpHost,
      });

      wss = new WebSocketServer({ host, port });
      wss.on('connection', (ws, req) => {
        const conn = attach({
          send: (b) => { if (ws.readyState === 1) ws.send(b); },
          remote: { address: req?.socket?.remoteAddress, headers: req?.headers ?? {} },
        });
        ws.on('message', (d) => {
          const buf = Array.isArray(d) ? Buffer.concat(d) : Buffer.isBuffer(d) ? d : Buffer.from(d);
          conn.receive(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
        });
        ws.on('close', () => conn.close());
        ws.on('error', () => {});
      });
      await new Promise((resolve, reject) => {
        wss.once('listening', resolve);
        wss.once('error', reject);
      });
      const a = wss.address();
      bound = { address: a.address, port: a.port };
      return bound;
    },

    async close() {
      if (!wss) return;
      const server = wss;
      wss = null;
      bound = null;
      for (const client of server.clients) client.terminate();
      await new Promise((resolve) => server.close(resolve));
    },

    address() {
      return bound;
    },

    /** The advertised host identity (`null` until `listen()` resolves, or with no `hostKey`). */
    hostKey() {
      return host_ ? { fingerprint: host_.fingerprint, publicKey: host_.publicKey, openssh: host_.openssh } : null;
    },
  };
}
