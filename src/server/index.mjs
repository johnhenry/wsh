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
import { buildBackends } from './backends.mjs';
import { SessionRegistry } from './sessions.mjs';
import { RelayHub } from './relay.mjs';
import { startWebTransport } from './webtransport.mjs';
import { createConnectionFactory, STREAM_ANNOUNCE } from './connection.mjs';
import { createRpcHost, mcpServerAdapter } from './rpc.mjs';

export { parseAuthorizedKeys, STREAM_ANNOUNCE, mcpServerAdapter };
export { createReverseHost } from './reverse-host.mjs';
export { generateSelfSignedCertificate } from './self-signed.mjs';

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
 * @param {{ port?: number, host?: string, path?: string, cert?: string, privKey?: string, selfSigned?: boolean | object, secret?: string }} [options.webTransport]
 *   Also listen for WebTransport (HTTP/3 over UDP) clients, with the same auth and features as the WebSocket
 *   listener. `cert` / `privKey` are PEM; `selfSigned: true` makes a 13-day ECDSA P-256 certificate and exposes its
 *   SHA-256 through `webTransport()` for the client's `serverCertificateHashes`. Needs the optional peers
 *   `@fails-components/webtransport` and `@fails-components/webtransport-transport-http3-quiche`. Off unless given.
 * @param {{ canRegister?: Function, canConnect?: Function, maxPeers?: number, connectTimeoutMs?: number }} [options.relay]
 *   Act as a relay: peers register (`ReverseRegister`, a signed record), operators list and connect to them
 *   (`ReverseList` / `ReverseConnect`) and traffic is carried between them as `RelayForward`. Default deny:
 *   `canRegister(who, record)` and `canConnect(from, to)` must both be given and return true. See `createReverseHost`.
 * @param {true | { detachTtlMs?: number, maxDetached?: number, ringBytes?: number, sessionSecret?: string | Uint8Array }} [options.sessions]
 *   Keep pty/exec sessions alive across disconnects so a client can `resumeSession()` / `attachSession()`
 *   them: a per-server registry, a ring buffer of the newest `ringBytes` (default 1 MiB) of output, and
 *   `detachTtlMs` (default 300000; 0 = kill on disconnect) / `maxDetached` (default 16) bounds. Off unless given.
 * @param {Record<string, true | object | Function>} [options.rpc] - Typed RPC channels (wsh #85): `{ [protocol]: handler }`.
 *   Built-ins: `'wsh-host': true`, `'wsh-fs': true` (confined by `fs`) or `{ root, readOnly?, maxFileBytes? }`; anything else is a
 *   function `(channel, ctx) => void` run per opened channel -- e.g. `mcp: mcpServerAdapter(server)`. Each protocol is
 *   advertised as `rpc-protocol:<name>`. Off unless given.
 * @param {number} [options.rpcMaxMessageBytes=1048576] - Largest single rpc message (advertised as `rpc-max-message:<n>`).
 * @param {number} [options.rpcMaxInflight=64] - Concurrent requests per rpc channel before `-32002`.
 * @param {string | Uint8Array} [options.sessionSecret] - Alias for `sessions.sessionSecret`.
 * @param {true | { file: string } | CryptoKeyPair} [options.hostKey] - The server's own Ed25519
 *   identity, advertised (with proof of possession) so clients can pin it. See `src/host-key.mjs`.
 * @param {object} [options.auth.rateLimit] - Password-failure throttle: `{ maxFailures=5, windowMs=60000,
 *   lockoutMs=60000, failureDelayMs=250, key(info) }` (`key` defaults to the peer address).
 * @param {number} [options.bindTimeoutMs=3000]
 * @param {(line: string) => void} [options.onLog]
 * @returns {{ listen(): Promise<{address: string, port: number}>, close(): Promise<void>, address(): ({address: string, port: number} | null) }}
 */
export function createWshServer({
  host = '127.0.0.1', port = 0, auth, exec, pty, fs, hostKey, mcp, rpc, rpcMaxMessageBytes, rpcMaxInflight, sessions, sessionSecret, relay, webTransport, bindTimeoutMs = 3000, onLog = () => {},
} = {}) {
  let wss = null;
  let bound = null;

  const { execRunner, execOptions, pty: ptyConfig, files, mcp: mcpHost } = buildBackends({ exec, pty, fs, mcp });
  const methods = authMethods(auth);
  const rl = auth?.rateLimit ?? {};
  const rateLimit = {
    limiter: new FailureLimiter(rl),
    key: typeof rl.key === 'function' ? rl.key : ({ address }) => String(address ?? 'unknown'),
    failureDelayMs: rl.failureDelayMs ?? 250,
  };
  const rpcHost = rpc ? createRpcHost(rpc, { files, maxMessageBytes: rpcMaxMessageBytes, maxInflight: rpcMaxInflight }) : null;
  let host_ = null;
  let registry = null;
  let hub = null;
  let wt = null;
  const sessionOptions = sessions ? (sessions === true ? {} : sessions) : null;

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
      if (sessionOptions) {
        const secret = sessionOptions.sessionSecret ?? sessionSecret;
        registry = new SessionRegistry({
          secret: secret === undefined ? undefined : Buffer.from(secret),
          detachTtlMs: sessionOptions.detachTtlMs,
          maxDetached: sessionOptions.maxDetached,
          ringBytes: sessionOptions.ringBytes,
          log: onLog,
        });
      }
      if (relay) hub = new RelayHub({ ...relay, log: onLog });
      const attach = createConnectionFactory({
        authorize, execRunner, execOptions, pty: ptyConfig, files, bindTimeoutMs, log: onLog,
        methods, hostKey: host_, rateLimit, mcp: mcpHost, rpc: rpcHost, sessions: registry, relay: hub,
      });

      wss = new WebSocketServer({ host, port });
      wss.on('connection', (ws, req) => {
        const conn = attach({
          send: (b) => { if (ws.readyState === 1) ws.send(b); },
          remote: { address: req?.socket?.remoteAddress, headers: req?.headers ?? {} },
          closeTransport: () => ws.close(1000),
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
      if (webTransport) {
        try {
          wt = await startWebTransport({ options: webTransport, host, attach, log: onLog });
        } catch (err) {
          await this.close();
          throw err;
        }
      }
      return bound;
    },

    async close() {
      if (!wss) return;
      const server = wss;
      wss = null;
      bound = null;
      for (const client of server.clients) client.terminate();
      await wt?.close();
      wt = null;
      await new Promise((resolve) => server.close(resolve));
      registry?.closeAll();
      registry = null;
      hub?.closeAll();
      hub = null;
    },

    address() {
      return bound;
    },

    /**
     * The WebTransport listener, or `null` (not configured, or `listen()` has not resolved). `certificateHash` is
     * the SHA-256 of a `selfSigned` certificate, for the client's `serverCertificateHashes`; `null` for your own.
     */
    webTransport() {
      if (!wt) return null;
      return {
        port: wt.port, host: wt.host, path: wt.path, url: `https://${wt.host.includes(':') ? `[${wt.host}]` : wt.host}:${wt.port}${wt.path}`,
        certificateHash: wt.certificateHash, certificateHashHex: wt.certificateHashHex, notAfter: wt.notAfter,
      };
    },

    /** Fingerprints of the peers currently registered with this relay (`[]` when it is not one). */
    peerFingerprints() {
      return hub ? hub.peerFingerprints() : [];
    },

    /** The advertised host identity (`null` until `listen()` resolves, or with no `hostKey`). */
    hostKey() {
      return host_ ? { fingerprint: host_.fingerprint, publicKey: host_.publicKey, openssh: host_.openssh } : null;
    },
  };
}
