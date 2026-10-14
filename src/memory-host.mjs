/**
 * `@johnhenry/wsh/memory` -- a wsh host that lives in the same JavaScript realm as its clients, with no sockets, no
 * ports and no Node. Browser-safe (a page, a Worker, Deno, Bun, Node): it imports nothing from `node:*`, and a test
 * (`test/memory-host.test.mjs`) keeps it that way. For demos, docs and tests of an application that talks wsh.
 *
 * It is the real protocol end to end -- the same connection handler `createWshServer` runs (handshake, Ed25519 or
 * password auth, exec channels, MCP tools, extensions), speaking QMux over a pair of in-memory WebSocket-like
 * sockets -- so what a client does here is what it does against a server. It serves what a browser can: `exec` as a
 * function you provide (there is no shell), `mcp` tools, `extensions`. Not available: `pty`, `fs`, `gateway`, `relay`,
 * `sessions`, `rpc`, `hostKey`, WebTransport (they need Node; use `@johnhenry/wsh/server`).
 *
 * ```js
 * import { createMemoryHost } from '@johnhenry/wsh/memory';
 * const host = createMemoryHost({
 *   auth: { authorizedKeys: [rawPublicKey] },
 *   exec: async (command, io) => { await io.write(`you ran: ${command}\n`); return 0; },
 * });
 * const client = await host.connect({ username: 'demo', keyPair });
 * ```
 */

import { WshClient } from './client.mjs';
import { WebSocketTransport } from './transport-ws.mjs';
import { createConnectionFactory } from './server/connection.mjs';
import { buildAuthorizer, authMethods, FailureLimiter } from './server/auth.mjs';
import { createMcpHost } from './server/mcp.mjs';
import { bindSocket } from './server/socket.mjs';

const CONNECTING = 0;
const OPEN = 1;
const CLOSING = 2;
const CLOSED = 3;

/** The URL to hand `client.connect()` (the host ignores it; it only has to look like a WebSocket URL). */
const MEMORY_URL = 'ws://memory.invalid/';

function event(type, props) {
  const ev = new Event(type);
  Object.assign(ev, props);
  return ev;
}

/** One end of an in-memory socket pair: just enough WebSocket for `WebSocketTransport` and `bindSocket`. */
class MemorySocket extends EventTarget {
  static CONNECTING = CONNECTING;
  static OPEN = OPEN;
  static CLOSING = CLOSING;
  static CLOSED = CLOSED;

  readyState = CONNECTING;
  binaryType = 'arraybuffer';
  /** @type {MemorySocket | null} */
  peer = null;

  send(data) {
    if (this.readyState !== OPEN) throw new Error('WebSocket is not open');
    if (typeof data === 'string') return; // wsh frames are binary
    const view = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    const copy = view.slice().buffer;
    const peer = this.peer;
    queueMicrotask(() => { if (peer.readyState === OPEN) peer.dispatchEvent(event('message', { data: copy })); });
  }

  close(code = 1000, reason = '') {
    if (this.readyState >= CLOSING) return;
    this.readyState = CLOSING;
    const peer = this.peer;
    queueMicrotask(() => {
      for (const s of [this, peer]) {
        if (s.readyState === CLOSED) continue;
        s.readyState = CLOSED;
        s.dispatchEvent(event('close', { code, reason, wasClean: true }));
      }
    });
  }
}

/**
 * Two connected sockets: what one sends, the other receives (asynchronously, in order). Both are open after a tick.
 * @returns {[MemorySocket, MemorySocket]}
 */
export function createSocketPair() {
  const a = new MemorySocket();
  const b = new MemorySocket();
  a.peer = b;
  b.peer = a;
  queueMicrotask(() => {
    for (const s of [a, b]) { s.readyState = OPEN; s.dispatchEvent(new Event('open')); }
  });
  return [a, b];
}

/**
 * @param {object} [options]
 * @param {object | Function} [options.auth] - As for `createWshServer`. Omitted = refuse everyone.
 * @param {Function | { run: Function, timeoutMs?: number, clientEnv?: boolean }} [options.exec]
 *   `run(command, io) => Promise<exitCode>` (see `ExecIo` in `server/exec.mjs`): the host has no shell, so there is no `true`.
 * @param {{ tools?: object[] | object, client?: object, authorize?: Function, maxConcurrent?: number, timeoutMs?: number }} [options.mcp]
 * @param {Record<string, Function>} [options.extensions] - Handlers for application-defined messages, as for `createWshServer`.
 * @param {number} [options.bindTimeoutMs=3000]
 * @param {(line: string) => void} [options.onLog]
 */
export function createMemoryHost({ auth, exec, mcp, extensions, bindTimeoutMs = 3000, onLog = () => {} } = {}) {
  if (exec === true) throw new TypeError('createMemoryHost: exec must be a function (run(command, io)); there is no shell to run `true` with');
  if (exec !== undefined && typeof exec !== 'function' && typeof exec?.run !== 'function') {
    throw new TypeError('createMemoryHost: exec must be a function or { run }');
  }
  if (extensions !== undefined && (extensions === null || typeof extensions !== 'object')) throw new TypeError('createMemoryHost: extensions must be an object of handlers');
  const execOptions = typeof exec === 'function' || !exec ? {} : exec;
  const execRunner = typeof exec === 'function' ? exec : exec?.run ?? null;
  const rl = auth?.rateLimit ?? {};
  const rateLimit = {
    limiter: new FailureLimiter(rl),
    key: typeof rl.key === 'function' ? rl.key : ({ address }) => String(address ?? 'unknown'),
    failureDelayMs: rl.failureDelayMs ?? 250,
  };
  const methods = authMethods(auth);
  const mcpHost = mcp ? createMcpHost(mcp) : null;

  const ready = buildAuthorizer(auth).then((authorize) => createConnectionFactory({
    authorize, execRunner, execOptions, pty: null, files: null, bindTimeoutMs, log: onLog,
    methods, hostKey: null, rateLimit, extensions, mcp: mcpHost, rpc: null, gateway: null, sessions: null, relay: null,
  }));
  ready.catch(() => {});

  const accepted = new Set();
  let closed = false;

  async function accept(socket, options) {
    if (closed) throw new Error('createMemoryHost: host is closed');
    const handle = await bindSocket(socket, ready, options);
    accepted.add(handle);
    return handle;
  }

  /** A `WebSocket` constructor that dials this host: `new host.WebSocket(url)` ignores the URL. */
  class HostWebSocket extends MemorySocket {
    constructor() {
      super();
      const [client, server] = createSocketPair();
      void accept(server, { remote: { address: 'memory' } }).catch(onLog);
      return client;
    }
  }

  const host = {
    /** Pass to `client.connect()`. */
    url: MEMORY_URL,
    WebSocket: HostWebSocket,
    accept,
    socketPair: createSocketPair,
    /** A `WshClient` whose transport is this host (`await client.connect(host.url, ...)`). */
    createClient(clientOptions = {}) {
      return new WshClient({
        ...clientOptions,
        transportFactories: {
          ws: () => new WebSocketTransport({ WebSocket: HostWebSocket }),
          wt: () => { throw new Error('createMemoryHost: WebTransport is not available in memory'); },
        },
      });
    },
    /** `createClient()` and `connect()` in one: resolves to a connected client. */
    async connect(credentials) {
      const client = host.createClient();
      await client.connect(MEMORY_URL, { transport: 'ws', ...credentials });
      return client;
    },
    async close() {
      closed = true;
      for (const handle of accepted) handle.close();
      accepted.clear();
    },
  };
  return host;
}
