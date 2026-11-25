/**
 * `@johnhenry/wsh/memory` -- a wsh host that lives in the same JavaScript realm as its clients, with no sockets, no
 * ports and no Node. Browser-safe (a page, a Worker, Deno, Bun, Node): it imports nothing from `node:*`, and a test
 * (`test/memory-host.test.mjs`) keeps it that way. For demos, docs and tests of an application that talks wsh.
 *
 * It is the real protocol end to end -- the same connection handler `createWshServer` runs (handshake, Ed25519 or
 * password auth, exec channels, MCP tools, extensions), speaking QMux over a pair of in-memory WebSocket-like
 * sockets -- so what a client does here is what it does against a server. It serves what a browser can: `exec` as a
 * function you provide (there is no shell), `mcp` tools, `extensions`, typed `rpc` channels (handler functions you
 * provide), `sessions` (detach / attach / resume of exec sessions, output replayed from an in-memory ring buffer) and
 * `endpoints` (named virtual endpoints, the in-memory stand-in for unix sockets, with flow control).
 * Backends are injected, shaped like the Node host's: `pty` (`{ spawn }`, node-pty shaped), `fs` (an object of file
 * operations, not a root path), `hostKey` (a `CryptoKeyPair`, which may be non-extractable, or a signer
 * `{ publicKey, sign }`).
 * Not available: the TCP, DNS, UDP and unix-socket parts of `gateway` (named `endpoints` are), `relay`, WebTransport,
 * `exec: true` and `fs: { root }` (they need Node), the `wsh-host` / `wsh-fs` rpc built-ins (use `@johnhenry/wsh/server`).
 *
 * To serve a socket someone else upgraded (a WebSocket the page opened to a relay, a byte pipe) use `host.accept(socket)`;
 * a peer that cannot open QMux data streams (the released Rust client over WebSocket) needs `dataStreams: false`.
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
import { createConnectionFactory, DEFAULT_SEAL_TIMEOUT_MS, assertSealTimeoutMs, DEFAULT_LOGIN_TIMEOUT_MS, assertLoginTimeoutMs } from './server/connection.mjs';
import { resolveUsernamePattern } from './server/username.mjs';
import { buildAuthorizer, authMethods, FailureLimiter } from './server/auth.mjs';
import { assertEd25519HostKey } from './host-key.mjs';
import { resolveBackends, resolveHostKey, createRpcTable } from './host-backends.mjs';
import { bindSocket } from './server/socket.mjs';
import { normalizeEndpointGateway, createEndpointGatewaySession } from './server/gateway-core.mjs';
import { CHANNEL_BINDING_KINDS } from './channel-binding.mjs';
import { RPC_DEFAULT_MAX_MESSAGE } from './rpc.mjs';
import { SessionRegistry, DEFAULT_RING_BYTES, DEFAULT_DETACH_TTL_MS, DEFAULT_MAX_DETACHED } from './session-registry.mjs';
import { validateOnShare } from './shares.mjs';
import { validateOnRefused } from './refusal.mjs';

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
    if (typeof data === 'string') {
      // wsh frames are binary; a text frame is what a pipe relay sends a host that asked: its paired signal (#253). It reaches the other end as text, as on a real WebSocket.
      const peer = this.peer;
      queueMicrotask(() => { if (peer.readyState === OPEN) peer.dispatchEvent(event('message', { data })); });
      return;
    }
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

function createRegistry(sessions, log) {
  const o = sessions === true ? {} : sessions;
  if (typeof o !== 'object' || Array.isArray(o)) throw new TypeError('createMemoryHost: sessions must be true or { detachTtlMs, maxDetached, ringBytes }');
  const { detachTtlMs = DEFAULT_DETACH_TTL_MS, maxDetached = DEFAULT_MAX_DETACHED, ringBytes = DEFAULT_RING_BYTES } = o;
  if (!(Number.isFinite(detachTtlMs) && detachTtlMs >= 0)) throw new TypeError('createMemoryHost: sessions.detachTtlMs must be a non-negative number');
  if (!Number.isSafeInteger(maxDetached) || maxDetached < 0) throw new TypeError('createMemoryHost: sessions.maxDetached must be a non-negative integer');
  if (!Number.isSafeInteger(ringBytes) || ringBytes < 1) throw new TypeError('createMemoryHost: sessions.ringBytes must be a positive integer');
  return new SessionRegistry({ detachTtlMs, maxDetached, ringBytes, log });
}

/**
 * `host.accept(socket, { waitForPeer })` (#253): `true`, or a promise (a relay's paired signal), for a half held before its partner has arrived; the login deadline
 * (`loginTimeoutMs`) then starts when the far side does (its first byte, or the promise) instead of at the accept.
 *
 * @param {object} [options]
 * @param {object | Function} [options.auth] - As for `createWshServer`. Omitted = refuse everyone.
 * @param {Function | { run: Function, timeoutMs?: number, clientEnv?: boolean | string[] | Function }} [options.exec]
 *   `run(command, io) => Promise<exitCode>` (see `ExecIo` in `server/exec.mjs`): the host has no shell, so there is no `true`.
 * @param {{ spawn: Function, shell?: string, cwd?: string, env?: object, term?: string }} [options.pty]
 *   `pty.spawn(file, args, { name, cols, rows, cwd, env })` as `node-pty`'s `spawn` (or anything shaped like it) returns
 *   `{ onData(cb), onExit(cb), write(data), resize(cols, rows), kill(signal?) }`. Input arrives at `write` as a `Uint8Array`.
 *   `shell` is the `file` it is called with (default `/bin/sh`: name the program your `spawn` understands).
 * @param {{ operate: Function, readWhole: Function, writeWhole: Function, writeAt: Function, openRange?: Function, maxFileBytes?: number }} [options.fs]
 *   File operations, as `createFileAccess` in `@johnhenry/wsh/server` returns them (see `normalizeFileBackend` in
 *   `host-backends.mjs`). Not a root path: confining paths is the backend's job.
 * @param {false | 'offer' | 'require'} [options.sealSession=false] - #155: seal the whole session end to end (needs `hostKey` and
 *   `dataStreams: false`, which is how a page host is served). A client that asks (a signed `KeyExchange` for the connection's
 *   session id, features `e2e-session`) gets every message after login -- gateway and endpoint data included -- as an
 *   authenticated encrypted frame, so a relay that only copies bytes (a pipe relay) can neither read nor alter it; a frame that
 *   does not open closes the session. `'offer'` serves a client that does not ask in the clear; `'require'` (advertised as
 *   `e2e-session-required`) serves nobody who has not sealed, and no password login. The keepalive stays plain.
 * @param {number} [options.sealTimeoutMs=30000] - #244: with `sealSession: 'require'`, how long after login the session may stay unsealed;
 *   then the host reports `seal-timeout` (`onRefused`), says so in an `Error` and closes the connection. 0 = no deadline.
 * @param {number} [options.loginTimeoutMs=60000] - #248: how long a connection may take, from the moment this host accepts it, to complete its login
 *   (Hello and Auth); then the host reports `login-timeout` (`onRefused`), says so in an `AuthFail` and closes the connection. 0 = no deadline.
 * @param {true | CryptoKeyPair | { publicKey: Uint8Array | CryptoKey, sign: Function }} [options.hostKey]
 *   This host's own identity, so clients can pin it (TOFU): a `CryptoKeyPair` (non-extractable is fine), a signer
 *   `{ publicKey, sign(data) }`, or `true` for a fresh non-extractable key.
 * @param {boolean} [options.dataStreams=true] - Offer client-opened QMux data streams for exec output (`stream-announce`,
 *   rpc). Set `false` for a peer that cannot open them -- the released Rust client over WebSocket -- so exec output rides
 *   `SessionData` instead (and rpc is stated as `rpc-virtual`, #191). The released clients state nothing in their `Hello` that a host could
 *   key an automatic choice on, so this is an option; `accept(socket, { dataStreams })` overrides it per connection.
 * @param {{ tools?: object[] | object, client?: object, authorize?: Function, maxConcurrent?: number, timeoutMs?: number }} [options.mcp]
 * @param {Record<string, Function>} [options.extensions] - Handlers for application-defined messages, as for `createWshServer`.
 * @param {Record<string, Function>} [options.rpc] - Typed RPC channels: `{ [protocol]: (channel, ctx) => void | Promise<void> }`,
 *   a handler per protocol that registers methods on an `RpcChannel`. Off unless given. Handler functions only (no built-ins).
 * @param {number} [options.rpcMaxMessageBytes=1048576] - Largest single rpc message (advertised as `rpc-max-message:<n>`; at least 256).
 * @param {number} [options.rpcMaxInflight=64] - Concurrent requests per rpc channel before `-32002`.
 * @param {true | { detachTtlMs?: number, maxDetached?: number, ringBytes?: number }} [options.sessions]
 *   Keep exec sessions alive across disconnects so a client can `resumeSession()` / `attachSession()`: as for
 *   `createWshServer`, with the same defaults (300000 ms detached, 16 detached sessions, 1 MiB of replayable output
 *   per session). Off unless given: sessions then die with their connection. There is no `sessionSecret`: session
 *   tokens are random per session.
 * @param {Record<string, ((duplex: object, who: { username: string | null, fingerprint: string | null }) => void | Promise<void>) | { open: Function, authorize?: (who: object) => boolean | Promise<boolean> }>} [options.endpoints]
 *   Named virtual endpoints (a host with no file system exposes these instead of unix sockets): a client reaches one with
 *   `client.openEndpoint(name)`. `duplex` is `{ readable, writable, close(), destroy(), closed, who }` (web streams with
 *   backpressure) and `who` is the authenticated `{ username, fingerprint }`, so the handler can authorise per call:
 *   throw synchronously to refuse, or give `{ open, authorize(who) }`. Only the names listed here exist (an allow-list by
 *   construction); nothing else of the gateway (TCP, DNS, unix sockets) is on in memory.
 * @param {Record<string, { description?: string, authorize?: Function, exec?: Function | { run: Function }, pty?: object, fs?: object, endpoints?: object }>} [options.targets]
 *   Execution targets (#121), as for `createWshServer`: each with its own `exec`, `pty`, `fs` and `endpoints` (the injected
 *   forms only: there is no shell or directory here) and an `authorize(who, { target, kind })`. Off unless given.
 * @param {boolean} [options.requireTarget=false] - With `targets`: a request that names no target is refused. As for `createWshServer`.
 * @param {number} [options.bindTimeoutMs=3000]
 * @param {number} [options.connectionTtlMs=0] - End each authenticated connection this long after login; advertised as
 *   `AuthOk.ttl` in whole seconds (#125). 0 = never.
 * @param {boolean | string[]} [options.requireChannelBinding=false] - Accept a key login only when its signature is bound
 *   to this host's key (#119). A memory host can bind only `host` (it has no TLS of its own), so this needs `hostKey`;
 *   `true` or `['host']`.
 * @param {(name: string, fs: object, who: { username: string | null, fingerprint: string | null }) => void | Promise<void>} [options.onShare]
 *   Folders of the OPERATOR's machine (#159): the operator's `wsh --share NAME=/abs/dir[:ro|:rw]` offers them after login and
 *   this is called once per share with an object of async file operations (`stat`, `readdir` with attributes, `readFile`,
 *   `open`, `writeFile`, `mkdir`, `rename`, `unlink`, ... and the `operate` / `readWhole` / `writeWhole` / `writeAt` shape of
 *   an `fs` backend) that the embedder can mount. Listing it makes the host state the `shares` feature. See `shares.mjs`.
 * @param {(refusal: { reason: string, who: { username?: string, fingerprint?: string, address?: string }, detail: string }) => void} [options.onRefused]
 *   #163: called once per connection that this host turned away (a key it does not allow, a plain client on a host that
 *   requires a sealed session, a login that is not bound, ...) with a stable `reason` code (`REFUSAL_REASONS`, exported
 *   from `@johnhenry/wsh/host`), what is known of `who`, and a human `detail` (not stable). Not for parsing `onLog`.
 * @param {(line: string) => void} [options.onLog]
 */
export function createMemoryHost({ auth, exec, pty, fs, hostKey, mcp, extensions, rpc, rpcMaxMessageBytes = RPC_DEFAULT_MAX_MESSAGE, rpcMaxInflight = 64, sessions, endpoints, dataStreams = true, bindTimeoutMs = 3000, connectionTtlMs = 0, sealTimeoutMs = DEFAULT_SEAL_TIMEOUT_MS, loginTimeoutMs = DEFAULT_LOGIN_TIMEOUT_MS, requireChannelBinding = false, sealSession = false, onLog = () => {},
  onShare, onRefused, onSealed, targets, requireTarget, usernamePattern } = {}) {
  if (onSealed !== undefined && typeof onSealed !== 'function') throw new TypeError('createMemoryHost: onSealed must be a function');
  resolveUsernamePattern(usernamePattern, 'createMemoryHost');
  validateOnShare(onShare, 'createMemoryHost');
  validateOnRefused(onRefused, 'createMemoryHost');
  if (!Number.isFinite(connectionTtlMs) || connectionTtlMs < 0) throw new TypeError('createMemoryHost: connectionTtlMs must be a non-negative number');
  assertSealTimeoutMs(sealTimeoutMs, 'createMemoryHost');
  assertLoginTimeoutMs(loginTimeoutMs, 'createMemoryHost');
  if (requireChannelBinding !== false && requireChannelBinding !== true && !(Array.isArray(requireChannelBinding) && requireChannelBinding.every((k) => CHANNEL_BINDING_KINDS.includes(k)))) {
    throw new TypeError(`createMemoryHost: requireChannelBinding must be true, false or an array of kinds (${CHANNEL_BINDING_KINDS.join(', ')})`);
  }
  if (Array.isArray(requireChannelBinding) && requireChannelBinding.some((k) => k !== 'host')) throw new TypeError('createMemoryHost: requireChannelBinding can name only "host" (a memory host has no TLS connection or certificate to bind)');
  if (hostKey !== undefined && hostKey !== null && hostKey !== false) assertEd25519HostKey(hostKey, 'createMemoryHost: hostKey');
  if (requireChannelBinding && !hostKey) throw new TypeError('createMemoryHost: requireChannelBinding needs a hostKey (the only thing a memory host can bind a login to)');
  if (sealSession !== false && sealSession !== 'offer' && sealSession !== 'require') throw new TypeError("createMemoryHost: sealSession must be false, 'offer' or 'require'");
  if (sealSession && !hostKey) throw new TypeError('createMemoryHost: sealSession needs a hostKey (the host signs its half of the key exchange with it)');
  if (exec === true) throw new TypeError('createMemoryHost: exec must be a function (run(command, io)); there is no shell to run `true` with');
  if (exec !== undefined && typeof exec !== 'function' && typeof exec?.run !== 'function') {
    throw new TypeError('createMemoryHost: exec must be a function or { run }');
  }
  if (extensions !== undefined && (extensions === null || typeof extensions !== 'object')) throw new TypeError('createMemoryHost: extensions must be an object of handlers');
  if (typeof dataStreams !== 'boolean') throw new TypeError('createMemoryHost: dataStreams must be true or false');
  const rpcHost = rpc === undefined || rpc === null ? null : createRpcTable(rpc, rpcMaxMessageBytes, rpcMaxInflight, 'createMemoryHost');
  const registry = sessions === undefined || sessions === null || sessions === false ? null : createRegistry(sessions, onLog);
  const { execRunner, execOptions, pty: ptyBackend, files, mcp: mcpHost, targets: targetTable, requireTarget: mustHaveTarget } = resolveBackends({ exec, pty, fs, mcp, targets, requireTarget });
  const hostKeyReady = hostKey === undefined || hostKey === null || hostKey === false ? Promise.resolve(null) : resolveHostKey(hostKey, 'createMemoryHost: hostKey');
  const rl = auth?.rateLimit ?? {};
  const rateLimit = {
    limiter: new FailureLimiter(rl),
    key: typeof rl.key === 'function' ? rl.key : ({ address }) => String(address ?? 'unknown'),
    failureDelayMs: rl.failureDelayMs ?? 250,
  };
  const methods = authMethods(auth);
  // Named virtual endpoints: a gateway with no TCP, DNS or unix sockets that answers only `OpenEndpoint`, built from
  // the browser-safe core (`server/gateway-core.mjs`), so a page can have it.
  let gatewayCfg = endpoints === undefined || endpoints === null ? null : normalizeEndpointGateway({ endpoints });
  // A target's own endpoints (#121) need the endpoints-only gateway too, even when the host has none of its own.
  if (targetTable && [...targetTable.values()].some((t) => t.endpoints)) gatewayCfg = { ...(gatewayCfg ?? normalizeEndpointGateway({})), targetEndpoints: true };

  const ready = Promise.all([buildAuthorizer(auth, { log: onLog }), hostKeyReady]).then(([authorize, hostKeyResolved]) => createConnectionFactory({
    authorize, execRunner, execOptions, pty: ptyBackend, files, bindTimeoutMs, connectionTtlMs, requireChannelBinding, sealSession, sealTimeoutMs, loginTimeoutMs, log: onLog,
    methods, hostKey: hostKeyResolved, rateLimit, extensions, mcp: mcpHost, rpc: rpcHost, onShare, onRefused, onSealed,
    targets: targetTable, requireTarget: mustHaveTarget, usernamePattern,
    gateway: gatewayCfg, createGatewaySession: gatewayCfg ? createEndpointGatewaySession : undefined, sessions: registry, relay: null,
  }));
  ready.catch(() => {});

  const accepted = new Set();
  let closed = false;

  async function accept(socket, options) {
    if (closed) throw new Error('createMemoryHost: host is closed');
    const handle = await bindSocket(socket, ready, { dataStreams, ...options });
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
      registry?.closeAll();
    },
  };
  return host;
}
