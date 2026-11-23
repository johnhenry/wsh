/**
 * `@johnhenry/wsh/host` -- the building blocks of a wsh host that runs anywhere JavaScript does (a page, a Worker,
 * Deno, Bun, Node), for an embedder that brings its own transport. No `node:*` import and no `Buffer` is reachable
 * from here (a test bundles this entry point for the browser and fails if one is), and it does not import the client.
 *
 *  - `createConnectionFactory(cfg)` -- the connection handler `createWshServer`, `createMemoryHost` and
 *    `createReverseHost` all run: handshake, auth, exec / pty / file / MCP channels, sessions, end-to-end encryption.
 *    `attach(...)` is called once per connection, over a byte pipe (QMux framing, what a WebSocket carries) or, for a
 *    transport that frames messages itself, over messages.
 *  - `bindSocket(socket, ready, options)` -- the byte-pipe side for a WebSocket-like duplex.
 *  - `resolveBackends({ exec, pty, fs, mcp })`, `resolveHostKey(key)`, `buildAuthorizer(auth)`, `authMethods(auth)` --
 *    turn the options a host takes into what the factory wants.
 *
 * ```js
 * import { createConnectionFactory, resolveBackends, buildAuthorizer, authMethods, bindSocket } from '@johnhenry/wsh/host';
 *
 * const auth = { authorizedKeys: [rawPublicKey] };
 * const backends = resolveBackends({ exec: async (command, io) => { await io.write('hi\n'); return 0; } });
 * const attach = createConnectionFactory({
 *   authorize: await buildAuthorizer(auth), methods: authMethods(auth), ...backends,
 * });
 * // `attach` is what `bindSocket` wants, as a promise:
 * await bindSocket(upgradedSocket, Promise.resolve(attach), { dataStreams: false });
 * ```
 */

export { createConnectionFactory, hostFeatures, STREAM_ANNOUNCE } from './server/connection.mjs';
export { bindSocket } from './server/socket.mjs';
export { resolveBackends, resolveHostKey, normalizeFileBackend } from './host-backends.mjs';
export { buildAuthorizer, authMethods } from './server/auth.mjs';
