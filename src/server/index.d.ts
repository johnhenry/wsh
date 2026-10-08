/**
 * Types for `@johnhenry/wsh/server` -- the Node host. Node-only; the package
 * root (`@johnhenry/wsh`) never imports it.
 */

import type { RpcChannel } from '@johnhenry/wsh';

/** Who is asking to authenticate. */
export interface WshServerPrincipal {
  username: string;
  /** Hex SHA-256 of the raw public key (see `fingerprint()`). */
  fingerprint: string;
  /** Raw 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
}

export interface WshServerAuthOptions {
  /**
   * Keys allowed to connect: `ssh-ed25519 AAAA... [comment]` lines (an
   * `authorized_keys` file's text works), raw 32-byte keys, or an array of either.
   */
  authorizedKeys?: string | Uint8Array | Array<string | Uint8Array>;
  /** Extra policy, run after the signature verifies (and after the allowlist, when given). */
  authorize?: (who: WshServerPrincipal) => boolean | Promise<boolean>;
  /**
   * Enable password login: return `true` to admit. Sent in the clear inside the
   * connection -- serve over `wss://` / a trusted link. Use a constant-time
   * compare against hashes, never `===` on plaintext. Failures are throttled
   * (see `rateLimit`); the callback is not consulted while a caller is locked out.
   */
  password?: (username: string, password: string) => boolean | Promise<boolean>;
  /** Password-failure throttle. */
  rateLimit?: {
    /** Failures inside `windowMs` before lockout (default 5). */
    maxFailures?: number;
    /** Failure counting window (default 60000). */
    windowMs?: number;
    /** Lockout length once tripped (default 60000). */
    lockoutMs?: number;
    /** Pause before answering a failed attempt (default 250). */
    failureDelayMs?: number;
    /** Throttle bucket; default the peer address. Use this behind a proxy (e.g. read `x-forwarded-for` from `headers`). */
    key?: (info: { address: string | undefined; headers: Record<string, string | string[] | undefined>; username: string }) => string;
  };
}

/** The server's own identity, as advertised to clients. */
export interface WshServerHostKey {
  /** Hex SHA-256 of the raw key. */
  fingerprint: string;
  /** Raw 32-byte Ed25519 key. */
  publicKey: Uint8Array;
  /** `ssh-ed25519 AAAA...` */
  openssh: string;
}

/** What a custom `exec` runner receives for one session. */
export interface WshExecIo {
  user: string;
  /** Environment the client asked for (empty when `clientEnv: false`). */
  env: Record<string, string>;
  cols: number;
  rows: number;
  /** Aborts on client Close, disconnect, timeout, or a terminating signal nothing handled. */
  signal: AbortSignal;
  /** Send output; resolves when flow control has accepted it. */
  write(data: Uint8Array | string): Promise<void>;
  /** Client stdin. */
  onInput(cb: (bytes: Uint8Array) => void): void;
  /** Client closed stdin. */
  onInputEnd(cb: () => void): void;
  /** Named signal from the client (`INT`, `TERM`, ...). */
  onSignal(cb: (name: string) => void): void;
}

/** Runs one exec session; resolve with the exit code. */
export type WshExecRunner = (command: string, io: WshExecIo) => Promise<number>;

export interface WshServerExecOptions {
  /** Working directory of spawned commands. */
  cwd?: string;
  /** Base environment (default `process.env`). */
  env?: Record<string, string | undefined>;
  /** `true` (default `/bin/sh`), or a shell path. */
  shell?: boolean | string;
  /** Kill a session after this long (0 / omitted = never). */
  timeoutMs?: number;
  /** Apply `env` sent by the client (default `true`). */
  clientEnv?: boolean;
  /** Replace the child_process runner entirely (e.g. a restricted, no-shell host). */
  run?: WshExecRunner;
}

/** The part of a pseudo-terminal process the server uses -- `node-pty`'s `IPty` fits. */
export interface WshPtyProcess {
  onData(cb: (data: string | Uint8Array) => void): unknown;
  onExit(cb: (e: { exitCode: number; signal?: number }) => void): unknown;
  write(data: string | Uint8Array): void;
  resize(cols: number, rows: number): void;
  kill(signal?: string): void;
}

export interface WshServerPtyOptions {
  /** `node-pty`'s `spawn(file, args, options)`, or anything shaped like it. */
  spawn(file: string, args: string[], options: {
    name: string; cols: number; rows: number; cwd?: string; env: Record<string, string | undefined>;
  }): WshPtyProcess;
  /** Shell to run (default `$SHELL` or `/bin/sh`). */
  shell?: string;
  cwd?: string;
  env?: Record<string, string | undefined>;
  /** `TERM` value (default `xterm-256color`). */
  term?: string;
}

export interface WshServerFsOptions {
  /** Every client path is resolved inside this directory; `..`, absolute paths and symlinks out of it are refused. */
  root: string;
  readOnly?: boolean;
  /** Upload / download size cap in bytes (default 64 MiB). */
  maxFileBytes?: number;
}

/** Context handed to an MCP tool's `call()`. */
export interface WshMcpCallContext {
  /** Authenticated username. */
  user: string;
  /** Hex SHA-256 of the client's key (`null` for a password login). */
  fingerprint: string | null;
  /** Aborts on client disconnect or `timeoutMs`. A tool that ignores it keeps running but its reply is dropped. */
  signal: AbortSignal;
}

/** One tool exposed over `McpDiscover` / `McpCall`. */
export interface WshMcpTool {
  name: string;
  description?: string;
  /** JSON Schema for the arguments (default `{ type: 'object' }`). Enforced before `call()` runs; keywords outside the supported subset are refused at startup. Advertised to clients as `parameters`. */
  inputSchema?: Record<string, unknown> | boolean;
  /** The result is sent as `McpResult.result` verbatim (any CBOR-encodable value). Throwing sends `{ success: false, error: message }`. */
  call(args: any, ctx: WshMcpCallContext): unknown | Promise<unknown>;
}

/** The part of an `@modelcontextprotocol/sdk` `Client` that the server proxies. */
export interface WshMcpClientLike {
  listTools(): Promise<{ tools: Array<{ name: string; description?: string; inputSchema?: Record<string, unknown> }> }>;
  callTool(params: { name: string; arguments: unknown }, resultSchema?: unknown, options?: { signal?: AbortSignal }): Promise<{ content?: unknown; structuredContent?: unknown; isError?: boolean }>;
}

export interface WshServerMcpOptions {
  /** Tools to serve: a list, or a `{ name: { description, inputSchema, call } }` map. */
  tools?: WshMcpTool[] | Record<string, Omit<WshMcpTool, 'name'>>;
  /** An MCP client whose tools are proxied (local `tools` win on a name clash). */
  client?: WshMcpClientLike;
  /** Per-principal filter, applied to discovery and to calls alike (a hidden tool looks unknown). */
  authorize?: (user: string, tool: { name: string; description: string; inputSchema: unknown }, who: { username: string; fingerprint: string | null }) => boolean | Promise<boolean>;
  /** In-flight calls per connection (default 8); further calls get an error result. */
  maxConcurrent?: number;
  /** Per-call time limit in ms (default 30000; 0 = none). */
  timeoutMs?: number;
}

export interface WshServerSessionsOptions {
  /** How long a session with nobody attached keeps running (default 300000). `0` kills it the moment its last connection goes. */
  detachTtlMs?: number;
  /** Unattended sessions kept at once (default 16); beyond that the longest-detached is killed. */
  maxDetached?: number;
  /** Output history kept per session, in bytes (default 1 MiB) -- what a resume can replay. Older output is dropped; a Resume older than it is refused with an "output gap" error. */
  ringBytes?: number;
  /** Secret the session tokens are minted with (default: random per process). Fixing it makes tokens verifiable across restarts. */
  sessionSecret?: string | Uint8Array;
}

/** A peer as the relay's policy callbacks see it. */
export interface WshRelayPeer {
  /** Hex SHA-256 of the peer's key. */
  fingerprint: string;
  username: string;
  capabilities: string[];
}

export interface WshServerRelayOptions {
  /**
   * May this authenticated connection register as a peer? `who` is the connection; `record` what it asks to
   * advertise. Default: no (a relay with no policy admits nobody).
   */
  canRegister?: (
    who: { username: string; fingerprint: string },
    record: { username: string; capabilities: string[]; peerType: string; shellBackend: string },
  ) => boolean | Promise<boolean>;
  /**
   * May `from` list and connect to `to`? A peer `from` may not connect to is neither listed nor distinguishable
   * from an absent one. Default: no.
   */
  canConnect?: (
    from: { username: string; fingerprint: string },
    to: WshRelayPeer,
  ) => boolean | Promise<boolean>;
  /** Registered peers at once (default 1024). */
  maxPeers?: number;
  /**
   * Operators bridged to one peer at once (default 1). Above 1, a peer is held to one operator unless it stated
   * `relay-multi-operator` in its `ReverseAccept.features` (it then addresses replies with
   * `RelayForward.to_fingerprint` and is sent a `ReverseClose` when one operator leaves instead of being closed).
   */
  maxOperatorsPerPeer?: number;
  /** How long a `ReverseConnect` waits for its peer to answer before the operator is rejected (default 8000). */
  connectTimeoutMs?: number;
}

export interface WshServerWebTransportOptions {
  /** UDP port for HTTP/3 (default 0 = pick a free one; read it back from `webTransport()`). */
  port?: number;
  /** Bind address (default: the server's `host`). */
  host?: string;
  /** URL path sessions are accepted on (default `/wsh`). */
  path?: string;
  /** PEM certificate chain. With `privKey`. Not together with `selfSigned`. */
  cert?: string;
  /** PEM private key for `cert`. */
  privKey?: string;
  /**
   * Generate a short-lived ECDSA P-256 certificate (13 days; browsers refuse a pinned one valid for more than 14) and
   * expose its SHA-256 as `webTransport().certificateHash`, for the client's `serverCertificateHashes`.
   *
   * It is rotated before it expires: `prepareBeforeMs` ahead of `notAfter` (default: 3 days, at most a third of the
   * validity) the next certificate is generated and its hash published next to the current one
   * (`server.certificateHashes()` returns both: a client that re-reads the list pins both), and `activateBeforeMs` ahead
   * (default: 1 hour, at most a sixth of the validity) the listener switches to it. The switch restarts the HTTP/3
   * listener on the same port, so live WebTransport sessions end and clients reconnect. `rotate: false` turns
   * all of this off (restart before `notAfter`). An object takes `{ hosts, validityDays }` for the certificates too.
   */
  selfSigned?: boolean | {
    hosts?: string[];
    validityDays?: number;
    rotate?: boolean;
    prepareBeforeMs?: number;
    activateBeforeMs?: number;
  };
  /** QUIC stateless-reset secret (default: random). */
  secret?: string;
}

export interface WshServerWebTransport {
  port: number;
  host: string;
  path: string;
  /** `https://host:port/path`, what a client connects to. */
  url: string;
  /** SHA-256 of the DER certificate, when `selfSigned` made it; `null` for a certificate you supplied. */
  certificateHash: Uint8Array | null;
  certificateHashHex: string | null;
  /** When the `selfSigned` certificate expires; `null` otherwise. */
  notAfter: Date | null;
  /** The `serverCertificateHashes` to pin now: the certificate being presented and, during a rotation's overlap, the next. */
  certificateHashes(): WshPinnedCertificateHash[];
  /** The same certificates with their validity and which one is being presented. */
  certificates(): WshServerCertificateInfo[];
  /** See `WshServer.rotateCertificate()`. */
  rotateCertificate(options?: { activate?: boolean }): Promise<{ current: WshServerCertificateInfo; next: WshServerCertificateInfo | null }>;
}

/** A `serverCertificateHashes` entry, ready to pass to `new WebTransport(url, { serverCertificateHashes })`. */
export interface WshPinnedCertificateHash {
  algorithm: 'sha-256';
  value: Uint8Array;
}

export interface WshServerCertificateInfo {
  hash: Uint8Array;
  hashHex: string;
  notBefore: Date;
  notAfter: Date;
  /** Is it the one the listener presents right now? */
  active: boolean;
}

export interface WshSelfSignedCertificate {
  /** PEM certificate. */
  cert: string;
  /** PEM (PKCS#8) private key. */
  privKey: string;
  /** SHA-256 of the DER certificate: the value to pin. */
  hash: Uint8Array;
  hashHex: string;
  notBefore: Date;
  notAfter: Date;
}

/** A dependency-free self-signed ECDSA P-256 certificate fit for WebTransport's `serverCertificateHashes`. */
export function generateSelfSignedCertificate(opts?: { hosts?: string[]; validityDays?: number; now?: Date }): WshSelfSignedCertificate;

export interface WshServerOptions {
  /** Bind address (default `127.0.0.1`). */
  host?: string;
  /** Port (default `0` = pick a free one; read it back from `address()`). */
  port?: number;
  /** Who may connect. Omitted = every connection is refused. A function is shorthand for `{ authorize }`. */
  auth?: WshServerAuthOptions | ((who: WshServerPrincipal) => boolean | Promise<boolean>);
  /** Enable `exec` sessions. `true`, options, or a custom runner. Off by default. */
  exec?: true | WshServerExecOptions | WshExecRunner;
  /** Enable `pty` sessions by injecting a pty implementation. Off by default. */
  pty?: WshServerPtyOptions;
  /**
   * Advertise an Ed25519 host identity (with proof of possession) so clients can pin it.
   * `{ file }` persists a PKCS#8 PEM (created 0600 on first start) -- the normal choice;
   * `true` is a fresh key every start; or pass a `CryptoKeyPair`. Off by default.
   */
  hostKey?: true | { file: string } | CryptoKeyPair;
  /** Enable file ops and uploads/downloads under one directory. Off by default. */
  fs?: WshServerFsOptions;
  /**
   * Keep pty/exec sessions alive across disconnects so `resumeSession()` /
   * `attachSession()` / `detach()` / `listRemoteSessions()` work against them.
   * `true` for the defaults. Off by default: sessions then die with their connection.
   */
  sessions?: true | WshServerSessionsOptions;
  /** Alias for `sessions.sessionSecret`. */
  sessionSecret?: string | Uint8Array;
  /**
   * Act as a relay: peers (`createReverseHost`, or any client's `connectReverse()`) register a signed record,
   * operators list and `reverseConnect()` to them, and traffic is carried between the two as `RelayForward`.
   * Default deny -- give both `canRegister` and `canConnect`. Off by default.
   */
  relay?: WshServerRelayOptions;
  /**
   * Also listen for WebTransport (HTTP/3 over UDP) clients -- the same auth, exec, pty, fs, mcp, sessions and relay as the
   * WebSocket listener, with real independent streams. Needs the optional peers `@fails-components/webtransport` and
   * `@fails-components/webtransport-transport-http3-quiche`, imported only when this is set. Off by default.
   */
  webTransport?: WshServerWebTransportOptions;
  /** Serve MCP tools (`McpDiscover` / `McpCall`) and advertise `mcp-call-id`. Off by default. */
  mcp?: WshServerMcpOptions;
  /**
   * Typed RPC channels (wsh #85): `{ [protocol]: handler }`. Each is advertised as `rpc-protocol:<name>` (plus `rpc` and
   * `rpc-max-message:<n>`). Built-ins: `'wsh-host': true` (`host.info`, `host.ping`), `'wsh-fs': true` (the server's
   * `fs`) or `{ root, readOnly?, maxFileBytes? }` (`stat list read write upload download rename mkdir remove`). Anything
   * else is a function run per opened channel, e.g. `mcp: mcpServerAdapter(server)`. Off by default.
   */
  rpc?: Record<string, true | WshServerFsOptions | WshRpcHandler | false | null | undefined>;
  /** Largest single rpc message (default 1048576). */
  rpcMaxMessageBytes?: number;
  /** Concurrent requests per rpc channel before `-32002` (default 64). */
  rpcMaxInflight?: number;
  /** How long exec output waits for a client that has not yet opened its data stream (default 3000). */
  bindTimeoutMs?: number;
  onLog?: (line: string) => void;
}

/** Per-channel context handed to an rpc protocol handler. */
export interface WshRpcContext {
  protocol: string;
  channelId: number;
  user: string | null;
  fingerprint: string | null;
  remote: { address?: string; headers?: Record<string, unknown> };
  /** The exact `ServerHello.features` this connection received. */
  features: string[];
  hostFingerprint: string | null;
  log(line: string): void;
}

/** Runs once per opened channel; register methods on `channel`. Inbound messages wait until the returned promise settles. */
export type WshRpcHandler = (channel: RpcChannel, ctx: WshRpcContext) => void | Promise<void>;

/**
 * Expose an MCP `Server` (`@modelcontextprotocol/sdk`) over an rpc channel: `rpc: { mcp: mcpServerAdapter(server) }`.
 * An instance serves one channel at a time; pass a factory for one `Server` per channel. The SDK is not imported.
 */
export function mcpServerAdapter(serverOrFactory: { connect(transport: any): Promise<void>; close?(): Promise<void> } | ((ctx: WshRpcContext) => any)): WshRpcHandler;

export interface WshServerAddress {
  address: string;
  port: number;
}

export interface WshServer {
  /** Start listening. Requires the `ws` package. */
  listen(): Promise<WshServerAddress>;
  /** Drop every connection and stop listening. */
  close(): Promise<void>;
  /** The bound address, or `null` when not listening. */
  address(): WshServerAddress | null;
  /** The WebTransport listener; `null` when not configured or before `listen()` resolves. */
  webTransport(): WshServerWebTransport | null;
  /**
   * The `serverCertificateHashes` a WebTransport client should pin right now: the `selfSigned` certificate being
   * presented and, during a rotation's overlap window, the next one. `[]` without a WebTransport listener or with a
   * certificate you supplied. Serve it to your clients out of band (see the README's re-pin flow).
   */
  certificateHashes(): WshPinnedCertificateHash[];
  /**
   * Start rotating the `selfSigned` certificate: generate the next one and publish it in `certificateHashes()` now; the
   * listener switches to it shortly before the current one expires (automatically, unless `selfSigned.rotate` is
   * `false`). `{ activate: true }` switches immediately: live WebTransport sessions end. Rejects for a certificate
   * you supplied, or before `listen()`.
   */
  rotateCertificate(options?: { activate?: boolean }): Promise<{ current: WshServerCertificateInfo; next: WshServerCertificateInfo | null }>;
  /** Fingerprints of the peers currently registered with this relay (`[]` when it is not one). */
  peerFingerprints(): string[];
  /** The advertised host identity; `null` before `listen()` resolves or without a `hostKey`. */
  hostKey(): WshServerHostKey | null;
}

export function createWshServer(options?: WshServerOptions): WshServer;

/** Parse `authorized_keys`-style text into raw 32-byte Ed25519 keys (malformed lines skipped). */
export function parseAuthorizedKeys(text: string): Uint8Array[];

/** ServerHello feature: the host discovers client-opened exec data streams itself (no primer byte). */
export const STREAM_ANNOUNCE: 'stream-announce';

export interface WshReverseHostOptions {
  /** The relay to register with (`ws://` / `wss://`). */
  url: string;
  username: string;
  /** This host's identity; its fingerprint is what operators connect to. */
  keyPair: CryptoKeyPair;
  /** Who may be bridged to this host. Default: nobody. */
  accept?: (operator: { fingerprint: string; username: string }) => boolean | Promise<boolean>;
  exec?: true | WshServerExecOptions | WshExecRunner;
  pty?: WshServerPtyOptions;
  fs?: WshServerFsOptions;
  mcp?: WshServerMcpOptions;
  /** Dial again, with backoff, after the relay connection ends -- which a relay does when a bridge does (default true). */
  reconnect?: boolean;
  /** Extra options for the relay connection (`expectHostKey`, `knownHosts`, `trustOnFirstUse`, ...). */
  connect?: Record<string, unknown>;
  peerType?: string;
  /**
   * Operators served at once (default 1). Above 1 the host states `relay-multi-operator`, addresses each reply
   * to its operator and handles `ReverseClose`; each operator gets its own connection state and is passed through
   * `accept` on its own identity. Needs `reportFeatures` and a relay with `maxOperatorsPerPeer` above 1; any other
   * relay serves it one operator, as before.
   */
  maxOperators?: number;
  /** State this host's features in `ReverseAccept.features` (default true). */
  reportFeatures?: boolean;
  /**
   * End-to-end encryption for the bridged operator (default on; `false` turns it off). The host answers an
   * operator's `KeyExchange` for a session it opened, seals that session's output into `EncryptedFrame`s and opens its
   * input from them. `sign`: sign the reply with `keyPair` so the operator can authenticate this host
   * (`initiateE2E(..., { verifyPeer })`); `'auto'` (default) signs when the relay's `ServerHello` carries `e2e-sign`.
   * `hybrid` (default true) offers X25519+ML-KEM-768 when asked and available.
   */
  e2e?: false | { sign?: boolean | 'auto'; hybrid?: boolean };
  onLog?: (line: string) => void;
}

export interface WshReverseHost {
  /** Dial the relay and register (rejects if the first attempt fails). Registration is not acknowledged on the wire. */
  start(): Promise<{ fingerprint: string }>;
  /** Leave the relay and end any bridged session. */
  close(): Promise<void>;
  /** What operators connect to; `null` before `start()`. */
  readonly fingerprint: string | null;
  /** Is the relay connection up right now? */
  readonly connected: boolean;
  /** Fingerprints of the operators bridged right now. */
  readonly operators: string[];
}

/**
 * A host that dials OUT to a relay and serves the operator it bridges to it, with the same exec / pty / fs / mcp
 * backends `createWshServer` serves direct clients with. For a machine that cannot accept connections.
 */
export function createReverseHost(options: WshReverseHostOptions): WshReverseHost;
