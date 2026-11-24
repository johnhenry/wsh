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

/** What `authorize()` may return instead of `true` (#122): a capability list, and/or an expiry. */
export interface WshCapabilityGrant {
  /** `exec`, `pty`, `relay`, `fs:read`, `fs:write`, `gateway:tcp:<host>:<port>`, `gateway:udp:<host>:<port>`, `gateway:listen:tcp:<port>`, `unix:<path>`, `unix:listen:<path>`, `endpoint:<name>`, `mcp:<tool>`, `target:<name>`, `rpc:<protocol>`; an array, or a comma-separated string. */
  capabilities?: string | string[];
  expires?: string | Date | number;
}

export interface WshServerAuthOptions {
  /**
   * Keys allowed to connect: `ssh-ed25519 AAAA... [comment]` lines (an
   * `authorized_keys` file's text works), raw 32-byte keys, or an array of either.
   */
  authorizedKeys?: string | Uint8Array | Array<string | Uint8Array>;
  /**
   * Extra policy, run after the signature verifies (and after the allowlist, when given). Return `true` to admit, or a
   * capability set (#122) to admit with less: the key may do only what it names, on top of what its `authorized_keys` options
   * allow (it never widens them). Same grammar as `capabilities="..."` in a key line; `expires` is an RFC 3339 string, a
   * `Date` or epoch milliseconds (whole seconds are used). A set that is not understood refuses the login (logged).
   */
  authorize?: (who: WshServerPrincipal) => boolean | WshCapabilityGrant | Promise<boolean | WshCapabilityGrant>;
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

/** The `clientEnv` option of `exec` and `pty`: see {@link WshServerExecOptions.clientEnv}. */
export type WshClientEnv = boolean | string[] | ((name: string, value: string) => boolean);

/** What a custom `exec` runner receives for one session. */
export interface WshExecIo {
  user: string;
  /** #121: the execution target this command runs on; undefined on the host's own. */
  target?: string;
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
  /**
   * Which `env` variables a client may set. Default: an allow-list (`TERM`, `COLORTERM`, `LANG`, `LANGUAGE`, `LC_*`).
   * `true` accepts everything (the behaviour before 0.36), `false` nothing, a list names exact variables or `PREFIX_*`
   * patterns (replacing the default list), a function decides per variable.
   */
  clientEnv?: WshClientEnv;
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

/** Who is calling a named endpoint: the authenticated identity of the connection. */
export interface WshGatewayWho { username: string | null; fingerprint: string | null }

/** What a named endpoint handler (or a client's `openEndpoint`) gets: web streams with backpressure. */
export interface WshGatewayEndpointDuplex {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  who: WshGatewayWho;
  /** #121: the execution target this endpoint belongs to; undefined for the host's own. */
  target?: string;
  /** Half-close: nothing more will be sent. */
  close(reason?: string): void;
  /** Tear the connection down now. */
  destroy(reason?: string): void;
  /** Settles when the connection is over (either side, or the client disconnected). */
  closed: Promise<string | undefined>;
}

export type WshGatewayEndpointHandler = (duplex: WshGatewayEndpointDuplex, who: WshGatewayWho) => void | Promise<void>;

export interface WshServerGatewayOptions {
  /** Destinations a client may reach: `"*"`, `"host"` (any port), `"host:port"`. Default deny. An IP-literal entry permits exactly that address even if private. */
  allow: string[];
  /** CIDR blocks or addresses the host may dial although they are not globally routable (`"10.0.0.0/8"`, `"127.0.0.1"`, `"fd00::/8"`). Default none. */
  allowPrivate?: string[];
  /** Concurrent gateway connections per client (default 32). */
  maxConnections?: number;
  connectTimeoutMs?: number;
  /** A UDP flow with no datagram in either direction for this long is closed (default 60000). */
  udpIdleMs?: number;
  /** Bytes received from a client for one connection and not yet taken by its origin before it is closed (default 4 MiB; at least 262144). */
  maxBufferedBytes?: number;
  /** The same, summed over one client's connections (default 32 MiB). */
  maxClientBufferedBytes?: number;
  socks?: string | { host: string; port: number };
  /**
   * Unix-domain sockets a client may reach (`OpenUnix`, feature `gateway-unix`) or ask the host to create
   * (`ListenUnix`). Off unless given; each entry is an absolute path (exact), a directory prefix with a trailing `/`,
   * or `@name` / `@prefix/` for the Linux abstract namespace. Checked after `realpath` of the parent directory; the
   * file must be a socket, not a symlink. Sockets the host creates are mode 0600 and removed on close.
   */
  unix?: {
    connect?: string[];
    listen?: string[];
    /** Let a client replace an existing STALE socket file when it asks to (OpenSSH `StreamLocalBindUnlink`). Default false. */
    replaceStale?: boolean;
    /** Unix listeners per client (default 4). */
    maxListeners?: number;
  };
  /** Named virtual endpoints (`OpenEndpoint`, feature `gateway-endpoints`): only these names exist. */
  endpoints?: Record<string, WshGatewayEndpointHandler | { open: WshGatewayEndpointHandler; authorize?: (who: WshGatewayWho) => boolean | Promise<boolean> }>;
  /** `false`: no TCP or DNS at all (an endpoints-only gateway). Default true. */
  tcp?: boolean;
  /**
   * TCP reverse tunnels (`ListenRequest`). OFF unless given (`true` = the defaults). The host binds `bindAddr` (default
   * 127.0.0.1) and ignores the client's `bind_addr` unless it is listed in `allowBindAddrs`; `ports` (default `[0, "1024-65535"]`)
   * is what a client may ask for, privileged ports only if listed.
   */
  reverse?: boolean | {
    enabled?: boolean;
    bindAddr?: string;
    allowBindAddrs?: string[];
    ports?: Array<number | string>;
    /** Reverse listeners per client (default 4). */
    maxListeners?: number;
    /** Open connections per listener (default 16); the next one is closed unannounced. */
    maxConnectionsPerListener?: number;
    /** `listen()` backlog (default 8). */
    backlog?: number;
    /** An accepted connection with no traffic either way for this long is closed (default 300000; 0 = never). */
    idleMs?: number;
  };
  /** Bounds of UDP flows (`OpenUdp`); all rates drop, not queue. */
  udp?: {
    /** Use WebTransport datagrams for a flow when the transport and the client have them (default true). */
    datagrams?: boolean;
    /** Concurrent UDP flows per client (default 16). */
    maxFlows?: number;
    /** Datagrams per second per flow (500), per client (2000), both directions. `Infinity` = unlimited. */
    packetsPerSecondPerFlow?: number;
    packetsPerSecondPerClient?: number;
    /** Payload bytes per second per client, both directions (default 4 MiB): bounds amplification. */
    bytesPerSecondPerClient?: number;
    /** A reply that does not fit one datagram: 'reliable' sends it on the control stream (default), 'drop' drops it and counts it. */
    oversize?: 'reliable' | 'drop';
  };
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
  /** Which `env` variables a client may add to the shell's environment; same forms and default as `exec.clientEnv`. */
  clientEnv?: WshClientEnv;
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
  /**
   * Called (not awaited; a throw is logged) when an authenticated operator asks to connect to a peer that is not
   * registered, with the operator, the fingerprint it asked for and the `ReverseConnect`'s claimed `username`. It
   * never changes the answer (the operator is still told `no such peer`); it lets the host reach the peer another
   * way, e.g. a Web Push notification.
   */
  onUnreachable?: (
    from: { username: string; fingerprint: string },
    targetFingerprint: string,
    request: { username?: string },
  ) => unknown;
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
  auth?: WshServerAuthOptions | ((who: WshServerPrincipal) => boolean | WshCapabilityGrant | Promise<boolean | WshCapabilityGrant>);
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
   * Serve the WebSocket listener over TLS (`wss://`) on the same port; these are the options of `https.createServer`.
   * The WebTransport listener has its own certificate (`webTransport`). Off (plain `ws://`) by default.
   */
  tls?: { cert: string | Uint8Array; key: string | Uint8Array; ca?: string | Uint8Array; passphrase?: string };
  /**
   * Answer the gateway opcodes (OpenTcp, ResolveDns, GatewayData, GatewayClose) so a client can open TCP connections and
   * resolve names from this host. Default deny: a destination must match `allow` (`"*"`, `"host"` any port, `"host:port"`).
   * `socks` dials through a SOCKS5 proxy (e.g. Tor at `127.0.0.1:9050`) with the name left unresolved; `ResolveDns` is then
   * refused. UDP and TCP reverse tunnels are answered with a failure. Off by default.
   *
   * The ADDRESS a name resolves to is checked too: the host resolves once, refuses every address
   * that is not globally routable (loopback, private, link-local, CGNAT, ULA, multicast, reserved, and IPv4 wrapped as
   * mapped / NAT64 / 6to4 IPv6) unless `allowPrivate` or an IP-literal `allow` entry says so, and connects to that
   * address. `ResolveDns` answers are filtered the same way. Gateway data is flow controlled (`gateway-credit`).
   */
  gateway?: WshServerGatewayOptions;
  /**
   * Handlers for application-defined control messages: one whose `type` is a string (protocol messages are numeric, so
   * there is no collision) from an authenticated connection is handed to `extensions[type]`. A throw is logged.
   */
  extensions?: Record<string, (msg: Record<string, unknown>, ctx: { username: string; fingerprint: string | null; send: (msg: object) => unknown }) => unknown>;
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
  /** End every authenticated connection this long after login; advertised as `AuthOk.ttl` (whole seconds, rounded up). 0 / omitted = never. */
  connectionTtlMs?: number;
  /**
   * Accept a key login only when its signature is bound to this connection (#119): `true` needs any binding kind, an array
   * names kinds that must all be bound (`host` needs `hostKey`; `tls-exporter` needs `wss://` served by this process, not a
   * TLS-terminating proxy; `cert-hash` needs WebTransport with `selfSigned`). Clients older than 0.36 cannot satisfy it.
   */
  requireChannelBinding?: boolean | Array<'cert-hash' | 'host' | 'tls-exporter'>;
  /**
   * Folders the operator's `wsh --share NAME=/abs/dir[:ro|:rw]` offers (#159): called once per share with an object of
   * async file operations to mount. Listing it makes the host state the `shares` feature.
   */
  onShare?: import('../host.js').WshOnShare;
  /** #163: told once per connection this host turned away (an operator, on a reverse host), with a stable reason code (`REFUSAL_REASONS`, from `@johnhenry/wsh/host`). */
  onRefused?: import('../host.js').WshOnRefused;
  /**
   * #121: execution targets (containers, VMs, workers, sandboxes), each with its own `exec` (`true` = a shell), `pty`, `fs`
   * (`{ root }` or operations) and `endpoints`, and an `authorize(who, { target, kind })`. A client names one in `Open`,
   * `FileOp` or `OpenEndpoint` and lists what it may use with `listTargets()`. Off unless given: the host then advertises no
   * `targets` and refuses a request that names one. A refused target and one that does not exist look the same to the client.
   */
  targets?: Record<string, Omit<import('../host.js').WshTargetOptions, 'exec' | 'fs'> & { exec?: true | WshServerExecOptions | WshExecRunner; fs?: WshServerFsOptions | import('../host.js').WshFileBackend }>;
  /** With `targets`: an `Open`, `FileOp` or `OpenEndpoint` that names no target is refused, so nothing runs on the host itself (`rpc` channels too). Does not cover the gateway, MCP or `Attach`. */
  requireTarget?: boolean;
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

/**
 * An already-accepted WebSocket-like duplex: `send(bytes)`, `close(code?)`, `readyState` (1 = open), and either Node-style
 * `on(event, fn)` or `addEventListener(event, fn)`. A `ws` socket, a browser/Worker `WebSocket`, or a test double.
 */
export interface WshAcceptableSocket {
  send(data: Uint8Array): void;
  close(code?: number): void;
  readonly readyState: number;
  on?(event: string, listener: (...args: any[]) => void): unknown;
  addEventListener?(event: string, listener: (ev: any) => void): unknown;
}

export interface WshAcceptOptions {
  /** What the embedder knows of the peer; `address` keys the password-failure throttle. */
  remote?: { address?: string; headers?: Record<string, unknown> };
  /**
   * Serve this connection without client-opened QMux data streams: exec output rides `SessionData`
   * (`data_mode: 'virtual'`) and `stream-announce` / `rpc` are not offered. For a peer that cannot open streams
   * (the released Rust client over WebSocket). Default `true`.
   */
  dataStreams?: boolean;
}

export interface WshServer {
  /** Start listening. Requires the `ws` package. */
  listen(): Promise<WshServerAddress>;
  /**
   * Serve a pre-upgraded transport -- a socket your own HTTP server, Worker or test already accepted -- with this
   * server's auth, features and sessions, so no listener of wsh's own is needed (`listen()` is optional).
   * Resolves once the connection is attached; the handle's `close()` drops it. `close()` of the server drops all of them.
   */
  accept(socket: WshAcceptableSocket, options?: WshAcceptOptions): Promise<{ close(): void }>;
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
  /** Counters of the gateway's UDP flows (datagrams in/out, drops by cause, oversize handling) and reverse listeners; null without a gateway. */
  gatewayStats(): { udp: Record<string, number>; reverse: Record<string, number> } | null;
  /** The advertised host identity; `null` before `listen()` resolves or without a `hostKey`. */
  hostKey(): WshServerHostKey | null;
}

export function createWshServer(options?: WshServerOptions): WshServer;

/**
 * Parse `authorized_keys`-style text into the raw 32-byte Ed25519 keys of the lines that carry NO options (malformed lines
 * skipped). A line with options is not returned, because its restrictions would be lost: use `auth.authorizedKeys` (which
 * enforces them) or `parseAuthorizedKeyEntries`.
 */
export function parseAuthorizedKeys(text: string): Uint8Array[];

/** What an `authorized_keys` line's options allow (wsh #122; the same on the Rust `wsh-server`). */
export interface KeyPermissions {
  /** A pty shell. */
  pty: boolean;
  /** `exec` channels. */
  exec: boolean;
  /** MCP discovery and calls. */
  mcp: boolean;
  /** File channels, `FileOp` and `wsh-fs`. */
  fileTransfer: boolean;
  /** Relay registration, listing and connecting. */
  relay: boolean;
  /** `command="..."`: the only command the key may run (replaces what the client asks for). */
  forcedCommand: string | null;
  /** `max-sessions=N`: most live pty/exec sessions the key may hold at once. */
  maxSessions: number | null;
  /** `capabilities="..."` (#122, step two): `null` when the line has none; else the list, default-deny (only what it names). */
  capabilities: string[] | null;
  /** `expires="..."`: the epoch second from which the key is refused, or `null`. */
  expires: number | null;
}

/**
 * Parse `authorized_keys`-style text, options included. `refused` lists the lines whose options this host does not
 * understand (`code`: `unknown-option`, `bad-syntax`, `bad-value`, `duplicate-option`); those keys are not let in.
 */
export function parseAuthorizedKeyEntries(text: string): {
  entries: Array<{ key: Uint8Array; options: string | null; permissions: KeyPermissions; line: number }>;
  refused: Array<{ line: number; code: string; reason: string; key: Uint8Array }>;
};

/** ServerHello feature: the host discovers client-opened exec data streams itself (no primer byte). */
export const STREAM_ANNOUNCE: 'stream-announce';

export interface WshReverseHostOptions {
  /** The relay to register with (`ws://` / `wss://`). */
  url: string;
  username: string;
  /** This host's identity; its fingerprint is what operators connect to. */
  keyPair: CryptoKeyPair;
  /** Who may be bridged to this host. Default: nobody. */
  accept?: (operator: {
    fingerprint: string;
    username: string;
    /** True when the operator signed a challenge from THIS host (wsh #117): `fingerprint` and `username` are then the operator's own claim, not the relay's. */
    proven: boolean;
    /** The operator's raw Ed25519 key, when `proven`. */
    publicKey?: Uint8Array;
  }) => boolean | Promise<boolean>;
  exec?: true | WshServerExecOptions | WshExecRunner;
  pty?: WshServerPtyOptions;
  fs?: WshServerFsOptions;
  mcp?: WshServerMcpOptions;
  /** Typed rpc channels (#191), as for `createWshServer` (the `wsh-host` and `wsh-fs` built-ins included), served to the bridged operator in virtual data mode and stated as `rpc-virtual` in `ReverseAccept.features` (so it needs `reportFeatures`). */
  rpc?: Record<string, true | WshServerFsOptions | WshRpcHandler | false | null | undefined>;
  rpcMaxMessageBytes?: number;
  rpcMaxInflight?: number;
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
  /**
   * Require the operator to prove its identity to this host (wsh #117) and seal the bridge: an operator that does not
   * offer proof is refused, `accept` runs only after the proof verifies (with the identity taken from the proof, not
   * the relay), and this host acts only on messages sealed under a key exchange both sides signed -- a relay cannot
   * inject an `Open`. Needs `e2e` and `reportFeatures`. Without it the proof is still requested when the relay and the
   * operator can do it, and reported as `proven`.
   */
  requireOperatorProof?: boolean;
  /** How long an operator has to answer the challenge (default 5000). */
  proofTimeoutMs?: number;
  /** Folders an operator offers over a bridge (#159), once per share, as an object of async file operations. */
  onShare?: import('../host.js').WshOnShare;
  /** #163: told once per connection this host turned away (an operator, on a reverse host), with a stable reason code (`REFUSAL_REASONS`, from `@johnhenry/wsh/host`). */
  onRefused?: import('../host.js').WshOnRefused;
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
