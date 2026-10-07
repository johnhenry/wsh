/**
 * Types for `@johnhenry/wsh/server` -- the Node host. Node-only; the package
 * root (`@johnhenry/wsh`) never imports it.
 */

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
  /** Serve MCP tools (`McpDiscover` / `McpCall`) and advertise `mcp-call-id`. Off by default. */
  mcp?: WshServerMcpOptions;
  /** How long exec output waits for a client that has not yet opened its data stream (default 3000). */
  bindTimeoutMs?: number;
  onLog?: (line: string) => void;
}

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
  /** The advertised host identity; `null` before `listen()` resolves or without a `hostKey`. */
  hostKey(): WshServerHostKey | null;
}

export function createWshServer(options?: WshServerOptions): WshServer;

/** Parse `authorized_keys`-style text into raw 32-byte Ed25519 keys (malformed lines skipped). */
export function parseAuthorizedKeys(text: string): Uint8Array[];

/** ServerHello feature: the host discovers client-opened exec data streams itself (no primer byte). */
export const STREAM_ANNOUNCE: 'stream-announce';
