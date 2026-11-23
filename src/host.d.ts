import type { WshSigner } from './index.js';
import type {
  WshExecRunner, WshServerPtyOptions, WshServerMcpOptions, WshServerAuthOptions, WshServerPrincipal, WshAcceptableSocket, WshAcceptOptions, WshClientEnv,
} from './server/index.js';

/**
 * File operations a host serves `FileOp` requests and `upload:` / `download:` channels from. An object of
 * operations, not a root path: confining client paths to what the host may expose is the backend's job.
 * (`createWshServer({ fs: { root } })` builds one of these over a directory.)
 */
export interface WshFileBackend {
  /**
   * `list` -> `{ entries, metadata: { path } }`; `stat` -> `{ metadata: { name, size, modified, type } }`;
   * `read` (`offset`, `length`) -> `{ metadata: { data, size } }`; `write` (`offset`, `data`) -> `{ metadata: { written } }`;
   * `rename` (`newPath`); `mkdir`; `remove`. Anything else should throw.
   */
  operate(op: string, path: string, args?: { offset?: number; length?: number; newPath?: string; data?: Uint8Array }): Promise<{ metadata?: Record<string, unknown>; entries?: Array<Record<string, unknown>> }>;
  /** The whole file, for a `download:` channel. Throw if it is larger than `maxFileBytes`. */
  readWhole(path: string): Promise<Uint8Array>;
  /** Create or replace a file (creating its directories), for an `upload:` channel. */
  writeWhole(path: string, data: Uint8Array): Promise<void>;
  /** Write `data` at `offset` (omitted = replace the file), without truncating when an offset is given. */
  writeAt(path: string, data: Uint8Array, offset?: number, options?: { mkdirs?: boolean }): Promise<void>;
  /** A byte range as chunks; only the `wsh-fs` rpc built-in (Node) reads it. */
  openRange?(path: string, options?: { offset?: number; length?: number; chunkBytes?: number }): Promise<{ size: number; offset: number; length: number; chunks: AsyncIterable<Uint8Array> }>;
  /** Largest file read or written whole, in bytes (default 64 MiB). */
  maxFileBytes?: number;
}

/** A host's own identity: a key pair (the private key may be non-extractable) or a signer for a key held elsewhere. */
export type WshHostKeyOption = true | CryptoKeyPair | WshSigner;

/** The identity `resolveHostKey` makes of a `WshHostKeyOption`. */
export interface WshResolvedHostKey {
  /** Raw 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  fingerprint: string;
  openssh: string;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export interface WshResolvedBackends {
  execRunner: WshExecRunner | null;
  execOptions: { timeoutMs?: number; clientEnv?: WshClientEnv };
  pty: { spawn: WshServerPtyOptions['spawn']; shell: string; cwd?: string; env?: Record<string, string | undefined>; term: string } | null;
  files: Required<Pick<WshFileBackend, 'operate' | 'readWhole' | 'writeWhole' | 'writeAt' | 'maxFileBytes'>> & Pick<WshFileBackend, 'openRange'> | null;
  mcp: object | null;
}

/** Validate injected backends (no shell, no directory: `exec` is a function or `{ run }`, `fs` an object of operations). */
export function resolveBackends(options?: {
  exec?: WshExecRunner | { run: WshExecRunner; timeoutMs?: number; clientEnv?: WshClientEnv };
  pty?: WshServerPtyOptions;
  fs?: WshFileBackend;
  mcp?: WshServerMcpOptions;
}): WshResolvedBackends;

/** Validate a file backend (see {@link WshFileBackend}). */
export function normalizeFileBackend(fs: WshFileBackend, who?: string): NonNullable<WshResolvedBackends['files']>;

/** Make the identity a host presents from a `CryptoKeyPair`, a signer, or `true` (a fresh non-extractable key). */
export function resolveHostKey(option: WshHostKeyOption, who?: string): Promise<WshResolvedHostKey>;

/** The `authorize(who)` function for a host's `auth` option (as `createWshServer` reads it). */
export function buildAuthorizer(auth: WshServerAuthOptions | ((who: WshServerPrincipal) => boolean | Promise<boolean>) | undefined): Promise<(who: { username: string; fingerprint: string; publicKey: Uint8Array }) => Promise<boolean>>;

/** Which auth methods an `auth` option turns on. */
export function authMethods(auth: WshServerAuthOptions | ((who: WshServerPrincipal) => boolean | Promise<boolean>) | undefined): { pubkey: boolean; password: ((user: string, pass: string) => boolean | Promise<boolean>) | null };

/** What the connection handler is given. Everything but `authorize` is optional. */
export interface WshConnectionConfig extends Partial<WshResolvedBackends> {
  /** Required: decides who is let in. A host with no authorizer would let everyone in, so there is no default. */
  authorize(who: { username: string; fingerprint?: string; publicKey?: Uint8Array }): Promise<boolean>;
  /** Auth methods on (default: pubkey only). */
  methods?: { pubkey: boolean; password: ((user: string, pass: string) => boolean | Promise<boolean>) | null };
  hostKey?: WshResolvedHostKey | null;
  /** Handlers for application-defined (string-typed) messages. */
  extensions?: Record<string, (message: any, ctx: { username: string | null; fingerprint: string | null; send(message: object): Promise<void> }) => unknown>;
  /** A `SessionRegistry` (see `src/session-registry.mjs`): detach / attach / resume. Null = sessions die with their connection. */
  sessions?: object | null;
  /** End-to-end encryption for a message-framed (relay-bridged) connection. */
  e2e?: { signKey: CryptoKey | null; hybrid?: boolean } | null;
  /** How long exec output waits for the client-opened data stream (default 3000). */
  bindTimeoutMs?: number;
  log?: (line: string) => void;
  [key: string]: unknown;
}

/** One connection over a byte pipe. */
export interface WshConnectionPipe {
  /** Send these bytes to the peer. */
  send(bytes: Uint8Array): void;
  remote?: { address?: string; headers?: Record<string, unknown> };
  /** End the underlying transport (the host ends the connection: a refused login, say). */
  closeTransport?(): void;
  /**
   * Serve the connection without client-opened QMux streams: exec output rides `SessionData` (`data_mode: 'virtual'`) and
   * `stream-announce` / `rpc` are not offered. Default `true`. Needed for a peer that cannot open streams (#132).
   */
  dataStreams?: boolean;
}

/** One connection over messages (a transport that does its own framing, e.g. a relay bridge). */
export interface WshConnectionMessages {
  sendMessage(message: object): unknown;
  /** The identity something else already authenticated: skips the handshake. */
  authenticated?: { username: string; fingerprint: string } | null;
  dataStreams?: boolean;
  e2e?: { signKey: CryptoKey | null; hybrid?: boolean } | null;
  remote?: { address?: string; headers?: Record<string, unknown> };
  closeTransport?(): void;
}

export interface WshConnection {
  /** Bytes from the peer (byte-pipe form). */
  receive(bytes: Uint8Array): void;
  /** One decoded message from the peer (message form). */
  receiveMessage(message: object): void;
  /** A QMux-style stream opened by the peer (message form, when it has them). */
  bindStream?(stream: object): void;
  close(): void;
}

export type WshConnectionAttach = (pipe: WshConnectionPipe | WshConnectionMessages) => WshConnection;

/**
 * The connection handler every wsh host runs. Returns `attach`, called once per connection. Over a WebSocket-like
 * duplex use {@link bindSocket} rather than calling it by hand.
 */
export function createConnectionFactory(config: WshConnectionConfig): WshConnectionAttach;

/** The features a host built from `config` advertises in `ServerHello` (minus the host-key proof). */
export function hostFeatures(config: Partial<WshConnectionConfig>, options?: { dataStreams?: boolean }): string[];

/** ServerHello feature: the host discovers client-opened exec data streams itself (no primer byte). */
export const STREAM_ANNOUNCE: 'stream-announce';

/**
 * Serve a pre-upgraded WebSocket-like duplex (`send`, `close`, `readyState`, and `addEventListener` or `on`) with the
 * connection handler `ready` resolves to. Resolves once attached; the handle's `close()` drops the connection.
 */
export function bindSocket(
  socket: WshAcceptableSocket,
  ready: Promise<WshConnectionAttach>,
  options?: WshAcceptOptions,
): Promise<{ close(): void }>;
