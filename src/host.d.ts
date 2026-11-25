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
  operate(op: string, path: string, args?: { offset?: number; length?: number; newPath?: string; data?: Uint8Array; target?: string }): Promise<{ metadata?: Record<string, unknown>; entries?: Array<Record<string, unknown>> }>;
  /** The whole file, for a `download:` channel. Throw if it is larger than `maxFileBytes`. */
  readWhole(path: string, options?: { target?: string }): Promise<Uint8Array>;
  /** Create or replace a file (creating its directories), for an `upload:` channel. */
  writeWhole(path: string, data: Uint8Array, options?: { target?: string }): Promise<void>;
  /** Write `data` at `offset` (omitted = replace the file), without truncating when an offset is given. */
  writeAt(path: string, data: Uint8Array, offset?: number, options?: { mkdirs?: boolean; target?: string }): Promise<void>;
  /** A byte range as chunks; only the `wsh-fs` rpc built-in (Node) reads it. */
  openRange?(path: string, options?: { offset?: number; length?: number; chunkBytes?: number; target?: string }): Promise<{ size: number; offset: number; length: number; chunks: AsyncIterable<Uint8Array> }>;
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

/** What a host that serves several execution targets takes for each (#121). The same forms as the host's own backends. */
export interface WshTargetOptions {
  /** A human line shown by `ListTargets`. */
  description?: string;
  /**
   * Who may use this target. Called for every `Open`, `FileOp` and `OpenEndpoint` naming it (`kind`: `exec`, `pty`, `file`,
   * `endpoint`) and for `ListTargets` (`kind: 'list'`); only `true` lets the caller on. Absent: any authenticated key.
   * A refusal looks like an unknown target to the client.
   */
  authorize?: (who: { username: string | null; fingerprint: string | null }, request: { target: string; kind: 'exec' | 'pty' | 'file' | 'endpoint' | 'list' }) => boolean | Promise<boolean>;
  /** `run(command, io)`; `io.target` is this target's name. (`true`, a shell, is for `createWshServer`.) */
  exec?: WshExecRunner | { run: WshExecRunner; timeoutMs?: number; clientEnv?: WshClientEnv };
  /** `spawn` is also given `{ target }` in its options. */
  pty?: WshServerPtyOptions;
  /** Every call is also given `{ target }`. */
  fs?: WshFileBackend;
  /** Named virtual endpoints of this target; the handler's `duplex.target` is its name. */
  endpoints?: Record<string, ((duplex: object, who: { username: string | null; fingerprint: string | null }) => void | Promise<void>) | { open: Function; authorize?: (who: object) => boolean | Promise<boolean> }>;
}

export interface WshResolvedBackends {
  execRunner: WshExecRunner | null;
  execOptions: { timeoutMs?: number; clientEnv?: WshClientEnv };
  pty: { spawn: WshServerPtyOptions['spawn']; shell: string; cwd?: string; env?: Record<string, string | undefined>; term: string } | null;
  files: Required<Pick<WshFileBackend, 'operate' | 'readWhole' | 'writeWhole' | 'writeAt' | 'maxFileBytes'>> & Pick<WshFileBackend, 'openRange'> | null;
  mcp: object | null;
  /** The validated `targets` option (#121), by name; null when the host has none. */
  targets: Map<string, object> | null;
  requireTarget: boolean;
}

/** Validate injected backends (no shell, no directory: `exec` is a function or `{ run }`, `fs` an object of operations). */
export function resolveBackends(options?: {
  exec?: WshExecRunner | { run: WshExecRunner; timeoutMs?: number; clientEnv?: WshClientEnv };
  pty?: WshServerPtyOptions;
  fs?: WshFileBackend;
  mcp?: WshServerMcpOptions;
  /** #121: execution targets, each with its own backends. Off unless given. */
  targets?: Record<string, WshTargetOptions>;
  /** With `targets`: a request that names none is refused. */
  requireTarget?: boolean;
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
  /**
   * With `sealSession: 'require'` (#244): how long after login the session may stay unsealed (default 30000). At the deadline the host
   * reports `seal-timeout` (`onRefused`), sends an `Error` naming it and closes the connection. 0 = no deadline. No effect where
   * sealing is not required.
   */
  sealTimeoutMs?: number;
  /**
   * #248: how long a connection may take, from the moment `attach()` accepts it, to complete its login (Hello and Auth), default 60000.
   * At the deadline the host reports `login-timeout` (`onRefused`), sends an `AuthFail` naming it and closes the connection.
   * 0 = no deadline. A connection attached with `authenticated` (already logged in by something else) has none.
   */
  loginTimeoutMs?: number;
  /** Folders the operator offers (`wsh --share`, #159): called once per share; listing it makes the host state `shares`. */
  onShare?: WshOnShare;
  /** Told once per connection this host turned away, with a stable reason code (#163). */
  onRefused?: WshOnRefused;
  log?: (line: string) => void;
  [key: string]: unknown;
}

/** The `ServerHello` feature of a host that can use shares (#159). */
export const SHARES_FEATURE: 'shares';

/** One connection over a byte pipe. */
export interface WshConnectionPipe {
  /** Send these bytes to the peer. */
  send(bytes: Uint8Array): void;
  remote?: { address?: string; headers?: Record<string, unknown> };
  /** End the underlying transport (the host ends the connection: a refused login, say). */
  closeTransport?(): void;
  /**
   * Serve the connection without client-opened QMux streams: exec output rides `SessionData` (`data_mode: 'virtual'`) and
   * `stream-announce` is not offered, and rpc is stated as `rpc-virtual` (#191). Default `true`. Needed for a peer that cannot open streams (#132).
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

/** A file's attributes on the operator's machine (`wsh --share`, #159). Times are milliseconds since the epoch. */
export interface WshShareAttr {
  type: 'file' | 'directory' | 'symlink';
  size: number;
  /** Permission bits only (`0o777` at most). */
  mode: number;
  mtimeMs: number;
  atimeMs: number;
  ctimeMs: number;
  nlink: number;
  ino: number;
  isFile(): boolean;
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
}

/** An entry of {@link WshShareFs.readdir}: attributes included, so listing a directory needs no `stat` per entry. */
export interface WshShareEntry extends WshShareAttr { name: string; /** A symlink's target. A link is never followed. */ target?: string }

/** An open file of a share. */
export interface WshShareFile {
  readonly attr: WshShareAttr;
  read(offset: number, length: number): Promise<{ data: Uint8Array; eof: boolean }>;
  write(offset: number, data: Uint8Array): Promise<number>;
  setattr(changes: WshShareChanges): Promise<WshShareAttr>;
  truncate(size: number): Promise<WshShareAttr>;
  close(): Promise<void>;
}

export interface WshShareChanges { mode?: number; atimeMs?: number; mtimeMs?: number; size?: number }

/** An errno-like failure answered by the operator's client (`code`: `ENOENT`, `EROFS`, `EEXIST`, `ELOOP`, `EPERM`, ...). */
export class ShareError extends Error { readonly errno: string; readonly code: string }

/**
 * One folder the operator shares with this host (`wsh --share NAME=/abs/dir[:ro|:rw]`, #159): async file operations
 * answered by the operator's client, which confines every path to the folder. Paths are relative to the folder root.
 * It also has the shape of a {@link WshFileBackend} (`operate`, `readWhole`, `writeWhole`, `writeAt`), so it can be served on.
 */
export interface WshShareFs extends WshFileBackend {
  readonly name: string;
  /** Whether the operator offered writes (`:rw`). A change on a read-only share fails with `EROFS`. */
  readonly writable: boolean;
  /**
   * The folder's absolute path on the operator's machine, as the operator typed it (made absolute and tidied), or
   * `undefined` when the operator's client did not send it (an older client, or `wsh --share-hide-path`) or sent
   * something invalid (not absolute, a NUL, over 4096 bytes, the wrong count). ADVISORY: the host cannot verify it, so use
   * it only to recognise a share (a bind-mount source, say), never to decide what is safe. The operator's client still
   * serves only the folder it opened, whatever this says.
   */
  readonly root: string | undefined;
  /** Aborted when the connection to the operator ends; every later call fails with `EIO`. */
  readonly signal: AbortSignal;
  /** Requests, replies, errors, bytes each way and timeouts on this connection so far. */
  readonly stats: { requests: number; replies: number; errors: number; bytesDown: number; bytesUp: number; timeouts: number };
  stat(path: string): Promise<WshShareAttr>;
  lstat(path: string): Promise<WshShareAttr>;
  readlink(path: string): Promise<string>;
  /** The whole directory with attributes, sorted by name, in as few messages as the operator's page size allows. */
  readdir(path: string): Promise<WshShareEntry[]>;
  open(path: string, flags?: Array<'read' | 'write' | 'create' | 'excl' | 'trunc'>, options?: { mode?: number; inlineBytes?: number }): Promise<WshShareFile>;
  create(path: string, options?: { mode?: number }): Promise<WshShareFile>;
  /** A small file arrives with the open (one round trip). */
  readFile(path: string, options?: { maxBytes?: number }): Promise<Uint8Array>;
  writeFile(path: string, data: Uint8Array, options?: { mode?: number; truncate?: boolean }): Promise<number>;
  mkdir(path: string, options?: { mode?: number }): Promise<WshShareAttr>;
  unlink(path: string): Promise<void>;
  rmdir(path: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  setattr(path: string, changes: WshShareChanges): Promise<WshShareAttr>;
  truncate(path: string, size: number): Promise<WshShareAttr>;
  chmod(path: string, mode: number): Promise<WshShareAttr>;
  utimes(path: string, atimeMs: number, mtimeMs: number): Promise<WshShareAttr>;
}

/** Called once per share the operator offers (#159). Mount `fs` where you like; `who` is the authenticated operator. */
export type WshOnShare = (name: string, fs: WshShareFs, who: { username: string | null; fingerprint: string | null }) => void | Promise<void>;

/** The stable reason codes of `onRefused` (#163). New ones may be added; none is renamed. */
export const REFUSAL_REASONS: readonly WshRefusalReason[];
export type WshRefusalReason =
  | 'not-sealed' | 'unauthorized' | 'binding-required' | 'bad-signature' | 'method-disabled' | 'rate-limited' | 'bad-request'
  | 'seal-failed' | 'busy' | 'proof-required' | 'proof-failed' | 'key-expired' | 'not-permitted' | 'seal-timeout';
/**
 * Called once per connection a host turned away (#163): `reason` is a stable code, `who` what is known of the peer (a
 * refusal before the login names no one), `detail` human text that is not stable. Not for parsing `onLog`.
 * Reverse hosts also use `busy`, `proof-required`, `proof-failed`; a sealed session that fails mid-way reports `seal-failed`.
 * `key-expired` (a key past its `expires`, at login or later) and `not-permitted` (a request the key's options or capabilities do not
 * allow; `detail` names the missing capability) are not per connection: `not-permitted` can come any number of times on one (#122).
 */
export type WshOnRefused = (refusal: { reason: WshRefusalReason; who: { username?: string; fingerprint?: string; address?: string }; detail: string }) => void;
