import type { WshClient, RpcChannel } from './index.js';
import type { WshSigner } from './index.js';
import type { WshFileBackend, WshHostKeyOption, WshOnShare, WshOnRefused } from './host.js';
import type {
  WshServerAuthOptions, WshServerPrincipal, WshServerMcpOptions, WshExecRunner, WshServerOptions, WshServerPtyOptions, WshClientEnv,
  WshAcceptableSocket, WshAcceptOptions, WshGatewayEndpointHandler as WshMemoryEndpointHandler,
} from './server/index.js';

export interface WshMemorySessionsOptions {
  /** How long a session nobody is attached to keeps running (default 300000; 0 = kill at once). */
  detachTtlMs?: number;
  /** Unattended sessions kept at once (default 16); beyond that the longest-detached is killed. */
  maxDetached?: number;
  /** Output history kept per session, i.e. what a resume can replay (default 1048576 bytes). */
  ringBytes?: number;
}

/** What an rpc handler is told about its channel. */
export interface WshMemoryRpcContext {
  protocol: string;
  channelId: number;
  user: string | null;
  fingerprint: string | null;
  features: string[];
  log(line: string): void;
  [key: string]: unknown;
}

export interface WshMemoryHostOptions {
  /** As for `createWshServer`. Omitted = refuse everyone. */
  auth?: WshServerAuthOptions | ((who: WshServerPrincipal) => boolean | Promise<boolean>);
  /** `run(command, io)`; there is no shell in memory, so there is no `true`. */
  exec?: WshExecRunner | { run: WshExecRunner; timeoutMs?: number; clientEnv?: WshClientEnv };
  /** `node-pty`-shaped `{ spawn }`, injected (a browser has no pty of its own). Input arrives at `write` as a `Uint8Array`. Off unless given. */
  pty?: WshServerPtyOptions;
  /** An object of file operations, not a root path (confining paths is the backend's job). Off unless given. */
  fs?: WshFileBackend;
  /**
   * This host's own identity, so clients can pin it: a `CryptoKeyPair` (the private key may be non-extractable), a signer
   * `{ publicKey, sign }` for a key held elsewhere, or `true` for a fresh non-extractable key. Off unless given.
   */
  hostKey?: WshHostKeyOption;
  /**
   * Offer client-opened QMux data streams (default `true`). `false` serves exec output as `SessionData` instead and
   * offers neither `stream-announce` nor `rpc`: needed for a peer that cannot open streams, the released Rust client over
   * WebSocket (#132). Released clients state nothing a host could choose on, so this is an option, not a negotiation;
   * `accept(socket, { dataStreams })` overrides it for one connection.
   */
  dataStreams?: boolean;
  mcp?: WshServerMcpOptions;
  extensions?: WshServerOptions['extensions'];
  /** Typed RPC channels: one handler per protocol, called once per opened channel to register methods. Handler functions only (the `wsh-host` / `wsh-fs` built-ins need Node). Off unless given. */
  rpc?: Record<string, ((channel: RpcChannel, ctx: WshMemoryRpcContext) => void | Promise<void>) | false | null | undefined>;
  /** Largest single rpc message (default 1048576; at least 256). */
  rpcMaxMessageBytes?: number;
  /** Concurrent requests per rpc channel before `-32002` (default 64). */
  rpcMaxInflight?: number;
  /**
   * Keep exec sessions alive across disconnects so `resumeSession()` / `attachSession()` work, with the same
   * defaults as `createWshServer`. `true` for the defaults. Off unless given.
   */
  sessions?: true | false | null | WshMemorySessionsOptions;
  /**
   * Named virtual endpoints: a host with no file system exposes these instead of unix sockets; a client reaches one with
   * `client.openEndpoint(name)`. The handler gets web streams with backpressure and `who` (the authenticated
   * `{ username, fingerprint }`) and refuses by throwing; `{ open, authorize(who) }` authorises per call. Only the
   * names listed exist. Nothing else of the gateway (TCP, DNS, unix sockets) is available in memory.
   */
  endpoints?: Record<string, WshMemoryEndpointHandler | { open: WshMemoryEndpointHandler; authorize?: (who: { username: string | null; fingerprint: string | null }) => boolean | Promise<boolean> }>;
  bindTimeoutMs?: number;
  /** End each authenticated connection this long after login; advertised as `AuthOk.ttl` in whole seconds. 0 / omitted = never. */
  connectionTtlMs?: number;
  /**
   * Accept a key login only when its signature is bound to this host's key (`host`, the one binding a memory host has).
   * Needs `hostKey`; a client older than 0.36 cannot satisfy it.
   */
  requireChannelBinding?: boolean | Array<'host'>;
  /**
   * Folders of the OPERATOR's machine (#159): `wsh --share NAME=/abs/dir[:ro|:rw]` offers them after login, and this is
   * called once per share with an object of async file operations the page can mount (a host with no disk of its own
   * can then serve `docker run -v $PWD:/app`). Listing it makes the host state the `shares` feature; a host without it
   * never hears a share offer. See `WshShareFs`.
   */
  onShare?: WshOnShare;
  /** #155: seal the whole session end to end (needs `hostKey`; offered where `dataStreams` is false). `'require'` serves nothing unsealed. */
  sealSession?: false | 'offer' | 'require';
  /** #163: told once per connection this host turned away (a key it does not allow, a plain client on a host that requires a sealed session, ...), with a stable reason code. */
  onRefused?: WshOnRefused;
  onLog?: (line: string) => void;
}

/** Credentials for `host.connect()`: the options of `WshClient.connect()` minus the URL. */
export interface WshMemoryConnectOptions {
  username: string;
  keyPair?: CryptoKeyPair;
  signer?: WshSigner;
  password?: string;
  timeout?: number;
}

export interface WshMemoryHost {
  /** The URL to give `client.connect()`; the host ignores it. */
  readonly url: string;
  /** A `WebSocket` constructor that dials this host. */
  readonly WebSocket: new (url?: string) => any;
  /** Serve any pre-upgraded socket (see `createSocketPair()`). */
  accept(socket: WshAcceptableSocket, options?: WshAcceptOptions): Promise<{ close(): void }>;
  socketPair: typeof createSocketPair;
  /** A `WshClient` whose transport is this host: `await client.connect(host.url, { username, keyPair, transport: 'ws' })`. */
  createClient(options?: ConstructorParameters<typeof WshClient>[0]): WshClient;
  /** `createClient()` and `connect()` in one. */
  connect(credentials: WshMemoryConnectOptions): Promise<WshClient>;
  /** Drop every connection. */
  close(): Promise<void>;
}

/** Two connected in-memory WebSocket-like sockets. */
export function createSocketPair(): [WshAcceptableSocket & EventTarget, WshAcceptableSocket & EventTarget];

/** A browser-safe wsh host in this JavaScript realm: no sockets, no Node. */
export function createMemoryHost(options?: WshMemoryHostOptions): WshMemoryHost;
