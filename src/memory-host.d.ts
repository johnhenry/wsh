import type { WshClient, RpcChannel } from './index.js';
import type { WshSigner } from './index.js';
import type {
  WshServerAuthOptions, WshServerPrincipal, WshServerMcpOptions, WshExecRunner, WshServerOptions,
  WshAcceptableSocket, WshAcceptOptions,
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
  exec?: WshExecRunner | { run: WshExecRunner; timeoutMs?: number; clientEnv?: boolean };
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
  sessions?: true | WshMemorySessionsOptions;
  bindTimeoutMs?: number;
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
