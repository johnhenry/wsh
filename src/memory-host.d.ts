import type { WshClient } from './index.js';
import type { WshSigner } from './index.js';
import type {
  WshServerAuthOptions, WshServerPrincipal, WshServerMcpOptions, WshExecRunner, WshServerOptions,
  WshAcceptableSocket, WshAcceptOptions,
} from './server/index.js';

export interface WshMemoryHostOptions {
  /** As for `createWshServer`. Omitted = refuse everyone. */
  auth?: WshServerAuthOptions | ((who: WshServerPrincipal) => boolean | Promise<boolean>);
  /** `run(command, io)`; there is no shell in memory, so there is no `true`. */
  exec?: WshExecRunner | { run: WshExecRunner; timeoutMs?: number; clientEnv?: boolean };
  mcp?: WshServerMcpOptions;
  extensions?: WshServerOptions['extensions'];
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
