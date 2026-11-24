import type { RpcChannel } from './index.js';
import type { WshRpcContext } from './server/index.js';
import type { WshOnRefused } from './host.js';
import type { ObjectsAllow, ObjectsWho, ObjectsOperation, ObjectsLimits } from './objects.js';

export { exposeObjects } from './objects.js';

/** The part of a `Window` (or `WorkerGlobalScope`, or a test double) this entry point reads. Everything is optional except what the call needs. */
export interface WshPageWindow {
  document?: any;
  navigator?: any;
  location?: { origin?: string };
  closed?: boolean;
  WebSocket?: new (url: string) => any;
  setTimeout?: (fn: () => void, ms?: number) => any;
  clearTimeout?: (id: any) => void;
  setInterval?: (fn: () => void, ms?: number) => any;
  clearInterval?: (id: any) => void;
  addEventListener?: (type: string, fn: (ev: any) => void) => void;
  removeEventListener?: (type: string, fn: (ev: any) => void) => void;
}

/** The timers of the realm that runs this code, when it is not the window's own (an opener serving a popup, a parent serving an iframe). */
export interface WshPageTimers {
  setTimeout?: (fn: () => void, ms?: number) => any;
  clearTimeout?: (id: any) => void;
  setInterval?: (fn: () => void, ms?: number) => any;
  clearInterval?: (id: any) => void;
}

/** A tool as the page passes it to `registerTool` (the WebMCP draft's `ModelContextTool`). */
export interface WebMcpToolDefinition {
  /** 1-128 characters of letters, digits, `_`, `-` and `.`. */
  name: string;
  title?: string;
  description: string;
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: {
    /** The tool only reads. A tool not marked read-only is consequential: it is asked about under `approve: 'consequential'`. */
    readOnlyHint?: boolean;
    untrustedContentHint?: boolean;
    consequentialHint?: boolean;
    debugging?: boolean;
  };
  execute(input: Record<string, any>, options: { signal: AbortSignal }): unknown | Promise<unknown>;
}

/** What `captureWebMcp(window)` recorded. */
export interface WebMcpCapture {
  list(): WebMcpToolDefinition[];
  get(name: string): WebMcpToolDefinition | undefined;
  /** Told when the set of registered tools changes. Returns the function that stops listening. */
  subscribe(fn: () => void): () => void;
  /** Put every wrapped function back and remove what was provided. The recorded tools stay. */
  restore(): void;
  /** What was wrapped or provided: `document.modelContext`, `navigator.modelContext`, `... (provided)`. */
  readonly installed: string[];
}

/**
 * Record the tools the application registers on `window`. Call it BEFORE the application's code. Wraps `registerTool` on
 * `window.document.modelContext` and `window.navigator.modelContext`, honours the registration's abort signal and `unregister()`, and provides
 * a minimal `modelContext` where the browser has none. Calling it again for the same window returns the same capture.
 */
export function captureWebMcp(window: WshPageWindow): WebMcpCapture;

/** The bounds of the tool server; each is refused by name. */
export interface WebMcpLimits {
  /** Default 64. Tools beyond it are not listed and cannot be called. */
  maxTools: number;
  /** Default 16384. Bytes of one tool's schemas as JSON; a tool over it is not listed and cannot be called. */
  maxSchemaBytes: number;
  /** Default 65536. Bytes of one call's arguments as JSON. */
  maxInputBytes: number;
  /** Default 262144. Bytes of one result as JSON. */
  maxResultBytes: number;
  /** Default 4. Calls running or waiting for the person's answer, per session. */
  maxInflight: number;
  /** Default 30. Calls started in any 60 seconds, per session (an unknown tool counts). */
  maxCallsPerMinute: number;
  /** Default 120000. A call still running then is aborted and fails. */
  callTimeoutMs: number;
}
export const WEBMCP_DEFAULT_LIMITS: Readonly<WebMcpLimits>;

/** What the person at the page is asked about. */
export interface WebMcpCall {
  name: string;
  title: string | null;
  description: string;
  input: Record<string, unknown>;
  consequential: boolean;
  readOnly: boolean;
}
export interface WebMcpWho { username: string | null; fingerprint: string | null }
/** Answers `true` to allow the call; anything else denies. `signal` aborts when the call is cancelled or the session ends. */
export type WebMcpPrompt = (call: WebMcpCall, who: WebMcpWho, extra: { signal: AbortSignal }) => boolean | Promise<boolean>;

export interface WebMcpCallEvent {
  outcome: 'ok' | 'error' | 'denied' | 'approved' | 'refused' | 'unknown' | 'unlisted';
  name?: string;
  who?: WebMcpWho;
  /** For `refused` and `unlisted`: the bound, by name (`maxTools`, `maxSchemaBytes`, `maxInputBytes`, `maxResultBytes`, `maxInflight`, `maxCallsPerMinute`). */
  limit?: string;
  detail?: string;
}

export interface WebMcpToolsOptions {
  /** The realm whose tools are served. Required. */
  window: WshPageWindow;
  /** Tool names that may be listed and called. Nothing is allowed by default. */
  allow?: string[];
  /** Ask the person at the page: never, for tools not marked read-only (default), or for every call. */
  approve?: 'never' | 'consequential' | 'always';
  /** Asks the person. Without one, a window with a document gets the default dialog; otherwise what needs approval is denied. */
  prompt?: WebMcpPrompt;
  /** The definitions the page passes to `registerTool` (source 1). */
  tools?: WebMcpToolDefinition[];
  /** A capture other than the one `captureWebMcp(window)` made. */
  capture?: { list(): WebMcpToolDefinition[]; subscribe?(fn: () => void): () => void } | null;
  limits?: Partial<WebMcpLimits>;
  onCall?: (event: WebMcpCallEvent) => void;
  /** Returns why the window is gone (every call is then refused), or null. */
  guard?: () => string | null;
  /** The `serverInfo` of `initialize`. */
  server?: { name?: string; version?: string };
  timers?: WshPageTimers;
  now?: () => number;
}

/** The `mcp` rpc handler for `createMemoryHost({ rpc: { mcp } })`, `createReverseHost` and so on. It declares itself `capabilityScoped`. */
export interface WebMcpHandler {
  /** It needs from the host's rpc context only who is calling and `permits` (a host that gives no `permits` serves every allowed tool). */
  (channel: RpcChannel, ctx?: { user?: string | null; fingerprint?: string | null; permits?: (request: { kind: string; [field: string]: unknown }) => boolean }): void;
  capabilityScoped: true;
  /** Tell every session (or those of one key) why, then end it. Resolves with how many were ended. */
  closeSessions(reason: string, fingerprint?: string): Promise<number>;
  /** The tools (as `tools/list` states them) a key with no limits would see now. */
  list(): Promise<object[]>;
}

/** The page's WebMCP tools as MCP, an rpc handler for the `mcp` protocol. */
export function webmcpTools(options: WebMcpToolsOptions): WebMcpHandler;

/** The default `prompt`: an accessible modal dialog in `window.document` (a key's fingerprint, the tool, the input as text; Deny has focus; Escape and a timeout deny). */
export function createDomPrompt(window: WshPageWindow, options?: { timeoutMs?: number; timers?: WshPageTimers }): WebMcpPrompt;

export interface WshPageIndicatorCallbacks {
  connected(who: { username: string; fingerprint: string }, control: { stop(): Promise<boolean> }): void;
  disconnected(who: { username: string; fingerprint: string }): void;
}

export interface WshPageHostOptions {
  /** The realm to serve: required, and the only thing read. Passing it exposes nothing by itself. */
  window: WshPageWindow;
  /** A pipe relay (`@johnhenry/wsh/pipe-relay`): its `ws://` / `wss://` URL, or `{ url, id }` with a rendezvous id of your own. */
  relay: string | { url: string; id?: string };
  /** What this tab is called: shown in the indicator, the `serverInfo.name` of the MCP server. */
  name: string;
  /** Who may log in: `authorized_keys` lines (options such as `capabilities="mcp:search"` apply) or raw 32-byte keys. Required. */
  authorizedKeys: string | Uint8Array | Array<string | Uint8Array>;
  /** The page's WebMCP tools as MCP. At least one of `mcp` and `expose` is needed. */
  mcp?: Omit<WebMcpToolsOptions, 'window' | 'guard' | 'timers'>;
  /**
   * Object access (`wsh-objects`, `values` mode), off unless written: named roots, each with its allow-lists by operation (paths RELATIVE to the root:
   * `'document.title'`, `'app.**'`; nothing allowed by default). A root named `window` is the window that was passed; another name needs `object`.
   * `mode: 'handles'` is refused: not built. See `@johnhenry/wsh/objects`.
   */
  expose?: Record<string, { mode?: 'values'; allow?: ObjectsAllow; authorize?: (who: ObjectsWho, op: ObjectsOperation) => boolean | Promise<boolean>; limits?: Partial<ObjectsLimits>; object?: object }>;
  /** `true` (default): the badge in `window.document`. Callbacks: for a context with no document, or your own UI. `false` needs `unattended: true`. */
  indicator?: boolean | WshPageIndicatorCallbacks;
  /** Nobody is in front of this window. Allows `indicator: false` and a window with no document; what needs approval is then denied unless `mcp.prompt` answers. */
  unattended?: boolean;
  /** This host's identity: a key pair or a signer. By default a fresh non-extractable key per page load. */
  hostKey?: CryptoKeyPair | { publicKey: Uint8Array | CryptoKey; sign(data: Uint8Array): Promise<Uint8Array> | Uint8Array };
  /** Persist the generated key through a store you inject (a non-extractable `CryptoKeyPair` can be kept in IndexedDB). */
  hostKeyStore?: { load(): Promise<CryptoKeyPair | null | undefined> | CryptoKeyPair | null | undefined; save(pair: CryptoKeyPair): Promise<void> | void };
  /** A key logged in. Return `false` to refuse it (ask the person first). */
  onSession?: (who: { username: string; fingerprint: string }) => boolean | void | Promise<boolean | void>;
  onSessionEnd?: (who: { username: string; fingerprint: string }) => void;
  onRefused?: WshOnRefused;
  /** The host closed itself (the window navigated to another origin, or closed) or was closed. */
  onClose?: (closed: { reason: string }) => void;
  timers?: WshPageTimers;
  /** Dial the relay again after a session or a failed attempt (default true). */
  reconnect?: boolean;
  onLog?: (line: string) => void;
}

export interface WshPageHost {
  /** The URL an operator dials. Its rendezvous id is the secret that pairs the operator with this page. */
  readonly operatorUrl: string;
  readonly rendezvousId: string;
  readonly name: string;
  /** The origin the host was started in; it closes if the window leaves it. */
  readonly origin: string;
  /** This host's key fingerprint, for the operator to pin (new on every page load unless a key or a `hostKeyStore` was given). */
  readonly fingerprint: string;
  /** Who is connected now. */
  readonly sessions: Array<{ username: string; fingerprint: string; since: number }>;
  readonly closed: boolean;
  /** Why the host closed itself, or null. */
  readonly closedReason: string | null;
  /** End the session of a key, telling the operator why, and refuse that key until this host is closed. Resolves true if a session was ended. */
  revoke(fingerprint: string): Promise<boolean>;
  close(): Promise<void>;
}

/** A page (or any window-shaped realm) as a host behind a pipe relay it chose: key login only, sealed sessions only, the window's WebMCP tools as MCP. */
export function createPageHost(options: WshPageHostOptions): Promise<WshPageHost>;

export type { RpcChannel, WshRpcContext };
