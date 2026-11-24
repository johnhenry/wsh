import type { RpcChannel, WshClient } from './index.js';

/** The rpc protocol name. */
export const OBJECTS_PROTOCOL: 'wsh-objects';

/** Error codes of the protocol (JSON-RPC's where one fits). */
export const OBJECTS_ERROR: Readonly<{ INVALID: -32602; LIMIT: -32002; REFUSED: -32003; FAILED: -32000 }>;

/**
 * A refusal or failure. `reason` names the rule: `always-refused`, `not-allowed`, `needs-listing`, `authorize`, `limit` (then `data.limit` names the bound),
 * `bad-request`, `no-such-root`, `bad-path`, `not-a-function`, `threw`, `gone`, `closed`.
 */
export class ObjectsError extends Error {
  constructor(code: number, message: string, data?: { reason?: string; [k: string]: unknown });
  code: number;
  data?: { reason?: string; limit?: string; max?: number; path?: string; op?: string; [k: string]: unknown };
  reason?: string;
}

/** What a remote value that cannot be cloned arrives as: named, never a handle. `kind`: `function`, `symbol`, `bigint`, `number` (too large for the wire), `Date`, `RegExp`, `Error`, `object`. */
export class NonValue {
  constructor(wire: { u: string; type?: string; text?: string });
  readonly kind: string;
  /** The class name (`HTMLDivElement`) or a function's name. */
  readonly type?: string;
  /** A short safe rendering: a date's ISO string, an error's message. */
  readonly text?: string;
  toString(): string;
}

/** The bounds, each refused by name (the error says which). */
export interface ObjectsLimits {
  /** Operations (get / call / construct) in one request. Default 32. */
  maxOps: number;
  /** Arguments of one call. Default 16. */
  maxArgs: number;
  /** How deep a returned or sent value nests. Default 8. */
  maxDepth: number;
  /** Bytes of one returned value and of one sent value. Default 262144 (and under what the transport carries in one message). */
  maxValueBytes: number;
  /** Keys one `describe` lists. Default 200. */
  maxKeys: number;
  /** Requests accepted per second, per channel. Default 50. */
  maxRequestsPerSecond: number;
  /** How long a call that returns a promise is waited for. Default 30000. */
  callTimeoutMs: number;
  /** Event subscriptions per channel. Default 16. */
  maxSubscriptions: number;
  /** Events delivered per second, per subscription; the rest are dropped and counted. Default 20. */
  maxEventsPerSecond: number;
  /** Bytes of one delivered event; a bigger one is dropped and counted. Default 16384. */
  maxEventBytes: number;
  /** Events waiting for the transport's credit, per channel; more are dropped and counted. Default 100. */
  maxQueuedEvents: number;
}
export const OBJECTS_DEFAULT_LIMITS: Readonly<ObjectsLimits>;

/** Path sequences refused until an allow-list entry names them (a wildcard does not): `document.cookie`, `localStorage`, `sessionStorage`, `indexedDB`, `navigator.credentials`, `fetch`, `XMLHttpRequest`, `postMessage`, `open`. */
export const NEEDS_LISTING: ReadonlyArray<readonly string[]>;

/** Allow-lists by operation: path patterns from a root (`'window.document.title'`, `'window.app.**'`; `*` is one segment, `**` any number). `call` covers `construct`. Nothing is allowed by default. */
export interface ObjectsAllow {
  get?: string[];
  call?: string[];
  set?: string[];
  /** Event sources, as `path@type` (`'window.app.bus@ready'`; the type may be `*`). Never implied by the other lists. */
  on?: string[];
}

export interface ObjectsWho { username: string | null; fingerprint: string | null }
export interface ObjectsOperation {
  kind: 'get' | 'call' | 'construct' | 'set' | 'on' | 'describe' | 'snapshot';
  /** For `on`: the event type. */
  type?: string;
  root: string;
  /** The path below the root. */
  path: string[];
  /** The whole path as text: `window.app.cart.add`. */
  text: string;
}

export interface ObjectsServerOptions {
  /** The named roots: all that is reachable. */
  roots: Record<string, object>;
  /** `'values'` is the only mode: `'handles'` is refused (not built). */
  mode?: 'values';
  allow?: ObjectsAllow;
  /** Asked for every operation the allow-list let through; anything but `true` (a throw included) refuses. */
  authorize?: (who: ObjectsWho, op: ObjectsOperation) => boolean | Promise<boolean>;
  limits?: Partial<ObjectsLimits>;
  /** Extra event fields a subscriber may ask for, by event type (`'*'`: any type): property names read from the event and copied as plain data (a node is left out). */
  eventFields?: Record<string, string[]>;
  /** Why nothing may be served any more (the window left), else null. */
  guard?: () => string | null;
  /** For `callTimeoutMs`. */
  timers?: { setTimeout(fn: () => void, ms: number): unknown; clearTimeout(id: unknown): void } | null;
  now?: () => number;
}

/** What the core needs of a transport (an `RpcChannel` is one; `createDuplexPeer` makes one from `send` and `receive`). */
export interface ObjectsPeer {
  onRequest(method: string, handler: (params: any, ctx: { signal?: AbortSignal; progress?: (chunk: unknown) => unknown; who?: ObjectsWho }) => unknown): unknown;
  onNotification?(method: string, handler: (params: any) => void): unknown;
  request(method: string, params?: unknown, options?: { signal?: AbortSignal; onProgress?: (chunk: unknown) => void }): Promise<any>;
  notify(method: string, params?: unknown): unknown;
  onClose: ((reason?: string) => void) | null;
  readonly maxMessageBytes: number;
  close?(reason?: string): unknown;
}

/** The transport-neutral server half: roots, allow-lists and limits, attachable to any peer. Knows nothing about wsh. */
export function createObjectsServer(options: ObjectsServerOptions): {
  attach(peer: Pick<ObjectsPeer, 'onRequest' | 'maxMessageBytes'>, options?: { who?: ObjectsWho }): { limits: ObjectsLimits };
  readonly limits: Readonly<ObjectsLimits>;
  readonly rootNames: string[];
};

/** A peer over `send(message)` and `receive(message)`: the same protocol over any duplex that is not wsh. */
export function createDuplexPeer(options: { send(message: object): void; maxMessageBytes?: number }): ObjectsPeer & { receive(message: unknown): void; close(reason?: string): void; readonly closed: boolean };

/** The client half over any peer: the roots, as lazy references. */
export function createObjectsClient<T = Record<string, any>>(peer: Pick<ObjectsPeer, 'request'> & Partial<ObjectsPeer>, options?: { timeoutMs?: number }): Promise<T>;

/** `exposeObjects`: the rpc handler for `wsh-objects`. Usable as `rpc: { 'wsh-objects': exposeObjects({ roots, allow }) }` in any host. */
export interface ObjectsHandler {
  (channel: RpcChannel, ctx?: { user?: string | null; fingerprint?: string | null }): void;
  /** Tell every session (or those of one key) why, then end it. Resolves with how many were ended. */
  closeSessions(reason: string, fingerprint?: string): Promise<number>;
  readonly rootNames: string[];
  readonly limits: Readonly<ObjectsLimits>;
}
export function exposeObjects(options: ObjectsServerOptions): ObjectsHandler;

/** Open `wsh-objects` on a connected client: the roots, as lazy references. Also `client.openObjects()`, which importing this entry point adds. */
export function openObjects<T = Record<string, any>>(client: WshClient, options?: { timeoutMs?: number }): Promise<T>;

declare module './index.js' {
  interface WshClient {
    /**
     * Open the `wsh-objects` channel: the host's named roots as lazy references (`const { window } = await client.openObjects()`). A reference is a path:
     * `window.document.title` sends nothing, `await` sends the whole chain in one request. Needs `import '@johnhenry/wsh/objects'` (which adds this method).
     */
    openObjects<T = Record<string, any>>(options?: { timeoutMs?: number }): Promise<T>;
  }
}

/** The value at a reference, or at a property of it: `await get(ref, 'then')` reaches a property that `ref.then` cannot. */
export function get(ref: any, ...keys: Array<string | number>): Promise<any>;
/** Assign a property of a remote object (not `=`: that throws). The reference must be a plain path. */
export function set(ref: any, key: string | number, value: unknown): Promise<void>;
/** Call a method reached by name, with plain-data arguments. */
export function call(ref: any, ...args: unknown[]): Promise<any>;
/** `new` a constructor reached by name. */
export function construct(ref: any, ...args: unknown[]): Promise<any>;
/** A bounded deep copy; subtrees deeper than `depth` are `null`. */
export function snapshot(ref: any, options?: { depth?: number; maxBytes?: number; signal?: AbortSignal }): Promise<any>;
/**
 * Listen for an event of a remote source named by the host's `allow.on`. `data` is plain: an Event as `{ type, timeStamp, isTrusted, ...fields }`, an emitter's as
 * `{ type, args }`. `dropped` counts events the host dropped before this one. Resolves to the function that unsubscribes. Never an event object, never a handle.
 */
export function on(ref: any, type: string, listener: (data: any, info: { type: string; seq: number; dropped: number }) => void, options?: { fields?: string[]; onError?: (error: unknown) => void }): Promise<() => Promise<void>>;
/** Stop a subscription: what `on` resolved to. */
export function off(unsubscribe: () => Promise<void>): Promise<void>;
/** The shape of an object, for completion: the names and types the allow-list could walk to. */
export function describe(ref: any, options?: { signal?: AbortSignal }): Promise<{ type: string; keys: Array<{ key: string; type: string; own: boolean }>; truncated?: boolean }>;
/** End the connection behind what `openObjects()` returned. */
export function closeObjects(page: unknown): Promise<void>;

export function matchPath(pattern: string[], path: string[]): boolean;
/** A value as plain data (`{ v }`), or a named non-value (`{ u, type?, text? }`). */
export function toWire(value: unknown, options?: { maxDepth?: number; maxBytes?: number; cut?: boolean }): { v: unknown; truncated?: boolean } | { u: string; type?: string; text?: string };
/** What may be sent to a host: plain data only, copied; throws an `ObjectsError` for anything else. */
export function fromWire(value: unknown, options?: { maxDepth?: number; maxBytes?: number }): unknown;
