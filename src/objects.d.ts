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
/**
 * What a value that cannot be cloned arrives as on a root that opted in to handles: an opaque token, nothing of it enumerable, not thenable, not an argument.
 * It stands at the path that produced it: `use(handle)` makes a reference that continues that path; `release(handle)` gives its place back.
 */
export class RemoteHandle<T = any> {
  readonly kind: 'function' | 'object';
  /** The class name, or a function's name. */
  readonly type?: string;
  /** Up to 8 member names, only if a `get` entry names the handle's path. */
  readonly preview?: { keys: string[] };
  /** Type-only: the shape of the value behind the handle, for `use` (a host's type map, or a type you write). Not there at run time. */
  readonly [handleShape]?: T;
}
declare const handleShape: unique symbol;
declare const eventsBrand: unique symbol;
declare const setBrand: unique symbol;

// ── Typed remotes (#219) ────────────────────────────────────────────────────────────────────────────────────────────────────
// A reference is a lazy path whose `await` is the value: it is `PromiseLike` (not a `Promise`: there is no `catch` or `finally` on it, and `ref.catch` would be a
// remote property named "catch"). `describeRootTypes` (from `@johnhenry/wsh/objects-types`) writes types for one root out of these pieces; you can write them by hand.

/** Anything: what a wildcard in an allow-list entry is typed as (the members behind it are not guessed). */
export type RemoteUntyped = any;
/** A path whose `await` is a `V` (a get). */
export type RemoteValue<V = unknown> = PromiseLike<V>;
/** A method: calling it gives a reference whose `await` is an `R` and that continues as `M` (`window.app.makeBus().ping`). Arguments are plain data. */
export type RemoteCall<A extends unknown[] = unknown[], R = unknown, M = unknown> = (...args: A) => PromiseLike<R> & M;
/** What a listener receives: an Event as `{ type, timeStamp, isTrusted, ...the fields you asked for }`, an emitter's as `{ type, args }`. */
export type RemoteEventData<F extends string = never> = { type: string; timeStamp?: number; isTrusted?: boolean; args?: unknown[] } & { [K in F]?: unknown };
/** The events a source offers, as `{ [type]: { data, fields } }`: it makes `on(ref, type, listener)` check the type, the data and the fields. */
export type WithEvents<E extends Record<string, { data: unknown; fields: string }>> = { readonly [eventsBrand]: E };
/** The properties of a node that may be assigned, as `{ [key]: valueType }`: it makes `set(ref, key, value)` check the key and the value. */
export type WithSet<S extends Record<string, unknown>> = { readonly [setBrand]: S };

type IsAny<T> = 0 extends 1 & T ? true : false;
type EventMapOf<R> = IsAny<R> extends true ? never : R extends { readonly [eventsBrand]: infer E } ? E : never;
type EventTypeOf<R> = [EventMapOf<R>] extends [never] ? string : Extract<keyof EventMapOf<R>, string>;
type EventDataOf<R, K> = [EventMapOf<R>] extends [never] ? any : K extends keyof EventMapOf<R> ? (EventMapOf<R>[K] extends { data: infer D } ? D : any) : any;
type EventFieldsOf<R, K> = [EventMapOf<R>] extends [never] ? string : K extends keyof EventMapOf<R> ? (EventMapOf<R>[K] extends { fields: infer F extends string } ? F : string) : string;
type SetMapOf<R> = IsAny<R> extends true ? never : R extends { readonly [setBrand]: infer S } ? S : never;
type SetKeyOf<R> = [SetMapOf<R>] extends [never] ? string | number : Extract<keyof SetMapOf<R>, string>;
type SetValueOf<R, K> = [SetMapOf<R>] extends [never] ? unknown : K extends keyof SetMapOf<R> ? SetMapOf<R>[K] : unknown;

type RemotePrimitive = string | number | boolean | bigint | symbol | null | undefined;
/**
 * The reference type of a value type you write: `Remote<{ cart: { add(item: Item): number; items: Item[] } }>` is what `await`s to the value, has the members as references,
 * and has methods that return references. Hand-written `T` says what you believe the host exposes; the host's allow-lists still decide. Arguments stay plain data.
 */
export type Remote<T> =
  0 extends 1 & T ? any
  : T extends RemotePrimitive ? PromiseLike<T>
  : T extends (...args: infer A) => infer R ? (...args: A) => Remote<Awaited<R>>
  : T extends Uint8Array | ArrayBuffer ? PromiseLike<T>
  : T extends readonly (infer U)[] ? PromiseLike<T> & { readonly length: PromiseLike<number>; readonly [index: number]: Remote<U> }
  : T extends object ? PromiseLike<T> & WithSet<{ [K in keyof T]: T[K] }> & { readonly [K in keyof T]: Remote<T[K]> }
  : PromiseLike<T>;
/** The roots as `openObjects` returns them, for value types you write: `client.openObjects<RemoteRoots<{ window: MyWindow }>>()`. A generated `{ window: WindowRemote }` is already remote-shaped. */
export type RemoteRoots<T> = { readonly [K in keyof T]: Remote<T[K]> };

/** A reference that stands on a handle: `await use(handle).items.length`. Judged by the producing path extended by what you name. With a typed handle (`RemoteHandle<Cart>`), a `Remote<Cart>`. */
export function use<T = any>(handle: RemoteHandle<T>): 0 extends 1 & T ? any : Remote<T>;
/** Give a handle's place back (releasing a released handle does nothing); or kill the stub of a function that was passed as a callback. */
export function release(handleOrCallback: RemoteHandle | ((...args: any[]) => unknown)): Promise<void>;

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
  /** Handles per channel on roots that opted in; more are refused by name, nothing is evicted. Default 64. */
  maxHandles: number;
  /** Callbacks (stubs of far-side functions) per channel; more are refused. Default 16. */
  maxCallbacks: number;
  /** Calls of one callback per second; the rest are dropped and counted. Default 20. */
  maxCallbacksPerSecond: number;
  /** Bytes of the arguments of one callback call; a bigger one is dropped and counted. Default 16384. */
  maxCallbackBytes: number;
}
export const OBJECTS_DEFAULT_LIMITS: Readonly<ObjectsLimits>;

/** Path sequences refused until an allow-list entry names them (a wildcard does not): `document.cookie`, `localStorage`, `sessionStorage`, `indexedDB`, `navigator.credentials`, `fetch`, `XMLHttpRequest`, `postMessage`, `open`. */
export const NEEDS_LISTING: ReadonlyArray<readonly string[]>;

/** Allow-lists by operation: path patterns from a root (`'window.document.title'`, `'window.app.**'`; `*` is one segment, `**` any number). `call` covers `construct`. Nothing is allowed by default. */
export interface ObjectsAllow {
  get?: string[];
  // (`call` entries may end in `(callback)`: the call accepts functions as arguments, which reach the page as one-way stubs.)
  call?: string[];
  set?: string[];
  /** Event sources, as `path@type` (`'window.app.bus@ready'`; the source and the type are named exactly, a wildcard in either is refused). Never implied by the other lists. */
  on?: string[];
}

/**
 * Who a call is from, as `authorize(who, op)` and the allow-list's hooks see it: `fingerprint` is the hex SHA-256 of the caller's public key
 * wherever the caller came from (over wsh: the key it logged in with). `podId` is there when the transport knows the caller by one (a mesh
 * adapter that gave `{ podId }`: then `fingerprint` is derived from it); a wsh caller has no `podId`. `fingerprint` is `null` for a caller
 * with no key (a password login).
 */
export interface ObjectsWho { username: string | null; fingerprint: string | null; podId?: string }
/** What a transport that is not wsh may say of its caller; whichever of `fingerprint` (64 hex digits) and `podId` it gives, `ObjectsWho` has the hex `fingerprint`. */
export interface ObjectsIdentity { username?: string | null; fingerprint?: string | null; podId?: string | null }
export interface ObjectsOperation {
  kind: 'get' | 'call' | 'construct' | 'set' | 'on' | 'describe' | 'snapshot';
  /** For `on`: the event type. */
  type?: string;
  /** For a call that carries callbacks: how many. */
  callbacks?: number;
  root: string;
  /** The path below the root. */
  path: string[];
  /** The whole path as text: `window.app.cart.add`. */
  text: string;
}

export interface ObjectsServerOptions {
  /** The named roots: all that is reachable. */
  roots: Record<string, object>;
  /** `'values'` (the default). Handles are chosen per root with `handles`, not here. */
  mode?: 'values';
  /**
   * Roots that opt in to handles: a value that cannot be cloned comes back as an opaque `RemoteHandle`, judged by the path that produced it. `nodes: true` is a
   * second opt-in, for DOM nodes, windows and documents (control of the page). Needs `random`.
   */
  handles?: Record<string, { nodes?: boolean; wideEntries?: boolean }>;
  // `wideEntries: true` acknowledges a wildcard in `allow.call` or `allow.set` on that root (without it the host refuses to start: list the paths, or say so).
  /** The random source for handle ids: `(n) => bytes` from `crypto.getRandomValues`. `exposeObjects` defaults to the platform's, the page host to its window's. */
  random?: (n: number) => Uint8Array;
  allow?: ObjectsAllow;
  /** Asked for every operation the allow-list let through; anything but `true` (a throw included) refuses. */
  authorize?: (who: ObjectsWho, op: ObjectsOperation) => boolean | Promise<boolean>;
  limits?: Partial<ObjectsLimits>;
  /** Extra event fields a subscriber may ask for, by event type (`'*'`: any type): property names read from the event and copied as plain data (a node is left out). */
  eventFields?: Record<string, string[]>;
  /**
   * Types for the far side's `.d.ts`, by qualified path (`'window.app.cart.add': { args: '[item: { sku: string }]', result: 'number' }`; `value` for a get, `data` for an
   * event `'window.app.bus@ready'`). Host-authored text that is sent to the far side: checked when the host is created (a conservative type syntax, bounded, only for a path
   * an allow-list entry names), copied into a file there and never evaluated. A bad text or an unlisted path is a `TypeError` here.
   */
  types?: Record<string, { value?: string; args?: string; result?: string; data?: string }>;
  /** Why nothing may be served any more (the window left), else null. */
  guard?: () => string | null;
  /** For `callTimeoutMs`. */
  timers?: { setTimeout(fn: () => void, ms: number): unknown; clearTimeout(id: unknown): void } | null;
  now?: () => number;
}

/** What the core needs of a transport (an `RpcChannel` is one; `createDuplexPeer` makes one from `send` and `receive`). */
export interface ObjectsPeer {
  onRequest(method: string, handler: (params: any, ctx: { signal?: AbortSignal; progress?: (chunk: unknown) => unknown; who?: ObjectsIdentity; permit?: (root: string, op: string) => boolean }) => unknown): unknown;
  onNotification?(method: string, handler: (params: any) => void): unknown;
  request(method: string, params?: unknown, options?: { signal?: AbortSignal; onProgress?: (chunk: unknown) => void }): Promise<any>;
  notify(method: string, params?: unknown): unknown;
  onClose: ((reason?: string) => void) | null;
  readonly maxMessageBytes: number;
  close?(reason?: string): unknown;
}

/** The transport-neutral server half: roots, allow-lists and limits, attachable to any peer. Knows nothing about wsh. */
export function createObjectsServer(options: ObjectsServerOptions): {
  /** `who`: the identity of every call unless the peer gives one per call (`ctx.who`); one that names two keys, or is not an identity, throws a `TypeError` here. */
  attach(peer: Pick<ObjectsPeer, 'onRequest' | 'maxMessageBytes'>, options?: { who?: ObjectsIdentity }): { limits: ObjectsLimits };
  readonly limits: Readonly<ObjectsLimits>;
  readonly rootNames: string[];
};

/**
 * A peer over `send(message)` and `receive(message)`: the same protocol over any duplex that is not wsh. `who` is who is on the far side, as an
 * identity object (a pod id goes in `podId`, not in a field named `fingerprint`); `permit(root, op)` is the transport's own capability check
 * for each operation (`get`, `call`, `set`, `on`, or `walk` for reading on the way): `true` allows, anything else and a throw refuse.
 */
export function createDuplexPeer(options: { send(message: object): void; maxMessageBytes?: number; who?: ObjectsIdentity; permit?: (root: string, op: 'get' | 'call' | 'set' | 'on' | 'walk') => boolean }): ObjectsPeer & { receive(message: unknown): void; close(reason?: string): void; readonly closed: boolean };

/** The client half over any peer: the roots, as lazy references. */
export function createObjectsClient<T = Record<string, any>>(peer: Pick<ObjectsPeer, 'request'> & Partial<ObjectsPeer>, options?: {
  timeoutMs?: number;
  /** A callback of ours threw: it stays here, the page never hears of it. */
  onCallbackError?: (error: unknown) => void;
  /** The host dropped calls of a callback (rate, size, a slow channel) before the one that follows. */
  onCallbackDropped?: (info: { dropped: number; fn: (...args: any[]) => unknown }) => void;
}): Promise<T>;

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
export function set<R, K extends SetKeyOf<R>>(ref: R, key: K, value: SetValueOf<R, K>): Promise<void>;
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
/**
 * `ref` is a path reached from a root, or a reference that stands on a handle (`use(handle).bus`): the source is then the handle's producing path extended as
 * written, and needs its own `allow.on` entry naming the type, the key's `objects:ROOT:on` and `authorize`. The subscription ends when the handle is released.
 * A host before 0.51.0 does not say it supports this (`unsupported`).
 */
export function on<R, K extends EventTypeOf<R>>(ref: R, type: K, listener: (data: EventDataOf<R, K>, info: { type: string; seq: number; dropped: number }) => void, options?: { fields?: Array<EventFieldsOf<R, K>>; onError?: (error: unknown) => void }): Promise<() => Promise<void>>;
/**
 * What this key may do on a root, as data (`{ version, root, ops, allow, eventFields, types }`): the host's allow-list entries for the root narrowed by the key's capabilities,
 * and the host's type map for them. Pass it to `describeRootTypes` (`@johnhenry/wsh/objects-types`) for the text of a `.d.ts`. A host before 0.51.0 does not say it supports this (`unsupported`).
 */
export function rootDescription(root: unknown, options?: { signal?: AbortSignal }): Promise<import('./objects-types.js').RootDescription & { version: number; ops: Array<'get' | 'call' | 'set' | 'on'>; handles: boolean }>;
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
