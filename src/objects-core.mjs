/**
 * The remote-object core (#190), `values` mode: path resolution, serialisation rules, limits and allow-list evaluation, with NO knowledge of
 * wsh. It needs only a duplex seam, `Peer`:
 *
 *   peer.onRequest(method, handler)      handler(params, { signal, progress?, who? }) -> result | Promise (throws ObjectsError to refuse)
 *   peer.onNotification?(method, fn)     optional
 *   peer.request(method, params, { signal, onProgress }) -> Promise     (the client side)
 *   peer.notify(method, params)
 *   peer.onClose                         the core assigns a function; the peer calls it once, with a reason, when it ends
 *   peer.maxMessageBytes                 the largest message the transport carries (the core keeps its answers under it)
 *   who                                  the per-call identity `{ username, fingerprint }`: `ctx.who` of a request, or the one given to `attach`
 *
 * A wsh `RpcChannel` is exactly this shape, so `exposeObjects` (in `objects.mjs`) is a few lines; `createDuplexPeer({ send })` below is the same
 * over a bare `send(obj)` / `receive(obj)` pair (a worker's `postMessage`, a test), and `test/objects.test.mjs` runs one suite over both.
 *
 * What makes the allow-list mean what it says is that NOTHING BUT CLONEABLE VALUES CROSSES: a result is plain data (primitives, bytes, arrays and
 * plain objects, bounded), a function, a DOM node, a class instance or a symbol is reported by name (`NonValue`) and is never a handle, so a
 * result can never be walked somewhere else. Where this module does call user code, it is the path the caller named and the allow-list let through:
 *   - a `get` of an accessor property runs its getter, and a `set` runs a setter. Getters with side effects are still gets, and an allow-list
 *     entry for one allows its side effects. The serialiser itself never calls a getter, `toJSON` or anything else of the value it copies;
 *   - a Proxy that the embedder made a root runs its own traps when it is read.
 *
 * Paths are `root.seg.seg`; an allow-list entry is such a path with `*` (one segment) or `**` (any number, also none) for a segment. After a call the
 * chain continues on the RESULT, whose path is the callee with `()`: `window.app.getCart().items`. Nothing is allowed by default.
 */

export const OBJECTS_PROTOCOL = 'wsh-objects';

/** Error codes, JSON-RPC's where one fits (`reason` in `data` says which rule). */
export const OBJECTS_ERROR = Object.freeze({ INVALID: -32602, LIMIT: -32002, REFUSED: -32003, FAILED: -32000 });

export class ObjectsError extends Error {
  /**
   * @param {number} code
   * @param {string} message
   * @param {{ reason?: string, [k: string]: unknown }} [data]
   */
  constructor(code, message, data) {
    super(message);
    this.name = 'ObjectsError';
    this.code = code;
    this.data = data;
    /** The rule that refused: `always-refused`, `not-allowed`, `needs-listing`, `authorize`, `limit`, `bad-request`, `no-such-root`, ... */
    this.reason = data?.reason;
  }
}
const refuse = (reason, message, extra) => new ObjectsError(OBJECTS_ERROR.REFUSED, message, { reason, ...extra });
const invalid = (message) => new ObjectsError(OBJECTS_ERROR.INVALID, message, { reason: 'bad-request' });
const limitError = (name, max, what) => new ObjectsError(OBJECTS_ERROR.LIMIT, `refused: ${name} (${max}): ${what}`, { reason: 'limit', limit: name, max });

/** The bounds, each refused by name. */
export const OBJECTS_DEFAULT_LIMITS = Object.freeze({
  /** Operations (get / call / construct) in one `resolve` request. */
  maxOps: 32,
  /** Arguments of one call. */
  maxArgs: 16,
  /** How deep a returned or sent value may nest. */
  maxDepth: 8,
  /** Bytes of one returned value, and of one sent value. */
  maxValueBytes: 256 * 1024,
  /** Keys one `describe` lists. */
  maxKeys: 200,
  /** Requests accepted per second, per attached peer. */
  maxRequestsPerSecond: 50,
  /** Event subscriptions per channel. */
  maxSubscriptions: 16,
  /** Events delivered per second, per subscription; the rest are dropped and counted. */
  maxEventsPerSecond: 20,
  /** Bytes of one delivered event; a bigger one is dropped and counted. */
  maxEventBytes: 16 * 1024,
  /** Events waiting for the transport (credit), per channel; more are dropped and counted. */
  maxQueuedEvents: 100,
  /** How long a call that returns a promise is waited for. */
  callTimeoutMs: 30_000,
});

// ── The rules that hold for every allow-list ────────────────────────────────────────────────────────────────────────

/** A path segment that is never walked, read, called or set: it climbs to a prototype or hands out a code evaluator. */
const ALWAYS_REFUSED = new Set([
  '__proto__', 'prototype', 'constructor', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__',
  'eval', 'Function', 'import', 'execScript',
]);
/** `fn.call`, `fn.apply` and `fn.bind` re-aim a function: refused on a function (an object may have a method of that name). */
const FUNCTION_REFLECTION = new Set(['call', 'apply', 'bind']);
/** Timers take a string to evaluate: refused with a string argument. */
const STRING_TIMERS = new Set(['setTimeout', 'setInterval', 'setImmediate']);
/** Refused until a pattern NAMES them (a literal sequence of segments, not a wildcard): a path that contains one of these sequences. */
export const NEEDS_LISTING = Object.freeze([
  ['document', 'cookie'], ['localStorage'], ['sessionStorage'], ['indexedDB'], ['navigator', 'credentials'], ['fetch'], ['XMLHttpRequest'], ['postMessage'], ['open'],
]);

const KEY_MAX = 256;
const EVENT_TYPE_RE = /^[A-Za-z0-9_$:.-]{1,128}$/;

function checkKey(key) {
  if (typeof key !== 'string' || key === '' || key.length > KEY_MAX) throw invalid(`a path segment must be a string of 1 to ${KEY_MAX} characters`);
  if (key.includes('.')) throw invalid(`a path segment cannot contain "." (${JSON.stringify(key.slice(0, 40))})`);
  if (ALWAYS_REFUSED.has(key)) throw refuse('always-refused', `refused: "${key}" is never reachable (it climbs to a prototype or evaluates code)`);
  return key;
}

// ── Allow-lists ─────────────────────────────────────────────────────────────────────────────────────────────────────

/** Compile one list of entries (`'window.app.**'`) into arrays of segments, refusing an entry that could never be right. */
function compileList(list, kind) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) throw new TypeError(`exposeObjects: allow.${kind} must be an array of path patterns`);
  return list.map((entry) => {
    if (typeof entry !== 'string' || entry === '') throw new TypeError(`exposeObjects: allow.${kind} entries must be non-empty strings`);
    const segs = entry.split('.');
    for (const s of segs) {
      if (s === '') throw new TypeError(`exposeObjects: allow.${kind} entry ${JSON.stringify(entry)} has an empty segment`);
      if (ALWAYS_REFUSED.has(s)) throw new TypeError(`exposeObjects: allow.${kind} entry ${JSON.stringify(entry)} names "${s}", which is never reachable`);
      if (/\*/.test(s) && s !== '*' && s !== '**') throw new TypeError(`exposeObjects: allow.${kind} entry ${JSON.stringify(entry)}: a wildcard must be a whole segment ("*" or "**")`);
    }
    return segs;
  });
}

/** Does the pattern match the whole path? `*` is one segment, `**` any number (also none). */
export function matchPath(pattern, path) {
  const rec = (i, j) => {
    if (i === pattern.length) return j === path.length;
    if (pattern[i] === '**') return rec(i + 1, j) || (j < path.length && rec(i, j + 1));
    return j < path.length && (pattern[i] === '*' || pattern[i] === path[j]) && rec(i + 1, j + 1);
  };
  return rec(0, 0);
}

/** Could the path be extended into a match? (Walking toward something allowed.) */
function prefixPath(pattern, path) {
  const rec = (i, j) => {
    if (j === path.length) return true;
    if (i === pattern.length) return false;
    if (pattern[i] === '**') return rec(i + 1, j) || rec(i, j + 1);
    return (pattern[i] === '*' || pattern[i] === path[j]) && rec(i + 1, j + 1);
  };
  return rec(0, 0);
}

const containsSequence = (segs, seq) => {
  for (let i = 0; i + seq.length <= segs.length; i++) if (seq.every((s, k) => segs[i + k] === s)) return true;
  return false;
};
/** The segments of a pattern, as literal text, contain `seq` consecutively. */
const patternNames = (pattern, seq) => containsSequence(pattern, seq);

const bareName = (seg) => (seg.endsWith('()') ? seg.slice(0, -2) : seg);

// ── Serialisation: only cloneable values cross ──────────────────────────────────────────────────────────────────────

function utf8Length(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) { n += 4; i++; } else n += 3;
  }
  return n;
}

const TYPE_MAX = 64;
const TEXT_MAX = 200;
const clip = (s, n) => (s.length > n ? `${s.slice(0, n)}...` : s);
const isPrintable = (s) => typeof s === 'string' && /^[\x20-\x7e]*$/.test(s);

/** The class name of an object, read without running any code of it (own data properties only). */
function typeName(value) {
  try {
    let proto = Object.getPrototypeOf(value);
    for (let hops = 0; proto && hops < 8; hops++, proto = Object.getPrototypeOf(proto)) {
      const d = Object.getOwnPropertyDescriptor(proto, 'constructor');
      const name = d && 'value' in d && typeof d.value === 'function' ? Object.getOwnPropertyDescriptor(d.value, 'name')?.value : undefined;
      if (typeof name === 'string' && isPrintable(name) && name) return clip(name, TYPE_MAX);
    }
  } catch { /* an exotic object: unnamed */ }
  return undefined;
}

/**
 * Describe a value that cannot be cloned: `{ u: kind, type?, text? }`. `kind` is `function`, `symbol`, `bigint`, `number` (an integer too large for the
 * wire), `Date`, `RegExp`, `Error` or `object`; `type` the class name; `text` a short, safe rendering (a date's ISO string, an error's message).
 */
function nonValue(value) {
  const t = typeof value;
  if (t === 'undefined') return { u: 'undefined' };
  if (t === 'function') {
    const name = (() => { try { const n = Object.getOwnPropertyDescriptor(value, 'name')?.value; return typeof n === 'string' && isPrintable(n) && n ? clip(n, TYPE_MAX) : undefined; } catch { return undefined; } })();
    return { u: 'function', ...(name ? { type: name } : {}) };
  }
  if (t === 'symbol') return { u: 'symbol' };
  if (t === 'bigint') return { u: 'bigint', text: clip(String(value), TEXT_MAX) };
  if (t === 'number') return { u: 'number', text: String(value) };
  const tag = Object.prototype.toString.call(value);
  const type = typeName(value);
  if (tag === '[object Date]') { let text; try { text = Number.isFinite(value.getTime()) ? value.toISOString() : 'Invalid Date'; } catch { text = undefined; } return { u: 'Date', ...(text ? { text } : {}) }; }
  if (tag === '[object RegExp]') { let text; try { text = clip(String(RegExp.prototype.toString.call(value)), TEXT_MAX); } catch { text = undefined; } return { u: 'RegExp', ...(text ? { text } : {}) }; }
  if (tag === '[object Error]' || tag === '[object DOMException]') {
    let text;
    try { const d = Object.getOwnPropertyDescriptor(value, 'message'); text = d && typeof d.value === 'string' ? clip(d.value, TEXT_MAX) : undefined; } catch { /* unreadable */ }
    return { u: 'Error', ...(type ? { type } : {}), ...(text ? { text } : {}) };
  }
  return { u: 'object', ...(type ? { type } : {}) };
}

const isBytes = (v) => v instanceof ArrayBuffer || ArrayBuffer.isView(v) || Object.prototype.toString.call(v) === '[object ArrayBuffer]';
const isPlainObject = (v) => {
  if (v === null || typeof v !== 'object') return false;
  const proto = Object.getPrototypeOf(v);
  return proto === null || proto === Object.prototype || (Object.getPrototypeOf(proto) === null && Object.prototype.toString.call(v) === '[object Object]' && typeName(v) === 'Object');
};
const bytesOf = (v) => {
  if (v instanceof Uint8Array) return v.slice();
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength).slice();
  return new Uint8Array(v).slice();
};

/**
 * A value as plain data, or a named non-value, within `{ maxDepth, maxBytes }`. Returns `{ v }` or `{ u, ... }` (+ `truncated: true` when `cut` replaced a
 * subtree with null because it was deeper than `depth`). Throws an `ObjectsError` naming `maxValueBytes` or `maxDepth`.
 *
 * Inside an object or array the rule is JSON's: a member that cannot be cloned (a function, a DOM node, a class instance, a symbol, an accessor
 * property, `undefined`, a circular reference) is left out of an object and is `null` in an array. The keys `__proto__`, `constructor` and
 * `prototype` are never copied. Nothing of the value is called: no getter, no `toJSON`.
 */
export function toWire(value, { maxDepth = OBJECTS_DEFAULT_LIMITS.maxDepth, maxBytes = OBJECTS_DEFAULT_LIMITS.maxValueBytes, cut = false } = {}) {
  let bytes = 0;
  let truncated = false;
  const spend = (n) => { bytes += n; if (bytes > maxBytes) throw limitError('maxValueBytes', maxBytes, 'the value is larger than that'); };
  const ancestors = new Set();

  /** `NOTHING` for a member to leave out. */
  const NOTHING = Symbol('nothing');
  function copy(v, depth) {
    switch (typeof v) {
      case 'boolean': spend(1); return v;
      case 'string': spend(utf8Length(v) + 3); return v;
      case 'number':
        // An integer past 2^64 does not survive the wire's integer encoding: name it instead.
        if (Number.isFinite(v) && Number.isInteger(v) && Math.abs(v) >= 2 ** 63) return NOTHING;
        spend(9); return v;
      case 'undefined': case 'function': case 'symbol': case 'bigint': return NOTHING;
      default: break;
    }
    if (v === null) { spend(1); return null; }
    if (isBytes(v)) { const b = bytesOf(v); spend(b.byteLength + 5); return b; }
    const isArr = Array.isArray(v);
    if (!isArr && !isPlainObject(v)) return NOTHING;
    if (ancestors.has(v)) return NOTHING;
    if (depth >= maxDepth) {
      if (cut) { truncated = true; return null; }
      throw limitError('maxDepth', maxDepth, 'the value nests deeper than that');
    }
    ancestors.add(v);
    try {
      if (isArr) {
        const out = [];
        const length = Math.min(v.length, maxBytes);
        spend(5);
        for (let i = 0; i < length; i++) {
          const d = Object.getOwnPropertyDescriptor(v, i);
          const item = d && 'value' in d ? copy(d.value, depth + 1) : NOTHING;
          if (item === NOTHING) { spend(1); out.push(null); } else out.push(item);
        }
        return out;
      }
      const out = {};
      spend(5);
      for (const key of Object.keys(v)) {
        if (ALWAYS_REFUSED.has(key)) continue;
        const d = Object.getOwnPropertyDescriptor(v, key);
        if (!d || !('value' in d)) continue; // an accessor is never called by a copy
        const item = copy(d.value, depth + 1);
        if (item === NOTHING) continue;
        spend(utf8Length(key) + 3);
        out[key] = item;
      }
      return out;
    } finally { ancestors.delete(v); }
  }

  const top = copy(value, 0);
  if (top === NOTHING) return nonValue(value);
  return { v: top, ...(truncated ? { truncated: true } : {}) };
}

/** What a value sent TO this side may be: plain data only, copied; anything else is refused. */
export function fromWire(value, { maxDepth = OBJECTS_DEFAULT_LIMITS.maxDepth, maxBytes = OBJECTS_DEFAULT_LIMITS.maxValueBytes } = {}) {
  let bytes = 0;
  const spend = (n) => { bytes += n; if (bytes > maxBytes) throw limitError('maxValueBytes', maxBytes, 'a sent value is larger than that'); };
  function copy(v, depth) {
    switch (typeof v) {
      case 'boolean': spend(1); return v;
      case 'string': spend(utf8Length(v) + 3); return v;
      case 'number': spend(9); return v;
      default: break;
    }
    if (v === null) { spend(1); return null; }
    if (v instanceof Uint8Array) { spend(v.byteLength + 5); return v.slice(); }
    if (depth >= maxDepth) throw limitError('maxDepth', maxDepth, 'a sent value nests deeper than that');
    if (Array.isArray(v)) { spend(5); return v.map((x) => copy(x, depth + 1)); }
    if (typeof v === 'object') {
      // Anything but a plain object is refused, whatever its prototype turns out to be after decoding.
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) throw invalid('an argument must be plain data (an object with a prototype of its own was sent)');
      const out = {};
      spend(5);
      for (const key of Object.keys(v)) {
        if (ALWAYS_REFUSED.has(key)) throw refuse('always-refused', `refused: a sent object has the key "${key}", which is never accepted`);
        spend(utf8Length(key) + 3);
        out[key] = copy(v[key], depth + 1);
      }
      return out;
    }
    throw invalid(`an argument of type ${typeof v} cannot be sent: only plain data crosses`);
  }
  return copy(value, 0);
}

// ── The server ──────────────────────────────────────────────────────────────────────────────────────────────────────

const isTimerCallee = (key) => STRING_TIMERS.has(bareName(key));

function isPromiseLike(v) {
  return v !== null && typeof v === 'object' && Object.prototype.toString.call(v) === '[object Promise]';
}

/**
 * The server half: roots, allow-lists and limits, attachable to any peer.
 *
 * @param {object} options
 * @param {Record<string, unknown>} options.roots - the objects that can be reached, by name. Nothing else is.
 * @param {'values'} [options.mode='values']
 * @param {{ get?: string[], call?: string[], set?: string[] }} [options.allow] - path patterns by operation, from a root (`'window.document.title'`,
 *   `'window.app.**'`). Nothing is allowed by default. `call` covers `construct`. An entry for a path that needs listing
 *   (`NEEDS_LISTING`) must name it.
 * @param {(who: object, op: { kind: string, root: string, path: string[], text: string }) => boolean | Promise<boolean>} [options.authorize]
 *   asked for every operation the allow-list let through; anything but `true` refuses.
 * @param {Partial<typeof OBJECTS_DEFAULT_LIMITS>} [options.limits]
 * @param {() => string | null} [options.guard] - why nothing may be served any more (the window left), else null
 * @param {{ setTimeout(fn: () => void, ms: number): any, clearTimeout(id: any): void } | null} [options.timers] - for `callTimeoutMs`; without them a call that
 *   returns a promise is waited for until it settles or the request is cancelled (this module reaches for no global)
 * @param {() => number} [options.now]
 */
export function createObjectsServer(options = {}) {
  const { roots, mode = 'values', allow = {}, authorize, limits: limitOptions = {}, guard, timers = null, eventFields = {}, now = () => Date.now() } = options;
  if (mode === 'handles') throw new TypeError("exposeObjects: mode 'handles' is not built: only 'values' exists (handles and callbacks are a later step of #190)");
  if (mode !== 'values') throw new TypeError("exposeObjects: mode must be 'values'");
  if (typeof allow === 'string') throw new TypeError('exposeObjects: allow must be { get, call, set } (the wide-open form belongs to mode handles, which is not built)');
  if (!allow || typeof allow !== 'object' || Array.isArray(allow)) throw new TypeError('exposeObjects: allow must be { get, call, set }');
  for (const k of Object.keys(allow)) if (!['get', 'call', 'set', 'on'].includes(k)) throw new TypeError(`exposeObjects: allow.${k} is not an operation (get, call, set, on)`);
  // The extra fields of an event a subscriber may ask for, by event type (`'*'`: any type): names of properties read from the event, copied as plain data.
  if (!eventFields || typeof eventFields !== 'object' || Array.isArray(eventFields)) throw new TypeError('exposeObjects: eventFields must be { [type]: [field names] }');
  for (const [type, names] of Object.entries(eventFields)) {
    if (!Array.isArray(names) || !names.every((n) => typeof n === 'string' && /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/.test(n))) throw new TypeError(`exposeObjects: eventFields[${JSON.stringify(type)}] must be an array of property names`);
    for (const n of names) if (ALWAYS_REFUSED.has(n)) throw new TypeError(`exposeObjects: eventFields[${JSON.stringify(type)}] names "${n}", which is never reachable`);
  }
  if (!roots || typeof roots !== 'object' || Array.isArray(roots)) throw new TypeError('exposeObjects: roots must be an object of { name: object }: the named roots are all that is reachable');
  const rootNames = Object.keys(roots);
  if (rootNames.length === 0) throw new TypeError('exposeObjects: at least one root is needed');
  for (const name of rootNames) {
    if (!/^[A-Za-z_$][A-Za-z0-9_$-]{0,63}$/.test(name) || ALWAYS_REFUSED.has(name)) throw new TypeError(`exposeObjects: root name ${JSON.stringify(name)} is not allowed`);
    if (roots[name] === null || (typeof roots[name] !== 'object' && typeof roots[name] !== 'function')) throw new TypeError(`exposeObjects: root "${name}" must be an object`);
  }
  if (authorize !== undefined && typeof authorize !== 'function') throw new TypeError('exposeObjects: authorize must be a function (who, op) => boolean');
  const limits = { ...OBJECTS_DEFAULT_LIMITS };
  for (const [k, v] of Object.entries(limitOptions)) {
    if (!(k in OBJECTS_DEFAULT_LIMITS)) throw new TypeError(`exposeObjects: unknown limit ${JSON.stringify(k)} (${Object.keys(OBJECTS_DEFAULT_LIMITS).join(', ')})`);
    if (!Number.isSafeInteger(v) || v < 1) throw new TypeError(`exposeObjects: limits.${k} must be a positive integer`);
    limits[k] = v;
  }
  // `on` entries are `path@type` (`'window.app.bus@ready'`): the source and the event type, both named exactly (no wildcard in either); each is compiled as a path with its type attached.
  const compileOn = (list) => {
    if (list === undefined || list === null) return [];
    if (!Array.isArray(list)) throw new TypeError('exposeObjects: allow.on must be an array of "path@type" entries');
    return list.map((entry) => {
      const at = typeof entry === 'string' ? entry.indexOf('@') : -1;
      const type = at < 0 ? '' : entry.slice(at + 1);
      if (at <= 0) throw new TypeError(`exposeObjects: allow.on entry ${JSON.stringify(entry)} must be "path@type"`);
      if (/[*?]/.test(type)) throw new TypeError(`exposeObjects: allow.on entry ${JSON.stringify(entry)}: list the event types one by one; a wildcard type would hand over every event of the source`);
      if (!EVENT_TYPE_RE.test(type)) throw new TypeError(`exposeObjects: allow.on entry ${JSON.stringify(entry)}: the event type must be a name of letters, digits and _ $ : . - (up to 128)`);
      if (/\*/.test(entry.slice(0, at))) throw new TypeError(`exposeObjects: allow.on entry ${JSON.stringify(entry)}: an event source is named exactly, with no wildcard in the path`);
      const segs = compileList([entry.slice(0, at)], 'on')[0];
      return Object.assign(segs, { type });
    });
  };
  const lists = { get: compileList(allow.get, 'get'), call: compileList(allow.call, 'call'), set: compileList(allow.set, 'set'), on: compileOn(allow.on) };
  const every = [...lists.get, ...lists.call, ...lists.set, ...lists.on];

  /** The checks every operation passes, in order. `terminal` ones need the operation's own list; the rest need only to walk toward something allowed. */
  async function check(kind, root, segs, ctx, { terminal, type }) {
    const who = ctx.who;
    const gone = guard?.();
    if (gone) throw refuse('gone', `refused: ${gone}`);
    // 0. what the caller's key may do on this root, if the transport says (`ctx.permit(root, op)`, asked afresh: an expiry holds at call time)
    permitted(ctx, root, kind === 'get' && !terminal ? 'walk' : kind === 'construct' ? 'call' : kind === 'describe' || kind === 'snapshot' ? 'get' : kind);
    const rel = segs.slice(1).map(bareName);
    const own = lists[kind === 'construct' ? 'call' : kind === 'describe' || kind === 'snapshot' ? 'get' : kind];
    // 1. the allow-list: the operation's own list for the operation itself, any list for walking toward something
    if (terminal) {
      if (!own.some((p) => matchPath(p, segs))) throw refuse('not-allowed', `refused: ${kind} of ${segs.join('.')} is not in the allow-list`, { path: segs.join('.'), op: kind });
      if (kind === 'on' && !own.some((p) => matchPath(p, segs) && p.type === type)) throw refuse('not-allowed', `refused: the event type "${type}" of ${segs.join('.')} is not in the allow-list`, { path: segs.join('.'), op: kind, type });
    } else if (!every.some((p) => prefixPath(p, segs))) {
      throw refuse('not-allowed', `refused: ${segs.join('.')} is not on the way to anything the allow-list names`, { path: segs.join('.') });
    }
    // 2. what a wildcard does not cover: the operation itself needs an entry that names it; walking toward one needs only that some entry that names it goes that way
    for (const seq of NEEDS_LISTING) {
      if (!containsSequence(rel, seq)) continue;
      const listed = terminal ? own.some((p) => matchPath(p, segs) && patternNames(p, seq)) : every.some((p) => prefixPath(p, segs) && patternNames(p, seq));
      if (!listed) throw refuse('needs-listing', `refused: "${rel.join('.')}" is refused until an allow-list entry names ${seq.join('.')} (a wildcard does not)`, { path: segs.join('.') });
    }
    if (terminal && authorize) {
      let ok = false;
      try { ok = (await authorize(who ?? {}, { kind, root, path: segs.slice(1), text: segs.join('.'), ...(type !== undefined ? { type } : {}) })) === true; } catch { ok = false; }
      if (!ok) throw refuse('authorize', `refused: ${kind} of ${segs.join('.')} was not authorized`, { path: segs.join('.'), op: kind });
    }
  }

  function permitted(ctx, root, op) {
    if (typeof ctx.permit !== 'function' || ctx.permit(root, op) === true) return;
    throw refuse('not-permitted', `refused: this key's capabilities do not allow ${op === 'walk' ? 'reading' : op} on ${root}`, { root, op });
  }

  const readKey = (holder, key) => {
    if (holder === null || holder === undefined) throw new ObjectsError(OBJECTS_ERROR.FAILED, `cannot read "${key}" of ${holder === null ? 'null' : 'undefined'}`, { reason: 'bad-path' });
    return Reflect.get(Object(holder), key, holder);
  };
  const wrapThrown = (e, where) => {
    if (e instanceof ObjectsError) return e;
    let message;
    try { message = clip(String(e?.message ?? e ?? ''), TEXT_MAX); } catch { message = ''; }
    return new ObjectsError(OBJECTS_ERROR.FAILED, `${where} threw: ${message || 'an error'}`, { reason: 'threw' });
  };

  /** A call that returns a promise is waited for, until it settles, the request is cancelled, or `callTimeoutMs` (when timers were given). */
  async function settle(value, ctx) {
    if (!isPromiseLike(value)) return value;
    let timer = null;
    const waits = [value];
    if (timers) {
      const timeout = new Promise((_, reject) => { timer = timers.setTimeout(() => reject(limitError('callTimeoutMs', limits.callTimeoutMs, 'the call did not settle in time')), limits.callTimeoutMs); });
      timeout.catch(() => {});
      waits.push(timeout);
    }
    if (ctx.signal) {
      const aborted = new Promise((_, reject) => ctx.signal.addEventListener('abort', () => reject(new ObjectsError(OBJECTS_ERROR.FAILED, 'the request was cancelled', { reason: 'cancelled' })), { once: true }));
      aborted.catch(() => {});
      waits.push(aborted);
    }
    try { return await Promise.race(waits); } finally { if (timer !== null) timers.clearTimeout(timer); }
  }

  async function resolve(params, ctx) {
    const root = requireRoot(params);
    const ops = params.ops;
    if (!Array.isArray(ops)) throw invalid('ops must be an array');
    if (ops.length > limits.maxOps) throw limitError('maxOps', limits.maxOps, `${ops.length} operations in one request`);
    let cur = roots[root];
    let segs = [root];
    for (let i = 0; i < ops.length; i++) {
      const op = ops[i];
      const last = i === ops.length - 1;
      if (op === null || typeof op !== 'object' || Array.isArray(op)) throw invalid('an operation must be an object');
      const names = ['get', 'call', 'construct'].filter((k) => Object.hasOwn(op, k));
      if (names.length !== 1) throw invalid('an operation names exactly one of get, call, construct');
      const kind = names[0];
      const key = checkKey(op[kind]);
      const next = [...segs, key];
      if (kind === 'get') {
        if (typeof cur === 'function' && FUNCTION_REFLECTION.has(key)) throw refuse('always-refused', `refused: "${key}" of a function re-aims it and is never reachable`);
        await check('get', root, next, ctx, { terminal: last });
        try { cur = readKey(cur, key); } catch (e) { throw wrapThrown(e, `reading ${next.join('.')}`); }
        segs = next;
        continue;
      }
      // call / construct
      if (kind === 'call' && typeof cur === 'function' && FUNCTION_REFLECTION.has(key)) throw refuse('always-refused', `refused: "${key}" of a function re-aims it and is never reachable`);
      await check(kind, root, next, ctx, { terminal: true });
      const args = op.args === undefined ? [] : op.args;
      if (!Array.isArray(args)) throw invalid('args must be an array');
      if (args.length > limits.maxArgs) throw limitError('maxArgs', limits.maxArgs, `${args.length} arguments`);
      const clean = fromWire(args, limits);
      if (kind === 'call' && isTimerCallee(key) && typeof clean[0] === 'string') throw refuse('always-refused', `refused: ${key} with a string would evaluate it`);
      let fn;
      try { fn = readKey(cur, key); } catch (e) { throw wrapThrown(e, `reading ${next.join('.')}`); }
      if (typeof fn !== 'function') throw new ObjectsError(OBJECTS_ERROR.FAILED, `${next.join('.')} is not a function`, { reason: 'not-a-function' });
      try {
        const out = kind === 'call' ? Reflect.apply(fn, cur, clean) : Reflect.construct(fn, clean);
        cur = kind === 'call' ? await settle(out, ctx) : out;
      } catch (e) { throw wrapThrown(e, next.join('.')); }
      segs = [...segs, `${key}()`];
    }
    return toWire(cur, { maxDepth: limits.maxDepth, maxBytes: ctx.maxBytes ?? limits.maxValueBytes });
  }

  function requireRoot(params) {
    if (params === null || typeof params !== 'object') throw invalid('params must be an object');
    const root = params.root;
    if (typeof root !== 'string' || !Object.hasOwn(roots, root)) throw new ObjectsError(OBJECTS_ERROR.INVALID, `no such root: ${JSON.stringify(typeof root === 'string' ? clip(root, 64) : root)}`, { reason: 'no-such-root' });
    return root;
  }

  /** Walk `path` (an array of keys) as traversal only; the holder and its path. */
  async function walk(root, path, ctx) {
    if (!Array.isArray(path)) throw invalid('path must be an array');
    if (path.length > limits.maxOps) throw limitError('maxOps', limits.maxOps, `a path of ${path.length} segments`);
    let cur = roots[root];
    let segs = [root];
    for (const raw of path) {
      const key = checkKey(raw);
      if (typeof cur === 'function' && FUNCTION_REFLECTION.has(key)) throw refuse('always-refused', `refused: "${key}" of a function re-aims it and is never reachable`);
      const next = [...segs, key];
      await check('get', root, next, ctx, { terminal: false });
      try { cur = readKey(cur, key); } catch (e) { throw wrapThrown(e, `reading ${next.join('.')}`); }
      segs = next;
    }
    return { cur, segs };
  }

  async function setValue(params, ctx) {
    const root = requireRoot(params);
    const path = params.path;
    if (!Array.isArray(path) || path.length === 0) throw invalid('set needs a path of at least one segment');
    const { cur: parent, segs } = await walk(root, path.slice(0, -1), ctx);
    const key = checkKey(path[path.length - 1]);
    const target = [...segs, key];
    await check('set', root, target, ctx, { terminal: true });
    if (parent === null || (typeof parent !== 'object' && typeof parent !== 'function')) throw new ObjectsError(OBJECTS_ERROR.FAILED, `cannot set "${key}" on ${segs.join('.')}: it is not an object`, { reason: 'bad-path' });
    const value = fromWire(params.value, limits);
    let ok;
    try { ok = Reflect.set(parent, key, value, parent); } catch (e) { throw wrapThrown(e, `setting ${target.join('.')}`); }
    if (!ok) throw new ObjectsError(OBJECTS_ERROR.FAILED, `${target.join('.')} refused the assignment (read-only or frozen)`, { reason: 'refused-by-object' });
    return { ok: true };
  }

  function kindOf(v) {
    if (v === null) return 'null';
    const t = typeof v;
    return t === 'object' ? (Array.isArray(v) ? 'array' : 'object') : t;
  }

  async function describe(params, ctx) {
    const root = requireRoot(params);
    const { cur, segs } = await walk(root, params.path ?? [], ctx);
    await check('describe', root, segs, ctx, { terminal: false });
    if (cur === null || (typeof cur !== 'object' && typeof cur !== 'function')) return { type: kindOf(cur), keys: [] };
    const keys = [];
    const seen = new Set();
    let object = cur;
    let own = true;
    for (let hops = 0; object && hops < 6 && keys.length < limits.maxKeys; hops++, object = Object.getPrototypeOf(object), own = false) {
      if (object === Object.prototype || object === Function.prototype) break;
      let names;
      try { names = Reflect.ownKeys(object); } catch { break; }
      for (const name of names) {
        if (typeof name !== 'string' || seen.has(name) || ALWAYS_REFUSED.has(name) || name.includes('.')) continue;
        seen.add(name);
        const child = [...segs, name];
        if (!every.some((p) => prefixPath(p, child))) continue; // a name the caller could not walk to is not told
        let d;
        try { d = Object.getOwnPropertyDescriptor(object, name); } catch { continue; }
        keys.push({ key: name, type: d && 'value' in d ? kindOf(d.value) : 'accessor', own });
        if (keys.length >= limits.maxKeys) break;
      }
    }
    return { type: kindOf(cur), keys, ...(keys.length >= limits.maxKeys ? { truncated: true } : {}) };
  }

  async function snapshot(params, ctx) {
    const root = requireRoot(params);
    const { cur, segs } = await walk(root, params.path ?? [], ctx);
    await check('snapshot', root, segs, ctx, { terminal: true });
    const depth = params.depth === undefined ? limits.maxDepth : Number.isSafeInteger(params.depth) && params.depth >= 0 ? Math.min(params.depth, limits.maxDepth) : (() => { throw invalid('depth must be a whole number'); })();
    const ceiling = ctx.maxBytes ?? limits.maxValueBytes;
    const wanted = params.maxBytes === undefined ? ceiling : Number.isSafeInteger(params.maxBytes) && params.maxBytes > 0 ? Math.min(params.maxBytes, ceiling) : (() => { throw invalid('maxBytes must be a positive whole number'); })();
    return toWire(cur, { maxDepth: depth, maxBytes: wanted, cut: true });
  }

  // ── Events ──────────────────────────────────────────────────────────────────────────────────────────────────────────
  // A subscription is a listener on an EventTarget-style source (`addEventListener`) or an emitter-style one (`on` / `off`), named by an `allow.on` entry
  // (`path@type`) of its own. What is delivered is plain data: an Event becomes `{ type, timeStamp, isTrusted }` plus the fields the host lists for its type
  // (`eventFields`) and the subscriber asked for, each copied as plain data (a node is left out); an emitter's arguments become `{ type, args }`. Never the event,
  // never a handle. A listener runs in the page's dispatch: it only copies, bounds, queues, and cannot throw into it.

  const sourceMethods = (source) => {
    const fn = (name) => { try { const f = Reflect.get(Object(source), name, source); return typeof f === 'function' ? f : null; } catch { return null; } };
    if (fn('addEventListener') && fn('removeEventListener')) return { kind: 'target', add: 'addEventListener', remove: 'removeEventListener' };
    if (fn('on') && fn('off')) return { kind: 'emitter', add: 'on', remove: 'off' };
    if (fn('on') && fn('removeListener')) return { kind: 'emitter', add: 'on', remove: 'removeListener' };
    return null;
  };

  /** An Event as plain data. */
  function describeEvent(event, fields) {
    const read = (name) => { try { return Reflect.get(Object(event), name, event); } catch { return undefined; } };
    const out = { type: String(read('type') ?? ''), timeStamp: Number.isFinite(read('timeStamp')) ? read('timeStamp') : 0, isTrusted: read('isTrusted') === true };
    for (const name of fields) {
      const w = toWire(read(name), { maxDepth: 3, maxBytes: limits.maxEventBytes });
      if ('v' in w && w.v !== undefined) out[name] = w.v;
    }
    return out;
  }

  async function pump(session) {
    if (session.pumping) return;
    session.pumping = true;
    try {
      while (session.queue.length && !session.closed) {
        const { sub, data, dropped } = session.queue.shift();
        const message = { id: sub.id, seq: ++sub.seq, data, ...(dropped ? { dropped } : {}) };
        // The write waits for the transport (credit): events behind it queue, to `maxQueuedEvents`, and beyond that are dropped and counted.
        try { await session.peer.notify('event', message); } catch { /* the channel is going away */ }
      }
    } finally { session.pumping = false; }
  }

  function deliver(session, sub, args) {
    if (session.closed) return;
    try {
      if (guard?.()) return;
      const t = now();
      while (sub.stamps.length && t - sub.stamps[0] >= 1000) sub.stamps.shift();
      if (sub.stamps.length >= limits.maxEventsPerSecond) { sub.dropped++; return; }
      // Room first, copy after: a dropped event costs a counter, not a read of the event or a copy of its fields.
      if (session.queue.length >= limits.maxQueuedEvents) { sub.dropped++; return; }
      let data;
      if (sub.kind === 'target') data = describeEvent(args[0], sub.fields);
      else {
        // Emitter arguments: plain values; what cannot be cloned is null (the whole value keeps its position).
        data = { type: sub.type, args: args.map((a) => { const w = toWire(a, { maxDepth: 4, maxBytes: limits.maxEventBytes }); return 'v' in w ? w.v : null; }) };
      }
      toWire(data, { maxDepth: 6, maxBytes: limits.maxEventBytes });
      sub.stamps.push(t);
      // The events dropped since the last accepted one are told with this one: "this many were lost before it".
      session.queue.push({ sub, data, dropped: sub.dropped });
      sub.dropped = 0;
      void pump(session);
    } catch { sub.dropped++; }
  }

  async function subscribe(params, ctx) {
    const { session } = ctx;
    const root = requireRoot(params);
    const type = params.type;
    if (typeof type !== 'string' || !EVENT_TYPE_RE.test(type)) throw invalid('an event type is a name of letters, digits and _ $ : . - (up to 128)');
    const id = params.id;
    if (!Number.isSafeInteger(id) || id < 1 || session.subs.has(id)) throw invalid('a subscription id is a whole number the channel has not used');
    const asked = params.fields === undefined ? [] : params.fields;
    if (!Array.isArray(asked) || asked.length > 16 || !asked.every((f) => typeof f === 'string')) throw invalid('fields must be an array of property names');
    const offered = [...(eventFields[type] ?? []), ...(eventFields['*'] ?? [])];
    for (const f of asked) if (!offered.includes(f)) throw refuse('not-allowed', `refused: the field "${f}" of ${type} events is not offered by this host`, { field: f, type });
    if (session.subs.size >= limits.maxSubscriptions) throw limitError('maxSubscriptions', limits.maxSubscriptions, 'too many event subscriptions on this channel');
    const { cur: source, segs } = await walk(root, params.path ?? [], ctx);
    await check('on', root, segs, ctx, { terminal: true, type });
    const kind = sourceMethods(source);
    if (!kind) throw new ObjectsError(OBJECTS_ERROR.FAILED, `${segs.join('.')} is not an event source (it needs addEventListener, or on and off)`, { reason: 'not-an-event-source' });
    const sub = { id, type, kind: kind.kind, fields: [...new Set(asked)], source, stamps: [], dropped: 0, seq: 0, remove: kind.remove, listener: null };
    sub.listener = (...args) => deliver(session, sub, args);
    try { Reflect.apply(Reflect.get(Object(source), kind.add, source), source, [type, sub.listener]); } catch (e) { throw wrapThrown(e, `${segs.join('.')}.${kind.add}`); }
    session.subs.set(id, sub);
    return { ok: true };
  }

  function removeSub(sub) {
    try { Reflect.apply(Reflect.get(Object(sub.source), sub.remove, sub.source), sub.source, [sub.type, sub.listener]); } catch { /* the page's own source: nothing to tell */ }
  }

  async function unsubscribe(params, ctx) {
    const sub = ctx.session.subs.get(params.id);
    if (!sub) throw invalid('no such subscription');
    ctx.session.subs.delete(params.id);
    removeSub(sub);
    ctx.session.queue = ctx.session.queue.filter((q) => q.sub !== sub);
    return { ok: true, dropped: sub.dropped };
  }

  /** Register the protocol's methods on a peer. `who` is the identity of every call unless the transport gives one per call. */
  function attach(peer, { who } = {}) {
    if (typeof peer?.onRequest !== 'function') throw new TypeError('attach: the peer needs onRequest(method, handler)');
    const session = { peer, subs: new Map(), queue: [], pumping: false, closed: false };
    // The end of the channel (the peer left, Stop, a navigation, a revoke) takes every listener out of the page's sources.
    const prior = peer.onClose;
    peer.onClose = (reason) => {
      session.closed = true;
      for (const sub of session.subs.values()) removeSub(sub);
      session.subs.clear();
      session.queue = [];
      try { prior?.(reason); } catch { /* ignore */ }
    };
    const stamps = [];
    const method = (name, fn) => peer.onRequest(name, async (params, ctx = {}) => {
      const t = now();
      while (stamps.length && t - stamps[0] >= 1000) stamps.shift();
      if (stamps.length >= limits.maxRequestsPerSecond) throw limitError('maxRequestsPerSecond', limits.maxRequestsPerSecond, 'too many requests in a second');
      stamps.push(t);
      // A value is kept under what the transport carries in one message, with room for the envelope.
      const maxBytes = Math.min(limits.maxValueBytes, Math.max(1024, (peer.maxMessageBytes ?? Infinity) - 4096));
      const call = { ...ctx, signal: ctx.signal, who: ctx.who ?? who, maxBytes, session };
      if (params === null || typeof params !== 'object' || Array.isArray(params)) throw invalid('params must be an object');
      try { return await fn(params, call); } catch (e) { if (e instanceof ObjectsError) throw e; throw wrapThrown(e, name); }
    });
    // A key that may use only some roots is told of those only.
    method('roots', async (_params, call) => ({ roots: rootNames.filter((name) => typeof call.permit !== 'function' || call.permit(name, 'walk') === true) }));
    method('resolve', resolve);
    method('set', setValue);
    method('describe', describe);
    method('snapshot', snapshot);
    method('subscribe', subscribe);
    method('unsubscribe', unsubscribe);
    return { limits };
  }

  return { attach, limits: Object.freeze({ ...limits }), rootNames: rootNames.slice() };
}

// ── A bare duplex as a peer ─────────────────────────────────────────────────────────────────────────────────────────

/**
 * A `Peer` over `send(message)` and `receive(message)` (JSON-RPC-shaped plain objects: requests `{ id, method, params }`, responses
 * `{ id, result }` / `{ id, error }`, notifications `{ method, params }`, and `$/cancel` and `$/progress`). For a transport that is not wsh.
 * @param {{ send(message: object): void, maxMessageBytes?: number }} options
 */
export function createDuplexPeer({ send, maxMessageBytes = 1024 * 1024 } = {}) {
  if (typeof send !== 'function') throw new TypeError('createDuplexPeer: send(message) is required');
  let nextId = 1;
  let closed = false;
  const pending = new Map();
  const inflight = new Map();
  const handlers = new Map();
  const notifications = new Map();
  const peer = {
    maxMessageBytes,
    onClose: null,
    get closed() { return closed; },
    onRequest(method, handler) { handlers.set(method, handler); },
    onNotification(method, handler) { notifications.set(method, handler); },
    notify(method, params) { if (!closed) send({ method, ...(params !== undefined ? { params } : {}) }); },
    request(method, params, { signal, onProgress } = {}) {
      if (closed) return Promise.reject(new ObjectsError(OBJECTS_ERROR.FAILED, 'the connection is closed', { reason: 'closed' }));
      const id = nextId++;
      return new Promise((resolve, reject) => {
        const settle = () => { pending.delete(id); signal?.removeEventListener?.('abort', onAbort); };
        const onAbort = () => { if (!pending.has(id)) return; settle(); send({ method: '$/cancel', params: { id } }); reject(new ObjectsError(OBJECTS_ERROR.FAILED, 'the request was cancelled', { reason: 'cancelled' })); };
        pending.set(id, { resolve: (v) => { settle(); resolve(v); }, reject: (e) => { settle(); reject(e); }, onProgress });
        if (signal?.aborted) { onAbort(); return; }
        signal?.addEventListener?.('abort', onAbort, { once: true });
        send({ id, method, ...(params !== undefined ? { params } : {}) });
      });
    },
    receive(message) {
      if (closed || message === null || typeof message !== 'object') return;
      if (typeof message.method === 'string') {
        if (message.id === undefined) {
          if (message.method === '$/cancel') { inflight.get(message.params?.id)?.abort(new ObjectsError(OBJECTS_ERROR.FAILED, 'cancelled', { reason: 'cancelled' })); return; }
          if (message.method === '$/progress') { pending.get(message.params?.id)?.onProgress?.(message.params.chunk); return; }
          try { notifications.get(message.method)?.(message.params); } catch { /* a notification has no one to tell */ }
          return;
        }
        const handler = handlers.get(message.method);
        const id = message.id;
        if (!handler) { send({ id, error: { code: -32601, message: `method not found: ${message.method}` } }); return; }
        const ctl = new AbortController();
        inflight.set(id, ctl);
        const ctx = { signal: ctl.signal, progress: (chunk) => send({ method: '$/progress', params: { id, chunk } }) };
        Promise.resolve().then(() => handler(message.params, ctx)).then(
          (result) => { if (ctl.signal.aborted) return; send({ id, result: result === undefined ? null : result }); },
          (e) => { if (ctl.signal.aborted) return; send({ id, error: { code: e?.code ?? OBJECTS_ERROR.FAILED, message: String(e?.message ?? e), ...(e?.data ? { data: e.data } : {}) } }); },
        ).finally(() => inflight.delete(id));
        return;
      }
      const p = pending.get(message.id);
      if (!p) return;
      if (message.error) p.reject(new ObjectsError(message.error.code ?? OBJECTS_ERROR.FAILED, String(message.error.message ?? 'error'), message.error.data));
      else p.resolve(message.result);
    },
    close(reason = 'closed') {
      if (closed) return;
      closed = true;
      for (const p of [...pending.values()]) p.reject(new ObjectsError(OBJECTS_ERROR.FAILED, `the connection closed (${reason})`, { reason: 'closed' }));
      pending.clear();
      for (const ctl of inflight.values()) ctl.abort(new ObjectsError(OBJECTS_ERROR.FAILED, 'closed', { reason: 'closed' }));
      try { peer.onClose?.(reason); } catch { /* ignore */ }
    },
  };
  return peer;
}

// ── The client: lazy references ─────────────────────────────────────────────────────────────────────────────────────

const BRAND = Symbol.for('wsh.objects.ref');
const SESSION = Symbol.for('wsh.objects.session');

/** What a remote value that cannot be cloned arrives as: named, never a handle. */
export class NonValue {
  /** @param {{ u: string, type?: string, text?: string }} wire */
  constructor(wire) {
    this.kind = wire.u;
    if (wire.type !== undefined) this.type = wire.type;
    if (wire.text !== undefined) this.text = wire.text;
    Object.freeze(this);
  }

  toString() { return `[remote ${this.kind}${this.type ? ` ${this.type}` : ''}${this.text ? `: ${this.text}` : ''}]`; }
}

const decodeResult = (res) => {
  if (res && typeof res === 'object' && 'u' in res) return res.u === 'undefined' ? undefined : new NonValue(res);
  return res?.v;
};

function asObjectsError(e, session) {
  if (e instanceof ObjectsError) return e;
  const closing = session?.closing ? ` (${session.closing})` : '';
  const message = `${String(e?.message ?? e)}${/closed|cancel/i.test(String(e?.message)) ? closing : ''}`;
  return new ObjectsError(Number.isInteger(e?.code) ? e.code : OBJECTS_ERROR.FAILED, message, e?.data);
}

const stateOf = (ref) => {
  const state = ref !== null && (typeof ref === 'function' || typeof ref === 'object') ? ref[BRAND] : undefined;
  if (!state) throw new TypeError('expected a remote reference (what openObjects() returns, and what you reach from it)');
  return state;
};

/** A function (a callback, or a remote reference, which is a function to the engine) cannot be sent: only plain data crosses, and a reference is a path, not a value. */
function plainArgs(args) {
  let visits = 0;
  const walk = (v, depth) => {
    if (typeof v === 'function') throw new TypeError('a function or a remote reference cannot be sent as an argument: only plain data crosses (a reference is a path: await it to get its value first)');
    if (v === null || typeof v !== 'object' || depth > 8 || ++visits > 2000) return;
    if (ArrayBuffer.isView(v)) return;
    for (const k of Object.keys(v)) walk(v[k], depth + 1);
  };
  walk(args, 0);
  return args;
}

function makeRef(session, root, ops) {
  const state = { session, root, ops };
  const readOnly = (what) => () => { throw new TypeError(what); };
  const handler = {
    get(_target, key) {
      if (key === BRAND) return state;
      if (typeof key === 'symbol') return undefined; // Symbol.toPrimitive, Symbol.asyncIterator, inspect hooks: not remote properties
      if (key === 'then') {
        // `await ref` sends the whole chain in ONE request. A remote property really named "then" is reached with get(ref, 'then').
        return (onFulfilled, onRejected) => send(state).then(onFulfilled, onRejected);
      }
      return makeRef(session, root, [...ops, { get: key }]);
    },
    set(_t, key) { throw new TypeError(`cannot assign to ${String(key)} of a remote reference with "=": assignment cannot be awaited or report a refusal. Use await set(ref, ${JSON.stringify(String(key))}, value)`); },
    defineProperty: readOnly('a remote reference cannot be defined on: use set(ref, key, value)'),
    deleteProperty: readOnly('a remote reference cannot be deleted from'),
    setPrototypeOf: readOnly('the prototype of a remote reference cannot be set'),
    apply(_t, _this, args) {
      const last = ops[ops.length - 1];
      if (!last || !('get' in last)) throw new TypeError('only a method reached by name can be called (win.app.cart.add(x)); call a path, not a result');
      return makeRef(session, root, [...ops.slice(0, -1), { call: last.get, args: plainArgs(args) }]);
    },
    construct(_t, args) {
      const last = ops[ops.length - 1];
      if (!last || !('get' in last)) throw new TypeError('only a constructor reached by name can be constructed (new win.app.Cart())');
      return makeRef(session, root, [...ops.slice(0, -1), { construct: last.get, args: plainArgs(args) }]);
    },
  };
  // A function as the target so the proxy can be called and constructed.
  return new Proxy(function remote() {}, handler);
}

async function send(state, { signal } = {}) {
  const { session, root, ops } = state;
  try {
    return decodeResult(await session.peer.request('resolve', { root, ops }, { signal, ...(session.timeoutMs ? { timeoutMs: session.timeoutMs } : {}) }));
  } catch (e) { throw asObjectsError(e, session); }
}

/** A reference that is a pure path (no call in it): what `set`, `describe` and `snapshot` take. */
function pathOf(ref, what) {
  const state = stateOf(ref);
  const keys = [];
  for (const op of state.ops) {
    if (!('get' in op)) throw new TypeError(`${what} needs a plain path (a reference with no call in it): await the call first, or name the path`);
    keys.push(op.get);
  }
  return { state, keys };
}

/** Read a property of a reference (also one named `then`, which `ref.then` cannot reach), or with no key, the reference itself. */
export function get(ref, ...keys) {
  const state = stateOf(ref);
  return send({ ...state, ops: [...state.ops, ...keys.map((k) => ({ get: String(k) }))] });
}

/** Assign a property of a remote object: `await set(win.document, 'title', 'Paid')`. Not `=`: an assignment cannot be awaited or report a refusal. */
export async function set(ref, key, value) {
  const { state, keys } = pathOf(ref, 'set');
  plainArgs([value]);
  try { await state.session.peer.request('set', { root: state.root, path: [...keys, String(key)], value }); } catch (e) { throw asObjectsError(e, state.session); }
}

/** Call a method reached by name with these (plain-data) arguments: `await call(win.app.cart.add, { sku: 'A1' })`; for a method named `then`, `call(ref, ...)`. */
export function call(ref, ...args) {
  const state = stateOf(ref);
  const last = state.ops[state.ops.length - 1];
  if (!last || !('get' in last)) throw new TypeError('call needs a method reached by name');
  return send({ ...state, ops: [...state.ops.slice(0, -1), { call: last.get, args: plainArgs(args) }] });
}

/** `new` a constructor reached by name: `await construct(win.app.Cart, 'A')`. */
export function construct(ref, ...args) {
  const state = stateOf(ref);
  const last = state.ops[state.ops.length - 1];
  if (!last || !('get' in last)) throw new TypeError('construct needs a constructor reached by name');
  return send({ ...state, ops: [...state.ops.slice(0, -1), { construct: last.get, args: plainArgs(args) }] });
}

/** A bounded deep copy: `await snapshot(win.app.state, { depth: 3, maxBytes: 256_000 })`. Subtrees deeper than `depth` are `null`. */
export async function snapshot(ref, { depth, maxBytes, signal } = {}) {
  const { state, keys } = pathOf(ref, 'snapshot');
  try {
    return decodeResult(await state.session.peer.request('snapshot', { root: state.root, path: keys, ...(depth !== undefined ? { depth } : {}), ...(maxBytes !== undefined ? { maxBytes } : {}) }, { signal }));
  } catch (e) { throw asObjectsError(e, state.session); }
}

/**
 * Listen for an event of a remote source named by the host's `allow.on`: `const stop = await on(win.app.bus, 'ready', (data, { seq, dropped }) => ...)`.
 * `data` is plain (an Event as `{ type, timeStamp, isTrusted, ...the fields you asked for }`, an emitter's as `{ type, args }`); `dropped` counts the events the
 * host dropped before this one (rate, size, or a slow channel). `fields` are extra event fields the host lists for the type. Resolves to the function that unsubscribes.
 */
export async function on(ref, type, listener, { fields, onError } = {}) {
  const { state, keys } = pathOf(ref, 'on');
  if (typeof listener !== 'function') throw new TypeError('on needs a listener function: listener(data, { type, seq, dropped })');
  const { session } = state;
  const id = session.nextSub++;
  // Registered before the request: an event can follow the answer at once.
  session.subs.set(id, { listener, onError, type });
  try {
    await session.peer.request('subscribe', { id, root: state.root, path: keys, type, ...(fields ? { fields } : {}) });
  } catch (e) { session.subs.delete(id); throw asObjectsError(e, session); }
  return async function off() {
    if (!session.subs.delete(id)) return;
    try { await session.peer.request('unsubscribe', { id }); } catch { /* the channel is already gone: the host removed the listener with it */ }
  };
}

/** Stop a subscription: `await off(await on(...))`, the same as calling the function `on` returned. */
export async function off(unsubscribe) {
  if (typeof unsubscribe !== 'function') throw new TypeError('off needs what on() returned');
  await unsubscribe();
}

/** The shape of an object, for a REPL or completion: `{ type, keys: [{ key, type, own }] }`. Only names the allow-list could walk to are told. */
export async function describe(ref, { signal } = {}) {
  const { state, keys } = pathOf(ref, 'describe');
  try { return await state.session.peer.request('describe', { root: state.root, path: keys }, { signal }); } catch (e) { throw asObjectsError(e, state.session); }
}

/**
 * The client half over any peer: asks for the roots and returns them as lazy references, `{ window }`.
 * @param {object} peer
 * @param {{ timeoutMs?: number }} [options]
 */
export async function createObjectsClient(peer, { timeoutMs } = {}) {
  if (typeof peer?.request !== 'function') throw new TypeError('createObjectsClient: the peer needs request(method, params)');
  const session = { peer, closing: null, timeoutMs, subs: new Map(), nextSub: 1 };
  // An event the host delivers: to the listener that asked, in this process. A listener that throws is this side's business and goes to its `onError`: it never travels back.
  peer.onNotification?.('event', (params) => {
    const sub = session.subs.get(params?.id);
    if (!sub) return;
    try { sub.listener(params.data, { type: sub.type, seq: params.seq, dropped: Number.isSafeInteger(params.dropped) ? params.dropped : 0 }); } catch (e) {
      try { sub.onError?.(e); } catch { /* the error handler's own */ }
    }
  });
  peer.onNotification?.('closing', (params) => { session.closing = typeof params?.reason === 'string' ? clip(params.reason, TEXT_MAX) : 'closing'; });
  let roots;
  try { roots = (await peer.request('roots', {}))?.roots; } catch (e) { throw asObjectsError(e, session); }
  if (!Array.isArray(roots)) throw new ObjectsError(OBJECTS_ERROR.FAILED, 'the host did not list its roots', { reason: 'bad-reply' });
  const page = {};
  for (const name of roots) if (typeof name === 'string' && !ALWAYS_REFUSED.has(name)) page[name] = makeRef(session, name, []);
  Object.defineProperty(page, SESSION, { value: session });
  return Object.freeze(page);
}

/** End the connection behind what `openObjects()` returned. */
export async function closeObjects(page) {
  const session = page?.[SESSION];
  if (!session) throw new TypeError('closeObjects: expected what openObjects() returned');
  await session.peer.close?.('closed by the caller');
}
