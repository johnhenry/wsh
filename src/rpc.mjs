/**
 * Typed ("object-mode") RPC channels -- wsh #85.
 *
 * An `rpc` channel is an ordinary QMux stream whose payload is a CBOR sequence
 * (RFC 8742) of JSON-RPC 2.0 messages, the way SSH's `sftp` subsystem is a
 * typed protocol inside a byte-stream channel. This module is transport-free
 * and browser-safe: `RpcChannel` is given a `write(bytes)` and fed received
 * bytes; the client (`WshClient.openRpc`) and the Node host
 * (`createWshServer({ rpc })`) each bind it to a stream.
 *
 * Messages (JSON-RPC 2.0 exactly, CBOR-encoded, so binary values are native
 * byte strings and surface as `Uint8Array`):
 *   Request      { jsonrpc: '2.0', id, method, params? }
 *   Notification { jsonrpc: '2.0', method, params? }
 *   Response     { jsonrpc: '2.0', id, result } | { jsonrpc: '2.0', id, error: { code, message, data? } }
 * plus two reserved notifications: `$/cancel { id }` and `$/progress { id, chunk }`.
 * Responses are matched by `id` only -- never by message type.
 */

import { cborEncode, cborDecode } from './cbor.mjs';

// ── Names ─────────────────────────────────────────────────────────────

/** ServerHello feature: the host serves `rpc` sessions. */
export const RPC_FEATURE = 'rpc';
/** ServerHello feature prefix: one `rpc-protocol:<name>` per supported protocol. */
export const RPC_PROTOCOL_PREFIX = 'rpc-protocol:';
/** ServerHello feature prefix: `rpc-max-message:<bytes>`, the largest single message the host accepts. */
export const RPC_MAX_MESSAGE_PREFIX = 'rpc-max-message:';
/** Largest message when the host does not say (1 MiB). Larger payloads must stream (`$/progress`) or be chunked. */
export const RPC_DEFAULT_MAX_MESSAGE = 1024 * 1024;

/** @param {string} name */
export const rpcProtocolFeature = (name) => RPC_PROTOCOL_PREFIX + name;

/** A protocol name is carried in a feature string and in `Open.command`: keep it boring. */
export const RPC_PROTOCOL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** JSON-RPC's reserved codes plus wsh's. */
export const RPC_ERROR = Object.freeze({
  PARSE: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL: -32603,
  UNSUPPORTED_PROTOCOL: -32000,
  CANCELLED: -32001,
  STREAM_LIMIT: -32002,
  UNAUTHORIZED: -32003,
});

/**
 * Read the rpc advertisement out of `ServerHello.features`.
 * @param {string[]} [features]
 * @returns {{ enabled: boolean, protocols: string[], maxMessageBytes: number }}
 */
export function parseRpcFeatures(features = []) {
  const protocols = [];
  let maxMessageBytes = RPC_DEFAULT_MAX_MESSAGE;
  let enabled = false;
  for (const f of features) {
    if (typeof f !== 'string') continue;
    if (f === RPC_FEATURE) enabled = true;
    else if (f.startsWith(RPC_PROTOCOL_PREFIX)) protocols.push(f.slice(RPC_PROTOCOL_PREFIX.length));
    else if (f.startsWith(RPC_MAX_MESSAGE_PREFIX)) {
      const n = Number(f.slice(RPC_MAX_MESSAGE_PREFIX.length));
      if (Number.isSafeInteger(n) && n > 0) maxMessageBytes = n;
    }
  }
  return { enabled, protocols, maxMessageBytes };
}

// ── Errors ────────────────────────────────────────────────────────────

/** A JSON-RPC error: thrown by `request()` for an error response, and by handlers to answer with one. */
export class RpcError extends Error {
  /**
   * @param {number} code
   * @param {string} message
   * @param {unknown} [data]
   * @param {string} [reason] - a short machine-readable cause (`channel-closed`, `timeout`, `UNSUPPORTED_PROTOCOL`, ...)
   */
  constructor(code, message, data, reason) {
    super(message);
    this.name = 'RpcError';
    this.code = code;
    if (data !== undefined) this.data = data;
    this.reason = reason ?? (data && typeof data === 'object' && typeof data.reason === 'string' ? data.reason : undefined);
  }

  /** @returns {{ code: number, message: string, data?: unknown }} */
  toJSON() {
    const o = { code: this.code, message: this.message };
    if (this.data !== undefined) o.data = this.data;
    else if (this.reason) o.data = { reason: this.reason };
    return o;
  }

  static fromWire(e) {
    const o = e && typeof e === 'object' ? e : {};
    return new RpcError(Number.isInteger(o.code) ? o.code : RPC_ERROR.INTERNAL, typeof o.message === 'string' ? o.message : 'rpc error', o.data);
  }
}

const tooLarge = (what, size, max) => new RpcError(RPC_ERROR.INVALID_REQUEST, `${what} of ${size} bytes exceeds the ${max} byte rpc message limit`, { reason: 'message-too-large' });
const closedError = (detail) => new RpcError(RPC_ERROR.CANCELLED, 'rpc channel closed', { reason: 'channel-closed', detail });

// ── CBOR sequence decoder ─────────────────────────────────────────────

const MAX_DEPTH = 128;

class Incomplete extends Error {}
const INCOMPLETE = new Incomplete('incomplete');

/**
 * End offset of the CBOR data item starting at `off`, or throws INCOMPLETE if `buf` ends first.
 * Structure is validated just enough to find the item's end; `cborDecode` does the decoding.
 */
function scan(buf, off, max, depth) {
  if (depth > MAX_DEPTH) throw new RpcError(RPC_ERROR.PARSE, 'cbor nesting too deep');
  if (off >= buf.length) throw INCOMPLETE;
  const initial = buf[off++];
  const mt = initial >> 5;
  const ai = initial & 0x1f;
  if (ai >= 28 && ai <= 30) throw new RpcError(RPC_ERROR.PARSE, 'malformed cbor (reserved additional info)');
  const indefinite = ai === 31;
  let arg = 0;
  if (ai < 24) arg = ai;
  else if (ai <= 27) {
    const n = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : 8;
    if (off + n > buf.length) throw INCOMPLETE;
    for (let i = 0; i < n; i++) arg = arg * 256 + buf[off + i];
    off += n;
  }
  switch (mt) {
    case 0: case 1:
      if (indefinite) throw new RpcError(RPC_ERROR.PARSE, 'malformed cbor (indefinite integer)');
      return off;
    case 2: case 3: {
      if (indefinite) {
        for (;;) {
          if (off >= buf.length) throw INCOMPLETE;
          if (buf[off] === 0xff) return off + 1;
          if ((buf[off] >> 5) !== mt || (buf[off] & 0x1f) === 31) throw new RpcError(RPC_ERROR.PARSE, 'malformed cbor (bad string chunk)');
          off = scan(buf, off, max, depth + 1);
        }
      }
      if (arg > max) throw tooLarge('message', arg, max);
      if (off + arg > buf.length) throw INCOMPLETE;
      return off + arg;
    }
    case 4: case 5: {
      const per = mt === 5 ? 2 : 1;
      if (indefinite) {
        for (;;) {
          if (off >= buf.length) throw INCOMPLETE;
          if (buf[off] === 0xff) return off + 1;
          for (let i = 0; i < per; i++) off = scan(buf, off, max, depth + 1);
        }
      }
      if (arg > max) throw tooLarge('message', arg, max); // every element is at least a byte
      for (let i = 0; i < arg * per; i++) off = scan(buf, off, max, depth + 1);
      return off;
    }
    case 6:
      if (indefinite) throw new RpcError(RPC_ERROR.PARSE, 'malformed cbor (indefinite tag)');
      return scan(buf, off, max, depth + 1);
    default: // 7: simple values and floats; 0xff outside an indefinite item is invalid
      if (indefinite) throw new RpcError(RPC_ERROR.PARSE, 'malformed cbor (unexpected break)');
      return off;
  }
}

/**
 * Incremental decoder for a CBOR sequence (RFC 8742): `feed()` bytes as they
 * arrive, get back every item completed so far. Items are self-delimiting, so
 * there is no length prefix. An item larger than `maxItemBytes` is refused as
 * soon as it is detectable; malformed CBOR throws an `RpcError` (-32700).
 */
export class CborSequenceDecoder {
  #buf = new Uint8Array(0);
  #max;

  /** @param {{ maxItemBytes?: number }} [opts] */
  constructor({ maxItemBytes = RPC_DEFAULT_MAX_MESSAGE } = {}) {
    this.#max = maxItemBytes;
  }

  /** Bytes buffered towards an incomplete item. */
  get pending() {
    return this.#buf.length;
  }

  /**
   * @param {Uint8Array} chunk
   * @returns {unknown[]}
   */
  feed(chunk) {
    if (chunk.length) {
      if (this.#buf.length === 0) this.#buf = chunk;
      else {
        const next = new Uint8Array(this.#buf.length + chunk.length);
        next.set(this.#buf, 0);
        next.set(chunk, this.#buf.length);
        this.#buf = next;
      }
    }
    const out = [];
    let off = 0;
    try {
      while (off < this.#buf.length) {
        let end;
        try {
          end = scan(this.#buf, off, this.#max, 0);
        } catch (e) {
          if (e === INCOMPLETE) {
            if (this.#buf.length - off > this.#max) throw tooLarge('message', this.#buf.length - off, this.#max);
            break;
          }
          throw e;
        }
        if (end - off > this.#max) throw tooLarge('message', end - off, this.#max);
        let item;
        try {
          item = cborDecode(this.#buf.subarray(off, end));
        } catch (e) {
          throw new RpcError(RPC_ERROR.PARSE, `malformed cbor: ${e.message}`);
        }
        out.push(item);
        off = end;
      }
    } catch (e) {
      this.#buf = new Uint8Array(0);
      throw e;
    }
    this.#buf = off === this.#buf.length ? new Uint8Array(0) : this.#buf.slice(off);
    return out;
  }
}

// ── Channel ───────────────────────────────────────────────────────────

/** Deep copy without `undefined` members (CBOR has no undefined; JSON-RPC drops them). Byte strings are shared. */
function prune(v) {
  if (Array.isArray(v)) return v.map((x) => (x === undefined ? null : prune(x)));
  if (v && typeof v === 'object' && !ArrayBuffer.isView(v) && !(v instanceof ArrayBuffer)) {
    const o = {};
    for (const k of Object.keys(v)) if (v[k] !== undefined) o[k] = prune(v[k]);
    return o;
  }
  return v;
}

const isId = (id) => typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id));
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && !ArrayBuffer.isView(v);

/**
 * One end of an `rpc` channel: JSON-RPC 2.0 over a CBOR sequence, symmetric --
 * either side may request, notify, and answer.
 *
 * @typedef {{ id: string|number, method: string, signal: AbortSignal, channel: RpcChannel, progress(chunk: unknown): Promise<void> }} RpcContext
 */
export class RpcChannel {
  #write; #closeFn; #max; #timeoutMs; #maxInflight;
  #nextId = 1;
  /** Outbound requests awaiting a response, by id. */
  #pending = new Map();
  /** Inbound requests a handler is working on, by id. */
  #inflight = new Map();
  #handlers = new Map();
  #notifications = new Map();
  #fallbackRequest = null;
  #fallbackNotification = null;
  #decoder;
  #writes = Promise.resolve();
  #closed = false;
  #closeReason = null;
  #closing = null;
  #held = false;
  #heldItems = [];

  /** Called once when the channel ends, with the reason. */
  onClose = null;

  /**
   * @param {object} opts
   * @param {(bytes: Uint8Array) => Promise<void> | void} opts.write - send bytes to the peer (in order)
   * @param {() => Promise<void> | void} [opts.close] - end the underlying stream
   * @param {number} [opts.maxMessageBytes=1048576]
   * @param {number} [opts.timeoutMs] - default per-request timeout (none when omitted)
   * @param {number} [opts.maxInflight=64] - concurrent inbound requests before `-32002`
   */
  constructor({ write, close, maxMessageBytes = RPC_DEFAULT_MAX_MESSAGE, timeoutMs, maxInflight = 64 } = {}) {
    if (typeof write !== 'function') throw new TypeError('RpcChannel: write(bytes) is required');
    this.#write = write;
    this.#closeFn = close ?? (() => {});
    this.#max = maxMessageBytes;
    this.#timeoutMs = timeoutMs > 0 ? timeoutMs : 0;
    this.#maxInflight = maxInflight;
    this.#decoder = new CborSequenceDecoder({ maxItemBytes: maxMessageBytes });
  }

  get closed() { return this.#closed; }
  get closeReason() { return this.#closeReason; }
  get maxMessageBytes() { return this.#max; }
  /** Outbound requests still waiting for a response. */
  get pendingCount() { return this.#pending.size; }
  /** Inbound requests still being handled. */
  get inflightCount() { return this.#inflight.size; }

  // ── Registration ────────────────────────────────────────────────────

  /**
   * Answer requests for `method`. The handler gets `(params, ctx)`; its return value is the result, a thrown
   * `RpcError` is the error response, and any other throw becomes `-32603`. `ctx.signal` aborts on `$/cancel` or
   * close; `ctx.progress(chunk)` sends a `$/progress` for this request.
   * @param {string} method
   * @param {(params: any, ctx: RpcContext) => unknown} handler
   * @returns {() => void} unregister
   */
  onRequest(method, handler) {
    if (typeof handler !== 'function') throw new TypeError('onRequest: handler must be a function');
    this.#handlers.set(method, handler);
    return () => { if (this.#handlers.get(method) === handler) this.#handlers.delete(method); };
  }

  /** @param {string} method @param {(params: any) => void} handler @returns {() => void} */
  onNotification(method, handler) {
    this.#notifications.set(method, handler);
    return () => { if (this.#notifications.get(method) === handler) this.#notifications.delete(method); };
  }

  /** Catch-all for requests with no `onRequest` handler: `(method, params, ctx) => result`. Pass `null` to clear. */
  setFallbackRequestHandler(fn) { this.#fallbackRequest = fn; }

  /** Catch-all for notifications with no `onNotification` handler: `(method, params) => void`. */
  setFallbackNotificationHandler(fn) { this.#fallbackNotification = fn; }

  /**
   * Listen for `$/progress` chunks of a request already in flight (or pass `onProgress` to `request()`).
   * @param {string | number} id - `request(...).id`
   * @param {(chunk: any) => void} fn
   */
  onProgress(id, fn) {
    const p = this.#pending.get(id);
    if (p) p.onProgress = fn;
  }

  /**
   * Queue inbound messages instead of dispatching them, until `release()`. A host holds a fresh channel while its
   * (possibly async) protocol handler registers methods, so a peer's first request cannot beat the registration.
   */
  hold() { this.#held = true; }

  /** Dispatch everything queued since `hold()`, in arrival order, and resume normal delivery. */
  release() {
    this.#held = false;
    for (const item of this.#heldItems.splice(0)) {
      if (this.#closed) return;
      this.#dispatch(item);
    }
  }

  // ── Outbound ────────────────────────────────────────────────────────

  /**
   * Send a request. The returned promise carries `.id` and `.cancel()`.
   * Rejects with `RpcError`: the peer's error response, `-32001` on cancel / timeout / channel close.
   * @param {string} method
   * @param {unknown} [params]
   * @param {{ onProgress?: (chunk: any) => void, signal?: AbortSignal, timeoutMs?: number, id?: string | number }} [opts]
   * @returns {Promise<any> & { id: string | number, cancel(reason?: string): boolean }}
   */
  request(method, params, { onProgress, signal, timeoutMs, id } = {}) {
    if (typeof method !== 'string' || !method) throw new TypeError('request: method must be a non-empty string');
    if (id !== undefined && !isId(id)) throw new TypeError('request: id must be a string or number');
    const rid = id ?? this.#nextId++;
    const promise = new Promise((resolve, reject) => this.#registerPending(rid, method, params, { resolve, reject, onProgress, signal, timeoutMs }));
    promise.id = rid;
    promise.cancel = (reason) => this.cancel(rid, reason);
    return promise;
  }

  #registerPending(id, method, params, { resolve, reject, onProgress, signal, timeoutMs }) {
    if (this.#closed) return reject(closedError(this.#closeReason));
    if (this.#pending.has(id)) return reject(new RpcError(RPC_ERROR.INVALID_REQUEST, `request id ${id} is already in flight`));
    const entry = { method, resolve, reject, onProgress, timer: null, signal, onAbort: null };
    let bytes;
    try {
      const msg = { jsonrpc: '2.0', id, method };
      if (params !== undefined) msg.params = params;
      bytes = this.#encode(msg);
    } catch (e) { return reject(e); }
    this.#pending.set(id, entry);
    const ms = timeoutMs ?? this.#timeoutMs;
    if (ms > 0) entry.timer = setTimeout(() => this.cancel(id, 'timeout', `request "${method}" timed out after ${ms} ms`), ms);
    if (signal) {
      if (signal.aborted) { queueMicrotask(() => this.cancel(id, 'aborted')); } else {
        entry.onAbort = () => this.cancel(id, 'aborted');
        signal.addEventListener('abort', entry.onAbort, { once: true });
      }
    }
    this.#enqueue(bytes).catch((e) => this.#settlePending(id, (p) => p.reject(e instanceof RpcError ? e : closedError(e?.message))));
  }

  #settlePending(id, fn) {
    const p = this.#pending.get(id);
    if (!p) return false;
    this.#pending.delete(id);
    clearTimeout(p.timer);
    if (p.onAbort) p.signal.removeEventListener('abort', p.onAbort);
    fn(p);
    return true;
  }

  /**
   * Cancel an outbound request: tell the callee (`$/cancel`), reject it locally with `-32001`, and drop any late
   * response. Returns false if `id` is not in flight.
   * @param {string | number} id
   * @param {string} [reason]
   */
  cancel(id, reason = 'cancelled', message) {
    const done = this.#settlePending(id, (p) => p.reject(new RpcError(RPC_ERROR.CANCELLED, message ?? `request "${p.method}" cancelled`, { reason })));
    if (done && !this.#closed) this.notify('$/cancel', { id });
    return done;
  }

  /**
   * Send a notification (no response).
   * @param {string} method
   * @param {unknown} [params]
   * @returns {Promise<void>}
   */
  notify(method, params) {
    if (typeof method !== 'string' || !method) throw new TypeError('notify: method must be a non-empty string');
    if (this.#closed) return Promise.resolve();
    const msg = { jsonrpc: '2.0', method };
    if (params !== undefined) msg.params = params;
    return this.#enqueue(this.#encode(msg)).catch(() => {});
  }

  /**
   * End the channel: pending requests reject with `-32001` / `channel-closed`, in-flight handlers are aborted, and
   * the underlying stream is closed.
   * @param {string} [reason]
   */
  async close(reason = 'closed') {
    if (this.#closing) return this.#closing;
    if (this.#closed) return;
    this.#closing = (async () => {
      const flush = this.#writes;
      this.#teardown(reason);
      await Promise.race([flush, new Promise((r) => setTimeout(r, 1000))]);
      try { await this.#closeFn(); } catch { /* already gone */ }
    })();
    return this.#closing;
  }

  /** For the transport: the underlying stream ended or was reset. */
  handleClose(reason = 'stream-closed') {
    this.#teardown(reason);
  }

  #teardown(reason) {
    if (this.#closed) return;
    this.#closed = true;
    this.#closeReason = reason;
    for (const id of [...this.#pending.keys()]) this.#settlePending(id, (p) => p.reject(closedError(reason)));
    for (const rec of this.#inflight.values()) { rec.done = true; rec.ctl.abort(closedError(reason)); }
    this.#inflight.clear();
    const cb = this.onClose;
    this.onClose = null;
    try { cb?.(reason); } catch { /* a listener's problem */ }
  }

  // ── Inbound ─────────────────────────────────────────────────────────

  /**
   * For the transport: bytes received from the peer.
   * @param {Uint8Array} bytes
   */
  feed(bytes) {
    if (this.#closed) return;
    let items;
    try {
      items = this.#decoder.feed(bytes);
    } catch (e) {
      const err = e instanceof RpcError ? e : new RpcError(RPC_ERROR.PARSE, String(e?.message ?? e));
      this.#sendRaw({ jsonrpc: '2.0', id: null, error: err.toJSON() });
      void this.close(err.code === RPC_ERROR.PARSE ? 'parse-error' : (err.reason ?? 'protocol-error'));
      return;
    }
    for (const item of items) {
      if (this.#closed) return;
      if (this.#held) this.#heldItems.push(item);
      else this.#dispatch(item);
    }
  }

  #dispatch(m) {
    if (!isObj(m) || m.jsonrpc !== '2.0') return this.#invalid(m);
    const hasMethod = typeof m.method === 'string';
    if (hasMethod) {
      if (m.params !== undefined && m.params !== null && typeof m.params !== 'object') return this.#invalid(m);
      if (m.id === undefined) return this.#notification(m);
      if (!isId(m.id)) return this.#sendRaw({ jsonrpc: '2.0', id: null, error: { code: RPC_ERROR.INVALID_REQUEST, message: 'invalid request id' } });
      return this.#request(m);
    }
    if (m.method !== undefined) return this.#invalid(m);
    // A response.
    if (m.id === null || m.id === undefined) return; // an error about a message we could not have correlated
    if (!isId(m.id) || ('result' in m) === ('error' in m)) return;
    this.#settlePending(m.id, (p) => {
      if ('error' in m) p.reject(RpcError.fromWire(m.error));
      else p.resolve(m.result);
    });
  }

  #invalid(m) {
    const id = isObj(m) && isId(m.id) ? m.id : null;
    this.#sendRaw({ jsonrpc: '2.0', id, error: { code: RPC_ERROR.INVALID_REQUEST, message: 'invalid JSON-RPC 2.0 message' } });
  }

  #notification(m) {
    const params = m.params ?? undefined;
    if (m.method === '$/cancel') {
      const id = params?.id;
      const rec = isId(id) ? this.#inflight.get(id) : undefined;
      if (!rec || rec.done) return;
      rec.done = true;
      this.#inflight.delete(id);
      rec.ctl.abort(new RpcError(RPC_ERROR.CANCELLED, 'request cancelled by the caller', { reason: 'cancelled' }));
      this.#sendRaw({ jsonrpc: '2.0', id, error: { code: RPC_ERROR.CANCELLED, message: 'request cancelled', data: { reason: 'cancelled' } } });
      return;
    }
    if (m.method === '$/progress') {
      const p = isId(params?.id) ? this.#pending.get(params.id) : undefined;
      if (p?.onProgress) {
        try { p.onProgress(params.chunk); } catch { /* a listener's problem */ }
      }
      return;
    }
    const handler = this.#notifications.get(m.method);
    try {
      if (handler) handler(params);
      else this.#fallbackNotification?.(m.method, params);
    } catch { /* a notification has no one to tell */ }
  }

  #request(m) {
    const { id, method } = m;
    const params = m.params ?? undefined;
    const respond = (msg) => this.#sendRaw(msg);
    if (this.#inflight.has(id)) return respond({ jsonrpc: '2.0', id, error: { code: RPC_ERROR.INVALID_REQUEST, message: `request id ${id} is already in flight` } });
    if (this.#inflight.size >= this.#maxInflight) {
      return respond({ jsonrpc: '2.0', id, error: { code: RPC_ERROR.STREAM_LIMIT, message: `more than ${this.#maxInflight} requests in flight`, data: { reason: 'stream-limit' } } });
    }
    const handler = this.#handlers.get(method);
    const fallback = this.#fallbackRequest;
    if (!handler && !fallback) return respond({ jsonrpc: '2.0', id, error: { code: RPC_ERROR.METHOD_NOT_FOUND, message: `method not found: ${method}` } });
    const ctl = new AbortController();
    const rec = { ctl, done: false };
    this.#inflight.set(id, rec);
    /** @type {RpcContext} */
    const ctx = {
      id, method, signal: ctl.signal, channel: this,
      progress: (chunk) => (rec.done || this.#closed ? Promise.resolve() : this.#progress(id, chunk)),
    };
    (async () => {
      let msg;
      try {
        const result = handler ? await handler(params, ctx) : await fallback(method, params, ctx);
        msg = { jsonrpc: '2.0', id, result: result === undefined ? null : result };
      } catch (e) {
        const err = e instanceof RpcError ? e : new RpcError(RPC_ERROR.INTERNAL, String(e?.message ?? e));
        msg = { jsonrpc: '2.0', id, error: err.toJSON() };
      }
      if (rec.done) return; // cancelled or closed while working: the answer was already sent (or is moot)
      rec.done = true;
      this.#inflight.delete(id);
      try {
        this.#enqueue(this.#encode(msg)).catch(() => {});
      } catch (e) {
        if (!(e instanceof RpcError)) throw e;
        this.#sendRaw({ jsonrpc: '2.0', id, error: { code: RPC_ERROR.INTERNAL, message: e.message, data: { reason: e.reason } } });
      }
    })();
  }

  #progress(id, chunk) {
    try {
      return this.#enqueue(this.#encode({ jsonrpc: '2.0', method: '$/progress', params: { id, chunk } }));
    } catch (e) {
      return Promise.reject(e);
    }
  }

  // ── Wire ────────────────────────────────────────────────────────────

  #encode(msg) {
    const bytes = cborEncode(prune(msg));
    if (bytes.length > this.#max) throw tooLarge('message', bytes.length, this.#max);
    return bytes;
  }

  /** Best-effort send of a small control message (errors, never throws). */
  #sendRaw(msg) {
    if (this.#closed && msg.error?.code !== RPC_ERROR.PARSE && msg.error?.code !== RPC_ERROR.INVALID_REQUEST) return;
    try { this.#enqueue(cborEncode(prune(msg))).catch(() => {}); } catch { /* nothing to be done */ }
  }

  #enqueue(bytes) {
    const p = this.#writes.then(() => this.#write(bytes));
    this.#writes = p.catch(() => {});
    return p;
  }
}
