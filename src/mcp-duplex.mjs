/**
 * MCP over any duplex (#220). The handler of `webmcpTools` (and any rpc handler of the `mcp` protocol written as `(channel, ctx) => void`)
 * serves MCP on a channel; over wsh that channel is an `RpcChannel` of the `mcp` rpc protocol. `serveMcpOverDuplex` gives the same handler
 * a channel made of nothing but two functions you already have: `send(message)` for what goes to the far side, and `receive(message)` for
 * what comes from it, so a transport that is not wsh at all (a mesh channel, a `MessagePort`, a data channel, a test) can carry it.
 *
 * ```js
 * import { webmcpTools, serveMcpOverDuplex } from '@johnhenry/wsh/page';
 * const handler = webmcpTools({ window, allow: ['search'], approve: 'consequential' });
 * const session = serveMcpOverDuplex(handler, { send: (message) => meshChannel.send(message), who: { podId } });
 * meshChannel.onmessage = (message) => session.receive(message);
 * meshChannel.onclose = () => session.close('the peer left');
 * ```
 *
 * WHAT THE FAR SIDE SPEAKS: plain MCP, that is JSON-RPC 2.0 messages as JavaScript objects (`{ jsonrpc: '2.0', id, method, params }`,
 * `{ jsonrpc: '2.0', id, result }` or `{ jsonrpc: '2.0', id, error: { code, message, data? } }`, and notifications with no `id`): an MCP SDK
 * `Client` can be connected to it through any `Transport` that moves those objects. Encoding them (JSON text, CBOR, structured clone) is the
 * transport's business; this file sees objects. No batches (MCP no longer has them), no ids but strings and integers, one answer per id.
 *
 * WHAT IS THE HANDLER'S, UNCHANGED: the allow-list of tools, the bounds on tools, schemas, arguments and results, the approval of the
 * person at the page (`approve`, `prompt`), the `onCall` events and the labelling of every result as untrusted page content. WHAT THIS
 * ADDS: the bounds of the seam itself (the size of a message in either direction, the requests running at once, one id one request), and
 * the refusal of anything that is not a JSON-RPC 2.0 message from the far side.
 *
 * It does NOT authenticate the far side or seal anything: whoever the transport says is on the other end is `who`, and `permits` is
 * whatever that transport's grants allow. Those are the adapter's to establish and say; they are not in the messages.
 */

import { RpcError, RPC_ERROR } from './rpc.mjs';
import { callerIdentity } from './key-names.mjs';

const DEFAULT_MAX_MESSAGE_BYTES = 1024 * 1024;
const DEFAULT_MAX_INFLIGHT = 64;
const MAX_ID_CHARS = 256;

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** UTF-8 length of the JSON of `value` (the size of the message on a JSON transport), or -1 when it has none. */
function jsonBytes(value) {
  let s;
  try { s = JSON.stringify(value); } catch { return -1; }
  if (typeof s !== 'string') return -1;
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) { n += 4; i++; } else n += 3;
  }
  return n;
}

const validId = (id) => (typeof id === 'string' && id.length >= 1 && id.length <= MAX_ID_CHARS) || (Number.isSafeInteger(id));

/**
 * Serve an MCP handler over a duplex.
 *
 * @param {(channel: object, ctx?: object) => void} handler what `webmcpTools(...)` returns, or any handler written for an rpc channel of the `mcp` protocol
 * @param {object} options
 * @param {(message: object) => void | Promise<void>} options.send writes a JSON-RPC 2.0 message to the far side; a throw (or a rejection) ends the session
 * @param {{ username?: string | null, fingerprint?: string | null, podId?: string | null }} [options.who] who is on the far side, as the transport knows
 *   it: the handler's prompt, `onCall` events and `closeSessions(reason, fingerprint)` see it (`fingerprint` and `podId` agree, see `callerIdentity`)
 * @param {(request: { kind: string, [field: string]: unknown }) => boolean} [options.permits] the far side's grants, asked afresh for each tool
 *   (`{ kind: 'mcp-tool', tool }`); with none, nothing narrows the handler's own allow-list. `@johnhenry/wsh/capabilities`'s `permits` fits: `(req) => permits(caps, req)`
 * @param {number} [options.maxMessageBytes=1048576] the largest message, JSON-encoded, in either direction
 * @param {number} [options.maxInflight=64] requests of the far side being answered at once, of any kind
 * @returns {{ receive(message: unknown): void, close(reason?: string): void, readonly closed: boolean, readonly who: object | undefined }}
 */
export function serveMcpOverDuplex(handler, options = {}) {
  if (typeof handler !== 'function') throw new TypeError('serveMcpOverDuplex: the handler must be a function (channel, ctx), what webmcpTools() returns');
  const { send, who, permits, maxMessageBytes = DEFAULT_MAX_MESSAGE_BYTES, maxInflight = DEFAULT_MAX_INFLIGHT } = options;
  if (typeof send !== 'function') throw new TypeError('serveMcpOverDuplex: send(message) is required');
  if (permits !== undefined && typeof permits !== 'function') throw new TypeError('serveMcpOverDuplex: permits must be a function');
  if (!Number.isSafeInteger(maxMessageBytes) || maxMessageBytes < 256) throw new TypeError('serveMcpOverDuplex: maxMessageBytes must be a whole number of at least 256');
  if (!Number.isSafeInteger(maxInflight) || maxInflight < 1) throw new TypeError('serveMcpOverDuplex: maxInflight must be a positive whole number');
  const identity = callerIdentity(who);

  let closed = false;
  const requestHandlers = new Map();
  const notificationHandlers = new Map();
  /** id -> its AbortController, for what is being answered. */
  const inflight = new Map();

  const fail = (reason) => { try { session.close(reason); } catch { /* already closing */ } };
  /** Write one message; a throw or rejection of the transport ends the session. Resolves when written. */
  async function write(message) {
    if (closed) return;
    const size = jsonBytes(message);
    if (size < 0) throw new TypeError('the message cannot be serialised as JSON');
    if (size > maxMessageBytes) throw new RpcError(RPC_ERROR.INTERNAL, `refused: a message of ${size} bytes is larger than maxMessageBytes (${maxMessageBytes})`, { reason: 'message-too-large' });
    try { await send(message); } catch (e) { fail('the transport failed to send'); throw e; }
  }
  const respond = (id, body) => write({ jsonrpc: '2.0', id, ...body }).catch(() => {});
  const refuse = (id, code, message, data) => respond(id, { error: { code, message, ...(data !== undefined ? { data } : {}) } });

  /** The channel the handler is given: the part of an `RpcChannel` that an MCP handler uses. */
  const channel = {
    maxMessageBytes,
    onRequest(method, fn) { requestHandlers.set(method, fn); },
    onNotification(method, fn) { notificationHandlers.set(method, fn); },
    notify: (method, params) => write({ jsonrpc: '2.0', method, ...(params !== undefined ? { params } : {}) }),
    request: () => Promise.reject(new RpcError(RPC_ERROR.METHOD_NOT_FOUND, 'this side serves MCP and asks the far side nothing')),
    close: async (reason) => { session.close(reason); },
    onClose: null,
    get closed() { return closed; },
  };

  async function dispatch(id, method, params) {
    const fn = requestHandlers.get(method);
    if (!fn) { await refuse(id, RPC_ERROR.METHOD_NOT_FOUND, `method not found: ${method}`); return; }
    const ctl = new AbortController();
    inflight.set(id, ctl);
    try {
      const result = await fn(params, { id, signal: ctl.signal });
      // A cancelled request is not answered: the far side said it no longer wants the answer.
      if (!closed && !ctl.signal.aborted) {
        const body = { jsonrpc: '2.0', id, result: result === undefined ? {} : result };
        const size = jsonBytes(body);
        if (size < 0) await refuse(id, RPC_ERROR.INTERNAL, 'the answer cannot be serialised as JSON');
        else if (size > maxMessageBytes) await refuse(id, RPC_ERROR.INTERNAL, `refused: the answer is ${size} bytes, larger than maxMessageBytes (${maxMessageBytes})`, { reason: 'message-too-large' });
        else await write(body).catch(() => {});
      }
    } catch (e) {
      if (!closed && !ctl.signal.aborted) {
        if (e instanceof RpcError) await refuse(id, e.code, e.message, e.toJSON().data);
        else await refuse(id, RPC_ERROR.INTERNAL, String(e?.message ?? e));
      }
    } finally {
      inflight.delete(id);
    }
  }

  const session = {
    /** Hand over one message from the far side. Never throws: what cannot be answered is refused or dropped. */
    receive(message) {
      if (closed) return;
      if (!isObject(message) || message.jsonrpc !== '2.0') {
        // An id we can read is answered; anything else is dropped (there is no one to tell).
        if (isObject(message) && validId(message.id)) void refuse(message.id, RPC_ERROR.INVALID_REQUEST, 'not a JSON-RPC 2.0 message (batches are not supported)');
        else if (Array.isArray(message) || message === null || typeof message !== 'object') void refuse(null, RPC_ERROR.INVALID_REQUEST, 'not a JSON-RPC 2.0 message (batches are not supported)');
        return;
      }
      const size = jsonBytes(message);
      if (size < 0 || size > maxMessageBytes) {
        void refuse(validId(message.id) ? message.id : null, RPC_ERROR.INVALID_REQUEST, `refused: a message larger than maxMessageBytes (${maxMessageBytes})`, { reason: 'message-too-large' });
        return;
      }
      const hasId = Object.hasOwn(message, 'id');
      if (typeof message.method !== 'string') {
        // A response (or error) of the far side: nothing here asked it anything.
        if (hasId && !('result' in message) && !('error' in message)) void refuse(validId(message.id) ? message.id : null, RPC_ERROR.INVALID_REQUEST, 'a request needs a method');
        return;
      }
      if (message.params !== undefined && !isObject(message.params)) {
        if (hasId) void refuse(validId(message.id) ? message.id : null, RPC_ERROR.INVALID_REQUEST, 'params must be an object');
        return;
      }
      if (!hasId) {
        // A notification. Cancellation is the one the seam knows: it aborts the request the far side names.
        if (message.method === 'notifications/cancelled') inflight.get(message.params?.requestId)?.abort(new Error('cancelled by the caller'));
        try { notificationHandlers.get(message.method)?.(message.params); } catch { /* a notification has no one to tell */ }
        return;
      }
      if (!validId(message.id)) { void refuse(null, RPC_ERROR.INVALID_REQUEST, 'a request id is a string or a whole number'); return; }
      if (inflight.has(message.id)) { void refuse(message.id, RPC_ERROR.INVALID_REQUEST, `request id ${JSON.stringify(message.id)} is still in flight`); return; }
      if (inflight.size >= maxInflight) { void refuse(message.id, RPC_ERROR.STREAM_LIMIT, `refused: maxInflight: more than ${maxInflight} requests at once`, { limit: 'maxInflight' }); return; }
      void dispatch(message.id, message.method, message.params);
    },

    /** End the session: running calls are aborted, the handler's watchers are removed, nothing more is answered. */
    close(reason = 'closed') {
      if (closed) return;
      closed = true;
      for (const ctl of inflight.values()) ctl.abort(new Error(`the session ended (${reason})`));
      try { channel.onClose?.(reason); } catch { /* the handler's own */ }
    },

    get closed() { return closed; },
    get who() { return identity; },
  };

  handler(channel, { ...(identity ? { who: identity, user: identity.username, fingerprint: identity.fingerprint } : {}), ...(permits ? { permits } : {}) });
  return session;
}
