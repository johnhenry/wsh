/**
 * MCP over an `rpc` channel -- wsh #85 / #71.
 *
 * `RpcMcpTransport` is a Model Context Protocol SDK `Transport`
 * (`start` / `send` / `close` + `onmessage` / `onclose` / `onerror`) built on an
 * `RpcChannel`, so an MCP `Server` or `Client` can speak across a wsh host:
 *
 *   host:   createWshServer({ rpc: { mcp: mcpServerAdapter(server) } })      // `@johnhenry/wsh/server`
 *   client: await mcpClient.connect(mcpClientTransport(await wsh.openRpc('mcp')))
 *
 * MCP messages already are JSON-RPC 2.0, so this is a pass-through: a request
 * keeps the id the SDK chose, results and errors map 1:1, and notifications
 * (including `notifications/progress`) are forwarded verbatim. The one
 * translation is cancellation, where MCP's `notifications/cancelled` and wsh's
 * `$/cancel` are two spellings of one thing:
 *   - outgoing `notifications/cancelled { requestId }` -> `$/cancel { id }` (and the local request is dropped);
 *   - an incoming `$/cancel` -> a synthetic `notifications/cancelled` delivered to the SDK, so its tool handler's
 *     `signal` fires; the channel itself answers the caller with `-32001`.
 *
 * Nothing here imports the SDK: the transport is structural, so the package
 * root stays dependency-free and browser-safe. `@modelcontextprotocol/sdk` is
 * an optional peer, needed only by whoever supplies the `Server`/`Client`.
 */

import { RpcError, RPC_ERROR } from './rpc.mjs';

const rpcErrorFromMcp = (e) => new RpcError(Number.isInteger(e?.code) ? e.code : RPC_ERROR.INTERNAL, String(e?.message ?? 'error'), e?.data);

export class RpcMcpTransport {
  #channel;
  #started = false;
  #closed = false;
  /** Inbound requests handed to the SDK, awaiting its response, by JSON-RPC id. */
  #awaiting = new Map();
  /** Messages that arrived before the SDK attached `onmessage`. */
  #queue = [];
  #onmessage = null;

  /** @type {(() => void) | undefined} */ onclose;
  /** @type {((error: Error) => void) | undefined} */ onerror;
  /** @type {string | undefined} */ sessionId;

  /** @param {import('./rpc.mjs').RpcChannel} channel */
  constructor(channel) {
    this.#channel = channel;
    // Installed now, not in start(): a peer's first request can land before the SDK has called start().
    channel.setFallbackRequestHandler((method, params, ctx) => this.#inboundRequest(method, params, ctx));
    channel.setFallbackNotificationHandler((method, params) => this.#deliver({ jsonrpc: '2.0', method, ...(params !== undefined ? { params } : {}) }));
    const prior = channel.onClose;
    channel.onClose = (reason) => {
      this.#closed = true;
      for (const w of this.#awaiting.values()) w.reject(new RpcError(RPC_ERROR.CANCELLED, 'rpc channel closed', { reason: 'channel-closed' }));
      this.#awaiting.clear();
      try { prior?.(reason); } catch { /* ignore */ }
      this.onclose?.();
    };
  }

  get channel() { return this.#channel; }

  get onmessage() { return this.#onmessage; }

  set onmessage(fn) {
    this.#onmessage = fn;
    if (fn) for (const m of this.#queue.splice(0)) this.#safeDeliver(m);
  }

  async start() {
    if (this.#started) throw new Error('RpcMcpTransport already started');
    this.#started = true;
  }

  /**
   * @param {{ jsonrpc: '2.0', id?: string | number, method?: string, params?: any, result?: any, error?: any }} message
   */
  async send(message) {
    if (this.#closed || this.#channel.closed) throw new Error('rpc channel is closed');
    const hasId = message.id !== undefined && message.id !== null;
    if (typeof message.method === 'string') {
      if (!hasId) return this.#sendNotification(message);
      this.#sendRequest(message);
      return;
    }
    // A response to a request we handed the SDK.
    const waiter = this.#awaiting.get(message.id);
    if (!waiter) return; // cancelled, or already answered
    this.#awaiting.delete(message.id);
    if (message.error) waiter.reject(rpcErrorFromMcp(message.error));
    else waiter.resolve(message.result ?? null);
  }

  async close() {
    this.#closed = true;
    await this.#channel.close('mcp-transport-closed');
  }

  #sendNotification(message) {
    const { method, params } = message;
    if (method === 'notifications/cancelled' && params && params.requestId !== undefined && this.#channel.cancel(params.requestId, 'cancelled')) return;
    return this.#channel.notify(method, params);
  }

  /** A request the SDK is making of the peer: keep its id, hand the answer back as a response message. */
  #sendRequest(message) {
    const { id, method, params } = message;
    this.#channel.request(method, params, { id }).then(
      (result) => this.#deliver({ jsonrpc: '2.0', id, result }),
      (e) => {
        // A request the SDK itself abandoned (cancelled) must not resurface as an error response.
        if (e instanceof RpcError && e.code === RPC_ERROR.CANCELLED && e.reason !== 'channel-closed' && e.reason !== 'timeout') return;
        const error = e instanceof RpcError ? e.toJSON() : { code: RPC_ERROR.INTERNAL, message: String(e?.message ?? e) };
        this.#deliver({ jsonrpc: '2.0', id, error });
      },
    );
  }

  /** A request from the peer: pass it to the SDK and wait for the response it sends back through `send()`. */
  #inboundRequest(method, params, ctx) {
    return new Promise((resolve, reject) => {
      const id = ctx.id;
      this.#awaiting.set(id, { resolve, reject });
      ctx.signal.addEventListener('abort', () => {
        if (!this.#awaiting.delete(id)) return;
        reject(new RpcError(RPC_ERROR.CANCELLED, 'request cancelled', { reason: 'cancelled' }));
        if (!this.#closed) this.#deliver({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id, reason: 'cancelled' } });
      }, { once: true });
      this.#deliver({ jsonrpc: '2.0', id, method, ...(params !== undefined ? { params } : {}) });
    });
  }

  #deliver(message) {
    if (!this.#onmessage) { this.#queue.push(message); return; }
    this.#safeDeliver(message);
  }

  #safeDeliver(message) {
    try {
      this.#onmessage(message, {});
    } catch (e) {
      this.onerror?.(e instanceof Error ? e : new Error(String(e)));
    }
  }
}

/** A transport for an MCP `Client` (`@modelcontextprotocol/sdk`), over a channel from `client.openRpc('mcp')`. */
export function mcpClientTransport(channel) {
  return new RpcMcpTransport(channel);
}

/** A transport for an MCP `Server` over a server-side channel. `mcpServerAdapter` (server entry) wraps this. */
export function mcpServerTransport(channel) {
  return new RpcMcpTransport(channel);
}
