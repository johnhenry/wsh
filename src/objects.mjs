/**
 * `@johnhenry/wsh/objects` -- remote objects (#190), `values` mode, as the rpc protocol `wsh-objects`: any object graph can be a named root
 * (a page's `window`, a worker's `self`, a Node object), reached by path, and only plain cloneable values ever cross. Both sides:
 *
 * ```js
 * // the host (any host that takes `rpc`):
 * createMemoryHost({ auth, hostKey: true, dataStreams: false, sealSession: 'require',
 *   rpc: { 'wsh-objects': exposeObjects({ roots: { window }, allow: { get: ['window.document.title', 'window.app.**'], call: ['window.app.**'] } }) } });
 *
 * // the far side:
 * import { get, set, call, snapshot, describe } from '@johnhenry/wsh/objects';
 * const page = await client.openObjects();                // { window }: lazy references (this entry point adds `openObjects` to WshClient)
 * await page.window.document.title;                       // one `resolve` request, whatever the length of the chain
 * await page.window.app.cart.add({ sku: 'A1', qty: 2 });  // a call, with plain-data arguments
 * await set(page.window.document, 'title', 'Paid');       // not `=`: an assignment cannot be awaited or report a refusal
 * ```
 *
 * The transport-neutral core is `objects-core.mjs`; this file is the wsh adapter (an `RpcChannel` is the seam the core needs) and the client
 * method. Read the README's "Remote objects" section for what an allow-list of paths can and cannot promise.
 */

import { RpcError } from './rpc.mjs';
import { callerIdentity } from './key-names.mjs';
import { WshClient } from './client.mjs';
import {
  OBJECTS_PROTOCOL, ObjectsError, createObjectsServer, createObjectsClient,
} from './objects-core.mjs';

export {
  OBJECTS_PROTOCOL, OBJECTS_ERROR, OBJECTS_DEFAULT_LIMITS, NEEDS_LISTING, ObjectsError, NonValue,
  createObjectsServer, createObjectsClient, createDuplexPeer, matchPath, toWire, fromWire,
  get, set, call, construct, snapshot, describe, on, off, use, release, RemoteHandle, closeObjects, rootDescription,
} from './objects-core.mjs';

/** Timers for `callTimeoutMs` where the embedder gave none: this module is the Node-or-browser adapter, not the page entry point. */
const defaultTimers = { setTimeout: (fn, ms) => setTimeout(fn, ms), clearTimeout: (id) => clearTimeout(id) };

/** The platform's CSPRNG for handle ids, where the embedder gave none (the page host gives its window's). */
const defaultRandom = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

/** An `RpcChannel` as the core's `Peer`: refusals become `RpcError`s with their reason, so the far side hears the sentence and the rule. */
function channelPeer(channel, host = {}) {
  // What the key of this channel may do on a root: `objects:ROOT[:OP]` capabilities, through the host's `permits`, asked afresh for each operation.
  const permit = typeof host.permits === 'function' ? (root, op) => host.permits({ kind: 'objects', root, op }) : undefined;
  return {
    onRequest: (method, handler) => channel.onRequest(method, async (params, ctx) => {
      try { return await handler(params, permit ? { ...ctx, permit } : ctx); } catch (e) {
        if (e instanceof ObjectsError) throw new RpcError(e.code, e.message, e.data);
        throw e;
      }
    }),
    get maxMessageBytes() { return channel.maxMessageBytes; },
    // Events go out as notifications, whose write waits for the channel's credit; the end of the channel takes the listeners out of the page.
    notify: (method, params) => channel.notify(method, params),
    get onClose() { return channel.onClose; },
    set onClose(fn) { channel.onClose = fn; },
  };
}

/**
 * The rpc handler for `wsh-objects`: `rpc: { 'wsh-objects': exposeObjects({ roots, mode: 'values', allow, authorize, limits }) }`.
 *
 * @param {object} options - as for `createObjectsServer`
 * @param {Record<string, object>} options.roots - the named roots: all that is reachable
 * @param {'values'} [options.mode='values'] - `'handles'` is refused: it is not built
 * @param {{ get?: string[], call?: string[], set?: string[] }} [options.allow] - path patterns by operation, root-qualified (`'window.app.**'`); nothing allowed by default
 * @param {(who: { username: string | null, fingerprint: string | null }, op: { kind: string, root: string, path: string[], text: string }) => boolean | Promise<boolean>} [options.authorize]
 * @param {object} [options.limits] - `maxOps`, `maxArgs`, `maxDepth`, `maxValueBytes`, `maxKeys`, `maxRequestsPerSecond`, `callTimeoutMs`
 */
export function exposeObjects(options = {}) {
  const server = createObjectsServer({ timers: defaultTimers, random: defaultRandom, ...options });
  const sessions = new Set();
  const handler = (channel, ctx = {}) => {
    // A wsh caller is its key, `{ username, fingerprint }`. A handler called by an adapter that is not wsh (a mesh channel) is given the
    // caller as `ctx.who` (`{ username, fingerprint?, podId? }`), and it is that identity that `authorize` and `closeSessions` see.
    const who = callerIdentity(ctx.who ?? { username: ctx.user ?? null, fingerprint: ctx.fingerprint ?? null });
    server.attach(channelPeer(channel, ctx), { who });
    const session = { channel, who };
    sessions.add(session);
    const prior = channel.onClose;
    channel.onClose = (reason) => { sessions.delete(session); try { prior?.(reason); } catch { /* ignore */ } };
  };
  /** Tell every session (or those of one key) why, then end it: used when the page goes away or the person presses Stop. */
  handler.closeSessions = async (reason, fingerprint) => {
    const targets = [...sessions].filter((s) => fingerprint === undefined || s.who.fingerprint === fingerprint);
    await Promise.all(targets.map(async (s) => {
      try { await s.channel.notify('closing', { reason }); } catch { /* going away */ }
      await s.channel.close('objects-host-closing').catch(() => {});
    }));
    return targets.length;
  };
  // This handler narrows by the key's capabilities itself (`objects:ROOT[:OP]`), so a key that names roots may open the channel without `rpc:wsh-objects`.
  handler.capabilityScoped = true;
  handler.rootNames = server.rootNames;
  handler.limits = server.limits;
  // The MCP face (#219): the tools the host named in `mcp: { tools }` (none unless written), for `webmcpTools({ tools: handler.mcpTools, allow: handler.mcpToolNames })`.
  handler.mcpTools = server.mcpTools;
  handler.mcpToolNames = server.mcpToolNames;
  return handler;
}

/** Open the `wsh-objects` channel of a connected client: the roots, as lazy references. */
export async function openObjects(client, options) {
  if (typeof client?.openRpc !== 'function') throw new TypeError('openObjects: expected a connected WshClient');
  return createObjectsClient(await client.openRpc(OBJECTS_PROTOCOL), options);
}

// `client.openObjects()`. Added here (and not in client.mjs) so that the objects code is in a page's bundle only when it imports this entry point.
if (typeof WshClient.prototype.openObjects !== 'function') {
  Object.defineProperty(WshClient.prototype, 'openObjects', {
    value: function openObjectsOfThisClient(options) { return openObjects(this, options); },
    configurable: true, writable: true, enumerable: false,
  });
}
