/**
 * MCP 2026-07-28 ("modern") on the tool server of `webmcpTools`, tools only (#302). Browser-safe: nothing here touches a realm.
 *
 * The 2026-07-28 revision has no `initialize` handshake and no session. Every request carries its protocol version and the
 * client's capabilities in `_meta`, `server/discover` replaces the handshake as the way to learn what a server speaks, change
 * notifications move to a client-opened `subscriptions/listen` stream, every result says `resultType`, and a list result says how
 * long it may be cached. `webmcpTools` answers all of it itself, beside the legacy `initialize` + `notifications/initialized`
 * session, which is unchanged. The era is chosen per request: a request whose `params._meta` has
 * `io.modelcontextprotocol/protocolVersion` is modern, any other is what it always was.
 *
 * WHAT THE `_meta` OF A REQUEST DECIDES: whether the request is modern, and nothing else. Its `clientInfo` and `clientCapabilities`
 * are self-reported by the caller and the spec says not to base decisions on them; here they are not read (the capabilities are
 * only required to be an object, as the spec requires), so nothing in them reaches `permits`, the limits, the prompt or `onCall`.
 *
 * WHAT IS NOT OFFERED: resources, prompts, sampling, roots, elicitation, tasks, skills, events and uploads. A client that declares
 * a capability for any of them gets exactly what a client that did not declare it gets.
 *
 * ERROR CODES: -32022 is the spec's `UnsupportedProtocolVersion`, used with its specified meaning. Everything else this module
 * refuses with is a JSON-RPC standard code (-32602) or a limit of the seam (-32002, the code wsh has always used for its limits:
 * -32000..-32019 is the range the spec leaves to implementations). No wsh meaning uses a code in -32020..-32099.
 */

import { RpcError, RPC_ERROR } from './rpc.mjs';

export const MODERN_PROTOCOL_VERSION = '2026-07-28';
/** The legacy revisions `initialize` answers for. */
export const LEGACY_PROTOCOL_VERSIONS = Object.freeze(['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05']);
/** What `server/discover` lists and what a request's `_meta` may name. */
export const SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([MODERN_PROTOCOL_VERSION, ...LEGACY_PROTOCOL_VERSIONS]);

export const META_PROTOCOL_VERSION = 'io.modelcontextprotocol/protocolVersion';
export const META_CLIENT_CAPABILITIES = 'io.modelcontextprotocol/clientCapabilities';
export const META_SERVER_INFO = 'io.modelcontextprotocol/serverInfo';
export const META_SUBSCRIPTION_ID = 'io.modelcontextprotocol/subscriptionId';

/** The spec's `UnsupportedProtocolVersionError`. The one code of the spec-reserved range -32020..-32099 this package emits. */
export const UNSUPPORTED_PROTOCOL_VERSION = -32022;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Which era a request is, from its params. Throws what the spec says to answer: `UnsupportedProtocolVersion` (-32022, `data.supported`
 * and `data.requested`) for a version this side does not speak, `-32602` for a modern request that lacks `clientCapabilities`.
 * A version of a legacy revision in `_meta` is accepted and served in the legacy shape (those revisions have no per-request meta).
 * @returns {{ modern: boolean, versioned: boolean }}
 */
export function requestEra(params) {
  const meta = isObj(params) && isObj(params._meta) ? params._meta : null;
  const asked = meta ? meta[META_PROTOCOL_VERSION] : undefined;
  if (asked === undefined) return { modern: false, versioned: false };
  if (typeof asked !== 'string' || !SUPPORTED_PROTOCOL_VERSIONS.includes(asked)) {
    throw new RpcError(UNSUPPORTED_PROTOCOL_VERSION, 'Unsupported protocol version', {
      supported: [...SUPPORTED_PROTOCOL_VERSIONS],
      requested: typeof asked === 'string' ? asked.slice(0, 64) : typeof asked,
    });
  }
  if (asked !== MODERN_PROTOCOL_VERSION) return { modern: false, versioned: true };
  if (!isObj(meta[META_CLIENT_CAPABILITIES])) {
    throw new RpcError(RPC_ERROR.INVALID_PARAMS, `a ${MODERN_PROTOCOL_VERSION} request needs _meta["${META_CLIENT_CAPABILITIES}"] (an object)`);
  }
  return { modern: true, versioned: true };
}

/**
 * The result of a modern request: `resultType`, who answered, and for `tools/list` and `server/discover` the cache hints the spec
 * requires. The list differs per caller (what its key may list), so it is `private`, and it is not fresh for any time: `ttlMs: 0`
 * (a tool may be registered at any moment, and `subscriptions/listen` is how a caller hears of it).
 */
export function decorateResult(method, result, serverInfo) {
  const body = isObj(result) ? result : {};
  const out = { resultType: 'complete', ...body };
  if (method === 'tools/list' || method === 'server/discover') {
    if (out.ttlMs === undefined) out.ttlMs = 0;
    if (out.cacheScope === undefined) out.cacheScope = 'private';
  }
  out._meta = { ...(isObj(body._meta) ? body._meta : {}), [META_SERVER_INFO]: serverInfo };
  return out;
}
