/**
 * Feature strings both the client and the host handlers state or look for. Kept in a module of their own so a host
 * (`@johnhenry/wsh/host`, `/memory`, `/reverse`) can name them without importing the whole client.
 */

/**
 * ServerHello feature advertising that McpResult echoes McpCall's call_id.
 *
 * Negotiated rather than assumed: McpCallPayload is `deny_unknown_fields` on
 * the Rust side, so sending call_id to a server predating it does not
 * degrade -- it makes the server reject the call.
 */
export const MCP_CALL_ID_FEATURE = 'mcp-call-id';

/**
 * ServerHello feature advertising that the host understands `McpCancel` (stop an in-flight `McpCall`).
 * Negotiated rather than assumed: McpCancelPayload is `deny_unknown_fields` on the Rust side, so an older
 * server would reject it. Implies `mcp-call-id` (the cancel names a call by its id).
 */
export const MCP_CANCEL_FEATURE = 'mcp-cancel';

/**
 * ServerHello feature: the host discovers a client-opened exec data stream
 * on its own (the transport announces it), so the client must NOT write the
 * one-byte "primer" -- against such a host it would reach the process's stdin.
 */
export const STREAM_ANNOUNCE_FEATURE = 'stream-announce';
export const EXEC_PIPES_FEATURE = 'exec-pipes';

/**
 * ServerHello feature (#121): this host serves several execution targets. `Open`, `FileOp` and `OpenEndpoint` take an optional
 * `target`, and `ListTargets` is answered with `TargetList`. Negotiated rather than assumed: the Rust types deny unknown
 * fields, so an older host rejects an `Open` that carries `target`.
 */
export const TARGETS_FEATURE = 'targets';

/**
 * Relay and reverse-host feature (#289): the gateway's requests (`OpenTcp`, `OpenUdp`, `ResolveDns`, `ListenRequest` and their
 * answers: the spec's `relay.gateway_forwardable`) cross a relay bridge. A relay lists it in `ServerHello.features`; a reverse host
 * whose owner turned its gateway on lists it in `ReverseAccept.features`. The relay carries those messages only for a bridge whose
 * peer stated it, and an operator sends them only when the relay AND the host did. It implies `gateway-credit`: every connection
 * opened this way is metered, whether or not the operator listed that feature.
 */
export const RELAY_GATEWAY_FEATURE = 'relay-gateway';

/**
 * Host feature (#155): this host seals the whole session end to end when asked (a signed `KeyExchange` for the
 * connection's session id, then every message but the keepalive as an `EncryptedFrame` on channel 0).
 */
export const SESSION_SEAL_FEATURE = 'e2e-session';
/** Host feature (#155): this host serves nothing on a session that is not sealed. */
export const SESSION_SEAL_REQUIRED_FEATURE = 'e2e-session-required';
