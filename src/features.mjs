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
