/** Type-only fixture: `@johnhenry/wsh/page` (#190): the page host, the WebMCP bridge, and what an rpc handler is told of its key. */
import { createPageHost, captureWebMcp, webmcpTools, createDomPrompt, WEBMCP_DEFAULT_LIMITS, type WshPageHost, type WebMcpToolDefinition, type WebMcpHandler } from '@johnhenry/wsh/page';
import { createMemoryHost } from '@johnhenry/wsh/memory';

declare const win: Window;

const search: WebMcpToolDefinition = {
  name: 'search', description: 'Search products', inputSchema: { type: 'object' }, annotations: { readOnlyHint: true },
  execute: async (input, { signal }) => { void [input.q, signal.aborted]; return { hits: [] }; },
};

const capture = captureWebMcp(win);
void [capture.list().map((t) => t.name), capture.subscribe(() => {}), capture.installed];

async function start(): Promise<WshPageHost> {
  const host = await createPageHost({
    window: win, relay: 'wss://relay.example/pipe', name: 'shop-tab', authorizedKeys: ['ssh-ed25519 AAAA'],
    mcp: { allow: ['search'], approve: 'consequential', tools: [search], limits: { maxInflight: 2 }, prompt: async (call, who, { signal }) => { void [call.name, who.fingerprint, signal.aborted]; return true; } },
    indicator: { connected: (who, { stop }) => { void [who.fingerprint, stop()]; }, disconnected: () => {} },
    unattended: false,
    onSession: (who) => who.username !== 'mallory',
    onRefused: (r) => { void r.reason; },
    onClose: ({ reason }) => { void reason; },
  });
  void [host.operatorUrl, host.fingerprint, host.sessions[0]?.fingerprint, host.closedReason, host.revoke('ab'), host.close()];
  return host;
}

const handler: WebMcpHandler = webmcpTools({ window: win, allow: ['search'], tools: [search] });
// The same handler in any host; a key's capabilities are told to every rpc handler.
const memory = createMemoryHost({
  auth: { authorizedKeys: 'ssh-ed25519 AAAA' }, dataStreams: false,
  rpc: { mcp: handler, other: (channel, ctx) => { void [channel.closed, ctx.capabilities, ctx.permits({ kind: 'mcp-tool', tool: 'search' }, { now: 1 })]; } },
});
void [start, memory, createDomPrompt(win, { timeoutMs: 1000 }), WEBMCP_DEFAULT_LIMITS.maxTools, handler.closeSessions('x'), handler.capabilityScoped];
