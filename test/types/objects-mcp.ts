/** Type-only fixture: the MCP face for allow-listed object paths (#219). */
import { exposeObjects, createObjectsServer, type ObjectsMcpTool } from '@johnhenry/wsh/objects';
import { webmcpTools, createPageHost, serveMcpOverDuplex } from '@johnhenry/wsh/page';

declare const win: Window;

const tools: ObjectsMcpTool[] = [
  { name: 'add_to_cart', description: 'Add a product', call: 'window.app.cart.add', inputSchema: { type: 'object', properties: { sku: { type: 'string' } }, required: ['sku'], additionalProperties: false } },
  { name: 'sum', description: 'Add two numbers', call: 'window.app.sum', args: ['a', 'b'], readOnly: true, inputSchema: { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' } } } },
  { name: 'page_title', description: 'The title', get: 'window.document.title' },
];
const handler = exposeObjects({ roots: { window: win }, allow: { get: ['window.document.title'], call: ['window.app.**'] }, mcp: { tools } });
const names: string[] = handler.mcpToolNames;
const mcp = webmcpTools({ window: win, tools: handler.mcpTools, allow: names, approve: 'consequential' });
void serveMcpOverDuplex(mcp, { send: () => {} });

const server = createObjectsServer({ roots: { window: win }, allow: { call: ['window.app.sum'] } });
void server.invoke({ kind: 'call', path: ['window', 'app', 'sum'], args: [1, 2] }, { permit: () => true }).then((r) => ('v' in r ? r.v : r.u));

void createPageHost({
  window: win, relay: 'wss://relay.example/pipe', name: 'tab', authorizedKeys: ['ssh-ed25519 AAAA'],
  expose: { window: { allow: { call: ['app.cart.add'] }, mcp: { tools: [{ name: 'add_to_cart', description: 'Add a product', call: 'app.cart.add' }] } } },
});

// @ts-expect-error a tool names a call or a get, as text
const bad: ObjectsMcpTool = { name: 'x', description: 'x', call: 5 };
void bad;
