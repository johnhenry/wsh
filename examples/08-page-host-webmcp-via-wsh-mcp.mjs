/**
 * A page host serves its WebMCP tools; `wsh-mcp`'s bridge carries them to an MCP client (wsh #190, #127).
 *
 * A browser page cannot listen, so `createPageHost` dials a pipe relay and serves the tools the page chose to
 * register, to a key that logs in over a SEALED session. The operator side is the real stdio bridge behind the
 * `wsh-mcp` command (`runMcpStdioBridge`): it reads newline-delimited JSON-RPC on `input` and writes it on `output`,
 * exactly what an MCP client such as Claude Desktop does over a child process's stdio. Everything runs in this
 * process: a window-shaped object, the in-process pipe relay from `@johnhenry/wsh/testing`, no sockets.
 */

import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw, exportPublicKeySSH } from '@johnhenry/wsh';
import { createPageHost } from '@johnhenry/wsh/page';
import { runMcpStdioBridge } from '@johnhenry/wsh/mcp-stdio';
import { createInProcessPipeRelay } from '@johnhenry/wsh/testing';

// ── The page: a relay, a window, and three registered tools ───────────

const relay = await createInProcessPipeRelay();
const operator = await generateKeyPair(true);
const orders = [];
const schema = (props) => ({ type: 'object', properties: props });
const window = {                                   // the only realm the host touches; no DOM, so unattended
  location: { origin: 'https://shop.example' }, WebSocket: relay.WebSocket, crypto: webcrypto, closed: false,
  addEventListener() {}, removeEventListener() {},
  setTimeout, clearTimeout, setInterval, clearInterval,
};
const host = await createPageHost({
  window, relay: 'ws://relay.test', name: 'shop-tab', unattended: true, indicator: false,
  authorizedKeys: [await exportPublicKeySSH(operator.publicKey)],
  mcp: {
    tools: [
      { name: 'search_products', description: 'Search the catalogue', inputSchema: schema({ q: { type: 'string' } }),
        annotations: { readOnlyHint: true }, execute: ({ q }) => ({ hits: [`${q}-mug`, `${q}-tee`] }) },
      { name: 'add_to_cart', description: 'Add a product to the cart', inputSchema: schema({ sku: { type: 'string' } }),
        execute: ({ sku }) => { orders.push(sku); return { added: sku }; } },
      { name: 'wipe_account', description: 'Not offered to operators', inputSchema: schema({}), execute: () => 'gone' },
    ],
    allow: ['search_products', 'add_to_cart'],     // by name; nothing is allowed by default
    approve: 'consequential',                      // a tool not marked readOnly needs a person's yes
  },
});
console.log(`1. page host "${host.name}" is waiting behind the relay (host key ${host.fingerprint.slice(0, 16)}...)`);

// ── The operator: the real wsh-mcp bridge, fed like an MCP client would ──

const raw = await exportPublicKeyRaw(operator.publicKey);
const signer = { publicKey: raw, sign: async (data) => new Uint8Array(await webcrypto.subtle.sign('Ed25519', operator.privateKey, data)) };
const clientFactory = () => new WshClient({ transportFactories: {
  ws: () => new WebSocketTransport({ WebSocket: relay.WebSocket }), wt: () => { throw new Error('no webtransport'); },
} });
const inbox = []; let wake; const lines = [];
const input = { async *[Symbol.asyncIterator]() { for (;;) { while (inbox.length) yield `${JSON.stringify(inbox.shift())}\n`; await new Promise((r) => { wake = r; }); } } };
const waiters = new Map();
const output = { write(chunk) { for (const l of String(chunk).split('\n').filter(Boolean)) { const m = JSON.parse(l); lines.push(m); waiters.get(m.id)?.(m); } } };
const bridge = runMcpStdioBridge({
  url: host.operatorUrl, username: 'alice', signer, sealSession: true, expectHostKey: host.fingerprint,
  reconnect: false, input, output, errorOutput: { write() {} }, clientFactory,
});
let nextId = 1;
const rpc = (method, params) => new Promise((resolve) => {
  const id = nextId++; waiters.set(id, resolve); inbox.push({ jsonrpc: '2.0', id, method, params }); wake?.();
});

const init = await rpc('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'agent', version: '1' } });
console.log(`2. initialize -> server "${init.result.serverInfo.name}"`);
inbox.push({ jsonrpc: '2.0', method: 'notifications/initialized' }); wake?.();

// ── A tool list, a call, and a refusal ────────────────────────────────

const list = await rpc('tools/list', {});
const names = list.result.tools.map((t) => t.name);
console.log(`3. tools/list -> ${names.join(', ')}`);
assert.deepEqual(names.sort(), ['add_to_cart', 'search_products'], 'wipe_account was registered but never allowed, so it is not listed');

const found = await rpc('tools/call', { name: 'search_products', arguments: { q: 'blue' } });
console.log(`4. ALLOWED: search_products(blue) -> ${found.result.content[0].text}`);
assert.match(found.result.content[0].text, /blue-mug/);

const bought = await rpc('tools/call', { name: 'add_to_cart', arguments: { sku: 'MUG-1' } });
console.log(`5. REFUSED: add_to_cart (consequential, nobody to approve) -> "${bought.error?.message ?? bought.result?.content?.[0]?.text}"`);
assert.ok(bought.result?.isError || bought.error, 'a consequential tool is denied when no person can say yes');
assert.deepEqual(orders, [], 'the page\'s tool never ran');

const hidden = await rpc('tools/call', { name: 'wipe_account', arguments: {} });
console.log(`6. REFUSED: wipe_account (not in allow) -> "${hidden.error?.message ?? hidden.result?.content?.[0]?.text}"`);
assert.ok(hidden.result?.isError || hidden.error);

// ── Stop ──────────────────────────────────────────────────────────────

await host.close();
await relay.close();
console.log('ok: the page served only what it allowed, through the real wsh-mcp bridge');
process.exit(0);   // the bridge keeps waiting on its (never-ending) input; a real client closes stdin instead
