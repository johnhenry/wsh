// wsh #85 / #71: an MCP Server exposed over an `rpc` channel, consumed by an MCP Client.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createWshServer, mcpServerAdapter } from '@johnhenry/wsh/server';
import { WshClient, mcpClientTransport, generateKeyPair, exportPublicKeySSH, RpcError } from '@johnhenry/wsh';

function makeServer(log = {}) {
  const server = new Server({ name: 'echo-server', version: '1.0.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: 'echo', description: 'Echo text back', inputSchema: { type: 'object', properties: { text: { type: 'string' }, delayMs: { type: 'number' } }, required: ['text'] } }],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
    const { text, delayMs = 0 } = req.params.arguments ?? {};
    log.started = (log.started ?? 0) + 1;
    if (delayMs) {
      await new Promise((resolve) => {
        const t = setTimeout(resolve, delayMs);
        extra.signal.addEventListener('abort', () => { log.aborted = true; clearTimeout(t); resolve(); });
      });
    }
    return { content: [{ type: 'text', text: `echo: ${text}` }] };
  });
  return server;
}

let keyPair; let authorizedKeys;
before(async () => { keyPair = await generateKeyPair(true); authorizedKeys = await exportPublicKeySSH(keyPair.publicKey); });

async function boot(mcp) {
  const server = createWshServer({ auth: { authorizedKeys }, rpc: { mcp } });
  const { port } = await server.listen();
  const wsh = new WshClient();
  await wsh.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
  return { server, wsh, stop: async () => { await wsh.disconnect(); await server.close(); } };
}

describe('mcp over an rpc channel', () => {
  it('an MCP Client runs initialize -> tools/list -> tools/call through the SDK transport adapters', async () => {
    const log = {};
    const { wsh, stop } = await boot(mcpServerAdapter(makeServer(log)));
    try {
      assert.ok(wsh.hasFeature('rpc-protocol:mcp'));
      const channel = await wsh.openRpc('mcp');
      const client = new Client({ name: 'test-client', version: '0.0.1' }, { capabilities: {} });
      await client.connect(mcpClientTransport(channel));
      assert.equal(client.getServerVersion().name, 'echo-server');
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map((t) => t.name), ['echo']);
      const res = await client.callTool({ name: 'echo', arguments: { text: 'hi' } });
      assert.equal(res.content[0].text, 'echo: hi');
      await client.close();
      assert.equal(channel.closed, true);
    } finally { await stop(); }
  });

  it('raw JSON-RPC works too (the surface is MCP verbatim): initialize, tools/list, tools/call', async () => {
    const { wsh, stop } = await boot(mcpServerAdapter(makeServer()));
    try {
      const rpc = await wsh.openRpc('mcp');
      const init = await rpc.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'raw', version: '1' } });
      assert.equal(init.serverInfo.name, 'echo-server');
      rpc.notify('notifications/initialized');
      assert.equal((await rpc.request('tools/list', {})).tools[0].name, 'echo');
      assert.equal((await rpc.request('tools/call', { name: 'echo', arguments: { text: 'raw' } })).content[0].text, 'echo: raw');
      await assert.rejects(rpc.request('bogus/method', {}), (e) => e instanceof RpcError && e.code === -32601);
    } finally { await stop(); }
  });

  it('an in-flight $/cancel aborts the tool handler (its signal fires) and the caller sees -32001', async () => {
    const log = {};
    const { wsh, stop } = await boot(mcpServerAdapter(makeServer(log)));
    try {
      const rpc = await wsh.openRpc('mcp');
      await rpc.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'raw', version: '1' } });
      rpc.notify('notifications/initialized');
      const call = rpc.request('tools/call', { name: 'echo', arguments: { text: 'slow', delayMs: 10_000 } });
      call.catch(() => {});
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(log.started, 1);
      const t0 = Date.now();
      call.cancel();
      await assert.rejects(call, (e) => e.code === -32001);
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(log.aborted, true, 'the SDK handler saw its abort signal');
      assert.ok(Date.now() - t0 < 2000);
      // the channel is still healthy
      assert.equal((await rpc.request('tools/call', { name: 'echo', arguments: { text: 'after' } })).content[0].text, 'echo: after');
    } finally { await stop(); }
  });

  it('an MCP Client abort (AbortSignal) is translated to $/cancel on the wire', async () => {
    const log = {};
    const { wsh, stop } = await boot(mcpServerAdapter(makeServer(log)));
    try {
      const channel = await wsh.openRpc('mcp');
      const client = new Client({ name: 'c', version: '1' }, { capabilities: {} });
      await client.connect(mcpClientTransport(channel));
      const ac = new AbortController();
      const p = client.callTool({ name: 'echo', arguments: { text: 'x', delayMs: 10_000 } }, undefined, { signal: ac.signal });
      p.catch(() => {});
      await new Promise((r) => setTimeout(r, 100));
      ac.abort();
      await assert.rejects(p);
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(log.aborted, true);
      await client.close();
    } finally { await stop(); }
  });

  it('a factory gives every channel its own Server; an instance serves one channel at a time', async () => {
    const { wsh, stop } = await boot(mcpServerAdapter(() => makeServer()));
    try {
      const chans = await Promise.all([wsh.openRpc('mcp'), wsh.openRpc('mcp')]);
      const clients = await Promise.all(chans.map(async (ch) => {
        const c = new Client({ name: 'c', version: '1' }, { capabilities: {} });
        await c.connect(mcpClientTransport(ch));
        return c;
      }));
      const out = await Promise.all(clients.map((c, i) => c.callTool({ name: 'echo', arguments: { text: String(i) } })));
      assert.deepEqual(out.map((r) => r.content[0].text), ['echo: 0', 'echo: 1']);
      await Promise.all(clients.map((c) => c.close()));
    } finally { await stop(); }

    const single = await boot(mcpServerAdapter(makeServer()));
    try {
      const first = await single.wsh.openRpc('mcp');
      await first.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'a', version: '1' } });
      const second = await single.wsh.openRpc('mcp');
      await assert.rejects(second.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'b', version: '1' } }), (e) => e.code === -32001);
      await first.close();
      await new Promise((r) => setTimeout(r, 100));
      const third = await single.wsh.openRpc('mcp');
      assert.equal((await third.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'c', version: '1' } })).serverInfo.name, 'echo-server');
    } finally { await single.stop(); }
  });

  it('server-initiated requests (sampling-style) flow back to the client', async () => {
    const server = new Server({ name: 's', version: '1' }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: 'roots', inputSchema: { type: 'object' } }] }));
    server.setRequestHandler(CallToolRequestSchema, async () => {
      const roots = await server.listRoots();
      return { content: [{ type: 'text', text: JSON.stringify(roots.roots) }] };
    });
    const { wsh, stop } = await boot(mcpServerAdapter(server));
    try {
      const channel = await wsh.openRpc('mcp');
      const { ListRootsRequestSchema } = await import('@modelcontextprotocol/sdk/types.js');
      const client = new Client({ name: 'c', version: '1' }, { capabilities: { roots: {} } });
      client.setRequestHandler(ListRootsRequestSchema, async () => ({ roots: [{ uri: 'file:///work', name: 'work' }] }));
      await client.connect(mcpClientTransport(channel));
      const res = await client.callTool({ name: 'roots', arguments: {} });
      assert.deepEqual(JSON.parse(res.content[0].text), [{ uri: 'file:///work', name: 'work' }]);
      await client.close();
    } finally { await stop(); }
  });
});
