/**
 * Remote MCP tools are discovered and called through the bridge.
 *
 * WshMcpBridge lets a wsh client use MCP tools hosted on the remote server:
 * MCP_DISCOVER/MCP_TOOLS to learn what exists, MCP_CALL/MCP_RESULT to invoke
 * (spec/wsh-v1.md, message codes 0x40-0x43). The bridge only needs an object
 * with `sendControl` + `addControlListener`/`removeControlListener`, so this
 * example runs fully headless against an in-process server that answers on
 * the control channel — no network, no real MCP host.
 */

import assert from 'node:assert/strict';
import { WshMcpBridge, MSG, mcpTools, mcpResult } from '@johnhenry/wsh';

// ── An in-process control channel with an MCP-capable "server" ────────

const serverTools = {
  read_file: {
    description: 'Read a file from the remote host',
    parameters: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
    invoke: ({ path }) => ({ success: true, output: `contents of ${path}` }),
  },
  run_command: {
    description: 'Run a shell command on the remote host',
    parameters: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] },
    invoke: ({ command }) => ({ success: true, output: { stdout: `ran: ${command}`, code: 0 } }),
  },
};

const client = {
  listeners: new Set(),
  addControlListener(fn) { this.listeners.add(fn); },
  removeControlListener(fn) { this.listeners.delete(fn); },
  deliver(msg) { for (const fn of [...this.listeners]) fn(msg); },

  // "Send to server": the server reacts and replies on the control channel.
  // Replies arrive on a fresh task, as they would from a real transport.
  async sendControl(msg) {
    setTimeout(() => {
      if (msg.type === MSG.MCP_DISCOVER) {
        this.deliver(mcpTools({
          tools: Object.entries(serverTools).map(([name, t]) => ({
            name, description: t.description, parameters: t.parameters,
          })),
        }));
      } else if (msg.type === MSG.MCP_CALL) {
        this.deliver(mcpResult({ result: serverTools[msg.tool].invoke(msg.arguments) }));
      }
    }, 0);
  },
};

// ── Discover ──────────────────────────────────────────────────────────

const bridge = new WshMcpBridge(client);
const tools = await bridge.discover();

console.log(`discovered ${tools.length} remote tools:`);
for (const t of tools) console.log(`  - ${t.name}: ${t.description}`);
assert.equal(bridge.toolCount, 2);
assert.ok(bridge.hasTool('read_file'));

// Tool specs come back in a shape ready to register with an agent framework.
const specs = bridge.getToolSpecs();
assert.deepEqual(Object.keys(specs[0]), ['name', 'description', 'parameters']);

// ── Call ──────────────────────────────────────────────────────────────

const fileResult = await bridge.call('read_file', { path: '/etc/hostname' });
assert.equal(fileResult.success, true);
console.log(`read_file → ${JSON.stringify(fileResult.output)}`);

const cmdResult = await bridge.call('run_command', { command: 'uptime' });
assert.equal(cmdResult.output.code, 0);
console.log(`run_command → ${JSON.stringify(cmdResult.output)}`);

// ── Guardrail: unknown tools are rejected client-side after discovery ─

await assert.rejects(
  () => bridge.call('format_disk', {}),
  /Unknown tool "format_disk"/,
);
console.log('call to undiscovered tool rejected before touching the wire');

// The bridge stopped listening once each request settled.
assert.equal(client.listeners.size, 0);
console.log('no control listeners leaked after requests settled');

console.log('ok: remote MCP tools discovered and called headlessly through the bridge');
