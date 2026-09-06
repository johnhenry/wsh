// test/mcp-correlation.test.mjs
//
// McpCall/McpResult carried no correlation field, and both client paths
// waited on the message TYPE alone -- client.mjs's callTool() via
// #waitForMessage([MSG.MCP_RESULT]), WshMcpBridge.call() via
// `msg.type === MSG.MCP_RESULT`. With two calls in flight the first result
// to arrive satisfied whichever waiter registered first, so a fast tool's
// answer was handed to the caller waiting on a slow one. Both callers got a
// result, neither threw, and the returned value identified no tool, so
// nobody could detect the swap. (#32)
//
// The existing MCP coverage issues one call at a time against a mock that
// answers it; one in flight is always correlated correctly. Every test here
// therefore has at least two calls in flight at once, against a real
// WshClient driven through the real handshake.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { WshTransport } from '../src/transport.mjs';
import { MSG, mcpResult, serverHello } from '../src/messages.gen.mjs';
import { WshMcpBridge } from '../src/mcp-bridge.mjs';

let auth;
let clientMod;
try {
  auth = await import('../src/auth.mjs');
  clientMod = await import('../src/client.mjs');
} catch {
  // Web Crypto Ed25519 unavailable in this runtime.
}
const hasEd25519 = auth && typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

/** Per-tool reply delays, so a later call can overtake an earlier one. */
const DELAYS = { slow_tool: 60, fast_tool: 5 };

/**
 * An in-process server that answers each tool after its own delay.
 *
 * `features` decides whether it advertises mcp-call-id and echoes call_id --
 * i.e. whether it is a server that predates the correlation field or one
 * that implements it.
 */
class McpServerTransport extends WshTransport {
  sent = [];

  constructor({ features = [], echoCallId = true } = {}) {
    super();
    this.features = features;
    this.echoCallId = echoCallId;
  }

  async _doConnect() {}
  async _doClose() {}
  async _doOpenStream() { throw new Error('not used'); }

  async _doSendControl(msg) {
    this.sent.push(msg);
    const reply = (m, delay = 0) => setTimeout(() => this._emitControl(m), delay);

    if (msg.type === MSG.HELLO) {
      reply(serverHello({ sessionId: 'sess-mcp', features: this.features, fingerprints: [] }));
      reply({ type: MSG.CHALLENGE, nonce: new Uint8Array(32).fill(7), session_id: 'sess-mcp' });
    } else if (msg.type === MSG.AUTH) {
      reply({ type: MSG.AUTH_OK });
    } else if (msg.type === MSG.MCP_CALL) {
      const delay = DELAYS[msg.tool] ?? 0;
      reply(
        mcpResult({
          // The payload names its own tool so a swap is visible at all; the
          // real defect is that nothing in a normal payload does.
          result: { success: true, output: `RESULT OF ${msg.tool}` },
          callId: this.echoCallId ? msg.call_id : undefined,
        }),
        delay,
      );
    }
  }
}

async function connect(transport) {
  const keyPair = await auth.generateKeyPair(true);
  const client = new clientMod.WshClient({ transportFactories: { ws: () => transport } });
  await client.connect('ws://test.invalid', { username: 'alice', keyPair, transport: 'ws' });
  return client;
}

const CORRELATING = { features: ['mcp', 'mcp-call-id'] };
const LEGACY = { features: ['mcp'] };

describe('concurrent MCP calls', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  it('callTool() returns each call its own result when the server correlates', async () => {
    const transport = new McpServerTransport(CORRELATING);
    const client = await connect(transport);

    const [slow, fast] = await Promise.all([
      client.callTool('slow_tool', {}),
      client.callTool('fast_tool', {}),
    ]);

    assert.equal(slow.output, 'RESULT OF slow_tool');
    assert.equal(fast.output, 'RESULT OF fast_tool');

    // Both were genuinely in flight together, which is what makes the
    // assertions above meaningful.
    const calls = transport.sent.filter((m) => m.type === MSG.MCP_CALL);
    assert.deepEqual(calls.map((c) => c.tool), ['slow_tool', 'fast_tool']);
    assert.equal(new Set(calls.map((c) => c.call_id)).size, 2, 'each call needs its own id');
    assert.ok(calls.every((c) => typeof c.call_id === 'string'));
  });

  it('callTool() is still correct against a server that does not correlate', async () => {
    const transport = new McpServerTransport(LEGACY);
    const client = await connect(transport);

    const [slow, fast] = await Promise.all([
      client.callTool('slow_tool', {}),
      client.callTool('fast_tool', {}),
    ]);

    assert.equal(slow.output, 'RESULT OF slow_tool');
    assert.equal(fast.output, 'RESULT OF fast_tool');
  });

  it('sends no call_id to a server that has not advertised the feature', async () => {
    const transport = new McpServerTransport(LEGACY);
    const client = await connect(transport);

    await client.callTool('fast_tool', {});

    const call = transport.sent.find((m) => m.type === MSG.MCP_CALL);
    assert.ok(!('call_id' in call), 'McpCallPayload is deny_unknown_fields: an unsolicited call_id is rejected, not ignored');
  });

  it('serialises against a non-correlating server, so only one call is in flight', async () => {
    const transport = new McpServerTransport(LEGACY);
    const client = await connect(transport);

    let inFlight = 0;
    let maxInFlight = 0;
    const origSend = transport._doSendControl.bind(transport);
    transport._doSendControl = async (msg) => {
      if (msg.type === MSG.MCP_CALL) {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
      }
      return origSend(msg);
    };
    transport._emitControl = new Proxy(transport._emitControl.bind(transport), {
      apply(target, thisArg, argsList) {
        if (argsList[0]?.type === MSG.MCP_RESULT) inFlight -= 1;
        return Reflect.apply(target, thisArg, argsList);
      },
    });

    await Promise.all([
      client.callTool('slow_tool', {}),
      client.callTool('fast_tool', {}),
    ]);

    assert.equal(maxInFlight, 1, 'without correlation, replies are indistinguishable');
  });

  it('a call whose result never arrives does not strand the next one', async () => {
    const transport = new McpServerTransport(LEGACY);
    const client = await connect(transport);

    // Swallow the first reply entirely.
    let swallowed = false;
    const origSend = transport._doSendControl.bind(transport);
    transport._doSendControl = async (msg) => {
      if (msg.type === MSG.MCP_CALL && !swallowed) {
        swallowed = true;
        transport.sent.push(msg);
        return;
      }
      return origSend(msg);
    };

    const first = client.callTool('slow_tool', {}, 60);
    const second = client.callTool('fast_tool', {}, 2000);

    await assert.rejects(() => first, /Timed out/);
    assert.equal((await second).output, 'RESULT OF fast_tool', 'the queue must not stay poisoned');
  });

  it('WshMcpBridge.call() returns each call its own result', async () => {
    const transport = new McpServerTransport(CORRELATING);
    const client = await connect(transport);
    const bridge = new WshMcpBridge(client);

    const [slow, fast] = await Promise.all([
      bridge.call('slow_tool', {}, { timeout: 2000 }),
      bridge.call('fast_tool', {}, { timeout: 2000 }),
    ]);

    assert.equal(slow.output, 'RESULT OF slow_tool');
    assert.equal(fast.output, 'RESULT OF fast_tool');
  });

  it('WshMcpBridge.call() is still correct against a non-correlating server', async () => {
    const transport = new McpServerTransport(LEGACY);
    const client = await connect(transport);
    const bridge = new WshMcpBridge(client);

    const [slow, fast] = await Promise.all([
      bridge.call('slow_tool', {}, { timeout: 2000 }),
      bridge.call('fast_tool', {}, { timeout: 2000 }),
    ]);

    assert.equal(slow.output, 'RESULT OF slow_tool');
    assert.equal(fast.output, 'RESULT OF fast_tool');
  });

  it('ignores a McpResult whose call_id matches no outstanding call', async () => {
    const transport = new McpServerTransport(CORRELATING);
    const client = await connect(transport);

    const pending = client.callTool('fast_tool', {}, 2000);
    transport._emitControl(mcpResult({ result: { output: 'STRAY' }, callId: 'not-mine' }));

    assert.equal((await pending).output, 'RESULT OF fast_tool');
  });
});
