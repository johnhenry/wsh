// test/helpers-against-real-client.test.mjs
//
// `WshMcpBridge` and `WshFileTransfer` are exported from the package root
// and both document their constructor argument as "a WshClient". Neither
// had ever been handed one: every existing test and both examples build a
// bespoke stand-in — `{ sendControl, addControlListener, removeControlListener }`
// in examples/05, `{ sendControl: async () => {}, openStream: async () => ({}) }`
// at test/file-transfer.test.mjs:297 — and a stand-in written to satisfy
// the caller cannot disagree with it.
//
// A real `WshClient` exposed none of those members. `WshMcpBridge.discover()`,
// `WshMcpBridge.call()` and `WshFileTransfer.list()` therefore all died on
//
//     TypeError: this.#client.sendControl is not a function
//
// the first time a real client reached them — three public methods
// unreachable while the suite was green, which is the shape CHANGELOG
// 0.14.0 records for `attachSession()`/`resumeSession()`.
//
// So every test below drives a real `WshClient`, connected over a real
// `WshTransport` subclass, through the real handshake. The server side is
// in-process, but it is on the far side of the client — it never stands in
// for the client itself.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { WshTransport } from '../src/transport.mjs';
import { MSG, mcpTools, mcpResult, openOk } from '../src/messages.gen.mjs';
import { WshMcpBridge } from '../src/mcp-bridge.mjs';
import { WshFileTransfer } from '../src/file-transfer.mjs';
import { attachControlListener } from '../src/control-listener.mjs';

let auth;
let clientMod;
try {
  auth = await import('../src/auth.mjs');
  clientMod = await import('../src/client.mjs');
} catch {
  // Web Crypto Ed25519 unavailable in this runtime.
}
const hasEd25519 = auth && typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

const LS_OUTPUT = [
  'total 8',
  'drwxr-xr-x  3 user  staff   96 Jan  1 10:00 .',
  'drwxr-xr-x  5 user  staff  160 Jan  1 09:00 ..',
  '-rw-r--r--  1 user  staff  512 Jan  2 11:30 notes.txt',
  '',
].join('\n');

/**
 * A transport with a small in-process server behind it: it completes the
 * auth handshake, and answers MCP_DISCOVER / MCP_CALL / OPEN the way the
 * protocol says a server does. Replies land on a macrotask, as they would
 * off a socket — replying on a microtask can beat the caller's own
 * response-waiter registration and be dropped (see the note on
 * ChallengeFirstMockTransport in client.test.mjs).
 */
class ServerBackedTransport extends WshTransport {
  /** Every message the client actually put on the wire. */
  sent = [];

  async _doConnect() {}
  async _doClose() {}

  async _doSendControl(msg) {
    this.sent.push(msg);
    const reply = (m) => setTimeout(() => this._emitControl(m), 0);

    if (msg.type === MSG.HELLO) {
      reply({ type: MSG.CHALLENGE, nonce: new Uint8Array(32).fill(7), session_id: 'sess-helpers' });
    } else if (msg.type === MSG.AUTH) {
      reply({ type: MSG.AUTH_OK });
    } else if (msg.type === MSG.MCP_DISCOVER) {
      reply(mcpTools({
        tools: [
          { name: 'read_file', description: 'Read a file', parameters: { type: 'object' } },
          { name: 'ping', description: 'No arguments at all', parameters: { type: 'object' } },
        ],
      }));
    } else if (msg.type === MSG.MCP_CALL) {
      reply(mcpResult({ result: { success: true, output: `called ${msg.tool}` } }));
    } else if (msg.type === MSG.OPEN) {
      reply(openOk({ channel_id: 1, stream_ids: {}, data_mode: 'stream', capabilities: [] }));
    }
  }

  async _doOpenStream() {
    return {
      id: 1,
      readable: new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(LS_OUTPUT));
          controller.close();
        },
      }),
      writable: new WritableStream({ write() {} }),
    };
  }
}

async function connectRealClient(transport) {
  const keyPair = await auth.generateKeyPair(true);
  const client = new clientMod.WshClient({ transportFactories: { ws: () => transport } });
  await client.connect('ws://test.invalid', { username: 'alice', keyPair, transport: 'ws' });
  return client;
}

describe('helper classes against a real WshClient', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  it('WshMcpBridge.discover() reaches the wire and returns the server\'s tools', async () => {
    const transport = new ServerBackedTransport();
    const client = await connectRealClient(transport);

    const tools = await new WshMcpBridge(client).discover({ timeout: 2000 });

    // The assertion that matters is not the return value — it is that a
    // MCP_DISCOVER was actually put on the wire. Before the fix nothing
    // ever left the client.
    assert.equal(transport.sent.filter((m) => m.type === MSG.MCP_DISCOVER).length, 1);
    assert.deepEqual(tools.map((t) => t.name), ['read_file', 'ping']);
  });

  it('WshMcpBridge.call() puts a complete McpCall on the wire and normalizes the reply', async () => {
    const transport = new ServerBackedTransport();
    const client = await connectRealClient(transport);
    const bridge = new WshMcpBridge(client);
    await bridge.discover({ timeout: 2000 });

    const result = await bridge.call('read_file', { path: '/etc/hostname' }, { timeout: 2000 });

    const call = transport.sent.find((m) => m.type === MSG.MCP_CALL);
    assert.ok(call, 'no McpCall reached the transport');
    assert.equal(call.tool, 'read_file');
    // `arguments` is required: true in spec/wsh-v1.yaml, and `undefined`
    // does not vanish — cborEncode emits the key with a CBOR null.
    assert.deepEqual(call.arguments, { path: '/etc/hostname' });
    assert.deepEqual(result, { success: true, output: 'called read_file', error: undefined });
  });

  it('WshMcpBridge.call() on a no-argument tool still sends an object, not null', async () => {
    const transport = new ServerBackedTransport();
    const client = await connectRealClient(transport);
    const bridge = new WshMcpBridge(client);
    await bridge.discover({ timeout: 2000 });

    await bridge.call('ping', undefined, { timeout: 2000 });

    const call = transport.sent.find((m) => m.type === MSG.MCP_CALL);
    assert.deepEqual(call.arguments, {});
    assert.notEqual(call.arguments, null);
  });

  it('WshFileTransfer.list() drives a real client end to end', async () => {
    const transport = new ServerBackedTransport();
    const client = await connectRealClient(transport);

    const entries = await new WshFileTransfer(client).list('/home/alice');

    const open = transport.sent.find((m) => m.type === MSG.OPEN);
    assert.ok(open, 'no Open reached the transport');
    assert.match(open.command, /^ls -la /);
    assert.ok(entries.some((e) => e.name === 'notes.txt'), `parsed entries: ${JSON.stringify(entries)}`);
  });

  it('a client with no sendControl is refused by name, not by a TypeError on a private field', async () => {
    assert.throws(
      () => new WshMcpBridge({ discoverTools: async () => [] }),
      (err) => err instanceof TypeError && /sendControl/.test(err.message),
    );
    await assert.rejects(
      () => new WshFileTransfer({ upload: async () => {} }).list('/tmp'),
      (err) => err instanceof TypeError && /sendControl\(\) and openStream\(\)/.test(err.message),
    );
  });

  it('repeated bridge operations leave no listeners behind on the client', async () => {
    const transport = new ServerBackedTransport();
    const client = await connectRealClient(transport);
    const bridge = new WshMcpBridge(client);

    await bridge.discover({ timeout: 2000 });
    for (let i = 0; i < 10; i++) await bridge.call('read_file', {}, { timeout: 2000 });

    // Nothing the bridge registered may still be attached: install a fresh
    // probe and confirm it is the only observer an inbound message finds.
    let observers = 0;
    const count = () => { observers++; };
    client.addControlListener(count);
    transport._emitControl({ type: MSG.MCP_RESULT, result: { success: true, output: 'late' } });
    client.removeControlListener(count);
    assert.equal(observers, 1, 'the bridge left listeners registered on the client');
  });

  it('an untrusted RelayForward is never handed to a control listener', async () => {
    const transport = new ServerBackedTransport();
    const client = await connectRealClient(transport);

    const seen = [];
    client.addControlListener((msg) => seen.push(msg.type));

    // from_fingerprint is not in #acceptedRelayPeers, so the client drops
    // the envelope. A listener placed before that gate would still see it.
    transport._emitControl({ type: MSG.RELAY_FORWARD, from_fingerprint: 'not-trusted', inner: new Uint8Array([0xa0]) });

    assert.deepEqual(seen, []);
  });
});

describe('control-listener subscription against an onControl-only client', () => {
  // A bare WshTransport's only hook is the settable `onControl` property.
  // The inlined registration used to wrap it and never unwrap:
  //
  //   const prev = client.onControl;
  //   client.onControl = (msg) => { prev?.(msg); listener(msg); };
  //
  // with a cleanup() that handled only removeControlListener and
  // _controlListeners. Measured against a real WshTransport, the frames an
  // inbound message traversed to reach the connection's own handler grew
  // one per operation: 1, 5, 20, 50 operations gave 5, 9, 24, 54 frames.

  class EchoTransport extends WshTransport {
    async _doConnect() {}
    async _doClose() {}
    async _doSendControl(msg) {
      if (msg.type === MSG.MCP_CALL) {
        setTimeout(() => this._emitControl(mcpResult({ result: 'ok' })), 0);
      }
    }
    async _doOpenStream() { throw new Error('not used'); }
  }

  it('the onControl chain does not grow one wrapper per operation', async () => {
    const transport = new EchoTransport();
    await transport.connect('ws://test.invalid');

    let frames = 0;
    const previousLimit = Error.stackTraceLimit;
    Error.stackTraceLimit = 500;
    try {
      // Stand in for what WshClient.connect() installs.
      transport.onControl = () => { frames = new Error().stack.split('\n').length; };
      const bridge = new WshMcpBridge(transport);

      transport._emitControl({ type: MSG.PONG });
      const baseline = frames;

      for (let i = 0; i < 25; i++) await bridge.call('echo', {}, { timeout: 2000 });

      transport._emitControl({ type: MSG.PONG });
      assert.equal(
        frames,
        baseline,
        `onControl chain grew from ${baseline} to ${frames} frames over 25 operations`,
      );
    } finally {
      Error.stackTraceLimit = previousLimit;
    }
  });

  it('the original onControl handler keeps receiving messages throughout', async () => {
    const transport = new EchoTransport();
    await transport.connect('ws://test.invalid');

    const seen = [];
    transport.onControl = (msg) => seen.push(msg.type);
    const bridge = new WshMcpBridge(transport);

    await bridge.call('echo', {}, { timeout: 2000 });
    transport._emitControl({ type: MSG.PONG });

    // Both halves matter. During the call the wrapper is installed, so it
    // must forward to the handler it displaced; after detach the handler
    // must be back in place. Dropping either one is silent — the bridge's
    // own promise resolves regardless.
    assert.ok(seen.includes(MSG.MCP_RESULT), `handler missed the in-flight reply: ${JSON.stringify(seen)}`);
    assert.ok(seen.includes(MSG.PONG), `handler stopped receiving after detach: ${JSON.stringify(seen)}`);
  });

  it('nested subscriptions detach in any order without severing each other', () => {
    // Wrappers nest, and nothing controls the order they come off in. A
    // detach that restores `prev` unconditionally looks harmless with one
    // subscription and silently severs the other here: the inner one puts
    // the pre-existing handler back and takes the still-live outer wrapper
    // with it, so the outer subscriber stops receiving anything while its
    // promise is still pending.
    const host = { onControl: null };
    const base = [];
    host.onControl = (msg) => base.push(`base:${msg.tag}`);

    const outer = [];
    const inner = [];
    const detachOuter = attachControlListener(host, (msg) => outer.push(msg.tag));
    const detachInner = attachControlListener(host, (msg) => inner.push(msg.tag));

    host.onControl({ tag: 'both' });
    detachOuter();                       // the outer wrapper comes off first,
    host.onControl({ tag: 'inner-only' }); // while the inner one is still live
    detachInner();
    host.onControl({ tag: 'none' });

    assert.deepEqual(inner, ['both', 'inner-only'], 'the inner subscriber was severed by the outer detach');
    assert.deepEqual(outer, ['both']);
    assert.deepEqual(base, ['base:both', 'base:inner-only', 'base:none']);
  });
});
