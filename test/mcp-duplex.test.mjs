// WebMCP tools served as MCP over ANY duplex (#220), not only a wsh rpc channel: `serveMcpOverDuplex(handler, { send })` gives the handler of
// `webmcpTools` a JSON-RPC 2.0 peer over a bare `send(message)` / `receive(message)` pair, the far side speaking plain MCP messages (the MCP
// SDK's `Client` here, over a transport that is an in-memory function call: no wsh anywhere). The bounds, the approval hook and the
// untrusted labelling are the handler's own; these tests check that they are the same ones over this transport, and what the seam adds.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { serveMcpOverDuplex } from '@johnhenry/wsh/page';
import { webmcpTools, captureWebMcp } from '../src/webmcp.mjs';
import { createFakeWindow } from './helpers/fake-window.mjs';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
async function until(cond, what, ms = 3000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 2)); }
}

const read = { name: 'search', description: 'Search products', inputSchema: { type: 'object', properties: { q: { type: 'string' } }, required: ['q'] }, annotations: { readOnlyHint: true }, execute: ({ q }) => ({ hits: [`${q}-1`] }) };
const loose = { description: 'A tool that takes any object', inputSchema: { type: 'object' }, annotations: { readOnlyHint: true } };
const write = { name: 'buy', title: 'Buy', description: 'Buy a product', inputSchema: { type: 'object', properties: { sku: { type: 'string' } } }, execute: ({ sku }) => ({ bought: sku }) };

/** The two ends joined by structured clone: the server end is `serveMcpOverDuplex`, the other is whatever `far` is given (default: nothing). */
function link(handler, options = {}) {
  const toFar = [];
  let farReceive = null;
  const server = serveMcpOverDuplex(handler, { send: (m) => { const copy = structuredClone(m); toFar.push(copy); queueMicrotask(() => farReceive?.(copy)); }, ...options });
  closers.push(async () => server.close());
  return { server, toFar, onFar: (fn) => { farReceive = fn; }, sendFromFar: (m) => queueMicrotask(() => server.receive(structuredClone(m))) };
}

/** An MCP SDK Client connected to the server end through a Transport that is two function calls. */
async function sdkClient(handler, options = {}) {
  const l = link(handler, options);
  const transport = {
    onmessage: null, onclose: null, onerror: null,
    async start() { l.onFar((m) => transport.onmessage?.(m)); },
    async send(message) { l.sendFromFar(message); },
    async close() { transport.onclose?.(); },
  };
  const client = new Client({ name: 'sdk', version: '1' }, { capabilities: {} });
  await client.connect(transport);
  closers.push(() => client.close());
  return { client, ...l };
}

/** The raw far side: JSON-RPC by hand, to look at what is on the wire. */
function raw(handler, options = {}) {
  const l = link(handler, options);
  const inbox = [];
  l.onFar((m) => inbox.push(m));
  const ask = (m) => { l.sendFromFar(m); };
  const reply = async (id) => until(() => inbox.find((m) => m.id === id), `a reply to ${id}`);
  return { ...l, inbox, ask, reply };
}

describe('the far side is a plain MCP client', () => {
  it('lists the tools and calls one: initialize, tools/list, tools/call, with the untrusted label and the instructions', async () => {
    const win = createFakeWindow();
    const { client } = await sdkClient(webmcpTools({ window: win, allow: ['search', 'buy'], tools: [read, write], approve: 'never' }));
    assert.match(client.getInstructions(), /untrusted/);
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search', 'buy']);
    const r = await client.callTool({ name: 'search', arguments: { q: 'x' } });
    assert.deepEqual(r.structuredContent, { hits: ['x-1'] });
    assert.equal(r._meta['wsh/untrusted'], true);
  });

  it('what is on the wire is JSON-RPC 2.0 and nothing else: every message has jsonrpc "2.0", a result or an error, the id of its request', async () => {
    const win = createFakeWindow();
    const r = raw(webmcpTools({ window: win, allow: ['search'], tools: [read] }));
    r.ask({ jsonrpc: '2.0', id: 7, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'raw', version: '1' } } });
    const init = await r.reply(7);
    assert.equal(init.jsonrpc, '2.0');
    assert.equal(init.result.protocolVersion, '2025-06-18');
    assert.deepEqual(Object.keys(init).sort(), ['id', 'jsonrpc', 'result']);
    r.ask({ jsonrpc: '2.0', id: 'two', method: 'tools/list' });
    assert.equal((await r.reply('two')).result.tools[0].name, 'search');
    r.ask({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'nothing', arguments: {} } });
    const err = await r.reply(3);
    assert.deepEqual(Object.keys(err).sort(), ['error', 'id', 'jsonrpc']);
    assert.equal(err.error.code, -32602);
    assert.match(err.error.message, /unknown tool/);
    r.ask({ jsonrpc: '2.0', id: 4, method: 'no/such/method' });
    assert.equal((await r.reply(4)).error.code, -32601);
  });

  it('a list change is a notification to the far side: notifications/tools/list_changed', async () => {
    const win = createFakeWindow();
    const capture = captureWebMcp(win);
    const { client } = await sdkClient(webmcpTools({ window: win, allow: ['search', 'buy'], tools: [], capture }));
    const changed = new Promise((resolve) => client.setNotificationHandler(ToolListChangedNotificationSchema, resolve));
    assert.deepEqual((await client.listTools()).tools, []);
    await win.document.modelContext.registerTool(read);
    await changed;
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search']);
  });
});

describe('the same bounds, approval and capability narrowing as over a wsh channel', () => {
  it('approval: a consequential tool asks the person at the page, with the call and who; Deny is an error and the tool does not run', async () => {
    const asked = [];
    let ran = 0;
    const win = createFakeWindow();
    const buy = { ...write, execute: ({ sku }) => { ran++; return { bought: sku }; } };
    const who = { username: 'mesh-peer', podId: 'A'.repeat(43) };
    const { client } = await sdkClient(webmcpTools({ window: win, allow: ['buy'], tools: [buy], prompt: async (call, w) => { asked.push({ call, w }); return asked.length > 1; } }), { who });
    await assert.rejects(client.callTool({ name: 'buy', arguments: { sku: 'A1' } }), /denied: the person at the page did not allow/);
    assert.equal(ran, 0);
    assert.deepEqual((await client.callTool({ name: 'buy', arguments: { sku: 'A2' } })).structuredContent, { bought: 'A2' });
    assert.equal(ran, 1);
    assert.equal(asked[0].call.name, 'buy');
    assert.deepEqual(asked[0].w, { username: 'mesh-peer', fingerprint: '00'.repeat(32), podId: 'A'.repeat(43) }, 'the pod id is the identity, and the hex fingerprint is derived from it');
  });

  it('with no way to ask (no prompt, a window with no document), a consequential call is denied', async () => {
    const win = createFakeWindow();
    delete win.document;
    const { client } = await sdkClient(webmcpTools({ window: win, allow: ['buy'], tools: [write] }));
    await assert.rejects(client.callTool({ name: 'buy', arguments: {} }), /denied/);
  });

  it('the key\'s capabilities (permits) narrow what is listed and what can be called', async () => {
    const win = createFakeWindow();
    const permits = (req) => req.tool === 'search';
    const { client } = await sdkClient(webmcpTools({ window: win, allow: ['search', 'buy'], tools: [read, write], approve: 'never' }), { permits });
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search']);
    await assert.rejects(client.callTool({ name: 'buy', arguments: {} }), /unknown tool/);
  });

  it('with permits from the capability notation: mcp:search lists search only', async () => {
    const { permits } = await import('@johnhenry/wsh/capabilities');
    const win = createFakeWindow();
    const caps = ['mcp:search'];
    const { client } = await sdkClient(webmcpTools({ window: win, allow: ['search', 'buy'], tools: [read, write], approve: 'never' }), { permits: (req) => permits(caps, req) });
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search']);
  });

  it('the handler\'s limits hold: more calls in a minute than maxCallsPerMinute are refused by name', async () => {
    const win = createFakeWindow();
    const { client } = await sdkClient(webmcpTools({ window: win, allow: ['search'], tools: [read], limits: { maxCallsPerMinute: 2 } }));
    await client.callTool({ name: 'search', arguments: { q: 'a' } });
    await client.callTool({ name: 'search', arguments: { q: 'b' } });
    await assert.rejects(client.callTool({ name: 'search', arguments: { q: 'c' } }), /maxCallsPerMinute/);
  });

  it('a cancelled call aborts the tool\'s signal (notifications/cancelled)', async () => {
    const win = createFakeWindow();
    let aborted = false;
    const slow = { ...loose, name:'slow', execute: (_input, { signal }) => new Promise((_, reject) => { signal.addEventListener('abort', () => { aborted = true; reject(new Error('stopped')); }); }) };
    const { client } = await sdkClient(webmcpTools({ window: win, allow: ['slow'], tools: [slow], approve: 'never' }));
    const ctl = new AbortController();
    const call = client.callTool({ name: 'slow', arguments: {} }, undefined, { signal: ctl.signal });
    await new Promise((r) => setTimeout(r, 20));
    ctl.abort();
    await assert.rejects(call);
    await until(() => aborted, 'the tool to be told');
  });

  it('closing the duplex aborts what is running and ends the session: the handler\'s watchers are removed', async () => {
    const win = createFakeWindow();
    let aborted = false;
    const slow = { ...loose, name:'slow', execute: (_input, { signal }) => new Promise((_, reject) => { signal.addEventListener('abort', () => { aborted = true; reject(new Error('stopped')); }); }) };
    const handler = webmcpTools({ window: win, allow: ['slow'], tools: [slow], approve: 'never' });
    const r = raw(handler);
    r.ask({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'slow', arguments: {} } });
    await new Promise((resolve) => setTimeout(resolve, 20));
    r.server.close('far side left');
    await until(() => aborted, 'the tool to be aborted by the close');
    assert.equal(r.server.closed, true);
    const before = r.inbox.length;
    r.ask({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(r.inbox.length, before, 'nothing is answered after the close');
  });
});

describe('what the seam adds: a bounded JSON-RPC peer that refuses what is not MCP', () => {
  const handler = () => webmcpTools({ window: createFakeWindow(), allow: ['search'], tools: [read] });

  it('a message that is not a plain JSON-RPC 2.0 message is refused or ignored, and never reaches the handler', async () => {
    const r = raw(handler());
    r.ask({ id: 1, method: 'tools/list' });                       // no jsonrpc
    r.ask({ jsonrpc: '1.0', id: 2, method: 'tools/list' });        // wrong version
    r.ask([{ jsonrpc: '2.0', id: 3, method: 'tools/list' }]);       // a batch
    r.ask({ jsonrpc: '2.0', id: { a: 1 }, method: 'tools/list' }); // an id that is not a string or number
    r.ask({ jsonrpc: '2.0', id: 1.5, method: 'tools/list' });
    r.ask({ jsonrpc: '2.0', id: 'x'.repeat(300), method: 'tools/list' });
    r.ask({ jsonrpc: '2.0', id: 4, method: 5 });
    r.ask('tools/list');
    r.ask(null);
    r.ask({ jsonrpc: '2.0', id: 5, method: 'tools/list', params: [1] });
    r.ask({ jsonrpc: '2.0', id: 6, method: 'tools/list' });         // and then a good one
    await r.reply(6);
    const answers = r.inbox.filter((m) => m.id !== 6);
    for (const a of answers) { assert.equal(a.jsonrpc, '2.0'); assert.ok(a.error, JSON.stringify(a)); assert.equal(a.error.code, -32600, JSON.stringify(a)); }
    assert.equal(r.inbox.find((m) => m.id === 6).result.tools[0].name, 'search');
  });

  it('a request id that is still in flight is refused: one id answers one request', async () => {
    const win = createFakeWindow();
    let release;
    const slow = { ...loose, name:'slow', execute: () => new Promise((resolve) => { release = resolve; }) };
    const r = raw(webmcpTools({ window: win, allow: ['slow'], tools: [slow], approve: 'never' }));
    r.ask({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'slow', arguments: {} } });
    await until(() => release, 'the call to start');
    r.ask({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const dup = await r.reply(1);
    assert.equal(dup.error.code, -32600);
    assert.match(dup.error.message, /in flight/);
    release({ ok: 1 });
    await until(() => r.inbox.filter((m) => m.id === 1).length === 2, 'the original answer');
  });

  it('maxInflight bounds the requests running at once, whatever their kind', async () => {
    const win = createFakeWindow();
    const releases = [];
    const slow = { ...loose, name:'slow', execute: () => new Promise((resolve) => { releases.push(resolve); }) };
    const r = raw(webmcpTools({ window: win, allow: ['slow'], tools: [slow], approve: 'never', limits: { maxInflight: 99 } }), { maxInflight: 2 });
    for (const id of [1, 2, 3]) r.ask({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'slow', arguments: {} } });
    const refused = await r.reply(3);
    assert.equal(refused.error.code, -32002);
    assert.match(refused.error.message, /maxInflight/);
    for (const release of releases) release({});
  });

  it('a message over maxMessageBytes is refused (and so is an answer that would be)', async () => {
    const win = createFakeWindow();
    const big = { ...loose, name:'big', execute: () => ({ text: 'x'.repeat(2000) }) };
    const r = raw(webmcpTools({ window: win, allow: ['big', 'search'], tools: [big, read], approve: 'never' }), { maxMessageBytes: 1024 });
    r.ask({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'search', arguments: { q: 'y'.repeat(2000) } } });
    assert.equal((await r.reply(1)).error.code, -32600);
    assert.match(r.inbox.find((m) => m.id === 1).error.message, /1024/);
    r.ask({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'big', arguments: {} } });
    const r2 = await r.reply(2);
    assert.equal(r2.error.code, -32603);
    assert.match(r2.error.message, /larger than/);
  });

  it('any handler written for an rpc channel of the mcp protocol is served the same way, and the seam aborts what it was running when it closes', async () => {
    let signalOf = null;
    const generic = (channel) => {
      channel.onRequest('echo/slow', (params, rpc) => new Promise((resolve) => { signalOf = rpc.signal; rpc.signal.addEventListener('abort', () => resolve('late')); }));
      channel.onRequest('echo/fast', (params) => ({ got: params }));
    };
    const r = raw(generic);
    r.ask({ jsonrpc: '2.0', id: 'a', method: 'echo/fast', params: { x: 1 } });
    assert.deepEqual((await r.reply('a')).result, { got: { x: 1 } });
    r.ask({ jsonrpc: '2.0', id: 'b', method: 'echo/slow' });
    await until(() => signalOf, 'the slow request to start');
    assert.equal(signalOf.aborted, false);
    r.server.close('gone');
    assert.equal(signalOf.aborted, true);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(r.inbox.find((m) => m.id === 'b'), undefined, 'an answer to a closed session is not written');
  });

  it('a throw from send ends the session (the transport is gone), and nothing escapes as an unhandled rejection', async () => {
    const win = createFakeWindow();
    let fail = false;
    const peer = serveMcpOverDuplex(webmcpTools({ window: win, allow: ['search'], tools: [read] }), { send: () => { if (fail) throw new Error('link down'); } });
    closers.push(async () => peer.close());
    fail = true;
    peer.receive({ jsonrpc: '2.0', id: 1, method: 'ping' });
    await until(() => peer.closed, 'the session to end');
  });

  it('a response or a notification from the far side that nothing waits for is ignored', async () => {
    const r = raw(handler());
    r.ask({ jsonrpc: '2.0', id: 99, result: {} });
    r.ask({ jsonrpc: '2.0', id: 98, error: { code: -1, message: 'x' } });
    r.ask({ jsonrpc: '2.0', method: 'notifications/unknown' });
    r.ask({ jsonrpc: '2.0', id: 1, method: 'ping' });
    assert.deepEqual((await r.reply(1)).result, {});
    assert.equal(r.inbox.length, 1);
  });

  it('refuses a handler or options that are not what they should be', () => {
    assert.throws(() => serveMcpOverDuplex(null, { send() {} }), TypeError);
    assert.throws(() => serveMcpOverDuplex(() => {}, {}), TypeError);
    assert.throws(() => serveMcpOverDuplex(() => {}, { send() {}, maxMessageBytes: 0 }), TypeError);
    assert.throws(() => serveMcpOverDuplex(() => {}, { send() {}, maxInflight: 1.5 }), TypeError);
    assert.throws(() => serveMcpOverDuplex(() => {}, { send() {}, who: { fingerprint: 'aa'.repeat(32), podId: 'B'.repeat(43) } }), TypeError);
  });

  it('handler.closeSessions(reason) tells the far side why and ends it, as over wsh', async () => {
    const win = createFakeWindow();
    const h = webmcpTools({ window: win, allow: ['search'], tools: [read] });
    const r = raw(h, { who: { username: 'a', fingerprint: 'aa'.repeat(32) } });
    r.ask({ jsonrpc: '2.0', id: 1, method: 'ping' });
    await r.reply(1);
    assert.equal(await h.closeSessions('the page is leaving'), 1);
    const note = await until(() => r.inbox.find((m) => m.method === 'notifications/message'), 'the notice');
    assert.equal(note.jsonrpc, '2.0');
    assert.equal(note.params.data, 'the page is leaving');
    assert.equal(r.server.closed, true);
  });
});
