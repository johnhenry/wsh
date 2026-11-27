// test/webmcp.test.mjs -- WebMCP tools of a window, served as MCP (#190): the capture shim over both API generations, the mapping to
// MCP, the bounds, the allow-list, the approval flow, narrowing by the key's capabilities, and the default dialog. A fake window
// throughout (test/helpers/fake-window.mjs): nothing here reads the real global.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { RpcChannel, mcpClientTransport } from '@johnhenry/wsh';
import { captureWebMcp, webmcpTools, createDomPrompt, toMcpResult, WEBMCP_DEFAULT_LIMITS } from '../src/webmcp.mjs';
import { createFakeWindow, manualTimers, byRole } from './helpers/fake-window.mjs';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
const tick = () => new Promise((r) => setImmediate(r));
async function until(cond, what, ms = 3000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 2)); }
}

/** Two linked rpc channels: the handler serves one, an MCP SDK client speaks over the other. */
async function serve(handler, ctx = { user: 'alice', fingerprint: 'aa'.repeat(32) }) {
  let server; let clientChannel;
  clientChannel = new RpcChannel({ write: (b) => server.feed(b) });
  server = new RpcChannel({ write: (b) => clientChannel.feed(b) });
  handler(server, ctx);
  const client = new Client({ name: 'sdk', version: '1' }, { capabilities: {} });
  await client.connect(mcpClientTransport(clientChannel));
  closers.push(() => client.close());
  return { client, server, clientChannel };
}

const read = { name: 'search', description: 'Search products', inputSchema: { type: 'object', properties: { q: { type: 'string' } }, required: ['q'] }, annotations: { readOnlyHint: true }, execute: ({ q }) => ({ hits: [`${q}-1`, `${q}-2`] }) };
const write = { name: 'buy', title: 'Buy', description: 'Buy a product', inputSchema: { type: 'object', properties: { sku: { type: 'string' } } }, execute: ({ sku }) => ({ bought: sku }) };

describe('captureWebMcp: the current draft (document.modelContext)', () => {
  function withNative() {
    const win = createFakeWindow();
    const calls = [];
    const registered = new Map();
    win.document.modelContext = {
      registerTool(tool, options) {
        calls.push(tool.name);
        if (registered.has(tool.name)) return Promise.reject(Object.assign(new Error('duplicate'), { name: 'InvalidStateError' }));
        registered.set(tool.name, tool);
        options?.signal?.addEventListener('abort', () => registered.delete(tool.name));
        return Promise.resolve(undefined);
      },
    };
    return { win, calls, registered };
  }

  it('records what the application registers, and still calls the browser\'s own registerTool', async () => {
    const { win, calls } = withNative();
    const capture = captureWebMcp(win);
    await win.document.modelContext.registerTool(read);
    await win.document.modelContext.registerTool(write);
    assert.deepEqual(capture.list().map((t) => t.name), ['search', 'buy']);
    assert.deepEqual(calls, ['search', 'buy']);
    // The browser has the current draft; the older name is provided too, so application code written for either runs.
    assert.deepEqual(capture.installed, ['document.modelContext', 'navigator.modelContext (provided)']);
  });

  it('honours the registration\'s abort signal: aborting forgets the tool', async () => {
    const { win } = withNative();
    const capture = captureWebMcp(win);
    const ctl = new AbortController();
    await win.document.modelContext.registerTool(read, { signal: ctl.signal });
    assert.equal(capture.list().length, 1);
    ctl.abort();
    assert.equal(capture.list().length, 0);
  });

  it('a registration the browser rejects (a duplicate name) leaves the first one in place and records nothing twice', async () => {
    const { win } = withNative();
    const capture = captureWebMcp(win);
    await win.document.modelContext.registerTool(read);
    await assert.rejects(win.document.modelContext.registerTool({ ...read, description: 'again' }));
    assert.equal(capture.list().length, 1);
    assert.equal(capture.get('search').description, 'Search products');
  });

  it('an already-aborted signal records nothing', async () => {
    const { win } = withNative();
    const capture = captureWebMcp(win);
    const ctl = new AbortController(); ctl.abort();
    await win.document.modelContext.registerTool(read, { signal: ctl.signal });
    assert.equal(capture.list().length, 0);
  });

  it('a second call returns the same capture, and restore() puts the browser\'s function back', () => {
    const { win } = withNative();
    const original = win.document.modelContext.registerTool;
    const capture = captureWebMcp(win);
    assert.equal(captureWebMcp(win), capture);
    assert.notEqual(win.document.modelContext.registerTool, original);
    capture.restore();
    assert.equal(win.document.modelContext.registerTool, original);
  });
});

describe('captureWebMcp: the older draft (navigator.modelContext)', () => {
  it('records registerTool\'s registration object, provideContext, unregisterTool and clearContext', () => {
    const win = createFakeWindow();
    const registrations = [];
    win.navigator.modelContext = {
      registerTool(tool) { const reg = { unregister() { registrations.push(`unregister ${tool.name}`); } }; return reg; },
      provideContext() {}, unregisterTool() {}, clearContext() {},
    };
    const capture = captureWebMcp(win);
    const reg = win.navigator.modelContext.registerTool(read);
    assert.deepEqual(capture.list().map((t) => t.name), ['search']);
    reg.unregister();
    assert.equal(capture.list().length, 0);
    assert.deepEqual(registrations, ['unregister search']);
    win.navigator.modelContext.provideContext({ tools: [read, write] });
    assert.deepEqual(capture.list().map((t) => t.name), ['search', 'buy']);
    win.navigator.modelContext.provideContext({ tools: [write] });
    assert.deepEqual(capture.list().map((t) => t.name), ['buy']);
    win.navigator.modelContext.unregisterTool('buy');
    assert.equal(capture.list().length, 0);
    win.navigator.modelContext.registerTool(read);
    win.navigator.modelContext.clearContext();
    assert.equal(capture.list().length, 0);
  });
});

describe('captureWebMcp: a browser with no modelContext', () => {
  it('provides one on document and navigator so the same application code runs, in either generation\'s style', async () => {
    const win = createFakeWindow();
    const capture = captureWebMcp(win);
    assert.deepEqual(capture.installed, ['document.modelContext (provided)', 'navigator.modelContext (provided)']);
    assert.equal(win.document.modelContext, win.navigator.modelContext);
    await win.document.modelContext.registerTool(read);                       // current draft: await the promise
    const registration = win.navigator.modelContext.registerTool(write);      // older draft: the registration object
    assert.deepEqual(capture.list().map((t) => t.name), ['search', 'buy']);
    registration.unregister();
    assert.deepEqual(capture.list().map((t) => t.name), ['search']);
    const ctl = new AbortController();
    await win.document.modelContext.registerTool({ ...write, name: 'buy2' }, { signal: ctl.signal });
    ctl.abort();
    assert.deepEqual(capture.list().map((t) => t.name), ['search']);
  });

  it('rejects a duplicate or invalid registration the way the draft says, and can list and run its tools', async () => {
    const win = createFakeWindow();
    captureWebMcp(win);
    const context = win.document.modelContext;
    await context.registerTool(read);
    await assert.rejects(context.registerTool(read), { name: 'InvalidStateError' });
    await assert.rejects(context.registerTool({ name: 'no execute', description: 'x' }));
    const [t] = await context.getTools();
    assert.equal(t.name, 'search');
    assert.equal(t.window, win);
    assert.equal(await context.executeTool(t, { q: 'x' }), JSON.stringify({ hits: ['x-1', 'x-2'] }));
  });

  it('restore() removes what it provided', () => {
    const win = createFakeWindow();
    const capture = captureWebMcp(win);
    capture.restore();
    assert.equal(win.document.modelContext, undefined);
    assert.equal(win.navigator.modelContext, undefined);
  });

  it('a window with no document and no navigator is captured without error (nothing to wrap)', () => {
    const win = createFakeWindow({ document: false });
    delete win.navigator;
    assert.deepEqual(captureWebMcp(win).installed, []);
  });

  it('needs a window', () => {
    assert.throws(() => captureWebMcp(), /window is required/);
    assert.throws(() => webmcpTools({}), /window is required/);
  });
});

describe('the mapping to MCP', () => {
  it('lists name, title, description, input and output schemas and annotations, for the allowed tools only', async () => {
    const win = createFakeWindow();
    const tool = { ...write, name: 'quote', title: 'Quote', outputSchema: { type: 'object', properties: { price: { type: 'number' } } }, annotations: { readOnlyHint: true, untrustedContentHint: true }, execute: () => ({ price: 3 }) };
    const { client } = await serve(webmcpTools({ window: win, allow: ['quote', 'search'], tools: [tool, read, write] }));
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), ['quote', 'search']);
    const q = tools.find((t) => t.name === 'quote');
    assert.equal(q.title, 'Quote');
    assert.equal(q.description, 'Buy a product');
    assert.deepEqual(q.inputSchema, { type: 'object', properties: { sku: { type: 'string' } } });
    assert.deepEqual(q.outputSchema, { type: 'object', properties: { price: { type: 'number' } } });
    assert.equal(q.annotations.readOnlyHint, true);
    assert.equal(q.annotations.destructiveHint, false);
    assert.deepEqual(q._meta['webmcp/annotations'], { untrustedContentHint: true, consequential: false });
    const s = tools.find((t) => t.name === 'search');
    assert.equal(s._meta['webmcp/annotations'].consequential, false);
  });

  it('a tool not marked read-only is consequential, and consequentialHint says destructive', async () => {
    const win = createFakeWindow();
    const { client } = await serve(webmcpTools({ window: win, allow: ['buy', 'pay'], tools: [write, { ...write, name: 'pay', annotations: { consequentialHint: true, readOnlyHint: false } }] }));
    const byName = Object.fromEntries((await client.listTools()).tools.map((t) => [t.name, t]));
    assert.equal(byName.buy._meta['webmcp/annotations'].consequential, true);
    assert.equal(byName.buy.annotations.readOnlyHint, false);
    assert.equal(byName.pay.annotations.destructiveHint, true);
  });

  it('an object result is structuredContent with a text rendering, and is labelled untrusted', async () => {
    const win = createFakeWindow();
    const { client } = await serve(webmcpTools({ window: win, allow: ['search'], tools: [read] }));
    const r = await client.callTool({ name: 'search', arguments: { q: 'tea' } });
    assert.deepEqual(r.structuredContent, { hits: ['tea-1', 'tea-2'] });
    assert.equal(r.content[0].text, JSON.stringify({ hits: ['tea-1', 'tea-2'] }));
    assert.equal(r._meta['wsh/untrusted'], true);
    assert.ok(!r.isError);
  });

  it('initialize says the results are untrusted page data', async () => {
    const win = createFakeWindow();
    const { client } = await serve(webmcpTools({ window: win, allow: [], server: { name: 'shop-tab' } }));
    assert.equal(client.getServerVersion().name, 'shop-tab');
    assert.match(client.getInstructions(), /untrusted/);
  });

  it('toMcpResult: content blocks of the draft\'s examples pass through; text, numbers and null are rendered', () => {
    assert.deepEqual(toMcpResult({ content: [{ type: 'text', text: 'hi' }] }).content, [{ type: 'text', text: 'hi' }]);
    assert.deepEqual(toMcpResult({ content: [{ type: 'weird', x: 1 }] }).content, [{ type: 'text', text: '{"type":"weird","x":1}' }]);
    assert.equal(toMcpResult('plain').content[0].text, 'plain');
    assert.equal(toMcpResult(42).content[0].text, '42');
    assert.equal(toMcpResult(null).content[0].text, '');
    assert.equal(toMcpResult([1, 2]).content[0].text, '[1,2]');
    assert.equal(toMcpResult({ content: [], isError: true }).isError, true);
  });

  it('a thrown error is a tool result with isError and the message, never a stack', async () => {
    const win = createFakeWindow();
    const boom = { ...read, name: 'boom', execute: () => { throw new Error('the cart is locked'); } };
    const { client } = await serve(webmcpTools({ window: win, allow: ['boom'], tools: [boom], approve: 'never' }));
    const r = await client.callTool({ name: 'boom', arguments: { q: 'x' } });
    assert.equal(r.isError, true);
    assert.equal(r.content[0].text, 'the cart is locked');
    assert.ok(!/\bat \S+ \(|\.mjs:\d+/.test(JSON.stringify(r)), 'a stack trace crossed');
  });

  it('a rejected promise with a non-Error, and a result that cannot be serialised, are tool errors too', async () => {
    const win = createFakeWindow();
    const circular = {}; circular.self = circular;
    const tools = [{ ...read, name: 'reject', execute: () => Promise.reject('plain string reason') }, { ...read, name: 'circular', execute: () => circular }, { ...read, name: 'bigint', execute: () => ({ n: 1n }) }];
    const { client } = await serve(webmcpTools({ window: win, allow: ['reject', 'circular', 'bigint'], tools, approve: 'never' }));
    assert.deepEqual((await client.callTool({ name: 'reject', arguments: { q: 'x' } })).content[0].text, 'plain string reason');
    for (const name of ['circular', 'bigint']) {
      const r = await client.callTool({ name, arguments: { q: 'x' } });
      assert.equal(r.isError, true, name);
      assert.match(r.content[0].text, /cannot be serialised/);
    }
  });

  it('an MCP cancel aborts the signal execute was given', async () => {
    const win = createFakeWindow();
    let aborted; let started;
    const slow = { ...read, name: 'slow', execute: (_i, { signal }) => new Promise((_res, reject) => { started = true; signal.addEventListener('abort', () => { aborted = true; reject(signal.reason); }); }) };
    const { client } = await serve(webmcpTools({ window: win, allow: ['slow'], tools: [slow], approve: 'never' }));
    const ctl = new AbortController();
    const pending = client.callTool({ name: 'slow', arguments: { q: 'x' } }, undefined, { signal: ctl.signal });
    pending.catch(() => {});
    await until(() => started, 'the tool to start');
    ctl.abort();
    await assert.rejects(pending);
    await until(() => aborted, 'the signal to fire');
  });

  it('a closed session aborts the calls it had running', async () => {
    const win = createFakeWindow();
    let aborted; let started;
    const slow = { ...read, name: 'slow', execute: (_i, { signal }) => new Promise((_res, reject) => { started = true; signal.addEventListener('abort', () => { aborted = true; reject(signal.reason); }); }) };
    const { client, server } = await serve(webmcpTools({ window: win, allow: ['slow'], tools: [slow], approve: 'never' }));
    const pending = client.callTool({ name: 'slow', arguments: { q: 'x' } });
    pending.catch(() => {});
    await until(() => started, 'the tool to start');
    await server.close('test');
    await until(() => aborted, 'the signal to fire');
  });

  it('a call that outlives callTimeoutMs is aborted and fails, saying so', async () => {
    const win = createFakeWindow();
    const timers = manualTimers();
    let aborted;
    const slow = { ...read, name: 'slow', execute: (_i, { signal }) => new Promise((_res, reject) => { signal.addEventListener('abort', () => { aborted = true; reject(signal.reason); }); }) };
    const { client } = await serve(webmcpTools({ window: win, allow: ['slow'], tools: [slow], approve: 'never', timers }));
    const pending = client.callTool({ name: 'slow', arguments: { q: 'x' } });
    await until(() => timers.timeouts.size > 0, 'the timeout to be armed');
    timers.run();
    const r = await pending;
    assert.equal(r.isError, true);
    assert.match(r.content[0].text, /did not finish in 120000 ms/);
    assert.ok(aborted);
  });

  it('notifies tools/list_changed when a tool is registered or unregistered later', async () => {
    const win = createFakeWindow();
    const capture = captureWebMcp(win);
    const { client } = await serve(webmcpTools({ window: win, allow: ['search', 'buy', 'hidden'] }));
    let changes = 0;
    client.setNotificationHandler(ToolListChangedNotificationSchema, () => { changes++; });
    assert.deepEqual((await client.listTools()).tools, []);
    const ctl = new AbortController();
    await win.document.modelContext.registerTool(read, { signal: ctl.signal });
    await until(() => changes === 1, 'a notification for the registration');
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search']);
    await win.document.modelContext.registerTool({ ...write, name: 'not-allowed' });
    await tick(); await tick();
    assert.equal(changes, 1, 'a tool that is not allowed is no change');
    ctl.abort();
    await until(() => changes === 2, 'a notification for the removal');
    assert.equal(capture.list().length, 1);
  });
});

describe('source 3: the browser\'s own API', () => {
  function browserWithTools() {
    const win = createFakeWindow();
    const listeners = new Set();
    const tools = [{ name: 'native-search', description: 'from the browser', inputSchema: { type: 'object', properties: {} }, annotations: { readOnlyHint: true }, window: win, origin: win.location.origin }];
    const ran = [];
    win.document.modelContext = {
      getTools: async () => tools.slice(),
      executeTool: async (tool, input, options) => { ran.push({ tool: tool.name, input, signal: !!options.signal }); return JSON.stringify({ ok: true }); },
      addEventListener: (type, fn) => listeners.add(fn), removeEventListener: (type, fn) => listeners.delete(fn),
    };
    return { win, tools, ran, listeners };
  }

  it('lists the tools getTools() returns and runs them through executeTool()', async () => {
    const { win, ran } = browserWithTools();
    const { client } = await serve(webmcpTools({ window: win, allow: ['native-search'] }));
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['native-search']);
    const r = await client.callTool({ name: 'native-search', arguments: {} });
    assert.deepEqual(r.structuredContent, { ok: true });
    assert.deepEqual(ran, [{ tool: 'native-search', input: {}, signal: true }]);
  });

  it('ignores tools of another window (a frame), and a toolchange event is a list_changed', async () => {
    const { win, tools, listeners } = browserWithTools();
    tools.push({ name: 'frame-tool', description: 'x', window: {}, origin: 'https://other.example' });
    const { client } = await serve(webmcpTools({ window: win, allow: ['native-search', 'frame-tool', 'later'] }));
    let changes = 0;
    client.setNotificationHandler(ToolListChangedNotificationSchema, () => { changes++; });
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['native-search']);
    await client.notification({ method: 'notifications/initialized' });
    await until(() => listeners.size === 1, 'the toolchange listener');
    tools.push({ name: 'later', description: 'x', window: win, origin: win.location.origin });
    for (const fn of listeners) fn({ type: 'toolchange' });
    await until(() => changes === 1, 'list_changed');
  });

  it('the minimal context captureWebMcp provides is not mistaken for the browser\'s own API (no tool twice)', async () => {
    const win = createFakeWindow();
    captureWebMcp(win);
    await win.document.modelContext.registerTool(read);
    const { client } = await serve(webmcpTools({ window: win, allow: ['search'] }));
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search']);
  });

  it('a getTools that throws lists nothing from the browser, and breaks nothing', async () => {
    const win = createFakeWindow();
    win.document.modelContext = { getTools: async () => { throw new Error('not allowed'); }, executeTool: async () => '{}' };
    const { client } = await serve(webmcpTools({ window: win, allow: ['x'], tools: [{ ...read, name: 'x' }] }));
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['x']);
  });
});

describe('the allow-list and the key\'s capabilities', () => {
  it('nothing is allowed by default: an explicit list and a capture are still not served', async () => {
    const win = createFakeWindow();
    captureWebMcp(win);
    await win.document.modelContext.registerTool(write);
    const { client } = await serve(webmcpTools({ window: win, tools: [read] }));
    assert.deepEqual((await client.listTools()).tools, []);
    await assert.rejects(client.callTool({ name: 'search', arguments: { q: 'x' } }), /unknown tool/);
    await assert.rejects(client.callTool({ name: 'buy', arguments: {} }), /unknown tool/);
  });

  it('a tool that exists but is not allowed answers exactly as one that does not exist', async () => {
    const win = createFakeWindow();
    const { client } = await serve(webmcpTools({ window: win, allow: ['search'], tools: [read, write] }));
    const msg = async (name) => (await client.callTool({ name, arguments: {} }).catch((e) => e)).message;
    assert.equal((await msg('buy')).replace('buy', 'X'), (await msg('nothing')).replace('nothing', 'X'));
  });

  it('a key with mcp:TOOL capabilities lists and calls those tools only (intersection with allow)', async () => {
    const win = createFakeWindow();
    const permits = (req) => req.tool === 'search';
    const { client } = await serve(webmcpTools({ window: win, allow: ['search', 'buy'], tools: [read, write], approve: 'never' }), { user: 'alice', fingerprint: 'bb'.repeat(32), permits });
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search']);
    assert.ok(await client.callTool({ name: 'search', arguments: { q: 'x' } }));
    await assert.rejects(client.callTool({ name: 'buy', arguments: {} }), /unknown tool/);
  });

  it('a capability for a tool the allow-list does not name adds nothing', async () => {
    const win = createFakeWindow();
    const { client } = await serve(webmcpTools({ window: win, allow: ['search'], tools: [read, write] }), { user: 'a', fingerprint: 'cc'.repeat(32), permits: () => true });
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search']);
  });

  it('declares itself capabilityScoped, and refuses a bad allow list', () => {
    const win = createFakeWindow();
    assert.equal(webmcpTools({ window: win }).capabilityScoped, true);
    assert.throws(() => webmcpTools({ window: win, allow: 'search' }), /allow must be an array/);
    assert.throws(() => webmcpTools({ window: win, allow: ['bad name'] }), /allow must be an array/);
    assert.throws(() => webmcpTools({ window: win, approve: 'sometimes' }), /approve must be/);
    assert.throws(() => webmcpTools({ window: win, limits: { maxTools: 0 } }), /positive integer/);
    assert.throws(() => webmcpTools({ window: win, limits: { nope: 1 } }), /unknown limit/);
    assert.throws(() => webmcpTools({ window: win, tools: [{ name: 'x', description: 'y' }] }), /execute/);
    assert.throws(() => webmcpTools({ window: win, tools: [read, read] }), /twice/);
  });
});

describe('bounds, each refused by name', () => {
  const events = () => { const log = []; return { log, onCall: (e) => log.push(e) }; };

  it('maxTools: the tools beyond it are not listed and cannot be called', async () => {
    const win = createFakeWindow();
    const tools = ['a', 'b', 'c'].map((name) => ({ ...read, name }));
    const e = events();
    const { client } = await serve(webmcpTools({ window: win, allow: ['a', 'b', 'c'], tools, limits: { maxTools: 2 }, ...e }));
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['a', 'b']);
    await assert.rejects(client.callTool({ name: 'c', arguments: { q: 'x' } }), /unknown tool/);
    assert.ok(e.log.some((x) => x.outcome === 'unlisted' && x.limit === 'maxTools' && x.name === 'c'));
  });

  it('maxSchemaBytes: a tool with a bigger schema is not listed, and is not callable', async () => {
    const win = createFakeWindow();
    const fat = { ...read, name: 'fat', inputSchema: { type: 'object', properties: { x: { type: 'string', description: 'x'.repeat(200) } } } };
    const e = events();
    const { client } = await serve(webmcpTools({ window: win, allow: ['fat', 'search'], tools: [fat, read], limits: { maxSchemaBytes: 150 }, ...e }));
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search']);
    await assert.rejects(client.callTool({ name: 'fat', arguments: {} }), /unknown tool/);
    assert.ok(e.log.some((x) => x.limit === 'maxSchemaBytes' && x.name === 'fat'));
  });

  it('a schema that is not for an object is not listed (MCP tools take objects)', async () => {
    const win = createFakeWindow();
    const { client } = await serve(webmcpTools({ window: win, allow: ['odd', 'search'], tools: [{ ...read, name: 'odd', inputSchema: { type: 'string' } }, read] }));
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search']);
  });

  it('maxInputBytes: the arguments are refused before the tool runs', async () => {
    const win = createFakeWindow();
    let ran = 0;
    const tool = { ...read, execute: () => { ran++; return {}; } };
    const { client } = await serve(webmcpTools({ window: win, allow: ['search'], tools: [tool], limits: { maxInputBytes: 100 } }));
    await assert.rejects(client.callTool({ name: 'search', arguments: { q: 'x'.repeat(200) } }), /maxInputBytes/);
    assert.equal(ran, 0);
    await client.callTool({ name: 'search', arguments: { q: 'x' } });
    assert.equal(ran, 1);
  });

  it('maxResultBytes: a result over it is not sent, and the refusal says so', async () => {
    const win = createFakeWindow();
    const tool = { ...read, execute: () => ({ blob: 'y'.repeat(500) }) };
    const { client } = await serve(webmcpTools({ window: win, allow: ['search'], tools: [tool], limits: { maxResultBytes: 300 } }));
    const r = await client.callTool({ name: 'search', arguments: { q: 'x' } });
    assert.equal(r.isError, true);
    assert.match(r.content[0].text, /maxResultBytes \(300\)/);
    assert.ok(!JSON.stringify(r).includes('yyyy'));
  });

  it('maxInflight: calls beyond it are refused until one finishes', async () => {
    const win = createFakeWindow();
    const release = [];
    const slow = { ...read, name: 'slow', execute: () => new Promise((resolve) => release.push(resolve)) };
    const { client } = await serve(webmcpTools({ window: win, allow: ['slow'], tools: [slow], approve: 'never', limits: { maxInflight: 2 } }));
    const a = client.callTool({ name: 'slow', arguments: { q: 'x' } });
    const b = client.callTool({ name: 'slow', arguments: { q: 'x' } });
    await until(() => release.length === 2, 'two calls running');
    await assert.rejects(client.callTool({ name: 'slow', arguments: { q: 'x' } }), /maxInflight/);
    release[0]({ n: 1 }); await a;
    const c = client.callTool({ name: 'slow', arguments: { q: 'x' } });
    await until(() => release.length === 3, 'a third call to start');
    release[1]({ n: 2 }); release[2]({ n: 3 });
    await Promise.all([b, c]);
  });

  it('maxCallsPerMinute: counted per session over a sliding minute, unknown names included', async () => {
    const win = createFakeWindow();
    let clock = 1_000_000;
    const { client } = await serve(webmcpTools({ window: win, allow: ['search'], tools: [read], limits: { maxCallsPerMinute: 3 }, now: () => clock }));
    await client.callTool({ name: 'search', arguments: { q: 'x' } });
    await assert.rejects(client.callTool({ name: 'nothing', arguments: {} }), /unknown tool/);
    await client.callTool({ name: 'search', arguments: { q: 'x' } });
    await assert.rejects(client.callTool({ name: 'search', arguments: { q: 'x' } }), /maxCallsPerMinute/);
    clock += 61_000;
    await client.callTool({ name: 'search', arguments: { q: 'x' } });
  });

  it('arguments are checked against the schema\'s required properties and basic types', async () => {
    const win = createFakeWindow();
    const { client } = await serve(webmcpTools({ window: win, allow: ['search'], tools: [read] }));
    await assert.rejects(client.callTool({ name: 'search', arguments: {} }), /missing required argument "q"/);
    await assert.rejects(client.callTool({ name: 'search', arguments: { q: 5 } }), /"q" must be string/);
  });

  it('the defaults are the documented ones', () => {
    assert.deepEqual({ ...WEBMCP_DEFAULT_LIMITS }, { maxTools: 64, maxSchemaBytes: 16384, maxInputBytes: 65536, maxResultBytes: 262144, maxInflight: 4, maxCallsPerMinute: 30, callTimeoutMs: 120000, maxSubscriptions: 4 });
  });
});

describe('approval: the person at the page', () => {
  const whoAsked = { user: 'alice', fingerprint: 'dd'.repeat(32) };
  function setup(approve, prompt) {
    const win = createFakeWindow();
    const e = { log: [] };
    return { win, e, handler: webmcpTools({ window: win, allow: ['search', 'buy'], tools: [read, write], approve, prompt, onCall: (x) => e.log.push(x) }) };
  }

  it("'consequential' (the default) asks for a tool not marked read-only, with the call and who, and not for a read-only one", async () => {
    const asked = [];
    const { win, handler } = setup(undefined, async (call, who, extra) => { asked.push({ call, who, signal: extra.signal instanceof AbortSignal }); return true; });
    void win;
    const { client } = await serve(handler, whoAsked);
    await client.callTool({ name: 'search', arguments: { q: 'x' } });
    assert.equal(asked.length, 0);
    const r = await client.callTool({ name: 'buy', arguments: { sku: 'A1' } });
    assert.deepEqual(r.structuredContent, { bought: 'A1' });
    assert.equal(asked.length, 1);
    assert.deepEqual(asked[0].call, { name: 'buy', title: 'Buy', description: 'Buy a product', input: { sku: 'A1' }, consequential: true, readOnly: false });
    assert.deepEqual(asked[0].who, { username: 'alice', fingerprint: 'dd'.repeat(32) });
    assert.equal(asked[0].signal, true);
  });

  it('Deny is an MCP error and the tool does not run', async () => {
    let ran = 0;
    const win = createFakeWindow();
    const buy = { ...write, execute: () => { ran++; return {}; } };
    const { client } = await serve(webmcpTools({ window: win, allow: ['buy'], tools: [buy], prompt: async () => false }), whoAsked);
    await assert.rejects(client.callTool({ name: 'buy', arguments: {} }), /denied: the person at the page did not allow/);
    assert.equal(ran, 0);
  });

  it("'always' asks for every call, 'never' for none", async () => {
    let asked = 0;
    const always = setup('always', async () => { asked++; return true; });
    const a = await serve(always.handler, whoAsked);
    await a.client.callTool({ name: 'search', arguments: { q: 'x' } });
    assert.equal(asked, 1);
    asked = 0;
    const never = setup('never', async () => { asked++; return false; });
    const n = await serve(never.handler, whoAsked);
    await n.client.callTool({ name: 'buy', arguments: {} });
    assert.equal(asked, 0);
  });

  it('a prompt that throws or answers anything but true denies', async () => {
    for (const prompt of [async () => { throw new Error('x'); }, async () => 'yes', async () => undefined, () => 1]) {
      const { handler } = setup('always', prompt);
      const { client } = await serve(handler, whoAsked);
      await assert.rejects(client.callTool({ name: 'search', arguments: { q: 'x' } }), /denied/);
    }
  });

  it('questions are asked one at a time, in order', async () => {
    const order = [];
    const resolvers = [];
    const { handler } = setup('always', (call) => new Promise((resolve) => { order.push(call.input.q); resolvers.push(resolve); }));
    const { client } = await serve(handler, whoAsked);
    const a = client.callTool({ name: 'search', arguments: { q: 'one' } });
    const b = client.callTool({ name: 'search', arguments: { q: 'two' } });
    await until(() => order.length === 1, 'the first question');
    await tick(); await tick();
    assert.deepEqual(order, ['one'], 'the second question waits for the first');
    resolvers[0](true); await a;
    await until(() => order.length === 2, 'the second question');
    resolvers[1](true); await b;
    assert.deepEqual(order, ['one', 'two']);
  });

  it('a call cancelled while the question is open aborts the question\'s signal', async () => {
    let signal;
    const { handler } = setup('always', (_c, _w, extra) => new Promise((resolve) => { signal = extra.signal; signal.addEventListener('abort', () => resolve(false)); }));
    const { client } = await serve(handler, whoAsked);
    const ctl = new AbortController();
    const pending = client.callTool({ name: 'search', arguments: { q: 'x' } }, undefined, { signal: ctl.signal });
    pending.catch(() => {});
    await until(() => signal, 'the question');
    ctl.abort();
    await until(() => signal.aborted, 'the question to be aborted');
  });

  it('with no document and no prompt a call that needs approval is denied (nobody to ask), and a read-only one is not', async () => {
    const win = createFakeWindow({ document: false });
    const { client } = await serve(webmcpTools({ window: win, allow: ['search', 'buy'], tools: [read, write] }), whoAsked);
    await client.callTool({ name: 'search', arguments: { q: 'x' } });
    await assert.rejects(client.callTool({ name: 'buy', arguments: {} }), /denied/);
  });

  it('guard: once the window is gone every call is refused', async () => {
    const win = createFakeWindow();
    let why = null;
    const { client } = await serve(webmcpTools({ window: win, allow: ['search'], tools: [read], guard: () => why }));
    await client.callTool({ name: 'search', arguments: { q: 'x' } });
    why = 'the window navigated to another origin';
    await assert.rejects(client.callTool({ name: 'search', arguments: { q: 'x' } }), /navigated to another origin/);
  });
});

describe('the default dialog', () => {
  const call = { name: 'buy', title: 'Buy', description: 'Buy a product', input: { sku: '<script>alert(1)</script>' }, consequential: true, readOnly: false };
  const who = { username: 'alice', fingerprint: 'ee'.repeat(32) };

  it('shows the tool, the caller\'s key fingerprint and the input as text, as an accessible modal dialog', async () => {
    const win = createFakeWindow();
    const opener = win.document.createElement('button'); win.document.body.appendChild(opener); opener.focus();
    const prompt = createDomPrompt(win);
    const answer = prompt(call, who);
    const [dialog] = byRole(win, 'approval');
    assert.equal(dialog.getAttribute('role'), 'alertdialog');
    assert.equal(dialog.getAttribute('aria-modal'), 'true');
    const title = dialog.findAll((e) => e.getAttribute('id') === dialog.getAttribute('aria-labelledby'))[0];
    assert.match(title.textContent, /"Buy"/);
    assert.ok(dialog.findAll((e) => e.getAttribute('id') === dialog.getAttribute('aria-describedby')).length === 1);
    const text = dialog.textContent;
    assert.match(text, /Tool: buy/);
    assert.ok(text.includes('ee'.repeat(32)), 'the key fingerprint');
    const [pre] = byRole(win, 'approval-input');
    assert.ok(pre.textContent.includes('<script>alert(1)</script>'), 'the input is shown verbatim as text');
    assert.equal(dialog.findAll((e) => e.tagName === 'SCRIPT').length, 0, 'nothing was parsed as markup');
    assert.equal(win.document.activeElement, byRole(win, 'deny')[0], 'the safe answer has the focus');
    byRole(win, 'allow')[0].click();
    assert.equal(await answer, true);
    assert.equal(byRole(win, 'approval').length, 0, 'the dialog is gone');
    assert.equal(win.document.activeElement, opener, 'focus goes back');
  });

  it('Deny, Escape and an abort answer no; Tab stays inside the dialog', async () => {
    const win = createFakeWindow();
    const prompt = createDomPrompt(win);
    let answer = prompt(call, who);
    byRole(win, 'deny')[0].click();
    assert.equal(await answer, false);

    answer = prompt(call, who);
    const [dialog] = byRole(win, 'approval');
    const tab = dialog.dispatch('keydown', { key: 'Tab' });
    assert.ok(tab.defaultPrevented);
    assert.equal(win.document.activeElement, byRole(win, 'allow')[0]);
    dialog.dispatch('keydown', { key: 'Tab' });
    assert.equal(win.document.activeElement, byRole(win, 'deny')[0]);
    dialog.dispatch('keydown', { key: 'Escape' });
    assert.equal(await answer, false);

    const ctl = new AbortController();
    answer = prompt(call, who, { signal: ctl.signal });
    ctl.abort();
    assert.equal(await answer, false);
    assert.equal(byRole(win, 'approval').length, 0);
    ctl.abort();
    assert.equal(await prompt(call, who, { signal: ctl.signal }), false, 'an already-aborted signal asks nothing');
  });

  it('a timeout denies', async () => {
    const win = createFakeWindow();
    const timers = manualTimers();
    const answer = createDomPrompt(win, { timers, timeoutMs: 5000 })(call, who);
    assert.equal(timers.timeouts.size, 1);
    assert.equal([...timers.timeouts.values()][0].ms, 5000);
    timers.run();
    assert.equal(await answer, false);
    assert.equal(byRole(win, 'approval').length, 0);
  });

  it('is the prompt of webmcpTools when the window has a document: Allow runs the tool, Deny is an error', async () => {
    const win = createFakeWindow();
    const { client } = await serve(webmcpTools({ window: win, allow: ['buy'], tools: [write] }), who);
    const first = client.callTool({ name: 'buy', arguments: { sku: 'A1' } });
    await until(() => byRole(win, 'approval').length === 1, 'the dialog');
    byRole(win, 'allow')[0].click();
    assert.deepEqual((await first).structuredContent, { bought: 'A1' });
    const second = client.callTool({ name: 'buy', arguments: { sku: 'A2' } });
    second.catch(() => {});
    await until(() => byRole(win, 'approval').length === 1, 'the dialog');
    byRole(win, 'deny')[0].click();
    await assert.rejects(second, /denied/);
  });

  it('needs a window with a document', () => {
    assert.throws(() => createDomPrompt(createFakeWindow({ document: false })), /no document/);
  });
});
