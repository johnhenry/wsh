// MCP 2026-07-28 answered natively by the tool server of `webmcpTools`, served over any duplex by `serveMcpOverDuplex` (#302): `server/discover`,
// per-request `_meta` (an unknown version is -32022), `resultType` and the cache hints, `subscriptions/listen` for tool list changes, a
// deterministic `tools/list`; and, unchanged, the legacy `initialize` session. Tools only. Also: what a wrapper that adds this from outside
// (browsermesh-mcp 0.3.0's `modern.mjs`) sees when wsh answers it itself, and the MCP SDK 2.x `Client` (a devDependency) in its three modes.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/client';
import { serveMcpOverDuplex } from '@johnhenry/wsh/page';
import { RPC_ERROR } from '../src/rpc.mjs';
import { webmcpTools, captureWebMcp, WEBMCP_DEFAULT_LIMITS } from '../src/webmcp.mjs';
import { SUPPORTED_PROTOCOL_VERSIONS, UNSUPPORTED_PROTOCOL_VERSION } from '../src/mcp-modern.mjs';
import { createFakeWindow } from './helpers/fake-window.mjs';

const VERSION = 'io.modelcontextprotocol/protocolVersion';
const CAPS = 'io.modelcontextprotocol/clientCapabilities';
const INFO = 'io.modelcontextprotocol/clientInfo';
const SERVER_INFO = 'io.modelcontextprotocol/serverInfo';
const SUB = 'io.modelcontextprotocol/subscriptionId';
const modern = (extra = {}) => ({ _meta: { [VERSION]: '2026-07-28', [CAPS]: {}, [INFO]: { name: 'test', version: '1' }, ...extra } });

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
async function until(cond, what, ms = 3000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 2)); }
}
/** Nothing arrives that matches `pred` for `ms` (the absence of a message cannot be polled for; this is a bound, not a fixed wait before an assertion on something that must arrive). */
const quiet = (ms = 40) => new Promise((r) => setTimeout(r, ms));

const tool = (name, extra = {}) => ({ name, description: `the ${name} tool`, inputSchema: { type: 'object', properties: { q: { type: 'string' } } }, annotations: { readOnlyHint: true }, execute: ({ q } = {}) => ({ name, q }), ...extra });

/** The server end over structured clone, and the raw far side (JSON-RPC by hand). */
function raw(handler, options = {}) {
  const inbox = [];
  const server = serveMcpOverDuplex(handler, { send: (m) => { inbox.push(structuredClone(m)); }, ...options });
  closers.push(async () => server.close());
  const ask = (m) => { queueMicrotask(() => server.receive(structuredClone(m))); };
  const reply = (id) => until(() => inbox.find((m) => m.id === id), `a reply to ${JSON.stringify(id)}`);
  const call = async (id, method, params) => { ask({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) }); return reply(id); };
  const notes = (method) => inbox.filter((m) => m.method === method && !('id' in m));
  return { server, inbox, ask, reply, call, notes };
}

function make({ tools = [tool('search'), tool('buy', { annotations: {} })], allow = ['search', 'buy', 'later'], ...rest } = {}) {
  const win = createFakeWindow();
  const capture = captureWebMcp(win);
  const events = [];
  const handler = webmcpTools({ window: win, allow, tools, capture, approve: 'never', onCall: (e) => events.push(e), ...rest });
  return { win, capture, events, handler };
}

describe('server/discover', () => {
  it('answers with the versions it speaks, the tools capability only, the cache fields, and no tool names', async () => {
    const { handler } = make();
    const r = raw(handler);
    const answer = await r.call(1, 'server/discover', modern());
    assert.equal(answer.error, undefined);
    const res = answer.result;
    assert.equal(res.resultType, 'complete');
    assert.deepEqual(res.supportedVersions, ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05']);
    assert.deepEqual(res.supportedVersions, [...SUPPORTED_PROTOCOL_VERSIONS]);
    assert.deepEqual(res.capabilities, { tools: { listChanged: true } });
    assert.equal(res.ttlMs, 0);
    assert.equal(res.cacheScope, 'private');
    assert.match(res.instructions, /untrusted/);
    assert.deepEqual(res._meta[SERVER_INFO], { name: 'wsh-page', version: '1' });
    const text = JSON.stringify(res);
    assert.ok(!/search|buy|later/.test(text), 'a caller that has only the right to open the channel learns no tool name from discover');
  });

  it('a request that does not say it is 2026-07-28 is not a discover request: -32602, and an unknown version is -32022', async () => {
    const r = raw(make().handler);
    assert.equal((await r.call(1, 'server/discover')).error.code, RPC_ERROR.INVALID_PARAMS);
    assert.equal((await r.call(2, 'server/discover', { _meta: { [VERSION]: '2025-11-25' } })).error.code, RPC_ERROR.INVALID_PARAMS);
    const old = await r.call(3, 'server/discover', modern({ [VERSION]: '1900-01-01' }));
    assert.equal(old.error.code, -32022);
  });
});

describe('the version of a request', () => {
  it('an unknown version answers UnsupportedProtocolVersion (-32022) with the supported ones, before anything runs', async () => {
    const { handler, events } = make();
    const r = raw(handler);
    for (const [id, version] of [[1, '1900-01-01'], [2, '2026-08-01'], [3, 20260728], [4, 'x'.repeat(500)]]) {
      const answer = await r.call(id, 'tools/call', { name: 'search', arguments: { q: 'x' }, ...modern({ [VERSION]: version }) });
      assert.equal(answer.error.code, -32022, JSON.stringify(version).slice(0, 20));
      assert.equal(answer.error.message, 'Unsupported protocol version');
      assert.deepEqual(answer.error.data.supported, [...SUPPORTED_PROTOCOL_VERSIONS]);
      assert.ok(String(answer.error.data.requested).length <= 64);
      assert.equal(answer.result, undefined);
    }
    assert.deepEqual(events, [], 'no call ran, was refused by a limit or asked a person');
    const list = await r.call(5, 'tools/list', modern({ [VERSION]: 'nope' }));
    assert.equal(list.error.code, -32022);
  });

  it('a 2026-07-28 request without clientCapabilities is malformed (-32602); with them, and clientInfo or not, it is served', async () => {
    const r = raw(make().handler);
    const bad = await r.call(1, 'tools/list', { _meta: { [VERSION]: '2026-07-28' } });
    assert.equal(bad.error.code, RPC_ERROR.INVALID_PARAMS);
    assert.match(bad.error.message, /clientCapabilities/);
    assert.equal((await r.call(2, 'tools/list', { _meta: { [VERSION]: '2026-07-28', [CAPS]: {} } })).result.resultType, 'complete');
  });

  it('a legacy version named in _meta is served in the legacy shape', async () => {
    const r = raw(make().handler);
    const answer = await r.call(1, 'tools/list', { _meta: { [VERSION]: '2025-11-25' } });
    assert.equal(answer.result.resultType, undefined);
    assert.equal(answer.result.ttlMs, undefined);
    assert.deepEqual(answer.result.tools.map((t) => t.name), ['buy', 'search']);
  });
});

describe('results of the two eras', () => {
  it('modern results carry resultType, who answered, and tools/list the cache hints (private, ttl 0); legacy results are what they were', async () => {
    const r = raw(make().handler);
    const m = (await r.call(1, 'tools/list', modern())).result;
    assert.equal(m.resultType, 'complete');
    assert.equal(m.ttlMs, 0);
    assert.equal(m.cacheScope, 'private');
    assert.deepEqual(m._meta[SERVER_INFO], { name: 'wsh-page', version: '1' });
    const l = (await r.call(2, 'tools/list')).result;
    assert.deepEqual(Object.keys(l), ['tools'], 'no resultType, no ttlMs, no cacheScope, no _meta for a legacy caller');
    assert.deepEqual(l.tools, m.tools);

    const mc = (await r.call(3, 'tools/call', { name: 'search', arguments: { q: 'x' }, ...modern() })).result;
    assert.equal(mc.resultType, 'complete');
    assert.equal(mc._meta['wsh/untrusted'], true, 'the untrusted label stays');
    assert.equal(mc.ttlMs, undefined, 'only lists are cacheable');
    const lc = (await r.call(4, 'tools/call', { name: 'search', arguments: { q: 'x' } })).result;
    assert.equal(lc.resultType, undefined);
    assert.deepEqual(lc._meta, { 'wsh/untrusted': true });
    assert.deepEqual(lc.content, mc.content);
  });

  it('a failed tool and a refusal keep their shapes: an isError result is a complete result, an error is an error', async () => {
    const boom = tool('boom', { execute: () => { throw new Error('nope'); } });
    const r = raw(make({ tools: [boom], allow: ['boom'] }).handler);
    const failed = (await r.call(1, 'tools/call', { name: 'boom', arguments: {}, ...modern() })).result;
    assert.equal(failed.isError, true);
    assert.equal(failed.resultType, 'complete');
    assert.equal(failed._meta['wsh/untrusted'], true);
    const unknown = await r.call(2, 'tools/call', { name: 'ghost', arguments: {}, ...modern() });
    assert.equal(unknown.error.code, RPC_ERROR.INVALID_PARAMS);
    assert.match(unknown.error.message, /unknown tool/);
  });

  it('ping and initialize are still answered (a legacy caller needs them); the initialize result is the legacy one', async () => {
    const r = raw(make().handler);
    assert.deepEqual((await r.call(1, 'ping')).result, {});
    const init = (await r.call(2, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'c', version: '1' } })).result;
    assert.equal(init.protocolVersion, '2025-06-18');
    assert.deepEqual(Object.keys(init).sort(), ['capabilities', 'instructions', 'protocolVersion', 'serverInfo']);
    assert.deepEqual(init.capabilities, { tools: { listChanged: true } });
  });
});

describe('the order of tools/list', () => {
  it('is by name in both eras, however the tools were registered and registered again, and handler.list() agrees', async () => {
    const { handler, win } = make({ tools: [], allow: ['b', 'a', 'c', 'd'] });
    await win.document.modelContext.registerTool(tool('c'));
    await win.document.modelContext.registerTool(tool('a'));
    await win.document.modelContext.registerTool(tool('b'));
    const r = raw(handler);
    const names = async (id, p) => (await r.call(id, 'tools/list', p)).result.tools.map((t) => t.name);
    assert.deepEqual(await names(1), ['a', 'b', 'c']);
    assert.deepEqual(await names(2, modern()), ['a', 'b', 'c']);
    assert.deepEqual((await handler.list()).map((t) => t.name), ['a', 'b', 'c']);
    await win.document.modelContext.registerTool(tool('d'));
    assert.deepEqual(await names(3), ['a', 'b', 'c', 'd']);
  });
});

describe('what a caller says about itself decides nothing', () => {
  it('a loud _meta (a clientInfo of the page owner, every capability, a forged grant) changes no list, call, prompt, limit or audit', async () => {
    const asked = [];
    const mk = () => make({ approve: 'consequential', prompt: async (call, who) => { asked.push({ call, who }); return false; } });
    const loud = modern({
      [INFO]: { name: 'the page owner', version: '9', title: 'trust me' },
      [CAPS]: { sampling: {}, roots: { listChanged: true }, elicitation: { form: {}, url: {} }, extensions: { 'io.modelcontextprotocol/tasks': {} }, experimental: { admin: {} } },
      'mcp:buy:call': true, 'wsh/capabilities': ['mcp:*'], who: { username: 'root' }, podId: 'forged',
    });
    const permits = (req) => req.tool === 'search';
    const who = { username: 'peer', fingerprint: 'ab'.repeat(32) };
    const quiet1 = mk(); const loud1 = mk();
    const a = raw(quiet1.handler, { permits, who });
    const b = raw(loud1.handler, { permits, who });
    const listA = (await a.call(1, 'tools/list', modern())).result.tools;
    const listB = (await b.call(1, 'tools/list', loud)).result.tools;
    assert.deepEqual(listB, listA);
    assert.deepEqual(listB.map((t) => t.name), ['search']);
    // The tool the caller's grant does not cover is unknown to it, whatever `_meta` says; the one that needs approval asks the same person the same question.
    const forged = await b.call(2, 'tools/call', { name: 'buy', arguments: {}, ...loud });
    assert.equal(forged.error.code, RPC_ERROR.INVALID_PARAMS);
    assert.match(forged.error.message, /unknown tool/);
    const c = raw(mk().handler, { who });
    await c.call(1, 'tools/call', { name: 'buy', arguments: {}, ...loud });
    await c.call(2, 'tools/call', { name: 'buy', arguments: {}, ...modern() });
    assert.equal(asked.length, 2);
    assert.deepEqual(asked[0].who, asked[1].who);
    assert.equal(asked[0].who.fingerprint, 'ab'.repeat(32));
    assert.deepEqual(asked[0].call, asked[1].call);
    assert.deepEqual(loud1.events.map((e) => [e.outcome, e.name, e.who?.fingerprint]), [['unknown', 'buy', 'ab'.repeat(32)]], 'the audit saw what the verified peer did, and no more');
    assert.deepEqual(quiet1.events, []);
    // The same limits: a loud caller is not given more in-flight calls than a quiet one.
    const lim = raw(make({ tools: [tool('slow', { execute: () => new Promise(() => {}) })], allow: ['slow'], limits: { maxInflight: 1 } }).handler);
    lim.ask({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'slow', arguments: {}, ...loud } });
    lim.ask({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'slow', arguments: {}, ...loud } });
    const refused = await lim.reply(2);
    assert.equal(refused.error.code, RPC_ERROR.STREAM_LIMIT);
    assert.equal(refused.error.data.limit, 'maxInflight');
  });

  it('what is not offered stays -32601 whatever the caller declares: resources, prompts, sampling, roots, tasks, logging', async () => {
    const r = raw(make().handler);
    let id = 0;
    for (const method of ['resources/list', 'resources/read', 'resources/templates/list', 'prompts/list', 'prompts/get', 'sampling/createMessage', 'roots/list', 'elicitation/create', 'tasks/get', 'logging/setLevel', 'resources/subscribe', 'completion/complete']) {
      const answer = await r.call(++id, method, modern({ [CAPS]: { sampling: {}, roots: {}, elicitation: {}, extensions: { 'io.modelcontextprotocol/tasks': {} } } }));
      assert.equal(answer.error.code, RPC_ERROR.METHOD_NOT_FOUND, method);
    }
  });
});

describe('subscriptions/listen', () => {
  it('acknowledges first, with its id, then tells of a change of the tool list, tagged; a legacy notification is not sent to it', async () => {
    const { handler, win } = make({ tools: [tool('search')] });
    const r = raw(handler);
    r.ask({ jsonrpc: '2.0', id: 'listen-1', method: 'subscriptions/listen', params: { ...modern(), notifications: { toolsListChanged: true } } });
    await until(() => r.notes('notifications/subscriptions/acknowledged').length, 'the acknowledgement');
    assert.deepEqual(r.inbox[0], { jsonrpc: '2.0', method: 'notifications/subscriptions/acknowledged', params: { _meta: { [SUB]: 'listen-1' }, notifications: { toolsListChanged: true } } });
    assert.equal(r.notes('notifications/tools/list_changed').length, 0);
    await win.document.modelContext.registerTool(tool('later'));
    await until(() => r.notes('notifications/tools/list_changed').length, 'the list-changed notification');
    assert.deepEqual(r.notes('notifications/tools/list_changed'), [{ jsonrpc: '2.0', method: 'notifications/tools/list_changed', params: { _meta: { [SUB]: 'listen-1' } } }]);
    assert.ok(r.inbox.indexOf(r.notes('notifications/tools/list_changed')[0]) > 0, 'after the acknowledgement');
    assert.equal(r.inbox.find((m) => m.id === 'listen-1'), undefined, 'the stream is open: the request is not answered');
    assert.deepEqual((await r.call(3, 'tools/list', modern())).result.tools.map((t) => t.name), ['later', 'search']);
  });

  it('what it cannot announce is left out of the acknowledgement, and asking for nothing it has asks for nothing', async () => {
    const r = raw(make().handler);
    r.ask({ jsonrpc: '2.0', id: 1, method: 'subscriptions/listen', params: { ...modern(), notifications: { toolsListChanged: true, promptsListChanged: true, resourcesListChanged: true, resourceSubscriptions: ['file:///x'] } } });
    r.ask({ jsonrpc: '2.0', id: 2, method: 'subscriptions/listen', params: { ...modern(), notifications: { promptsListChanged: true } } });
    await until(() => r.notes('notifications/subscriptions/acknowledged').length === 2, 'both acknowledgements');
    const acked = Object.fromEntries(r.notes('notifications/subscriptions/acknowledged').map((n) => [n.params._meta[SUB], n.params.notifications]));
    assert.deepEqual(acked, { 1: { toolsListChanged: true }, 2: {} });
  });

  it('a change this caller may not list is not announced to it (the list it is compared on is its own)', async () => {
    const { handler, win } = make({ tools: [tool('search')] });
    const r = raw(handler, { permits: (req) => req.tool !== 'later' });
    r.ask({ jsonrpc: '2.0', id: 1, method: 'subscriptions/listen', params: { ...modern(), notifications: { toolsListChanged: true } } });
    await until(() => r.notes('notifications/subscriptions/acknowledged').length, 'the acknowledgement');
    await win.document.modelContext.registerTool(tool('later'));
    await quiet();
    assert.equal(r.notes('notifications/tools/list_changed').length, 0);
    await win.document.modelContext.registerTool(tool('buy'));
    await until(() => r.notes('notifications/tools/list_changed').length, 'a change it may list');
  });

  it('at most limits.maxSubscriptions (default 4) at once, per session: the next is refused by name with -32002, a cancelled one frees its place', async () => {
    assert.equal(WEBMCP_DEFAULT_LIMITS.maxSubscriptions, 4);
    const r = raw(make().handler);
    const listen = (id) => r.ask({ jsonrpc: '2.0', id, method: 'subscriptions/listen', params: { ...modern(), notifications: { toolsListChanged: true } } });
    for (let i = 1; i <= 4; i++) listen(`s${i}`);
    await until(() => r.notes('notifications/subscriptions/acknowledged').length === 4, 'four acknowledgements');
    listen('s5');
    const refused = await r.reply('s5');
    assert.equal(refused.error.code, RPC_ERROR.STREAM_LIMIT);
    assert.equal(refused.error.data.limit, 'maxSubscriptions');
    assert.equal(r.notes('notifications/subscriptions/acknowledged').length, 4, 'a refused one is not acknowledged');
    r.ask({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 's1' } });
    await until(async () => { listen('s6'); await quiet(10); return r.notes('notifications/subscriptions/acknowledged').length === 5; }, 'a place freed by the cancellation');
    assert.equal(r.inbox.find((m) => m.id === 's1'), undefined, 'a cancelled request is not answered');
    // A smaller bound can be set, and is checked like the others.
    const small = raw(make({ limits: { maxSubscriptions: 1 } }).handler);
    small.ask({ jsonrpc: '2.0', id: 1, method: 'subscriptions/listen', params: modern() });
    await until(() => small.notes('notifications/subscriptions/acknowledged').length, 'the one');
    assert.equal((await small.call(2, 'subscriptions/listen', modern())).error.data.limit, 'maxSubscriptions');
    assert.throws(() => webmcpTools({ window: createFakeWindow(), limits: { maxSubscriptions: 0 } }), /positive integer/);
  });

  it('is refused without 2026-07-28 meta and with a filter that is not an object; ending the session ends the streams', async () => {
    const { handler, win } = make();
    const r = raw(handler);
    assert.equal((await r.call(1, 'subscriptions/listen', { notifications: { toolsListChanged: true } })).error.code, RPC_ERROR.INVALID_PARAMS);
    assert.equal((await r.call(2, 'subscriptions/listen', { ...modern(), notifications: 'all' })).error.code, RPC_ERROR.INVALID_PARAMS);
    r.ask({ jsonrpc: '2.0', id: 3, method: 'subscriptions/listen', params: { ...modern(), notifications: { toolsListChanged: true } } });
    await until(() => r.notes('notifications/subscriptions/acknowledged').length, 'the acknowledgement');
    r.server.close('gone');
    const before = r.inbox.length;
    await win.document.modelContext.registerTool(tool('later'));
    await quiet();
    assert.equal(r.inbox.length, before, 'nothing is sent after the session ended');
  });

  it('the legacy list-changed notification works as it did: after initialize + notifications/initialized, untagged; a caller that never asks is told nothing', async () => {
    const { handler, win } = make({ tools: [tool('search')] });
    const legacy = raw(handler);
    const silent = raw(handler);
    await legacy.call(1, 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'c', version: '1' } });
    legacy.ask({ jsonrpc: '2.0', method: 'notifications/initialized' });
    await legacy.call(2, 'tools/list');
    await silent.call(1, 'tools/list', modern());
    await win.document.modelContext.registerTool(tool('later'));
    await until(() => legacy.notes('notifications/tools/list_changed').length, 'the legacy notification');
    assert.deepEqual(legacy.notes('notifications/tools/list_changed'), [{ jsonrpc: '2.0', method: 'notifications/tools/list_changed' }]);
    await quiet();
    assert.equal(silent.notes('notifications/tools/list_changed').length, 0, 'a modern caller that did not open a stream is not told');
  });

  it('a session that is both gets each its own: the untagged one for the handshake, the tagged one for the stream', async () => {
    const { handler, win } = make({ tools: [tool('search')] });
    const r = raw(handler);
    r.ask({ jsonrpc: '2.0', method: 'notifications/initialized' });
    r.ask({ jsonrpc: '2.0', id: 'l', method: 'subscriptions/listen', params: { ...modern(), notifications: { toolsListChanged: true } } });
    await until(() => r.notes('notifications/subscriptions/acknowledged').length, 'the acknowledgement');
    await win.document.modelContext.registerTool(tool('later'));
    await until(() => r.notes('notifications/tools/list_changed').length === 2, 'both');
    const tagged = r.notes('notifications/tools/list_changed').map((n) => n.params?._meta?.[SUB] ?? null).sort();
    assert.deepEqual(tagged, ['l', null]);
  });
});

describe('closeSessions', () => {
  it('tells a legacy caller why (a log message) and ends a caller that has only spoken 2026-07-28 without one (that revision forbids log messages it did not ask for)', async () => {
    const { handler } = make();
    const legacy = raw(handler);
    const mod = raw(handler);
    await legacy.call(1, 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'c', version: '1' } });
    await mod.call(1, 'tools/list', modern());
    assert.equal(await handler.closeSessions('the page is closing'), 2);
    assert.equal(legacy.notes('notifications/message').length, 1);
    assert.equal(legacy.notes('notifications/message')[0].params.data, 'the page is closing');
    assert.equal(mod.notes('notifications/message').length, 0);
    assert.ok(legacy.server.closed && mod.server.closed);
  });
});

describe('error codes', () => {
  it('no code of wsh in the spec-reserved range -32020..-32099 but the spec\'s own -32022, and the codes this handler answers with are the known ones', async () => {
    const reserved = (c) => c <= -32020 && c >= -32099;
    assert.deepEqual(Object.values(RPC_ERROR).filter(reserved), []);
    assert.equal(UNSUPPORTED_PROTOCOL_VERSION, -32022);
    const { handler } = make({ limits: { maxCallsPerMinute: 1, maxSubscriptions: 1 } });
    const r = raw(handler);
    const seen = new Set();
    const note = (a) => { if (a.error) seen.add(a.error.code); return a; };
    note(await r.call(1, 'no/such'));
    note(await r.call(2, 'tools/call', { ...modern() }));
    note(await r.call(3, 'tools/call', { name: 'ghost', arguments: {}, ...modern() }));
    note(await r.call(4, 'tools/call', { name: 'search', arguments: {}, ...modern() }));
    note(await r.call(5, 'tools/list', { _meta: { [VERSION]: 'x' } }));
    note(await r.call(6, 'tools/list', { _meta: { [VERSION]: '2026-07-28' } }));
    note(await r.call(7, 'server/discover'));
    r.ask({ jsonrpc: '2.0', id: 8, method: 'subscriptions/listen', params: modern() });
    await until(() => r.notes('notifications/subscriptions/acknowledged').length, 'ack');
    note(await r.call(9, 'subscriptions/listen', modern()));
    assert.deepEqual([...seen].filter(reserved), [-32022], 'the one reserved code is the spec\'s, used for its meaning');
    for (const code of seen) assert.ok([-32601, -32602, -32002, -32022].includes(code), `unexpected code ${code}`);
  });
});

// ── What browsermesh-mcp 0.3.0's wrapper (`packages/browsermesh-mcp/src/modern.mjs`) does around the handler, as it does it ───────────────────────

/**
 * The call pattern of that wrapper, kept to what it does to wsh's handler (a test double, not its code): `incoming(message)` answers an unknown
 * version and a fifth `subscriptions/listen` BEFORE the seam sees the message; `wrap(handler)` registers `server/discover` and
 * `subscriptions/listen` on the channel AFTER the handler did (so its registration is the one that answers); `startWatching` is a synthetic
 * `notifications/initialized` into the seam; `outgoing(message)` decorates what the seam sends (`{ resultType: 'complete', ...result }`, `ttlMs`
 * only when absent, a sort by name, the fan-out of an untagged list-changed to its own subscriptions) and drops `notifications/message` for a
 * caller that only spoke modern.
 */
function meshWrapper(handler) {
  const META = 'io.modelcontextprotocol/subscriptionId';
  const tracked = new Map();
  const subscriptions = new Map();
  let legacy = false;
  let modernSeen = false;
  const session = { current: null };
  const outbox = [];
  const incoming = (m) => {
    if (typeof m.method !== 'string') return null;
    if (!('id' in m)) { if (m.method === 'notifications/initialized') legacy = true; return null; }
    if (m.method === 'initialize') legacy = true;
    const asked = m.params?._meta?.[VERSION];
    if (asked !== undefined && !SUPPORTED_PROTOCOL_VERSIONS.includes(asked)) return { jsonrpc: '2.0', id: m.id, error: { code: -32022, message: 'Unsupported protocol version', data: { supported: [...SUPPORTED_PROTOCOL_VERSIONS], requested: String(asked) } } };
    if (m.method === 'subscriptions/listen' && subscriptions.size >= 4) return { jsonrpc: '2.0', id: m.id, error: { code: -32002, message: 'refused: more than 4 subscriptions at once', data: { limit: 'maxSubscriptions' } } };
    if (asked !== undefined) modernSeen = true;
    tracked.set(m.id, { method: m.method, modern: asked !== undefined });
    return null;
  };
  const outgoing = (m) => {
    if (typeof m.method === 'string') {
      if (m.method === 'notifications/tools/list_changed' && !('id' in m)) {
        const out = [];
        if (legacy) out.push(m);
        for (const [id, sub] of subscriptions) if (sub.acked) out.push({ jsonrpc: '2.0', method: m.method, params: { _meta: { [META]: id } } });
        return out;
      }
      if (m.method === 'notifications/message' && modernSeen && !legacy) return [];
      return [m];
    }
    const note = 'id' in m ? tracked.get(m.id) : undefined;
    if (note) tracked.delete(m.id);
    if (!note || typeof m.result !== 'object') return [m];
    let result = m.result;
    if (note.method === 'tools/list' && Array.isArray(result.tools)) result = { ...result, tools: [...result.tools].sort((a, b) => (a.name < b.name ? -1 : 1)) };
    if (note.modern) {
      result = { resultType: 'complete', ...result };
      if (note.method === 'tools/list' && result.ttlMs === undefined) result = { ...result, ttlMs: 0, cacheScope: 'private' };
    }
    return [{ ...m, result }];
  };
  const wrapped = (channel, ctx) => {
    handler(channel, ctx);
    channel.onRequest('server/discover', () => ({ resultType: 'complete', supportedVersions: [...SUPPORTED_PROTOCOL_VERSIONS], capabilities: { tools: { listChanged: true } }, ttlMs: 0, cacheScope: 'private', _meta: { [SERVER_INFO]: { name: 'wsh-page', version: '1' } } }));
    channel.onRequest('subscriptions/listen', (params, { id, signal }) => {
      const sub = { acked: false };
      subscriptions.set(id, sub);
      return new Promise((resolve) => {
        signal.addEventListener('abort', () => { subscriptions.delete(id); resolve({}); }, { once: true });
        session.current.receive({ jsonrpc: '2.0', method: 'notifications/initialized' });
        Promise.resolve(channel.notify('notifications/subscriptions/acknowledged', { _meta: { [META]: id }, notifications: { toolsListChanged: true } })).then(() => { sub.acked = true; });
      });
    });
  };
  Object.assign(wrapped, handler);
  const server = serveMcpOverDuplex(wrapped, { send: (m) => { for (const out of outgoing(m)) outbox.push(structuredClone(out)); } });
  session.current = server;
  closers.push(async () => server.close());
  const receive = (m) => { const answer = incoming(m); if (answer) outbox.push(answer); else server.receive(structuredClone(m)); };
  const ask = (m) => queueMicrotask(() => receive(m));
  const reply = (id) => until(() => outbox.find((x) => x.id === id), `a reply to ${id}`);
  return { server, outbox, ask, reply, call: async (id, method, params) => { ask({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) }); return reply(id); }, notes: (method) => outbox.filter((m) => m.method === method && !('id' in m)) };
}

describe('under the wrapper of browsermesh-mcp 0.3.0 (which answers these itself, before and around the handler)', () => {
  it('nothing is handled twice: one resultType, one cache hint, one order; the wrapper\'s discover, version check and stream answer, as before', async () => {
    const { handler } = make({ tools: [tool('search'), tool('buy', { annotations: {} })] });
    const w = meshWrapper(handler);
    const list = (await w.call(1, 'tools/list', modern())).result;
    assert.deepEqual(list.tools.map((t) => t.name), ['buy', 'search']);
    assert.deepEqual([list.resultType, list.ttlMs, list.cacheScope], ['complete', 0, 'private']);
    assert.equal(Object.keys(list).filter((k) => k === 'resultType').length, 1);
    const legacyList = (await w.call(2, 'tools/list')).result;
    assert.deepEqual(Object.keys(legacyList), ['tools']);
    const discover = (await w.call(3, 'server/discover', modern())).result;
    assert.deepEqual(discover.capabilities, { tools: { listChanged: true } });
    assert.equal((await w.call(4, 'tools/list', modern({ [VERSION]: '1900-01-01' }))).error.code, -32022);
    const call = (await w.call(5, 'tools/call', { name: 'search', arguments: { q: 'z' }, ...modern() })).result;
    assert.equal(call.resultType, 'complete');
    assert.equal(call._meta['wsh/untrusted'], true);
  });

  it('a change reaches a modern stream once, tagged, and no untagged one reaches a caller that never did the handshake', async () => {
    const { handler, win } = make({ tools: [tool('search')] });
    const w = meshWrapper(handler);
    w.ask({ jsonrpc: '2.0', id: 'l1', method: 'subscriptions/listen', params: { ...modern(), notifications: { toolsListChanged: true } } });
    w.ask({ jsonrpc: '2.0', id: 'l2', method: 'subscriptions/listen', params: { ...modern(), notifications: { toolsListChanged: true } } });
    await until(() => w.notes('notifications/subscriptions/acknowledged').length === 2, 'two acknowledgements');
    await quiet(20);
    await win.document.modelContext.registerTool(tool('later'));
    await until(() => w.notes('notifications/tools/list_changed').length >= 2, 'the notifications');
    await quiet();
    const notes = w.notes('notifications/tools/list_changed');
    assert.deepEqual(notes.map((n) => n.params._meta[SUB]).sort(), ['l1', 'l2'], 'one per stream, none untagged, none twice');
  });

  it('a caller that only spoke modern is not sent the closing log message: the wrapper drops it, and wsh sends nothing of its own then either', async () => {
    const { handler } = make();
    const w = meshWrapper(handler);
    await w.call(1, 'tools/list', modern());
    await handler.closeSessions('bye');
    assert.equal(w.notes('notifications/message').length, 0);
  });
});

// ── The MCP SDK 2.x Client (devDependency only) ───────────────────────────────────────────────────────────────────────────────────────────────────

/** A Transport made of two function calls to the server end. */
function sdkTransport(handler, options = {}) {
  const transport = { onmessage: null, onclose: null, onerror: null, sessionId: undefined };
  const server = serveMcpOverDuplex(handler, { send: (m) => { const copy = structuredClone(m); queueMicrotask(() => transport.onmessage?.(copy)); }, ...options });
  closers.push(async () => server.close());
  transport.start = async () => {};
  transport.send = async (message) => { queueMicrotask(() => server.receive(structuredClone(message))); };
  transport.close = async () => { server.close('the client left'); transport.onclose?.(); };
  return transport;
}

describe('the MCP SDK 2.x Client', () => {
  for (const [label, versionNegotiation, era] of [['legacy (the SDK default)', undefined, 'legacy'], ['auto', { mode: 'auto' }, 'modern'], ['pinned to 2026-07-28', { mode: { pin: '2026-07-28' } }, 'modern']]) {
    it(`${label}: connects, lists in order, calls, hears of a change, and speaks the ${era} era`, async () => {
      const { handler, win } = make({ tools: [tool('search'), tool('buy', { annotations: {} })] });
      const client = new Client({ name: 'sdk', version: '1' }, { capabilities: {}, ...(versionNegotiation ? { versionNegotiation } : {}) });
      const changed = new Promise((resolve) => client.setNotificationHandler('notifications/tools/list_changed', resolve));
      await client.connect(sdkTransport(handler));
      closers.push(() => client.close());
      assert.equal(client.getProtocolEra(), era);
      if (era === 'modern') assert.equal(client.getNegotiatedProtocolVersion(), '2026-07-28');
      assert.match(client.getInstructions() ?? '', /untrusted/);
      assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['buy', 'search']);
      const result = await client.callTool({ name: 'search', arguments: { q: 'x' } });
      assert.deepEqual(result.structuredContent, { name: 'search', q: 'x' });
      assert.equal(result._meta['wsh/untrusted'], true);
      if (era === 'modern') {
        const sub = await client.listen({ toolsListChanged: true });
        assert.deepEqual(sub.honoredFilter, { toolsListChanged: true });
        await win.document.modelContext.registerTool(tool('later'));
        await changed;
        assert.deepEqual((await client.listTools({}, { cache: 'bypass' })).tools.map((t) => t.name), ['buy', 'later', 'search']);
        await sub.close();
        assert.equal(await sub.closed, 'local');
      } else {
        await win.document.modelContext.registerTool(tool('later'));
        await changed;
        assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['buy', 'later', 'search']);
      }
    });
  }

  it('a client pinned to a version the server does not speak is told so with the versions it does', async () => {
    const { handler } = make();
    const client = new Client({ name: 'sdk', version: '1' }, { capabilities: {}, versionNegotiation: { mode: { pin: '2099-01-01' } } });
    await assert.rejects(client.connect(sdkTransport(handler)), (e) => /2099-01-01|supported|version/i.test(String(e?.message)));
  });
});
