// test/page-host-connect.test.mjs -- the dial-out form of the page host (#219): `createPageHost({ connect })` dials an endpoint that WAITS (an operator that listens)
// instead of a pipe relay, and serves the same sealed key login behind it, with the same approval, indicator and Stop. Off unless written. A fake window throughout;
// the listener is a real WebSocket server in this process that wraps what it accepts as a duplex and logs in as the operator.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocketServer } from 'ws';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { createPageHost, captureWebMcp } from '@johnhenry/wsh/page';
import { connectWshOverDuplex } from '@johnhenry/wsh/duplex';
import { generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, mcpClientTransport } from '@johnhenry/wsh';
import { createFakeWindow, manualTimers, byRole } from './helpers/fake-window.mjs';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
async function until(cond, what, ms = 5000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 5)); }
}

let alice; let aliceLine; let aliceFp;
before(async () => {
  alice = await generateKeyPair(true);
  aliceLine = await exportPublicKeySSH(alice.publicKey);
  aliceFp = await fingerprint(await exportPublicKeyRaw(alice.publicKey));
});

const read = { name: 'search', description: 'Search products', inputSchema: { type: 'object', properties: { q: { type: 'string' } }, required: ['q'] }, annotations: { readOnlyHint: true }, execute: ({ q }) => ({ hits: [`${q}-1`] }) };
const write = { name: 'buy', title: 'Buy', description: 'Buy a product', inputSchema: { type: 'object', properties: { sku: { type: 'string' } } }, execute: ({ sku }) => ({ bought: sku }) };

/** An operator that listens: it accepts what dials it, and records the request path (the page must use the URL as written). */
async function listener() {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  const arrivals = [];
  // The host speaks first: what arrives before the test attaches its operator waits in `queue`.
  wss.on('connection', (ws, req) => {
    const entry = { ws, url: req.url, queue: [], sink: null };
    ws.on('message', (d) => { if (entry.sink) entry.sink(d); else entry.queue.push(d); });
    arrivals.push(entry);
  });
  closers.push(() => new Promise((r) => { for (const c of wss.clients) c.terminate(); wss.close(() => r()); }));
  return { port: wss.address().port, url: (p = '/') => `ws://127.0.0.1:${wss.address().port}${p}`, arrivals };
}

/** Log in over an accepted socket as the operator: the page is the wsh host, so this side is the wsh client. */
function operatorOver(entry, { keyPair = alice, username = 'alice', expectHostKey, ...rest }) {
  const { ws } = entry;
  const link = connectWshOverDuplex({ send: (b) => ws.send(b), close: () => ws.close(1000) }, { username, keyPair, expectHostKey, timeout: 3000, ...rest });
  entry.sink = (d) => link.receive(d);
  for (const d of entry.queue.splice(0)) link.receive(d);
  ws.on('close', () => link.end('the page closed the connection'));
  closers.push(() => link.close());
  return link;
}

async function startPage(connect, options = {}) {
  const win = options.window ?? createFakeWindow();
  captureWebMcp(win);
  for (const t of options.registered ?? [read, write]) await win.document?.modelContext.registerTool(t);
  const log = []; const refused = []; const sessionsSeen = [];
  const timers = manualTimers();
  const host = await createPageHost({
    window: win, connect, name: 'shop-tab', authorizedKeys: options.authorizedKeys ?? [aliceLine],
    mcp: { allow: ['search', 'buy'], approve: 'consequential', ...options.mcp },
    timers: { setInterval: timers.setInterval, clearInterval: timers.clearInterval },
    onLog: (l) => log.push(l), onRefused: (r) => refused.push(r), onSession: (w) => { sessionsSeen.push(w); },
    ...options.host,
  });
  closers.push(() => host.close());
  return { win, host, log, refused, sessionsSeen };
}

describe('the dial-out form: what it refuses to start with', () => {
  const ok = { name: 'x', authorizedKeys: ['k'], mcp: { allow: [] } };
  const win = () => createFakeWindow();
  it('relay or connect, one of them: both, neither, and a connect that is not a ws:// or wss:// URL are refused with a sentence', async () => {
    await assert.rejects(createPageHost({ ...ok, window: win(), relay: 'ws://127.0.0.1:1', connect: 'ws://127.0.0.1:2' }), /relay or connect, not both/);
    await assert.rejects(createPageHost({ ...ok, window: win() }), /relay is required.*connect/s);
    for (const bad of ['', 'https://operator.example/', 'http://x/', 'operator.example:9000', 'ws://user:pw@operator.example/', 'wss://operator.example/#frag', 5, null, {}, { url: 5 }]) {
      await assert.rejects(createPageHost({ ...ok, window: win(), connect: bad }), /connect/, JSON.stringify(bad));
    }
  });
  it('nothing is dialled unless connect (or relay) is written: a window whose WebSocket is a spy sees no connection from a refused start', async () => {
    let dialled = 0;
    function Spy() { dialled++; throw new Error('no'); }
    await assert.rejects(createPageHost({ ...ok, window: createFakeWindow({ WebSocket: Spy }), connect: 'https://not-a-websocket.example/' }), /connect/);
    await assert.rejects(createPageHost({ ...ok, window: createFakeWindow({ WebSocket: Spy }) }), /relay is required/);
    assert.equal(dialled, 0);
  });
});

describe('a page host that dials an operator that waits', () => {
  it('dials the URL exactly as written (no role or rendezvous id added), serves the same sealed key login, and says it has no operatorUrl', async () => {
    const l = await listener();
    const page = await startPage(l.url('/page-hosts/shop?token=abc'));
    assert.equal(page.host.operatorUrl, null);
    assert.equal(page.host.rendezvousId, null);
    const arrival = await until(() => l.arrivals[0], 'the page to dial');
    assert.equal(arrival.url, '/page-hosts/shop?token=abc');
    const link = operatorOver(arrival, { expectHostKey: page.host.fingerprint });
    const wsh = await link.connected;
    assert.equal(wsh.sessionSealed, true);
    const channel = await wsh.openRpc('mcp');
    const mcp = new Client({ name: 'agent', version: '1' }, { capabilities: {} });
    await mcp.connect(mcpClientTransport(channel));
    closers.push(() => mcp.close());
    assert.deepEqual((await mcp.listTools()).tools.map((t) => t.name).sort(), ['buy', 'search']);
    assert.deepEqual((await mcp.callTool({ name: 'search', arguments: { q: 'x' } })).structuredContent, { hits: ['x-1'] });
    assert.deepEqual(page.sessionsSeen, [{ username: 'alice', fingerprint: aliceFp }]);
  });

  it('the log never carries the URL (it may hold a secret in its query), only that the endpoint was dialled', async () => {
    const l = await listener();
    const page = await startPage(l.url('/x?secret=SECRET-IN-QUERY'));
    await until(() => l.arrivals[0], 'the page to dial');
    assert.ok(page.log.some((line) => /dialed the operator endpoint/.test(line)));
    assert.ok(!page.log.some((line) => /SECRET-IN-QUERY|secret=/.test(line)), page.log.join('\n'));
  });

  it('the same indicator and Stop: a row with the key appears at login; Stop ends the session, refuses that key, and the page dials again for another', async () => {
    const l = await listener();
    const page = await startPage(l.url('/'));
    const first = await until(() => l.arrivals[0], 'the page to dial');
    const link = operatorOver(first, { expectHostKey: page.host.fingerprint });
    const wsh = await link.connected;
    await wsh.openRpc('mcp');
    await until(() => page.win.document.find('session', aliceFp).length === 1, 'the indicator row');
    byRole(page.win, 'stop')[0].click();
    await until(() => page.host.sessions.length === 0, 'the session to end');
    await until(() => page.win.document.find('session').length === 0, 'the indicator to go');
    // The page dials again (the host serves the next arrival); the same key is not let back in.
    const second = await until(() => l.arrivals[1], 'the page to dial again');
    const again = operatorOver(second, { expectHostKey: page.host.fingerprint });
    await assert.rejects(again.connected);
    await until(() => page.refused.some((r) => r.reason === 'unauthorized' || r.reason === 'revoked' || /revok|unauthor/i.test(r.reason)), 'a refusal');
  });

  it('the same approval: a tool that changes something asks the person at the page, and is denied when they say no', async () => {
    const l = await listener();
    const asked = [];
    const page = await startPage(l.url('/'), { mcp: { prompt: async (q) => { asked.push(q.tool ?? q.name ?? 'asked'); return false; } } });
    const arrival = await until(() => l.arrivals[0], 'the page to dial');
    const wsh = await operatorOver(arrival, { expectHostKey: page.host.fingerprint }).connected;
    const channel = await wsh.openRpc('mcp');
    const mcp = new Client({ name: 'agent', version: '1' }, { capabilities: {} });
    await mcp.connect(mcpClientTransport(channel));
    closers.push(() => mcp.close());
    await assert.rejects(mcp.callTool({ name: 'buy', arguments: { sku: 'A' } }), /the person at the page did not allow the call to "buy"/);
    assert.equal(asked.length, 1);
    assert.deepEqual((await mcp.callTool({ name: 'search', arguments: { q: 'y' } })).structuredContent, { hits: ['y-1'] }, 'a read-only tool is not asked about');
    assert.equal(asked.length, 1);
  });

  it('a stranger at the endpoint can do nothing without an authorized key: an unknown key is refused, a plain (unsealed) session serves nothing', async () => {
    const l = await listener();
    const page = await startPage(l.url('/'));
    const arrival = await until(() => l.arrivals[0], 'the page to dial');
    const stranger = await generateKeyPair(true);
    await assert.rejects(operatorOver(arrival, { keyPair: stranger, expectHostKey: page.host.fingerprint }).connected);
    await until(() => page.refused.some((r) => r.reason === 'unauthorized'), 'an unauthorized refusal');
    assert.equal(page.host.sessions.length, 0);
  });

  it('after a session the page dials again by default; with reconnect: false it does not, and close() stops the dialling', async () => {
    const l = await listener();
    const page = await startPage(l.url('/'), { host: { reconnect: false } });
    const first = await until(() => l.arrivals[0], 'the page to dial');
    first.ws.close(1000);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(l.arrivals.length, 1, 'no second dial');
    await page.host.close();
    assert.equal(page.host.closed, true);
  });

  it('an endpoint that is not there is retried with a backoff, never in a loop (the log says it failed, the page keeps serving nothing)', async () => {
    const win = createFakeWindow();
    captureWebMcp(win);
    const timers = manualTimers();
    const log = [];
    const host = await createPageHost({ window: win, connect: 'ws://127.0.0.1:1/', name: 'x', authorizedKeys: [aliceLine], mcp: { allow: [] }, timers: { setInterval: timers.setInterval, clearInterval: timers.clearInterval, setTimeout: timers.setTimeout, clearTimeout: timers.clearTimeout }, onLog: (l) => log.push(l) });
    closers.push(() => host.close());
    await until(() => timers.timeouts.size === 1, 'one redial scheduled after the failed dial');
    assert.equal(log.filter((l) => /dialed the operator endpoint/.test(l)).length, 1, 'one dial so far: the next waits for its timer (a backoff), it is not a loop');
    const [{ ms }] = [...timers.timeouts.values()];
    assert.ok(ms >= 1000, 'the first retry waits at least a second');
    assert.equal(host.sessions.length, 0);
    assert.equal(host.closed, false);
  });
});
