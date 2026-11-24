// test/page-host.test.mjs -- `@johnhenry/wsh/page` (#190): a page host behind a pipe relay serves a window's WebMCP tools as MCP, to key logins on
// sealed sessions only, with an indicator and a Stop control in the page, narrowing by the key's capabilities, closing itself when the window
// leaves its origin. A fake window throughout; the real browser runs the same thing in test/browser/page-webmcp.spec.mjs.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { LoggingMessageNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { createPipeRelay } from '@johnhenry/wsh/pipe-relay';
import { createPageHost, captureWebMcp } from '@johnhenry/wsh/page';
import {
  WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, exportPrivateKeyPKCS8, fingerprint, mcpClientTransport, cborEncode, MSG,
} from '@johnhenry/wsh';
import { hostileRelay } from './helpers/hostile-relay.mjs';
import { createFakeWindow, manualTimers, byRole } from './helpers/fake-window.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
async function until(cond, what, ms = 5000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 5)); }
}

let alice; let bob; let aliceLine; let bobLine; let aliceFp; let bobFp;
before(async () => {
  alice = await generateKeyPair(true); bob = await generateKeyPair(true);
  aliceLine = await exportPublicKeySSH(alice.publicKey); bobLine = await exportPublicKeySSH(bob.publicKey);
  aliceFp = await fingerprint(await exportPublicKeyRaw(alice.publicKey)); bobFp = await fingerprint(await exportPublicKeyRaw(bob.publicKey));
});

const read = { name: 'search', description: 'Search products', inputSchema: { type: 'object', properties: { q: { type: 'string' } }, required: ['q'] }, annotations: { readOnlyHint: true }, execute: ({ q }) => ({ hits: [`${q}-1`] }) };
const write = { name: 'buy', title: 'Buy', description: 'Buy a product', inputSchema: { type: 'object', properties: { sku: { type: 'string' } } }, execute: ({ sku }) => ({ bought: sku }) };

async function relay() {
  const r = createPipeRelay();
  const { port } = await r.listen();
  closers.push(() => r.close());
  return `ws://127.0.0.1:${port}`;
}

/** A page host over a fake window, with the application's tools registered through the capture shim, as a page would. */
async function startPage(options = {}) {
  const win = options.window ?? createFakeWindow();
  captureWebMcp(win);
  for (const t of options.registered ?? [read, write]) await win.document?.modelContext.registerTool(t);
  const log = [];
  const refused = [];
  const sessionsSeen = [];
  const timers = manualTimers();
  const host = await createPageHost({
    window: win, relay: options.relay ?? await relay(), name: 'shop-tab', authorizedKeys: options.authorizedKeys ?? [aliceLine],
    mcp: { allow: ['search', 'buy'], approve: 'consequential', ...options.mcp },
    timers: { setInterval: timers.setInterval, clearInterval: timers.clearInterval },
    onLog: (l) => log.push(l), onRefused: (r) => refused.push(r), onSession: (w) => { sessionsSeen.push(w); },
    ...options.host,
  });
  closers.push(() => host.close());
  return { win, host, log, refused, sessionsSeen, timers };
}

/** An operator: a client sealed to the page through the relay, with an MCP SDK client over its `mcp` channel. */
async function operator(host, { keyPair = alice, username = 'alice', connect = {}, via = host.operatorUrl } = {}) {
  const wsh = new WshClient();
  closers.push(() => wsh.disconnect());
  await wsh.connect(via, { username, keyPair, transport: 'ws', sealSession: true, ...connect });
  const channel = await wsh.openRpc('mcp');
  const mcp = new Client({ name: 'agent', version: '1' }, { capabilities: {} });
  await mcp.connect(mcpClientTransport(channel));
  closers.push(() => mcp.close());
  return { wsh, mcp, channel };
}

describe('createPageHost: what it refuses to start without', () => {
  const ok = { relay: 'ws://127.0.0.1:1', name: 'x', authorizedKeys: ['k'], mcp: { allow: [] } };
  const win = () => createFakeWindow();
  it('a window, a name, authorized keys, a relay and something to serve', async () => {
    await assert.rejects(createPageHost({ ...ok }), /window is required/);
    await assert.rejects(createPageHost({ ...ok, window: win(), name: undefined }), /name is required/);
    await assert.rejects(createPageHost({ ...ok, window: win(), authorizedKeys: undefined }), /no anonymous mode and no password/);
    await assert.rejects(createPageHost({ ...ok, window: win(), authorizedKeys: [] }), /no anonymous mode/);
    await assert.rejects(createPageHost({ ...ok, window: win(), relay: undefined }), /relay is required/);
    await assert.rejects(createPageHost({ ...ok, window: win(), mcp: undefined }), /nothing to serve/);
  });
  it('indicator: false unless unattended: true; a window with no document unless the embedder supplies callbacks or says unattended', async () => {
    await assert.rejects(createPageHost({ ...ok, window: win(), indicator: false }), /unattended: true/);
    await assert.rejects(createPageHost({ ...ok, window: createFakeWindow({ document: false }) }), /no document/);
    await assert.rejects(createPageHost({ ...ok, window: createFakeWindow({ document: false }), indicator: false }), /unattended: true/);
    await assert.rejects(createPageHost({ ...ok, window: win(), indicator: {} }), /connected\(who, control\)/);
    await assert.rejects(createPageHost({ ...ok, window: win(), indicator: 'yes' }), /indicator must be/);
  });
  it('a window with no document and callbacks but nobody to ask: a prompt, approve never, or unattended', async () => {
    const callbacks = { connected() {}, disconnected() {} };
    await assert.rejects(createPageHost({ ...ok, window: createFakeWindow({ document: false }), indicator: callbacks }), /no document to ask the person/);
  });
  it('expose (object access) is not offered here', async () => {
    await assert.rejects(createPageHost({ ...ok, window: win(), expose: { window: {} } }), /expose.*not available/);
  });
  it('a window whose origin cannot be read, and one with no WebSocket', async () => {
    const w1 = win(); w1.location = undefined;
    await assert.rejects(createPageHost({ ...ok, window: w1 }), /window.location.origin/);
    const w2 = win(); w2.WebSocket = undefined;
    await assert.rejects(createPageHost({ ...ok, window: w2 }), /window.WebSocket/);
  });
});

describe('a page host behind a pipe relay', () => {
  it('serves the allowed tools to an MCP client over a sealed session, and the relay sees no tool name or payload', async () => {
    const base = await relay();
    const page = await startPage({ relay: base, mcp: { prompt: async () => true } });
    const via = new URL(page.host.operatorUrl);
    const recorded = await hostileRelay(`${base}${via.pathname}`);
    closers.push(() => recorded.close());
    const { wsh, mcp } = await operator(page.host, { via: recorded.url });
    assert.equal(wsh.sessionSealed, true);
    assert.deepEqual((await mcp.listTools()).tools.map((t) => t.name).sort(), ['buy', 'search']);
    const MARK = 'ZEBRA-MARKER-4471';
    assert.deepEqual((await mcp.callTool({ name: 'search', arguments: { q: MARK } })).structuredContent, { hits: [`${MARK}-1`] });
    const seen = (text) => recorded.seen.some((e) => Buffer.from(cborEncode(e.msg)).includes(Buffer.from(text)));
    assert.ok(!seen(MARK) && !seen('search') && !seen('tools/call'), 'the relay saw a tool name, a method or an argument');
    assert.equal(page.sessionsSeen.length, 1);
    assert.deepEqual(page.sessionsSeen[0], { username: 'alice', fingerprint: aliceFp });
  });

  it('refuses what is not a sealed key login: a plain session, a password, an unknown key', async () => {
    const page = await startPage();
    const client = () => { const c = new WshClient(); closers.push(() => c.disconnect()); return c; };
    const attempt = (connect, kp = alice) => client().connect(page.host.operatorUrl, { username: 'alice', keyPair: kp, transport: 'ws', ...connect });
    // A client that does not seal logs in (the login itself is plain) and is turned away at its first message: nothing is served.
    const c = client();
    await c.connect(page.host.operatorUrl, { username: 'alice', keyPair: alice, transport: 'ws', sealSession: false });
    await assert.rejects(c.openRpc('mcp', { openTimeout: 1000 }));
    await until(() => page.refused.some((r) => r.reason === 'not-sealed'), 'a not-sealed refusal');
    await assert.rejects(attempt({ keyPair: undefined, password: 'hunter2', sealSession: false }, undefined));
    await assert.rejects(attempt({ sealSession: true }, await generateKeyPair(true)));
    await until(() => page.refused.some((r) => r.reason === 'unauthorized'), 'an unauthorized refusal');
    // The host went on to serve the next arrival each time.
    const { mcp } = await operator(page.host);
    assert.equal((await mcp.listTools()).tools.length, 2);
  });

  it('a session holds nothing but the mcp channel: no exec, no file access, no other rpc, no gateway', async () => {
    const page = await startPage({ mcp: { prompt: async () => true } });
    const { wsh } = await operator(page.host);
    await assert.rejects(wsh.openSession({ type: 'exec', command: 'ls' }));
    await assert.rejects(wsh.openSession({ type: 'pty' }));
    await assert.rejects(wsh.openRpc('wsh-host'), /not supported|UNSUPPORTED/);
    await assert.rejects(wsh.openRpc('wsh-fs'), /not supported|UNSUPPORTED/);
    await assert.rejects(wsh.download('/etc/passwd'));
    await assert.rejects(wsh.openEndpoint('anything'));
  });

  it('serves one operator at a time and the next one after it leaves; sessions says who is connected', async () => {
    const page = await startPage({ authorizedKeys: [aliceLine, bobLine] });
    assert.deepEqual(page.host.sessions, []);
    const a = await operator(page.host);
    assert.equal(page.host.sessions.length, 1);
    assert.equal(page.host.sessions[0].fingerprint, aliceFp);
    assert.ok(page.host.sessions[0].since > 0);
    await a.wsh.disconnect();
    await until(() => page.host.sessions.length === 0, 'the session to end');
    const b = await operator(page.host, { keyPair: bob, username: 'bob' });
    assert.equal(page.host.sessions[0].fingerprint, bobFp);
    assert.ok(await b.mcp.listTools());
  });
});

describe('the indicator and Stop', () => {
  it('shows the key\'s fingerprint while a session is connected, and Stop ends it, tells the operator why and keeps that key out', async () => {
    const page = await startPage({ authorizedKeys: [aliceLine, bobLine] });
    assert.equal(byRole(page.win, 'indicator').length, 0, 'nothing is shown while nobody is connected');
    const { wsh, mcp } = await operator(page.host);
    await until(() => byRole(page.win, 'indicator').length === 1, 'the indicator');
    const [badge] = byRole(page.win, 'indicator');
    assert.equal(badge.getAttribute('role'), 'status');
    assert.match(badge.textContent, /Remote session connected to "shop-tab"/);
    assert.ok(badge.textContent.includes(aliceFp));
    assert.equal(byRole(page.win, 'fingerprint')[0].textContent, aliceFp);
    const told = new Promise((resolve) => mcp.setNotificationHandler(LoggingMessageNotificationSchema, (n) => resolve(n.params)));
    const closed = new Promise((resolve) => { wsh.onClose = resolve; });
    byRole(page.win, 'stop')[0].click();
    assert.match((await told).data, /stopped this session/);
    await closed;
    await until(() => page.host.sessions.length === 0 && byRole(page.win, 'indicator').length === 0, 'the indicator to go');
    // The same key is not let straight back in (the host has dialed the relay again by now); another key is.
    await until(() => page.log.filter((l) => /dialed the relay/.test(l)).length === 2, 'the host to dial the relay again');
    const c = new WshClient(); closers.push(() => c.disconnect());
    await assert.rejects(c.connect(page.host.operatorUrl, { username: 'alice', keyPair: alice, transport: 'ws', sealSession: true }), /auth|denied|not authorized|fail/i);
    assert.ok(page.refused.some((r) => r.reason === 'unauthorized' && r.who.fingerprint === aliceFp), JSON.stringify(page.refused));
    const b = await operator(page.host, { keyPair: bob, username: 'bob' });
    assert.ok(await b.mcp.listTools());
  });

  it('revoke(fingerprint) is the same as Stop, and says whether a session was ended', async () => {
    const page = await startPage();
    assert.equal(await page.host.revoke(bobFp), false, 'nobody of that key was connected');
    const { wsh } = await operator(page.host);
    const closed = new Promise((resolve) => { wsh.onClose = resolve; });
    assert.equal(await page.host.revoke(aliceFp), true);
    await closed;
    await until(() => page.host.sessions.length === 0, 'the session to end');
  });

  it('indicator callbacks replace the badge (a context with its own UI), and see who and a stop control', async () => {
    const events = [];
    let stop;
    const page = await startPage({ host: { indicator: { connected: (who, control) => { events.push(['connected', who.fingerprint]); stop = control.stop; }, disconnected: (who) => events.push(['disconnected', who.fingerprint]) } } });
    const { wsh } = await operator(page.host);
    assert.deepEqual(events, [['connected', aliceFp]]);
    assert.equal(byRole(page.win, 'indicator').length, 0);
    const closed = new Promise((resolve) => { wsh.onClose = resolve; });
    await stop();
    await closed;
    await until(() => events.length === 2, 'disconnected');
    assert.deepEqual(events[1], ['disconnected', aliceFp]);
  });

  it('a page that removes the badge while a session is connected has it put back', async () => {
    const page = await startPage();
    await operator(page.host);
    await until(() => byRole(page.win, 'indicator').length === 1, 'the indicator');
    byRole(page.win, 'indicator')[0].remove();
    page.timers.tick();
    assert.equal(byRole(page.win, 'indicator').length, 1);
  });

  it('unattended: true allows no indicator, and a consequential call is then denied unless a prompt answers', async () => {
    const page = await startPage({ host: { indicator: false, unattended: true }, mcp: {} });
    const { mcp } = await operator(page.host);
    assert.equal(byRole(page.win, 'indicator').length, 0);
    assert.ok(await mcp.callTool({ name: 'search', arguments: { q: 'x' } }));
    await assert.rejects(mcp.callTool({ name: 'buy', arguments: { sku: 'A1' } }), /denied/);
  });

  it('onSession can refuse a key (ask the person first)', async () => {
    const page = await startPage({ host: { onSession: async (who) => who.fingerprint !== aliceFp } });
    const c = new WshClient(); closers.push(() => c.disconnect());
    await assert.rejects(c.connect(page.host.operatorUrl, { username: 'alice', keyPair: alice, transport: 'ws', sealSession: true }));
    assert.deepEqual(page.host.sessions, []);
  });
});

describe('approval through the whole stack', () => {
  it('a consequential call raises the dialog in the page: Deny is an MCP error, Allow returns the result; a read-only call asks nothing', async () => {
    const page = await startPage();
    const { mcp } = await operator(page.host);
    assert.deepEqual((await mcp.callTool({ name: 'search', arguments: { q: 'x' } })).structuredContent, { hits: ['x-1'] });
    assert.equal(byRole(page.win, 'approval').length, 0);
    const denied = mcp.callTool({ name: 'buy', arguments: { sku: 'A1' } });
    denied.catch(() => {});
    await until(() => byRole(page.win, 'approval').length === 1, 'the dialog');
    assert.ok(byRole(page.win, 'approval')[0].textContent.includes(aliceFp), 'the dialog names the key');
    byRole(page.win, 'deny')[0].click();
    await assert.rejects(denied, /denied/);
    const allowed = mcp.callTool({ name: 'buy', arguments: { sku: 'A2' } });
    await until(() => byRole(page.win, 'approval').length === 1, 'the dialog');
    byRole(page.win, 'allow')[0].click();
    assert.deepEqual((await allowed).structuredContent, { bought: 'A2' });
  });
});

describe('per-key capabilities', () => {
  it('capabilities="mcp:search" lists and calls that tool only; another key on the same host sees both', async () => {
    const page = await startPage({ authorizedKeys: [`capabilities="mcp:search" ${aliceLine}`, bobLine], mcp: { prompt: async () => true } });
    const a = await operator(page.host);
    assert.deepEqual((await a.mcp.listTools()).tools.map((t) => t.name), ['search']);
    assert.ok(await a.mcp.callTool({ name: 'search', arguments: { q: 'x' } }));
    await assert.rejects(a.mcp.callTool({ name: 'buy', arguments: {} }), /unknown tool/);
    await a.wsh.disconnect();
    await until(() => page.host.sessions.length === 0, 'the session to end');
    const b = await operator(page.host, { keyPair: bob, username: 'bob' });
    assert.deepEqual((await b.mcp.listTools()).tools.map((t) => t.name).sort(), ['buy', 'search']);
  });

  it('a capability for a tool outside allow adds nothing, and a key whose capabilities do not name mcp cannot open the channel', async () => {
    const page = await startPage({ authorizedKeys: [`capabilities="mcp:search,mcp:secret" ${aliceLine}`, `capabilities="exec" ${bobLine}`] });
    const a = await operator(page.host);
    assert.deepEqual((await a.mcp.listTools()).tools.map((t) => t.name), ['search']);
    await a.wsh.disconnect();
    await until(() => page.host.sessions.length === 0, 'the session to end');
    const wsh = new WshClient(); closers.push(() => wsh.disconnect());
    await wsh.connect(page.host.operatorUrl, { username: 'bob', keyPair: bob, transport: 'ws', sealSession: true });
    await assert.rejects(wsh.openRpc('mcp'), /capability/);
    await until(() => page.refused.some((r) => r.reason === 'not-permitted'), 'a not-permitted refusal');
  });

  it('an expired key is refused at login', async () => {
    const page = await startPage({ authorizedKeys: [`expires="2001-01-01T00:00:00Z" ${aliceLine}`] });
    const c = new WshClient(); closers.push(() => c.disconnect());
    await assert.rejects(c.connect(page.host.operatorUrl, { username: 'alice', keyPair: alice, transport: 'ws', sealSession: true }));
    await until(() => page.refused.some((r) => r.reason === 'key-expired'), 'a key-expired refusal');
  });
});

describe('the window leaves', () => {
  async function connected(options) {
    const page = await startPage(options);
    const op = await operator(page.host);
    const told = new Promise((resolve) => op.mcp.setNotificationHandler(LoggingMessageNotificationSchema, (n) => resolve(n.params)));
    const closed = new Promise((resolve) => { op.wsh.onClose = resolve; });
    return { page, ...op, told, closed };
  }

  it('navigating to another origin closes the host and tells the operator why', async () => {
    const closes = [];
    const s = await connected({ host: { onClose: (c) => closes.push(c.reason) } });
    s.page.win.location = { origin: 'https://evil.example' };
    s.page.timers.tick();
    assert.match((await s.told).data, /navigated to another origin/);
    await s.closed;
    await until(() => s.page.host.closed, 'the host to close');
    assert.match(s.page.host.closedReason, /another origin/);
    assert.deepEqual(closes, ['the window navigated to another origin']);
    assert.equal(byRole(s.page.win, 'indicator').length, 0);
    await assert.rejects(s.mcp.callTool({ name: 'search', arguments: { q: 'x' } }));
  });

  it('a window that cannot be read any more (a cross-origin frame) counts as another origin', async () => {
    const s = await connected();
    Object.defineProperty(s.page.win, 'location', { get() { throw new DOMException('Blocked a frame', 'SecurityError'); } });
    s.page.timers.tick();
    assert.match((await s.told).data, /another origin/);
    await s.closed;
  });

  it('a closed window closes the host', async () => {
    const s = await connected();
    s.page.win.closed = true;
    s.page.timers.tick();
    assert.match((await s.told).data, /window was closed/);
    await s.closed;
    assert.equal(s.page.host.closed, true);
  });

  it('pagehide closes the host, and a navigation is caught on the next call even before the check runs', async () => {
    const s = await connected();
    s.page.win.fire('pagehide');
    await s.closed;
    assert.equal(s.page.host.closed, true);
    const t = await connected();
    t.page.win.location = { origin: 'https://evil.example' };
    await assert.rejects(t.mcp.callTool({ name: 'search', arguments: { q: 'x' } }), /navigated to another origin/);
  });

  it('close() ends sessions, leaves the relay and does not serve a later arrival', async () => {
    const s = await connected();
    await s.page.host.close();
    await s.closed;
    assert.equal(s.page.host.closed, true);
    const c = new WshClient(); closers.push(() => c.disconnect());
    await assert.rejects(c.connect(s.page.host.operatorUrl, { username: 'alice', keyPair: alice, transport: 'ws', sealSession: true, timeout: 800 }));
  });
});

describe('the host key', () => {
  it('is generated for each page load, and host.fingerprint is what an operator pins', async () => {
    const a = await startPage();
    const b = await startPage();
    assert.match(a.host.fingerprint, /^[0-9a-f]{64}$/);
    assert.notEqual(a.host.fingerprint, b.host.fingerprint);
    const { wsh } = await operator(a.host, { connect: { expectHostKey: a.host.fingerprint } });
    assert.equal(wsh.hostKey.fingerprint, a.host.fingerprint);
    assert.equal(wsh.hostKey.status, 'pinned');
    const c = new WshClient(); closers.push(() => c.disconnect());
    await assert.rejects(c.connect(b.host.operatorUrl, { username: 'alice', keyPair: alice, transport: 'ws', sealSession: true, expectHostKey: a.host.fingerprint }), /host key|fingerprint|pin/i);
  });

  it('persists through an injected store: the same identity on the next load, saved once', async () => {
    const store = { saved: [], pair: undefined, async load() { return this.pair; }, async save(p) { this.saved.push(p); this.pair = p; } };
    const a = await startPage({ host: { hostKeyStore: store } });
    const b = await startPage({ host: { hostKeyStore: store } });
    assert.equal(a.host.fingerprint, b.host.fingerprint);
    assert.equal(store.saved.length, 1);
  });

  it('an injected key or signer is used as given, and a bad store is refused', async () => {
    const pair = await generateKeyPair(false);
    const a = await startPage({ host: { hostKey: pair } });
    assert.equal(a.host.fingerprint, await fingerprint(await exportPublicKeyRaw(pair.publicKey)));
    await assert.rejects(createPageHost({ window: createFakeWindow(), relay: 'ws://127.0.0.1:1', name: 'x', authorizedKeys: ['k'], mcp: {}, hostKeyStore: {} }), /load\(\) and save/);
  });
});

describe('the far side needs nothing new', () => {
  it('wsh-mcp --sealed (the npm bin) reaches a page host through the pipe relay', async () => {
    const scratch = await mkdtemp(path.join(tmpdir(), 'wsh-page-'));
    closers.push(() => rm(scratch, { recursive: true, force: true }));
    await mkdir(path.join(scratch, 'keys'));
    const pkcs8 = await exportPrivateKeyPKCS8(alice.privateKey);
    const identity = path.join(scratch, 'keys', 'default.pem');
    await writeFile(identity, `-----BEGIN WSH PRIVATE KEY-----\n${Buffer.from(pkcs8).subarray(-32).toString('base64')}\n-----END WSH PRIVATE KEY-----\n`, { mode: 0o600 });
    const page = await startPage();
    const env = { PATH: process.env.PATH, HOME: scratch, USERPROFILE: scratch, XDG_CONFIG_HOME: scratch };
    const transport = new StdioClientTransport({ command: process.execPath, args: [path.join(here, '..', 'bin', 'wsh-mcp.mjs'), '--identity', identity, '--user', 'alice', '--sealed', '--host-key', page.host.fingerprint, page.host.operatorUrl], env, stderr: 'pipe' });
    const mcp = new Client({ name: 'agent', version: '1' }, { capabilities: {} });
    await mcp.connect(transport);
    closers.push(() => mcp.close());
    assert.equal(mcp.getServerVersion().name, 'shop-tab');
    assert.deepEqual((await mcp.listTools()).tools.map((t) => t.name).sort(), ['buy', 'search']);
    assert.deepEqual((await mcp.callTool({ name: 'search', arguments: { q: 'cli' } })).structuredContent, { hits: ['cli-1'] });
    assert.equal(page.host.sessions.length, 1);
  });
});

describe('pipe-url: the relay\'s two pure helpers, kept apart so a page does not bundle the relay', () => {
  it('agree with the relay module\'s own', async () => {
    const relayModule = await import('../src/pipe-relay.mjs');
    const mine = await import('../src/pipe-url.mjs');
    const bytes = Uint8Array.from({ length: 16 }, (_, i) => (i * 37 + 11) & 255);
    const fixed = { getRandomValues: (b) => { b.set(bytes); return b; } };
    const expected = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    assert.equal(mine.newRendezvousId(fixed), expected);
    assert.match(mine.newRendezvousId(globalThis.crypto), /^[A-Za-z0-9_-]{22}$/);
    for (const role of ['host', 'operator']) assert.equal(mine.pipeUrl('wss://r.example/base/', expected, role), relayModule.pipeUrl('wss://r.example/base/', expected, role));
    assert.throws(() => mine.pipeUrl('wss://r.example', 'short'), /rendezvous id/);
    assert.throws(() => mine.pipeUrl('wss://r.example', expected, 'x'), /role/);
    assert.throws(() => mine.newRendezvousId({}), /getRandomValues/);
  });
});

describe('the entry point touches only the window it is given', () => {
  /** The source with comments and the contents of strings and templates removed, so only code is left. */
  function codeOf(source) {
    let out = ''; let i = 0;
    while (i < source.length) {
      const c = source[i]; const n = source[i + 1];
      if (c === '/' && n === '/') { while (i < source.length && source[i] !== '\n') i++; continue; }
      if (c === '/' && n === '*') { i = source.indexOf('*/', i + 2) + 2; continue; }
      if (c === '"' || c === "'" || c === '`') {
        const q = c; i++;
        while (i < source.length && source[i] !== q) { if (source[i] === '\\') i++; if (q === '`' && source[i] === '$' && source[i + 1] === '{') { let depth = 1; i += 2; const start = i; while (i < source.length && depth) { if (source[i] === '{') depth++; if (source[i] === '}') depth--; i++; } out += ` ${codeOf(source.slice(start, i - 1))} `; continue; } i++; }
        i++; out += '""'; continue;
      }
      out += c; i++;
    }
    return out;
  }
  const AMBIENT = /(?<![.\w$])(globalThis|document|navigator|location|localStorage|sessionStorage|indexedDB|fetch|XMLHttpRequest|WebSocket|setTimeout|clearTimeout|setInterval|clearInterval|requestAnimationFrame|queueMicrotask|crypto|self|alert|confirm|history|postMessage)\b(?!\s*:)/g;
  for (const file of ['page-host.mjs', 'webmcp.mjs']) {
    it(`src/${file} names no ambient global (window, window.document and window.navigator only)`, async () => {
      const source = await readFile(path.join(here, '..', 'src', file), 'utf8');
      const code = codeOf(source);
      const found = [...code.matchAll(AMBIENT)].map((m) => m[1]);
      assert.deepEqual(found, [], `ambient names in ${file}`);
      assert.ok(!/\binnerHTML\b|\binsertAdjacentHTML\b|\bdocument\.write\b|\beval\s*\(|\bnew Function\b/.test(code), 'markup or code built from strings');
      for (const imp of source.matchAll(/^import .* from '(.+)';/gm)) assert.ok(imp[1].startsWith('./'), `${file} imports ${imp[1]}`);
    });
  }

  it('the grep itself catches what it is for (a control)', () => {
    const bad = codeOf('const a = document.title; const b = globalThis.x; setTimeout(f, 1); const w = window.document;');
    assert.deepEqual([...bad.matchAll(AMBIENT)].map((m) => m[1]), ['document', 'globalThis', 'setTimeout']);
  });
});
