// test/rust/wsh-mcp-page-host.test.mjs -- the Rust `wsh --sealed --via <pipe relay> mcp` reaches a REAL page host (`createPageHost` of
// `@johnhenry/wsh/page`, over a fake window): it lists only the allowed tools and calls one, and a recording relay sees no tool name.
// Needs the built CLI: WSH_BIN, or target/release/wsh (cargo build --release -p wsh-cli). HOME and friends point at a scratch directory.
import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createPageHost, captureWebMcp } from '@johnhenry/wsh/page';
import { createFakeWindow } from '../helpers/fake-window.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const MARKER = 'PLANTED-MARKER-OKAPI-5521';
const scratch = [];
const closers = [];
before(() => { assert.ok(existsSync(WSH_BIN), `expected the built wsh at ${WSH_BIN} (cargo build -p wsh-cli, or set WSH_BIN)`); });
after(() => { for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true }); });
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'alice', TERM: 'xterm' });

/** A pipe relay that pairs the two halves of an id and copies bytes, recording them. */
async function copyingRelay() {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  const waiting = new Map();
  const seen = [];
  wss.on('connection', (ws, req) => {
    const u = new URL(req.url, 'ws://x');
    const id = u.pathname.split('/').pop();
    const other = waiting.get(id);
    if (!other) { waiting.set(id, ws); return; }
    waiting.delete(id);
    for (const [from, to] of [[ws, other], [other, ws]]) {
      from.on('message', (data, isBinary) => { seen.push(Buffer.from(data)); if (to.readyState === 1) to.send(data, { binary: isBinary }); });
      from.on('close', () => { if (to.readyState === 1) to.close(); });
    }
  });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  return { url: `ws://127.0.0.1:${wss.address().port}`, text: () => Buffer.concat(seen).toString('latin1') };
}

describe('the Rust `wsh mcp --sealed --via` against a page host', () => {
  it('lists only the allowed tools, calls one, and the relay sees no tool name or payload', async () => {
    const home = realpathSync(mkdtempSync(path.join(tmpdir(), 'wsh-page-rust-')));
    scratch.push(home);
    execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
    const pub = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
    const relay = await copyingRelay();
    const win = createFakeWindow();
    captureWebMcp(win);
    await win.document.modelContext.registerTool({ name: 'search_okapi', description: 'Search', annotations: { readOnlyHint: true }, inputSchema: { type: 'object', properties: { q: { type: 'string' } } }, execute: ({ q }) => ({ hits: [`found ${q}`] }) });
    await win.document.modelContext.registerTool({ name: 'hidden_okapi', description: 'Not allowed', annotations: { readOnlyHint: true }, execute: () => ({}) });
    const host = await createPageHost({ window: win, relay: relay.url, name: 'shop-tab', authorizedKeys: [pub], mcp: { allow: ['search_okapi'] } });
    closers.push(() => host.close());
    const transport = new StdioClientTransport({
      command: WSH_BIN, args: ['--accept-new-host-key', '--via', host.operatorUrl, '--sealed', 'mcp', 'alice@tab.example'], env: cleanEnv(home), stderr: 'pipe',
    });
    const client = new Client({ name: 'an-mcp-client', version: '1' }, { capabilities: {} });
    closers.push(() => client.close());
    await client.connect(transport);
    assert.equal(client.getServerVersion().name, 'shop-tab');
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['search_okapi']);
    assert.deepEqual((await client.callTool({ name: 'search_okapi', arguments: { q: MARKER } })).structuredContent, { hits: [`found ${MARKER}`] });
    const seen = relay.text();
    assert.ok(seen.length > 500);
    for (const word of [MARKER, 'search_okapi', 'tools/call', 'shop-tab']) assert.ok(!seen.includes(word), `"${word}" crossed the relay in the clear`);
  });
});
