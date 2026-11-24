// A page's WebMCP tools reached as MCP through a byte pipe, in a real Chromium page (#190). The page installs the capture shim, registers
// tools through `document.modelContext` the way an application does, and starts `createPageHost`; a Node MCP SDK client reaches it over a
// SEALED session. Nothing in the page is wired by hand: public entry points only.
import { test, expect } from './fixtures.mjs';
import { startPipe } from './nodes.mjs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { LoggingMessageNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeySSH, exportPrivateKeyPKCS8, mcpClientTransport } from '@johnhenry/wsh';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'wsh-mcp.mjs');
const MARKER = 'PLANTED-MARKER-OKAPI-4417';

test.describe('a page host: WebMCP tools as MCP over a sealed relayed session', () => {
  let pipe; let alice; let bob; let aliceLine; let bobLine;
  test.beforeAll(async () => {
    alice = await generateKeyPair(true); bob = await generateKeyPair(true);
    aliceLine = await exportPublicKeySSH(alice.publicKey); bobLine = await exportPublicKeySSH(bob.publicKey);
  });
  test.beforeEach(async () => { pipe = await startPipe(); });
  test.afterEach(async () => { await pipe.close(); });

  /** The application's side: shim, tools, host. */
  async function startPage(page, { authorizedKeys, allow = ['search', 'add_to_cart'], approve } = {}) {
    await page.evaluate(() => window.h.pageTools());
    return page.evaluate((o) => window.h.startPageHost(o), { relay: pipe.hostUrl, authorizedKeys: authorizedKeys ?? [aliceLine], allow, approve });
  }
  /** An operator in Node: sealed, key login, an MCP SDK client over the `mcp` rpc channel. */
  async function operator(host, { keyPair = alice, username = 'alice' } = {}) {
    const wsh = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    await wsh.connect(pipe.operatorUrl, { username, keyPair, transport: 'ws', sealSession: true, expectHostKey: host.fingerprint });
    const mcp = new Client({ name: 'agent', version: '1' }, { capabilities: {} });
    await mcp.connect(mcpClientTransport(await wsh.openRpc('mcp')));
    return { wsh, mcp, close: async () => { await mcp.close().catch(() => {}); await wsh.disconnect().catch(() => {}); } };
  }

  test('lists only the allowed tools; a read-only call returns its result; the relay sees no tool name or payload', async ({ page }) => {
    const host = await startPage(page);
    const op = await operator(host);
    try {
      expect(op.wsh.sessionSealed).toBe(true);
      expect((await op.mcp.listTools()).tools.map((t) => t.name).sort()).toEqual(['add_to_cart', 'search']);
      const r = await op.mcp.callTool({ name: 'search', arguments: { text: MARKER } });
      expect(r.structuredContent).toEqual({ hits: [`found ${MARKER}`] });
      expect(r.isError).toBeFalsy();
      await expect(op.mcp.callTool({ name: 'read_secret', arguments: {} })).rejects.toThrow(/unknown tool/);
      const info = await page.evaluate(() => window.h.pageHostInfo());
      expect(info.ran).toEqual(['search']);
      const seen = pipe.recording();
      expect(seen.length).toBeGreaterThan(1000); // the pipe really carried the session
      for (const text of [MARKER, 'search', 'add_to_cart', 'tools/call', 'read_secret']) expect(seen.includes(Buffer.from(text)), `the relay saw "${text}"`).toBe(false);
    } finally { await op.close(); }
  });

  test('a consequential tool raises the approval dialog in the page: Deny is an MCP error, Allow returns the result', async ({ page }) => {
    const host = await startPage(page);
    const op = await operator(host);
    try {
      const dialog = page.getByRole('alertdialog');
      const denied = op.mcp.callTool({ name: 'add_to_cart', arguments: { text: 'widget' } });
      denied.catch(() => {});
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText('add_to_cart');
      await expect(dialog).toContainText((await page.evaluate(() => window.h.pageHostInfo())).sessions[0]);
      await expect(dialog.locator('[data-wsh-page="approval-input"]')).toContainText('widget');
      await expect(page.locator('[data-wsh-page="deny"]')).toBeFocused();
      await page.locator('[data-wsh-page="deny"]').click();
      await expect(denied).rejects.toThrow(/denied/);
      expect((await page.evaluate(() => window.h.pageHostInfo())).cart).toEqual([]);
      const allowed = op.mcp.callTool({ name: 'add_to_cart', arguments: { text: 'widget' } });
      await expect(dialog).toBeVisible();
      await page.locator('[data-wsh-page="allow"]').click();
      expect((await allowed).structuredContent).toEqual({ cart: ['widget'] });
      expect((await page.evaluate(() => window.h.pageHostInfo())).cart).toEqual(['widget']);
      await expect(dialog).toHaveCount(0);
    } finally { await op.close(); }
  });

  test('the indicator shows the key\'s fingerprint, and Stop ends the session and keeps that key out', async ({ page }) => {
    const host = await startPage(page);
    const op = await operator(host);
    try {
      const indicator = page.locator('[data-wsh-page="indicator"]');
      await expect(indicator).toBeVisible();
      const fp = (await page.evaluate(() => window.h.pageHostInfo())).sessions[0];
      expect(fp).toMatch(/^[0-9a-f]{64}$/);
      await expect(indicator).toContainText(fp);
      await expect(indicator).toContainText('Remote session connected');
      const told = new Promise((resolve) => op.mcp.setNotificationHandler(LoggingMessageNotificationSchema, (n) => resolve(n.params.data)));
      const closed = new Promise((resolve) => { op.wsh.onClose = resolve; });
      await indicator.getByRole('button', { name: /Stop/ }).click();
      expect(await told).toMatch(/stopped this session/);
      await closed;
      await expect(indicator).toHaveCount(0);
      expect((await page.evaluate(() => window.h.pageHostInfo())).sessions).toEqual([]);
      const again = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
      await expect(again.connect(pipe.operatorUrl, { username: 'alice', keyPair: alice, transport: 'ws', sealSession: true, timeout: 4000 })).rejects.toThrow();
    } finally { await op.close(); }
  });

  test('a key limited to one tool sees one tool and cannot call another', async ({ page }) => {
    const host = await startPage(page, { authorizedKeys: [aliceLine, `capabilities="mcp:search" ${bobLine}`], approve: 'never' });
    const op = await operator(host, { keyPair: bob, username: 'bob' });
    try {
      expect((await op.mcp.listTools()).tools.map((t) => t.name)).toEqual(['search']);
      expect((await op.mcp.callTool({ name: 'search', arguments: { text: 'x' } })).structuredContent).toEqual({ hits: ['found x'] });
      await expect(op.mcp.callTool({ name: 'add_to_cart', arguments: { text: 'x' } })).rejects.toThrow(/unknown tool/);
      expect((await page.evaluate(() => window.h.pageHostInfo())).ran).toEqual(['search']);
    } finally { await op.close(); }
  });

  test('wsh-mcp --sealed, the npm bin, reaches the page through the pipe', async ({ page }) => {
    const host = await startPage(page, { approve: 'never' });
    const scratch = await mkdtemp(path.join(tmpdir(), 'wsh-page-spec-'));
    try {
      await mkdir(path.join(scratch, 'keys'));
      const identity = path.join(scratch, 'keys', 'default.pem');
      await writeFile(identity, `-----BEGIN WSH PRIVATE KEY-----\n${Buffer.from(await exportPrivateKeyPKCS8(alice.privateKey)).subarray(-32).toString('base64')}\n-----END WSH PRIVATE KEY-----\n`, { mode: 0o600 });
      const transport = new StdioClientTransport({
        command: process.execPath, args: [BIN, '--identity', identity, '--user', 'alice', '--sealed', '--host-key', host.fingerprint, pipe.operatorUrl],
        env: { PATH: process.env.PATH, HOME: scratch, USERPROFILE: scratch, XDG_CONFIG_HOME: scratch }, stderr: 'pipe',
      });
      const mcp = new Client({ name: 'agent', version: '1' }, { capabilities: {} });
      await mcp.connect(transport);
      try {
        expect(mcp.getServerVersion().name).toBe('shop-tab');
        expect((await mcp.listTools()).tools.map((t) => t.name).sort()).toEqual(['add_to_cart', 'search']);
        expect((await mcp.callTool({ name: 'add_to_cart', arguments: { text: 'via bin' } })).structuredContent).toEqual({ cart: ['via bin'] });
      } finally { await mcp.close(); }
    } finally { await rm(scratch, { recursive: true, force: true }); }
  });

  test('the host closes when the page navigates away, and the operator\'s session ends', async ({ page }) => {
    const host = await startPage(page);
    const op = await operator(host);
    try {
      const closed = new Promise((resolve) => { op.wsh.onClose = resolve; });
      await page.goto('about:blank');
      await closed;
    } finally { await op.close(); }
  });
});
