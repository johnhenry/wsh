// The MCP face for allow-listed object paths (#219) in a real Chromium page: `createPageHost({ expose: { window: { mcp: { tools } } } })` makes two named paths MCP tools; a Node MCP SDK client reaches
// them over a SEALED session through a byte pipe. A call that is not read-only raises the page's approval dialog, the arguments are checked before it, a key needs both mcp:TOOL and objects:ROOT:OP,
// and the relay sees nothing of the tool names or values.
import { test, expect } from './fixtures.mjs';
import { startPipe } from './nodes.mjs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeySSH, mcpClientTransport } from '@johnhenry/wsh';

test.describe('a page host: an MCP face for allow-listed paths over a sealed relayed session', () => {
  let pipe; let alice; let bob; let aliceLine; let bobLine;
  test.beforeAll(async () => {
    alice = await generateKeyPair(true); bob = await generateKeyPair(true);
    aliceLine = await exportPublicKeySSH(alice.publicKey); bobLine = await exportPublicKeySSH(bob.publicKey);
  });
  test.beforeEach(async () => { pipe = await startPipe(); });
  test.afterEach(async () => { await pipe.close(); });

  const EXPOSE = {
    window: {
      allow: { get: ['document.title', 'app.cart.**', 'app.secret'], call: ['app.cart.add', 'app.cart.clearAll'] },
      mcp: { tools: [
        { name: 'cart_add', description: 'Add a product to the cart', call: 'app.cart.add', inputSchema: { type: 'object', properties: { sku: { type: 'string', minLength: 1 }, qty: { type: 'integer', minimum: 1 } }, required: ['sku'], additionalProperties: false } },
        { name: 'page_title', description: 'The title of the page', get: 'document.title', readOnly: true },
      ] },
    },
  };

  async function startPage(page, authorizedKeys = [aliceLine]) {
    await page.evaluate(() => window.h.pageApp());
    return page.evaluate((o) => window.h.startPageHost(o), { relay: pipe.hostUrl, authorizedKeys, expose: EXPOSE });
  }
  async function operator(host, { keyPair = alice, username = 'alice' } = {}) {
    const wsh = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    await wsh.connect(pipe.operatorUrl, { username, keyPair, transport: 'ws', sealSession: true, expectHostKey: host.fingerprint });
    const mcp = new Client({ name: 'agent', version: '1' }, { capabilities: {} });
    await mcp.connect(mcpClientTransport(await wsh.openRpc('mcp')));
    return { wsh, mcp, close: async () => { await mcp.close().catch(() => {}); await wsh.disconnect().catch(() => {}); } };
  }

  test('lists the two named paths only; a read returns the page title as untrusted data; the relay sees none of it', async ({ page }) => {
    const host = await startPage(page);
    const op = await operator(host);
    try {
      expect((await op.mcp.listTools()).tools.map((t) => t.name).sort()).toEqual(['cart_add', 'page_title']);
      const r = await op.mcp.callTool({ name: 'page_title', arguments: {} });
      expect(r.content[0].text).toBe('Planted Shop Title');
      expect(r._meta['wsh/untrusted']).toBe(true);
      await expect(op.mcp.callTool({ name: 'clearAll', arguments: {} })).rejects.toThrow(/unknown tool/);
      const seen = pipe.recording();
      expect(seen.length).toBeGreaterThan(1000);
      for (const text of ['Planted Shop Title', 'cart_add', 'page_title', 'tools/call']) expect(seen.includes(Buffer.from(text)), `the relay saw "${text}"`).toBe(false);
    } finally { await op.close(); }
  });

  test('a call that is not read-only raises the approval dialog: Deny leaves the page alone, Allow runs the page function with the plain arguments; bad arguments never reach the dialog', async ({ page }) => {
    const host = await startPage(page);
    const op = await operator(host);
    try {
      const dialog = page.getByRole('alertdialog');
      await expect(op.mcp.callTool({ name: 'cart_add', arguments: { sku: 'A1', qty: 0 } })).rejects.toThrow(/invalid arguments/);
      await expect(dialog).toHaveCount(0);
      const denied = op.mcp.callTool({ name: 'cart_add', arguments: { sku: 'B2', qty: 3 } });
      denied.catch(() => {});
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText('cart_add');
      await expect(dialog.locator('[data-wsh-page="approval-input"]')).toContainText('B2');
      await page.locator('[data-wsh-page="deny"]').click();
      await expect(denied).rejects.toThrow(/denied/);
      expect(await page.evaluate(() => window.__calls)).toEqual([]);
      const allowed = op.mcp.callTool({ name: 'cart_add', arguments: { sku: 'B2', qty: 3 } });
      await expect(dialog).toBeVisible();
      await page.locator('[data-wsh-page="allow"]').click();
      expect((await allowed).structuredContent).toEqual({ count: 2 });
      expect(await page.evaluate(() => window.__calls)).toEqual([{ sku: 'B2', qty: 3 }]);
    } finally { await op.close(); }
  });

  test('a key with mcp:TOOL only sees nothing: the objects grant is needed too', async ({ page }) => {
    const host = await startPage(page, [aliceLine, `capabilities="mcp:page_title,mcp:cart_add" ${bobLine}`]);
    const op = await operator(host, { keyPair: bob, username: 'bob' });
    try {
      expect((await op.mcp.listTools()).tools).toEqual([]);
      await expect(op.mcp.callTool({ name: 'page_title', arguments: {} })).rejects.toThrow(/unknown tool/);
    } finally { await op.close(); }
  });

  test('a key with mcp:page_title and objects:window:get sees the read and not the call', async ({ page }) => {
    const host = await startPage(page, [aliceLine, `capabilities="mcp:*,objects:window:get" ${bobLine}`]);
    const op = await operator(host, { keyPair: bob, username: 'bob' });
    try {
      expect((await op.mcp.listTools()).tools.map((t) => t.name)).toEqual(['page_title']);
      expect((await op.mcp.callTool({ name: 'page_title', arguments: {} })).content[0].text).toBe('Planted Shop Title');
      await expect(op.mcp.callTool({ name: 'cart_add', arguments: { sku: 'x' } })).rejects.toThrow(/unknown tool/);
      expect(await page.evaluate(() => window.__calls)).toEqual([]);
    } finally { await op.close(); }
  });
});
