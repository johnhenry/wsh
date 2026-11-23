// WshKeyStore in a real browser: a non-extractable key (IndexedDB) survives a reload and still authenticates (#116).
import { test, expect } from './fixtures.mjs';
import { startServer } from './nodes.mjs';

test('a non-extractable key survives a page reload and still signs in', async ({ page }) => {
  const made = await page.evaluate(async () => {
    const store = new window.wsh.WshKeyStore();
    await store.open();
    const info = await store.generateKey('laptop', { extractable: false });
    const pair = await store.getKeyPair('laptop');
    store.close();
    return { ...info, extractable: pair.privateKey.extractable };
  });
  expect(made.extractable).toBe(false);
  expect(made.publicKeySSH).toMatch(/^ssh-ed25519 /);

  await page.reload();
  await page.waitForFunction(() => window.wshReady === true);

  const ctx = await startServer({ auth: { authorizedKeys: made.publicKeySSH }, exec: true });
  try {
    const after = await page.evaluate(async (url) => {
      const store = new window.wsh.WshKeyStore();
      await store.open();
      const listed = await store.listKeys();
      const keyPair = await store.getKeyPair('laptop');
      // The private key cannot leave the browser, yet it still proves possession to a host.
      const exportable = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey).then(() => true, () => false);
      const transport = new window.wsh.WebSocketTransport();
      const client = new window.wsh.WshClient({ transportFactories: { ws: () => transport } });
      await client.connect(url, { username: 'alice', keyPair, transport: 'ws' });
      await client.disconnect();
      store.close();
      return { listed: listed.map((k) => [k.name, k.fingerprint]), extractable: keyPair.privateKey.extractable, exportable };
    }, ctx.url);
    expect(after.listed).toEqual([['laptop', made.fingerprint]]);
    expect(after.extractable).toBe(false);
    expect(after.exportable).toBe(false);
  } finally { await ctx.close(); }
});
