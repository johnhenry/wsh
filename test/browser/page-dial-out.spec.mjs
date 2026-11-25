// The dial-out form of the page host (#219) in a REAL Chromium page: `createPageHost({ connect })` makes the page itself open a WebSocket to an operator that
// listens (a `ws` server in this process), which then logs in as the wsh client over what it accepted. Same sealed key login, same indicator and Stop.
import { test, expect } from './fixtures.mjs';
import { WebSocketServer } from 'ws';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { connectWshOverDuplex } from '@johnhenry/wsh/duplex';
import '@johnhenry/wsh/objects';   // adds client.openObjects()

test.describe('a page host that dials an operator that listens', () => {
  let alice; let aliceLine; let wss; let arrivals;
  test.beforeAll(async () => { alice = await generateKeyPair(true); aliceLine = await exportPublicKeySSH(alice.publicKey); });
  test.beforeEach(async () => {
    wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise((r) => wss.once('listening', r));
    arrivals = [];
    // The page speaks first; what arrives before a login is attached waits here.
    wss.on('connection', (ws, req) => {
      const entry = { ws, url: req.url, queue: [], sink: null };
      ws.on('message', (d) => { if (entry.sink) entry.sink(d); else entry.queue.push(d); });
      arrivals.push(entry);
    });
  });
  test.afterEach(async () => { for (const c of wss.clients) c.terminate(); await new Promise((r) => wss.close(r)); });

  const login = (entry, expectHostKey) => {
    const link = connectWshOverDuplex({ send: (b) => entry.ws.send(b), close: () => entry.ws.close(1000) }, { username: 'alice', keyPair: alice, expectHostKey, timeout: 5000 });
    entry.sink = (d) => link.receive(d);
    for (const d of entry.queue.splice(0)) link.receive(d);   // a Node Buffer, as `ws` hands it over
    entry.ws.on('close', () => link.end('the page closed the connection'));
    return link;
  };

  test('the page dials the URL as written, a key logs in sealed over the accepted socket, objects work, Stop ends it and the page dials again', async ({ page }) => {
    await page.evaluate(() => window.h.pageApp());
    const host = await page.evaluate((o) => window.h.startPageHost(o), {
      connect: `ws://127.0.0.1:${wss.address().port}/pages/shop?token=abc`, authorizedKeys: [aliceLine],
      expose: { window: { allow: { get: ['document.title'], call: ['app.cart.add'] } } },
    });
    await expect.poll(() => arrivals.length).toBe(1);
    expect(arrivals[0].url).toBe('/pages/shop?token=abc');

    const link = login(arrivals[0], host.fingerprint);
    const wsh = await link.connected;
    try {
      expect(wsh).toBeInstanceOf(WshClient);
      expect(wsh.sessionSealed).toBe(true);
      const { window: remote } = await wsh.openObjects();
      expect(await remote.document.title).toBe('Planted Shop Title');
      expect(await remote.app.cart.add({ sku: 'D1', qty: 1 })).toEqual({ count: 2 });
      await expect(Promise.resolve(remote.document.cookie)).rejects.toMatchObject({ reason: 'not-allowed' });
      // The indicator is the page's own, and Stop ends the session and refuses that key.
      await expect(page.locator('[data-wsh-page="indicator"]')).toHaveCount(1);
      await page.locator('[data-wsh-page="indicator"]').getByRole('button', { name: /Stop/ }).click();
      await expect(page.locator('[data-wsh-page="indicator"]')).toHaveCount(0);
    } finally { await wsh.disconnect().catch(() => {}); }

    // The page dials again for the next arrival; the key that was stopped is not let back in.
    await expect.poll(() => arrivals.length).toBe(2);
    const again = login(arrivals[1], host.fingerprint);
    await expect(again.connected).rejects.toThrow();
  });

  test('a stranger (a key that is not authorized) gets nothing, and nothing is dialled unless connect is written', async ({ page }) => {
    await page.evaluate(() => window.h.pageApp());
    expect(arrivals.length).toBe(0);
    const stranger = await generateKeyPair(true);
    const host = await page.evaluate((o) => window.h.startPageHost(o), {
      connect: `ws://127.0.0.1:${wss.address().port}/`, authorizedKeys: [aliceLine], expose: { window: { allow: { get: ['document.title'] } } },
    });
    await expect.poll(() => arrivals.length).toBe(1);
    const entry = arrivals[0];
    const link = connectWshOverDuplex({ send: (b) => entry.ws.send(b), close: () => entry.ws.close(1000) }, { username: 'mallory', keyPair: stranger, expectHostKey: host.fingerprint, timeout: 5000 });
    entry.sink = (d) => link.receive(d);
    for (const d of entry.queue.splice(0)) link.receive(d);
    entry.ws.on('close', () => link.end('closed'));
    await expect(link.connected).rejects.toThrow();
    await expect(page.locator('[data-wsh-page="indicator"]')).toHaveCount(0);
  });
});
