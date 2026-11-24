// Object access to a real page through a byte pipe (#190, `wsh-objects`, values mode): a page host with `expose: { window }`, reached over a SEALED
// session by a Node client that reads `document.title`, calls an allow-listed application function, and is refused `document.cookie`.
import { test, expect } from './fixtures.mjs';
import { startPipe } from './nodes.mjs';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { set, snapshot, describe, on, use, release, RemoteHandle, NonValue } from '@johnhenry/wsh/objects';

test.describe('a page host: object access (values mode) over a sealed relayed session', () => {
  let pipe; let alice; let aliceLine;
  test.beforeAll(async () => { alice = await generateKeyPair(true); aliceLine = await exportPublicKeySSH(alice.publicKey); });
  test.beforeEach(async () => { pipe = await startPipe(); });
  test.afterEach(async () => { await pipe.close(); });

  const EXPOSE = { window: { mode: 'values', allow: { get: ['document.title', 'location.href', 'app.cart.**', 'app.state.**'], call: ['app.cart.add'], set: ['app.state.user'] } } };

  async function start(page, expose = EXPOSE) {
    await page.evaluate(() => window.h.pageApp());
    const host = await page.evaluate((o) => window.h.startPageHost(o), { relay: pipe.hostUrl, authorizedKeys: [aliceLine], expose });
    const wsh = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    await wsh.connect(pipe.operatorUrl, { username: 'alice', keyPair: alice, transport: 'ws', sealSession: true, expectHostKey: host.fingerprint });
    return { wsh, host, remote: (await wsh.openObjects()).window };
  }

  test('reads document.title, calls an allow-listed application function, and is refused document.cookie', async ({ page }) => {
    const { wsh, remote } = await start(page);
    try {
      expect(wsh.sessionSealed).toBe(true);
      expect(await remote.document.title).toBe('Planted Shop Title');
      expect(await remote.location.href).toMatch(/^http:\/\/127\.0\.0\.1:/);
      expect(await remote.app.cart.items.length).toBe(1);
      expect(await remote.app.cart.add({ sku: 'B2', qty: 3 })).toEqual({ count: 2 });
      expect(await page.evaluate(() => window.__calls)).toEqual([{ sku: 'B2', qty: 3 }]);
      await set(remote.app.state, 'user', 'bob');
      expect(await page.evaluate(() => window.app.state.user)).toBe('bob');
      expect(await snapshot(remote.app.state)).toEqual({ user: 'bob', flags: { beta: true } });
      // What is not listed is refused, by rule, and the secrets stay where they were.
      await expect(Promise.resolve(remote.document.cookie)).rejects.toMatchObject({ reason: 'not-allowed' });
      await expect(Promise.resolve(remote.app.secret)).rejects.toMatchObject({ reason: 'not-allowed' });
      await expect(Promise.resolve(remote.localStorage)).rejects.toMatchObject({ reason: 'not-allowed' });
      await expect(Promise.resolve(remote.eval('1'))).rejects.toMatchObject({ reason: 'always-refused' });
      await expect(Promise.resolve(remote.document.constructor)).rejects.toMatchObject({ reason: 'always-refused' });
      await expect(set(remote.document, 'title', 'defaced')).rejects.toMatchObject({ reason: 'not-allowed' });
      expect(await page.evaluate(() => document.title)).toBe('Planted Shop Title');
      // A DOM-ish value is named, never a handle.
      const names = await describe(remote.document);
      expect(names.keys.map((k) => k.key)).toEqual(['title']);
      expect(await remote.app.cart.add instanceof NonValue).toBe(true);
    } finally { await wsh.disconnect(); }
  });

  test('a wildcard does not reach document.cookie; naming it does; and the relay sees neither the paths nor the values', async ({ page }) => {
    const { wsh, remote } = await start(page, { window: { allow: { get: ['**'], call: ['**'] } } });
    try {
      await expect(Promise.resolve(remote.document.cookie)).rejects.toMatchObject({ reason: 'needs-listing' });
      await expect(Promise.resolve(remote.localStorage.getItem('k'))).rejects.toMatchObject({ reason: 'needs-listing' });
      expect(await remote.document.title).toBe('Planted Shop Title');
      const seen = pipe.recording();
      expect(seen.length).toBeGreaterThan(1000);
      for (const text of ['Planted Shop Title', 'planted-cookie-value', 'document', 'resolve', 'localStorage']) expect(seen.includes(Buffer.from(text)), `the relay saw "${text}"`).toBe(false);
    } finally { await wsh.disconnect(); }

    // Named, the cookie can be read: an allow-list that says so means it.
    const wsh2Pipe = await startPipe();
    try {
      await page.evaluate(() => window.h.stopPageHost());
      const host = await page.evaluate((o) => window.h.startPageHost(o), { relay: wsh2Pipe.hostUrl, authorizedKeys: [aliceLine], expose: { window: { allow: { get: ['document.cookie'] } } } });
      const again = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
      await again.connect(wsh2Pipe.operatorUrl, { username: 'alice', keyPair: alice, transport: 'ws', sealSession: true, expectHostKey: host.fingerprint });
      try { expect(await (await again.openObjects()).window.document.cookie).toBe('sid=planted-cookie-value'); } finally { await again.disconnect(); }
    } finally { await wsh2Pipe.close(); }
  });

  test('a real DOM event (hashchange) arrives as plain data with the fields the host lists, never the event; Stop removes the listener', async ({ page }) => {
    const { wsh, remote } = await start(page, { window: { allow: { on: ['@hashchange', '@click'] }, eventFields: { hashchange: ['newURL', 'oldURL'] } } });
    try {
      const got = [];
      await on(remote, 'hashchange', (d) => got.push(d), { fields: ['newURL', 'oldURL'] });
      await page.evaluate(() => { window.location.hash = '#next'; });
      await expect.poll(() => got.length).toBe(1);
      expect(Object.keys(got[0]).sort()).toEqual(['isTrusted', 'newURL', 'oldURL', 'timeStamp', 'type']);
      expect(got[0].newURL).toMatch(/#next$/);
      expect(got[0].type).toBe('hashchange');
      // A field the host did not list is refused (a node is never one), and a type not named is refused.
      await expect(on(remote, 'hashchange', () => {}, { fields: ['target'] })).rejects.toMatchObject({ reason: 'not-allowed' });
      await expect(on(remote, 'beforeunload', () => {})).rejects.toMatchObject({ reason: 'not-allowed' });
      await page.locator('[data-wsh-page="indicator"]').getByRole('button', { name: /Stop/ }).click();
      await expect(page.locator('[data-wsh-page="indicator"]')).toHaveCount(0);
      await page.evaluate(() => { window.location.hash = '#after'; });
      await new Promise((r) => setTimeout(r, 200));
      expect(got.length).toBe(1);
    } finally { await wsh.disconnect(); }
  });

  test('handles: an app object that cannot be cloned is a handle used across calls (path-bound); a DOM node is refused; release; Stop ends them all', async ({ page }) => {
    const expose = { window: { mode: 'handles', allow: { get: ['app.account', 'app.account.balance', 'document.body', 'document.title'], call: ['app.account.deposit'] }, limits: { maxHandles: 2 } } };
    const { wsh, remote } = await start(page, expose);
    try {
      const account = await remote.app.account;
      expect(account).toBeInstanceOf(RemoteHandle);
      expect(account.type).toBe('Account');
      expect(await use(account).deposit(5)).toBe(15);
      expect(await use(account).deposit(1)).toBe(16);
      expect(await use(account).balance).toBe(16);
      expect(await page.evaluate(() => window.app.account.balance)).toBe(16);
      // The handle stands at window.app.account: members the lists do not name are refused, and the refused names stay refused.
      await expect(Promise.resolve(use(account).secret)).rejects.toMatchObject({ reason: 'not-allowed' });
      await expect(Promise.resolve(use(account).constructor)).rejects.toMatchObject({ reason: 'always-refused' });
      // A DOM node of the real document is not a handle without nodes: true.
      const body = await remote.document.body;
      expect(body).toBeInstanceOf(NonValue);
      expect(body.type).toBe('HTMLBodyElement');
      // Release gives the place back; a released handle is gone.
      await release(account);
      await expect(Promise.resolve(use(account).deposit(1))).rejects.toThrow(/no such handle/);
      expect(await page.evaluate(() => window.app.account.balance)).toBe(16);
      const again = await remote.app.account;
      expect(again).toBeInstanceOf(RemoteHandle);
      await page.locator('[data-wsh-page="indicator"]').getByRole('button', { name: /Stop/ }).click();
      await expect(Promise.resolve(use(again).deposit(1))).rejects.toThrow();
      expect(await page.evaluate(() => window.app.account.balance)).toBe(16);
    } finally { await wsh.disconnect(); }
  });

  test('events through a handle (#219): a real click on a node handle arrives as plain data, needs its own allow.on entry, and ends with release and Stop', async ({ page }) => {
    const expose = { window: { mode: 'handles', nodes: true, allow: { get: ['document.body', 'document.title'], on: ['document.body@click'] } } };
    const { wsh, remote } = await start(page, expose);
    try {
      const body = await remote.document.body;
      expect(body).toBeInstanceOf(RemoteHandle);
      const got = [];
      await on(use(body), 'click', (data, info) => got.push({ data, seq: info.seq }));
      await page.evaluate(() => document.body.click());
      await expect.poll(() => got.length).toBe(1);
      expect(Object.keys(got[0].data).sort()).toEqual(['isTrusted', 'timeStamp', 'type']);
      expect(got[0].data.type).toBe('click');
      // A member of the node has no entry of its own.
      await expect(on(use(body).ownerDocument, 'click', () => {})).rejects.toMatchObject({ reason: expect.stringMatching(/needs-listing|not-allowed/) });
      await release(body);
      await page.evaluate(() => document.body.click());
      expect(await remote.document.title).toBe('Planted Shop Title'); // a round trip after the click: an event, if one were sent, is already here
      expect(got.length).toBe(1);
      // Stop ends a handle subscription too.
      const again = await remote.document.body;
      const stopped = [];
      await on(use(again), 'click', (data) => stopped.push(data));
      await page.locator('[data-wsh-page="indicator"]').getByRole('button', { name: /Stop/ }).click();
      await page.evaluate(() => document.body.click());
      await new Promise((r) => setTimeout(r, 100));
      expect(stopped.length).toBe(0);
    } finally { await wsh.disconnect(); }
  });

  test('handles with nodes: true: a real node is a handle, and ownerDocument and defaultView stay refused until an entry names them', async ({ page }) => {
    const expose = { window: { mode: 'handles', nodes: true, allow: { get: ['document.body', 'document.body.tagName'], call: [] } } };
    const { wsh, remote } = await start(page, expose);
    try {
      const body = await remote.document.body;
      expect(body).toBeInstanceOf(RemoteHandle);
      expect(body.type).toBe('HTMLBodyElement');
      expect(await use(body).tagName).toBe('BODY');
      for (const member of ['ownerDocument', 'parentNode', 'getRootNode']) await expect(Promise.resolve(use(body)[member])).rejects.toMatchObject({ reason: expect.stringMatching(/needs-listing|not-allowed/) });
    } finally { await wsh.disconnect(); }
  });

  test('callbacks: a far-side function reaches the page as a stub it calls with plain values; one-way; refused where the entry does not say (callback); dead after Stop', async ({ page }) => {
    const expose = { window: { allow: { call: ['app.watch(callback)', 'app.tick', 'app.noCallbacks'] } } };
    const { wsh, remote } = await start(page, expose);
    try {
      const got = [];
      expect(await remote.app.watch((v) => got.push(v))).toBe('watching');
      expect(await remote.app.tick(1)).toBe(1);
      await expect.poll(() => got.length).toBe(1);
      expect(got[0]).toEqual({ n: 1, at: 'page' });
      // The stub is one-way: a call from page code returns at once, whatever the far side does.
      expect(await page.evaluate(() => window.__watchers[0]({ n: 2 }))).toBeUndefined();
      await expect.poll(() => got.length).toBe(2);
      await expect(Promise.resolve(remote.app.noCallbacks(() => 1))).rejects.toMatchObject({ reason: 'not-allowed' });
      await page.locator('[data-wsh-page="indicator"]').getByRole('button', { name: /Stop/ }).click();
      await expect(page.locator('[data-wsh-page="indicator"]')).toHaveCount(0);
      expect(await page.evaluate(() => { try { window.__watchers[0]({ n: 3 }); return 'no error'; } catch (e) { return String(e); } })).toBe('no error');
      await new Promise((r) => setTimeout(r, 150));
      expect(got.length).toBe(2);
    } finally { await wsh.disconnect(); }
  });

  test('the indicator is shown while the object session lasts, and Stop ends it', async ({ page }) => {
    const { wsh, remote } = await start(page);
    try {
      expect(await remote.document.title).toBe('Planted Shop Title');
      const indicator = page.locator('[data-wsh-page="indicator"]');
      await expect(indicator).toBeVisible();
      await expect(indicator).toContainText('Remote session connected');
      await indicator.getByRole('button', { name: /Stop/ }).click();
      await expect(Promise.resolve(remote.document.title)).rejects.toThrow(/stopped this session|closed/);
      await expect(indicator).toHaveCount(0);
    } finally { await wsh.disconnect(); }
  });
});
