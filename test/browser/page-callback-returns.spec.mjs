// Callback return values (#219) in a REAL Chromium page host: an entry that says `(callback:returns)` gives the page's stub a promise of what the far side's function
// returned; the page never waits past the host's bound, and Stop settles a call that is waiting at once. A relay is the repo's own pipe relay.
import { test, expect } from './fixtures.mjs';
import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import '@johnhenry/wsh/objects';   // adds client.openObjects()

test.describe('a real page host: callbacks that return a value', () => {
  let relay; let base; let id; let alice; let aliceLine;
  test.beforeAll(async () => { alice = await generateKeyPair(true); aliceLine = await exportPublicKeySSH(alice.publicKey); });
  test.beforeEach(async () => { relay = createPipeRelay(); base = `ws://127.0.0.1:${(await relay.listen()).port}`; id = newRendezvousId(); });
  test.afterEach(async () => { await relay.close(); });

  async function start(page, limits) {
    await page.evaluate(() => window.h.pageApp());
    const expose = { window: { allow: { call: ['app.ask(callback:returns)', 'app.noCallbacks'] }, ...(limits ? { limits } : {}) } };
    const host = await page.evaluate((o) => window.h.startPageHost(o), { relay: { url: base, id }, authorizedKeys: [aliceLine], expose });
    const wsh = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    await wsh.connect(pipeUrl(base, id), { username: 'alice', keyPair: alice, transport: 'ws', sealSession: true, expectHostKey: host.fingerprint });
    return { wsh, remote: (await wsh.openObjects()).window };
  }

  test('the page gets the far side\'s answer as a promise, also from an async function; a function that throws, or answers with a function, is undefined', async ({ page }) => {
    const { wsh, remote } = await start(page);
    try {
      const questions = [];
      expect(await remote.app.ask(async (q) => { questions.push(q); if (q === 'throw') throw new Error('far-side text'); if (q === 'fn') return () => 1; return { answer: `to ${q}`, bytes: new Uint8Array([1, 2]) }; })).toBe('asked');
      expect(await page.evaluate(async () => { const r = await window.__askers[0]('why'); return { answer: r.answer, bytes: [...r.bytes] }; })).toEqual({ answer: 'to why', bytes: [1, 2] });
      expect(await page.evaluate(() => window.__askers[0]('throw'))).toBeUndefined();
      expect(await page.evaluate(() => window.__askers[0]('fn'))).toBeUndefined();
      expect(questions).toEqual(['why', 'throw', 'fn']);
      // An entry that says nothing of returns stays one-way: the call is refused when it carries a function the entry does not accept, as before.
      await expect(Promise.resolve(remote.app.noCallbacks(() => 1))).rejects.toMatchObject({ reason: 'not-allowed' });
    } finally { await wsh.disconnect(); }
  });

  test('the page waits at most the host\'s bound: a far side that never answers is undefined after it, and the page is not blocked meanwhile', async ({ page }) => {
    const { wsh, remote } = await start(page, { callbackReturnTimeoutMs: 400 });
    try {
      await remote.app.ask(() => new Promise(() => {}));
      const outcome = await page.evaluate(async () => {
        const started = performance.now();
        const waiting = window.__askers[0]('never');
        const returnedAt = performance.now() - started;     // the call itself came back at once, with a promise
        const value = await waiting;
        return { isPromise: waiting instanceof Promise, returnedAt, value: value === undefined ? 'undefined' : value, waited: performance.now() - started };
      });
      expect(outcome.isPromise).toBe(true);
      expect(outcome.returnedAt).toBeLessThan(200);
      expect(outcome.value).toBe('undefined');
      expect(outcome.waited).toBeGreaterThanOrEqual(300);   // not an exact count: it waited for the bound, not for the far side
      expect(outcome.waited).toBeLessThan(8000);
    } finally { await wsh.disconnect(); }
  });

  test('Stop settles a waiting call with undefined at once, long before a 20 second bound', async ({ page }) => {
    const { wsh, remote } = await start(page, { callbackReturnTimeoutMs: 20_000 });
    try {
      await remote.app.ask(() => new Promise(() => {}));
      await page.evaluate(() => { window.__pending = window.__askers[0]('never'); });
      await page.locator('[data-wsh-page="indicator"]').getByRole('button', { name: /Stop/ }).click();
      expect(await page.evaluate(async () => { const v = await window.__pending; return v === undefined ? 'undefined' : v; })).toBe('undefined');
      expect(await page.evaluate(async () => { const v = await window.__askers[0]('after'); return v === undefined ? 'undefined' : v; })).toBe('undefined');
    } finally { await wsh.disconnect().catch(() => {}); }
  });
});
