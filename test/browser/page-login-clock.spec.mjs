// The login deadline of a page host in a REAL Chromium page (#253). The 60 s `loginTimeoutMs` of #248 counts from the moment an operator is THERE, not from the moment the
// page dialled the relay (or the listener) and began to wait: a page that waits for its operator longer than the deadline keeps its half (no redial, no `login-timeout`
// refusal), and the operator who then arrives logs in. An operator that arrives and never logs in is still closed at the deadline. The deadline is set to 1 s here, which is
// what `loginTimeoutMs` on `createPageHost` is for; the page waits 3.5 s, well past it. The relay is the real pipe relay, which tells the page when its partner has come.
import { test, expect } from './fixtures.mjs';
import { WebSocket as WsClient, WebSocketServer } from 'ws';
import { createPipeRelay } from '@johnhenry/wsh/pipe-relay';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { connectWshOverDuplex } from '@johnhenry/wsh/duplex';

const DEADLINE_MS = 1000;
const WAIT_MS = 3500;

test.describe('a page host that waits longer than the login deadline for its operator', () => {
  let alice; let aliceLine; let relay; let relayUrl;
  test.beforeAll(async () => { alice = await generateKeyPair(true); aliceLine = await exportPublicKeySSH(alice.publicKey); });
  test.beforeEach(async () => {
    relay = createPipeRelay();
    const { port } = await relay.listen();
    relayUrl = `ws://127.0.0.1:${port}`;
  });
  test.afterEach(async () => { await relay.close(); });

  const start = (page) => page.evaluate((o) => window.h.startPageHost(o), {
    relay: relayUrl, authorizedKeys: [aliceLine], allow: ['search'], loginTimeoutMs: DEADLINE_MS,
  });

  test('behind a relay: it neither redials nor refuses while nobody is there, and the operator who then arrives logs in', async ({ page }) => {
    await page.evaluate(() => window.h.pageTools());
    const host = await start(page);
    await expect.poll(() => relay.stats().waiting).toBe(1);
    await page.waitForTimeout(WAIT_MS);
    const log = await page.evaluate(() => window.h.hostLog());
    expect(log.filter((l) => l.startsWith('dialed'))).toHaveLength(1);
    expect(log.filter((l) => l.startsWith('refused'))).toEqual([]);
    expect(relay.stats().waiting).toBe(1);   // its half is still there, the same one

    const wsh = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    try {
      await wsh.connect(host.operatorUrl, { username: 'alice', keyPair: alice, transport: 'ws', sealSession: true, expectHostKey: host.fingerprint });
      expect(wsh.state).toBe('authenticated');
      expect(wsh.sessionSealed).toBe(true);
    } finally { await wsh.disconnect().catch(() => {}); }
    expect((await page.evaluate(() => window.h.hostLog())).filter((l) => l.startsWith('refused'))).toEqual([]);
  });

  test('behind a relay: an operator that arrives and never logs in is closed at the deadline, counted from its arrival', async ({ page }) => {
    await page.evaluate(() => window.h.pageTools());
    const host = await start(page);
    await expect.poll(() => relay.stats().waiting).toBe(1);
    await page.waitForTimeout(WAIT_MS);
    expect((await page.evaluate(() => window.h.hostLog())).filter((l) => l.startsWith('refused'))).toEqual([]);

    const silent = new WsClient(host.operatorUrl);   // pairs with the page, and says nothing
    silent.on('error', () => {});
    const arrived = Date.now();
    const closed = new Promise((resolve) => silent.once('close', resolve));
    try {
      await closed;
      expect(Date.now() - arrived).toBeGreaterThanOrEqual(DEADLINE_MS - 100);
      await expect.poll(async () => (await page.evaluate(() => window.h.hostLog())).filter((l) => l.startsWith('refused: login-timeout')).length).toBe(1);
    } finally { silent.terminate(); }
  });
});

test.describe('the dial-out form waits as long, too', () => {
  let alice; let aliceLine; let wss; let arrivals;
  test.beforeAll(async () => { alice = await generateKeyPair(true); aliceLine = await exportPublicKeySSH(alice.publicKey); });
  test.beforeEach(async () => {
    wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise((r) => wss.once('listening', r));
    arrivals = [];
    wss.on('connection', (ws) => {
      const entry = { ws, queue: [], sink: null };
      ws.on('message', (d) => { if (entry.sink) entry.sink(d); else entry.queue.push(d); });
      arrivals.push(entry);
    });
  });
  test.afterEach(async () => { for (const c of wss.clients) c.terminate(); await new Promise((r) => wss.close(r)); });

  test('a listener that has accepted the page and said nothing for longer than the deadline has not had it refused or closed; it then logs in', async ({ page }) => {
    await page.evaluate(() => window.h.pageTools());
    const host = await page.evaluate((o) => window.h.startPageHost(o), {
      connect: `ws://127.0.0.1:${wss.address().port}/`, authorizedKeys: [aliceLine], allow: ['search'], loginTimeoutMs: DEADLINE_MS,
    });
    await expect.poll(() => arrivals.length).toBe(1);
    await page.waitForTimeout(WAIT_MS);
    expect(arrivals).toHaveLength(1);                                  // the page did not have to dial again
    expect(arrivals[0].ws.readyState).toBe(1);                         // and its socket is open
    expect((await page.evaluate(() => window.h.hostLog())).filter((l) => l.startsWith('refused'))).toEqual([]);

    const entry = arrivals[0];
    const link = connectWshOverDuplex({ send: (b) => entry.ws.send(b), close: () => entry.ws.close(1000) }, { username: 'alice', keyPair: alice, expectHostKey: host.fingerprint, timeout: 5000 });
    entry.sink = (d) => link.receive(d);
    for (const d of entry.queue.splice(0)) link.receive(d);
    entry.ws.on('close', () => link.end('the page closed the connection'));
    const wsh = await link.connected;
    try {
      expect(wsh.state).toBe('authenticated');
      expect(wsh.sessionSealed).toBe(true);
    } finally { await wsh.disconnect().catch(() => {}); }
  });
});
