// A wsh host that lives in the page: `createMemoryHost().accept(new WebSocket(url))` through a byte pipe, driven by the
// JS client from Node (#114, #115, #116, #132, #133). Nothing in the page is wired by hand: public entry points only.
import { test, expect } from './fixtures.mjs';
import { startPipe } from './nodes.mjs';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw, WshFileTransfer } from '@johnhenry/wsh';

const dec = new TextDecoder();
const enc = new TextEncoder();

test.describe('browser host <- JS client over a byte pipe', () => {
  let pipe; let operatorKey; let raw;
  test.beforeAll(async () => {
    operatorKey = await generateKeyPair(true);
    raw = Array.from(await exportPublicKeyRaw(operatorKey.publicKey));
  });
  test.beforeEach(async () => { pipe = await startPipe(); });
  test.afterEach(async () => { await pipe.close(); });

  /** Start a host in the page, serve one pipe socket with it, and connect the Node JS client through the pipe. */
  async function connect(page, options = {}, connectOptions = {}) {
    const id = await page.evaluate((o) => window.h.startHost(o), { authorizedKeys: [raw], ...options });
    await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipe.hostUrl]);
    const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    await client.connect(pipe.operatorUrl, { username: 'alice', keyPair: operatorKey, transport: 'ws', ...connectOptions });
    return { id, client };
  }
  const run = async (client, command, { input } = {}) => {
    const session = await client.openSession({ type: 'exec', command });
    const chunks = [];
    session.onData = (d) => chunks.push(dec.decode(d));
    const exit = new Promise((r) => { session.onExit = r; });
    if (input) { await session.write(input); await session.close?.(); }
    return { out: () => chunks.join(''), exit, session };
  };

  for (const dataStreams of [true, false]) {
    test(`exec and stdin work with dataStreams: ${dataStreams}`, async ({ page }) => {
      const { client } = await connect(page, { dataStreams });
      try {
        const r = await run(client, 'hello');
        expect(await r.exit).toBe(3);
        expect(r.out()).toBe('ran:hello\n');
        expect(r.session.dataMode).toBe(dataStreams ? 'stream' : 'virtual');
        expect(client.hasFeature('stream-announce')).toBe(dataStreams);
        const cat = await run(client, 'cat');
        await cat.session.write('typed into the page\n');
        await expect.poll(() => cat.out()).toBe('typed into the page\n');
      } finally { await client.disconnect(); }
      expect(pipe.traffic.toHost).toBeGreaterThan(0);
      expect(pipe.traffic.toOperator).toBeGreaterThan(0);
    });
  }

  test('pty stdin reaches the page\'s pty as bytes in a browser, which has no Buffer (#133), and resize arrives', async ({ page }) => {
    const { id, client } = await connect(page);
    try {
      const session = await client.openSession({ type: 'pty', cols: 90, rows: 20 });
      const out = []; session.onData = (d) => out.push(dec.decode(d));
      await session.write('ls -l\n');
      await expect.poll(() => out.join('')).toBe('pty-echo:ls -l\n');
      await session.resize(101, 33);
      await expect.poll(async () => (await page.evaluate((i) => window.h.hostInfo(i), id)).ptyCalls.some((c) => c.resize)).toBe(true);
      const info = await page.evaluate((i) => window.h.hostInfo(i), id);
      expect(info.bufferType).toBe('undefined');
      expect(info.ptyCalls).toEqual([{ spawn: ['page-shell', 90, 20] }, { write: true, text: 'ls -l\n' }, { resize: [101, 33] }]);
      expect(info.log.filter((l) => /input not written/.test(l))).toEqual([]);
    } finally { await client.disconnect(); }
  });

  test('file transfer to the page\'s file backend', async ({ page }) => {
    const { id, client } = await connect(page, { initialFiles: { '/a.txt': 'in the page' } });
    try {
      const files = new WshFileTransfer(client);
      expect((await files.list('/')).map((e) => e.name)).toEqual(['a.txt']);
      expect(dec.decode(await client.download('/a.txt'))).toBe('in the page');
      await client.upload(enc.encode('sent to the page'), '/b.txt');
      expect((await page.evaluate((i) => window.h.hostInfo(i), id)).files['/b.txt']).toBe('sent to the page');
      await expect(client.download('/missing')).rejects.toThrow(/no such file/);
    } finally { await client.disconnect(); }
  });

  for (const hostKey of ['pair', 'signer']) {
    test(`a non-extractable host key (${hostKey}) is presented and can be pinned`, async ({ page }) => {
      const id = await page.evaluate((o) => window.h.startHost(o), { authorizedKeys: [raw], hostKey });
      await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipe.hostUrl]);
      const fp = (await page.evaluate((i) => window.h.hostInfo(i), id)).hostFingerprint;
      expect(fp).toMatch(/^[0-9a-f]{64}$/);
      const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
      await client.connect(pipe.operatorUrl, { username: 'alice', keyPair: operatorKey, transport: 'ws', expectHostKey: fp });
      try { expect(client.hostKey).toMatchObject({ fingerprint: fp, status: 'pinned' }); } finally { await client.disconnect(); }
    });
  }

  test('a wrong pin is refused before any credential is sent', async ({ page }) => {
    const id = await page.evaluate((o) => window.h.startHost(o), { authorizedKeys: [raw], hostKey: 'pair' });
    await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipe.hostUrl]);
    const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    await expect(client.connect(pipe.operatorUrl, { username: 'alice', keyPair: operatorKey, transport: 'ws', expectHostKey: 'ab'.repeat(32) })).rejects.toThrow(/host key|fingerprint|pin/i);
  });

  test('a key the host does not know is refused', async ({ page }) => {
    const id = await page.evaluate((o) => window.h.startHost(o), { authorizedKeys: [raw] });
    await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipe.hostUrl]);
    const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    await expect(client.connect(pipe.operatorUrl, { username: 'alice', keyPair: await generateKeyPair(true), transport: 'ws' })).rejects.toThrow(/auth|denied|not authorized|fail/i);
  });
});
