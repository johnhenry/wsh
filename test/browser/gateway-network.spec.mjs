// A host in the page serves the gateway over a network the page supplies (#299): `createMemoryHost({ gateway: { network } })` bundled for the browser,
// reached by the JS client through the byte pipe. The network is virtual (`test/helpers/virtual-network.mjs`); what is pinned is that the gateway session, its
// destination policy and its credit flow control run in a browser with no Node under them.
import { test, expect } from './fixtures.mjs';
import { startPipe } from './nodes.mjs';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw, GATEWAY_CREDIT_WINDOW } from '@johnhenry/wsh';
import { createHash } from 'node:crypto';

const enc = new TextEncoder();
const dec = new TextDecoder();

test.describe('the gateway of a host in the page, over the page\'s own network', () => {
  let operatorKey; let raw;
  const pipes = [];
  test.beforeAll(async () => {
    operatorKey = await generateKeyPair(true);
    raw = Array.from(await exportPublicKeyRaw(operatorKey.publicKey));
  });
  test.afterEach(async () => { for (const p of pipes.splice(0)) await p.close(); });

  /** A host in the page behind a byte pipe of its own (one pairing each, so a host that outlives its client cannot be paired with the next one). */
  async function connect(page, gateway) {
    const pipe = await startPipe();
    pipes.push(pipe);
    const id = await page.evaluate((o) => window.h.startNetworkHost(o), { authorizedKeys: [raw], gateway });
    await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipe.hostUrl]);
    const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    await client.connect(pipe.operatorUrl, { username: 'alice', keyPair: operatorKey, transport: 'ws' });
    return { id, client };
  }

  function chunk(i, size) {
    const b = new Uint8Array(size);
    let x = (i * 2654435761) >>> 0;
    for (let k = 0; k < size; k++) { x = (Math.imul(x, 1664525) + 1013904223) >>> 0; b[k] = x >>> 24; }
    return b;
  }

  test('the gateway entry point bundles for the browser and runs there', async ({ page }) => {
    const info = await page.evaluate(() => window.h.gatewayEntryInfo());
    expect(info.exports).toEqual(expect.arrayContaining(['GATEWAY_FAIL', 'createGatewaySession', 'normalizeGateway', 'normalizeNetwork']));
    expect(info.policyDenied).toBe(4);
    expect(info.bufferType).toBe('undefined');
  });

  test('a TCP connection reaches the network by name, byte-exact with a half-close; the network was asked once, for the address', async ({ page }) => {
    const { id, client } = await connect(page);
    try {
      expect(client.hasFeature('gateway')).toBe(true);
      expect(client.hasFeature('gateway-credit')).toBe(true);
      const d = await client.openTcp('svc.test', 7);
      const w = d.writable.getWriter();
      await w.write(enc.encode('hello network'));
      await w.close();
      const r = d.readable.getReader();
      let got = '';
      for (;;) { const { value, done } = await r.read(); if (done) break; got += dec.decode(value); }
      expect(got).toBe('hello network');
      const calls = await page.evaluate((i) => window.h.networkCalls(i), id);
      expect(calls.resolve).toEqual(['svc.test']);
      expect(calls.connect).toEqual([['93.184.216.7', 7]]);
    } finally { await client.disconnect(); }
  });

  test('an address of the network\'s own that is private is refused until the embedder names it; nothing is dialled for it', async ({ page }) => {
    const { id, client } = await connect(page);
    try {
      await expect(client.openTcp('inner.test', 7)).rejects.toThrow(/not permitted by the gateway policy/);
      await expect(client.openTcp('nobody.test', 7)).rejects.toThrow(/not allowed/);
      expect((await page.evaluate((i) => window.h.networkCalls(i), id)).connect).toEqual([]);
    } finally { await client.disconnect(); }
    const named = await connect(page, { allowPrivate: ['10.0.0.0/8'] });
    try {
      (await named.client.openTcp('inner.test', 7)).destroy();
      expect((await page.evaluate((i) => window.h.networkCalls(i), named.id)).connect).toEqual([['10.0.0.5', 7]]);
    } finally { await named.client.disconnect(); }
  });

  test('a 12 MiB echo, far past the credit window, arrives intact', async ({ page }) => {
    const { client } = await connect(page);
    try {
      const d = await client.openTcp('svc.test', 7);
      const CHUNK = 64 * 1024; const COUNT = 192;
      expect(CHUNK * COUNT).toBeGreaterThan(GATEWAY_CREDIT_WINDOW * 40);
      const sent = createHash('sha256'); const got = createHash('sha256');
      const writing = (async () => {
        const w = d.writable.getWriter();
        for (let i = 0; i < COUNT; i++) { const c = chunk(i, CHUNK); sent.update(c); await w.write(c); }
        await w.close();
      })();
      let total = 0;
      const r = d.readable.getReader();
      for (;;) { const { done, value } = await r.read(); if (done) break; got.update(value); total += value.byteLength; }
      await writing;
      expect(total).toBe(CHUNK * COUNT);
      expect(got.digest('hex')).toBe(sent.digest('hex'));
    } finally { await client.disconnect(); }
  });

  test('UDP is refused unless the embedder turned it on; with it a datagram round-trips', async ({ page }) => {
    const off = await connect(page);
    try {
      await expect(off.client.openUdp('93.184.216.7', 53)).rejects.toThrow(/UDP is not enabled/);
    } finally { await off.client.disconnect(); }
    const on = await connect(page, { udp: true });
    try {
      const flow = await on.client.openUdp('93.184.216.7', 53);
      const w = flow.writable.getWriter(); await w.write(enc.encode('ping'));
      expect(dec.decode((await flow.readable.getReader().read()).value)).toBe('ping');
      flow.close();
    } finally { await on.client.disconnect(); }
  });

  test('a client that goes away: the network\'s signal is aborted', async ({ page }) => {
    const { id, client } = await connect(page);
    await client.openTcp('svc.test', 7);
    await client.disconnect();
    await expect.poll(async () => (await page.evaluate((i) => window.h.networkCalls(i), id)).signalsAborted).toEqual([true]);
  });
});
