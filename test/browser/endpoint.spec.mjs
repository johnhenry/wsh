// A named endpoint on a host that lives in the page (#120, #123): `createMemoryHost({ endpoints })` reached by the JS client
// through the byte pipe, with credit-based flow control, a transfer far larger than the credit window, and a refusal.
import { test, expect } from './fixtures.mjs';
import { startPipe } from './nodes.mjs';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw, GATEWAY_CREDIT_WINDOW } from '@johnhenry/wsh';
import { createHash } from 'node:crypto';

const dec = new TextDecoder();

test.describe('named endpoints on a host in the page', () => {
  let pipe; let operatorKey; let raw;
  test.beforeAll(async () => {
    operatorKey = await generateKeyPair(true);
    raw = Array.from(await exportPublicKeyRaw(operatorKey.publicKey));
  });
  test.beforeEach(async () => { pipe = await startPipe(); });
  test.afterEach(async () => { await pipe.close(); });

  async function connect(page, username = 'alice') {
    const id = await page.evaluate((o) => window.h.startHost(o), { authorizedKeys: [raw], endpoints: true });
    await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipe.hostUrl]);
    const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });
    await client.connect(pipe.operatorUrl, { username, keyPair: operatorKey, transport: 'ws' });
    return { id, client };
  }

  /** Deterministic, incompressible-ish bytes. */
  function chunk(i, size) {
    const b = new Uint8Array(size);
    let x = (i * 2654435761) >>> 0;
    for (let k = 0; k < size; k++) { x = (Math.imul(x, 1664525) + 1013904223) >>> 0; b[k] = x >>> 24; }
    return b;
  }

  test('the host offers the endpoints and credit; an echo round-trips, with who', async ({ page }) => {
    const { id, client } = await connect(page);
    try {
      expect(client.hasFeature('gateway-endpoints')).toBe(true);
      expect(client.hasFeature('gateway-credit')).toBe(true);
      expect(client.hasFeature('gateway')).toBe(false); // no TCP in a page
      const duplex = await client.openEndpoint('echo');
      const w = duplex.writable.getWriter();
      await w.write(new TextEncoder().encode('hello page'));
      const r = duplex.readable.getReader();
      expect(dec.decode((await r.read()).value)).toBe('hello page');
      await w.close();
      expect((await r.read()).done).toBe(true);
      expect((await page.evaluate((i) => window.h.hostInfo(i), id)).endpointsOpened).toEqual([{ name: 'echo', user: 'alice' }]);
    } finally { await client.disconnect(); }
  });

  test('a 24 MiB echo through the pipe, far past the credit window, arrives intact', async ({ page }) => {
    const { client } = await connect(page);
    try {
      const duplex = await client.openEndpoint('echo');
      const CHUNK = 64 * 1024; const COUNT = 384; // 24 MiB
      expect(CHUNK * COUNT).toBeGreaterThan(GATEWAY_CREDIT_WINDOW * 90);
      const sent = createHash('sha256'); const got = createHash('sha256');
      const writing = (async () => {
        const w = duplex.writable.getWriter();
        for (let i = 0; i < COUNT; i++) { const c = chunk(i, CHUNK); sent.update(c); await w.write(c); }
        await w.close();
      })();
      let total = 0;
      const r = duplex.readable.getReader();
      for (;;) { const { done, value } = await r.read(); if (done) break; got.update(value); total += value.byteLength; }
      await writing;
      expect(total).toBe(CHUNK * COUNT);
      expect(got.digest('hex')).toBe(sent.digest('hex'));
    } finally { await client.disconnect(); }
  });

  test('a slow reader on the client holds the page back instead of making it buffer (flow control)', async ({ page }) => {
    const { client } = await connect(page);
    try {
      const duplex = await client.openEndpoint('echo');
      const w = duplex.writable.getWriter();
      // Write without reading anything back: the echo's output stops at the credit window, then the echo stops reading,
      // then our writes stop being accepted. A write that never settles is the backpressure; it must not throw or grow.
      let accepted = 0;
      const pump = (async () => { for (let i = 0; i < 400; i++) { await w.write(chunk(i, 64 * 1024)); accepted += 64 * 1024; } })();
      await new Promise((r) => setTimeout(r, 1500));
      const stalledAt = accepted;
      expect(stalledAt).toBeLessThan(400 * 64 * 1024);
      expect(stalledAt).toBeLessThan(16 * 1024 * 1024); // bounded: a few credit windows, not the whole 25 MiB
      await new Promise((r) => setTimeout(r, 500));
      expect(accepted).toBe(stalledAt);
      // Reading resumes the flow and everything completes.
      const r = duplex.readable.getReader();
      let total = 0;
      const reading = (async () => { for (;;) { const { done, value } = await r.read(); if (done) break; total += value.byteLength; } })();
      await pump; await w.close(); await reading;
      expect(total).toBe(400 * 64 * 1024);
    } finally { await client.disconnect(); }
  });

  test('the client sends 8 MiB one way and the page answers with the count', async ({ page }) => {
    const { client } = await connect(page);
    try {
      const duplex = await client.openEndpoint('count');
      const w = duplex.writable.getWriter();
      for (let i = 0; i < 128; i++) await w.write(chunk(i, 64 * 1024));
      await w.close();
      const r = duplex.readable.getReader();
      let text = '';
      for (;;) { const { done, value } = await r.read(); if (done) break; text += dec.decode(value); }
      expect(text).toBe(String(128 * 64 * 1024));
    } finally { await client.disconnect(); }
  });

  test('an unknown name and an endpoint that refuses this caller are denied with a policy error', async ({ page }) => {
    const { client } = await connect(page, 'alice');
    try {
      await expect(client.openEndpoint('nope')).rejects.toMatchObject({ name: 'GatewayError', code: 4 });
      await expect(client.openEndpoint('private')).rejects.toMatchObject({ name: 'GatewayError', code: 4 });
      await expect(client.openEndpoint('../echo')).rejects.toMatchObject({ code: 4 });
      // TCP is not on in a page: the host does not advertise it, so the client refuses before sending anything.
      await expect(client.openTcp('example.com', 80, { timeoutMs: 3000 })).rejects.toMatchObject({ name: 'GatewayError', message: /did not advertise "gateway"/ });
    } finally { await client.disconnect(); }
  });
});
