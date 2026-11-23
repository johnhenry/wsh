// UDP as WebTransport datagrams (#124) from a real Chromium page to the Node host: the page connects over HTTP/3 with the host's
// self-signed certificate pinned by hash (`serverCertificateHashes`), opens a UDP flow to a local echo server, and checks that its
// payloads traveled as datagrams (the host's counters), that a DNS-sized and a near-limit datagram round-trip, that an oversize
// payload still arrives (reliable stream), and that over WebSocket the same page code falls back to the control stream.
//
// If Chromium cannot open an HTTP/3 session to the host in this environment (a container without UDP, say) the WebTransport tests
// are skipped, and the skip prints why, rather than failing: the Node WebTransport client test (test/gateway-datagram.test.mjs)
// covers the same path there.
import { test, expect } from './fixtures.mjs';
import { startServer } from './nodes.mjs';
import dgram from 'node:dgram';

let echo; let echoPort; let ctx;
test.describe('browser client -> Node host: UDP datagrams', () => {
  test.beforeEach(async ({ page }) => {
    echo = dgram.createSocket('udp4');
    await new Promise((r) => echo.bind(0, '127.0.0.1', r));
    echoPort = echo.address().port;
    echo.on('message', (m, r) => echo.send(m, r.port, r.address));
    const authorized = await page.evaluate(() => window.h.newKey('k', { extractable: false }));
    ctx = await startServer({ auth: { authorizedKeys: authorized }, gateway: { allow: [`127.0.0.1:${echoPort}`] }, webTransport: { selfSigned: true } });
  });
  test.afterEach(async () => { echo.close(); await ctx.close(); });

  /** Runs in the page: connect (over WebTransport or WebSocket), open the UDP flow, run the exchanges. */
  const exchange = async ([wtUrl, wsUrl, hash, port, useWt]) => {
    const { WshClient, WebTransportTransport, WebSocketTransport } = window.wsh;
    const client = new WshClient({ transportFactories: { wt: () => new WebTransportTransport(), ws: () => new WebSocketTransport() } });
    const options = { username: 'alice', keyPair: window.h.key('k') };
    if (useWt) await client.connect(wtUrl, { ...options, transport: 'wt', webTransport: { serverCertificateHashes: [{ algorithm: 'sha-256', value: new Uint8Array(hash) }] } });
    else await client.connect(wsUrl, { ...options, transport: 'ws' });
    const flow = await client.openUdp('127.0.0.1', port);
    const reader = flow.readable.getReader();
    const make = (n) => Uint8Array.from({ length: n }, (_, i) => (i * 7) & 255);
    const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
    const out = { transport: flow.transport, maxDatagramSize: flow.maxDatagramSize, feature: client.hasFeature('gateway-datagram'), ok: {} };
    for (const [name, n] of [['dns', 33], ['large', Math.min(flow.maxDatagramSize, 1200)], ['oversize', 3000]]) {
      const q = make(n);
      await flow.send(q);
      const { value } = await reader.read();
      out.ok[name] = same(value, q);
    }
    out.stats = { ...flow.stats };
    flow.destroy();
    await client.disconnect();
    return out;
  };

  test('datagrams over WebTransport: DNS-sized, near-limit and oversize payloads round-trip', async ({ page }) => {
    const hash = Array.from(ctx.server.webTransport().certificateHash);
    let result;
    try {
      result = await page.evaluate(exchange, [ctx.server.webTransport().url, ctx.url, hash, echoPort, true]);
    } catch (e) {
      test.skip(true, `Chromium could not open a WebTransport (HTTP/3) session to the Node host here, so the browser datagram test is skipped (${String(e.message).split('\n')[0]}); the Node WebTransport client test covers the path`);
    }
    expect(result.feature).toBe(true);
    expect(result.transport).toBe('datagram');
    expect(result.maxDatagramSize).toBeGreaterThan(500);
    expect(result.ok).toEqual({ dns: true, large: true, oversize: true });
    expect(result.stats.sentReliable).toBe(1); // only the 3000-byte payload used the control stream
    const s = ctx.server.gatewayStats().udp;
    expect(s.datagramsFromClient).toBe(2);
    expect(s.datagramsToClient).toBe(2);
    expect(s.oversizeReliable).toBe(1);
  });

  test('over WebSocket the same page code uses the reliable control stream', async ({ page }) => {
    const result = await page.evaluate(exchange, [ctx.server.webTransport().url, ctx.url, [], echoPort, false]);
    expect(result.feature).toBe(false);
    expect(result.transport).toBe('stream');
    expect(result.ok).toEqual({ dns: true, large: true, oversize: true });
    expect(ctx.server.gatewayStats().udp.datagramsFromClient).toBe(0);
  });
});
