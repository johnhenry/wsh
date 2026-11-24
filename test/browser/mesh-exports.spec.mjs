// The exports a mesh adapter leans on (#220), run in a real browser: the capability evaluation, the identity conversions on real WebCrypto
// keys, an `authorized_keys` line a Node host reads back, the in-process pipe relay and memory pair, and MCP / objects over a bare duplex.
import { test, expect } from './fixtures.mjs';
import { parseAuthorizedKeyLine } from '../../src/key-options.mjs';

test.describe('the exports for a mesh adapter, in a page', () => {
  test('permits() and the identity module agree with Node on a real key', async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { generateKeyPair, exportPublicKeyRaw, permits, identityOf, fingerprintToPodId, podIdToFingerprint, authorizedKeyLine, rawKeyToOpenSsh, openSshToRawKey } = window.wsh;
      const kp = await generateKeyPair(true);
      const raw = await exportPublicKeyRaw(kp.publicKey);
      const id = await identityOf(raw);
      return {
        raw: Array.from(raw),
        id: { fingerprint: id.fingerprint, podId: id.podId, openssh: id.openssh },
        roundTrip: podIdToFingerprint(fingerprintToPodId(id.fingerprint)) === id.fingerprint,
        sshBack: Array.from(openSshToRawKey(rawKeyToOpenSsh(raw))),
        line: authorizedKeyLine(raw, { capabilities: ['objects:window:get', 'gateway:tcp:*.example.com:443'], expires: '2030-01-01T00:00:00Z', comment: 'page' }),
        allowed: permits(['gateway:tcp:*.example.com:443'], { kind: 'tcp', host: 'a.example.com', port: 443 }),
        apex: permits(['gateway:tcp:*.example.com:443'], { kind: 'tcp', host: 'example.com', port: 443 }),
        unknown: permits(['exec', 'teleport'], { kind: 'open', channel: 'exec' }),
      };
    });
    expect(out.roundTrip).toBe(true);
    expect(out.sshBack).toEqual(out.raw);
    expect(out.allowed).toBe(true);
    expect(out.apex).toBe(false);
    expect(out.unknown).toBe(false);
    const parsed = parseAuthorizedKeyLine(out.line);
    expect(Array.from(parsed.key)).toEqual(out.raw);
    expect(parsed.permissions.capabilities).toEqual(['objects:window:get', 'gateway:tcp:*.example.com:443']);
    expect(parsed.permissions.expires).toBe(1893456000);
  });

  test('the in-process pipe relay joins a page host and a client, and its tap sees the sealed bytes only', async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { createInProcessPipeRelay, createMemoryHost, pipeUrl, newRendezvousId, WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw } = window.wsh;
      const env = await createInProcessPipeRelay();
      const kp = await generateKeyPair(true);
      const host = createMemoryHost({ auth: { authorizedKeys: [await exportPublicKeyRaw(kp.publicKey)] }, exec: async (c, io) => { await io.write(`ran:${c}\n`); return 0; }, hostKey: true, dataStreams: false, sealSession: 'require' });
      const rid = newRendezvousId();
      void host.accept(new env.WebSocket(pipeUrl('ws://relay.test', rid, 'host')));
      const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport({ WebSocket: env.WebSocket }) } });
      await client.connect(pipeUrl('ws://relay.test', rid), { transport: 'ws', username: 'alice', keyPair: kp });
      let text = '';
      const session = await client.openSession({ type: 'exec', command: 'marker-xyz' });
      session.onData = (d) => { text += new TextDecoder().decode(d); };
      for (let i = 0; i < 200 && !text.includes('ran:marker-xyz'); i++) await new Promise((r) => setTimeout(r, 10));
      const seen = env.recorded.map((r) => new TextDecoder('latin1').decode(r.bytes)).join('');
      await client.disconnect(); await host.close(); await env.close();
      return { text, plain: seen.includes('marker-xyz'), recorded: env.recorded.length };
    });
    expect(out.text).toBe('ran:marker-xyz\n');
    expect(out.plain).toBe(false);
    expect(out.recorded).toBeGreaterThan(0);
  });

  test('MCP over a bare duplex serves a page\'s WebMCP tools to a plain JSON-RPC peer; objects over createDuplexPeer carry a pod id', async ({ page }) => {
    const out = await page.evaluate(async () => {
      const { webmcpTools, serveMcpOverDuplex, createDuplexPeer, createObjectsServer, createObjectsClient, podIdToFingerprint } = window.wsh;
      const tool = { name: 'search', description: 'Search', inputSchema: { type: 'object', properties: { q: { type: 'string' } } }, annotations: { readOnlyHint: true }, execute: ({ q }) => ({ hits: [`${q}-1`] }) };
      const inbox = [];
      const session = serveMcpOverDuplex(webmcpTools({ window, allow: ['search'], tools: [tool], approve: 'never' }), { send: (m) => { inbox.push(m); } });
      const until = async (id) => { for (let i = 0; i < 300; i++) { const m = inbox.find((x) => x.id === id); if (m) return m; await new Promise((r) => setTimeout(r, 5)); } return null; };
      session.receive({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'search', arguments: { q: 'x' } } });
      const called = await until(1);
      session.receive({ jsonrpc: '2.0', id: 2, method: 'no/such' });
      const missing = await until(2);
      session.close();

      const podId = 'A'.repeat(43);
      let a; let b;
      a = createDuplexPeer({ send: (m) => queueMicrotask(() => b.receive(structuredClone(m))) });
      b = createDuplexPeer({ send: (m) => queueMicrotask(() => a.receive(structuredClone(m))), who: { username: 'mesh', podId } });
      const asked = [];
      createObjectsServer({ roots: { box: { value: 7 } }, allow: { get: ['box.value'] }, authorize: (who) => { asked.push(who); return true; } }).attach(b);
      const objects = await createObjectsClient(a);
      const value = await objects.box.value;
      return { structured: called.result.structuredContent, untrusted: called.result._meta['wsh/untrusted'], missing: missing.error.code, value, asked, fp: podIdToFingerprint(podId) };
    });
    expect(out.structured).toEqual({ hits: ['x-1'] });
    expect(out.untrusted).toBe(true);
    expect(out.missing).toBe(-32601);
    expect(out.value).toBe(7);
    expect(out.asked).toEqual([{ username: 'mesh', fingerprint: out.fp, podId: 'A'.repeat(43) }]);
  });
});
