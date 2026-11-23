// Identity in a page (#117, #118, #119): a host that lives in the page behind the PIPE RELAY authenticates a JS operator
// exactly as on a direct connection (host-key pinning, channel binding `host`, an unknown key refused), and a REVERSE host
// in the page that requires operator proof, against the hostile relay of the Node suite (test/helpers/hostile-relay.mjs).
import { test, expect } from './fixtures.mjs';
import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw, exportPublicKeySSH, fingerprint, cborEncode, open, relayForward, MSG } from '@johnhenry/wsh';
import { hostileRelay } from '../helpers/hostile-relay.mjs';

const dec = new TextDecoder();
const collect = (session) => new Promise((resolve) => { const ch = []; session.onData = (d) => ch.push(dec.decode(d)); session.onClose = () => resolve(ch.join('')); });

test.describe('an in-page host behind the pipe relay', () => {
  let relay; let relayUrl; let operatorKey; let raw;
  test.beforeAll(async () => {
    operatorKey = await generateKeyPair(true);
    raw = Array.from(await exportPublicKeyRaw(operatorKey.publicKey));
  });
  test.beforeEach(async () => { relay = createPipeRelay(); relayUrl = `ws://127.0.0.1:${(await relay.listen()).port}`; });
  test.afterEach(async () => { await relay.close(); });

  /** The page's host serves its own WebSocket to the relay as `role: host`; resolves the operator's URL. */
  async function behindPipe(page, options = {}) {
    const id = await page.evaluate((o) => window.h.startHost(o), { authorizedKeys: [raw], hostKey: 'pair', ...options });
    const rendezvous = newRendezvousId();
    await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipeUrl(relayUrl, rendezvous, 'host')]);
    const fp = (await page.evaluate((i) => window.h.hostInfo(i), id)).hostFingerprint;
    return { id, fp, url: pipeUrl(relayUrl, rendezvous) };
  }
  const operator = () => new WshClient({ transportFactories: { ws: () => new WebSocketTransport() } });

  test('an authorized JS operator runs a command, its login is bound to the host key, and the host key can be pinned', async ({ page }) => {
    const { fp, url } = await behindPipe(page);
    const client = operator();
    await client.connect(url, { username: 'alice', keyPair: operatorKey, transport: 'ws', expectHostKey: fp, requireChannelBinding: ['host'] });
    try {
      expect(client.hostKey).toMatchObject({ fingerprint: fp, status: 'pinned' });
      expect(client.channelBinding).toEqual(['host']);
      expect(client.authTtl).toBe(0);
      expect(await collect(await client.openSession({ type: 'exec', command: 'hello' }))).toBe('ran:hello\n');
    } finally { await client.disconnect(); }
  });

  test('a wrong pin is refused through the pipe, and so is a key the host does not know', async ({ page }) => {
    const pinned = await behindPipe(page);
    await expect(operator().connect(pinned.url, { username: 'alice', keyPair: operatorKey, transport: 'ws', expectHostKey: 'ab'.repeat(32) })).rejects.toThrow(/host key|fingerprint|pin/i);
    const other = await behindPipe(page);
    await expect(operator().connect(other.url, { username: 'alice', keyPair: await generateKeyPair(true), transport: 'ws' })).rejects.toThrow(/auth|denied|not authorized|fail/i);
  });

  test('a host that requires channel binding is served by an operator that binds (kind host), through the pipe', async ({ page }) => {
    const { url } = await behindPipe(page, { requireChannelBinding: ['host'] });
    const client = operator();
    await client.connect(url, { username: 'alice', keyPair: operatorKey, transport: 'ws', requireChannelBinding: true });
    try { expect(client.channelBinding).toEqual(['host']); } finally { await client.disconnect(); }
  });

  test('the client env allow-list holds in a page: PATH is dropped, TERM kept', async ({ page }) => {
    const { url } = await behindPipe(page);
    const client = operator();
    await client.connect(url, { username: 'alice', keyPair: operatorKey, transport: 'ws' });
    try {
      const out = await collect(await client.openSession({ type: 'exec', command: 'env', env: { TERM: 'xterm', PATH: '/evil', LC_ALL: 'C' } }));
      expect(JSON.parse(out)).toEqual({ TERM: 'xterm', LC_ALL: 'C' });
    } finally { await client.disconnect(); }
  });

  test('an operator pinning one host key refuses another in-page host (another key) behind the pipe', async ({ page }) => {
    const { fp, url } = await behindPipe(page);
    // Another in-page host, with another key (the impostor-first-at-the-rendezvous case is in test/pipe-relay.test.mjs).
    const impostor = await behindPipe(page);
    expect(impostor.fp).not.toBe(fp);
    await expect(operator().connect(impostor.url, { username: 'alice', keyPair: operatorKey, transport: 'ws', expectHostKey: fp })).rejects.toThrow(/host key/i);
    void url;
  });
});

test.describe('an in-page reverse host that requires operator proof, behind a hostile relay', () => {
  const keys = {};
  let authorizedKeys; let server; let relayUrl; let mitm; const closers = [];
  test.beforeAll(async () => {
    for (const name of ['bob', 'mallory']) {
      const keyPair = await generateKeyPair(true);
      const rawKey = await exportPublicKeyRaw(keyPair.publicKey);
      keys[name] = { keyPair, raw: rawKey, fp: await fingerprint(rawKey) };
    }
    authorizedKeys = (await Promise.all(Object.entries(keys).map(async ([n, k]) => `${await exportPublicKeySSH(k.keyPair.publicKey)} ${n}`))).join('\n');
  });
  test.afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

  /** A relay; a hostile hop in front of the page host's relay connection; the page's host dialling that hop. */
  async function world(page, hop = {}) {
    // The page's own (non-extractable) key is the host's identity at the relay: the relay must be told its public half.
    const hostLine = await page.evaluate(() => window.h.newKey('host'));
    server = createWshServer({
      auth: { authorizedKeys: `${authorizedKeys}\n${hostLine} host` },
      relay: { canRegister: (w) => w.username === 'host', canConnect: (f) => f.username !== 'host', connectTimeoutMs: 3000 },
    });
    relayUrl = `ws://127.0.0.1:${(await server.listen()).port}`;
    closers.push(() => server.close());
    mitm = await hostileRelay(relayUrl, hop);
    closers.push(() => mitm.close());
    const host = await page.evaluate((o) => window.h.startReverseHost(o), { url: mitm.url, acceptFingerprints: [keys.bob.fp] });
    expect(host.bufferType).toBe('undefined');
    for (let i = 0; i < 200 && !server.peerFingerprints?.().includes(host.fingerprint); i++) await new Promise((r) => setTimeout(r, 25));
    return host;
  }
  async function login(name) {
    const c = new WshClient();
    await c.connect(relayUrl, { username: name, keyPair: keys[name].keyPair, transport: 'ws' });
    closers.push(() => c.disconnect());
    return c;
  }

  test('a proven operator is accepted (accept hears who proved it), the bridge is sealed, and the relay reads nothing', async ({ page }) => {
    const host = await world(page);
    const bob = await login('bob');
    const res = await bob.reverseConnect(host.fingerprint, 5000, { sealed: true });
    expect(res.type).toBe(MSG.REVERSE_ACCEPT);
    expect(res.features).toContain('e2e-sealed');
    const out = await collect(await bob.openSession({ type: 'exec', command: 'echo SECRET-IN-A-PAGE' }));
    expect(out).toBe('ran:echo SECRET-IN-A-PAGE\n');
    const info = await page.evaluate((i) => window.h.reverseInfo(i), host.id);
    expect(info.accepted).toHaveLength(1);
    expect(info.accepted[0]).toMatchObject({ fingerprint: keys.bob.fp, username: 'bob', proven: true });
    expect(info.accepted[0].publicKey).toEqual(Array.from(keys.bob.raw));
    const wire = JSON.stringify(mitm.seen.map((s) => s.msg), (_k, v) => (v instanceof Uint8Array ? Array.from(v) : v));
    expect(wire).not.toContain('SECRET-IN-A-PAGE');
    expect(info.ran).toEqual(['echo SECRET-IN-A-PAGE']);
  });

  test('an operator that offers no proof is refused, and accept never runs', async ({ page }) => {
    const host = await world(page);
    const bob = await login('bob');
    const res = await bob.reverseConnect(host.fingerprint, 5000, { proof: false });
    expect(res.type).toBe(MSG.REVERSE_REJECT);
    expect(res.reason).toMatch(/operator proof required/);
    expect((await page.evaluate((i) => window.h.reverseInfo(i), host.id)).accepted).toEqual([]);
  });

  test('a relay that rewrites from_fingerprint to an authorized operator gets nothing: accept never runs, nothing runs', async ({ page }) => {
    const host = await world(page, { toClient: (m) => (m.type === MSG.REVERSE_CONNECT ? { ...m, from_fingerprint: keys.bob.fp } : m) });
    const mallory = await login('mallory');
    const res = await mallory.reverseConnect(host.fingerprint, 3000).catch((e) => e);
    expect(res instanceof Error || res.type === MSG.REVERSE_REJECT).toBe(true);
    const info = await page.evaluate((i) => window.h.reverseInfo(i), host.id);
    expect(info.accepted).toEqual([]);
    expect(info.ran).toEqual([]);
    expect(info.operators).toEqual([]);
  });

  test('a relay that injects a plain Open into a sealed bridge runs nothing', async ({ page }) => {
    const host = await world(page);
    const bob = await login('bob');
    await bob.reverseConnect(host.fingerprint, 5000, { sealed: true });
    const ctx = mitm.context();
    await ctx.injectToClient(relayForward({ fromFingerprint: keys.bob.fp, inner: cborEncode(open({ kind: 'exec', command: 'echo INJECTED' })) }));
    expect(await collect(await bob.openSession({ type: 'exec', command: 'legit' }))).toBe('ran:legit\n');
    await new Promise((r) => setTimeout(r, 400));
    expect((await page.evaluate((i) => window.h.reverseInfo(i), host.id)).ran).toEqual(['legit']);
  });
});
