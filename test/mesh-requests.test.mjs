// What the browsermesh adapter asked for on top of #220: the permission hook of the MCP handler tells a list from a call; the badge is its own
// export; a host that requires a sealed session says so to `authorize` and says when the session is sealed; and the identity shape
// `{ username: null, fingerprint: null, podId }` is accepted as it is.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createDuplexPeer, createObjectsServer, createObjectsClient } from '@johnhenry/wsh/objects';
import { serveMcpOverDuplex, webmcpTools, createPageIndicator } from '@johnhenry/wsh/page';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeyRaw, podIdToFingerprint } from '@johnhenry/wsh';
import { createFakeWindow, byRole } from './helpers/fake-window.mjs';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
const until = async (cond, what, ms = 3000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 3)); }
};

describe('the MCP permission hook tells a list from a call', () => {
  it('asks { kind: "mcp-tool", op: "list" } to list and { kind: "mcp-call", op: "call" } to call, so an adapter can scope them apart', async () => {
    const asked = [];
    const tool = { name: 'search', description: 'x', inputSchema: { type: 'object' }, annotations: { readOnlyHint: true }, execute: () => ({ ok: 1 }) };
    const inbox = [];
    // may list, may not call
    const s = serveMcpOverDuplex(webmcpTools({ window: createFakeWindow(), allow: ['search'], tools: [tool] }), {
      send: (m) => { inbox.push(m); },
      permits: (req) => { asked.push(req); return req.kind === 'mcp-tool'; },
    });
    closers.push(async () => s.close());
    s.receive({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const listed = await until(() => inbox.find((m) => m.id === 1), 'the list');
    assert.equal(listed.result.tools.length, 1);
    s.receive({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'search', arguments: {} } });
    const called = await until(() => inbox.find((m) => m.id === 2), 'the call');
    assert.equal(called.error.code, -32602);
    assert.ok(asked.some((r) => r.kind === 'mcp-tool' && r.op === 'list' && r.tool === 'search'));
    assert.ok(asked.some((r) => r.kind === 'mcp-call' && r.op === 'call' && r.tool === 'search'));
  });
});

describe('the badge is its own export', () => {
  it('shows a row with the fingerprint and a Stop that calls stop(); hide removes it; it says best effort', () => {
    const win = createFakeWindow();
    const badge = createPageIndicator(win, { name: 'shop' });
    let stopped = 0;
    badge.show({ fingerprint: 'ab'.repeat(32) }, () => { stopped++; });
    assert.equal(byRole(win, 'fingerprint').length, 1, 'the fingerprint is shown');
    byRole(win, 'stop')[0].click();
    assert.equal(stopped, 1);
    badge.hide({ fingerprint: 'ab'.repeat(32) });
    assert.equal(byRole(win, 'stop').length, 0);
    badge.destroy();
  });
});

describe('a host that requires a sealed session says so, and says when it is sealed', () => {
  it('authorize sees sealRequired; onSealed is called for a client that seals and not for one that does not', async () => {
    const kp = await generateKeyPair(true);
    const raw = await exportPublicKeyRaw(kp.publicKey);
    const logins = [];
    const sealed = [];
    const host = createMemoryHost({
      auth: { authorizedKeys: [raw], authorize: (who) => { logins.push(who); return true; } },
      hostKey: true, dataStreams: false, sealSession: 'require',
      onSealed: (who) => sealed.push(who),
    });
    closers.push(() => host.close());
    const good = await host.connect({ username: 'alice', keyPair: kp, sealSession: true });
    closers.push(() => good.disconnect());
    assert.equal(logins[0].sealRequired, true);
    await until(() => sealed.length === 1, 'onSealed');
    assert.equal(sealed[0].username, 'alice');
    assert.match(sealed[0].fingerprint, /^[0-9a-f]{64}$/);
    const plain = host.createClient();
    closers.push(() => plain.disconnect());
    await plain.connect(host.url, { transport: 'ws', username: 'alice', keyPair: kp, sealSession: false }).catch(() => {});
    await until(() => logins.length === 2, 'the plain login');
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(sealed.length, 1, 'a client that never sealed is never reported as sealed');
    assert.throws(() => createMemoryHost({ onSealed: 5 }), TypeError);
  });

  it('a host that does not require sealing does not say sealRequired', async () => {
    const kp = await generateKeyPair(true);
    const logins = [];
    const host = createMemoryHost({ auth: { authorizedKeys: [await exportPublicKeyRaw(kp.publicKey)], authorize: (who) => { logins.push(who); return true; } } });
    closers.push(() => host.close());
    const c = await host.connect({ username: 'alice', keyPair: kp });
    closers.push(() => c.disconnect());
    assert.equal(logins[0].sealRequired, undefined);
  });
});

describe('the identity shape of the browsermesh adapter', () => {
  it('{ username: null, fingerprint: null, podId } is accepted as it is, with the fingerprint derived and no warning', async () => {
    const podId = 'A'.repeat(43);
    const warnings = [];
    const onWarning = (w) => warnings.push(w);
    process.on('warning', onWarning);
    let a; let b;
    a = createDuplexPeer({ send: (m) => queueMicrotask(() => b.receive(structuredClone(m))) });
    b = createDuplexPeer({ send: (m) => queueMicrotask(() => a.receive(structuredClone(m))), who: { username: null, fingerprint: null, podId } });
    const asked = [];
    createObjectsServer({ roots: { r: { v: 1 } }, allow: { get: ['r.v'] }, authorize: (who) => { asked.push(who); return true; } }).attach(b);
    assert.equal(await (await createObjectsClient(a)).r.v, 1);
    await new Promise((r) => setImmediate(r));
    process.off('warning', onWarning);
    assert.deepEqual(asked, [{ username: null, fingerprint: podIdToFingerprint(podId), podId }]);
    assert.deepEqual(warnings, []);
  });
});
