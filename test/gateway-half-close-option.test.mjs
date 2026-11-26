// test/gateway-half-close-option.test.mjs -- the half-close idle bound (#271) on EVERY way of building a host, with one meaning and one
// validation: a Node server (`gateway.halfCloseIdleMs`, covered by test/gateway-half-close.test.mjs), a memory host
// (`gatewayHalfCloseIdleMs`, the same option for a host that has no `gateway` object), a named endpoint of either
// (`{ open, halfCloseIdleMs }`, which wins over the host's), and the client (`connect(url, { gatewayHalfCloseIdleMs })`, a memory host's
// `connect(...)`, and `openEndpoint(name, { halfCloseIdleMs })` for one connection). A page host, a reverse host and a pipe-relay
// pairing serve no gateway, so they have no such clock.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { generateKeyPair, exportPublicKeySSH, WshClient } from '@johnhenry/wsh';

const BAD = [-1, 1.5, '1000', NaN, Infinity, null, 2 ** 31, {}];
const SHORT = 100;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** Resolves with the connection's close reason, or 'open' if it is still open after `ms`. */
const stateAfter = (closed, ms) => Promise.race([closed, sleep(ms).then(() => 'open')]);

describe('the half-close idle bound is an option of every host', () => {
  let keyPair; let authorizedKeys;
  before(async () => { keyPair = await generateKeyPair(true); authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} u`; });

  /** An endpoint that records its duplex and does nothing else: it never closes, so a half-closed connection to it is idle. */
  const parked = () => { const seen = []; return { seen, open: (d) => { seen.push(d); } }; };

  it('createMemoryHost validates gatewayHalfCloseIdleMs like the Node gateway does', () => {
    for (const bad of BAD) assert.throws(() => createMemoryHost({ endpoints: { a: () => {} }, gatewayHalfCloseIdleMs: bad }), (e) => e instanceof TypeError && /gatewayHalfCloseIdleMs/.test(e.message), String(bad));
    for (const ok of [undefined, 0, 1, 300_000, 2 ** 31 - 1]) assert.doesNotThrow(() => createMemoryHost({ endpoints: { a: () => {} }, gatewayHalfCloseIdleMs: ok }), String(ok));
    // a host with no endpoints has no gateway, and a bad value is still a mistake
    assert.throws(() => createMemoryHost({ gatewayHalfCloseIdleMs: -1 }), /gatewayHalfCloseIdleMs/);
  });

  it('a named endpoint validates its own halfCloseIdleMs the same way, on a memory host and on a Node server', () => {
    for (const bad of BAD) {
      assert.throws(() => createMemoryHost({ endpoints: { a: { open: () => {}, halfCloseIdleMs: bad } } }), (e) => e instanceof TypeError && /halfCloseIdleMs/.test(e.message), String(bad));
      assert.throws(() => createWshServer({ gateway: { allow: [], tcp: false, endpoints: { a: { open: () => {}, halfCloseIdleMs: bad } } } }), /halfCloseIdleMs/, String(bad));
      assert.throws(() => createMemoryHost({ targets: { t: { endpoints: { a: { open: () => {}, halfCloseIdleMs: bad } } } } }), /halfCloseIdleMs/, String(bad));
    }
    assert.doesNotThrow(() => createMemoryHost({ endpoints: { a: { open: () => {}, halfCloseIdleMs: 0 } } }));
  });

  it('memory host: the host-side connection of a half-closed endpoint is ended after gatewayHalfCloseIdleMs', async () => {
    const ep = parked();
    const host = createMemoryHost({ auth: { authorizedKeys }, endpoints: { quiet: ep.open }, gatewayHalfCloseIdleMs: SHORT });
    try {
      const client = await host.connect({ username: 'u', keyPair });
      const d = await client.openEndpoint('quiet');
      await d.writable.getWriter().close(); // the client half-closes; the endpoint never answers
      assert.equal(await ep.seen[0].closed, 'idle timeout');
      await client.disconnect().catch(() => {});
    } finally { await host.close(); }
  });

  it('memory host: 0 never ends it, and a sealed session is no different', async () => {
    const ep = parked();
    const host = createMemoryHost({ auth: { authorizedKeys }, hostKey: true, dataStreams: false, sealSession: 'require', endpoints: { quiet: ep.open }, gatewayHalfCloseIdleMs: 0 });
    try {
      const client = await host.connect({ username: 'u', keyPair });
      assert.equal(client.sessionSealed, true);
      const d = await client.openEndpoint('quiet');
      await d.writable.getWriter().close();
      assert.equal(await stateAfter(ep.seen[0].closed, 5 * SHORT), 'open');
      d.destroy();
      await client.disconnect().catch(() => {});
    } finally { await host.close(); }
  });

  it('memory host: a sealed session honours the bound too', async () => {
    const ep = parked();
    const host = createMemoryHost({ auth: { authorizedKeys }, hostKey: true, dataStreams: false, sealSession: 'require', endpoints: { quiet: ep.open }, gatewayHalfCloseIdleMs: SHORT });
    try {
      const client = await host.connect({ username: 'u', keyPair });
      assert.equal(client.sessionSealed, true);
      const d = await client.openEndpoint('quiet');
      await d.writable.getWriter().close();
      assert.equal(await ep.seen[0].closed, 'idle timeout');
      await client.disconnect().catch(() => {});
    } finally { await host.close(); }
  });

  it('a per-endpoint bound wins over the host\'s: a long one on a quiet stream, a short one on another, on a memory host', async () => {
    const quiet = parked(); const fast = parked();
    const host = createMemoryHost({
      auth: { authorizedKeys }, gatewayHalfCloseIdleMs: SHORT,
      endpoints: { quiet: { open: quiet.open, halfCloseIdleMs: 0 }, fast: fast.open, brisk: { open: (d) => { quiet.seen.push(d); }, halfCloseIdleMs: 50 } },
    });
    try {
      const client = await host.connect({ username: 'u', keyPair });
      const a = await client.openEndpoint('quiet'); const b = await client.openEndpoint('fast'); const c = await client.openEndpoint('brisk');
      for (const d of [a, b, c]) await d.writable.getWriter().close();
      assert.equal(await fast.seen[0].closed, 'idle timeout', 'the host default (short) applies to an endpoint with no bound of its own');
      assert.equal(await quiet.seen[1].closed, 'idle timeout', 'a shorter bound of its own');
      assert.equal(await stateAfter(quiet.seen[0].closed, 3 * SHORT), 'open', 'its own 0 (never) beats the host default');
      a.destroy();
      await client.disconnect().catch(() => {});
    } finally { await host.close(); }
  });

  it('a target\'s endpoints take the host bound and their own', async () => {
    const dflt = parked(); const own = parked();
    const host = createMemoryHost({
      auth: { authorizedKeys }, gatewayHalfCloseIdleMs: SHORT,
      targets: { t: { endpoints: { dflt: dflt.open, own: { open: own.open, halfCloseIdleMs: 0 } } } },
    });
    try {
      const client = await host.connect({ username: 'u', keyPair });
      const a = await client.openEndpoint('dflt', { target: 't' }); const b = await client.openEndpoint('own', { target: 't' });
      await a.writable.getWriter().close(); await b.writable.getWriter().close();
      assert.equal(await dflt.seen[0].closed, 'idle timeout');
      assert.equal(await stateAfter(own.seen[0].closed, 3 * SHORT), 'open');
      b.destroy();
      await client.disconnect().catch(() => {});
    } finally { await host.close(); }
  });

  it('Node server: a named endpoint\'s own bound applies, over gateway.halfCloseIdleMs', async () => {
    const quiet = parked(); const brisk = parked();
    const server = createWshServer({ auth: { authorizedKeys }, gateway: { allow: [], tcp: false, halfCloseIdleMs: 0, endpoints: { quiet: quiet.open, brisk: { open: brisk.open, halfCloseIdleMs: SHORT } } } });
    const { port } = await server.listen();
    const client = new WshClient();
    try {
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'u', keyPair });
      const a = await client.openEndpoint('quiet'); const b = await client.openEndpoint('brisk');
      await a.writable.getWriter().close(); await b.writable.getWriter().close();
      assert.equal(await brisk.seen[0].closed, 'idle timeout');
      assert.equal(await stateAfter(quiet.seen[0].closed, 3 * SHORT), 'open', 'the server-wide 0 holds for the other endpoint');
      a.destroy();
    } finally { await client.disconnect().catch(() => {}); await server.close(); }
  });

  it('client side: a memory host\'s connect() takes gatewayHalfCloseIdleMs, and openEndpoint() a bound for one connection', async () => {
    // The host half-closes and never reads; the client's connection to it is the one that idles.
    const host = createMemoryHost({ auth: { authorizedKeys }, gatewayHalfCloseIdleMs: 0, endpoints: { talk: async (d) => { await d.writable.getWriter().close(); } } });
    try {
      const short = await host.connect({ username: 'u', keyPair, gatewayHalfCloseIdleMs: SHORT });
      assert.equal(await (await short.openEndpoint('talk')).closed, 'idle timeout');
      await short.disconnect().catch(() => {});

      const never = await host.connect({ username: 'u', keyPair, gatewayHalfCloseIdleMs: 0 });
      const kept = await never.openEndpoint('talk');
      assert.equal(await stateAfter(kept.closed, 3 * SHORT), 'open');
      const own = await never.openEndpoint('talk', { halfCloseIdleMs: SHORT });
      assert.equal(await own.closed, 'idle timeout', 'one connection with a bound of its own, on a client that has none');
      assert.equal(await stateAfter(kept.closed, SHORT), 'open', 'the other is untouched');
      kept.destroy();
      await never.disconnect().catch(() => {});

      const c = await host.connect({ username: 'u', keyPair });
      for (const bad of BAD) await assert.rejects(c.openEndpoint('talk', { halfCloseIdleMs: bad }), (e) => e instanceof TypeError && /halfCloseIdleMs/.test(e.message), String(bad));
      await c.disconnect().catch(() => {});
    } finally { await host.close(); }
  });
});
