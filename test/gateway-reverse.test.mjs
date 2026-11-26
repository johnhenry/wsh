// test/gateway-reverse.test.mjs -- #98: TCP reverse tunnels (ListenRequest) on the Node host: the host binds a port, announces each
// inbound connection with InboundOpen, the client accepts it, and data flows with the same credit rules as any gateway
// connection. Off by default; loopback unless the operator allows named addresses; a port allow-list; bounded everywhere.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import os from 'node:os';
import crypto from 'node:crypto';
import { MSG } from '@johnhenry/wsh';
import { GatewayError } from '../src/gateway-client.mjs';
import { normalizeGateway, reversePortAllowed } from '../src/server/gateway.mjs';
import { fixture, until, sleep } from './gateway-fixture.mjs';

const enc = new TextEncoder();
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

/** Echo what a duplex reads, prefixed. */
const echoer = (prefix = 'echo:') => async (duplex) => {
  const reader = duplex.readable.getReader(); const w = duplex.writable.getWriter();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    await w.write(Buffer.concat([enc.encode(prefix), value]));
  }
  await w.close().catch(() => {});
};
const dial = (port, host = '127.0.0.1') => new Promise((resolve, reject) => {
  const s = net.connect({ port, host }); s.once('connect', () => resolve(s)); s.once('error', reject);
});
const roundTrip = async (port, text, host) => {
  const s = await dial(port, host);
  return new Promise((resolve, reject) => { s.on('data', (d) => { resolve(d.toString()); s.destroy(); }); s.on('error', reject); s.write(text); });
};
const refusedConnect = (port, host = '127.0.0.1') => new Promise((resolve) => {
  const s = net.connect({ port, host }); s.once('connect', () => { s.destroy(); resolve(false); }); s.once('error', () => resolve(true));
});
const refused = (p, re) => assert.rejects(p, (e) => e instanceof GatewayError && e.code === 4 && re.test(e.message), `expected a policy refusal matching ${re}`);

describe('reverse tunnels: the Node host listens, the client serves (#98)', () => {
  const fx = fixture();
  afterEach(() => fx.teardown());

  it('is off by default, and a gateway for outbound use does not turn it on', async () => {
    const { client } = await fx.setup({ allow: ['*'] });
    assert.ok(client.hasFeature('gateway'));
    await refused(client.listenTcp(0, { onConnection() {} }), /reverse tunnels are not enabled/);
    const off = await fx.setup({ allow: [], reverse: false });
    await refused(off.client.listenTcp(0, { onConnection() {} }), /reverse tunnels are not enabled/);
  });

  it('a reverse-only host (no outbound allow list) advertises "gateway" and still refuses OpenTcp', async () => {
    const { client } = await fx.setup({ allow: [], reverse: {} });
    assert.ok(client.hasFeature('gateway'));
    await assert.rejects(client.openTcp('127.0.0.1', 80), (e) => e instanceof GatewayError && e.code === 4);
  });

  it('listens, announces each inbound connection with its peer, and round-trips data both ways', async () => {
    const { client } = await fx.setup({ allow: [], reverse: {} });
    const peers = [];
    const handle = await client.listenTcp(0, { onConnection: (d, info) => { peers.push(info); void echoer()(d); } });
    assert.ok(Number.isInteger(handle.port) && handle.port >= 1024, `ephemeral port reported: ${handle.port}`);
    const answers = await Promise.all(['a', 'b', 'c'].map((t) => roundTrip(handle.port, t)));
    assert.deepEqual(answers.sort(), ['echo:a', 'echo:b', 'echo:c']);
    assert.equal(peers.length, 3);
    assert.ok(peers.every((p) => p.peer === '127.0.0.1' && p.peerPort > 0), JSON.stringify(peers));
    await handle.close();
    await until(() => refusedConnect(handle.port), 'port closed after close()');
  });

  it('moves a few MiB each way intact (credit-metered like any gateway connection)', async () => {
    const { client } = await fx.setup({ allow: [], reverse: {} });
    const handle = await client.listenTcp(0, { onConnection: (d) => { void d.readable.pipeTo(d.writable).catch(() => {}); } });
    const data = crypto.randomBytes(3 * 1024 * 1024);
    const s = await dial(handle.port);
    const got = [];
    const done = new Promise((resolve) => { let n = 0; s.on('data', (c) => { got.push(c); n += c.length; if (n >= data.length) resolve(); }); });
    s.write(data);
    await done;
    assert.equal(sha(Buffer.concat(got)), sha(data));
    s.destroy();
  });

  it('a slow client does not make the host buffer without bound', async () => {
    const { client, server } = await fx.setup({ allow: [], reverse: {} });
    const stalled = [];
    const handle = await client.listenTcp(0, { onConnection: (d) => { stalled.push(d); } }); // never reads
    const s = await dial(handle.port); s.on('error', () => {});
    const chunk = Buffer.alloc(64 * 1024, 1);
    let written = 0;
    // Write until the socket stops draining (the host stopped reading it) or a generous ceiling is reached.
    for (;;) {
      if (written > 64 * 1024 * 1024) break;
      written += chunk.length;
      if (!s.write(chunk)) { const drained = await Promise.race([new Promise((r) => s.once('drain', () => r(true))), sleep(1000).then(() => false)]); if (!drained) break; }
    }
    assert.ok(written < 32 * 1024 * 1024, `the peer was held back by credit (wrote ${written} bytes)`);
    assert.ok(server.gatewayStats().reverse.accepted === 1);
    assert.ok(stalled.length === 1);
    s.destroy();
  });

  describe('bind policy', () => {
    it('binds loopback by default and ignores the address the client asks for', async () => {
      const lines = [];
      const { client } = await fx.setup({ allow: [], reverse: {} }, { onLog: (l) => lines.push(l) });
      const handle = await client.listenTcp(0, { bindAddr: '0.0.0.0', onConnection: echoer() });
      assert.ok(lines.some((l) => l.includes(`listening on 127.0.0.1:${handle.port}`)), lines.join('\n'));
      const external = Object.values(os.networkInterfaces()).flat().find((a) => a && a.family === 'IPv4' && !a.internal);
      if (external) assert.equal(await refusedConnect(handle.port, external.address), true, 'not reachable on a non-loopback address');
      assert.equal(await roundTrip(handle.port, 'x'), 'echo:x');
    });

    it('the operator picks the bind address; a client address is honoured only if the operator listed it', async () => {
      const lines = [];
      const v6 = Object.values(os.networkInterfaces()).flat().some((a) => a && a.family === 'IPv6' && a.address === '::1');
      const { client } = await fx.setup({ allow: [], reverse: { bindAddr: '127.0.0.1', allowBindAddrs: v6 ? ['::1'] : ['127.0.0.1'] } }, { onLog: (l) => lines.push(l) });
      const unlisted = await client.listenTcp(0, { bindAddr: '0.0.0.0', onConnection: echoer() });
      assert.ok(lines.some((l) => l.includes(`listening on 127.0.0.1:${unlisted.port}`)));
      if (v6) {
        const listed = await client.listenTcp(0, { bindAddr: '::1', onConnection: echoer() });
        assert.ok(lines.some((l) => l.includes(`listening on ::1:${listed.port}`)), lines.join('\n'));
        assert.equal(await roundTrip(listed.port, 'v6', '::1'), 'echo:v6');
      }
    });

    it('rejects a bind address that is not an IP, and a configuration that would bind wide by accident', async () => {
      assert.throws(() => normalizeGateway({ allow: [], reverse: { bindAddr: 'localhost' } }), /bindAddr/);
      assert.throws(() => normalizeGateway({ allow: [], reverse: { allowBindAddrs: ['*'] } }), /allowBindAddrs/);
      assert.throws(() => normalizeGateway({ allow: [], reverse: { allowBindAddrs: ['example.com'] } }), /allowBindAddrs/);
    });
  });

  describe('port policy', () => {
    it('the default allows ephemeral (0) and 1024-65535; nothing below 1024 unless listed', () => {
      const cfg = normalizeGateway({ allow: [], reverse: {} }).reverse;
      assert.equal(reversePortAllowed(cfg, 0), true);
      assert.equal(reversePortAllowed(cfg, 1024), true);
      assert.equal(reversePortAllowed(cfg, 65535), true);
      for (const p of [1, 22, 80, 443, 1023]) assert.equal(reversePortAllowed(cfg, p), false, `${p}`);
    });

    it('an explicit list replaces the default: only what it names, privileged ports included when named', () => {
      const cfg = normalizeGateway({ allow: [], reverse: { ports: [80, '8000-8010', '9090'] } }).reverse;
      for (const p of [80, 8000, 8005, 8010, 9090]) assert.equal(reversePortAllowed(cfg, p), true, `${p}`);
      for (const p of [0, 81, 7999, 8011, 9091, 40000]) assert.equal(reversePortAllowed(cfg, p), false, `${p}`);
      assert.equal(reversePortAllowed(normalizeGateway({ allow: [], reverse: { ports: [0, 3000] } }).reverse, 0), true);
    });

    it('refuses malformed port rules at configuration time', () => {
      for (const bad of [[70000], ['9-1'], ['a'], [-1], [1.5], ['1-2-3'], 'x']) assert.throws(() => normalizeGateway({ allow: [], reverse: { ports: bad } }), /reverse\.ports/, JSON.stringify(bad));
    });

    it('answers a port outside the list with a ListenFail that says why', async () => {
      const { client } = await fx.setup({ allow: [], reverse: { ports: ['20000-20010'] } });
      await refused(client.listenTcp(80, { onConnection() {} }), /port 80 is not allowed by the reverse-tunnel policy/);
      await refused(client.listenTcp(0, { onConnection() {} }), /port 0 is not allowed/);
      const { client: c2 } = await fx.setup({ allow: [], reverse: {} });
      await refused(c2.listenTcp(443, { onConnection() {} }), /below 1024/);
    });

    it('asks for a specific port, reports it, and reports "address in use" for a port that is taken', async () => {
      const probe = net.createServer(); await new Promise((r) => probe.listen(0, '127.0.0.1', r));
      const free = probe.address().port; await new Promise((r) => probe.close(r));
      const { client } = await fx.setup({ allow: [], reverse: { ports: [free] } });
      const handle = await client.listenTcp(free, { onConnection: echoer() });
      assert.equal(handle.port, free);
      await assert.rejects(client.listenTcp(free, { onConnection() {} }), (e) => e instanceof GatewayError && /in use/.test(e.message));
    });
  });

  describe('bounds', () => {
    it('limits listeners per client and says so', async () => {
      const { client } = await fx.setup({ allow: [], reverse: { maxListeners: 2 } });
      const a = await client.listenTcp(0, { onConnection() {} });
      await client.listenTcp(0, { onConnection() {} });
      await refused(client.listenTcp(0, { onConnection() {} }), /too many reverse listeners \(limit 2\)/);
      await a.close();
      await until(async () => { try { (await client.listenTcp(0, { onConnection() {} })); return true; } catch { return false; } }, 'a slot frees when a listener closes');
    });

    it('limits connections per listener: the extra one is closed without being announced, and a slot frees when one ends', async () => {
      const { client, server } = await fx.setup({ allow: [], reverse: { maxConnectionsPerListener: 2 } });
      const opened = [];
      // An application that notices the connector's end of file and finishes its own side (a half-closed connection is
      // over when both sides have; see #271), which is what frees the slot.
      const finishOnEof = async (d) => { const r = d.readable.getReader(); while (!(await r.read()).done); await d.writable.getWriter().close(); };
      const handle = await client.listenTcp(0, { onConnection: (d) => { opened.push(d); void finishOnEof(d).catch(() => {}); } });
      const a = await dial(handle.port); const b = await dial(handle.port);
      await until(() => opened.length === 2, 'two announced');
      const c = await dial(handle.port).catch(() => null);
      const closed = c ? await new Promise((r) => { c.once('close', () => r(true)); c.once('error', () => {}); setTimeout(() => r(false), 2000); }) : true;
      assert.equal(closed, true, 'the third connection is closed by the host');
      assert.equal(opened.length, 2, 'and was never announced');
      assert.ok(server.gatewayStats().reverse.refusedConnections >= 1);
      a.destroy();
      await until(async () => { const d = await dial(handle.port).catch(() => null); if (!d) return false; d.on('error', () => {}); await sleep(150); return opened.length === 3; }, 'a freed slot admits a new connection');
      b.destroy();
    });

    it('closes an accepted connection that has been idle too long', async () => {
      const { client } = await fx.setup({ allow: [], reverse: { idleMs: 250 } });
      const handle = await client.listenTcp(0, { onConnection: echoer() });
      const s = await dial(handle.port);
      const closed = new Promise((r) => s.once('close', () => r('closed')));
      assert.equal(await Promise.race([closed, sleep(3000).then(() => 'still open')]), 'closed');
      // activity keeps a connection alive
      const t = await dial(handle.port);
      const alive = new Promise((r) => t.once('close', () => r('closed')));
      for (let i = 0; i < 6; i++) { t.write('k'); await sleep(100); }
      assert.equal(t.destroyed, false, 'kept alive by traffic');
      t.destroy(); await alive;
    });

    it('passes a backlog to the listening socket, and refuses a nonsense one', () => {
      assert.equal(normalizeGateway({ allow: [], reverse: { backlog: 3 } }).reverse.backlog, 3);
      assert.throws(() => normalizeGateway({ allow: [], reverse: { backlog: 0 } }), /backlog/);
      assert.throws(() => normalizeGateway({ allow: [], reverse: { maxListeners: -1 } }), /maxListeners/);
      assert.throws(() => normalizeGateway({ allow: [], reverse: { maxConnectionsPerListener: 0 } }), /maxConnectionsPerListener/);
      assert.throws(() => normalizeGateway({ allow: [], reverse: { idleMs: -5 } }), /idleMs/);
    });

    it('counts reverse connections against the client\'s gateway connection cap', async () => {
      const { client } = await fx.setup({ allow: [], reverse: {}, maxConnections: 1 });
      const seen = [];
      const handle = await client.listenTcp(0, { onConnection: (d) => { seen.push(d); } });
      const a = await dial(handle.port); await until(() => seen.length === 1, 'first');
      const b = await dial(handle.port).catch(() => null);
      await sleep(300);
      assert.equal(seen.length, 1, 'the second is refused by the cap');
      a.destroy(); b?.destroy();
    });
  });

  describe('lifecycle', () => {
    it('closes its listeners and their connections when the client disconnects', async () => {
      const { client } = await fx.setup({ allow: [], reverse: {} });
      const handle = await client.listenTcp(0, { onConnection: echoer() });
      const peer = await dial(handle.port); peer.on('error', () => {});
      const closed = new Promise((r) => peer.once('close', r));
      await client.disconnect();
      await Promise.race([closed, sleep(3000).then(() => assert.fail('the accepted connection stayed open'))]);
      await until(() => refusedConnect(handle.port), 'the port is closed');
    });

    it('InboundReject drops the peer; a pending connection nobody accepts is dropped', async () => {
      const { client, inbox } = await fx.setup({ allow: [], reverse: {} });
      await client.sendControl({ type: MSG.LISTEN_REQUEST, listener_id: 5, port: 0, bind_addr: '0.0.0.0' });
      const ok = await until(() => inbox.find((m) => m.type === MSG.LISTEN_OK && m.listener_id === 5), 'ListenOk');
      assert.ok(ok.actual_port >= 1024);
      const peer = await dial(ok.actual_port); peer.on('error', () => {});
      const open = await until(() => inbox.find((m) => m.type === MSG.INBOUND_OPEN), 'InboundOpen');
      assert.equal(open.listener_id, 5); assert.equal(open.peer_addr, '127.0.0.1'); assert.ok(open.peer_port > 0);
      const closed = new Promise((r) => peer.once('close', r));
      await client.sendControl({ type: MSG.INBOUND_REJECT, channel_id: open.channel_id, reason: 'no' });
      await Promise.race([closed, sleep(3000).then(() => assert.fail('the rejected connection stayed open'))]);
      await client.sendControl({ type: MSG.LISTEN_CLOSE, listener_id: 5 });
      await until(() => refusedConnect(ok.actual_port), 'closed by ListenClose');
    });

    it('a listener id in use is refused, and a malformed request is refused', async () => {
      const { client, inbox } = await fx.setup({ allow: [], reverse: {} });
      await client.sendControl({ type: MSG.LISTEN_REQUEST, listener_id: 9, port: 0 });
      await until(() => inbox.find((m) => m.type === MSG.LISTEN_OK), 'ok');
      await client.sendControl({ type: MSG.LISTEN_REQUEST, listener_id: 9, port: 0 });
      assert.match((await until(() => inbox.find((m) => m.type === MSG.LISTEN_FAIL && m.listener_id === 9), 'fail')).reason, /already in use/);
      await client.sendControl({ type: MSG.LISTEN_REQUEST, listener_id: 10, port: 'x' });
      assert.match((await until(() => inbox.find((m) => m.type === MSG.LISTEN_FAIL && m.listener_id === 10), 'fail 10')).reason, /malformed/);
    });
  });
});
