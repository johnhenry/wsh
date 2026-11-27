// test/gateway-expiry-unhandled.test.mjs -- #319: a grant that expires (`endAll`: `end(reason)` then `destroy()` of every connection, listeners stopped, connects in
// flight told to stop) leaves nothing unhandled, whatever state the connections and the transport are in.
//
// `endAll` runs from a timer, so anything it throws is an `uncaughtException` and anything it starts that rejects is an `unhandledRejection`. Each test
// holds something at the exact moment the expiry fires (a send to the peer, a connect on an injected network, an endpoint's authorize, a listener's close)
// and settles it afterwards, with the transport already gone, and watches the process over several macrotasks. The runner starts every file with
// `--unhandled-rejections=strict`.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createGatewayCore } from '../src/server/gateway-core.mjs';
import { createGatewaySession, normalizeGateway } from '@johnhenry/wsh/gateway';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH, MSG } from '@johnhenry/wsh';
import { openEndpoint, openTcp, listenRequest } from '../src/messages.gen.mjs';

/** Run `fn` with a process-wide hook on `unhandledRejection`/`uncaughtException`; resolve with what was raised after a few macrotasks. */
async function raised(fn) {
  const seen = [];
  const hook = (e) => seen.push(e);
  process.on('unhandledRejection', hook);
  process.on('uncaughtException', hook);
  try {
    await fn();
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    await new Promise((r) => setTimeout(r, 30));
  } finally {
    process.off('unhandledRejection', hook);
    process.off('uncaughtException', hook);
  }
  return seen;
}
const tick = () => new Promise((r) => setImmediate(r));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const MANY = 60;
async function waitFor(cond, what, ms = 5000) {
  const t0 = Date.now();
  for (;;) { const v = cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(2); }
}
const REASON = 'key expired';

/** How the transport behaves when the session sends to a peer that is gone. */
const transports = {
  'send rejects': () => () => Promise.reject(new Error('transport closed')),
  'send throws': () => () => { throw new Error('transport closed'); },
  'send is held, then rejects after the expiry': () => { let open = false; const held = []; const send = () => (open ? Promise.reject(new Error('write after close')) : new Promise((_, rej) => { held.push(rej); })); send.settle = () => { open = true; for (const rej of held.splice(0)) rej(new Error('write after close')); }; return send; },
  'send is held, then resolves after the expiry': () => { let open = false; const held = []; const send = () => (open ? Promise.resolve() : new Promise((res) => { held.push(res); })); send.settle = () => { open = true; for (const res of held.splice(0)) res(); }; return send; },
};

describe('endAll on the connection core: many endpoint connections, the transport gone (#319)', () => {
  for (const [name, make] of Object.entries(transports)) {
    it(`${MANY} connections with readers, writers held for credit, a failing endpoint, and an authorize still in flight; ${name}`, async () => {
      const send = make();
      const endpointResults = [];
      let releaseAuthorize;
      const endpoints = new Map([
        ['echo', {
          open(duplex) {
            // A reader and a writer, as an endpoint has: the reader is pending on the connection, the writer waits for the peer (held send / no credit).
            const r = duplex.readable.getReader();
            const w = duplex.writable.getWriter();
            const done = (async () => {
              void w.write(new Uint8Array(1000)).catch(() => {});
              for (;;) { const { done: d } = await r.read(); if (d) break; }
            })().catch(() => {});
            endpointResults.push(done);
          },
        }],
        // An endpoint whose open() rejects only once the connection is over (what an embedder's own `await duplex.closed; throw` does).
        ['fails-late', { open(duplex) { const p = duplex.closed.then(() => { throw new Error('endpoint failed after the close'); }); endpointResults.push(p.catch(() => {})); return p; } }],
        ['slow-authorize', { authorize: () => new Promise((r) => { releaseAuthorize = r; }), open(duplex) { void duplex.readable.getReader().read().catch(() => {}); } }],
      ]);
      const cfg = { maxConnections: 1000, maxBufferedBytes: 4 * 1024 * 1024, maxClientBufferedBytes: 64 * 1024 * 1024, endpoints };
      const core = createGatewayCore(cfg, send, () => {});
      core.setPeerFeatures(['gateway-credit']);
      const seen = await raised(async () => {
        // (A held send holds the reply to the open, so the opens are not awaited: the connection loop of a real host is a separate matter.)
        const opens = [];
        for (let id = 1; id <= MANY; id++) opens.push(core.handle(openEndpoint({ gatewayId: id, name: id % 5 === 0 ? 'fails-late' : 'echo' })));
        await tick();
        assert.equal(core.size, MANY);
        const inFlight = core.handle(openEndpoint({ gatewayId: 1000, name: 'slow-authorize' }));
        await tick();
        assert.equal(core.pending.size, 1, 'an authorize is in flight');
        core.endAll(REASON);
        assert.equal(core.size, 0, 'every connection ended');
        // The transport is gone: what was held now fails or completes, the late authorize completes, and the core is closed behind it.
        send.settle?.();
        releaseAuthorize(true);
        await Promise.all([inFlight, ...opens]);
        core.close();
        await tick();
        core.endAll(REASON); // and again, as a second timer fire or an expiry behind a close would
        await Promise.all(endpointResults);
      });
      assert.deepEqual(seen, []);
    });
  }

  it('an endAll behind a close, or twice, or with nothing open, throws nothing', async () => {
    const core = createGatewayCore({ maxConnections: 4, maxBufferedBytes: 1 << 20, maxClientBufferedBytes: 1 << 22, endpoints: null }, () => Promise.reject(new Error('gone')), () => {});
    const seen = await raised(async () => { core.endAll(REASON); core.close(); core.endAll(REASON); core.endAll(undefined); });
    assert.deepEqual(seen, []);
  });
});

describe('endAll on the gateway session: injected network, many connections, a connect in flight, listeners (#319)', () => {
  const origins = [];
  afterEach(() => { for (const s of origins.splice(0)) s.close(); });
  const PUB = '93.184.216.7';

  /** A duplex of the network's: bytes written to it are read back; it says when it was cancelled/aborted. */
  function loop() {
    const t = new TransformStream();
    const state = { cancelled: false, aborted: false };
    return { state, duplex: { readable: new ReadableStream({ start() {}, pull: async (c) => { c.enqueue(await new Promise(() => {})); }, cancel() { state.cancelled = true; } }, { highWaterMark: 0 }), writable: new WritableStream({ abort() { state.aborted = true; } }) }, t };
  }

  for (const [name, make] of Object.entries(transports)) {
    it(`${MANY} open connections and ${MANY / 6} connects still in flight (some that never settle, some that settle late, some that fail late), ${MANY / 6} listeners; ${name}`, async () => {
      const send = make();
      const sentLog = []; const connects = [];
      const listens = [];
      const network = {
        connectTcp: ({ host, port, signal }) => new Promise((resolve, reject) => {
          const rec = { port, signal, resolve: () => resolve(loop().duplex), reject: (e) => reject(e) };
          connects.push(rec);
          if (port >= 2000) return; // established at once below
          signal.addEventListener('abort', () => { if (rec.abortRejects) reject(signal.reason ?? new Error('aborted')); }, { once: true });
        }),
        listenTcp: async ({ port }) => {
          const l = { port: port || 40000 + listens.length, closes: 0, close() { l.closes++; if (l.closes % 2) throw new Error('close threw'); return Promise.reject(new Error('close rejected')); } };
          listens.push(l);
          return l;
        },
      };
      const cfg = normalizeGateway({ network, allow: ['*'], reverse: { maxListeners: 50 }, maxConnections: 500 });
      const session = createGatewaySession(cfg, (m) => { sentLog.push(m); return send(m); }, (l) => process.env.DBG && console.log(l));
      session.setPeerFeatures(['gateway-credit']);
      const seen = await raised(async () => {
        // Open connections: the network answers at once.
        const opening = [];
        for (let id = 1; id <= MANY; id++) {
          opening.push(session.handle(openTcp({ gatewayId: id, host: PUB, port: 2000 + id })));
          await waitFor(() => connects.find((c) => c.port === 2000 + id), `the dial of ${id}`);
          connects.find((c) => c.port === 2000 + id).resolve();
        }
        await waitFor(() => session.size >= MANY, 'the connections to be attached');
        // Connects in flight at the expiry. Three kinds: never settles, settles after the expiry (success), fails after the expiry.
        const inFlight = [];
        for (let i = 0; i < MANY / 6; i++) {
          inFlight.push(session.handle(openTcp({ gatewayId: 500 + i, host: PUB, port: 100 + i })));
          await waitFor(() => connects.find((c) => c.port === 100 + i), `the dial of ${100 + i}`);
        }
        // Listeners (the network's close throws or rejects).
        const listening = [];
        for (let i = 0; i < MANY / 6; i++) listening.push(session.handle(listenRequest({ listenerId: 900 + i, port: 7000 + i, bindAddr: '127.0.0.1' })));
        await waitFor(() => listens.length === MANY / 6, 'the listens');
        await tick();
        assert.ok(session.size >= MANY, 'connections are open');
        assert.equal(listens.length, MANY / 6);

        session.endAll(REASON);
        assert.ok(connects.filter((c) => c.port < 2000).every((c) => c.signal.aborted), 'every connect in flight was told to stop by the expiry itself');
        assert.equal(listens.filter((l) => l.closes > 0).length, MANY / 6, 'every listener was closed by the expiry itself');

        // After the expiry: the held connects settle, the transport settles what it held, then the session closes (as the connection does).
        const pendingConnects = connects.filter((c) => c.port < 2000);
        pendingConnects.forEach((c, i) => { c.abortRejects = false; if (i % 3 === 1) c.resolve(); else if (i % 3 === 2) c.reject(Object.assign(new Error('connect failed late'), { code: 'ECONNREFUSED' })); });
        send.settle?.();
        await tick();
        session.close();
        for (const c of pendingConnects.filter((_, i) => i % 3 === 0)) c.reject(new Error('aborted late'));
        await Promise.race([Promise.allSettled([...opening, ...inFlight, ...listening]), sleep(500)]);
      });
      assert.deepEqual(seen, []);
      assert.equal(session.size, 0);
    });
  }

  it('real sockets: many TCP origins, the expiry while their writes are held for credit and the origins are still sending, the transport already gone', async () => {
    const sockets = [];
    const origin = net.createServer((s) => { sockets.push(s); s.on('error', () => {}); const t = setInterval(() => s.write(Buffer.alloc(8192)), 1); s.on('close', () => clearInterval(t)); s.on('data', () => {}); });
    await new Promise((r) => origin.listen(0, '127.0.0.1', r)); origins.push(origin);
    const port = origin.address().port;
    const sent = [];
    // The send goes nowhere and never completes (the transport is stuck), so writes toward the client are held, the origin keeps sending, and the expiry arrives.
    const cfg = normalizeGateway({ allow: [`127.0.0.1:${port}`], maxConnections: 500 });
    const session = createGatewaySession(cfg, (m) => { sent.push(m); return new Promise(() => {}); }, () => {});
    session.setPeerFeatures(['gateway-credit']);
    const seen = await raised(async () => {
      // Replies (GatewayOk) are never completed either, which the session tolerates: it does not await them.
      for (let i = 0; i < 30; i++) void session.handle(openTcp({ gatewayId: i + 1, host: '127.0.0.1', port })); // each handle waits on its held GatewayOk: not awaited
      const t0 = Date.now();
      while (session.size < 30 && Date.now() - t0 < 5000) await sleep(10);
      assert.equal(session.size, 30);
      await sleep(30); // the origins are sending, the held sends back the pumps up
      session.endAll(REASON);
      assert.equal(session.size, 0);
      const t1 = Date.now();
      while (sockets.some((s) => !s.destroyed) && Date.now() - t1 < 5000) await sleep(10);
      assert.ok(sockets.every((s) => s.destroyed), 'every origin socket was closed');
      session.close();
    });
    assert.deepEqual(seen, []);
  });

  it('real sockets: the expiry runs before the origin\'s dial completes, with the transport gone: the connection that opens behind it is ended by the next expiry check, nothing is raised', async () => {
    const origin = net.createServer((s) => { s.on('error', () => {}); s.on('data', () => {}); });
    await new Promise((r) => origin.listen(0, '127.0.0.1', r)); origins.push(origin);
    const port = origin.address().port;
    const cfg = normalizeGateway({ allow: [`127.0.0.1:${port}`], maxConnections: 500 });
    const session = createGatewaySession(cfg, () => Promise.reject(new Error('transport closed')), () => {});
    session.setPeerFeatures(['gateway-credit']);
    const seen = await raised(async () => {
      const opening = Array.from({ length: 20 }, (_, i) => session.handle(openTcp({ gatewayId: i + 1, host: '127.0.0.1', port })));
      session.endAll(REASON); // dials started, none finished
      await Promise.all(opening);
      session.endAll(REASON); // what the connection does after an opener (watchGatewayExpiry): ends what opened behind the expiry
      await sleep(30);
      session.close();
    });
    assert.deepEqual(seen, []);
    assert.equal(session.size, 0);
  });
});

describe('the connection\'s expiry timer with the transport gone (#319)', () => {
  const clients = []; const servers = []; const nets = [];
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
    for (const n of nets.splice(0)) n.close();
  });
  const soon = (s = 5) => (Math.floor(Date.now() / 1000) + s) * 1000;
  const iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');

  async function arrange(n) {
    const origin = net.createServer((s) => { s.on('error', () => {}); s.on('data', (d) => s.write(d)); });
    await new Promise((r) => origin.listen(0, '127.0.0.1', r)); nets.push(origin);
    const oport = origin.address().port;
    const kp = await generateKeyPair(true);
    const at = soon();
    const server = createWshServer({ auth: { authorizedKeys: `expires="${iso(at)}" ${await exportPublicKeySSH(kp.publicKey)} alice` }, gateway: { allow: [`127.0.0.1:${oport}`], maxConnections: 200 } });
    const { port } = await server.listen(); servers.push(server);
    const c = new WshClient();
    await c.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair: kp });
    clients.push(c);
    const inbox = [];
    c.onGatewayMessage = (m) => inbox.push(m);
    for (let id = 1; id <= n; id++) await c.sendControl({ type: MSG.OPEN_TCP, gateway_id: id, host: '127.0.0.1', port: oport });
    const t0 = Date.now();
    while (inbox.filter((m) => m.type === MSG.GATEWAY_OK).length < n && Date.now() - t0 < 8000) await sleep(10);
    assert.equal(inbox.filter((m) => m.type === MSG.GATEWAY_OK).length, n);
    return { c, at, inbox };
  }

  it('the client goes away just before the expiry fires, with many connections open: the timer ends them (or finds the connection closed) and nothing is raised', async () => {
    const { c, at } = await arrange(25);
    const seen = await raised(async () => {
      while (Date.now() < at - 20) await sleep(5);
      await c.disconnect().catch(() => {});
      await sleep(Math.max(0, at - Date.now()) + 400); // the expiry has passed and the timer has run on a connection that is gone
    });
    assert.deepEqual(seen, []);
  });

  it('the client stays: every connection gets the close with the reason, nothing is raised', async () => {
    const { at, inbox } = await arrange(25);
    const seen = await raised(async () => {
      while (Date.now() < at + 100) await sleep(20);
      const t0 = Date.now();
      const ended = () => new Set(inbox.filter((m) => m.type === MSG.GATEWAY_CLOSE && m.reason === REASON).map((m) => m.gateway_id)).size;
      while (ended() < 25 && Date.now() - t0 < 8000) await sleep(10);
      assert.equal(ended(), 25);
    });
    assert.deepEqual(seen, []);
  });
});
