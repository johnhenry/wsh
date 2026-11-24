// test/objects-handle-events.test.mjs -- events through a handle (#219): `on(use(handle).path, type, listener)`. A handle stands at the path that produced it, so the
// subscription is judged exactly as a path subscription for that path extended as written: an `allow.on` entry that names the type, the key's `objects:ROOT:on`
// capability, and `authorize`. Never implied by get or call; the subscription ends with the handle and with the session.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { exposeObjects, createObjectsServer, createObjectsClient, on, off, use, release, RemoteHandle } from '@johnhenry/wsh/objects';
import { createDuplexPair } from './helpers/duplex.mjs';

const rejects = (x, ...rest) => assert.rejects(Promise.resolve(x), ...rest);
const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
async function until(cond, what, ms = 3000) {
  const t0 = Date.now();
  for (;;) { if (await cond()) return; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 2)); }
}
let keyPair; let keyLine;
before(async () => { keyPair = await generateKeyPair(true); keyLine = await exportPublicKeySSH(keyPair.publicKey); });
const random = (n) => webcrypto.getRandomValues(new Uint8Array(n));

class CountingTarget extends EventTarget {
  listeners = 0;
  addEventListener(...a) { this.listeners++; return super.addEventListener(...a); }
  removeEventListener(...a) { this.listeners--; return super.removeEventListener(...a); }
}
class Hub { constructor() { this.bus = new CountingTarget(); this.other = new CountingTarget(); } }
class Node {}
class Document extends Node {}
class HTMLDivElement extends Node {
  constructor(owner) { super(); this.ownerDocument = owner; }
  addEventListener(...a) { return this.events.addEventListener(...a); }
  removeEventListener(...a) { return this.events.removeEventListener(...a); }
  events = new CountingTarget();
}

function makeWorld() {
  const bus = new CountingTarget();
  const doc = new Document();
  doc.events = new CountingTarget();
  doc.addEventListener = (...a) => doc.events.addEventListener(...a);
  doc.removeEventListener = (...a) => doc.events.removeEventListener(...a);
  const body = new HTMLDivElement(doc);
  doc.body = body;
  const made = [];
  const win = { document: doc, app: { bus, hub: new Hub(), makeBus() { const b = new CountingTarget(); made.push(b); return b; } } };
  return { win, bus, hub: win.app.hub, doc, body, made };
}
const ALLOW = { get: ['window.app.**', 'window.document.body'], call: ['window.app.makeBus'], on: ['window.app.bus@ready', 'window.app.hub.bus@ready', 'window.app.makeBus()@ready'] };

async function overBare(options) {
  const [c, s] = createDuplexPair();
  const server = createObjectsServer({ random, ...options });
  server.attach(s, { who: { username: 'alice', fingerprint: 'ab' } });
  closers.push(async () => { c.close(); s.close(); });
  return { page: await createObjectsClient(c), peer: c, serverPeer: s };
}
async function overWsh(options, { caps } = {}) {
  const host = createMemoryHost({ auth: { authorizedKeys: caps ? `capabilities="${caps}" ${keyLine}` : keyLine }, rpc: { 'wsh-objects': exposeObjects(options) } });
  closers.push(() => host.close());
  const client = await host.connect({ username: 'alice', keyPair });
  closers.push(() => client.disconnect());
  return { page: await client.openObjects(), client };
}
const TRANSPORTS = { 'a bare in-memory duplex': overBare, 'a wsh rpc channel': overWsh };

for (const [name, connect] of Object.entries(TRANSPORTS)) {
  describe(`events through a handle over ${name}`, () => {
    const open = async (extra = {}, more) => {
      const w = makeWorld();
      const c = await connect({ roots: { window: w.win }, allow: ALLOW, handles: { window: { wideEntries: true } }, ...extra }, more);
      return { ...w, ...c };
    };

    it('a handle that stands at a path named in allow.on can be subscribed to: the same delivery as a path subscription, and off() removes the listener', async () => {
      const { page, bus } = await open();
      const handle = await page.window.app.bus;
      assert.ok(handle instanceof RemoteHandle);
      const got = [];
      const stop = await on(use(handle), 'ready', (data, info) => got.push({ data, info }));
      assert.equal(bus.listeners, 1);
      bus.dispatchEvent(new Event('ready'));
      await until(() => got.length === 1, 'the event');
      assert.deepEqual(Object.keys(got[0].data).sort(), ['isTrusted', 'timeStamp', 'type'], 'a described copy, never the event');
      assert.equal(got[0].info.dropped, 0);
      await stop();
      assert.equal(bus.listeners, 0);
    });

    it('the handle\'s path extended as written: a member of the handle, and a handle returned by a call, are judged by their own entries', async () => {
      const { page, hub, made } = await open();
      const hubHandle = await page.window.app.hub;
      const got = [];
      await on(use(hubHandle).bus, 'ready', (d) => got.push(d.type));
      hub.bus.dispatchEvent(new Event('ready'));
      await until(() => got.length === 1, 'the event of hub.bus');
      await rejects(on(use(hubHandle).other, 'ready', () => {}), (e) => e.reason === 'not-allowed' && /window\.app\.hub\.other/.test(e.message));
      assert.equal(hub.other.listeners, 0);
      const made1 = await page.window.app.makeBus();
      await on(use(made1), 'ready', (d) => got.push(`made:${d.type}`));
      made[0].dispatchEvent(new Event('ready'));
      await until(() => got.includes('made:ready'), 'the event of the call result');
    });

    it('never implied by get or call: a handle at a path with get and call entries but no on entry for the type is refused, and nothing is listened to', async () => {
      const { page, bus } = await open({ allow: { get: ['window.app.**'], call: ['window.app.**'], on: ['window.app.bus@ready'] } });
      const handle = await page.window.app.bus;
      await rejects(on(use(handle), 'other', () => {}), (e) => e.reason === 'not-allowed' && /other/.test(e.message), 'the type is named exactly');
      const hub = await page.window.app.hub;
      await rejects(on(use(hub).bus, 'ready', () => {}), (e) => e.reason === 'not-allowed');
      const bare = await open({ allow: { get: ['window.**'], call: ['window.**'] } });
      const h = await bare.page.window.app.bus;
      await rejects(on(use(h), 'ready', () => {}), (e) => e.reason === 'not-allowed');
      assert.equal(bare.bus.listeners, 0);
      assert.equal(bus.listeners, 0);
    });

    it('the source is named by the PRODUCING path: a handle to the same object reached by another path does not inherit the entry', async () => {
      const w = makeWorld();
      w.win.app.alias = w.bus;
      const c = await connect({ roots: { window: w.win }, allow: { get: ['window.app.bus', 'window.app.alias'], on: ['window.app.bus@ready'] }, handles: { window: {} } });
      const viaBus = await c.page.window.app.bus;
      const viaAlias = await c.page.window.app.alias;
      await on(use(viaBus), 'ready', () => {});
      await rejects(on(use(viaAlias), 'ready', () => {}), (e) => e.reason === 'not-allowed' && /window\.app\.alias/.test(e.message));
      assert.equal(w.bus.listeners, 1);
    });

    it('authorize is asked, with the extended path and the type, and a refusal listens to nothing', async () => {
      const asked = [];
      const { page, bus } = await open({ authorize: (who, op) => { asked.push([op.kind, op.text, op.type]); return op.kind !== 'on'; } });
      const handle = await page.window.app.bus;
      await rejects(on(use(handle), 'ready', () => {}), (e) => e.reason === 'authorize');
      assert.deepEqual(asked.at(-1), ['on', 'window.app.bus', 'ready']);
      assert.equal(bus.listeners, 0);
    });

    it('a node handle keeps its rules: no handle without nodes: true, and its graph members need an entry that names them', async () => {
      const opts = { allow: { get: ['window.document.body'], on: ['window.document.body@click'] } };
      const plain = await open({ ...opts, handles: { window: {} } });
      const named = await plain.page.window.document.body;
      assert.ok(!(named instanceof RemoteHandle), 'a node is only named, never a handle, without the root\'s own opt-in');
      const nodes = await open({ ...opts, handles: { window: { nodes: true } } });
      const body = await nodes.page.window.document.body;
      assert.ok(body instanceof RemoteHandle);
      await on(use(body), 'click', () => {});
      assert.equal(nodes.body.events.listeners, 1);
      await rejects(on(use(body).ownerDocument, 'click', () => {}), (e) => e.reason === 'not-allowed' || e.reason === 'needs-listing');
      assert.equal(nodes.doc.events.listeners, 0, 'the document was not reached through the node');
      const listed = await open({ allow: { get: ['window.document.body'], on: ['window.document.body.ownerDocument@click'] }, handles: { window: { nodes: true } } });
      const body2 = await listed.page.window.document.body;
      await rejects(on(use(body2), 'click', () => {}), (e) => e.reason === 'not-allowed', 'the node itself is not listed');
      await on(use(body2).ownerDocument, 'click', () => {});
      assert.equal(listed.doc.events.listeners, 1, 'only an entry that names the graph member reaches it');
    });

    it('the subscription dies with the handle: release removes the page listener, stops delivery, and frees the subscription place', async () => {
      const { page, bus } = await open({ limits: { maxSubscriptions: 1 } });
      const handle = await page.window.app.bus;
      const got = [];
      const stop = await on(use(handle), 'ready', (d) => got.push(d));
      await rejects(on(use(handle), 'ready', () => {}), (e) => e.reason === 'limit' && e.data.limit === 'maxSubscriptions');
      await release(handle);
      assert.equal(bus.listeners, 0, 'the listener left the page with the handle');
      bus.dispatchEvent(new Event('ready'));
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(got.length, 0);
      await stop();
      const again = await page.window.app.bus;
      await on(use(again), 'ready', () => {});
      assert.equal(bus.listeners, 1, 'the place was given back');
    });

    it('a handle released while its subscription is being authorized leaves no listener behind', async () => {
      let handle; let freed = false;
      const { page, bus } = await open({
        authorize: async (who, op) => { if (op.kind === 'on' && !freed) { freed = true; await release(handle); } return true; },
      });
      handle = await page.window.app.bus;
      await rejects(on(use(handle), 'ready', () => {}), (e) => e.reason === 'bad-request' && /no such handle/.test(e.message));
      assert.equal(bus.listeners, 0);
    });

    it('a subscription through a handle is bounded and counted like a path subscription', async () => {
      let clock = 1_000_000;
      const { page, bus } = await open({ limits: { maxEventsPerSecond: 2 }, now: () => clock });
      const handle = await page.window.app.bus;
      const got = [];
      await on(use(handle), 'ready', (d, i) => got.push(i.dropped));
      for (let i = 0; i < 5; i++) bus.dispatchEvent(new Event('ready'));
      await until(() => got.length === 2, 'two events');
      await new Promise((r) => setTimeout(r, 20));
      assert.deepEqual(got, [0, 0]);
      clock += 1000;
      bus.dispatchEvent(new Event('ready'));
      await until(() => got.length === 3, 'the next second');
      assert.equal(got[2], 3, 'the drops are told with the next event');
    });

    it('the end of the session removes the listeners of handle subscriptions', async () => {
      const w = await open();
      const handle = await w.page.window.app.bus;
      await on(use(handle), 'ready', () => {});
      assert.equal(w.bus.listeners, 1);
      if (w.client) await w.client.disconnect(); else w.serverPeer.close('gone');
      await until(() => w.bus.listeners === 0, 'the listener to go');
    });

  });
}

describe('events through a handle: the key, the host\'s statement and an older host', () => {
  it('a handle id of another session, or a made-up one, subscribes to nothing', async () => {
    const world = makeWorld();
    const options = { roots: { window: world.win }, allow: ALLOW, handles: { window: {} } };
    const one = await overBare(options);
    const other = await overBare(options);
    const seen = [];
    const request = one.peer.request.bind(one.peer);
    one.peer.request = (m, p, o) => { seen.push(p); return request(m, p, o); };
    const handle = await one.page.window.app.bus;
    await use(handle).listeners;
    const id = seen.find((p) => p.handle)?.handle;
    assert.match(id, /^[A-Za-z0-9_-]{22,}$/);
    for (const bad of [id, 'A'.repeat(22), '', 5, null]) {
      await rejects(other.peer.request('subscribe', { id: 1, handle: bad, path: [], type: 'ready' }), (e) => e.reason === 'bad-request', String(bad));
    }
    assert.equal(world.bus.listeners, 0);
  });

  it('the key\'s objects:ROOT:on capability is needed; get and call of the same key do not give it', async () => {
    const results = {};
    for (const caps of ['objects:window:get,objects:window:call', 'objects:window:get,objects:window:on']) {
      const w = makeWorld();
      const { page } = await overWsh({ roots: { window: w.win }, allow: ALLOW, handles: { window: {} } }, { caps });
      const handle = await page.window.app.bus;
      results[caps] = await on(use(handle), 'ready', () => {}).then(() => `ok:${w.bus.listeners}`, (e) => `${e.reason}:${w.bus.listeners}`);
    }
    assert.deepEqual(results, { 'objects:window:get,objects:window:call': 'not-permitted:0', 'objects:window:get,objects:window:on': 'ok:1' });
  });

  it('the host says it supports events through a handle only when a root opted in to handles', async () => {
    const [c1, s1] = createDuplexPair();
    createObjectsServer({ roots: { window: makeWorld().win }, random, allow: ALLOW, handles: { window: {} } }).attach(s1);
    const [c2, s2] = createDuplexPair();
    createObjectsServer({ roots: { window: makeWorld().win }, allow: ALLOW }).attach(s2);
    closers.push(async () => { c1.close(); s1.close(); c2.close(); s2.close(); });
    assert.deepEqual((await c1.request('roots', {})).features, ['events', 'callbacks', 'handles', 'handle-events']);
    assert.deepEqual((await c2.request('roots', {})).features, ['events', 'callbacks']);
  });

  it('a host that did not say it supports events through a handle (0.50.0) gets no request: a named error on the client, and nothing is sent', async () => {
    const [c, s] = createDuplexPair();
    createObjectsServer({ roots: { window: makeWorld().win }, random, allow: ALLOW, handles: { window: {} } }).attach(s);
    closers.push(async () => { c.close(); s.close(); });
    const sent = [];
    const request = c.request.bind(c);
    c.request = async (method, params, o) => {
      sent.push(method);
      const answer = await request(method, params, o);
      return method === 'roots' ? { ...answer, features: answer.features.filter((f) => f !== 'handle-events') } : answer;
    };
    const page = await createObjectsClient(c);
    const handle = await page.window.app.bus;
    await rejects(on(use(handle), 'ready', () => {}), (e) => e.reason === 'unsupported' && /handle/.test(e.message) && /did not say/.test(e.message));
    assert.ok(!sent.includes('subscribe'));
    void off;
  });
});
