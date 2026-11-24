// test/objects-handles.test.mjs -- handles on the PATH-BOUND model (#190): a root can opt in with `handles: { ROOT: { nodes? } }`; a value that cannot be cloned
// then comes back as an opaque handle, and every operation through it is judged by the allow-list for the path that produced it.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import {
  exposeObjects, createObjectsServer, createObjectsClient, NonValue, RemoteHandle, get, set, call, describe as describeRef, snapshot, use, release, ObjectsError,
} from '@johnhenry/wsh/objects';
import { createDuplexPair } from './helpers/duplex.mjs';

const rejects = (x, ...rest) => assert.rejects(Promise.resolve(x), ...rest);
const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
let keyPair; let keyLine;
before(async () => { keyPair = await generateKeyPair(true); keyLine = await exportPublicKeySSH(keyPair.publicKey); });
const random = (n) => webcrypto.getRandomValues(new Uint8Array(n));

class Node {}
class Element extends Node {}
class Document extends Node {}
class HTMLDivElement extends Element { constructor(owner) { super(); this.ownerDocument = owner; this.id = 'main'; } }
class Window {}
class Cart {
  constructor() { this.items = [{ sku: 'A1' }]; }
  add(item) { this.items.push(item); return this.items.length; }
  get size() { return this.items.length; }
}
class Counter { n = 0; inc() { this.n++; return this.n; } }

function makeWorld() {
  const log = { fetched: 0 };
  const doc = new Document();
  doc.title = 'Shop';
  const body = new HTMLDivElement(doc);
  doc.body = body;
  const win = Object.assign(new Window(), {
    document: doc,
    app: {
      cart: new Cart(),
      makeCounter() { return new Counter(); },
      echo: (v) => v,
      fetch: () => { log.fetched++; return 'fetched'; },
      node: body,
      tools: new (class Tools { run() { return 'ran'; } })(),
    },
    localStorage: { getItem: () => 'x' },
  });
  win.self = win;
  doc.defaultView = win;
  return { win, doc, body, log };
}
const ALLOW = { get: ['window.app.**', 'window.document.title'], call: ['window.app.**'], set: ['window.app.cart.items'] };

async function overBare(options) {
  const [c, s] = createDuplexPair();
  const server = createObjectsServer({ random, ...options });
  const attached = server.attach(s, { who: { username: 'alice', fingerprint: 'ab' } });
  closers.push(async () => { c.close(); s.close(); });
  return { page: await createObjectsClient(c), peer: c, serverPeer: s, attached };
}
async function overWsh(options) {
  const host = createMemoryHost({ auth: { authorizedKeys: keyLine }, rpc: { 'wsh-objects': exposeObjects(options) } });
  closers.push(() => host.close());
  const client = await host.connect({ username: 'alice', keyPair });
  closers.push(() => client.disconnect());
  const channel = await client.openRpc('wsh-objects');
  return { page: await createObjectsClient(channel), peer: channel, client };
}
const TRANSPORTS = { 'a bare in-memory duplex': overBare, 'a wsh rpc channel': overWsh };

for (const [name, connect] of Object.entries(TRANSPORTS)) {
  describe(`handles over ${name}`, () => {
    const open = async (extra = {}) => { const w = makeWorld(); const c = await connect({ roots: { window: w.win }, allow: ALLOW, handles: { window: {} }, ...extra }); return { ...w, ...c }; };

    it('a value that cannot be cloned is an opaque handle on an opted-in root, usable across calls; on a values root it stays a named non-value', async () => {
      const { page } = await open();
      const cart = await page.window.app.cart;
      assert.ok(cart instanceof RemoteHandle);
      assert.equal(cart.type, 'Cart');
      assert.deepEqual(Object.keys(cart), [], 'nothing of it is enumerable: no id to copy out of it');
      const c = use(cart);
      assert.equal(await c.items.length, 1);
      assert.equal(await c.add({ sku: 'B2' }), 2);
      assert.equal(await c.size, 2);
      assert.equal(await c.items.length, 2, 'the same object, across requests');
      const values = await connect({ roots: { window: makeWorld().win }, allow: ALLOW });
      assert.ok((await values.page.window.app.cart) instanceof NonValue);
    });

    it('a handle returned by a call behaves as the path f(): state is kept, and the allow-list can name that path', async () => {
      const { page } = await open();
      const counter = await page.window.app.makeCounter();
      assert.ok(counter instanceof RemoteHandle);
      assert.equal(await use(counter).inc(), 1);
      assert.equal(await use(counter).inc(), 2);
      assert.equal(await use(counter).n, 2);
      const narrow = await open({ allow: { get: [], call: ['window.app.makeCounter', 'window.app.makeCounter().inc'] } });
      const c2 = await narrow.page.window.app.makeCounter();
      assert.equal(await use(c2).inc(), 1);
      await rejects(use(c2).n, (e) => e.reason === 'not-allowed' && /window\.app\.makeCounter\(\)\.n/.test(e.message));
      const none = await open({ allow: { call: ['window.app.makeCounter'] } });
      const c3 = await none.page.window.app.makeCounter();
      await rejects(use(c3).inc(), (e) => e.reason === 'not-allowed');
    });

    it('a handle never widens what its path grants', async () => {
      const { page, win } = await open({ allow: { get: ['window.app.cart'], call: ['window.app.cart.add'] } });
      const cart = await page.window.app.cart;
      assert.equal(await use(cart).add({ sku: 'Z' }), 2);
      await rejects(use(cart).items, (e) => e.reason === 'not-allowed' && /window\.app\.cart\.items/.test(e.message));
      await rejects(use(cart).size, (e) => e.reason === 'not-allowed');
      await rejects(set(use(cart), 'items', []), (e) => e.reason === 'not-allowed');
      assert.equal(win.app.cart.items.length, 2);
    });

    it('the always-refused names and the entries that must name their path stay refused through a handle', async () => {
      const { page, log } = await open({ allow: { get: ['window.app.**'], call: ['window.app.**'] } });
      const tools = await page.window.app.tools;
      for (const attempt of [use(tools).constructor, use(tools).__proto__, use(tools).run.constructor, use(tools).run.call(null)]) {
        await rejects(attempt, (e) => e.reason === 'always-refused');
      }
      const cart = await page.window.app.cart;
      await rejects(use(cart).fetch('/x'), (e) => e.reason === 'needs-listing' || e.reason === 'not-allowed');
      await rejects(use(await page.window.app.tools).run.apply(null, []), (e) => e.reason === 'always-refused');
      assert.equal(log.fetched, 0);
      // `fetch` is refused until named, handle or no handle.
      const wide = await open({ allow: { get: ['window.**'], call: ['window.**'] } });
      const toolsH = await wide.page.window.app.tools;
      await rejects(use(toolsH).fetch('/x'), (e) => e.reason === 'needs-listing');
      await rejects(wide.page.window.app.fetch('/x'), (e) => e.reason === 'needs-listing');
      assert.equal(log.fetched, 0);
    });

    it('a node, a window or a document is not a handle unless the root opts in with nodes; and then its graph members stay refused unless named', async () => {
      const { page } = await open({ allow: { get: ['window.document.**', 'window.self', 'window.app.node.**'], call: [] } });
      for (const ref of [page.window.document.body, page.window.self, page.window.app.node]) {
        const v = await ref;
        assert.ok(v instanceof NonValue && v.kind === 'object', 'named, not a handle');
      }
      const optIn = await open({ handles: { window: { nodes: true } }, allow: { get: ['window.document.**', 'window.app.cart', 'window.app.node'], call: [] } });
      const body = await optIn.page.window.document.body;
      assert.ok(body instanceof RemoteHandle, 'the root said nodes: true');
      assert.equal(body.type, 'HTMLDivElement');
      assert.equal(await use(body).id, 'main');
      for (const member of ['ownerDocument', 'defaultView', 'parentNode', 'getRootNode', 'contentWindow', 'contentDocument']) {
        await rejects(use(body)[member], (e) => e.reason === 'needs-listing' || e.reason === 'not-allowed', member);
      }
      await rejects(use(body).ownerDocument, (e) => e.reason === 'not-allowed' || e.reason === 'needs-listing');
      // Even a wide entry does not reach them; only an entry that names the member does.
      const wide = await open({ handles: { window: { nodes: true } }, allow: { get: ['window.document.**'], call: [] } });
      await rejects(wide.page.window.document.body.ownerDocument, (e) => e.reason === 'needs-listing');
      const named = await open({ handles: { window: { nodes: true } }, allow: { get: ['window.document.body', 'window.document.body.ownerDocument'], call: [] } });
      const doc = await use(await named.page.window.document.body).ownerDocument;
      assert.ok(doc instanceof RemoteHandle && doc.type === 'Document');
      await rejects(use(doc).defaultView, (e) => e.reason === 'not-allowed' || e.reason === 'needs-listing');
    });

    it('the table is bounded by name and never evicts; release frees a place, and a released handle is gone', async () => {
      const { page } = await open({ limits: { maxHandles: 2 } });
      const a = await page.window.app.cart;
      const b = await page.window.app.makeCounter();
      await rejects(page.window.app.tools, (e) => e.reason === 'limit' && e.data.limit === 'maxHandles' && /maxHandles/.test(e.message));
      assert.equal(await use(a).size, 1, 'nothing was evicted');
      await release(b);
      await release(b);
      await rejects(use(b).inc(), (e) => e.reason === 'bad-request' && /no such handle/.test(e.message));
      const c = await page.window.app.tools;
      assert.ok(c instanceof RemoteHandle);
      assert.equal(await use(c).run(), 'ran');
    });

    it('ids are unguessable and meaningful only on their own session: another session, and a made-up id, find nothing', async () => {
      const one = await open();
      const other = await open();
      const cart = await one.page.window.app.cart;
      const id = await (async () => { let seen; const orig = one.peer.request.bind(one.peer); one.peer.request = (m, p, o) => { seen = p; return orig(m, p, o); }; await use(cart).size; one.peer.request = orig; return seen.handle; })();
      assert.match(id, /^[A-Za-z0-9_-]{22,}$/);
      const second = await one.page.window.app.cart;
      const id2 = await (async () => { let seen; const orig = one.peer.request.bind(one.peer); one.peer.request = (m, p, o) => { seen = p; return orig(m, p, o); }; await use(second).size; one.peer.request = orig; return seen.handle; })();
      assert.notEqual(id, id2);
      for (const bad of [id, 'A'.repeat(22), '', 5, null, {}]) {
        await rejects(other.peer.request('resolve', { handle: bad, ops: [{ get: 'size' }] }), (e) => e.reason === 'bad-request', String(bad));
      }
      await rejects(other.peer.request('release', { handle: id }), (e) => e.reason === 'bad-request');
    });

    it('a preview reveals only what a get on the same path may: nothing without a get entry, a bounded list of key names with one', async () => {
      const without = await open({ allow: { call: ['window.app.makeCounter'] } });
      const h1 = await without.page.window.app.makeCounter();
      assert.equal(h1.preview, undefined);
      const withGet = await open({ allow: { get: ['window.app.makeCounter()'], call: ['window.app.makeCounter'] } });
      const h2 = await withGet.page.window.app.makeCounter();
      assert.deepEqual(h2.preview, { keys: ['n'] });
    });

    it('describe of a handle lists only the members the allow-list could walk to; snapshot is a plain copy', async () => {
      const { page } = await open({ allow: { get: ['window.app.cart', 'window.app.cart.items.**'], call: [] } });
      const cart = await page.window.app.cart;
      const d = await describeRef(use(cart));
      assert.deepEqual(d.keys.map((k) => k.key).sort(), ['items']);
      assert.deepEqual(await snapshot(use(cart).items), [{ sku: 'A1' }]);
    });

    it('a handle is not an argument: refused where it is written', async () => {
      const { page } = await open();
      const cart = await page.window.app.cart;
      assert.throws(() => page.window.app.echo(cart), /handle cannot be sent as an argument/);
      assert.throws(() => page.window.app.echo({ nested: cart }), /handle cannot be sent as an argument/);
    });
  });
}

describe('handles: the session end, the key, and the configuration', () => {
  it('the end of the channel empties the table (the host holds nothing)', async () => {
    const { page, attached, serverPeer, peer } = await overBare({ roots: { window: makeWorld().win }, allow: ALLOW, handles: { window: {} } });
    await page.window.app.cart;
    await page.window.app.makeCounter();
    assert.equal(attached.handleCount(), 2);
    peer.close('bye');
    serverPeer.close('bye');
    assert.equal(attached.handleCount(), 0);
  });

  it('the key\'s capabilities apply unchanged: an operation through a handle is the same get / call / set of the producing path', async () => {
    const w = makeWorld();
    const host = createMemoryHost({ auth: { authorizedKeys: `capabilities="objects:window:get" ${keyLine}` }, rpc: { 'wsh-objects': exposeObjects({ roots: { window: w.win }, allow: ALLOW, handles: { window: {} } }) } });
    closers.push(() => host.close());
    const client = await host.connect({ username: 'alice', keyPair });
    closers.push(() => client.disconnect());
    const page = await client.openObjects();
    const cart = await page.window.app.cart;
    assert.equal(await use(cart).size, 1);
    await rejects(use(cart).add({ sku: 'x' }), (e) => e.reason === 'not-permitted');
    assert.equal(w.win.app.cart.items.length, 1);
  });

  it('configuration: handles need a random source and a named root; the root mode is per root; the wide-open string is not accepted', () => {
    const roots = { window: {} };
    assert.throws(() => createObjectsServer({ roots, handles: { window: {} } }), /random/);
    assert.throws(() => createObjectsServer({ roots, random, handles: { other: {} } }), /no such root/);
    assert.throws(() => createObjectsServer({ roots, random, handles: { window: { nodes: 'yes' } } }), /nodes must be true or false/);
    assert.throws(() => createObjectsServer({ roots, mode: 'handles' }), /per root/);
    assert.throws(() => createObjectsServer({ roots, allow: 'everything-i-understand-this-is-remote-control' }), /not accepted/);
    assert.throws(() => createObjectsServer({ roots, random, limits: { maxHandles: 0 } }), /positive integer/);
    assert.doesNotThrow(() => createObjectsServer({ roots, random, handles: { window: { nodes: true } } }));
    assert.ok(new ObjectsError(1, 'x'));
    void [get, call];
  });
});
