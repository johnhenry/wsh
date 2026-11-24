// test/objects.test.mjs -- remote objects, `values` mode (#190): `exposeObjects` / `client.openObjects()` / the helpers, and the transport-neutral core.
//
// The SAME suite runs over two transports: a bare in-memory duplex (`createDuplexPeer`, no wsh anywhere) and a wsh rpc channel (a memory host
// serving `wsh-objects`, a client that opens it). Then the refusals, a prototype-pollution table, the limits, and the wsh-only parts (a key's
// `rpc:wsh-objects` capability, the method `client.openObjects()`).
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH, cborEncode, cborDecode, RpcChannel, CborSequenceDecoder } from '@johnhenry/wsh';
import {
  exposeObjects, createObjectsServer, createObjectsClient, ObjectsError, NonValue, matchPath, toWire, fromWire, OBJECTS_DEFAULT_LIMITS,
  get, set, call, construct, snapshot, describe as describeRef, closeObjects,
} from '@johnhenry/wsh/objects';
import { createDuplexPair } from './helpers/duplex.mjs';

/** `assert.rejects`, for a remote reference too: a reference is a function to the engine, and `assert.rejects` would CALL it instead of awaiting it. */
const rejects = (promiseOrRef, ...rest) => assert.rejects(Promise.resolve(promiseOrRef), ...rest);

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
const tick = () => new Promise((r) => setImmediate(r));
async function until(cond, what, ms = 3000) {
  const t0 = Date.now();
  for (;;) { if (await cond()) return; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 2)); }
}

let keyPair; let keyLine;
before(async () => {
  keyPair = await generateKeyPair(true);
  keyLine = await exportPublicKeySSH(keyPair.publicKey);
});

// ── A world to reach into ───────────────────────────────────────────────────────────────────────────────────────────

const nest = (n) => (n === 0 ? { leaf: true } : { next: nest(n - 1) });

function makeWorld() {
  const log = { calls: [], getterRuns: 0, timers: [], proxyKeys: [], evaled: 0 };
  class Cart { constructor(name) { this.name = name; } hello(who) { return `hi ${who} from ${this.name}`; } }
  class HTMLDivElement { constructor(owner) { this.ownerDocument = owner; } }
  const app = {
    cart: {
      items: [{ sku: 'A1', qty: 1 }],
      add(item) { this.items.push(item); log.calls.push(['add', item]); return { count: this.items.length }; },
      get size() { log.getterRuns++; return this.items.length; },
    },
    state: {
      a: { b: { c: { d: 1 } } }, bytes: new Uint8Array([1, 2, 3]), when: new Date(0), nested: { ok: 1, fn() {}, sym: Symbol('x') },
      list: [1, () => 1, { z: 1 }, undefined], text: 'héllo', neg: -5, float: 1.5, nothing: null, yes: true,
    },
    greet(name) { return `hello ${name}`; },
    echo(v) { return v; },
    record(v) { log.calls.push(['record', v]); return 'recorded'; },
    boom() { throw new Error('the cart is locked'); },
    slow() { return new Promise((resolve) => setTimeout(() => resolve('late'), 15)); },
    reject() { return Promise.reject(new Error('async refusal')); },
    getCart() { return this.cart; },
    Cart,
    then: 'a property really named then',
    sym: Symbol('s'),
    huge: 1e21,
    big: 'x'.repeat(1000),
    deep: nest(12),
    count: 0,
    circular: (() => { const o = { n: 1 }; o.self = o; return o; })(),
    secret: 'visible only if listed',
  };
  class Window {}
  const win = Object.assign(new Window(), {
    document: { title: 'Shop', cookie: 'sid=secret-cookie', lang: 'en' },
    location: { href: 'https://shop.example/' },
    app,
    localStorage: { getItem: (k) => `ls:${k}`, setItem() {} },
    navigator: { credentials: { get: () => 'cred' }, userAgent: 'test' },
    fetch: () => { log.calls.push(['fetch']); return 'fetched'; },
    eval: () => { log.evaled++; return 'evaled'; },
    Function,
    setTimeout: (f) => { log.timers.push(f); return 1; },
    open: () => 'opened',
    postMessage: () => 'posted',
    node: new HTMLDivElement(null),
    Array,
    Object,
  });
  win.document.defaultView = win;
  win.node.ownerDocument = win.document;
  win.window = win;
  win.self = win;
  return { win, app, log };
}

const ALLOW = Object.freeze({
  get: ['window.document.title', 'window.location.href', 'window.node', 'window.app.**'],
  call: ['window.app.**'],
  set: ['window.document.title', 'window.app.count', 'window.app.cart.items'],
});

// ── Two transports ──────────────────────────────────────────────────────────────────────────────────────────────────

/** Count what the client asks of its peer. */
function counting(peer) {
  const requests = [];
  const original = peer.request.bind(peer);
  peer.request = (method, params, options) => { requests.push({ method, params }); return original(method, params, options); };
  return requests;
}

async function overBareDuplex(options) {
  const [clientPeer, serverPeer] = createDuplexPair();
  const server = createObjectsServer(options);
  server.attach(serverPeer, { who: { username: 'alice', fingerprint: 'ab' } });
  const requests = counting(clientPeer);
  const page = await createObjectsClient(clientPeer);
  closers.push(async () => { clientPeer.close(); serverPeer.close(); });
  return { page, requests, peer: clientPeer };
}

async function overWshRpc(options) {
  const host = createMemoryHost({ auth: { authorizedKeys: keyLine }, rpc: { 'wsh-objects': exposeObjects(options) } });
  closers.push(() => host.close());
  const client = await host.connect({ username: 'alice', keyPair });
  closers.push(() => client.disconnect());
  const channel = await client.openRpc('wsh-objects');
  const requests = counting(channel);
  const page = await createObjectsClient(channel);
  return { page, requests, peer: channel, client };
}

const TRANSPORTS = { 'a bare in-memory duplex': overBareDuplex, 'a wsh rpc channel': overWshRpc };

for (const [transportName, connect] of Object.entries(TRANSPORTS)) {
  describe(`remote objects over ${transportName}`, () => {
    const open = async (overrides = {}, worldOverride) => {
      const world = worldOverride ?? makeWorld();
      const conn = await connect({ roots: { window: world.win }, allow: ALLOW, ...overrides });
      return { ...conn, ...world };
    };

    it('lists only the named roots, as lazy references that send nothing until awaited', async () => {
      const { page, requests } = await open();
      assert.deepEqual(Object.keys(page), ['window']);
      assert.deepEqual(requests.map((r) => r.method), ['roots']);
      const ref = page.window.document.title; // a path: nothing sent
      assert.equal(typeof ref, 'function');
      assert.deepEqual(requests.map((r) => r.method), ['roots']);
      assert.equal(await ref, 'Shop');
      assert.deepEqual(requests.map((r) => r.method), ['roots', 'resolve']);
    });

    it('pipelining: a whole chain is ONE request, however long, calls included', async () => {
      const { page, requests } = await open();
      requests.length = 0;
      assert.equal(await page.window.app.cart.items.length, 1);
      assert.equal(await page.window.app.getCart().items[0].sku, 'A1');
      assert.equal(await new page.window.app.Cart('k').hello('bob'), 'hi bob from k');
      assert.deepEqual(requests.map((r) => r.method), ['resolve', 'resolve', 'resolve']);
      assert.deepEqual(requests[0].params.ops, [{ get: 'app' }, { get: 'cart' }, { get: 'items' }, { get: 'length' }]);
      assert.deepEqual(requests[1].params.ops.map((o) => Object.keys(o)[0]), ['get', 'call', 'get', 'get', 'get']);
      assert.deepEqual(requests[2].params.ops.map((o) => Object.keys(o)[0]), ['get', 'construct', 'call']);
    });

    it('get, call with arguments (this is the object the method was found on), construct, set', async () => {
      const { page, win, app } = await open();
      assert.deepEqual(await page.window.app.cart.add({ sku: 'B2', qty: 2 }), { count: 2 });
      assert.equal(app.cart.items.length, 2);
      assert.equal(await call(page.window.app.greet, 'x'), 'hello x');
      assert.equal(await page.window.app.echo([1, 'two', { three: 3 }, new Uint8Array([4])]).then((v) => v.length), 4);
      await set(page.window.document, 'title', 'Paid');
      assert.equal(win.document.title, 'Paid');
      assert.equal(await page.window.document.title, 'Paid');
      const c = await construct(page.window.app.Cart, 'z');
      assert.ok(c instanceof NonValue && c.kind === 'object' && c.type === 'Cart');
      assert.equal(await get(page.window.app.cart.items, 0, 'sku'), 'A1');
      assert.equal(await page.window.app.cart.items[0].qty, 1);
    });

    it('plain data comes back as itself, bytes as a Uint8Array, undefined as undefined', async () => {
      const { page } = await open();
      assert.equal(await page.window.app.state.text, 'héllo');
      assert.equal(await page.window.app.state.neg, -5);
      assert.equal(await page.window.app.state.float, 1.5);
      assert.equal(await page.window.app.state.nothing, null);
      assert.equal(await page.window.app.state.yes, true);
      const bytes = await page.window.app.state.bytes;
      assert.ok(bytes instanceof Uint8Array);
      assert.deepEqual([...bytes], [1, 2, 3]);
      assert.equal(await page.window.app.nonexistent, undefined);
      assert.deepEqual(await page.window.app.echo({ a: [1, { b: null }] }), { a: [1, { b: null }] });
    });

    it('what cannot be cloned comes back named, never as a handle', async () => {
      const { page } = await open();
      const fn = await page.window.app.greet;
      assert.ok(fn instanceof NonValue);
      assert.deepEqual({ ...fn }, { kind: 'function', type: 'greet' });
      assert.equal(typeof fn, 'object');
      assert.equal(String(fn), '[remote function greet]');
      assert.deepEqual({ ...(await page.window.app.sym) }, { kind: 'symbol' });
      assert.deepEqual({ ...(await page.window.app.state.when) }, { kind: 'Date', text: '1970-01-01T00:00:00.000Z' });
      assert.deepEqual({ ...(await page.window.node) }, { kind: 'object', type: 'HTMLDivElement' });
      assert.deepEqual({ ...(await page.window.app.huge) }, { kind: 'number', text: '1e+21' });
      // A function, or a reference (a path, which is a function to the engine), is not plain data: refused where it is written, before anything is sent.
      assert.throws(() => page.window.app.echo(() => 1), /cannot be sent as an argument/);
      assert.throws(() => page.window.app.echo(page.window.app.greet), /cannot be sent as an argument/);
      assert.throws(() => page.window.app.echo({ nested: [{ f() {} }] }), /cannot be sent as an argument/);
    });

    it('inside an object or array a member that cannot be cloned is left out (null in an array); nothing of it is called', async () => {
      const { page, log } = await open();
      const state = await snapshot(page.window.app.state);
      assert.deepEqual(state.a, { b: { c: { d: 1 } } });
      assert.deepEqual(state.nested, { ok: 1 });
      assert.deepEqual(state.list, [1, null, { z: 1 }, null]);
      assert.ok(!('when' in state));
      assert.deepEqual(await snapshot(page.window.app.circular), { n: 1 });
      const cart = await snapshot(page.window.app.cart);
      assert.deepEqual(Object.keys(cart), ['items']);
      assert.equal(log.getterRuns, 0, 'a copy never runs a getter');
      assert.equal(await page.window.app.cart.size, 1);
      assert.equal(log.getterRuns, 1, 'a get of the accessor does: getters with side effects are still gets');
    });

    it('snapshot is bounded: a depth, cut with null; bytes, refused by name', async () => {
      const { page } = await open();
      const cut = await snapshot(page.window.app.state, { depth: 2 });
      assert.deepEqual(cut.a, { b: null });
      assert.equal(cut.text, 'héllo');
      await rejects(snapshot(page.window.app.state, { maxBytes: 30 }), (e) => e instanceof ObjectsError && e.reason === 'limit' && /maxValueBytes/.test(e.message));
      await rejects(snapshot(page.window.app.state, { depth: -1 }), /depth must be a whole number/);
    });

    it('describe: names and types of what the allow-list could walk to, and nothing else', async () => {
      const { page } = await open();
      const cart = await describeRef(page.window.app.cart);
      assert.equal(cart.type, 'object');
      assert.deepEqual(cart.keys.map((k) => [k.key, k.type, k.own]).sort(), [['add', 'function', true], ['items', 'array', true], ['size', 'accessor', true]]);
      const doc = await describeRef(page.window.document);
      assert.deepEqual(doc.keys.map((k) => k.key), ['title'], 'cookie, lang and defaultView are not on the way to anything allowed');
      const win = await describeRef(page.window);
      assert.deepEqual(win.keys.map((k) => k.key).sort(), ['app', 'document', 'location', 'node']);
      assert.deepEqual((await describeRef(page.window.app.state.text)).keys, []);
    });

    it('`then` is special: await sends the request; a property really named then is reached with get()', async () => {
      const { page } = await open();
      assert.equal(await get(page.window.app, 'then'), 'a property really named then');
      assert.equal(typeof page.window.app.then, 'function', 'ref.then is the awaiting function, not a remote property');
      const awaited = await page.window.app.cart.items[0];
      assert.deepEqual(awaited, { sku: 'A1', qty: 1 });
    });

    it('assignment with = throws a sentence naming set(); set() works and reports a refusal', async () => {
      const { page } = await open();
      assert.throws(() => { page.window.document.title = 'x'; }, /cannot assign to title.*"=".*set\(ref, "title", value\)/s);
      assert.throws(() => { delete page.window.document.title; }, /cannot be deleted/);
      await rejects(set(page.window.document, 'lang', 'fr'), (e) => e.reason === 'not-allowed');
      await rejects(set(page.window.app.getCart(), 'x', 1), /plain path/);
      await set(page.window.app, 'count', 7);
      assert.equal(await page.window.app.count, 7);
      assert.throws(() => get({}, 'x'), /remote reference/);
    });

    it('an error thrown by the page is its message, with no stack; an async one too', async () => {
      const { page } = await open();
      await rejects(page.window.app.boom(), (e) => e.reason === 'threw' && /window\.app\.boom threw: the cart is locked$/.test(e.message) && !/\bat \S+ \(/.test(e.message));
      await rejects(page.window.app.reject(), /async refusal/);
      assert.equal(await page.window.app.slow(), 'late');
      await rejects(page.window.app.greet.nothing(), /not a function/);
      await rejects(page.window.app.cart.items.length.nothing(), /not a function|cannot read/);
    });

    it('nothing is allowed by default, and with no call and no set the access is read-only for real', async () => {
      const none = await open({ allow: {} });
      for (const attempt of [() => none.page.window.document.title, () => none.page.window.app.greet('x'), () => set(none.page.window.document, 'title', 'x'), () => describeRef(none.page.window), () => snapshot(none.page.window.app)]) {
        await rejects(attempt(), (e) => e instanceof ObjectsError && ['not-allowed'].includes(e.reason), String(attempt));
      }
      const readOnly = await open({ allow: { get: ['window.app.**'] } });
      assert.equal(await readOnly.page.window.app.state.text, 'héllo');
      await rejects(readOnly.page.window.app.cart.add({ sku: 'Z' }), (e) => e.reason === 'not-allowed');
      await rejects(set(readOnly.page.window.app, 'count', 1), (e) => e.reason === 'not-allowed');
      await rejects(construct(readOnly.page.window.app.Cart, 'x'), (e) => e.reason === 'not-allowed');
      assert.equal(readOnly.app.cart.items.length, 1);
      assert.equal(readOnly.app.count, 0);
    });

    it('a path is walkable only toward something allowed; a segment that could never be reached is refused with its path', async () => {
      const { page } = await open();
      await rejects(page.window.document.cookie, (e) => e.reason === 'not-allowed' && /window\.document\.cookie/.test(e.message));
      await rejects(page.window.localStorage.getItem('k'), (e) => e.reason === 'not-allowed');
      assert.equal(await page.window.location.href, 'https://shop.example/');
      await rejects(page.window.location, (e) => e.reason === 'not-allowed', 'the object itself is not listed, only href is');
    });

    it('authorize(who, op) is asked for every operation the allow-list let through, and anything but true refuses', async () => {
      const asked = [];
      const { page } = await open({ authorize: (who, op) => { asked.push({ who, kind: op.kind, text: op.text }); return op.kind !== 'call' || op.path.at(-1) !== 'greet'; } });
      assert.equal(await page.window.document.title, 'Shop');
      assert.equal(await page.window.app.echo(5), 5);
      await rejects(page.window.app.greet('x'), (e) => e.reason === 'authorize');
      assert.deepEqual(asked.map((a) => [a.kind, a.text]), [['get', 'window.document.title'], ['call', 'window.app.echo'], ['call', 'window.app.greet']]);
      assert.equal(typeof asked[0].who.username, 'string');
      const throwing = await open({ authorize: () => { throw new Error('x'); } });
      await rejects(throwing.page.window.document.title, (e) => e.reason === 'authorize');
      const maybe = await open({ authorize: async () => 'yes' });
      await rejects(maybe.page.window.document.title, (e) => e.reason === 'authorize');
    });

    it('closeObjects ends the connection; later requests fail', async () => {
      const { page } = await open();
      await closeObjects(page);
      await tick();
      await rejects(page.window.document.title);
      await rejects(closeObjects({}), /openObjects/);
    });
  });
}

// ── What is refused always, and until listed ────────────────────────────────────────────────────────────────────────

describe('always refused, in every list', () => {
  const wide = { get: ['window.**'], call: ['window.**'], set: ['window.**'] };
  for (const [transportName, connect] of Object.entries(TRANSPORTS)) {
    it(`${transportName}: __proto__, prototype, constructor, eval, Function, string timers, call/apply/bind of a function`, async () => {
      const world = makeWorld();
      const { page } = await connect({ roots: { window: world.win }, allow: wide });
      const always = (p) => rejects(p, (e) => e instanceof ObjectsError && e.reason === 'always-refused');
      await always(get(page.window.app.cart.items, '__proto__'));
      await always(page.window.app.cart.constructor);
      await always(page.window.app.greet.constructor);
      await always(page.window.app.cart.add.constructor.constructor('return 1'));
      await always(page.window.app.Cart.prototype);
      await always(page.window.eval('1'));
      await always(page.window.Function('return 1'));
      await always(new page.window.Function('return 1'));
      await always(page.window.app.__defineGetter__('x', 1));
      await always(page.window.app.greet.call(null, 'x'));
      await always(page.window.app.greet.apply(null, ['x']));
      await always(page.window.app.greet.bind(null));
      await always(page.window.setTimeout('alert(1)', 0));
      await always(set(page.window.app, '__proto__', {}));
      await always(set(page.window.app, 'constructor', {}));
      await always(set(page.window.app.cart, 'prototype', 1));
      assert.equal(world.log.evaled, 0);
      assert.equal(world.log.timers.length, 0);
      // a function argument cannot cross, so a timer takes none; a number is what a timer may be given as a call
      assert.equal(await page.window.setTimeout(), 1);
    });
  }

  it('an allow-list entry that names a refused segment, or is malformed, is a configuration error', () => {
    const roots = { window: {} };
    for (const entry of ['window.constructor', 'window.a.__proto__.b', 'window.eval', 'window.Function', 'window.a*', 'window..a', '']) {
      assert.throws(() => createObjectsServer({ roots, allow: { get: [entry] } }), TypeError, entry);
    }
    assert.throws(() => createObjectsServer({ roots, allow: { get: 'window.**' } }), /array of path patterns/);
    assert.throws(() => createObjectsServer({ roots, allow: { post: [] } }), /not an operation/);
    assert.throws(() => createObjectsServer({ roots, allow: 'everything-i-understand-this-is-remote-control' }), /not built/);
  });
});

describe('refused until an entry names them', () => {
  for (const [transportName, connect] of Object.entries(TRANSPORTS)) {
    it(`${transportName}: cookie, storage, indexedDB, credentials, fetch, XMLHttpRequest, postMessage and open need their own entry`, async () => {
      const wideWorld = makeWorld();
      const wide = await connect({ roots: { window: wideWorld.win }, allow: { get: ['window.**'], call: ['window.**'], set: ['window.**'] } });
      const needs = (p) => rejects(p, (e) => e.reason === 'needs-listing');
      await needs(wide.page.window.document.cookie);
      await needs(wide.page.window.localStorage.getItem('k'));
      await needs(wide.page.window.sessionStorage);
      await needs(wide.page.window.indexedDB);
      await needs(wide.page.window.navigator.credentials.get());
      await needs(wide.page.window.fetch('/x'));
      await needs(wide.page.window.XMLHttpRequest);
      await needs(wide.page.window.postMessage('x', '*'));
      await needs(wide.page.window.open('/x'));
      await needs(set(wide.page.window.document, 'cookie', 'a=b'));
      await needs(wide.page.window.self.localStorage);
      assert.equal(wideWorld.log.calls.length, 0);
      // wide patterns still cover everything else
      assert.equal(await wide.page.window.document.lang, 'en');
      assert.equal(await wide.page.window.navigator.userAgent, 'test');

      const listedWorld = makeWorld();
      const listed = await connect({
        roots: { window: listedWorld.win },
        allow: { get: ['window.document.cookie', 'window.localStorage.**', 'window.navigator.userAgent'], call: ['window.localStorage.getItem', 'window.fetch', 'window.open'], set: ['window.document.cookie'] },
      });
      assert.equal(await listed.page.window.document.cookie, 'sid=secret-cookie');
      assert.equal(await listed.page.window.localStorage.getItem('k'), 'ls:k');
      assert.equal(await listed.page.window.fetch('/x'), 'fetched');
      assert.equal(await listed.page.window.open('/x'), 'opened');
      await set(listed.page.window.document, 'cookie', 'a=b');
      assert.equal(listedWorld.win.document.cookie, 'a=b');
      // not named: not allowed at all (the allow-list is checked first)
      await rejects(listed.page.window.sessionStorage, (e) => e.reason === 'not-allowed');
      await rejects(listed.page.window.postMessage('x'), (e) => e.reason === 'not-allowed');
    });
  }
});

// ── The prototype-pollution table ───────────────────────────────────────────────────────────────────────────────────

describe('a prototype-pollution table', () => {
  const wide = { get: ['window.**'], call: ['window.**'], set: ['window.**'] };
  const attacks = (page) => ({
    'a path through an array to its prototype': () => get(page.window.app.cart.items, '__proto__'),
    'a path through an array to its constructor': () => get(page.window.app.cart.items, 'constructor'),
    'constructor.prototype of a function': () => page.window.app.greet.constructor.prototype,
    'a property read of __proto__ on an array': () => page.window.app.cart.items['__proto__'],
    'a set of __proto__ on an array': () => set(page.window.app.cart.items, '__proto__', { polluted: true }),
    'a set through a path with __proto__ in the middle': () => set(page.window.app.cart.items['__proto__'], 'polluted', true),
    'a set of constructor': () => set(page.window.app, 'constructor', { prototype: { polluted: true } }),
    'a set of prototype on a class': () => set(page.window.app.Cart, 'prototype', { polluted: true }),
    'an argument with an own __proto__ key': () => page.window.app.record(JSON.parse('{"__proto__":{"polluted":true}}')),
    'a nested argument with a constructor key': () => page.window.app.record({ ok: { constructor: { prototype: { polluted: true } } } }),
    'a value for set with an own __proto__ key': () => set(page.window.app, 'count', JSON.parse('{"a":{"__proto__":{"polluted":true}}}')),
    'Object.assign with a value that has an own __proto__ key': () => page.window.Object.assign({}, JSON.parse('{"__proto__":{"polluted":true}}')),
    'Array.prototype by name': () => page.window.Array.prototype,
  });

  for (const [transportName, connect] of Object.entries(TRANSPORTS)) {
    it(`${transportName}: every row is refused and nothing is polluted`, async () => {
      const world = makeWorld();
      const { page } = await connect({ roots: { window: world.win }, allow: wide });
      for (const [name, attack] of Object.entries(attacks(page))) {
        // The wsh channel's own encoder leaves such a key out before sending (the raw-bytes test below covers the host's side): nothing crosses to be refused.
        if (transportName.includes('wsh') && /own __proto__/.test(name)) continue;
        await rejects(Promise.resolve().then(attack), (e) => e instanceof ObjectsError && ['always-refused', 'bad-request', 'needs-listing'].includes(e.reason), name);
      }
      assert.equal({}.polluted, undefined);
      assert.equal([].polluted, undefined);
      assert.equal(Object.prototype.polluted, undefined);
      assert.equal(world.app.polluted, undefined);
      assert.equal(Object.getPrototypeOf(world.app.cart.items), Array.prototype);
      assert.deepEqual(world.log.calls, []);
    });

    it(`${transportName}: keys that are not strings never reach the page: numbers, objects, arrays, symbols, dotted names, empty`, async () => {
      const world = makeWorld();
      const { page, peer } = await connect({ roots: { window: world.win }, allow: { get: ['window.**'] } });
      for (const key of [5, null, {}, ['a'], '', 'a.b', 'x'.repeat(300), true]) {
        await rejects(peer.request('resolve', { root: 'window', ops: [{ get: key }] }), (e) => e.reason === 'bad-request', JSON.stringify(key)?.slice(0, 20));
      }
      for (const params of [{ root: 'nope', ops: [] }, { root: 5, ops: [] }, { root: 'window', ops: 'x' }, { root: 'window', ops: [{}] }, { root: 'window', ops: [{ get: 'a', call: 'b' }] }, { root: 'window', ops: [null] }]) {
        await rejects(peer.request('resolve', params), (e) => e instanceof Error && (e.reason === 'bad-request' || e.reason === 'no-such-root'), JSON.stringify(params));
      }
      // The proxy does not turn a symbol into a path.
      assert.equal(page.window.app[Symbol.iterator], undefined);
      assert.equal(page.window.app[Symbol.toPrimitive], undefined);
      assert.equal(page.window.app[Symbol.asyncIterator], undefined);
      // Numeric property names are strings like any other, and walk an array.
      assert.equal(await page.window.app.cart.items[0].sku, 'A1');
      assert.equal(await page.window.app.cart.items[7], undefined);
      assert.equal(await page.window.app.cart.items['-1'], undefined);
    });

    it(`${transportName}: an accessor property runs only when it is the path named, never inside a copy`, async () => {
      const world = makeWorld();
      const { page } = await connect({ roots: { window: world.win }, allow: wide });
      await snapshot(page.window.app);
      await page.window.app.cart.items.length;
      assert.equal(world.log.getterRuns, 0);
      assert.equal(await page.window.app.cart.size, 1);
      assert.equal(world.log.getterRuns, 1);
    });

    it(`${transportName}: a Proxy as a root is asked only for what the allow-list lets through`, async () => {
      const world = makeWorld();
      const seen = [];
      const proxy = new Proxy(world.win, {
        get(target, key, receiver) { seen.push(String(key)); return Reflect.get(target, key, receiver); },
        ownKeys(target) { seen.push('<ownKeys>'); return Reflect.ownKeys(target); },
        getPrototypeOf(target) { seen.push('<getPrototypeOf>'); return Reflect.getPrototypeOf(target); },
      });
      const { page } = await connect({ roots: { window: proxy }, allow: { get: ['window.document.title'], call: ['window.app.greet'] } });
      assert.equal(await page.window.document.title, 'Shop');
      assert.equal(await page.window.app.greet('p'), 'hello p');
      for (const attack of [() => page.window.localStorage, () => page.window.__proto__, () => page.window.constructor, () => page.window.eval('1'), () => page.window.app.record('x'), () => page.window.secret]) {
        await rejects(attack());
      }
      assert.deepEqual([...new Set(seen)].sort(), ['app', 'document'], `the Proxy's traps saw ${seen.join(', ')}`);
      assert.equal(world.log.evaled, 0);
    });

    it(`${transportName}: a root that is not an object, an unknown root, and a request for the root itself`, async () => {
      assert.throws(() => createObjectsServer({ roots: { window: 5 }, allow: {} }), /must be an object/);
      assert.throws(() => createObjectsServer({ roots: { window: null }, allow: {} }), /must be an object/);
      assert.throws(() => createObjectsServer({ roots: { __proto__x: {}, 'a b': {} }, allow: {} }), /not allowed/);
      assert.throws(() => createObjectsServer({ roots: {}, allow: {} }), /at least one root/);
      assert.throws(() => createObjectsServer({ allow: {} }), /roots must be an object/);
      assert.throws(() => createObjectsServer({ roots: { constructor: {} }, allow: {} }), /not allowed/);
      const world = makeWorld();
      const { page } = await connect({ roots: { window: world.win }, allow: { get: ['window'] } });
      const self = await page.window;
      assert.ok(self instanceof NonValue && self.kind === 'object', 'a root is not a value: it is named');
    });
  }
});

// ── Limits, each refused by name ────────────────────────────────────────────────────────────────────────────────────

describe('limits are refused by name', () => {
  for (const [transportName, connect] of Object.entries(TRANSPORTS)) {
    const limited = async (limits, extra = {}) => {
      const world = makeWorld();
      return { world, ...(await connect({ roots: { window: world.win }, allow: ALLOW, limits, ...extra })) };
    };
    const refusedBy = (name) => (e) => e instanceof ObjectsError && e.reason === 'limit' && e.data?.limit === name && e.message.includes(name);

    it(`${transportName}: maxOps, maxArgs, maxDepth, maxValueBytes`, async () => {
      const { page } = await limited({ maxOps: 3, maxArgs: 2, maxDepth: 4, maxValueBytes: 600 });
      await rejects(page.window.app.cart.items.length, refusedBy('maxOps'));
      await rejects(page.window.app.echo(1, 2, 3), refusedBy('maxArgs'));
      await rejects(page.window.app.echo(nest(6)), refusedBy('maxDepth'));
      await rejects(page.window.app.deep, refusedBy('maxDepth'));
      await rejects(page.window.app.big, refusedBy('maxValueBytes'));
      await rejects(page.window.app.echo('y'.repeat(2000)), refusedBy('maxValueBytes'));
      assert.equal(await page.window.app.greet('ok'), 'hello ok');
    });

    it(`${transportName}: maxRequestsPerSecond (per attached peer, over a sliding second)`, async () => {
      let clock = 1_000_000;
      const { page } = await limited({ maxRequestsPerSecond: 3 }, { now: () => clock });
      // (the request for the roots, when the page was opened, was the first of the three)
      for (let i = 0; i < 2; i++) assert.equal(await page.window.document.title, 'Shop');
      await rejects(page.window.document.title, refusedBy('maxRequestsPerSecond'));
      clock += 1000;
      assert.equal(await page.window.document.title, 'Shop');
    });

    it(`${transportName}: a value is kept under what the transport carries in one message`, async () => {
      // A message is 1 MiB here. Ask for a limit above it: the transport's own bound still holds the answer under it, refused by name.
      const world = makeWorld();
      world.app.mega = { text: 'm'.repeat(1536 * 1024), fits: 'f'.repeat(900 * 1024) };
      const { page } = await connect({ roots: { window: world.win }, allow: ALLOW, limits: { maxValueBytes: 8 * 1024 * 1024 } });
      assert.equal((await page.window.app.mega.fits).length, 900 * 1024);
      await rejects(page.window.app.mega.text, (e) => e.reason === 'limit' && /maxValueBytes/.test(e.message));
    });

    it(`${transportName}: the limits themselves are checked`, () => {
      assert.throws(() => createObjectsServer({ roots: { window: {} }, limits: { maxOps: 0 } }), /positive integer/);
      assert.throws(() => createObjectsServer({ roots: { window: {} }, limits: { nope: 1 } }), /unknown limit/);
      assert.throws(() => createObjectsServer({ roots: { window: {} }, mode: 'handles' }), /'handles' is not built/);
      assert.throws(() => createObjectsServer({ roots: { window: {} }, mode: 'other' }), /must be 'values'/);
      assert.throws(() => createObjectsServer({ roots: { window: {} }, authorize: 'yes' }), /authorize must be a function/);
    });
  }
});

// ── The core, unit by unit ──────────────────────────────────────────────────────────────────────────────────────────

describe('the core: path patterns and the wire rules', () => {
  it('matchPath: * is one segment, ** is any number, also none', () => {
    const m = (pattern, path) => matchPath(pattern.split('.'), path.split('.'));
    assert.ok(m('window.app.**', 'window.app'));
    assert.ok(m('window.app.**', 'window.app.cart.items.length'));
    assert.ok(m('window.*.title', 'window.document.title'));
    assert.ok(!m('window.*.title', 'window.document.x.title'));
    assert.ok(m('window.**.title', 'window.document.title'));
    assert.ok(m('window.**.title', 'window.title'));
    assert.ok(!m('window.app.**', 'window.apple'));
    assert.ok(!m('window.app', 'window.app.cart'));
    assert.ok(m('**', 'a.b.c'));
  });

  it('toWire: plain data is itself, anything else is named; limits throw by name', () => {
    assert.deepEqual(toWire({ a: [1, 'x', null, true] }), { v: { a: [1, 'x', null, true] } });
    assert.deepEqual(toWire(undefined), { u: 'undefined' });
    assert.deepEqual(toWire(() => {}), { u: 'function' });
    assert.deepEqual(toWire(Symbol('q')), { u: 'symbol' });
    assert.deepEqual(toWire(10n), { u: 'bigint', text: '10' });
    assert.deepEqual(toWire(new Map()), { u: 'object', type: 'Map' });
    assert.deepEqual(toWire(new RegExp('a+', 'g')), { u: 'RegExp', text: '/a+/g' });
    assert.deepEqual(toWire(new TypeError('boom')), { u: 'Error', type: 'TypeError', text: 'boom' });
    assert.deepEqual(toWire(Object.create(null, { x: { value: 1, enumerable: true } })), { v: { x: 1 } });
    assert.deepEqual(toWire({ get a() { throw new Error('never called'); }, b: 1 }), { v: { b: 1 } });
    assert.deepEqual(toWire({ toJSON() { throw new Error('never called'); }, c: 1 }).v.c, 1);
    assert.deepEqual(toWire({ ['__proto__x']: 1, constructor: 5, prototype: 6, ok: 1 }), { v: { __proto__x: 1, ok: 1 } });
    assert.deepEqual(toWire(JSON.parse('{"__proto__":1,"ok":2}')), { v: { ok: 2 } });
    assert.deepEqual(toWire(new Uint16Array([1, 2])).v, new Uint8Array([1, 0, 2, 0]));
    assert.deepEqual(toWire(new ArrayBuffer(2)).v, new Uint8Array(2));
    assert.deepEqual(toWire(Array(3)).v, [null, null, null]);
    assert.throws(() => toWire({ s: 'x'.repeat(100) }, { maxBytes: 50 }), /maxValueBytes/);
    assert.throws(() => toWire(nest(5), { maxDepth: 3 }), /maxDepth/);
    assert.deepEqual(toWire(nest(5), { maxDepth: 3, cut: true }), { v: { next: { next: { next: null } } }, truncated: true });
    assert.deepEqual(toWire(Number.NaN), { v: Number.NaN });
  });

  it('fromWire: plain data only, copied; a prototype of its own, a refused key, a function, too deep or too big are refused', () => {
    assert.deepEqual(fromWire({ a: [1, { b: new Uint8Array([1]) }] }), { a: [1, { b: new Uint8Array([1]) }] });
    assert.throws(() => fromWire(() => {}), /cannot be sent/);
    assert.throws(() => fromWire({ d: new Date() }), /plain data/);
    assert.throws(() => fromWire(JSON.parse('{"__proto__":{"x":1}}')), /never accepted/);
    assert.throws(() => fromWire({ constructor: 1 }), /never accepted/);
    assert.throws(() => fromWire(nest(10)), /maxDepth/);
    assert.throws(() => fromWire('x'.repeat(OBJECTS_DEFAULT_LIMITS.maxValueBytes + 1)), /maxValueBytes/);
    // A decoded map with that key is a plain object with an own `__proto__` member (the decoder never lets a key change the
    // prototype), and the key is refused as a refused key.
    const decoded = cborDecode(cborEncode(JSON.parse('{"__proto__":{"x":1}}')));
    assert.equal(Object.getPrototypeOf(decoded), Object.prototype);
    assert.throws(() => fromWire(decoded), /never accepted/);
    const copy = fromWire({ k: 1 });
    assert.equal(Object.getPrototypeOf(copy), Object.prototype);
  });
});

// ── Over wsh only ───────────────────────────────────────────────────────────────────────────────────────────────────

describe('over wsh: the capability, client.openObjects(), and the wire', () => {
  async function serveWith(authorizedKeys) {
    const world = makeWorld();
    const host = createMemoryHost({ auth: { authorizedKeys }, rpc: { 'wsh-objects': exposeObjects({ roots: { window: world.win }, allow: ALLOW }) } });
    closers.push(() => host.close());
    const client = await host.connect({ username: 'alice', keyPair });
    closers.push(() => client.disconnect());
    return { client, world, host };
  }

  it('client.openObjects() returns the roots as lazy references', async () => {
    const { client } = await serveWith(keyLine);
    const page = await client.openObjects();
    assert.equal(await page.window.document.title, 'Shop');
    assert.equal(typeof Object.getOwnPropertyDescriptor(Object.getPrototypeOf(client), 'openObjects')?.value, 'function');
    assert.equal(Object.keys(Object.getPrototypeOf(client)).includes('openObjects'), false);
  });

  it("a key's rpc:wsh-objects capability opens the channel; a key without it is refused, and one with no capabilities is not limited", async () => {
    for (const [line, ok] of [[`capabilities="rpc:wsh-objects" ${keyLine}`, true], [`capabilities="mcp:*,exec" ${keyLine}`, false], [keyLine, true]]) {
      const { client } = await serveWith(line);
      if (ok) assert.equal(await (await client.openObjects()).window.document.title, 'Shop');
      else await rejects(client.openObjects(), /capability|rpc:wsh-objects/);
    }
  });

  it('the identity of the caller reaches authorize()', async () => {
    const asked = [];
    const world = makeWorld();
    const host = createMemoryHost({ auth: { authorizedKeys: keyLine }, rpc: { 'wsh-objects': exposeObjects({ roots: { window: world.win }, allow: ALLOW, authorize: (who) => { asked.push(who); return true; } }) } });
    closers.push(() => host.close());
    const client = await host.connect({ username: 'alice', keyPair });
    closers.push(() => client.disconnect());
    await (await client.openObjects()).window.document.title;
    assert.equal(asked[0].username, 'alice');
    assert.match(asked[0].fingerprint, /^[0-9a-f]{64}$/);
  });

  it('a map with a "__proto__" key in raw CBOR is refused as a refused key, and nothing changes', async () => {
    // The decoder keeps such a key as an own member (it never alters the prototype), and the object core refuses it.
    const world = makeWorld();
    const handler = exposeObjects({ roots: { window: world.win }, allow: ALLOW });
    const replies = [];
    const decoder = new CborSequenceDecoder();
    const channel = new RpcChannel({ write: (bytes) => { for (const m of decoder.feed(bytes)) replies.push(m); } });
    handler(channel, { user: 'mallory', fingerprint: 'cd' });
    const hostile = JSON.parse('{"__proto__":{"polluted":true},"ok":1}');
    const send = (id, params) => channel.feed(cborEncode({ jsonrpc: '2.0', id, method: 'resolve', params }));
    send(1, { root: 'window', ops: [{ get: 'app' }, { call: 'record', args: [hostile] }] });
    send(2, { root: 'window', ops: [{ get: 'app' }, { call: 'record', args: [{ nested: hostile }] }] });
    send(3, { root: 'window', ops: [{ get: 'app' }, { call: 'record', args: [{ fine: 1 }] }] });
    await until(() => replies.length === 3, 'three replies');
    const byId = Object.fromEntries(replies.map((r) => [r.id, r]));
    assert.match(byId[1].error?.message ?? '', /never accepted/);
    assert.match(byId[2].error?.message ?? '', /never accepted/);
    assert.equal(byId[3].result?.v, 'recorded');
    assert.deepEqual(world.log.calls, [['record', { fine: 1 }]], 'only the plain call ran');
    assert.equal({}.polluted, undefined);
    assert.equal(Object.prototype.polluted, undefined);
    await channel.close('done');
  });

  it('exposeObjects without roots, and mode handles, are refused with a sentence', () => {
    assert.throws(() => exposeObjects({}), /roots must be an object/);
    assert.throws(() => exposeObjects({ roots: { window: {} }, mode: 'handles' }), /not built/);
  });

  it('closeSessions tells the caller why and ends the channel', async () => {
    const world = makeWorld();
    const handler = exposeObjects({ roots: { window: world.win }, allow: ALLOW });
    const host = createMemoryHost({ auth: { authorizedKeys: keyLine }, rpc: { 'wsh-objects': handler } });
    closers.push(() => host.close());
    const client = await host.connect({ username: 'alice', keyPair });
    closers.push(() => client.disconnect());
    const page = await client.openObjects();
    assert.equal(await handler.closeSessions('the page is leaving'), 1);
    await rejects(page.window.document.title, /the page is leaving|closed/);
    assert.equal(await handler.closeSessions('again'), 0);
  });
});
