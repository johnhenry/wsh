// test/objects-callbacks.test.mjs -- callbacks (#190): a far-side function passed as an argument of a call whose allow-list entry says it accepts callbacks
// (`'window.app.subscribe(callback)'`). The page gets a stub it may call with plain values; one-way, bounded, dead when the session ends.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { exposeObjects, createObjectsServer, createObjectsClient, release, use, NonValue, ObjectsError } from '@johnhenry/wsh/objects';
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

function makeWorld() {
  const state = { stubs: [], returned: [] };
  class Thing { constructor() { this.x = 1; } }
  const app = {
    subscribe(fn) { state.stubs.push(fn); return 'subscribed'; },
    subscribeTwo(a, b) { state.stubs.push(a, b); return 2; },
    plain(fn) { return typeof fn; },
    echo: (v) => v,
    Thing,
  };
  return { win: { app }, state };
}
const ALLOW = { get: ['window.app.**'], call: ['window.app.subscribe(callback)', 'window.app.subscribeTwo(callback)', 'window.app.plain', 'window.app.echo'] };

async function overBare(options) {
  const [c, s] = createDuplexPair();
  const server = createObjectsServer({ random, ...options });
  const attached = server.attach(s, { who: { username: 'alice', fingerprint: 'ab' } });
  closers.push(async () => { c.close(); s.close(); });
  return { page: await createObjectsClient(c, options.client), attached, closeServer: () => s.close('gone'), peer: c };
}
async function overWsh(options) {
  const { client: clientOptions, ...serverOptions } = options;
  const handler = exposeObjects(serverOptions);
  const host = createMemoryHost({ auth: { authorizedKeys: keyLine }, rpc: { 'wsh-objects': handler } });
  closers.push(() => host.close());
  const client = await host.connect({ username: 'alice', keyPair });
  closers.push(() => client.disconnect());
  const channel = await client.openRpc('wsh-objects');
  return { page: await createObjectsClient(channel, clientOptions), closeServer: () => handler.closeSessions('the person at the page stopped this session'), peer: channel };
}
const TRANSPORTS = { 'a bare in-memory duplex': overBare, 'a wsh rpc channel': overWsh };

for (const [name, connect] of Object.entries(TRANSPORTS)) {
  describe(`callbacks over ${name}`, () => {
    const open = async (extra = {}) => { const w = makeWorld(); const c = await connect({ roots: { window: w.win }, allow: ALLOW, ...extra }); return { ...w, ...c }; };

    it('a function passed to an entry that says (callback) becomes a stub the page can call with plain values; one-way, in order', async () => {
      const { page, state } = await open();
      const got = [];
      assert.equal(await page.window.app.subscribe((...args) => { got.push(args); return 'ignored'; }), 'subscribed');
      const stub = state.stubs[0];
      assert.equal(typeof stub, 'function');
      const returned = [stub(1, { x: [2] }), stub('two', new Uint8Array([3])), stub()];
      assert.deepEqual(returned, [undefined, undefined, undefined], 'one-way: nothing comes back to the page');
      await until(() => got.length === 3, 'three calls');
      assert.deepEqual(got, [[1, { x: [2] }], ['two', new Uint8Array([3])], []]);
    });

    it('an entry without (callback) refuses a function argument, as does a path that is not listed; a nested function and a reference are refused where written', async () => {
      const { page, state } = await open();
      await rejects(page.window.app.plain(() => 1), (e) => e.reason === 'not-allowed' && /does not accept callbacks/.test(e.message));
      await rejects(page.window.app.echo(() => 1), (e) => e.reason === 'not-allowed' && /does not accept callbacks/.test(e.message));
      assert.throws(() => page.window.app.subscribe({ nested: () => 1 }), /cannot be sent as an argument/);
      assert.throws(() => page.window.app.subscribe(page.window.app.echo), /cannot be sent as an argument/);
      assert.deepEqual(state.stubs, []);
    });

    it('the stub carries plain values only: a function, a node-like object, a date and a class instance arrive as null; never a handle', async () => {
      const { page, state, win } = await open();
      const got = [];
      await page.window.app.subscribe((...a) => got.push(a));
      state.stubs[0](() => 1, new win.app.Thing(), new Date(0), Symbol('s'), { ok: 1, f() {} });
      await until(() => got.length === 1, 'the call');
      assert.deepEqual(got[0], [null, null, null, null, { ok: 1 }]);
      assert.ok(!got[0].some((v) => v instanceof NonValue));
    });

    it('several callbacks in one call, and the same function twice is one callback', async () => {
      const { page, state } = await open();
      const a = []; const b = [];
      const fa = (x) => a.push(x); const fb = (x) => b.push(x);
      assert.equal(await page.window.app.subscribeTwo(fa, fb), 2);
      state.stubs[0]('A'); state.stubs[1]('B');
      await until(() => a.length === 1 && b.length === 1, 'both');
      await page.window.app.subscribeTwo(fa, fa);
      assert.equal(state.stubs.length, 4);
    });

    it('bounds: maxCallbacks is refused by name; calls per second and the size of a call are dropped, counted and reported', async () => {
      let clock = 1_000_000;
      const told = [];
      const { page, state } = await open({ limits: { maxCallbacks: 2, maxCallbacksPerSecond: 2, maxCallbackBytes: 100 }, now: () => clock, client: { onCallbackDropped: (d) => told.push(d.dropped) } });
      const dropped = [];
      const f = (x) => dropped.push([x, told.length ? told.at(-1) : 0]);
      await page.window.app.subscribe(f);
      await rejects((async () => { await page.window.app.subscribe(() => 1); await page.window.app.subscribe(() => 2); })(), (e) => e.reason === 'limit' && e.data.limit === 'maxCallbacks' && /maxCallbacks/.test(e.message));
      const stub = state.stubs[0];
      for (let i = 0; i < 5; i++) stub(i);
      await until(() => dropped.length === 2, 'two delivered');
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(dropped.length, 2, 'two per second');
      clock += 1000;
      stub('x'.repeat(500));
      stub('after');
      await until(() => dropped.length === 3, 'the next second');
      assert.deepEqual(dropped[2], ['after', 4], 'the drops (three by rate, one by size) are told with the next delivered call');
    });

    it('the far side\'s errors never reach the page: a listener that throws goes to onCallbackError, the stub never throws', async () => {
      const errors = [];
      const { page, state } = await open({ client: { onCallbackError: (e) => errors.push(e.message) } });
      await page.window.app.subscribe(() => { throw new Error('far-side bug'); });
      assert.doesNotThrow(() => state.stubs[0](1));
      assert.doesNotThrow(() => state.stubs[0](2));
      await until(() => errors.length === 2, 'two errors');
      assert.deepEqual(errors, ['far-side bug', 'far-side bug']);
    });

    it('release(fn) kills the stub: later calls are no-ops that are counted; releasing twice is harmless', async () => {
      const w = await open();
      const got = [];
      const fn = (x) => got.push(x);
      await w.page.window.app.subscribe(fn);
      w.state.stubs[0]('before');
      await until(() => got.length === 1, 'the first call');
      await release(fn);
      await release(fn);
      assert.doesNotThrow(() => w.state.stubs[0]('after'));
      await new Promise((r) => setTimeout(r, 20));
      assert.deepEqual(got, ['before']);
      if (w.attached) assert.equal(w.attached.deadCallbackCalls(), 1);
      await rejects(release(() => 1), TypeError);
    });

    it('a stub is dead after the session ends (Stop, navigation, revoke all end the channel): calling it is a no-op that is counted', async () => {
      const w = await open();
      const got = [];
      await w.page.window.app.subscribe((x) => got.push(x));
      await w.closeServer();
      await new Promise((r) => setTimeout(r, 20));
      assert.doesNotThrow(() => w.state.stubs[0]('late'));
      await new Promise((r) => setTimeout(r, 20));
      assert.deepEqual(got, []);
      if (w.attached) assert.equal(w.attached.deadCallbackCalls(), 1);
    });
  });
}

describe('the host says what it supports; a client does not lose a callback or a handle silently', () => {
  /** A host as a 0.47.0 one was: `roots` lists roots and says nothing of features; the rest of the protocol is whatever the test registers. */
  async function oldHost(register = () => {}) {
    const [c, s] = createDuplexPair();
    s.onRequest('roots', async () => ({ roots: ['window'] }));
    register(s);
    const sent = [];
    const original = c.request.bind(c);
    c.request = (m, p, o) => { sent.push(m); return original(m, p, o); };
    closers.push(async () => { c.close(); s.close(); });
    return { page: await createObjectsClient(c), sent };
  }

  it('a new host states its features with the roots: events and callbacks always, handles when a root opted in', async () => {
    const [c, s] = createDuplexPair();
    createObjectsServer({ roots: { window: {} }, allow: {} }).attach(s);
    assert.deepEqual((await c.request('roots', {})).features, ['events', 'callbacks', 'types']);
    const [c2, s2] = createDuplexPair();
    createObjectsServer({ roots: { window: {} }, allow: {}, random, handles: { window: {} } }).attach(s2);
    assert.deepEqual((await c2.request('roots', {})).features, ['events', 'callbacks', 'types', 'handles', 'handle-events']);
    closers.push(async () => { c.close(); s.close(); c2.close(); s2.close(); });
  });

  it('a client refuses to send a function to a host that has not said it supports callbacks: a named error, and nothing is sent', async () => {
    const { page, sent } = await oldHost((s) => s.onRequest('resolve', async () => ({ v: 'ran with null' })));
    await rejects(page.window.app.subscribe(() => 1), (e) => e instanceof ObjectsError && e.reason === 'unsupported' && /host does not support callbacks/.test(e.message));
    assert.deepEqual(sent, ['roots'], 'no resolve was sent');
    assert.equal(await page.window.app.plain(1), 'ran with null', 'a call without a function still works against such a host');
  });

  it('a handle-shaped result from a host that has not said it supports handles is a named error, not an unnamed value', async () => {
    const { page } = await oldHost((s) => s.onRequest('resolve', async () => ({ h: 'abcdefghijklmnopqrstuv', kind: 'object', type: 'Cart' })));
    await rejects(page.window.app.cart, (e) => e instanceof ObjectsError && e.reason === 'unsupported' && /did not say it supports handles/.test(e.message));
  });
});

describe('callbacks: notation, capabilities and the page host', () => {
  it('the notation: (callback) only on a call entry, as the last part of the path; a path with () segments is unaffected', () => {
    const roots = { window: {} };
    assert.doesNotThrow(() => createObjectsServer({ roots, allow: { call: ['window.app.subscribe(callback)', 'window.app.makeCounter().inc', 'window.app.on(callback)'] } }));
    for (const allow of [{ get: ['window.app.x(callback)'] }, { set: ['window.app.x(callback)'] }, { call: ['window.app.(callback)'] }, { call: ['window.app.x(callback).y'] }]) {
      assert.throws(() => createObjectsServer({ roots, allow }), TypeError, JSON.stringify(allow));
    }
  });

  it('authorize sees how many callbacks the call carries; the key\'s call capability is what permits a call that carries them', async () => {
    const w = makeWorld();
    const seen = [];
    const handler = exposeObjects({ roots: { window: w.win }, allow: ALLOW, authorize: (who, op) => { seen.push([op.kind, op.callbacks ?? 0]); return true; } });
    const make = async (line) => {
      const host = createMemoryHost({ auth: { authorizedKeys: line }, rpc: { 'wsh-objects': handler } });
      closers.push(() => host.close());
      const client = await host.connect({ username: 'alice', keyPair });
      closers.push(() => client.disconnect());
      return client.openObjects();
    };
    const open = await make(keyLine);
    await open.window.app.subscribe(() => {});
    assert.deepEqual(seen.at(-1), ['call', 1]);
    const readOnly = await make(`capabilities="objects:window:get" ${keyLine}`);
    await rejects(readOnly.window.app.subscribe(() => {}), (e) => e.reason === 'not-permitted');
    assert.equal(w.state.stubs.length, 1, 'the call without the capability never ran');
  });

  it('the callbacks of a call that is refused are not created', async () => {
    const { page, state, attached } = await (async () => { const w = makeWorld(); const c = await overBare({ roots: { window: w.win }, allow: ALLOW }); return { ...w, ...c }; })();
    await rejects(page.window.app.plain(() => 1), (e) => e.reason === 'not-allowed');
    assert.equal(attached.callbackCount(), 0);
    assert.deepEqual(state.stubs, []);
    void use;
  });
});
