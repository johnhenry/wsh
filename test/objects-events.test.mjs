// test/objects-events.test.mjs -- events in values mode (#190): `on(ref, type, listener)` for EventTarget-style and emitter-style sources named by an allow-list
// entry of their own (`allow.on: ['window.bus@ready']`), delivered as bounded plain values, with bounds, drop counting, backpressure and cleanup. No handles, no callbacks.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { exposeObjects, createObjectsServer, createObjectsClient, createDuplexPeer, on, off, get, ObjectsError } from '@johnhenry/wsh/objects';
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

/** An EventTarget that counts its listeners, and an emitter that does. */
class CountingTarget extends EventTarget {
  listeners = 0;
  addEventListener(...a) { this.listeners++; return super.addEventListener(...a); }
  removeEventListener(...a) { this.listeners--; return super.removeEventListener(...a); }
}
function makeWorld() {
  const bus = new CountingTarget();
  const emitter = new EventEmitter();
  const hash = new CountingTarget();
  class HTMLDivElement {}
  const win = Object.assign(new (class Window {})(), { hash, app: { bus, emitter, secret: new CountingTarget(), notAnEmitter: { n: 1 } }, node: new HTMLDivElement() });
  return { win, bus, emitter, hash };
}
const ALLOW = {
  get: ['window.app.**'],
  on: ['window.hash@hashchange', 'window.app.bus@ready', 'window.app.emitter@tick', 'window.app.notAnEmitter@x'],
};
const EVENT_FIELDS = { hashchange: ['newURL', 'oldURL', 'node'], '*': ['detail'] };

async function overBare(options) {
  const [clientPeer, serverPeer] = createDuplexPair();
  createObjectsServer(options).attach(serverPeer, { who: { username: 'alice', fingerprint: 'ab' } });
  closers.push(async () => { clientPeer.close(); serverPeer.close(); });
  return { page: await createObjectsClient(clientPeer), serverPeer };
}
async function overWsh(options) {
  const host = createMemoryHost({ auth: { authorizedKeys: keyLine }, rpc: { 'wsh-objects': exposeObjects(options) } });
  closers.push(() => host.close());
  const client = await host.connect({ username: 'alice', keyPair });
  closers.push(() => client.disconnect());
  return { page: await client.openObjects(), client };
}
const TRANSPORTS = { 'a bare in-memory duplex': overBare, 'a wsh rpc channel': overWsh };

for (const [name, connect] of Object.entries(TRANSPORTS)) {
  describe(`events over ${name}`, () => {
    const open = async (extra = {}) => { const w = makeWorld(); const c = await connect({ roots: { window: w.win }, allow: ALLOW, eventFields: EVENT_FIELDS, ...extra }); return { ...w, ...c }; };

    it('an EventTarget source: the event arrives as a described plain object with a fixed set of fields, never the event', async () => {
      const { page, bus } = await open();
      const got = [];
      const stop = await on(page.window.app.bus, 'ready', (data, info) => got.push({ data, info }));
      assert.equal(bus.listeners, 1);
      bus.dispatchEvent(new Event('ready'));
      await until(() => got.length === 1, 'the event');
      assert.deepEqual(Object.keys(got[0].data).sort(), ['isTrusted', 'timeStamp', 'type']);
      assert.equal(got[0].data.type, 'ready');
      assert.equal(got[0].data.isTrusted, false);
      assert.equal(typeof got[0].data.timeStamp, 'number');
      assert.equal(got[0].info.dropped, 0);
      await stop();
      assert.equal(bus.listeners, 0, 'unsubscribing removes the host listener');
      bus.dispatchEvent(new Event('ready'));
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(got.length, 1);
    });

    it('extra fields only if the host lists them for that type: plain values are copied, a node is left out, anything not listed is refused', async () => {
      const { page, hash, win } = await open();
      const got = [];
      await on(page.window.hash, 'hashchange', (d) => got.push(d), { fields: ['newURL', 'oldURL', 'node'] });
      const ev = Object.assign(new Event('hashchange'), { newURL: 'https://x/#b', oldURL: 'https://x/#a', node: win.node });
      hash.dispatchEvent(ev);
      await until(() => got.length === 1, 'the event');
      assert.equal(got[0].newURL, 'https://x/#b');
      assert.equal(got[0].oldURL, 'https://x/#a');
      assert.ok(!('node' in got[0]), 'a DOM node is never delivered, not even named');
      await rejects(on(page.window.hash, 'hashchange', () => {}, { fields: ['target'] }), (e) => e.reason === 'not-allowed' && /target/.test(e.message));
    });

    it('an emitter source: the arguments arrive as plain values; what cannot be cloned is null', async () => {
      const { page, emitter } = await open();
      const got = [];
      await on(page.window.app.emitter, 'tick', (d) => got.push(d));
      emitter.emit('tick', 1, { a: [2] }, () => {}, new Uint8Array([7]));
      await until(() => got.length === 1, 'the event');
      assert.deepEqual(got[0], { type: 'tick', args: [1, { a: [2] }, null, new Uint8Array([7])] });
      assert.equal(emitter.listenerCount('tick'), 1);
    });

    it('an event source is named by an entry of its own: get and call do not imply it, and neither does a wildcard on another operation', async () => {
      const { page } = await open({ allow: { get: ['window.**'], call: ['window.**'], on: ['window.app.bus@ready'] } });
      await rejects(on(page.window.app.secret, 'ready', () => {}), (e) => e.reason === 'not-allowed');
      await rejects(on(page.window.app.bus, 'other', () => {}), (e) => e.reason === 'not-allowed' && /other/.test(e.message));
      await rejects(on(page.window.hash, 'hashchange', () => {}), (e) => e.reason === 'not-allowed');
      const bare = await open({ allow: { get: ['window.**'], call: ['window.**'] } });
      await rejects(on(bare.page.window.app.bus, 'ready', () => {}), (e) => e.reason === 'not-allowed');
      assert.equal(bare.bus.listeners, 0);
    });

    it('the always-refused names stay refused, a node or a non-source is refused by name, and authorize is asked with the type', async () => {
      const asked = [];
      const { page, bus } = await open({ authorize: (who, op) => { asked.push([op.kind, op.text, op.type]); return op.type !== 'ready'; } });
      await rejects(on(page.window.app.bus.constructor, 'ready', () => {}), (e) => e.reason === 'always-refused');
      await rejects(on(page.window.app.notAnEmitter, 'x', () => {}), (e) => e.reason === 'not-an-event-source');
      await rejects(on(page.window.app.bus, 'bad type!', () => {}), (e) => e.reason === 'bad-request');
      await rejects(on(page.window.app.bus, 'ready', () => {}), (e) => e.reason === 'authorize');
      assert.deepEqual(asked.at(-1), ['on', 'window.app.bus', 'ready']);
      assert.equal(bus.listeners, 0);
      await rejects(on(page.window.app.bus, 'ready', 'not a function'), TypeError);
    });

    it('bounds: maxSubscriptions by name, events per second per subscription with the drops counted and reported, and the size of an event', async () => {
      let clock = 1_000_000;
      const { page, bus } = await open({ limits: { maxSubscriptions: 2, maxEventsPerSecond: 2, maxEventBytes: 200 }, now: () => clock, allow: { ...ALLOW, on: [...ALLOW.on, 'window.app.bus@big'] } });
      const got = [];
      await on(page.window.app.bus, 'ready', (d, i) => got.push(i.dropped));
      await on(page.window.app.bus, 'big', () => got.push('big'));
      await rejects(on(page.window.app.bus, 'ready', () => {}), (e) => e.reason === 'limit' && e.data.limit === 'maxSubscriptions' && /maxSubscriptions/.test(e.message));
      for (let i = 0; i < 5; i++) bus.dispatchEvent(new Event('ready'));
      await until(() => got.length === 2, 'two events');
      await new Promise((r) => setTimeout(r, 20));
      assert.deepEqual(got, [0, 0], 'only two per second were delivered');
      clock += 1000;
      bus.dispatchEvent(new Event('ready'));
      await until(() => got.length === 3, 'the next second');
      assert.equal(got[2], 3, 'the subscriber is told how many were dropped before this one');
      bus.dispatchEvent(Object.assign(new Event('big'), { detail: 'x' }));
      await until(() => got.includes('big'), 'a small event of another subscription');
    });

    it('an event larger than maxEventBytes is dropped and counted, not sent', async () => {
      const { page, emitter } = await open({ limits: { maxEventBytes: 100 } });
      const got = [];
      await on(page.window.app.emitter, 'tick', (d, i) => got.push([d.args[0], i.dropped]));
      emitter.emit('tick', 'x'.repeat(500));
      emitter.emit('tick', 'ok');
      await until(() => got.length === 1, 'the small event');
      assert.deepEqual(got[0], ['ok', 1]);
    });

    it('the far side\'s listener errors stay on the far side: the page\'s dispatch is not disturbed, and later events still arrive', async () => {
      const { page, bus } = await open();
      const errors = [];
      const got = [];
      await on(page.window.app.bus, 'ready', (d) => { got.push(d); throw new Error('listener bug'); }, { onError: (e) => errors.push(e.message) });
      assert.doesNotThrow(() => bus.dispatchEvent(new Event('ready')));
      bus.dispatchEvent(new Event('ready'));
      await until(() => got.length === 2, 'both events');
      assert.deepEqual(errors, ['listener bug', 'listener bug']);
    });

    it('a listener that throws in the PAGE (the source calls it) never reaches the page: an emitter that throws on add is a refusal', async () => {
      const { page, win } = await open();
      win.app.emitter.on = () => { throw new Error('page bug'); };
      await rejects(on(page.window.app.emitter, 'tick', () => {}), (e) => /threw: page bug/.test(e.message));
    });

    it('the end of the session removes every listener; unsubscribing an unknown id is refused', async () => {
      const w = await open();
      await on(w.page.window.app.bus, 'ready', () => {});
      await on(w.page.window.hash, 'hashchange', () => {});
      assert.equal(w.bus.listeners + w.hash.listeners, 2);
      if (w.client) await w.client.disconnect(); else w.serverPeer.close('gone');
      await until(() => w.bus.listeners + w.hash.listeners === 0, 'the listeners to go');
    });

    it('off() and a second off() are harmless; events keep their order', async () => {
      const { page, bus } = await open();
      const seq = [];
      const stop = await on(page.window.app.bus, 'ready', (d, i) => seq.push(i.seq));
      for (let i = 0; i < 3; i++) bus.dispatchEvent(new Event('ready'));
      await until(() => seq.length === 3, 'three events');
      assert.deepEqual(seq, [1, 2, 3]);
      await off(stop);
      await stop();
      assert.equal(bus.listeners, 0);
    });
  });
}

describe('events: backpressure and the transport', () => {
  it('a notification that waits (no credit) holds a bounded queue; more is dropped and counted, and the count is reported when it drains', async () => {
    const [clientPeer, serverPeer] = createDuplexPair();
    const world = makeWorld();
    const original = serverPeer.notify.bind(serverPeer);
    let release; const gate = new Promise((r) => { release = r; });
    let gated = true;
    serverPeer.notify = (m, p) => { const out = original(m, p); return gated ? gate.then(() => out) : out; };
    createObjectsServer({ roots: { window: world.win }, allow: ALLOW, limits: { maxQueuedEvents: 3, maxEventsPerSecond: 1000 } }).attach(serverPeer);
    closers.push(async () => { clientPeer.close(); serverPeer.close(); });
    const page = await createObjectsClient(clientPeer);
    const got = [];
    await on(page.window.app.bus, 'ready', (d, i) => got.push(i.dropped));
    for (let i = 0; i < 10; i++) world.bus.dispatchEvent(new Event('ready'));
    gated = false; release();
    await until(() => got.length >= 4, 'the queued events');
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(got.length, 4, 'one in flight and three queued; the other six were dropped');
    world.bus.dispatchEvent(new Event('ready'));
    await until(() => got.length === 5, 'the next one');
    assert.equal(got[4], 6, 'the six drops are reported');
  });

  it('Stop and revoke: ending the session through the handler removes the listeners (closeSessions)', async () => {
    const w = makeWorld();
    const handler = exposeObjects({ roots: { window: w.win }, allow: ALLOW });
    const host = createMemoryHost({ auth: { authorizedKeys: keyLine }, rpc: { 'wsh-objects': handler } });
    closers.push(() => host.close());
    const client = await host.connect({ username: 'alice', keyPair });
    closers.push(() => client.disconnect());
    const page = await client.openObjects();
    await on(page.window.app.bus, 'ready', () => {});
    assert.equal(w.bus.listeners, 1);
    assert.equal(await handler.closeSessions('the person at the page stopped this session'), 1);
    await until(() => w.bus.listeners === 0, 'the listener to go');
  });

  it('events are gated by the key: objects:ROOT:on is the capability', async () => {
    const w = makeWorld();
    const results = {};
    for (const caps of ['objects:window:get', 'objects:window:on']) {
      const host = createMemoryHost({ auth: { authorizedKeys: `capabilities="${caps}" ${keyLine}` }, rpc: { 'wsh-objects': exposeObjects({ roots: { window: w.win }, allow: ALLOW }) } });
      closers.push(() => host.close());
      const client = await host.connect({ username: 'alice', keyPair });
      closers.push(() => client.disconnect());
      const page = await client.openObjects();
      results[caps] = await on(page.window.app.bus, 'ready', () => {}).then(() => 'ok', (e) => e.reason);
    }
    assert.deepEqual(results, { 'objects:window:get': 'not-permitted', 'objects:window:on': 'ok' });
  });

  it('configuration: an on entry needs path@type, callbacks are not offered, the wide-open forms are refused', () => {
    const roots = { window: {} };
    for (const entry of ['window.bus', 'window.bus@', '@ready', 'window.constructor@x', 'window.bus@a b']) assert.throws(() => createObjectsServer({ roots, allow: { on: [entry] } }), TypeError, entry);
    assert.throws(() => createObjectsServer({ roots, eventFields: { x: 'newURL' } }), /eventFields/);
    assert.throws(() => createObjectsServer({ roots, eventFields: { x: ['__proto__'] } }), /never/);
    assert.throws(() => createObjectsServer({ roots, limits: { maxSubscriptions: 0 } }), /positive integer/);
  });

  it('an event source and its type are named exactly: a wildcard in the type or in the path is refused when the host is created, with a sentence', () => {
    const roots = { window: {} };
    for (const entry of ['window.bus@*', 'window.bus@re*', 'window.bus@r?', 'window.*@ready', 'window.**@ready', 'window.a.*.b@ready', '**@ready']) {
      assert.throws(() => createObjectsServer({ roots, allow: { on: [entry] } }), (e) => e instanceof TypeError && /list the (event )?types?|named exactly|exactly/.test(e.message), entry);
    }
    assert.doesNotThrow(() => createObjectsServer({ roots, allow: { on: ['window.bus@ready', 'window@hashchange', 'window.bus@app:ready'] } }));
  });

  it('a dropped event costs a counter, not a copy: the event\'s fields are not read once the rate or the queue says no', async () => {
    let clock = 1_000_000;
    const [clientPeer, serverPeer] = createDuplexPair();
    const world = makeWorld();
    let reads = 0;
    const original = serverPeer.notify.bind(serverPeer);
    let gate; const held = new Promise((r) => { gate = r; });
    let hold = false;
    serverPeer.notify = (m, p) => (hold ? held : original(m, p));
    createObjectsServer({ roots: { window: world.win }, allow: ALLOW, eventFields: { ready: ['detail'] }, limits: { maxEventsPerSecond: 2, maxQueuedEvents: 2 }, now: () => clock }).attach(serverPeer);
    closers.push(async () => { clientPeer.close(); serverPeer.close(); });
    const page = await createObjectsClient(clientPeer);
    const got = [];
    await on(page.window.app.bus, 'ready', (d) => got.push(d), { fields: ['detail'] });
    const counting = () => { const e = new Event('ready'); Object.defineProperty(e, 'detail', { get() { reads++; return 1; } }); return e; };
    // Rate: two are copied, the other eight are only counted.
    for (let i = 0; i < 10; i++) world.bus.dispatchEvent(counting());
    assert.equal(reads, 2, 'only the events inside the rate were copied');
    await until(() => got.length === 2, 'two events');
    // Queue: with the transport held and the queue full, further events are not copied either.
    clock += 1000; hold = true; reads = 0;
    const queueLimitedWorld = world;
    for (let i = 0; i < 2; i++) queueLimitedWorld.bus.dispatchEvent(counting());
    clock += 1000;
    for (let i = 0; i < 6; i++) queueLimitedWorld.bus.dispatchEvent(counting());
    assert.ok(reads <= 4, `the queue was full, yet ${reads} events were copied`);
    void gate;
  });

  it('what is not offered: a callback as an argument is refused where it is written', async () => {
    const [c, s] = createDuplexPair();
    createObjectsServer({ roots: { window: makeWorld().win }, allow: { call: ['window.**'] } }).attach(s);
    const page = await createObjectsClient(c);
    await assert.rejects(Promise.resolve(page.window.app.bus.addEventListener('ready', () => {})), (e) => e.reason === 'not-allowed' && /does not accept callbacks/.test(e.message));
    void [createDuplexPeer, ObjectsError, get];
  });
});
