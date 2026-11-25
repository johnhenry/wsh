// test/objects-callback-returns.test.mjs -- callback return values (#219): a call entry that says `(callback:returns)` lets the page's stub hand back the far side's return value.
// Off unless the host opts in per entry (and per argument position); the page never waits longer than `callbackReturnTimeoutMs`; a timeout, an error, a result that is too
// big or not plain data, a full table, a dead channel and a client that cannot answer all end in `undefined`, never in a wait or a throw.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { exposeObjects, createObjectsServer, createObjectsClient, release } from '@johnhenry/wsh/objects';
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

/** Timers the test moves by hand: nothing here waits on the wall clock. */
function fakeTimers() {
  let next = 1; const live = new Map(); let t = 0;
  return {
    setTimeout(fn, ms) { const id = next++; live.set(id, { fn, at: t + ms }); return id; },
    clearTimeout(id) { live.delete(id); },
    advance(ms) { t += ms; for (const [id, x] of [...live]) if (x.at <= t) { live.delete(id); x.fn(); } },
    count: () => live.size,
  };
}

function makeWorld() {
  const state = { stubs: [] };
  const app = {
    ask(fn) { state.stubs.push(fn); return 'asked'; },
    askTwo(a, b) { state.stubs.push(a, b); return 2; },
    tell(fn) { state.stubs.push(fn); return 'told'; },
  };
  return { win: { app }, state };
}
const ALLOW = { get: ['window.app.**'], call: ['window.app.ask(callback:returns)', 'window.app.askTwo(callback:returns=1)', 'window.app.tell(callback)'] };

async function overBare(options) {
  const [c, s] = createDuplexPair();
  const server = createObjectsServer({ random, timers: { setTimeout, clearTimeout }, ...options });
  const attached = server.attach(s, { who: { username: 'alice', fingerprint: 'ab' } });
  closers.push(async () => { c.close(); s.close(); });
  return { page: await createObjectsClient(c, options.client), attached, closeServer: () => s.close('gone'), peer: c, serverPeer: s };
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

for (const [name, connect] of Object.entries({ 'a bare in-memory duplex': overBare, 'a wsh rpc channel': overWsh })) {
  describe(`callback return values over ${name}`, () => {
    const open = async (extra = {}) => { const w = makeWorld(); const c = await connect({ roots: { window: w.win }, allow: ALLOW, ...extra }); return { ...w, ...c }; };

    it('a stub of an entry that says (callback:returns) gives back a promise of what the far side returned, a plain value, also from an async function', async () => {
      const { page, state } = await open();
      await page.window.app.ask((a, b) => ({ sum: a + b, bytes: new Uint8Array([1, 2]) }));
      const stub = state.stubs[0];
      const p = stub(2, 3);
      assert.ok(p instanceof Promise, 'a promise, at once: the page is never blocked');
      assert.deepEqual(await p, { sum: 5, bytes: new Uint8Array([1, 2]) });
      const { page: page2, state: state2 } = await open();
      await page2.window.app.ask(async (x) => { await new Promise((r) => setTimeout(r, 5)); return `late ${x}`; });
      assert.equal(await state2.stubs[0]('x'), 'late x');
    });

    it('an entry that says only (callback) stays one-way: the stub returns undefined at once, as before', async () => {
      const { page, state } = await open();
      await page.window.app.tell(() => 'ignored');
      assert.equal(state.stubs[0](1), undefined);
    });

    it('per argument position: (callback:returns=1) makes the second function return and leaves the first one-way', async () => {
      const { page, state } = await open();
      const got = [];
      await page.window.app.askTwo((x) => { got.push(x); return 'no'; }, (x) => `yes ${x}`);
      const [first, second] = state.stubs;
      assert.equal(first('a'), undefined);
      assert.equal(await second('b'), 'yes b');
      await until(() => got.length === 1, 'the first one-way call');
    });
  });
}

describe('callback return values: the bound, and what the page gets when the answer does not come', () => {
  const open = async (extra = {}) => {
    const timers = fakeTimers();
    const w = makeWorld();
    const c = await overBare({ roots: { window: w.win }, allow: ALLOW, timers, ...extra });
    return { ...w, ...c, timers };
  };

  it('the page waits at most callbackReturnTimeoutMs: a far side that never answers gets undefined at that time, and the timer is gone', async () => {
    const { page, state, timers, attached } = await open({ limits: { callbackReturnTimeoutMs: 1500 } });
    await page.window.app.ask(() => new Promise(() => {}));
    const timersBefore = timers.count();
    let settled = false; let value = 'unset';
    const p = state.stubs[0]().then((v) => { settled = true; value = v; });
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(settled, false, 'still waiting, within the bound');
    timers.advance(1499);
    await new Promise((r) => setTimeout(r, 5));
    assert.equal(settled, false);
    timers.advance(1);
    await p;
    assert.equal(value, undefined);
    assert.equal(timers.count(), timersBefore, 'no timer is left behind');
    assert.deepEqual(attached.callbackReturnStats(), { pending: 0, answered: 0, timedOut: 1, failed: 0, refused: 0, dropped: 0 });
  });

  it('the default bound is 2 seconds, and a limit above 30 seconds is refused when the host is configured', () => {
    assert.throws(() => createObjectsServer({ roots: { window: {} }, allow: {}, limits: { callbackReturnTimeoutMs: 30_001 } }), /callbackReturnTimeoutMs/);
    assert.throws(() => createObjectsServer({ roots: { window: {} }, allow: {}, limits: { maxPendingCallbackReturns: 65 } }), /maxPendingCallbackReturns/);
    assert.doesNotThrow(() => createObjectsServer({ roots: { window: {} }, allow: {}, limits: { callbackReturnTimeoutMs: 30_000, maxPendingCallbackReturns: 64 } }));
  });

  it('a late answer after the timeout is ignored (the table no longer has it) and changes nothing', async () => {
    const { page, state, timers, attached } = await open();
    let release_; const gate = new Promise((r) => { release_ = r; });
    await page.window.app.ask(() => gate.then(() => 'too late'));
    const p = state.stubs[0]();
    timers.advance(2000);
    assert.equal(await p, undefined);
    release_();
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(attached.callbackReturnStats().timedOut, 1);
    assert.equal(attached.callbackReturnStats().answered, 0);
  });

  it('an error in the far side\'s function is undefined for the page and goes to onCallbackError on the far side: its text never reaches the page', async () => {
    const errors = [];
    const { page, state, attached } = await open({ client: { onCallbackError: (e) => errors.push(e.message) } });
    await page.window.app.ask(() => { throw new Error('far-side secret text'); });
    assert.equal(await state.stubs[0](), undefined);
    await until(() => errors.length === 1, 'the far side told');
    assert.deepEqual(errors, ['far-side secret text']);
    assert.equal(attached.callbackReturnStats().failed, 1);
    await page.window.app.ask(async () => { throw new Error('async one'); });
    assert.equal(await state.stubs[1](), undefined);
    assert.equal(attached.callbackReturnStats().failed, 2);
  });

  it('a result bigger than maxCallbackResultBytes, or that is not plain data, is undefined and counted', async () => {
    const { page, state, attached } = await open({ limits: { maxCallbackResultBytes: 64 } });
    await page.window.app.ask((kind) => (kind === 'big' ? 'x'.repeat(500) : kind === 'fn' ? () => 1 : { ok: 1 }));
    assert.equal(await state.stubs[0]('big'), undefined);
    assert.deepEqual(await state.stubs[0]('fine'), { ok: 1 });
    assert.equal(await state.stubs[0]('fn'), undefined, 'a function is not plain data');
    const stats = attached.callbackReturnStats();
    assert.equal(stats.answered, 1);
    assert.ok(stats.refused + stats.failed >= 2);
  });

  it('a hostile answer on the wire is refused by the host: an unknown request id, one answered twice, a value too deep or too large, a handle-shaped value', async () => {
    const { page, state, peer, attached } = await open({ limits: { maxCallbackResultBytes: 256 } });
    await page.window.app.ask(() => new Promise(() => {}));
    const p = state.stubs[0]();
    await until(() => attached.callbackReturnStats().pending === 1, 'the call pending');
    const rid = 1;
    assert.equal((await peer.request('callbackResult', { rid: 999, value: 1 })).ok, false, 'an id nobody waits for');
    await rejects(peer.request('callbackResult', { rid: 'x', value: 1 }), (e) => e.reason === 'bad-request');
    const deep = (n) => (n === 0 ? 1 : { a: deep(n - 1) });
    assert.equal((await peer.request('callbackResult', { rid, value: deep(40) })).ok, true, 'the request is answered, the value is not trusted');
    assert.equal(await p, undefined, 'a value past the bounds is undefined for the page');
    assert.equal((await peer.request('callbackResult', { rid, value: 'again' })).ok, false, 'answered once only');
    assert.equal(attached.callbackReturnStats().pending, 0);
  });

  it('at most maxPendingCallbackReturns wait at once on a channel: the next call is undefined at once, counted, and never sent', async () => {
    const { page, state, attached, timers } = await open({ limits: { maxPendingCallbackReturns: 2 } });
    const calls = [];
    await page.window.app.ask((n) => { calls.push(n); return new Promise(() => {}); });
    const [a, b] = [state.stubs[0](1), state.stubs[0](2)];
    assert.equal(await Promise.race([state.stubs[0](3), new Promise((r) => setTimeout(() => r('still waiting'), 50))]), undefined, 'answered at once, not left waiting');
    await until(() => calls.length === 2, 'two sent');
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(calls, [1, 2], 'the third was not delivered');
    assert.equal(attached.callbackReturnStats().dropped, 1);
    timers.advance(2000);
    assert.deepEqual(await Promise.all([a, b]), [undefined, undefined]);
    assert.equal(timers.count(), 0);
  });

  it('the end of the channel (Stop, navigation, revoke) answers every waiting call with undefined at once and clears its timers', async () => {
    const { page, state, closeServer, timers } = await open();
    await page.window.app.ask(() => new Promise(() => {}));
    const waiting = [state.stubs[0](), state.stubs[0]()];
    await closeServer();
    assert.deepEqual(await Promise.all(waiting), [undefined, undefined]);
    assert.equal(timers.count(), 0);
    assert.equal(await state.stubs[0](), undefined, 'a call after the end is undefined at once');
  });

  it('release(fn) answers the calls waiting on it with undefined and kills the stub', async () => {
    const { page, state, timers } = await open();
    const fn = () => new Promise(() => {});
    await page.window.app.ask(fn);
    const waiting = state.stubs[0]();
    await release(fn);
    assert.equal(await waiting, undefined);
    assert.equal(timers.count(), 0);
    assert.equal(await state.stubs[0](), undefined);
  });

  it('the rate and size bounds of a callback still hold for one that returns: a call over them is undefined at once and counted', async () => {
    const { page, state, attached } = await open({ limits: { maxCallbacksPerSecond: 1, maxCallbackBytes: 100 }, now: () => 5_000_000 });
    await page.window.app.ask((x) => x);
    const first = state.stubs[0]('one');
    assert.equal(await state.stubs[0]('two'), undefined, 'over the rate');
    assert.equal(await first, 'one');
    assert.ok(attached.callbackReturnStats().dropped >= 1);
  });
});

describe('callback return values: negotiated, so an older peer neither waits nor breaks', () => {
  it('the host states callback-returns only when an entry says (callback:returns); a host with plain (callback) entries states what it always did', async () => {
    const [c, s] = createDuplexPair();
    createObjectsServer({ roots: { window: {} }, allow: { call: ['window.app.ask(callback:returns)'] }, timers: fakeTimers() }).attach(s);
    assert.deepEqual((await c.request('roots', {})).features, ['events', 'callbacks', 'callback-returns', 'types']);
    const [c2, s2] = createDuplexPair();
    createObjectsServer({ roots: { window: {} }, allow: { call: ['window.app.ask(callback)'] } }).attach(s2);
    assert.deepEqual((await c2.request('roots', {})).features, ['events', 'callbacks', 'types']);
    closers.push(async () => { c.close(); s.close(); c2.close(); s2.close(); });
  });

  it('a client that did not say it answers (a 0.51.0 client) gets the callback with no request id, and the page gets undefined at once: it never waits for a peer that cannot answer', async () => {
    const w = makeWorld();
    const [c, s] = createDuplexPair();
    createObjectsServer({ random, roots: { window: w.win }, allow: ALLOW, timers: fakeTimers() }).attach(s);
    const got = [];
    c.onNotification('callback', (m) => got.push(m));
    const answer = await c.request('roots', {});   // the old client's roots request: no features
    assert.ok(answer.features.includes('callback-returns'));
    await c.request('resolve', { root: 'window', ops: [{ get: 'app' }, { call: 'ask', args: [null], callbacks: [[0, 1]] }] });
    closers.push(async () => { c.close(); s.close(); });
    assert.equal(await Promise.race([w.state.stubs[0]('hello'), new Promise((r) => setTimeout(() => r('still waiting'), 50))]), undefined, 'at once, not after the bound');
    await until(() => got.length === 1, 'the notification');
    assert.deepEqual(got[0].args, ['hello']);
    assert.ok(!('rid' in got[0]), 'no request id: nothing asks this client for an answer');
  });

  it('a new client says so with its roots request; the callback then carries a request id', async () => {
    const w = makeWorld();
    const [c, s] = createDuplexPair();
    createObjectsServer({ random, roots: { window: w.win }, allow: ALLOW, timers: fakeTimers() }).attach(s);
    const got = [];
    c.onNotification('callback', (m) => got.push(m));
    await c.request('roots', { features: ['callback-returns'] });
    await c.request('resolve', { root: 'window', ops: [{ get: 'app' }, { call: 'ask', args: [null], callbacks: [[0, 1]] }] });
    closers.push(async () => { c.close(); s.close(); });
    void w.state.stubs[0]('q');
    await until(() => got.length === 1, 'the notification');
    assert.ok(Number.isSafeInteger(got[0].rid) && got[0].rid >= 1);
  });

  it('a new client against a host that states nothing of it: nothing changes (a plain function call is one-way, no extra request is made)', async () => {
    const [c, s] = createDuplexPair();
    s.onRequest('roots', async (p) => { assert.deepEqual(p, { features: ['callback-returns'] }); return { roots: ['window'], features: ['events', 'callbacks', 'types'] }; });
    s.onRequest('resolve', async () => ({ v: 'ok' }));
    closers.push(async () => { c.close(); s.close(); });
    const page = await createObjectsClient(c);
    assert.equal(await page.window.app.tell(() => 1), 'ok');
  });

  it('a host with (callback:returns) entries and no timers is refused when it is configured: the bound needs a clock', () => {
    assert.throws(() => createObjectsServer({ roots: { window: {} }, allow: { call: ['window.app.ask(callback:returns)'] } }), /timers/);
    assert.doesNotThrow(() => createObjectsServer({ roots: { window: {} }, allow: { call: ['window.app.ask(callback)'] } }));
  });

  it('the notation: (callback:returns) and (callback:returns=N,M) only on a call entry, last; anything else is a TypeError', () => {
    const roots = { window: {} };
    const timers = fakeTimers();
    assert.doesNotThrow(() => createObjectsServer({ roots, timers, allow: { call: ['window.a.b(callback:returns)', 'window.a.c(callback:returns=0,2)', 'window.a.d(callback)'] } }));
    for (const entry of ['window.a(callback:return)', 'window.a(callback:returns=)', 'window.a(callback:returns=x)', 'window.a(callback:returns=1,)', 'window.a(callback:returns=-1)', 'window.a(callback:returns=99999999999)', 'window.a(callback:returns).b', 'window.a(callback:returns=1)(callback)']) {
      assert.throws(() => createObjectsServer({ roots, timers, allow: { call: [entry] } }), TypeError, entry);
    }
    for (const allow of [{ get: ['window.a(callback:returns)'] }, { set: ['window.a(callback:returns)'] }]) assert.throws(() => createObjectsServer({ roots, timers, allow }), TypeError);
  });

  it('a call whose entry only says (callback) is not widened by another entry that names a different path with returns', async () => {
    const w = makeWorld();
    const { page } = await overBare({ roots: { window: w.win }, allow: { call: ['window.app.ask(callback:returns)', 'window.app.tell(callback)'] }, timers: fakeTimers() });
    await page.window.app.tell(() => 'x');
    assert.equal(w.state.stubs[0]('q'), undefined);
  });

  it('the types a host sends are readable by a 0.51.0 client: the entry keeps its old form (callback) in the description', async () => {
    const [c, s] = createDuplexPair();
    createObjectsServer({ roots: { window: {} }, allow: { call: ['window.app.ask(callback:returns)', 'window.app.d(callback:returns=1)'] }, timers: fakeTimers() }).attach(s);
    closers.push(async () => { c.close(); s.close(); });
    const d = await c.request('types', { root: 'window' });
    assert.deepEqual(d.allow.call, ['window.app.ask(callback)', 'window.app.d(callback)']);
  });
});
