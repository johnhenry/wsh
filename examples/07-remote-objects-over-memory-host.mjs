/**
 * Remote objects over a memory host: values, events, handles, callbacks, and per-root authorisation (wsh #190).
 *
 * `@johnhenry/wsh/objects` reaches an object graph by path. The host names its roots and allow-lists every
 * operation; nothing is reachable by default. Here one host exposes two roots (`window` and `store`) and two keys
 * log in: Alice may do everything on both, Bob holds `objects:window:get` and so may only READ `window`.
 * The same host, over the in-memory transport, shows plain values, an event subscription, a handle, and a callback.
 */

import assert from 'node:assert/strict';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { exposeObjects, set, on, use, release } from '@johnhenry/wsh/objects';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── The page's world: what the host actually holds ────────────────────

class Cart { items = [{ sku: 'A1' }]; add(i) { this.items.push(i); return this.items.length; } }
const bus = new EventTarget();
const subscribers = [];
const win = { title: 'Shop', app: { cart: new Cart(), bus, subscribe: (fn) => { subscribers.push(fn); return 'subscribed'; } } };
const store = { secret: 42 };

// ── Two keys, two capability lists ────────────────────────────────────

const alice = await generateKeyPair(true);
const bob = await generateKeyPair(true);
const line = async (k) => exportPublicKeySSH(k.publicKey);
const host = createMemoryHost({
  auth: { authorizedKeys: `${await line(alice)}\ncapabilities="objects:window:get" ${await line(bob)}` },
  rpc: {
    'wsh-objects': exposeObjects({
      roots: { window: win, store },
      handles: { window: {} },                 // opt this root in to handles
      allow: {
        get: ['window.title', 'window.app.**', 'store.**'],
        call: ['window.app.cart.add', 'window.app.subscribe(callback)'],
        set: ['window.title'],
        on: ['window.app.bus@ready'],          // events need an entry of their own: get/call never imply it
      },
    }),
  },
});

// ── 1. Alice: values, a call, a set ───────────────────────────────────

console.log('1. alice reads, calls and sets');
const a = await (await host.connect({ username: 'alice', keyPair: alice })).openObjects();
console.log(`   roots visible to alice: ${Object.keys(a).join(', ')}`);
assert.deepEqual(Object.keys(a).sort(), ['store', 'window']);
assert.equal(await a.window.title, 'Shop');
assert.equal(await a.window.app.cart.items.length, 1, 'a whole chain is one request');
assert.equal(await a.window.app.cart.add({ sku: 'B2' }), 2);
await set(a.window, 'title', 'Paid');
assert.equal(win.title, 'Paid');
console.log('   ALLOWED: title=%s, cart.add -> 2 items', win.title);

// ── 2. An event arrives as plain data, never as the event itself ──────

console.log('2. alice subscribes to window.app.bus@ready');
const seen = [];
const off = await on(a.window.app.bus, 'ready', (data, meta) => seen.push({ type: data.type, seq: meta.seq }));
bus.dispatchEvent(new Event('ready'));
for (let i = 0; i < 50 && !seen.length; i++) await sleep(5);
assert.equal(seen[0].type, 'ready');
console.log(`   got { type: '${seen[0].type}' } (a copy: the page's Event never crossed)`);
await off();

// ── 3. A handle: an opaque reference to something not plain data ──────

console.log('3. alice holds a handle to the cart');
const cart = await a.window.app.cart;          // a Cart instance cannot be cloned: it comes back as a handle
assert.equal(cart.type, 'Cart');
assert.equal(await use(cart).items.length, 2);
await release(cart);
console.log(`   handle type=${cart.type}; use(cart).items.length -> 2, then released`);

// ── 4. A callback: a far-side function the page may call, one way ─────

console.log('4. alice passes a callback to window.app.subscribe(callback)');
const pushed = [];
await a.window.app.subscribe((msg) => pushed.push(msg));
subscribers[0]({ n: 1 });
for (let i = 0; i < 50 && !pushed.length; i++) await sleep(5);
assert.deepEqual(pushed, [{ n: 1 }]);
console.log('   the page called the stub with { n: 1 }; the callback ran here');

// ── 5. Bob: read-only on window, and no store at all ──────────────────

console.log('5. bob holds objects:window:get');
const b = await (await host.connect({ username: 'bob', keyPair: bob })).openObjects();
assert.deepEqual(Object.keys(b), ['window'], 'a root his key cannot use is not even listed');
assert.equal(await b.window.title, 'Paid');
console.log('   ALLOWED: read window.title ->', await b.window.title);
await assert.rejects(async () => b.window.app.cart.add({ sku: 'C3' }), (e) => e.reason === 'not-permitted');
await assert.rejects(async () => set(b.window, 'title', 'hacked'), (e) => e.reason === 'not-permitted');
assert.equal(win.title, 'Paid');
assert.equal(win.app.cart.items.length, 2);
console.log('   REFUSED: cart.add and set(title) -> not-permitted; page unchanged');

await host.close();
console.log('ok: values, events, handles, callbacks and per-root authorisation all behaved');
