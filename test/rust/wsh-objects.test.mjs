// test/rust/wsh-objects.test.mjs -- the Rust `wsh --sealed --via <pipe relay> objects` (the `wsh-objects` client of the Rust crates, #219) against a REAL
// JS host in a page (`createPageHost` of `@johnhenry/wsh/page` over a fake window, and a memory host for an older host's shape), through a recording relay.
//
//   values mode   roots, get, set, call, construct, snapshot, describe: plain data as JSON, bytes and what cannot be cloned as named objects; the
//                 always-refused names, a path no allow-list names, a name that needs listing, a root that is not there, a key that may only `get`
//                 refused `call`; text from the page (names, strings, errors) never reaches the terminal raw; the relay sees no path, value or method
//   events        `watch`: one JSON line per event, a burst past the host's bounded queue is told as `dropped` on the next event
//   handles       `session`: a handle used across calls and released, never widening the allow-list; the host's table is bounded and releasing gives a place back
//   features      a host that does not state `events` or `handles` is refused locally, by name (exit 5), before anything is sent
//
// Needs the built CLI: WSH_BIN, or target/release/wsh. Every process runs with HOME, USERPROFILE and XDG_CONFIG_HOME in a scratch directory.
import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer, WebSocket as WsClient } from 'ws';
import { createPageHost } from '@johnhenry/wsh/page';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { newRendezvousId } from '@johnhenry/wsh/pipe-relay';
import { createFakeWindow } from '../helpers/fake-window.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const MARKER = 'PLANTED-MARKER-OKAPI-5521';
const scratch = [];
const closers = [];
before(() => { assert.ok(existsSync(WSH_BIN), `expected the built wsh at ${WSH_BIN} (cargo build -p wsh-cli, or set WSH_BIN)`); });
after(() => { for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true }); });
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, what, ms = 15_000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
};
const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'alice', TERM: 'xterm' });

/** A scratch HOME with keys `default` and `getter` (the second is the one a host limits to `objects:window:get`). */
function makeHome() {
  const home = realpathSync(mkdtempSync(path.join(tmpdir(), 'wsh-objects-rust-')));
  scratch.push(home);
  for (const name of ['default', 'getter']) execFileSync(WSH_BIN, ['keygen', name], { env: cleanEnv(home), stdio: 'ignore' });
  const pub = (name) => readFileSync(path.join(home, '.wsh', 'keys', `${name}.pub`), 'utf8').trim();
  return { home, pub: pub('default'), getterPub: pub('getter') };
}

/** A pipe relay that pairs the two halves of an id and copies bytes, recording them. */
async function copyingRelay() {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  const waiting = new Map();
  const seen = [];
  wss.on('connection', (ws, req) => {
    const u = new URL(req.url, 'ws://x');
    const id = u.pathname.split('/').pop();
    const other = waiting.get(id);
    if (!other) { waiting.set(id, ws); return; }
    waiting.delete(id);
    for (const [from, to] of [[ws, other], [other, ws]]) {
      from.on('message', (data, isBinary) => { seen.push(Buffer.from(data)); if (to.readyState === 1) to.send(data, { binary: isBinary }); });
      from.on('close', () => { if (to.readyState === 1) to.close(); });
    }
  });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  return { url: `ws://127.0.0.1:${wss.address().port}`, text: () => Buffer.concat(seen).toString('latin1') };
}

/** What the page has: an app with data, a method, an event source, a class whose instance is not plain data. */
function makeWorld() {
  const win = createFakeWindow();
  const listeners = new Map();
  const bus = {
    addEventListener(t, fn) { listeners.set(t, [...(listeners.get(t) ?? []), fn]); },
    removeEventListener(t, fn) { listeners.set(t, (listeners.get(t) ?? []).filter((f) => f !== fn)); },
    emit(t, detail) { for (const fn of listeners.get(t) ?? []) fn({ type: t, timeStamp: 5, isTrusted: false, detail }); },
    listening: (t) => (listeners.get(t) ?? []).length,
  };
  class Cart { constructor(owner = 'anon') { this.owner = owner; this.items = [{ sku: 'A1' }]; this.total = 3; this.secret = 'hidden'; } sum() { return this.total; } }
  const cart = new Cart();
  const app = {
    n: 1,
    title: 'Shop',
    blob: new Uint8Array([1, 2, 3]),
    when: new Date(0),
    nested: { a: { b: { c: 1 } }, '\u001b[2Jkey': 1, text: '\u001b]0;pwned\u0007‮\u009b2J' },
    secret: 'S3CRET',
    add(x) { this.n += x; return this.n; },
    fn() {},
    boom() { throw new Error('\u001b[31mboom'); },
    getCart: () => cart,
    Cart,
    bus,
    [MARKER]: `value-of-${MARKER}`,
  };
  win.app = app;
  win.localStorage = { getItem: () => 'x' };
  return { win, app, bus, cart };
}

const ALLOW = {
  get: ['app.n', 'app.title', 'app.blob', 'app.when', 'app.fn', 'app.nested.**', 'app.getCart().items', 'app.getCart().total', 'app.getCart().owner', 'app.getCart()', 'app.cart', MARKER_PATH()],
  call: ['app.add', 'app.getCart', 'app.boom', 'app.Cart', 'app.getCart().sum'],
  set: ['app.n'],
  on: ['app.bus@ping'],
};
function MARKER_PATH() { return `app.${MARKER}`; }

/**
 * A page host behind a recording relay, with `getter` limited to `objects:window:get`. `expose` is the host's own (default: values mode).
 * Returns the scratch HOME, the relay, and `wsh(args, opts)`: runs the real CLI sealed through the relay.
 */
async function pageHost({ expose, authorizedKeys, world = makeWorld() } = {}) {
  const h = makeHome();
  const relay = await copyingRelay();
  const host = await createPageHost({
    window: world.win, relay: relay.url, name: 'shop-tab',
    authorizedKeys: authorizedKeys ? authorizedKeys(h) : [h.pub, `capabilities="objects:window:get" ${h.getterPub}`],
    expose: expose ?? { window: { allow: ALLOW, eventFields: { ping: ['detail'] } } },
  });
  closers.push(() => host.close());
  return { h, relay, host, world, wsh: (args, opts) => runWsh(h, host.operatorUrl, args, opts), session: (opts) => startSession(h, host.operatorUrl, opts) };
}

const base = (via, extra = []) => ['--accept-new-host-key', '--via', via, ...extra];

/** `wsh --sealed --via <url> objects alice@tab.example ...args`; resolves when it exits. */
function runWsh(h, via, args, { sealed = true, identity, timeout = 60_000, input } = {}) {
  const argv = [...base(via, [...(sealed ? ['--sealed'] : []), ...(identity ? ['-i', identity] : [])]), 'objects', 'alice@tab.example', ...args];
  return new Promise((resolve, reject) => {
    const child = spawn(WSH_BIN, argv, { env: cleanEnv(h.home), stdio: ['pipe', 'pipe', 'pipe'] });
    const out = []; const err = [];
    child.stdout.on('data', (d) => out.push(d)); child.stderr.on('data', (d) => err.push(d));
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`wsh ${args.join(' ')} did not exit: ${Buffer.concat(err)}`)); }, timeout);
    child.once('close', (code) => { clearTimeout(timer); resolve({ code, stdoutBytes: Buffer.concat(out), stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }); });
    if (input !== undefined) child.stdin.end(input); else child.stdin.end();
  });
}
const lines = (r) => r.stdout.split('\n').filter(Boolean);
const json = (r) => JSON.parse(r.stdout);

/** A `session` process: write a request, read its answer line. */
function startSession(h, via, { identity } = {}) {
  const argv = [...base(via, ['--sealed', ...(identity ? ['-i', identity] : [])]), 'objects', 'alice@tab.example', 'session'];
  const child = spawn(WSH_BIN, argv, { env: cleanEnv(h.home), stdio: ['pipe', 'pipe', 'pipe'] });
  closers.push(async () => { child.kill('SIGKILL'); });
  let buf = ''; const answers = []; let stderr = '';
  child.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { answers.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); } });
  child.stderr.on('data', (d) => { stderr += d; });
  const ask = async (request) => {
    const before = answers.length;
    child.stdin.write(`${JSON.stringify(request)}\n`);
    await until(() => answers.length > before, `an answer to ${JSON.stringify(request)} (stderr: ${stderr})`);
    return answers[before];
  };
  return { ask, end: () => new Promise((r) => { child.once('close', (code) => r(code)); child.stdin.end(); }), stderr: () => stderr };
}

describe('wsh --sealed objects: values mode against a page host', () => {
  it('roots, get, set, call, snapshot and describe: JSON on stdout, the relay sees no path, value or method', async () => {
    const { relay, wsh, world } = await pageHost();
    const roots = await wsh(['roots']);
    assert.equal(roots.code, 0, roots.stderr);
    assert.deepEqual(json(roots).roots, ['window']);
    assert.deepEqual(json(roots).features.sort(), ['callbacks', 'events', 'types'], 'values mode: no handles stated');
    assert.match(roots.stderr, /session sealed end to end/);

    assert.equal((await wsh(['get', 'window.app.title'])).stdout, '"Shop"\n');
    assert.equal(json(await wsh(['call', 'window.app.add', '4'])), 5);
    assert.equal(world.app.n, 5, 'the call ran in the page');
    const set = await wsh(['set', 'window.app.n', '41']);
    assert.deepEqual(json(set), { ok: true });
    assert.equal(world.app.n, 41);
    assert.equal(json(await wsh(['get', 'window.app.n'])), 41);
    assert.deepEqual(json(await wsh(['get', 'window.app.nested.a'])), { b: { c: 1 } });

    const cut = await wsh(['snapshot', 'window.app.nested.a', '--depth', '1']);
    assert.equal(cut.code, 0, cut.stderr);
    assert.deepEqual(json(cut), { b: null });
    assert.match(cut.stderr, /snapshot was cut/);

    const d = json(await wsh(['describe', 'window.app']));
    const names = d.keys.map((k) => k.key);
    for (const n of ['n', 'title', 'add', 'nested']) assert.ok(names.includes(n), `${n} in ${names}`);
    assert.ok(!names.includes('secret'), 'a name no allow-list reaches is not told');

    const marked = await wsh(['get', `window.app.${MARKER}`]);
    assert.equal(json(marked), `value-of-${MARKER}`);
    const seen = relay.text();
    assert.ok(seen.length > 500);
    for (const word of [MARKER, 'S3CRET', 'resolve', 'snapshot', 'describe', 'window.app', 'Shop']) assert.ok(!seen.includes(word), `"${word}" crossed the relay in the clear`);
  });

  it('bytes are native, and what cannot be cloned is named, never interpreted', async () => {
    const { wsh } = await pageHost();
    assert.deepEqual(json(await wsh(['get', 'window.app.blob'])), { $bytes: 'AQID' });
    assert.deepEqual(json(await wsh(['get', 'window.app.when'])), { $nonValue: { kind: 'Date', text: '1970-01-01T00:00:00.000Z' } });
    assert.deepEqual(json(await wsh(['get', 'window.app.fn'])), { $nonValue: { kind: 'function', type: 'fn' } });
    const cart = await wsh(['call', 'window.app.getCart']);
    assert.deepEqual(json(cart), { $nonValue: { kind: 'object', type: 'Cart' } }, 'values mode: an instance is named, not a handle');
    const made = await wsh(['construct', 'window.app.Cart', '"bob"']);
    assert.deepEqual(json(made), { $nonValue: { kind: 'object', type: 'Cart' } });
  });

  it('text from the page never reaches the terminal raw: stdout and stderr carry every control as an escape', async () => {
    const { wsh } = await pageHost();
    const snap = await wsh(['snapshot', 'window.app.nested']);
    assert.equal(snap.code, 0, snap.stderr);
    const raw = snap.stdoutBytes;
    for (const b of raw.subarray(0, raw.length - 1)) assert.ok(b >= 0x20 && b !== 0x7f, `a raw control byte ${b} on stdout`);
    const text = snap.stdout;
    for (const c of ['\u001b', '\u0007', '\u009b', '‮']) assert.ok(!text.includes(c), `${JSON.stringify(c)} came through raw`);
    assert.match(text, /\\u001b\[2Jkey/, 'a key with an escape in its name');
    assert.match(text, /\\u001b\]0;pwned\\u0007\\u202e\\u009b2J/);
    assert.deepEqual(JSON.parse(text).text, '\u001b]0;pwned\u0007‮\u009b2J', 'and it is still the page\'s string, once parsed');
    // an error whose text is the page's
    const boom = await wsh(['call', 'window.app.boom']);
    assert.equal(boom.code, 1);
    assert.ok(!boom.stderr.includes('\u001b'), `an escape reached stderr: ${JSON.stringify(boom.stderr)}`);
    assert.match(boom.stderr, /threw/);
    assert.match(boom.stderr, /\\u001b\[31mboom/);
  });

  it('refuses what the host refuses, with exit 3 and the rule that spoke: always-refused names, an unnamed path, a name that needs listing', async () => {
    const world = makeWorld();
    const { wsh } = await pageHost({
      world,
      expose: {
        window: { allow: ALLOW },
        store: { object: { fetch: () => 'x', count: 2 }, allow: { get: ['**'] } },
      },
    });
    for (const name of ['__proto__', 'constructor', 'prototype', 'eval', 'Function', 'import']) {
      const r = await wsh(['get', `window.app.${name}`]);
      assert.equal(r.code, 3, `${name}: ${r.stderr}`);
      assert.match(r.stderr, /refused \(always-refused\)/, name);
    }
    const unnamed = await wsh(['get', 'window.app.secret']);
    assert.equal(unnamed.code, 3);
    assert.match(unnamed.stderr, /refused \(not-allowed\)/);
    assert.equal(unnamed.stdout, '');
    const listing = await wsh(['get', 'store.fetch']);
    assert.equal(listing.code, 3, listing.stderr);
    assert.match(listing.stderr, /refused \(needs-listing\)/);
    assert.equal(json(await wsh(['get', 'store.count'])), 2, 'a wildcard still reads what is not on the list of names that need listing');
    // set where no entry says so, and call where no entry says so
    assert.equal((await wsh(['set', 'window.app.title', '"x"'])).code, 3);
    assert.equal((await wsh(['call', 'window.app.fn'])).code, 3);
    assert.equal(world.app.title, 'Shop');
  });

  it('a root the host does not list is not found (exit 4) and a bad argument is a usage error (exit 2), nothing dialled', async () => {
    const { wsh, relay } = await pageHost();
    const nope = await wsh(['get', 'nowhere.x']);
    assert.equal(nope.code, 4, nope.stderr);
    assert.match(nope.stderr, /not-found \(no-such-root\)/);
    const missing = await wsh(['get', 'window.app.ghost']);
    assert.equal(missing.code, 3, 'a path no allow-list names is refused, not "not found": it does not tell what exists');
    const bad = await wsh(['call', 'window.app.add', '{nope']);
    assert.equal(bad.code, 2);
    assert.match(bad.stderr, /not JSON/);
    const empty = await wsh(['get', 'window..x']);
    assert.equal(empty.code, 2);
    assert.ok(relay.text().length > 0);
  });

  it('a key limited to objects:window:get may read and is refused call, set and construct, by its capability', async () => {
    const { wsh, world } = await pageHost();
    const read = await wsh(['get', 'window.app.n'], { identity: 'getter' });
    assert.equal(read.code, 0, read.stderr);
    assert.equal(json(read), 1);
    for (const args of [['call', 'window.app.add', '1'], ['set', 'window.app.n', '9'], ['construct', 'window.app.Cart']]) {
      const r = await wsh(args, { identity: 'getter' });
      assert.equal(r.code, 3, `${args[0]}: ${r.stderr}`);
      assert.match(r.stderr, /refused \(not-permitted\)/);
    }
    assert.equal(world.app.n, 1, 'nothing ran');
    // the same key through the default identity may call
    assert.equal(json(await wsh(['call', 'window.app.add', '1'])), 2);
  });

  it('refuses to start unsealed (exit 2) without dialling, and a host that offers no wsh-objects channel is unsupported (exit 5)', async () => {
    const { wsh, relay } = await pageHost();
    const before = relay.text().length;
    const unsealed = await wsh(['get', 'window.app.n'], { sealed: false });
    assert.equal(unsealed.code, 2);
    assert.match(unsealed.stderr, /needs --sealed/);
    assert.equal(relay.text().length, before, 'nothing was sent');
    // a page host that serves MCP only
    const world = makeWorld();
    const h = makeHome(); const r2 = await copyingRelay();
    const mcpOnly = await createPageHost({ window: world.win, relay: r2.url, name: 'only-mcp', authorizedKeys: [h.pub], mcp: { allow: ['x'] } });
    closers.push(() => mcpOnly.close());
    const none = await runWsh(h, mcpOnly.operatorUrl, ['roots']);
    assert.equal(none.code, 5, none.stderr);
    assert.match(none.stderr, /unsupported/);
    assert.match(none.stderr, /does not state the \\"wsh-objects\\" channel \(it offers: mcp\)/);
  });
});

describe('wsh --sealed objects watch: events from a page host', () => {
  it('prints one JSON line per event with the fields asked for, and --count ends it', async () => {
    const { wsh, world } = await pageHost();
    const watching = wsh(['watch', 'window.app.bus@ping', '--field', 'detail', '--count', '2']);
    await until(() => world.bus.listening('ping') === 1, 'the subscription on the page');
    world.bus.emit('ping', { n: 1 });
    world.bus.emit('ping', 'two');
    const r = await watching;
    assert.equal(r.code, 0, r.stderr);
    const got = lines(r).map((l) => JSON.parse(l));
    assert.deepEqual(got.map((e) => e.seq), [1, 2]);
    assert.deepEqual(got[0].data, { type: 'ping', timeStamp: 5, isTrusted: false, detail: { n: 1 } });
    assert.equal(got[1].data.detail, 'two');
    assert.deepEqual(got.map((e) => [e.dropped, e.dropped_here]), [[0, 0], [0, 0]]);
    await until(() => world.bus.listening('ping') === 0, 'the page to drop its listener when the watch ended');
  });

  it('a burst past the host\'s bounded queue is dropped and counted, and the count is told with the next event', async () => {
    const world = makeWorld();
    const { wsh } = await pageHost({ world, expose: { window: { allow: ALLOW, eventFields: { ping: ['detail'] }, limits: { maxQueuedEvents: 3 } } } });
    const watching = wsh(['watch', 'window.app.bus@ping', '--field', 'detail', '--count', '5']);
    await until(() => world.bus.listening('ping') === 1, 'the subscription on the page');
    // One synchronous burst: the first goes straight to the channel, the next three wait for it, the other six do not fit.
    for (let i = 1; i <= 10; i++) world.bus.emit('ping', i);
    await sleep(500); // the four that fit arrive; the page is asked for more only after
    world.bus.emit('ping', 'after');
    const r = await watching;
    assert.equal(r.code, 0, r.stderr);
    const got = lines(r).map((l) => JSON.parse(l));
    assert.deepEqual(got.map((e) => e.data.detail), [1, 2, 3, 4, 'after']);
    assert.deepEqual(got.map((e) => e.dropped), [0, 0, 0, 0, 6], 'the six lost are told with the event after them');
  });

  it('a source the allow-list does not name is refused (exit 3), and an event type it does not list too', async () => {
    const { wsh } = await pageHost();
    const other = await wsh(['watch', 'window.app.bus@other', '--count', '1']);
    assert.equal(other.code, 3, other.stderr);
    assert.match(other.stderr, /refused \(not-allowed\)/);
    const field = await wsh(['watch', 'window.app.bus@ping', '--field', 'secretField', '--count', '1']);
    assert.equal(field.code, 3, field.stderr);
    const notASource = await wsh(['watch', 'window.app.nested@ping', '--count', '1']);
    assert.notEqual(notASource.code, 0);
  });

  it('a key that may only get is refused events (not-permitted)', async () => {
    const { wsh } = await pageHost();
    const r = await wsh(['watch', 'window.app.bus@ping', '--count', '1'], { identity: 'getter' });
    assert.equal(r.code, 3, r.stderr);
    assert.match(r.stderr, /refused \(not-permitted\)/);
  });
});

describe('wsh --sealed objects session: handles', () => {
  const handlesHost = (limits) => pageHost({ expose: { window: { mode: 'handles', allow: ALLOW, ...(limits ? { limits } : {}) } } });

  it('a handle is used across calls, never widens the allow-list, and is released', async () => {
    const { session, world } = await handlesHost();
    const s = session();
    const roots = await s.ask({ op: 'roots' });
    assert.deepEqual(roots, { ok: true, result: { roots: ['window'] } });
    const made = await s.ask({ op: 'call', path: 'window.app.getCart' });
    assert.equal(made.ok, true, JSON.stringify(made));
    const { $handle } = made.result;
    assert.equal($handle.kind, 'object');
    assert.equal($handle.type, 'Cart');
    assert.equal($handle.id, 'h1');
    assert.deepEqual($handle.preview.slice().sort(), ['items', 'owner', 'total']);
    assert.ok(!JSON.stringify(made).includes('secret'), 'the preview names only what a get could walk to');
    // two operations through it
    assert.deepEqual(await s.ask({ op: 'get', handle: 'h1', path: 'total' }), { ok: true, result: 3 });
    assert.deepEqual(await s.ask({ op: 'call', handle: 'h1', path: 'sum' }), { ok: true, result: 3 });
    assert.deepEqual((await s.ask({ op: 'get', handle: 'h1', path: 'items' })).result, [{ sku: 'A1' }]);
    // it stands at its path: what that path does not allow stays refused through it
    const secret = await s.ask({ op: 'get', handle: 'h1', path: 'secret' });
    assert.equal(secret.ok, false);
    assert.deepEqual([secret.error.kind, secret.error.reason], ['refused', 'not-allowed']);
    assert.equal((await s.ask({ op: 'set', handle: 'h1', path: 'total', value: 9 })).error.reason, 'not-allowed');
    assert.equal(world.cart.total, 3);
    // release, and it is gone
    assert.deepEqual(await s.ask({ op: 'release', handle: 'h1' }), { ok: true, result: { ok: true } });
    const gone = await s.ask({ op: 'get', handle: 'h1', path: 'total' });
    assert.deepEqual([gone.ok, gone.error.kind], [false, 'invalid']);
    assert.equal(await s.end(), 0);
  });

  it('the host\'s table is bounded and evicts nothing; releasing gives a place back', async () => {
    const { session } = await handlesHost({ maxHandles: 2 });
    const s = session();
    const a = await s.ask({ op: 'call', path: 'window.app.getCart' });
    const b = await s.ask({ op: 'call', path: 'window.app.getCart' });
    assert.deepEqual([a.result.$handle.id, b.result.$handle.id], ['h1', 'h2']);
    const full = await s.ask({ op: 'call', path: 'window.app.getCart' });
    assert.deepEqual([full.ok, full.error.kind, full.error.reason], [false, 'limit', 'limit']);
    assert.equal((await s.ask({ op: 'get', handle: 'h1', path: 'total' })).result, 3, 'nothing was evicted');
    assert.equal((await s.ask({ op: 'release', handle: 'h1' })).ok, true);
    const again = await s.ask({ op: 'call', path: 'window.app.getCart' });
    assert.equal(again.ok, true, JSON.stringify(again));
    assert.equal(await s.end(), 0);
  });

  it('a one-shot call through a host with handles prints the handle by kind and type only (the id means nothing across processes)', async () => {
    const { wsh } = await handlesHost();
    const r = await wsh(['call', 'window.app.getCart']);
    assert.equal(r.code, 0, r.stderr);
    const { $handle } = json(r);
    assert.equal($handle.id, undefined);
    assert.deepEqual([$handle.kind, $handle.type], ['object', 'Cart']);
    assert.match((await wsh(['roots'])).stdout, /handles/);
  });

  it('a key that may only get cannot use a handle to call, and events are not offered through one', async () => {
    const { session } = await handlesHost();
    const s = session({ identity: 'getter' });
    // `getCart` is a call: the key may not make the handle at all
    const refused = await s.ask({ op: 'call', path: 'window.app.getCart' });
    assert.deepEqual([refused.ok, refused.error.reason], [false, 'not-permitted']);
    assert.equal(await s.end(), 0);
  });
});

describe('wsh --sealed objects against a host that does not state what is asked', () => {
  /** A released 0.47-style host: roots only (no `features`), and a `resolve` that answers a handle without ever having said it supports them. */
  async function oldHost() {
    const h = makeHome();
    const relay = await copyingRelay();
    const received = [];
    // One `accept` serves one connection: each call of `connect()` is a fresh rendezvous for one run of the CLI.
    const host = createMemoryHost({
      auth: { authorizedKeys: h.pub }, exec: async () => 0, hostKey: true, dataStreams: false, requireChannelBinding: true, sealSession: 'require',
      rpc: { 'wsh-objects': (channel) => {
        const on = (method, fn) => channel.onRequest(method, (p) => { received.push(method); return fn(p); });
        on('roots', () => ({ roots: ['window'] }));
        on('resolve', (p) => (p.ops[0].get === 'thing' ? { h: 'abc', kind: 'object' } : { v: 7 }));
        on('subscribe', () => ({ ok: true }));
      } },
    });
    closers.push(() => host.close());
    const connect = async () => {
      const id = newRendezvousId();
      const ws = new WsClient(`${relay.url}/r/${id}?role=host`);
      ws.on('error', () => {});
      closers.push(async () => ws.terminate());
      await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
      await host.accept(ws);
      return `${relay.url}/r/${id}`;
    };
    return { h, received, run: async (args) => runWsh(h, await connect(), args) };
  }

  it('a host that did not state events: watch is refused locally, by name (exit 5), and works for what it does state', async () => {
    const { run, received } = await oldHost();
    const roots = await run(['roots']);
    assert.equal(roots.code, 0, roots.stderr);
    assert.deepEqual(json(roots), { roots: ['window'], features: [] });
    assert.equal(json(await run(['get', 'window.x'])), 7);
    const watch = await run(['watch', 'window.bus@ping', '--count', '1']);
    assert.equal(watch.code, 5, watch.stderr);
    assert.match(watch.stderr, /unsupported/);
    assert.match(watch.stderr, /\\"events\\"/);
    assert.match(watch.stderr, /nothing was sent/);
    assert.equal(watch.stdout, '');
    assert.ok(!received.includes('subscribe'), `the host was asked for events: ${received}`);
    assert.deepEqual([...new Set(received)].sort(), ['resolve', 'roots']);
  });

  it('a handle from a host that did not state handles is refused (exit 5), never made into something', async () => {
    const { run } = await oldHost();
    const r = await run(['get', 'window.thing']);
    assert.equal(r.code, 5, r.stderr);
    assert.match(r.stderr, /handles/);
    assert.equal(r.stdout, '');
  });
});
