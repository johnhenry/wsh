// test/objects-capabilities.test.mjs -- `objects:ROOT[:OP]` key capabilities (#190): a key's capability list limits it to named roots and operations,
// enforced in `exposeObjects` through the handler context's `capabilities` / `permits`, intersected with the host's allow-lists.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH, RpcChannel, CborSequenceDecoder, cborEncode } from '@johnhenry/wsh';
import { exposeObjects, set } from '@johnhenry/wsh/objects';
import { parseCapabilityList, checkKeyRequest, parseKeyOptions } from '../src/key-options.mjs';

const rejects = (x, ...rest) => assert.rejects(Promise.resolve(x), ...rest);
const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

let keyPair; let keyLine;
before(async () => { keyPair = await generateKeyPair(true); keyLine = await exportPublicKeySSH(keyPair.publicKey); });

function world() {
  const win = { title: 'Shop', app: { n: 1, add(x) { this.n += x; return this.n; } } };
  const store = { count: 3, bump() { this.count++; return this.count; } };
  return { win, store };
}
const ALLOW = { get: ['window.title', 'window.app.**', 'store.**'], call: ['window.app.**', 'store.**'], set: ['window.title', 'store.count'] };

async function open(capLine, { extra = {} } = {}) {
  const w = world();
  const host = createMemoryHost({ auth: { authorizedKeys: capLine === null ? keyLine : `capabilities="${capLine}" ${keyLine}` }, rpc: { 'wsh-objects': exposeObjects({ roots: { window: w.win, store: w.store }, allow: ALLOW, ...extra }) } });
  closers.push(() => host.close());
  const client = await host.connect({ username: 'alice', keyPair });
  closers.push(() => client.disconnect());
  return { client, ...w };
}

describe('the grammar of objects:ROOT[:OP]', () => {
  it('parses a root, a root with one operation, and *; refuses what is malformed', () => {
    const ok = (...c) => parseCapabilityList(c);
    assert.equal(ok('objects:window').ok, true);
    assert.equal(ok('objects:window:get', 'objects:*:call', 'objects:store:set').ok, true);
    for (const bad of ['objects:', 'objects:window:fly', 'objects:win dow', 'objects:window:get:x', 'objects::get', 'objects:a.b', 'objects:__x y']) {
      const r = ok(bad);
      assert.equal(r.ok, false, bad);
      assert.match(r.code, /capability/);
    }
    assert.equal(parseKeyOptions('capabilities="objects:window:get"').ok ?? true, true);
  });

  it('checkKeyRequest: operation, root, walk, and the plain rpc:wsh-objects key', () => {
    const p = (list) => ({ ...parseKeyOptions(`capabilities="${list}"`).permissions });
    const ask = (list, root, op) => checkKeyRequest(p(list), { kind: 'objects', root, op });
    assert.equal(ask('objects:window:get', 'window', 'get'), null);
    assert.equal(ask('objects:window:get', 'window', 'walk'), null);
    assert.equal(ask('objects:window:get', 'window', 'call')?.code, 'capability-missing');
    assert.equal(ask('objects:window:get', 'store', 'get')?.code, 'capability-missing');
    assert.equal(ask('objects:window', 'window', 'set'), null);
    assert.equal(ask('objects:*:call', 'anything', 'call'), null);
    assert.equal(ask('objects:*:call', 'anything', 'get')?.code, 'capability-missing');
    assert.equal(ask('rpc:wsh-objects', 'window', 'set'), null, 'a key with only rpc:wsh-objects keeps today\'s behaviour');
    assert.equal(ask('exec', 'window', 'get')?.code, 'capability-missing');
    assert.equal(ask('rpc:wsh-objects,objects:store:get', 'window', 'get')?.code, 'capability-missing', 'once a key names roots, it is limited to them');
    const expired = { ...p('objects:window'), expires: 100 };
    assert.equal(checkKeyRequest(expired, { kind: 'objects', root: 'window', op: 'get' }, { now: 200 })?.code, 'key-expired');
  });
});

describe('enforced by exposeObjects', () => {
  it('a key with objects:window:get can open the channel without rpc:wsh-objects, reads, and is refused call and set and the other root', async () => {
    const { client, win, store } = await open('objects:window:get');
    const page = await client.openObjects();
    assert.deepEqual(Object.keys(page), ['window'], 'a root the key cannot use is not even listed');
    assert.equal(await page.window.title, 'Shop');
    await rejects(page.window.app.add(1), (e) => e.reason === 'not-permitted' && /call/.test(e.message));
    await rejects(set(page.window, 'title', 'x'), (e) => e.reason === 'not-permitted');
    assert.equal(win.title, 'Shop');
    assert.equal(win.app.n, 1);
    assert.equal(store.count, 3);
  });

  it('objects:store limits a key to that root, every operation; the window is refused', async () => {
    const { client, store } = await open('objects:store');
    const page = await client.openObjects();
    assert.deepEqual(Object.keys(page), ['store']);
    assert.equal(await page.store.bump(), 4);
    await set(page.store, 'count', 9);
    assert.equal(store.count, 9);
    // Even a hand-made request for the other root is refused.
    const ch = await client.openRpc('wsh-objects');
    await rejects(ch.request('resolve', { root: 'window', ops: [{ get: 'title' }] }), (e) => e.reason === 'not-permitted');
  });

  it('a key that can only call cannot read, but can walk to the function it may call', async () => {
    const { client, win } = await open('objects:window:call');
    const page = await client.openObjects();
    assert.equal(await page.window.app.add(2), 3);
    assert.equal(win.app.n, 3);
    await rejects(page.window.app.n, (e) => e.reason === 'not-permitted');
    await rejects(page.window.title, (e) => e.reason === 'not-permitted');
  });

  it('the capability intersects the host allow-lists: it never widens them', async () => {
    const { client } = await open('objects:window');
    const page = await client.openObjects();
    assert.equal(await page.window.title, 'Shop');
    await rejects(page.window.secret, (e) => e.reason === 'not-allowed');
    await rejects(set(page.window.app, 'n', 5), (e) => e.reason === 'not-allowed');
  });

  it('a key with only rpc:wsh-objects keeps today\'s behaviour: every root, every operation the lists allow', async () => {
    const { client } = await open('rpc:wsh-objects');
    const page = await client.openObjects();
    assert.deepEqual(Object.keys(page).sort(), ['store', 'window']);
    assert.equal(await page.store.bump(), 4);
    assert.equal(await page.window.title, 'Shop');
  });

  it('rpc:wsh-objects with objects:ROOT is limited to the roots named; a key with other capabilities cannot open the channel; a key with none is unlimited', async () => {
    const limited = await open('rpc:wsh-objects,objects:store:get');
    const page = await limited.client.openObjects();
    assert.deepEqual(Object.keys(page), ['store']);
    assert.equal(await page.store.count, 3);
    await rejects(page.store.bump(), (e) => e.reason === 'not-permitted');
    const other = await open('exec');
    await rejects(other.client.openObjects(), /capability/);
    const free = await open(null);
    assert.deepEqual(Object.keys(await free.client.openObjects()).sort(), ['store', 'window']);
  });

  it('expiry is honoured at call time: permits() is asked afresh for every operation', async () => {
    const w = world();
    let alive = true;
    const handler = exposeObjects({ roots: { window: w.win }, allow: ALLOW });
    const replies = [];
    const decoder = new CborSequenceDecoder();
    const channel = new RpcChannel({ write: (b) => { for (const m of decoder.feed(b)) replies.push(m); } });
    handler(channel, { user: 'a', fingerprint: 'ab', capabilities: ['objects:window'], permits: (req) => alive && req.kind === 'objects' });
    const ask = (id) => channel.feed(cborEncode({ jsonrpc: '2.0', id, method: 'resolve', params: { root: 'window', ops: [{ get: 'title' }] } }));
    ask(1);
    alive = false;
    ask(2);
    while (replies.length < 2) await new Promise((r) => setTimeout(r, 2));
    const by = Object.fromEntries(replies.map((r) => [r.id, r]));
    assert.equal(by[1].result.v, 'Shop');
    assert.equal(by[2].error.data.reason, 'not-permitted');
    await channel.close('done');
  });

  it('a transport that is not wsh gives no permit(): nothing is limited by capabilities there (its own authorize is the hook)', async () => {
    const { createDuplexPair } = await import('./helpers/duplex.mjs');
    const { createObjectsServer, createObjectsClient } = await import('@johnhenry/wsh/objects');
    const [c, s] = createDuplexPair();
    createObjectsServer({ roots: { window: world().win }, allow: ALLOW }).attach(s);
    assert.equal(await (await createObjectsClient(c)).window.title, 'Shop');
  });
});
