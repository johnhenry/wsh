// The caller's identity in the object layer is transport-neutral (#220): `who` is `{ username, fingerprint, podId? }`, and a transport that is
// not wsh (a mesh adapter over `createDuplexPeer`) hands it over as an identity object instead of putting a pod id in a field named
// `fingerprint`. The wsh path keeps the shape it always had. Capability checks (`permit`) are asked per operation, `on` as `on`.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createObjectsServer, createObjectsClient, createDuplexPeer, get, call, on, ObjectsError } from '@johnhenry/wsh/objects';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { exposeObjects } from '@johnhenry/wsh/objects';
import { generateKeyPair, exportPublicKeyRaw, exportPublicKeySSH, fingerprint, podId } from '@johnhenry/wsh';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c(); });
const rejects = (p, ...rest) => assert.rejects(Promise.resolve(p), ...rest);

const FP = 'ab'.repeat(32);
let POD;
async function podOf(fp) { const { fingerprintToPodId } = await import('@johnhenry/wsh'); return fingerprintToPodId(fp); }

/** A server peer and a client peer joined in memory; the server side is described by `serverPeer` options (its `who`, `permit`). */
function pair(serverPeerOptions = {}) {
  let c; let s;
  c = createDuplexPeer({ send: (m) => { const copy = structuredClone(m); queueMicrotask(() => s.receive(copy)); } });
  s = createDuplexPeer({ ...serverPeerOptions, send: (m) => { const copy = structuredClone(m); queueMicrotask(() => c.receive(copy)); } });
  closers.push(async () => { c.close(); s.close(); });
  return [c, s];
}

function world() {
  const bus = new EventTarget();
  const win = { title: 'Shop', n: 1, add(x) { win.n += x; return win.n; }, bus };
  return win;
}

describe('an identity object given to createDuplexPeer reaches authorize(who, op)', () => {
  it('a pod id alone: the hex fingerprint is derived, and the pod id is kept', async () => {
    POD = await podOf(FP);
    const asked = [];
    const [c, s] = pair({ who: { username: 'peer-1', podId: POD } });
    createObjectsServer({ roots: { window: world() }, allow: { get: ['window.title'] }, authorize: (who, op) => { asked.push({ who, kind: op.kind }); return true; } }).attach(s);
    const page = await createObjectsClient(c);
    assert.equal(await page.window.title, 'Shop');
    assert.deepEqual(asked, [{ who: { username: 'peer-1', fingerprint: FP, podId: POD }, kind: 'get' }]);
  });

  it('a fingerprint alone keeps the shape the wsh path always had: { username, fingerprint }, with no podId added', async () => {
    const asked = [];
    const [c, s] = pair({ who: { username: 'alice', fingerprint: FP } });
    createObjectsServer({ roots: { window: world() }, allow: { get: ['window.title'] }, authorize: (who) => { asked.push(who); return true; } }).attach(s);
    await (await createObjectsClient(c)).window.title;
    assert.deepEqual(asked, [{ username: 'alice', fingerprint: FP }]);
  });

  it('attach(peer, { who }) takes the same identity object, and an old-style who with a short fingerprint still works', async () => {
    POD = await podOf(FP);
    const asked = [];
    const [c, s] = pair();
    createObjectsServer({ roots: { window: world() }, allow: { get: ['window.title'] }, authorize: (who) => { asked.push(who); return true; } }).attach(s, { who: { podId: POD } });
    await (await createObjectsClient(c)).window.title;
    assert.deepEqual(asked, [{ username: null, fingerprint: FP, podId: POD }]);
    const [c2, s2] = pair();
    createObjectsServer({ roots: { window: world() }, allow: { get: ['window.title'] }, authorize: (who) => { asked.push(who); return true; } }).attach(s2, { who: { username: 'alice', fingerprint: 'ab' } });
    await (await createObjectsClient(c2)).window.title;
    assert.deepEqual(asked[1], { username: 'alice', fingerprint: 'ab' });
  });

  it('an identity that names two different keys is refused when it is given, not when a call arrives', async () => {
    POD = await podOf(FP);
    assert.throws(() => createDuplexPeer({ send() {}, who: { fingerprint: '11'.repeat(32), podId: POD } }), TypeError);
    assert.throws(() => createDuplexPeer({ send() {}, who: { podId: 'not-a-pod-id' } }), TypeError);
    assert.throws(() => createDuplexPeer({ send() {}, who: 'alice' }), TypeError);
    const [, s] = pair();
    const server = createObjectsServer({ roots: { window: world() }, allow: {} });
    assert.throws(() => server.attach(s, { who: { fingerprint: '11'.repeat(32), podId: POD } }), TypeError);
  });

  it('a request that carries its own identity wins over the peer\'s (a transport that multiplexes callers)', async () => {
    const asked = [];
    const [c, s] = pair({ who: { username: 'default', fingerprint: FP } });
    const onRequest = s.onRequest.bind(s);
    // an adapter can wrap the handlers it registers and add `who` to the context of each call
    s.onRequest = (method, handler) => onRequest(method, (params, ctx) => handler(params, { ...ctx, who: { username: 'other', fingerprint: '22'.repeat(32) } }));
    createObjectsServer({ roots: { window: world() }, allow: { get: ['window.title'] }, authorize: (who) => { asked.push(who); return true; } }).attach(s);
    await (await createObjectsClient(c)).window.title;
    assert.deepEqual(asked, [{ username: 'other', fingerprint: '22'.repeat(32) }]);
  });
});

describe('capability checks over a bare duplex: createDuplexPeer({ permit })', () => {
  const ALLOW = { get: ['window.title', 'window.bus'], call: ['window.add', 'window.bus.**'], set: ['window.title'], on: ['window.bus@ping'] };
  const open = async (permitted) => {
    const asks = [];
    const [c, s] = pair({ permit: (root, op) => { asks.push(`${root}:${op}`); return permitted(root, op); } });
    createObjectsServer({ roots: { window: world() }, allow: ALLOW }).attach(s);
    return { page: await createObjectsClient(c), asks };
  };

  it('is asked per operation, afresh, with the operation as the page names it: get, call, set and on', async () => {
    const { page, asks } = await open(() => true);
    assert.equal(await page.window.title, 'Shop');
    assert.equal(await page.window.add(2), 3);
    const off = await on(page.window.bus, 'ping', () => {});
    await off();
    assert.ok(asks.includes('window:get'));
    assert.ok(asks.includes('window:call'));
    assert.ok(asks.includes('window:on'), `an event subscription needs on, not get: ${asks.join(', ')}`);
  });

  it('refuses what the permit refuses, whatever the allow-list says, and says it is the key\'s capabilities', async () => {
    const { page } = await open((root, op) => op === 'get' || op === 'walk');
    assert.equal(await page.window.title, 'Shop');
    await rejects(page.window.add(2), (e) => e instanceof ObjectsError && e.reason === 'not-permitted' && /capabilities/.test(e.message));
    await rejects(on(page.window.bus, 'ping', () => {}), (e) => e.reason === 'not-permitted');
  });

  it('an `on` capability is not a `get` capability: a key with objects:window:on may subscribe and not read', async () => {
    const { permits } = await import('@johnhenry/wsh/capabilities');
    const caps = ['objects:window:on'];
    const { page } = await open((root, op) => permits(caps, { kind: 'objects', root, op }));
    const off = await on(page.window.bus, 'ping', () => {});
    await off();
    await rejects(page.window.title, (e) => e.reason === 'not-permitted');
  });

  it('a permit that throws or answers anything but true refuses (fail closed)', async () => {
    for (const answer of [() => { throw new Error('boom'); }, () => 'yes', () => 1, () => undefined]) {
      const { page } = await open(answer);
      assert.deepEqual(Object.keys(page), [], `no root is listed to a key whose permit says ${String(answer)}`);
    }
    // and a permit that answers true for listing but throws for an operation refuses that operation, by name
    let listed = false;
    const [c, s] = pair({ permit: (root, op) => { if (op === 'walk') { listed = true; return true; } throw new Error('boom'); } });
    createObjectsServer({ roots: { window: world() }, allow: ALLOW }).attach(s);
    const page = await createObjectsClient(c);
    assert.ok(listed);
    await rejects(page.window.title, (e) => e instanceof ObjectsError && e.reason === 'not-permitted');
  });

  it('the roots a key may not use are not listed to it', async () => {
    const [c, s] = pair({ permit: (root) => root === 'window' });
    createObjectsServer({ roots: { window: world(), vault: { secret: 1 } }, allow: { get: ['window.title', 'vault.secret'] } }).attach(s);
    const page = await createObjectsClient(c);
    assert.deepEqual(Object.keys(page), ['window']);
  });
});

describe('over wsh the caller is the key, and a handler served by an adapter may be given an identity object', () => {
  it('exposeObjects: wsh callers are { username, fingerprint }; a handler called with ctx.who (an adapter) is given the pod id too', async () => {
    const asked = [];
    const handler = exposeObjects({ roots: { window: world() }, allow: { get: ['window.title'] }, authorize: (who) => { asked.push(who); return true; } });
    const keyPair = await generateKeyPair(true);
    const host = createMemoryHost({ auth: { authorizedKeys: await exportPublicKeySSH(keyPair.publicKey) }, rpc: { 'wsh-objects': handler } });
    closers.push(() => host.close());
    const client = await host.connect({ username: 'alice', keyPair });
    closers.push(() => client.disconnect());
    await (await createObjectsClient(await client.openRpc('wsh-objects'))).window.title;
    const fp = await fingerprint(await exportPublicKeyRaw(keyPair.publicKey));
    assert.deepEqual(asked[0], { username: 'alice', fingerprint: fp });
    assert.equal(asked[0].podId, undefined);

    // the same handler, called as a mesh adapter would call it: a channel-shaped peer and an identity object
    const [c, s] = pair();
    handler(s, { who: { username: 'mesh', podId: await podId(await exportPublicKeyRaw(keyPair.publicKey)) } });
    await (await createObjectsClient(c)).window.title;
    assert.equal(asked[1].fingerprint, fp, 'the fingerprint is derived from the pod id');
    assert.equal(asked[1].podId, await podId(await exportPublicKeyRaw(keyPair.publicKey)));
    assert.equal(asked[1].username, 'mesh');
  });
});
