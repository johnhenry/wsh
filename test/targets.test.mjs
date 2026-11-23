// test/targets.test.mjs -- execution targets (#121): `Open.target`, `FileOp.target` and `OpenEndpoint.target`, the `targets` feature,
// `ListTargets` / `TargetList`, and a host that serves two targets, one of which a key may not use.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeyRaw, fingerprint, MSG, TARGETS_FEATURE, listTargets, open as openMsg, fileOp } from '@johnhenry/wsh';
import { openEndpoint as openEndpointMsg } from '../src/messages.mjs';

const dec = new TextDecoder();
const enc = new TextEncoder();

/** An exec backend that says where it ran: `<label>:<command>`, and what it was told about the target. */
function labelled(label, seen) {
  return async (command, io) => { seen?.push({ label, target: io.target, user: io.user }); await io.write(`${label}:${command}\n`); return 0; };
}

function memoryFs(label, calls) {
  const fail = (m) => Object.assign(new Error(m), { wsh: true });
  return {
    maxFileBytes: 1024,
    async operate(op, path, opts = {}) { calls?.push({ label, op, path, target: opts.target }); if (op === 'list') return { entries: [{ name: `${label}.txt`, size: 1, modified: 0, type: 'file' }], metadata: { path } }; throw fail(`${op} is not offered`); },
    async readWhole(path, opts = {}) { calls?.push({ label, op: 'download', path, target: opts?.target }); return enc.encode(`${label}:${path}`); },
    async writeWhole() {},
    async writeAt() {},
  };
}

describe('execution targets (#121)', () => {
  let alice; let bob; let carol; let aliceFp; let bobFp;
  before(async () => {
    [alice, bob, carol] = await Promise.all([generateKeyPair(true), generateKeyPair(true), generateKeyPair(true)]);
    aliceFp = await fingerprint(await exportPublicKeyRaw(alice.publicKey));
    bobFp = await fingerprint(await exportPublicKeyRaw(bob.publicKey));
  });

  const hosts = [];
  const clients = [];
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const h of hosts.splice(0)) await h.close();
  });
  async function keys() { return [await exportPublicKeyRaw(alice.publicKey), await exportPublicKeyRaw(bob.publicKey)]; }
  async function connect(host, who) {
    const c = await host.connect({ username: who === bob ? 'bob' : 'alice', keyPair: who });
    clients.push(c);
    return c;
  }
  const run = async (client, command, opts) => {
    const s = await client.openSession({ type: 'exec', command, ...opts });
    return new Promise((resolve) => { const out = []; s.onData = (d) => out.push(dec.decode(d)); s.onClose = () => resolve(out.join('')); });
  };

  /** web: alice and bob; db: bob only. */
  async function twoTargets(extra = {}) {
    const seen = [];
    const authCalls = [];
    const fsCalls = [];
    const host = createMemoryHost({
      auth: { authorizedKeys: await keys() },
      exec: labelled('default', seen),
      targets: {
        web: { description: 'the web container', authorize: (who, req) => { authCalls.push({ who, req }); return true; }, exec: labelled('web', seen), fs: memoryFs('web', fsCalls), endpoints: { echo: (d) => { d.readable.pipeTo(d.writable).catch(() => {}); } } },
        db: { description: 'the database VM', authorize: (who, req) => { authCalls.push({ who, req }); return who.fingerprint === bobFp; }, exec: labelled('db', seen), fs: memoryFs('db', fsCalls) },
      },
      ...extra,
    });
    hosts.push(host);
    return { host, seen, authCalls, fsCalls };
  }

  describe('a host with two targets', () => {
    it('advertises the targets feature, and a target runs on its own backend', async () => {
      const { host, seen } = await twoTargets();
      const c = await connect(host, bob);
      assert.equal(c.hasFeature(TARGETS_FEATURE), true);
      assert.equal(TARGETS_FEATURE, 'targets');
      assert.equal(await run(c, 'whoami', { target: 'web' }), 'web:whoami\n');
      assert.equal(await run(c, 'whoami', { target: 'db' }), 'db:whoami\n');
      assert.deepEqual(seen.map((s) => [s.label, s.target]), [['web', 'web'], ['db', 'db']], 'the callback is told which target it serves');
    });

    it('a key allowed on one target is refused on the other, in the same words as for a target that does not exist', async () => {
      const { host } = await twoTargets();
      const a = await connect(host, alice);
      assert.equal(await run(a, 'ok', { target: 'web' }), 'web:ok\n');
      const refused = await run(a, 'no', { target: 'db' }).then(() => null, (e) => e.message);
      const missing = await run(a, 'no', { target: 'nowhere' }).then(() => null, (e) => e.message);
      assert.match(refused, /no such target/);
      assert.equal(refused, missing, 'the answer does not reveal which targets exist');
    });

    it('ListTargets shows each key only the targets it may use, with descriptions and what it can do there', async () => {
      const { host } = await twoTargets();
      const a = await connect(host, alice);
      const b = await connect(host, bob);
      assert.deepEqual(await a.listTargets(), [{ name: 'web', description: 'the web container', capabilities: ['exec', 'file', 'endpoint'] }]);
      assert.deepEqual((await b.listTargets()).map((t) => t.name), ['web', 'db']);
      assert.deepEqual((await b.listTargets())[1], { name: 'db', description: 'the database VM', capabilities: ['exec', 'file'] });
    });

    it('authorize is given who is asking and what for (target and kind), for every operation', async () => {
      const { host, authCalls } = await twoTargets();
      const b = await connect(host, bob);
      await run(b, 'x', { target: 'db' });
      await b.fileOperation('list', '/', { target: 'db' });
      await b.listTargets();
      const kinds = authCalls.filter((c) => c.req.target === 'db').map((c) => c.req.kind);
      assert.deepEqual(kinds.slice(0, 2), ['exec', 'file']);
      assert.ok(kinds.includes('list'));
      assert.equal(authCalls[0].who.fingerprint, bobFp);
      assert.equal(authCalls[0].who.username, 'bob');
    });

    it('a target without a backend for the operation refuses it (it never falls back to the host default)', async () => {
      const host = createMemoryHost({ auth: { authorizedKeys: await keys() }, exec: labelled('default'), targets: { files: { fs: memoryFs('files') } } });
      hosts.push(host);
      const c = await connect(host, alice);
      await assert.rejects(c.openSession({ type: 'exec', command: 'x', target: 'files' }), /exec is not enabled/);
      await assert.rejects(c.openSession({ type: 'pty', target: 'files' }), /pty is not enabled/);
      assert.equal((await c.fileOperation('list', '/', { target: 'files' })).success, true);
    });

    it('file operations name their target: another target\'s files, and a refused target\'s, are not reachable', async () => {
      const { host, fsCalls } = await twoTargets();
      const a = await connect(host, alice);
      const web = await a.fileOperation('list', '/', { target: 'web' });
      assert.equal(web.success, true);
      assert.equal(web.entries[0].name, 'web.txt');
      const db = await a.fileOperation('list', '/', { target: 'db' });
      assert.equal(db.success, false);
      assert.match(db.error_message, /no such target/);
      assert.deepEqual(fsCalls.map((c) => c.label), ['web'], 'the refused target\'s backend was never called');
      assert.equal(fsCalls[0].target, 'web');
    });

    it('a download and an upload channel name their target too', async () => {
      const { host, fsCalls } = await twoTargets();
      const b = await connect(host, bob);
      const s = await b.openSession({ type: 'file', command: 'download:/etc/motd', target: 'db' }).catch((e) => e);
      assert.ok(!(s instanceof Error), s?.message);
      await new Promise((r) => setTimeout(r, 50));
      assert.deepEqual(fsCalls.filter((c) => c.op === 'download').map((c) => [c.label, c.target]), [['db', 'db']]);
    });

    it('endpoints are per target, and an endpoint of a refused target is refused', async () => {
      const { host } = await twoTargets();
      const a = await connect(host, alice);
      const d = await a.openEndpoint('echo', { target: 'web' });
      d.destroy();
      await assert.rejects(a.openEndpoint('echo', { target: 'db' }), /no such|refused|policy/i);
      await assert.rejects(a.openEndpoint('echo', { target: 'nowhere' }), /no such|refused|policy/i);
    });

    it('a pty is spawned by the target\'s own pty backend, which is told the target', async () => {
      const spawns = [];
      const pty = (label) => ({ shell: 'sh', spawn: (file, args, o) => { spawns.push({ label, target: o.target }); let exit; return { onData() {}, onExit: (cb) => { exit = cb; }, write() {}, resize() {}, kill: () => exit?.({ exitCode: 0 }) }; } });
      const host = createMemoryHost({ auth: { authorizedKeys: await keys() }, targets: { box: { pty: pty('box') } }, pty: pty('default') });
      hosts.push(host);
      const c = await connect(host, alice);
      await c.openSession({ type: 'pty', target: 'box' });
      await c.openSession({ type: 'pty' });
      assert.deepEqual(spawns, [{ label: 'box', target: 'box' }, { label: 'default', target: undefined }]);
    });
  });

  describe('without a target nothing changes', () => {
    it('an Open with no target runs on the host\'s own backend, with or without targets configured', async () => {
      const { host, seen } = await twoTargets();
      const c = await connect(host, alice);
      assert.equal(await run(c, 'plain'), 'default:plain\n');
      assert.equal(seen[0].target, undefined);
    });

    it('requireTarget refuses an Open, FileOp or OpenEndpoint that names none (and an rpc channel): the host itself is not a target', async () => {
      const { host } = await twoTargets({ requireTarget: true, endpoints: { top: (d) => d.destroy() }, rpc: { demo: () => {} }, fs: memoryFs('default') });
      const c = await connect(host, bob);
      await assert.rejects(c.openSession({ type: 'exec', command: 'x' }), /a target is required/);
      assert.equal((await c.fileOperation('list', '/')).success, false);
      await assert.rejects(c.openEndpoint('top'), /target is required|refused|no such/i);
      await assert.rejects(c.openSession({ type: 'rpc', protocol: 'demo' }), /target is required|not enabled|not supported/i);
      assert.equal(await run(c, 'x', { target: 'web' }), 'web:x\n');
    });

    it('a host without targets does not advertise the feature, and the client refuses to send a target to it', async () => {
      const host = createMemoryHost({ auth: { authorizedKeys: await keys() }, exec: labelled('default'), endpoints: { echo: (d) => d.destroy() } });
      hosts.push(host);
      const c = await connect(host, alice);
      assert.equal(c.hasFeature(TARGETS_FEATURE), false);
      await assert.rejects(c.openSession({ type: 'exec', command: 'x', target: 'web' }), /does not advertise "targets"/);
      await assert.rejects(c.fileOperation('list', '/', { target: 'web' }), /does not advertise "targets"/);
      await assert.rejects(c.openEndpoint('echo', { target: 'web' }), /advertise "targets"/);
      await assert.rejects(c.listTargets(), /does not advertise "targets"/);
    });

    it('a client that sends one anyway is refused, never served from the default (raw messages)', async () => {
      const host = createMemoryHost({ auth: { authorizedKeys: await keys() }, exec: labelled('default'), fs: memoryFs('default'), endpoints: { echo: (d) => d.destroy() } });
      hosts.push(host);
      const c = await connect(host, alice);
      const got = [];
      c.addControlListener((m) => got.push(m));
      const until = async (pred) => { for (let i = 0; i < 100; i += 1) { const m = got.find(pred); if (m) return m; await new Promise((r) => setTimeout(r, 10)); } throw new Error('no reply'); };
      await c._transport.sendControl(openMsg({ kind: 'exec', command: 'x', target: 'web' }));
      assert.match((await until((m) => m.type === MSG.OPEN_FAIL)).reason, /no targets/);
      await c._transport.sendControl(fileOp({ channelId: 77, op: 'list', path: '/', target: 'web' }));
      assert.equal((await until((m) => m.type === MSG.FILE_RESULT && m.channel_id === 77)).success, false);
      await c._transport.sendControl(openEndpointMsg({ gatewayId: 5, name: 'echo', target: 'web' }));
      assert.equal((await until((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 5)).code, 4);
      await c._transport.sendControl(listTargets());
      assert.equal((await until((m) => m.type === MSG.ERROR)).code, 3);
    });

    it('a target that is not a plain name is refused like an unknown one', async () => {
      const { host } = await twoTargets();
      const c = await connect(host, alice);
      const got = [];
      c.addControlListener((m) => got.push(m));
      for (const bad of [42, '', 'web/../db', 'a'.repeat(200), '__proto__', 'constructor']) {
        got.length = 0;
        await c._transport.sendControl(openMsg({ kind: 'exec', command: 'x', target: bad }));
        for (let i = 0; i < 100 && !got.some((m) => m.type === MSG.OPEN_FAIL); i += 1) await new Promise((r) => setTimeout(r, 10));
        assert.match(got.find((m) => m.type === MSG.OPEN_FAIL)?.reason ?? 'none', /no such target/, JSON.stringify(bad));
      }
    });
  });

  describe('options', () => {
    it('are validated', () => {
      assert.throws(() => createMemoryHost({ targets: [] }), /targets must be an object/);
      assert.throws(() => createMemoryHost({ targets: { 'bad name': {} } }), /not a valid target name/);
      assert.throws(() => createMemoryHost({ targets: { web: { authorize: 'yes' } } }), /authorize must be a function/);
      assert.throws(() => createMemoryHost({ targets: { web: { description: 7 } } }), /description must be a string/);
      assert.throws(() => createMemoryHost({ targets: { web: { exec: true } } }), /exec/);
      assert.throws(() => createMemoryHost({ requireTarget: true }), /requireTarget needs targets/);
      assert.throws(() => createMemoryHost({ targets: { web: {} }, requireTarget: 'yes' }), /requireTarget must be a boolean/);
    });

    it('createWshServer takes them too, with the Node backends (exec: true runs a shell per target)', async () => {
      const server = createWshServer({
        auth: { authorizedKeys: await keys() },
        targets: { shell: { description: 'a shell', exec: true }, noop: { authorize: () => false } },
      });
      const { port } = await server.listen();
      try {
        const c = new WshClient();
        clients.push(c);
        await c.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair: alice });
        assert.deepEqual((await c.listTargets()).map((t) => t.name), ['shell']);
        assert.match(await run(c, 'echo from-shell', { target: 'shell' }), /from-shell/);
        await assert.rejects(c.openSession({ type: 'exec', command: 'echo no', target: 'noop' }), /no such target/);
        await assert.rejects(c.openSession({ type: 'exec', command: 'echo no' }), /exec is not enabled/);
      } finally { await server.close(); }
    });

    it('createReverseHost does not take them (it would silently ignore them)', async () => {
      const { createReverseHost } = await import('@johnhenry/wsh/server');
      assert.throws(() => createReverseHost({ url: 'ws://127.0.0.1:1', username: 'h', keyPair: alice, targets: { a: {} } }), /targets/);
    });
  });
});
