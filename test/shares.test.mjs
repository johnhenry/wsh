// test/shares.test.mjs -- the HOST half of operator-side shared folders (#159): `onShare(name, fs, who)` on createMemoryHost /
// createWshServer / createReverseHost, the `shares` feature, and what the host does with an operator that answers badly.
// The operator here is a scripted fake (a connected client whose transport answers ShareRequests by hand); the real CLI as the
// operator is test/rust/wsh-cli-share.test.mjs.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { generateKeyPair, exportPublicKeyRaw } from '@johnhenry/wsh';
import { MSG, shareOffer, shareReply } from '../src/messages.gen.mjs';
import { ShareError, SHARES_FEATURE } from '../src/shares.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

const attrOf = (type, size = 0, extra = {}) => ({ type, size, mode: 0o644, mtime_ms: 1_700_000_000_000, atime_ms: 1_700_000_000_000, ctime_ms: 1_700_000_000_000, nlink: 1, ino: 7, ...extra });

/** Connect a client to `host` and make it the operator: ShareRequests go to `answer(request, reply)`. */
async function operator(host, { offer = { shares: ['proj'], writable: ['proj'], maxInflight: 4, maxBytes: 65536 }, answer, keyPair, sendOffer = true } = {}) {
  const client = await host.connect({ username: 'alice', keyPair, timeout: 4000 });
  const t = client._transport;
  const original = t.onControl;
  const requests = [];
  let unanswered = 0;
  let peak = 0;
  const reply = (req, fields) => t.sendControl(shareReply({ requestId: req.request_id, ok: true, ...fields }));
  const fail = (req, errno, message) => t.sendControl(shareReply({ requestId: req.request_id, ok: false, errno, message }));
  t.onControl = (m) => {
    if (m.type === MSG.SHARE_REQUEST) {
      requests.push(m);
      unanswered += 1; peak = Math.max(peak, unanswered);
      Promise.resolve(answer?.(m, { reply: (f) => { unanswered -= 1; return reply(m, f); }, fail: (e, msg) => { unanswered -= 1; return fail(m, e, msg); } })).catch(() => {});
      return;
    }
    original?.(m);
  };
  if (sendOffer) await t.sendControl(shareOffer(offer));
  return { client, requests, peak: () => peak, reply, fail, send: (m) => t.sendControl(m) };
}

async function setup(hostOptions = {}) {
  const keyPair = await generateKeyPair(true);
  const raw = await exportPublicKeyRaw(keyPair.publicKey);
  const shares = [];
  const logs = [];
  const host = createMemoryHost({
    auth: { authorizedKeys: [raw] }, onLog: (l) => logs.push(l),
    onShare: (name, fs, who) => { shares.push({ name, fs, who }); },
    ...hostOptions,
  });
  const got = async (n = 1) => { for (let i = 0; i < 100 && shares.length < n; i += 1) await sleep(10); return shares; };
  return { keyPair, host, shares, got, logs };
}

describe('onShare: negotiation (#159)', () => {
  it('a host with onShare states `shares`; a host without it does not, and ignores an offer', async () => {
    const withIt = await setup();
    const c1 = await withIt.host.connect({ username: 'alice', keyPair: withIt.keyPair, timeout: 4000 });
    assert.ok(c1.hasFeature(SHARES_FEATURE));
    await c1.disconnect(); await withIt.host.close();

    const keyPair = await generateKeyPair(true);
    const without = createMemoryHost({ auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] } });
    const op = await operator(without, { keyPair });
    assert.equal(op.client.hasFeature(SHARES_FEATURE), false);
    await sleep(50);
    assert.deepEqual(op.requests, []);
    await op.client.disconnect(); await without.close();
  });

  it('createWshServer takes onShare too', async () => {
    const keyPair = await generateKeyPair(true);
    const seen = [];
    const server = createWshServer({ auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] }, onShare: (name) => seen.push(name) });
    const { port } = await server.listen();
    const { WshClient } = await import('@johnhenry/wsh');
    const client = new WshClient();
    try {
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair, transport: 'ws', timeout: 4000 });
      assert.ok(client.hasFeature(SHARES_FEATURE));
      await client._transport.sendControl(shareOffer({ shares: ['a', 'b'], maxInflight: 2, maxBytes: 8192 }));
      for (let i = 0; i < 100 && seen.length < 2; i += 1) await sleep(10);
      assert.deepEqual(seen, ['a', 'b']);
    } finally { await client.disconnect(); await server.close(); }
  });

  it('onShare must be a function', () => {
    assert.throws(() => createMemoryHost({ onShare: 'x' }), /onShare/);
    assert.throws(() => createWshServer({ onShare: {} }), /onShare/);
  });

  it('calls onShare once per share with the authenticated operator, and the share says whether it is writable', async () => {
    const { keyPair, host, got } = await setup();
    const op = await operator(host, { keyPair, offer: { shares: ['ro', 'rw'], writable: ['rw'], maxInflight: 4, maxBytes: 65536 } });
    const shares = await got(2);
    assert.deepEqual(shares.map((s) => [s.name, s.fs.writable]), [['ro', false], ['rw', true]]);
    assert.equal(shares[0].who.username, 'alice');
    assert.match(shares[0].who.fingerprint, /^[0-9a-f]{64}$/);
    await op.client.disconnect(); await host.close();
  });

  it('refuses an offer with bad names, too many shares, duplicates; a second offer changes nothing; nothing is asked before an offer', async () => {
    for (const shares of [['../x'], ['a b'], [''], ['ok', 'ok'], Array.from({ length: 17 }, (_, i) => `s${i}`), 'nope']) {
      const t = await setup();
      const op = await operator(t.host, { keyPair: t.keyPair, offer: { shares, maxInflight: 2, maxBytes: 8192 } });
      await sleep(60);
      assert.deepEqual(t.shares, [], `offer ${JSON.stringify(shares)} must be ignored`);
      await op.client.disconnect(); await t.host.close();
    }
    const t = await setup();
    const op = await operator(t.host, { keyPair: t.keyPair });
    await t.got(1);
    await op.send(shareOffer({ shares: ['other'], maxInflight: 2, maxBytes: 8192 }));
    await sleep(60);
    assert.deepEqual(t.shares.map((s) => s.name), ['proj']);
    await op.client.disconnect(); await t.host.close();
  });

  it('clamps what the offer says about its window and sizes', async () => {
    const { keyPair, host, got } = await setup();
    let inflightNow = 0; let peak = 0;
    const op = await operator(host, {
      keyPair, offer: { shares: ['proj'], maxInflight: 1_000_000, maxBytes: 4_000_000_000 },
      answer: async (req, { reply }) => { inflightNow += 1; peak = Math.max(peak, inflightNow); await sleep(5); inflightNow -= 1; await reply({ attr: attrOf('file') }); },
    });
    const [{ fs }] = await got();
    await Promise.all(Array.from({ length: 200 }, () => fs.stat('/a')));
    assert.ok(peak <= 64, `the host kept ${peak} requests in flight; the cap is 64`);
    assert.equal(fs.stats.requests, 200);
    await op.client.disconnect(); await host.close();
  });
});

describe('the host side of the file operations (#159)', () => {
  it('readdir carries attributes and follows pages; stat decodes attributes; the cursor must advance', async () => {
    const { keyPair, host, got } = await setup();
    const names = ['a', 'b', 'c', 'd', 'e'];
    const op = await operator(host, {
      keyPair,
      answer: async (req, { reply }) => {
        if (req.op === 'readdir') {
          const from = req.cursor ? names.indexOf(req.cursor) + 1 : 0;
          const page = names.slice(from, from + 2);
          await reply({ entries: page.map((n) => ({ name: n, ...attrOf(n === 'c' ? 'directory' : 'file', n.charCodeAt(0)) })), cursor: from + 2 < names.length ? page.at(-1) : undefined });
        } else await reply({ attr: attrOf('file', 5, { mode: 0o100644 }) });
      },
    });
    const [{ fs }] = await got();
    const list = await fs.readdir('/');
    assert.deepEqual(list.map((e) => e.name), names);
    assert.equal(list[2].type, 'directory');
    assert.equal(list[2].isDirectory(), true);
    assert.equal(list[0].size, 97);
    assert.equal(op.requests.filter((r) => r.op === 'readdir').length, 3, 'three pages, three messages: attributes did not cost a message per entry');
    const st = await fs.stat('/x');
    assert.equal(st.mode, 0o644, 'permission bits only');
    assert.equal(st.mtimeMs, 1_700_000_000_000);
    await op.client.disconnect(); await host.close();
  });

  it('a directory cursor that does not advance, a bad entry name, or a bad type is an error, not a loop or a throw in the embedder', async () => {
    for (const bad of [
      { entries: [{ name: 'a', ...attrOf('file') }], cursor: 'a' },
      { entries: [{ name: '../x', ...attrOf('file') }] },
      { entries: [{ name: 'a/b', ...attrOf('file') }] },
      { entries: [{ name: 'a', ...attrOf('fifo') }] },
      { entries: 'nope' },
    ]) {
      const { keyPair, host, got } = await setup();
      const op = await operator(host, { keyPair, answer: async (_req, { reply }) => reply(bad) });
      const [{ fs }] = await got();
      await assert.rejects(fs.readdir('/'), (e) => e instanceof ShareError && e.code === 'EIO', JSON.stringify(bad).slice(0, 60));
      await op.client.disconnect(); await host.close();
    }
  });

  it('a small file arrives with the open: one request, no handle, no close', async () => {
    const { keyPair, host, got } = await setup();
    const op = await operator(host, {
      keyPair,
      answer: async (req, { reply }) => reply({ attr: attrOf('file', 5), data: enc('hello'), eof: true }),
    });
    const [{ fs }] = await got();
    assert.equal(dec(await fs.readFile('/a.txt')), 'hello');
    assert.equal(op.requests.length, 1);
    assert.equal(op.requests[0].op, 'open');
    assert.deepEqual(op.requests[0].flags, ['read']);
    await op.client.disconnect(); await host.close();
  });

  it('a big file is read in the offered size and closed; a write is chunked to the offered size', async () => {
    const { keyPair, host, got } = await setup();
    const body = new Uint8Array(150_000).map((_, i) => i % 251);
    const stored = new Uint8Array(150_000);
    let nextHandle = 1;
    const op = await operator(host, {
      keyPair, offer: { shares: ['proj'], writable: ['proj'], maxInflight: 4, maxBytes: 65536 },
      answer: async (req, { reply }) => {
        if (req.op === 'open') return reply({ handle: nextHandle++, attr: attrOf('file', body.length) });
        if (req.op === 'read') { const d = body.subarray(req.offset, req.offset + req.length); return reply({ data: d, eof: req.offset + d.length >= body.length }); }
        if (req.op === 'write') { stored.set(req.data, req.offset); return reply({ written: req.data.length }); }
        return reply({});
      },
    });
    const [{ fs }] = await got();
    const read = await fs.readFile('/big');
    assert.deepEqual(read, body);
    assert.deepEqual(op.requests.map((r) => r.op), ['open', 'read', 'read', 'read', 'close']);
    assert.ok(op.requests.every((r) => r.op !== 'read' || r.length <= 65536));
    op.requests.length = 0;
    assert.equal(await fs.writeFile('/out', body), body.length);
    assert.deepEqual(stored, body);
    assert.deepEqual(op.requests.map((r) => r.op), ['open', 'write', 'write', 'write', 'close']);
    assert.deepEqual(op.requests[0].flags, ['write', 'create', 'trunc']);
    assert.ok(op.requests.every((r) => !r.data || r.data.length <= 65536));
    await op.client.disconnect(); await host.close();
  });

  it('an errno from the operator becomes a ShareError with that code; an unknown one is EIO; the message is made safe', async () => {
    const { keyPair, host, got } = await setup();
    const op = await operator(host, {
      keyPair,
      answer: async (req, { fail }) => fail(req.path === '/x' ? 'EROFS' : 'EWHATEVER', `line one\nline two ${'x'.repeat(500)}`),
    });
    const [{ fs }] = await got();
    await assert.rejects(fs.mkdir('/x'), (e) => e instanceof ShareError && e.code === 'EROFS' && e.errno === 'EROFS' && !e.message.includes('\n') && e.message.length < 300);
    await assert.rejects(fs.mkdir('/y'), (e) => e.code === 'EIO');
    await op.client.disconnect(); await host.close();
  });

  it('more data than the offer allows, a missing handle, and a nonsense write size are EIO', async () => {
    const { keyPair, host, got } = await setup();
    const op = await operator(host, {
      keyPair, offer: { shares: ['proj'], writable: ['proj'], maxInflight: 2, maxBytes: 4096 },
      answer: async (req, { reply }) => {
        if (req.op === 'read') return reply({ data: new Uint8Array(5000), eof: false });
        if (req.op === 'open') return reply({ attr: attrOf('file', 10) }); // no handle, no data
        if (req.op === 'write') return reply({ written: 999_999 });
        return reply({});
      },
    });
    const [{ fs }] = await got();
    await assert.rejects(fs.readFile('/a'), (e) => e.code === 'EIO');
    await assert.rejects(fs.writeFile('/a', new Uint8Array(10)), (e) => e.code === 'EIO');
    await op.client.disconnect(); await host.close();
  });

  it('an unanswered request times out, keeps its slot, and the window is never exceeded', async () => {
    // The deadline is a connection-config knob (`shareTimeoutMs`), not a public option: build the connection factory by hand.
    const t = await setup2(150);
    const op = await operator(t.host, { keyPair: t.keyPair, offer: { shares: ['proj'], maxInflight: 1, maxBytes: 8192 }, answer: async () => {} });
    const [{ fs }] = await t.got();
    const first = fs.stat('/a');
    const second = fs.stat('/b');
    await assert.rejects(first, /did not answer/);
    await assert.rejects(second, /did not answer/);
    assert.equal(op.requests.length, 1, 'the second request was never sent while the first held the only slot');
    await op.client.disconnect(); await t.host.close();
  });

  it('a late or unknown reply is ignored; a ShareRequest from the operator is ignored', async () => {
    const { keyPair, host, got, logs } = await setup();
    const op = await operator(host, { keyPair, answer: async (_req, { reply }) => reply({ attr: attrOf('file') }) });
    const [{ fs }] = await got();
    await op.send(shareReply({ requestId: 424242, ok: true, attr: attrOf('file') }));
    await op.send({ type: MSG.SHARE_REQUEST, request_id: 1, share: 'proj', op: 'stat', path: '/', flags: [], attr: {} });
    await fs.stat('/');
    assert.ok(logs.some((l) => /ignored a ShareRequest/.test(l)));
    await op.client.disconnect(); await host.close();
  });

  it('when the connection ends every pending call fails with EIO and the signal aborts', async () => {
    const { keyPair, host, got } = await setup();
    const op = await operator(host, { keyPair, answer: async () => {} });
    const [{ fs }] = await got();
    const pending = [fs.stat('/a'), fs.stat('/b')];
    await sleep(30);
    await op.client.disconnect();
    for (const p of pending) await assert.rejects(p, (e) => e.code === 'EIO');
    for (let i = 0; i < 100 && !fs.signal.aborted; i += 1) await sleep(10);
    assert.equal(fs.signal.aborted, true);
    await assert.rejects(fs.stat('/c'), (e) => e.code === 'EIO');
    await host.close();
  });

  it('a share is also an fs backend: operate / readWhole / writeWhole / writeAt work on top of the share operations', async () => {
    const { keyPair, host, got } = await setup();
    const files = new Map([['/a.txt', enc('hello')]]);
    let h = 1; const open = new Map();
    const op = await operator(host, {
      keyPair,
      answer: async (req, { reply, fail }) => {
        const path = `/${req.path ?? ''}`.replace('//', '/');
        if (req.op === 'readdir') return reply({ entries: [...files].map(([p, d]) => ({ name: p.slice(1), ...attrOf('file', d.length) })) });
        if (req.op === 'lstat' || req.op === 'stat') return files.has(path) ? reply({ attr: attrOf('file', files.get(path).length) }) : fail('ENOENT', 'no');
        if (req.op === 'open') {
          if (req.flags.includes('create') && !files.has(path)) files.set(path, new Uint8Array(0));
          if (!files.has(path)) return fail('ENOENT', 'no');
          if (req.flags.includes('trunc')) files.set(path, new Uint8Array(0));
          const d = files.get(path);
          if (req.flags.length === 1 && req.flags[0] === 'read' && req.length >= d.length) return reply({ attr: attrOf('file', d.length), data: d, eof: true });
          open.set(h, path); return reply({ handle: h++, attr: attrOf('file', d.length) });
        }
        if (req.op === 'write') { const p = open.get(req.handle); const cur = files.get(p); const next = new Uint8Array(Math.max(cur.length, req.offset + req.data.length)); next.set(cur); next.set(req.data, req.offset); files.set(p, next); return reply({ written: req.data.length }); }
        if (req.op === 'close') { open.delete(req.handle); return reply({}); }
        if (req.op === 'unlink') { files.delete(path); return reply({}); }
        return reply({});
      },
    });
    const [{ fs }] = await got();
    assert.deepEqual((await fs.operate('list', '/')).entries.map((e) => e.name), ['a.txt']);
    assert.equal(dec(await fs.readWhole('/a.txt')), 'hello');
    await fs.writeWhole('/b.txt', enc('bee'));
    assert.equal(dec(files.get('/b.txt')), 'bee');
    await fs.writeAt('/b.txt', enc('X'), 1);
    assert.equal(dec(files.get('/b.txt')), 'bXe');
    assert.equal((await fs.operate('stat', '/a.txt')).metadata.size, 5);
    await fs.operate('remove', '/b.txt');
    assert.equal(files.has('/b.txt'), false);
    await op.client.disconnect(); await host.close();
  });
});

/** A host whose share requests time out after `timeoutMs` (the connection config knob the tests use). */
async function setup2(timeoutMs) {
  const keyPair = await generateKeyPair(true);
  const raw = await exportPublicKeyRaw(keyPair.publicKey);
  const shares = [];
  const { createConnectionFactory } = await import('../src/server/connection.mjs');
  const { buildAuthorizer, authMethods } = await import('../src/server/auth.mjs');
  const { bindSocket } = await import('../src/server/socket.mjs');
  const { createSocketPair } = await import('@johnhenry/wsh/memory');
  const { WshClient } = await import('@johnhenry/wsh');
  const { WebSocketTransport } = await import('../src/transport-ws.mjs');
  const auth = { authorizedKeys: [raw] };
  const factory = createConnectionFactory({ authorize: await buildAuthorizer(auth), methods: authMethods(auth), onShare: (name, fs, who) => { shares.push({ name, fs, who }); }, shareTimeoutMs: timeoutMs });
  const open = new Set();
  class Sock {
    constructor() { const [c, s] = createSocketPair(); void bindSocket(s, Promise.resolve(factory), {}).then((h) => open.add(h)); return c; }
  }
  const host = {
    url: 'ws://memory.invalid/',
    async connect(credentials) {
      const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport({ WebSocket: Sock }), wt: () => { throw new Error('no'); } } });
      await client.connect('ws://memory.invalid/', { transport: 'ws', ...credentials });
      return client;
    },
    async close() { for (const h of open) h.close(); },
  };
  const got = async (n = 1) => { for (let i = 0; i < 100 && shares.length < n; i += 1) await sleep(10); return shares; };
  return { keyPair, host, got };
}

describe('ShareOffer.paths: the root path of each share, advisory (#164)', () => {
  const offerOf = (extra) => ({ shares: ['a', 'b'], writable: [], maxInflight: 4, maxBytes: 65536, ...extra });
  const rootsOf = async (offer) => {
    const t = await setup();
    const op = await operator(t.host, { keyPair: t.keyPair, offer });
    const shares = await t.got(offer.shares.length);
    const roots = shares.map((s) => s.fs.root);
    await op.client.disconnect(); await t.host.close();
    return roots;
  };

  it('the message builder carries `paths` when given and omits the key otherwise (an offer of 0.40.0 has no such key)', () => {
    assert.deepEqual(shareOffer(offerOf({ paths: ['/x', '/y'] })).paths, ['/x', '/y']);
    assert.equal('paths' in shareOffer(offerOf()), false);
  });

  it('fs.root is the path the operator offered, per share, and the share still works', async () => {
    assert.deepEqual(await rootsOf(offerOf({ paths: ['/home/me/proj', '/srv/out dir/x'] })), ['/home/me/proj', '/srv/out dir/x']);
  });

  it('an offer without `paths` (a peer of 0.40.0 / rust-v0.11.0) works: fs.root is undefined and the files are served', async () => {
    const { keyPair, host, got } = await setup();
    const op = await operator(host, { keyPair, offer: offerOf({ shares: ['proj'] }), answer: (req, { reply }) => reply({ attr: attrOf('file', 5) }) });
    const [{ fs }] = await got();
    assert.equal(fs.root, undefined);
    assert.equal('root' in fs && fs.root !== undefined, false);
    assert.equal((await fs.stat('/a')).size, 5);
    await op.client.disconnect(); await host.close();
  });

  it('anything invalid is ignored (undefined), never an error: wrong type, relative, NUL, too long, wrong length', async () => {
    const long = `/${'a'.repeat(4096)}`;
    const cases = [
      [['rel/path', '/ok'], [undefined, '/ok']],
      [['/ok', ''], ['/ok', undefined]],
      [['/a\0b', '/ok'], [undefined, '/ok']],
      [[long, `/${'a'.repeat(4095)}`], [undefined, `/${'a'.repeat(4095)}`]],
      [[5, null], [undefined, undefined]],
      [[['/x'], { a: 1 }], [undefined, undefined]],
      [['/only-one'], [undefined, undefined]],
      [['/a', '/b', '/c'], [undefined, undefined]],
      ['/not-an-array', [undefined, undefined]],
      [{ 0: '/a', 1: '/b' }, [undefined, undefined]],
    ];
    for (const [paths, want] of cases) assert.deepEqual(await rootsOf(offerOf({ paths })), want, JSON.stringify(paths).slice(0, 60));
  });

  it('the length bound is in bytes, not characters', async () => {
    const wide = `/${'é'.repeat(2048)}`; // 1 + 4096 bytes
    assert.deepEqual(await rootsOf(offerOf({ paths: [wide, '/é'] })), [undefined, '/é']);
  });

  it('fs.root is read-only data: the host cannot change what the share is', async () => {
    const { keyPair, host, got } = await setup();
    const op = await operator(host, { keyPair, offer: offerOf({ shares: ['proj'], paths: ['/real'] }) });
    const [{ fs }] = await got();
    assert.throws(() => { 'use strict'; fs.root = '/elsewhere'; }, TypeError);
    assert.equal(fs.root, '/real');
    await op.client.disconnect(); await host.close();
  });
});
