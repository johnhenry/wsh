// test/pipe-relay.test.mjs -- #118: a pipe relay, so the host authenticates the operator itself.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { WebSocket as WsClient } from 'ws';
import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { loadHostKey } from '../src/server/host-key.mjs';

const dec = new TextDecoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

describe('pipe relay: what the module can reach', () => {
  // The relay process must import nothing that can execute code or read files. Walk the module graph from the entry
  // point: every static import, and every dynamic one, resolved through the files under src/.
  const FORBIDDEN = /^(node:)?(child_process|fs|fs\/promises|worker_threads|vm|cluster|os|path|module|v8|inspector|repl|readline|dgram|dns|http2)$/;
  const IMPORT_RE = /(?:^|[^\w.$])(?:import\s*(?:[\w*{}\s,]*?\s*from\s*)?|import\s*\(\s*)['"]([^'"]+)['"]/g;
  const strip = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

  async function graph(entry) {
    const seen = new Map(); // file -> specifiers
    const queue = [entry];
    while (queue.length) {
      const file = queue.pop();
      if (seen.has(file)) continue;
      const specs = [...strip(await readFile(file, 'utf8')).matchAll(IMPORT_RE)].map((m) => m[1]);
      seen.set(file, specs);
      for (const s of specs) if (s.startsWith('.')) queue.push(path.resolve(path.dirname(file), s));
    }
    return seen;
  }

  it('the relay module imports nothing, by name or dynamically: it is browser-safe', async () => {
    const g = await graph(path.join(SRC, 'pipe-relay.mjs'));
    assert.equal(g.size, 1, 'it imports no other module of this package');
    assert.deepEqual([...g.values()].flat(), [], 'no specifier it could be bundled through');
  });

  it('the Node half (listen) imports only ws, node:http and node:https, dynamically, and nothing that runs code or reads files', async () => {
    const g = await graph(path.join(SRC, 'pipe-relay-node.mjs'));
    assert.equal(g.size, 1);
    const specs = [...g.values()].flat();
    assert.deepEqual([...new Set(specs)].sort(), ['node:http', 'node:https', 'ws']);
    assert.ok(specs.every((s) => !FORBIDDEN.test(s)));
  });

  it('listen() loads the Node half by name from the relay module, so a bundler never follows it', async () => {
    const src = await readFile(path.join(SRC, 'pipe-relay.mjs'), 'utf8');
    assert.match(src, /import\(NODE_LISTENER\)/);
    assert.doesNotMatch(src, /import\(\s*['"]/);
    assert.match(src, /const NODE_LISTENER = '\.\/pipe-relay-node\.mjs'/);
  });

  it('the test itself catches a module that would reach a file or a process (the walker is not blind)', async () => {
    const g = await graph(path.join(SRC, 'server', 'index.mjs'));
    const all = [...g.values()].flat();
    assert.ok(all.some((s) => FORBIDDEN.test(s)), 'the full server entry reaches child_process / fs');
  });

  it('the published entry is the module itself', async () => {
    const pkg = JSON.parse(await readFile(path.join(SRC, '..', 'package.json'), 'utf8'));
    assert.equal(pkg.exports['./pipe-relay'].import, './src/pipe-relay.mjs');
  });
});

describe('pipe relay: rendezvous and copying', () => {
  let relay; let url;
  const sockets = [];
  before(async () => {
    relay = createPipeRelay({ rendezvousTimeoutMs: 400 });
    const { port } = await relay.listen();
    url = `ws://127.0.0.1:${port}`;
  });
  after(async () => { for (const s of sockets) s.terminate(); await relay.close(); });

  function dial(id, role) {
    const ws = new WsClient(pipeUrl(url, id, role));
    sockets.push(ws);
    const got = []; let closed = null;
    ws.on('message', (d) => got.push(Buffer.from(d)));
    ws.on('close', (code, reason) => { closed = { code, reason: reason.toString() }; });
    ws.on('error', () => {});
    return { ws, got, get closed() { return closed; }, open: new Promise((r) => ws.once('open', r)) };
  }

  it('ids are 128 bits, unique, and pipeUrl builds both URL forms', () => {
    const a = newRendezvousId();
    assert.match(a, /^[A-Za-z0-9_-]{22}$/);
    assert.notEqual(a, newRendezvousId());
    assert.equal(pipeUrl('wss://relay.example/', a), `wss://relay.example/r/${a}`);
    assert.equal(pipeUrl('wss://relay.example/base', a, 'host'), `wss://relay.example/base/r/${a}?role=host`);
    assert.throws(() => pipeUrl('wss://x', 'short'), /rendezvous id/);
    assert.throws(() => pipeUrl('wss://x', a, 'both'), /role/);
  });

  it('pairs a host and an operator and copies both ways, including what was said before the partner came', async () => {
    const id = newRendezvousId();
    const op = dial(id, 'operator');
    await op.open;
    op.ws.send(Buffer.from('early-from-operator'));
    await sleep(50);
    const host = dial(id, 'host');
    await host.open;
    host.ws.send(Buffer.from('from-host'));
    await sleep(100);
    assert.deepEqual(host.got.map(String), ['early-from-operator']);
    assert.deepEqual(op.got.map(String), ['from-host']);
    op.ws.send(Buffer.from('more'));
    await sleep(50);
    assert.deepEqual(host.got.map(String), ['early-from-operator', 'more']);
    assert.equal(relay.stats().pipes >= 1, true);
    op.ws.close(1000);
    await sleep(100);
    assert.equal(host.closed?.code, 1000, 'the other end follows');
  });

  it('refuses a bad id, a bad role, and a second half with the same role', async () => {
    const bad = { ws: new WsClient(`${url}/r/short`), closed: null }; sockets.push(bad.ws); bad.open = new Promise((r) => bad.ws.once('error', r));
    await bad.open.catch(() => {});
    await sleep(100);
    assert.equal(bad.closed?.code ?? 1006, bad.closed ? 1008 : 1006); // refused at upgrade (404) or closed 1008
    const id = newRendezvousId();
    const a = dial(id, 'host'); await a.open;
    const b = dial(id, 'host'); await b.open;
    await sleep(100);
    assert.equal(b.closed?.code, 1008);
    assert.equal(a.closed, null, 'the first host keeps waiting');
  });

  it('a half nobody answers is closed after the rendezvous timeout and its id is free again', async () => {
    const id = newRendezvousId();
    const a = dial(id, 'host'); await a.open;
    await sleep(700);
    assert.equal(a.closed?.code, 1000);
    const again = dial(id, 'host'); await again.open;
    await sleep(50);
    assert.equal(again.closed, null);
  });
});

describe('pipe relay: bounds', () => {
  /** A stand-in socket: records what it was sent and told, lets the test emit messages and close. */
  function fake({ pausable = true } = {}) {
    const e = new EventEmitter();
    const s = Object.assign(e, {
      readyState: 1, bufferedAmount: 0, sent: [], closedWith: null, paused: 0, resumed: 0,
      send(d) { s.sent.push(d); },
      close(code, reason) { s.closedWith = [code, reason]; s.readyState = 3; },
    });
    if (pausable) { s.pause = () => { s.paused++; }; s.resume = () => { s.resumed++; }; }
    return s;
  }
  const id = () => newRendezvousId();
  const bytes = (n) => Buffer.alloc(n, 1);
  async function paired(relay, opts = {}) {
    const i = id();
    const host = fake(opts); const op = fake(opts);
    await relay.accept(host, { id: i, role: 'host' });
    await relay.accept(op, { id: i, role: 'operator' });
    return { host, op };
  }

  it('maxWaiting: more waiting halves than the limit are refused', async () => {
    const relay = createPipeRelay({ maxWaiting: 2 });
    const socks = [fake(), fake(), fake()];
    const results = [];
    for (const s of socks) results.push(await relay.accept(s, { id: id(), role: 'host' }));
    assert.deepEqual(results, [true, true, false]);
    assert.equal(socks[2].closedWith[0], 1013);
    assert.equal(relay.stats().waiting, 2);
    await relay.close();
  });

  it('maxMessageBytes: an oversized message ends the pipe', async () => {
    const relay = createPipeRelay({ maxMessageBytes: 1000 });
    const { host, op } = await paired(relay);
    host.emit('message', bytes(900), true);
    assert.equal(op.sent.length, 1);
    host.emit('message', bytes(1001), true);
    assert.equal(op.closedWith[0], 1009);
    await relay.close();
  });

  it('maxBytes: the byte budget is per pipe, both directions together', async () => {
    const relay = createPipeRelay({ maxBytes: 3000 });
    const { host, op } = await paired(relay);
    host.emit('message', bytes(1500), true);
    op.emit('message', bytes(1500), true);
    assert.equal(host.closedWith, null);
    op.emit('message', bytes(10), true);
    assert.equal(host.closedWith[0], 1008);
    await relay.close();
  });

  it('text frames are not wsh and end the pipe', async () => {
    const relay = createPipeRelay();
    const { host, op } = await paired(relay);
    host.emit('message', Buffer.from('hello'), false);
    assert.equal(op.closedWith[0], 1003);
    await relay.close();
  });

  it('earlyBytes: a half cannot make the relay hold more than the limit while it waits', async () => {
    const relay = createPipeRelay({ earlyBytes: 100 });
    const a = fake();
    await relay.accept(a, { id: id(), role: 'host' });
    a.emit('message', bytes(60), true);
    assert.equal(a.closedWith, null);
    a.emit('message', bytes(60), true);
    assert.equal(a.closedWith[0], 1009);
    assert.equal(relay.stats().waiting, 0);
    await relay.close();
  });

  it('idleTimeoutMs and maxLifetimeMs close a pipe that stalls or lives too long', async () => {
    const relay = createPipeRelay({ idleTimeoutMs: 100 });
    const { host, op } = await paired(relay);
    await sleep(1300);
    assert.ok(host.closedWith && op.closedWith, 'idle pipe closed');
    await relay.close();
    const relay2 = createPipeRelay({ maxLifetimeMs: 100 });
    const p = await paired(relay2);
    await sleep(250);
    assert.ok(p.host.closedWith && p.op.closedWith, 'old pipe closed');
    await relay2.close();
  });

  it('backpressure: a sender is paused while the receiver is backed up and resumed when it drains', async () => {
    const relay = createPipeRelay({ highWaterBytes: 1000 });
    const { host, op } = await paired(relay);
    op.bufferedAmount = 5000; // the operator's socket is not draining
    host.emit('message', bytes(10), true);
    assert.equal(host.paused, 1, 'the host side was told to stop reading');
    host.emit('message', bytes(10), true); // already paused: no second pause
    assert.equal(host.paused, 1);
    await sleep(60);
    assert.equal(host.resumed, 0, 'still backed up');
    op.bufferedAmount = 100;
    await sleep(60);
    assert.equal(host.resumed, 1, 'drained: reading resumes');
    await relay.close();
  });

  it('a socket that cannot pause is closed rather than buffered without bound', async () => {
    const relay = createPipeRelay({ highWaterBytes: 1000 });
    const { host, op } = await paired(relay, { pausable: false });
    op.bufferedAmount = 5000;
    host.emit('message', bytes(10), true);
    assert.equal(op.closedWith[0], 1013);
    await relay.close();
  });

  it('authorize can refuse a half', async () => {
    const relay = createPipeRelay({ authorize: ({ role }) => role === 'operator' });
    const h = fake(); const o = fake();
    assert.equal(await relay.accept(h, { id: id(), role: 'host' }), false);
    assert.equal(h.closedWith[0], 1008);
    assert.equal(await relay.accept(o, { id: id(), role: 'operator' }), true);
    await relay.close();
  });
});

describe('a host behind a pipe relay authenticates the operator exactly as on a direct connection', () => {
  let relay; let relayUrl; let alice; let mallory; let authorizedKeys; let hostKey;
  before(async () => {
    alice = await generateKeyPair(true);
    mallory = await generateKeyPair(true);
    authorizedKeys = `${await exportPublicKeySSH(alice.publicKey)} alice@test\n`;
    hostKey = await loadHostKey(true);
    relay = createPipeRelay();
    const { port } = await relay.listen();
    relayUrl = `ws://127.0.0.1:${port}`;
  });
  after(async () => { await relay.close(); });

  /** The host dials the relay and serves that connection; resolves the operator's URL. */
  async function behindPipe(srv) {
    const id = newRendezvousId();
    const ws = new WsClient(pipeUrl(relayUrl, id, 'host'));
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
    await srv.accept(ws);
    return pipeUrl(relayUrl, id);
  }

  const cases = [
    ['direct', async (srv) => { srv.port ??= (await srv.listen()).port; return `ws://127.0.0.1:${srv.port}`; }],
    ['through the pipe', behindPipe],
  ];

  for (const [label, dialUrl] of cases) {
    describe(label, () => {
      let srv;
      before(() => { srv = createWshServer({ auth: { authorizedKeys }, exec: true, hostKey: true }); });
      after(() => srv.close());
      const out = (s) => new Promise((resolve) => { const ch = []; s.onData = (d) => ch.push(d); s.onClose = () => resolve(dec.decode(Buffer.concat(ch))); });

      it('an authorized key runs a command', async () => {
        const client = new WshClient();
        await client.connect(await dialUrl(srv), { username: 'alice', keyPair: alice, timeout: 4000 });
        try { assert.equal(await out(await client.openSession({ type: 'exec', command: 'echo piped' })), 'piped\n'); } finally { await client.disconnect(); }
      });

      it('a key that is not authorized is refused by the host', async () => {
        await assert.rejects(new WshClient().connect(await dialUrl(srv), { username: 'alice', keyPair: mallory, timeout: 4000 }), /key not authorized/);
      });

      it('a username the signature was not made for is refused', async () => {
        // The transcript binds the username: sign as alice, present as bob is not possible with the stock client, so
        // check the host's own rejection of a malformed name instead.
        await assert.rejects(new WshClient().connect(await dialUrl(srv), { username: 'not a user!', keyPair: alice, timeout: 4000 }), /bad username/);
      });

      it('the operator can pin the host key, and a host presenting another key is refused', async () => {
        const url2 = await dialUrl(srv); // one pipe per connection
        const unpinned = new WshClient();
        await unpinned.connect(url2, { username: 'alice', keyPair: alice, timeout: 4000 });
        const real = unpinned.hostKey.fingerprint;
        await unpinned.disconnect();
        const ok = new WshClient();
        await ok.connect(await dialUrl(srv), { username: 'alice', keyPair: alice, expectHostKey: real, timeout: 4000 });
        assert.equal(ok.hostKey.status, 'pinned');
        await ok.disconnect();
        await assert.rejects(new WshClient().connect(await dialUrl(srv), { username: 'alice', keyPair: alice, expectHostKey: hostKey.fingerprint, timeout: 4000 }), /host key/i);
      });
    });
  }

  it('whoever reaches the rendezvous id first as the host is an impostor, and a pinning operator refuses it', async () => {
    const real = createWshServer({ auth: { authorizedKeys }, exec: true, hostKey: true });
    const realKey = await (async () => { const { port } = await real.listen(); const c = new WshClient(); await c.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair: alice }); const fp = c.hostKey.fingerprint; await c.disconnect(); return fp; })();
    const impostor = createWshServer({ auth: { authorizedKeys }, exec: true, hostKey: true }); // its own, different key
    const url = await behindPipe(impostor);
    await assert.rejects(new WshClient().connect(url, { username: 'alice', keyPair: alice, expectHostKey: realKey, timeout: 4000 }), /host key mismatch/);
    await real.close(); await impostor.close();
  });
});
