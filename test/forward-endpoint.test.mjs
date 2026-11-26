// test/forward-endpoint.test.mjs -- client.forwardEndpoint({ local, endpoint }): a local unix socket (or loopback TCP
// port) joined, per connection, to a NAMED endpoint of the host. The JS equivalent of the CLI's
// `wsh -L /tmp/d.sock:endpoint=NAME` (crates/wsh-cli/src/commands/forward.rs), run against a real in-process host
// (the memory host) and a real client; nothing here needs a Rust binary.
import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeyRaw } from '@johnhenry/wsh';
import { GatewayError } from '../src/gateway-client.mjs';
import { fixture, until, sleep } from './gateway-fixture.mjs';

const MiB = 1024 * 1024;
const enc = new TextEncoder();
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const bulkBytes = () => { const b = Buffer.alloc(20 * MiB); for (let i = 0; i < b.length; i += 4096) b.writeUInt32LE(i, i); return b; };

/** Wait until `read()` has not changed for `quietMs`. */
async function settled(read, quietMs = 300) {
  let last = read(); let since = Date.now();
  while (Date.now() - since < quietMs) { await sleep(20); const v = read(); if (v !== last) { last = v; since = Date.now(); } }
  return last;
}
const connectUnix = (p) => new Promise((resolve, reject) => { const s = net.connect({ path: p, allowHalfOpen: true }); s.once('connect', () => resolve(s)); s.once('error', reject); });
const connectTcp = (port, host = '127.0.0.1') => new Promise((resolve, reject) => { const s = net.connect({ host, port, allowHalfOpen: true }); s.once('connect', () => resolve(s)); s.once('error', reject); });
/** Everything a socket delivers until it ends or closes. */
const readAll = (s) => new Promise((resolve) => { const cs = []; s.on('data', (c) => cs.push(c)); s.on('error', () => {}); s.on('close', () => resolve(Buffer.concat(cs))); s.on('end', () => resolve(Buffer.concat(cs))); });
/** Resolves when the socket is fully closed; these sockets are half-open, so an EOF from the other side is answered with our own end. */
const closed = (s) => {
  if (s.destroyed) return Promise.resolve();
  s.on('error', () => {});
  s.once('end', () => s.end());
  return new Promise((r) => s.once('close', r));
};

describe('forwardEndpoint: a local socket or port joined to a named endpoint of the host', () => {
  let keyPair; let raw; let host; let dir;
  const clients = []; const forwards = []; const socks = [];
  let n = 0;
  const sockPath = () => path.join(dir, `s${n++}.sock`);

  // Endpoint bookkeeping, reset for each test.
  let st;
  const resetState = () => {
    let openGate; const gate = new Promise((r) => { openGate = r; });
    st = { active: 0, written: 0, received: 0, flaky: 0, openGate, gate, sawClose: 0, trailing: [] };
  };

  before(async () => {
    keyPair = await generateKeyPair(true);
    raw = await exportPublicKeyRaw(keyPair.publicKey);
    const guard = (fn) => async (d, who) => { st.active++; try { await fn(d, who); } catch { /* the connection ended under it */ } finally { st.active--; d.closed.then(() => { st.sawClose++; }); } };
    host = createMemoryHost({
      auth: { authorizedKeys: [raw] },
      endpoints: {
        // echoes until the client half-closes, then closes its own side
        echo: guard(async (d) => { const r = d.readable.getReader(); const w = d.writable.getWriter(); for (;;) { const { value, done } = await r.read(); if (done) break; await w.write(value); } await w.close(); }),
        // reads to the client's EOF, and only then answers: the client's half-close must reach the endpoint with the return path open
        'eof-reply': guard(async (d) => { const r = d.readable.getReader(); const w = d.writable.getWriter(); let total = 0; for (;;) { const { value, done } = await r.read(); if (done) break; total += value.length; } await w.write(enc.encode(`got ${total}`)); await w.close(); }),
        // says goodbye and closes ITS write side first; whatever the client sends afterwards is recorded
        bye: guard(async (d) => { const r = d.readable.getReader(); const w = d.writable.getWriter(); await w.write(enc.encode('bye')); await w.close(); for (;;) { const { value, done } = await r.read(); if (done) break; st.trailing.push(Buffer.from(value).toString()); } }),
        bulk: guard(async (d) => { const w = d.writable.getWriter(); const b = bulkBytes(); for (let o = 0; o < b.length; o += 65536) await w.write(b.subarray(o, o + 65536)); await w.close(); }),
        // a source faster than any reader: counts what it managed to hand over
        firehose: guard(async (d) => { const w = d.writable.getWriter(); const chunk = new Uint8Array(65536); for (;;) { await w.write(chunk); st.written += chunk.length; } }),
        // a sink that reads nothing until the test opens the gate, then reads to EOF and reports the total
        sink: guard(async (d) => { const r = d.readable.getReader(); const w = d.writable.getWriter(); await st.gate; for (;;) { const { value, done } = await r.read(); if (done) break; st.received += value.length; } await w.write(enc.encode(String(st.received))); await w.close(); }),
        // holds a connection open until the client goes away
        idle: guard(async (d) => { const r = d.readable.getReader(); const w = d.writable.getWriter(); for (;;) { const { done } = await r.read(); if (done) break; } await w.close(); }),
        // refuses the first caller, accepts the rest
        flaky: { authorize: () => ++st.flaky > 1, open: guard(async (d) => { const r = d.readable.getReader(); const w = d.writable.getWriter(); const { value } = await r.read(); await w.write(value); await w.close(); }) },
        locked: { authorize: () => false, open: async () => {} },
      },
    });
  });
  after(() => host.close());
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-fe-')); resetState(); });
  afterEach(async () => {
    st.openGate();
    for (const s of socks.splice(0)) s.destroy();
    for (const f of forwards.splice(0)) await f.close().catch(() => {});
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    fs.rmSync(dir, { recursive: true, force: true }); // a directory this test made
  });

  const newClient = async () => { const c = await host.connect({ username: 'alice', keyPair }); clients.push(c); return c; };
  /** Start a forward on a fresh client; `errors` collects what `onError` hears. */
  async function start(opts = {}) {
    const client = await newClient();
    const errors = [];
    const local = opts.local ?? sockPath();
    const fwd = await client.forwardEndpoint({ local, endpoint: 'echo', onError: (e) => errors.push(e), ...opts });
    forwards.push(fwd);
    return { client, fwd, errors, local };
  }
  const open = async (p) => { const s = await connectUnix(p); socks.push(s); return s; };

  it('moves bytes both ways through a unix socket; the handle has the shape of the other forwards', async () => {
    const { fwd, local, errors } = await start({ endpoint: 'echo' });
    assert.equal(fwd.local, local);
    assert.equal(fwd.endpoint, 'echo');
    assert.equal(fwd.remote, 'endpoint=echo');
    assert.equal(typeof fwd.close, 'function');
    const s = await open(local);
    s.write('hello ');
    s.end('endpoint');
    assert.equal((await readAll(s)).toString(), 'hello endpoint');
    assert.deepEqual(errors, []);
  });

  it('creates the socket owner-only and removes the file on close()', async () => {
    const { fwd, local } = await start();
    assert.equal(fs.statSync(local).isSocket(), true);
    assert.equal(fs.statSync(local).mode & 0o777, 0o600);
    await fwd.close();
    assert.equal(fs.existsSync(local), false);
  });

  it('a TCP port on the local side binds loopback unless an address is given', async () => {
    const a = await start({ local: '0' });
    assert.equal(a.fwd.address.address, '127.0.0.1');
    const s = await connectTcp(a.fwd.address.port); socks.push(s);
    s.end('over tcp');
    assert.equal((await readAll(s)).toString(), 'over tcp');
    const b = await start({ local: '127.0.0.1:0' });
    assert.equal(b.fwd.address.address, '127.0.0.1');
    const c = await start({ local: '0.0.0.0:0' });
    assert.equal(c.fwd.address.address, '0.0.0.0');
  });

  it('moves a large transfer both ways intact (20 MiB down, 12 MiB up)', async () => {
    const down = await start({ endpoint: 'bulk' });
    const s = await open(down.local);
    const got = await readAll(s);
    assert.equal(got.length, 20 * MiB);
    assert.equal(sha(got), sha(bulkBytes()));

    const up = await start({ endpoint: 'echo' });
    const payload = crypto.randomBytes(12 * MiB);
    const e = await open(up.local);
    const reading = readAll(e);
    e.end(payload);
    assert.equal(sha(await reading), sha(payload));
  });

  it('backpressure, host to local: a stalled local reader holds the endpoint back instead of piling bytes up', async () => {
    const { local } = await start({ endpoint: 'firehose' });
    const s = await open(local);
    s.pause();
    await until(() => st.written > 0, 'the endpoint to start writing');
    const stuck = await settled(() => st.written);
    assert.ok(stuck < 48 * MiB, `the endpoint wrote ${(stuck / MiB).toFixed(1)} MiB into a reader that read nothing`);
    let got = 0;
    await new Promise((resolve) => { s.on('data', (d) => { got += d.length; if (got >= 4 * MiB) resolve(); }); s.resume(); });
    assert.ok(st.written > stuck, 'reading resumes the flow');
  });

  it('backpressure, local to host: an endpoint that reads nothing holds the local writer back', async () => {
    const { local } = await start({ endpoint: 'sink' });
    const s = await open(local);
    const total = 64 * MiB;
    s.write(Buffer.alloc(total));
    await settled(() => s.writableLength);
    assert.ok(s.writableLength > total / 2, `only ${((total - s.writableLength) / MiB).toFixed(1)} of 64 MiB left the local socket while the endpoint read nothing`);
    const reply = readAll(s);
    st.openGate();
    s.end();
    assert.equal((await reply).toString(), String(total), 'every byte arrives once the endpoint reads');
  });

  it('half-close, local to host: the local EOF reaches the endpoint and the answer still comes back', async () => {
    const { local } = await start({ endpoint: 'eof-reply' });
    const s = await open(local);
    s.write('twelve bytes');
    s.end();
    assert.equal((await readAll(s)).toString(), 'got 12');
  });

  it('half-close, host to local: the endpoint ends its side, the local socket sees the data then EOF, and ending ours finishes the connection', async () => {
    const { local, errors } = await start({ endpoint: 'bye' });
    const s = await open(local);
    const seen = [];
    const ended = new Promise((r) => s.once('end', r));
    s.on('data', (c) => seen.push(c));
    await ended;
    assert.equal(Buffer.concat(seen).toString(), 'bye');
    assert.equal(s.destroyed, false, 'the local socket is still ours to close');
    s.end();
    await closed(s);
    await until(() => st.sawClose > 0, 'the endpoint to learn the connection is over');
    assert.deepEqual(errors, []);
  });

  it('an unknown endpoint, and one that refuses this caller: the local connection closes, the reason reaches onError, the listener stays up', async () => {
    const missing = await start({ endpoint: 'nothing-here' });
    const s = await open(missing.local);
    assert.equal((await readAll(s)).length, 0);
    await until(() => missing.errors.length === 1, 'the refusal to be reported');
    assert.ok(missing.errors[0] instanceof GatewayError);
    assert.equal(missing.errors[0].code, 4);
    const again = await open(missing.local); // still listening
    await closed(again);
    await until(() => missing.errors.length === 2, 'a second refusal');

    const locked = await start({ endpoint: 'locked' });
    const l = await open(locked.local);
    await closed(l);
    await until(() => locked.errors.length === 1, 'the refusal to be reported');
    assert.match(locked.errors[0].message, /refused/);

    // a refusal that passes: the first caller of "flaky" is refused, the next one is served
    const flaky = await start({ endpoint: 'flaky' });
    const first = await open(flaky.local);
    await closed(first);
    await until(() => flaky.errors.length === 1, 'the first refusal');
    const second = await open(flaky.local);
    second.end('served');
    assert.equal((await readAll(second)).toString(), 'served');
    assert.equal(flaky.errors.length, 1);
  });

  it('a host with no named endpoints is refused when the forward starts, not once per connection', async () => {
    const fx = fixture();
    try {
      const { client } = await fx.setup({ allow: ['*'] });
      const local = sockPath();
      await assert.rejects(client.forwardEndpoint({ local, endpoint: 'docker' }), /gateway-endpoints|endpoint/);
      assert.equal(fs.existsSync(local), false, 'nothing was left listening');
    } finally { await fx.teardown(); }
  });

  it('refuses a malformed endpoint name before listening on anything (the CLI\'s rule: letters, digits, ".", "_", "-"; at most 64)', async () => {
    const client = await newClient();
    for (const endpoint of ['', 'bad name', '-leading', 'a/b', 'x'.repeat(65), 42, undefined]) {
      const local = sockPath();
      await assert.rejects(client.forwardEndpoint({ local, endpoint }), TypeError, String(endpoint));
      assert.equal(fs.existsSync(local), false);
    }
    const ok = await client.forwardEndpoint({ local: sockPath(), endpoint: 'a.b_c-d'.padEnd(64, 'x') });
    forwards.push(ok);
  });

  it('serves many concurrent connections, each with its own bytes', async () => {
    const { local, errors } = await start({ endpoint: 'echo' });
    const results = await Promise.all(Array.from({ length: 48 }, async (_, i) => {
      const s = await open(local);
      const msg = crypto.randomBytes(50_000 + i);
      const reading = readAll(s);
      s.end(msg);
      return (await reading).equals(msg);
    }));
    assert.deepEqual(results, new Array(48).fill(true));
    assert.deepEqual(errors, []);
  });

  it('bounds concurrent connections (128 by default; maxConnections changes it): the extra one is closed and reported, and a freed slot is reusable', async () => {
    const { fwd, local, errors } = await start({ endpoint: 'idle', maxConnections: 2 });
    const a = await open(local); const b = await open(local);
    await until(() => st.active === 2 && fwd.connections === 2, 'two live connections');
    const c = await open(local);
    await closed(c);
    await until(() => errors.length === 1, 'the over-limit report');
    assert.match(errors[0].message, /more than 2 connections/);
    assert.equal(fwd.connections, 2);
    const aGone = closed(a);
    a.end(); // the endpoint ends its side once it sees ours, and the slot is free
    await aGone;
    await until(() => fwd.connections === 1, 'a slot to free up');
    const d = await open(local);
    await until(() => st.active === 2 && fwd.connections === 2, 'the freed slot to be used');
    assert.equal(errors.length, 1);
    b.destroy(); d.destroy();
    const client = await newClient();
    for (const maxConnections of [0, -1, 1.5, '3']) await assert.rejects(client.forwardEndpoint({ local: sockPath(), endpoint: 'echo', maxConnections }), TypeError, String(maxConnections));
  });

  it('the default bound is 128, the CLI\'s', async () => {
    const { fwd } = await start({ endpoint: 'idle' });
    assert.equal(fwd.maxConnections, 128);
  });

  it('close() during traffic ends the listener and every live connection, and removes the socket file', async () => {
    const { fwd, local } = await start({ endpoint: 'firehose' });
    const live = [];
    for (let i = 0; i < 4; i++) { const s = await open(local); s.on('data', () => {}); live.push(s); }
    await until(() => st.active === 4 && st.written > 0, 'traffic on four connections');
    const allClosed = Promise.all(live.map(closed)); // watch before closing: an EOF is answered when it arrives
    await fwd.close();
    await allClosed;
    assert.equal(fs.existsSync(local), false);
    await assert.rejects(connectUnix(local), (e) => e.code === 'ENOENT' || e.code === 'ECONNREFUSED');
    await until(() => st.active === 0, 'the endpoint to see every connection end');
    await fwd.close(); // closing twice is harmless
  });

  it('a client that closes first is not a failure: no onError, no uncaught error, and the listener keeps working', async () => {
    const uncaught = [];
    const onUncaught = (e) => uncaught.push(e);
    process.on('uncaughtException', onUncaught); process.on('unhandledRejection', onUncaught);
    try {
      const { local, errors } = await start({ endpoint: 'firehose' });
      for (let i = 0; i < 8; i++) {
        const s = await open(local);
        await new Promise((r) => s.once('data', r));
        s.destroy(); // the client goes first while the endpoint is still writing
      }
      await until(() => st.active === 0, 'every connection to end');
      await settled(() => st.sawClose);
      assert.deepEqual(uncaught, []);
      assert.deepEqual(errors, []);
      const s = await open(local);
      await new Promise((r) => s.once('data', r));
    } finally { process.off('uncaughtException', onUncaught); process.off('unhandledRejection', onUncaught); }
  });

  describe('an existing path (the CLI: refused, unless a STALE socket may be replaced)', () => {
    const staleSocket = async (p) => {
      const child = spawn(process.execPath, [new URL('./stale-socket-child.mjs', import.meta.url).pathname, p], { stdio: 'ignore' });
      await new Promise((r) => child.on('exit', r));
      assert.equal(fs.lstatSync(p).isSocket(), true);
    };

    it('is refused by default, whatever it is, and left untouched', async () => {
      const client = await newClient();
      const file = sockPath(); fs.writeFileSync(file, 'data');
      await assert.rejects(client.forwardEndpoint({ local: file, endpoint: 'echo' }), /exists|not a socket/);
      assert.equal(fs.readFileSync(file, 'utf8'), 'data');
      const stale = sockPath(); await staleSocket(stale);
      await assert.rejects(client.forwardEndpoint({ local: stale, endpoint: 'echo' }), /already exists.*replace/);
      assert.equal(fs.lstatSync(stale).isSocket(), true);
    });

    it('replace: true replaces a stale socket, never a live one, never a file that is not a socket', async () => {
      const client = await newClient();
      const stale = sockPath(); await staleSocket(stale);
      const fwd = await client.forwardEndpoint({ local: stale, endpoint: 'echo', replace: true });
      forwards.push(fwd);
      const s = await open(stale); s.end('replaced');
      assert.equal((await readAll(s)).toString(), 'replaced');

      const live = sockPath();
      const server = net.createServer((c) => { c.on('error', () => {}); c.end('mine'); });
      await new Promise((r) => server.listen(live, r));
      try {
        await assert.rejects(client.forwardEndpoint({ local: live, endpoint: 'echo', replace: true }), /in use/);
        const t = await open(live);
        assert.equal((await readAll(t)).toString(), 'mine');
        t.destroy();
      } finally { await new Promise((r) => server.close(r)); }

      const file = sockPath(); fs.writeFileSync(file, 'data');
      await assert.rejects(client.forwardEndpoint({ local: file, endpoint: 'echo', replace: true }), /not a socket/);
      assert.equal(fs.readFileSync(file, 'utf8'), 'data');
    });
  });

  it('forwardUnix accepts the CLI\'s spelling, remote: "endpoint=NAME", and it cannot be a reverse forward', async () => {
    const client = await newClient();
    const local = sockPath();
    const fwd = await client.forwardUnix({ local, remote: 'endpoint=echo' });
    forwards.push(fwd);
    assert.equal(fwd.remote, 'endpoint=echo');
    const s = await open(local); s.end('via forwardUnix');
    assert.equal((await readAll(s)).toString(), 'via forwardUnix');
    await assert.rejects(client.forwardUnix({ local: '127.0.0.1:1', remote: 'endpoint=echo', reverse: true }), /endpoint/);
    await assert.rejects(client.forwardUnix({ local, remote: 'endpoint=bad name' }), TypeError);
  });
});
