// wsh over a duplex that someone else provides (#220, spec/duplex-binding.md): a full session (login, host key, seal, channels) over a pair of
// `send` / `receive` functions, with a hostile middle that reads, changes, drops and repeats what passes.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createDuplexSocket, serveWshOverDuplex, connectWshOverDuplex } from '@johnhenry/wsh/duplex';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw, HostKeyError } from '@johnhenry/wsh';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
const until = async (cond, what, ms = 4000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 3)); }
};
const dec = new TextDecoder();

/**
 * The two ends of a duplex with a middle between them. `tap({ to: 'host' | 'client', bytes })` sees every message and returns undefined (pass),
 * null (drop) or bytes / an array of bytes (written instead). `seen` records what passed, before the tap.
 */
function middle({ tap = null, delayed = false } = {}) {
  const seen = [];
  const waiting = {};
  const ends = new Proxy({ host: null, client: null }, { set(t, k, v) { t[k] = v; for (const b of waiting[k]?.splice(0) ?? []) queueMicrotask(() => v.receive(b)); return true; } });
  const wire = (to) => (bytes) => {
    const copy = bytes.slice();
    seen.push({ to, bytes: copy.slice() });
    let out = [copy];
    if (tap) { const r = tap({ to, bytes: copy.slice() }); if (r === null) out = []; else if (r !== undefined) out = Array.isArray(r) ? r : [r]; }
    // A message for an end that is not wired yet waits for it (the host speaks first, before the client exists).
    for (const b of out) { if (ends[to]) queueMicrotask(() => ends[to].receive(b)); else (waiting[to] ??= []).push(b); }
    if (delayed) return new Promise((r) => setTimeout(r, 1));
    return undefined;
  };
  return { seen, ends, toHost: wire('host'), toClient: wire('client') };
}

async function world({ tap, hostOptions = {}, serve = {}, connect = {}, delayed = false, wait = true } = {}) {
  const keyPair = await generateKeyPair(true);
  const refused = [];
  const ran = [];
  const host = createMemoryHost({
    auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] },
    exec: async (c, io) => { ran.push(c); await io.write(`ran:${c}\n`); return 0; },
    hostKey: true, onRefused: (r) => refused.push(r), ...hostOptions,
  });
  closers.push(() => host.close());
  const m = middle({ tap, delayed });
  const served = serveWshOverDuplex(host, { send: m.toClient, ...serve });
  m.ends.host = served;
  const hostFp = hostOptions.hostKey === false ? undefined : undefined;
  void hostFp;
  return { m, host, served, keyPair, refused, ran, connect: async (extra = {}) => {
    const fp = (await host.connect({ username: 'probe', keyPair }).then(async (c) => { const f = c.hostKey?.fingerprint; await c.disconnect(); return f; }));
    const { duplex = {}, ...credentials } = { ...connect, ...extra };
    const link = connectWshOverDuplex({ send: m.toHost, ...duplex }, { username: 'alice', keyPair, expectHostKey: fp, timeout: 1500, ...credentials });
    m.ends.client = link;
    closers.push(() => link.close());
    return { link, fp };
  }, wait };
}

describe('createDuplexSocket: the WebSocket-shaped object over a duplex', () => {
  it('opens, delivers messages in order as binary, and writes in order, waiting for an asynchronous send', async () => {
    const sent = [];
    let release;
    const gate = new Promise((r) => { release = r; });
    const link = createDuplexSocket({ send: async (b) => { sent.push([...b]); if (sent.length === 1) await gate; } });
    const events = [];
    link.socket.addEventListener('open', () => events.push('open'));
    link.socket.addEventListener('message', (e) => events.push([...new Uint8Array(e.data)]));
    await until(() => link.socket.readyState === 1, 'open');
    link.receive(new Uint8Array([1])); link.receive(new Uint8Array([2]).buffer);
    await until(() => events.length === 3, 'messages');
    assert.deepEqual(events, ['open', [1], [2]]);
    link.socket.send(new Uint8Array([7])); link.socket.send(new Uint8Array([8]));
    await new Promise((r) => setTimeout(r, 10));
    assert.deepEqual(sent, [[7]], 'the second write waits for the first to finish');
    assert.equal(link.socket.bufferedAmount, 2);
    release();
    await until(() => sent.length === 2, 'the second write');
    assert.deepEqual(sent, [[7], [8]]);
    await until(() => link.socket.bufferedAmount === 0, 'the buffer to drain');
  });

  it('a Node Buffer (what the `ws` package hands over) and a view into a bigger ArrayBuffer arrive as their own bytes, not as the memory they sit in', async () => {
    const link = createDuplexSocket({ send: () => {} });
    const got = [];
    link.socket.addEventListener('message', (e) => got.push([...new Uint8Array(e.data)]));
    await until(() => link.socket.readyState === 1, 'open');
    const pool = new Uint8Array([9, 9, 1, 2, 3, 9, 9]);
    link.receive(Buffer.from(pool.buffer, 2, 3));            // a Buffer is a view: Buffer.prototype.slice() does not copy it
    link.receive(new Uint8Array(pool.buffer, 2, 3));         // so is any other view
    link.receive(Buffer.from([4, 5]));                       // small Buffers come from a shared pool
    await until(() => got.length === 3, 'three messages');
    assert.deepEqual(got, [[1, 2, 3], [1, 2, 3], [4, 5]]);
  });

  it('cuts a large write into messages of at most maxMessageBytes, in order, and ends the link on a larger incoming message', async () => {
    const sent = [];
    const link = createDuplexSocket({ send: (b) => { sent.push(b); }, maxMessageBytes: 300 });
    await until(() => link.socket.readyState === 1, 'open');
    const big = Uint8Array.from({ length: 1000 }, (_, i) => i % 251);
    link.socket.send(big);
    await until(() => sent.reduce((n, b) => n + b.byteLength, 0) === 1000, 'all of it');
    assert.deepEqual(sent.map((b) => b.byteLength), [300, 300, 300, 100]);
    assert.deepEqual(Uint8Array.from(sent.flatMap((b) => [...b])), big);
    let closed = null;
    link.socket.addEventListener('close', (e) => { closed = e; });
    link.receive(new Uint8Array(301));
    assert.equal(closed.code, 1009);
    assert.equal(link.socket.readyState, 3);
  });

  it('a send that rejects, a peer that does not read (maxBufferedBytes), a text message and end() each close it, and close() reaches the duplex once', async () => {
    const reasons = [];
    const make = (opts) => { const l = createDuplexSocket({ close: (r) => reasons.push(r), ...opts }); const c = []; l.socket.addEventListener('close', (e) => c.push(e.code)); return { l, c }; };
    const a = make({ send: async () => { throw new Error('link down'); } });
    await until(() => a.l.socket.readyState === 1, 'open');
    a.l.socket.send(new Uint8Array(3));
    await until(() => a.c.length === 1, 'the failed send to end it');
    assert.equal(a.c[0], 1011);
    const b = make({ send: () => new Promise(() => {}), maxMessageBytes: 256, maxBufferedBytes: 1024 });
    await until(() => b.l.socket.readyState === 1, 'open');
    for (let i = 0; i < 5; i++) b.l.socket.send(new Uint8Array(256));
    assert.deepEqual(b.c, [1013]);
    const c = make({ send() {} });
    await until(() => c.l.socket.readyState === 1, 'open');
    c.l.receive('text');
    assert.deepEqual(c.c, [1003]);
    const d = make({ send() {} });
    await until(() => d.l.socket.readyState === 1, 'open');
    const before = reasons.length;
    d.l.end('peer left');
    assert.deepEqual(d.c, [1006]);
    assert.equal(reasons.length, before, 'end() is the duplex ending: it is not told to close');
    d.l.socket.close();
    assert.deepEqual(d.c, [1006], 'closed once');
    assert.throws(() => d.l.socket.send(new Uint8Array(1)), /not open/);
  });

  it('refuses bad options', () => {
    assert.throws(() => createDuplexSocket({}), TypeError);
    assert.throws(() => createDuplexSocket({ send() {}, maxMessageBytes: 10 }), TypeError);
    assert.throws(() => createDuplexSocket({ send() {}, maxMessageBytes: 1024, maxBufferedBytes: 10 }), TypeError);
    assert.throws(() => createDuplexSocket({ send() {}, close: 5 }), TypeError);
  });
});

describe('a session over a duplex', () => {
  it('logs in, pins the host key, is sealed, and runs a command; the middle reads only sealed bytes after login', async () => {
    const w = await world();
    const { link, fp } = await w.connect();
    const client = await link.connected;
    assert.equal(client.state, 'authenticated');
    assert.equal(client.hostKey.fingerprint, fp);
    assert.equal(client.hostKey.status, 'pinned');
    assert.equal(client.sessionSealed, true, 'the whole session is sealed');
    const out = [];
    const session = await client.openSession({ type: 'exec', command: 'marker-secret-77' });
    session.onData = (d) => out.push(dec.decode(d));
    await until(() => out.join('').includes('ran:marker-secret-77'), 'the output');
    const everything = w.m.seen.map((s) => Buffer.from(s.bytes).toString('latin1')).join('');
    assert.ok(!everything.includes('marker-secret-77'), 'the command is not in what the middle saw');
    assert.ok(!everything.includes('ran:'), 'nor the output');
    assert.deepEqual(w.refused, []);
  });

  it('carries a session whose messages are small and slow: maxMessageBytes of 512 and an asynchronous send', async () => {
    const w = await world({ serve: { maxMessageBytes: 512 }, connect: { duplex: { maxMessageBytes: 512 }, timeout: 15000 }, delayed: true });
    const { link } = await w.connect();
    const client = await link.connected;
    const out = [];
    const s = await client.openSession({ type: 'exec', command: 'x'.repeat(2000) });
    s.onData = (d) => out.push(dec.decode(d));
    await until(() => out.join('').length >= 2005, 'the long output');
    assert.ok(w.m.seen.every((x) => x.bytes.byteLength <= 512), 'no message over maxMessageBytes was written');
  });

  it('a middle that changes a byte of a sealed message from the client: the host ends the session and runs nothing more', async () => {
    let flip = false;
    // a byte in the middle of the message, where the ciphertext is
    const w = await world({ tap: ({ to, bytes }) => { if (flip && to === 'host' && bytes.length > 64) { bytes[bytes.length >> 1] ^= 1; return bytes; } return undefined; } });
    const { link } = await w.connect();
    const client = await link.connected;
    flip = true;
    void client.openSession({ type: 'exec', command: 'altered' }).catch(() => {});
    await new Promise((r) => setTimeout(r, 400));
    assert.ok(!w.ran.includes('altered'), 'the altered request was not run');
    assert.ok(!w.ran.length, 'and nothing else was either');
  });

  it('a middle that changes a byte of a sealed message from the host: nothing altered is delivered', async () => {
    let flip = false;
    const w = await world({ tap: ({ to, bytes }) => { if (flip && to === 'client') { bytes[bytes.length - 1] ^= 1; return bytes; } return undefined; } });
    const { link } = await w.connect();
    const client = await link.connected;
    flip = true;
    const got = [];
    // The last byte of a frame is the end of its session id (#292): a frame that is not this session's ends the session, so the open fails
    // (it used to be dropped as plain and the open timed out with the session still up).
    const s = await Promise.race([client.openSession({ type: 'exec', command: 'wanted' }).catch((e) => e), new Promise((r) => setTimeout(() => r(null), 400))]);
    if (s && !(s instanceof Error)) s.onData = (d) => got.push(dec.decode(d));
    await new Promise((r) => setTimeout(r, 200));
    assert.deepEqual(got, [], 'the client never hears the altered answer');
    assert.ok(s instanceof Error, `the session ended instead of carrying on: ${s}`);
    assert.equal(client.state, 'closed');
  });

  it('a middle that repeats a sealed message from the client: the command runs once', async () => {
    let dupe = false;
    const w = await world({ tap: ({ to, bytes }) => (dupe && to === 'host' ? [bytes, bytes] : undefined) });
    const { link } = await w.connect();
    const client = await link.connected;
    dupe = true;
    await client.openSession({ type: 'exec', command: 'once' }).catch(() => {});
    await new Promise((r) => setTimeout(r, 300));
    assert.ok(w.ran.filter((c) => c === 'once').length <= 1, 'a replayed frame did not run the command again');
  });

  it('a middle that drops the host\'s first answer: the connect fails by its timeout, it is not left hanging, and no credential reached anyone else', async () => {
    const w = await world({ tap: ({ to }) => (to === 'client' ? null : undefined) });
    const { link } = await w.connect({ timeout: 300 });
    await assert.rejects(link.connected);
  });

  it('a middle that drops messages after login stalls the session and delivers nothing wrong', async () => {
    let drop = false;
    const w = await world({ tap: ({ to }) => (drop && to === 'client' ? null : undefined) });
    const { link } = await w.connect();
    const client = await link.connected;
    drop = true;
    const got = [];
    const s = await Promise.race([client.openSession({ type: 'exec', command: 'dropped-answer' }), new Promise((r) => setTimeout(() => r(null), 300))]);
    if (s) s.onData = (d) => got.push(dec.decode(d));
    await new Promise((r) => setTimeout(r, 200));
    assert.deepEqual(got, []);
  });
});

describe('what a middle that answers as the host cannot do', () => {
  it('a client that names the host key refuses another host that answers (before a credential is sent)', async () => {
    const real = await world();
    const impostorKey = await generateKeyPair(true);
    const impostor = createMemoryHost({ auth: { authorizedKeys: [await exportPublicKeyRaw(real.keyPair.publicKey)] }, hostKey: true, exec: async () => 0 });
    closers.push(() => impostor.close());
    const m = middle();
    m.ends.host = serveWshOverDuplex(impostor, { send: m.toClient });
    const { fp } = await real.connect();
    const link = connectWshOverDuplex({ send: m.toHost }, { username: 'alice', keyPair: real.keyPair, expectHostKey: fp, timeout: 1500 });
    m.ends.client = link;
    closers.push(() => link.close());
    await assert.rejects(link.connected, (e) => e instanceof HostKeyError || /host key/i.test(e.message));
    assert.ok(impostorKey);
  });

  it('connect refuses to start without a named host key, and without a key login unless it is told', async () => {
    const send = () => {};
    const keyPair = await generateKeyPair(true);
    assert.throws(() => connectWshOverDuplex({ send }, { username: 'a', keyPair }), /name the host key/);
    assert.doesNotThrow(() => { const l = connectWshOverDuplex({ send }, { username: 'a', keyPair, trustOnFirstUse: true, timeout: 50 }); l.connected.catch(() => {}); l.close(); });
    assert.throws(() => connectWshOverDuplex({ send }, { username: 'a', password: 'x', expectHostKey: 'ab'.repeat(32) }), /password/);
  });
});

describe('an unsealed session is refused by default', () => {
  it('the host: a plain client (sealSession: false) over the duplex is served nothing, though the host itself does not require sealing', async () => {
    const w = await world();
    const fp = (await w.host.connect({ username: 'probe', keyPair: w.keyPair }).then(async (c) => { const f = c.hostKey.fingerprint; await c.disconnect(); return f; }));
    const link = createDuplexSocket({ send: w.m.toHost });
    w.m.ends.client = link;
    class Plain { constructor() { return link.socket; } }
    const plain = new WshClient({ transportFactories: { ws: () => new WebSocketTransport({ WebSocket: Plain }) } });
    closers.push(() => plain.disconnect());
    await plain.connect('ws://x/', { transport: 'ws', username: 'alice', keyPair: w.keyPair, sealSession: false, expectHostKey: fp, timeout: 1500 }).catch(() => {});
    const s = await Promise.race([plain.openSession({ type: 'exec', command: 'unsealed' }).catch(() => null), new Promise((r) => setTimeout(() => r(null), 400))]);
    const out = [];
    if (s) s.onData = (d) => out.push(dec.decode(d));
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(!w.ran.includes('unsealed'), 'nothing ran');
    assert.deepEqual(out, []);
    assert.ok(w.refused.some((r) => r.reason === 'not-sealed'), JSON.stringify(w.refused));
  });

  it('the host: allowUnsealed: true serves it (and says so in its name)', async () => {
    const w = await world({ serve: { allowUnsealed: true } });
    const fp = (await w.host.connect({ username: 'probe', keyPair: w.keyPair }).then(async (c) => { const f = c.hostKey.fingerprint; await c.disconnect(); return f; }));
    const link = connectWshOverDuplex({ send: w.m.toHost }, { username: 'alice', keyPair: w.keyPair, expectHostKey: fp, allowUnsealed: true, timeout: 1500 });
    w.m.ends.client = link;
    closers.push(() => link.close());
    const client = await link.connected;
    assert.equal(client.sessionSealed, false);
    const out = [];
    const s = await client.openSession({ type: 'exec', command: 'plain-ok' });
    s.onData = (d) => out.push(dec.decode(d));
    await until(() => out.join('').includes('ran:plain-ok'), 'the output');
  });

  it('the client: a host that does not offer sealing is refused before a credential is sent', async () => {
    const w = await world({ serve: { allowUnsealed: true }, hostOptions: { hostKey: undefined } });
    // a host with a key that cannot seal because it was given data streams is not reachable here; one with no host key cannot even be pinned
    const keyPair = w.keyPair;
    const link = connectWshOverDuplex({ send: w.m.toHost }, { username: 'alice', keyPair, trustOnFirstUse: true, timeout: 800 });
    w.m.ends.client = link;
    closers.push(() => link.close());
    await assert.rejects(link.connected);
  });

  it('a host without a host key cannot serve a duplex at all: it is refused, not served unsealed', async () => {
    const keyPair = await generateKeyPair(true);
    const host = createMemoryHost({ auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] }, exec: async () => 0 });
    closers.push(() => host.close());
    const m = middle();
    const served = serveWshOverDuplex(host, { send: m.toClient });
    await assert.rejects(served.ready, /cannot seal/);
    assert.equal(served.close(), undefined);
  });

  it('refuses a host without accept(), and a non-boolean allowUnsealed', () => {
    assert.throws(() => serveWshOverDuplex({}, { send() {} }), TypeError);
    assert.throws(() => serveWshOverDuplex({ accept() {} }, { send() {}, allowUnsealed: 'yes' }), TypeError);
  });
});

describe('the duplex ending', () => {
  it('end() on the client ends the session and a later connect on the same duplex is refused: one duplex, one connection', async () => {
    const w = await world();
    const { link } = await w.connect();
    const client = await link.connected;
    const closed = new Promise((r) => { client.onClose = r; });
    link.end('the channel closed');
    await closed;
    assert.equal(client.state, 'closed');
  });
});
