// test/pipe-relay-paired.test.mjs -- the host half of a pipe relay can be told when its partner arrived, without a peer that
// never asked noticing: the host opts in (`?role=host&paired=1`, `accept(socket, { notifyPaired: true })`), the relay sends ONE text
// frame (`wsh-pipe/1 paired`) before it forwards anything, and `watchPairing()` turns that frame into a promise and keeps it out of the
// byte stream the wsh host reads. A released relay ignores the flag and never sends it; a released host never sets it.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket as WsClient } from 'ws';
import { createPipeRelay, newRendezvousId, pipeUrl, watchPairing, PAIRED_FRAME } from '@johnhenry/wsh/pipe-relay';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, what, ms = 4000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
};

describe('the paired signal', () => {
  let relay; let url;
  const sockets = [];
  before(async () => {
    relay = createPipeRelay({ rendezvousTimeoutMs: 5000 });
    const { port } = await relay.listen();
    url = `ws://127.0.0.1:${port}`;
  });
  after(async () => { for (const s of sockets) s.terminate(); await relay.close(); });

  function dial(id, role, opts) {
    const ws = new WsClient(pipeUrl(url, id, role, opts));
    sockets.push(ws);
    const got = []; let closed = null;
    ws.on('message', (d, isBinary) => got.push({ isBinary, text: isBinary ? null : d.toString(), bytes: isBinary ? Buffer.from(d) : null }));
    ws.on('close', (code) => { closed = code; });
    ws.on('error', () => {});
    return { ws, got, get closed() { return closed; }, open: new Promise((r) => ws.once('open', r)) };
  }

  it('pipeUrl asks for it only for a host, and only when told to', () => {
    const id = newRendezvousId();
    assert.equal(pipeUrl('wss://r.example', id, 'host', { notifyPaired: true }), `wss://r.example/r/${id}?role=host&paired=1`);
    assert.equal(pipeUrl('wss://r.example', id, 'host'), `wss://r.example/r/${id}?role=host`);
    assert.throws(() => pipeUrl('wss://r.example', id, 'operator', { notifyPaired: true }), /host/);
    assert.equal(PAIRED_FRAME, 'wsh-pipe/1 paired');
  });

  it('a host that asked gets one text frame when its partner arrives, before anything the partner said; the partner gets none', async () => {
    const id = newRendezvousId();
    const host = dial(id, 'host', { notifyPaired: true });
    await host.open;
    await sleep(100);
    assert.deepEqual(host.got, [], 'nothing while it waits');
    const op = dial(id, 'operator');
    await op.open;
    op.ws.send(Buffer.from('hello-from-operator'));
    await until(() => host.got.length >= 2, 'the host to hear both frames');
    assert.deepEqual(host.got.map((m) => [m.isBinary, m.text ?? String(m.bytes)]), [[false, PAIRED_FRAME], [true, 'hello-from-operator']]);
    host.ws.send(Buffer.from('hello-from-host'));
    await until(() => op.got.length >= 1, 'the operator to hear the host');
    assert.deepEqual(op.got.map((m) => [m.isBinary, String(m.bytes)]), [[true, 'hello-from-host']], 'the operator never sees the signal');
  });

  it('what the partner said BEFORE the host arrived still follows the signal', async () => {
    const id = newRendezvousId();
    const op = dial(id, 'operator');
    await op.open;
    op.ws.send(Buffer.from('early'));
    await sleep(50);
    const host = dial(id, 'host', { notifyPaired: true });
    await until(() => host.got.length >= 2, 'the host to hear both frames');
    assert.deepEqual(host.got.map((m) => m.text ?? String(m.bytes)), [PAIRED_FRAME, 'early']);
  });

  it('a host that did not ask is never sent a text frame (what a released host sees), and the operator asking changes nothing', async () => {
    const id = newRendezvousId();
    const host = dial(id, 'host');
    await host.open;
    const op = new WsClient(`${url}/r/${id}?paired=1`);
    sockets.push(op);
    const opGot = []; op.on('message', (d, isBinary) => opGot.push(isBinary)); op.on('error', () => {});
    await new Promise((r) => op.once('open', r));
    op.send(Buffer.from('x'));
    await until(() => host.got.length >= 1, 'the host to hear the operator');
    assert.deepEqual(host.got.map((m) => m.isBinary), [true]);
    host.ws.send(Buffer.from('y'));
    await until(() => opGot.length >= 1, 'the operator to hear the host');
    assert.deepEqual(opGot, [true]);
  });

  it('accept() takes notifyPaired for an embedder that routes its own upgrades; for an operator it is refused', async () => {
    const r = createPipeRelay();
    const fake = () => {
      const s = { sent: [], readyState: 1, listeners: {}, send(d) { this.sent.push(typeof d === 'string' ? d : `bin:${d.length}`); }, close() { this.readyState = 3; }, on(ev, fn) { this.listeners[ev] = fn; } };
      return s;
    };
    const id = newRendezvousId();
    const host = fake(); const op = fake();
    assert.equal(await r.accept(host, { id, role: 'host', notifyPaired: true }), true);
    assert.deepEqual(host.sent, [], 'nothing before the partner');
    assert.equal(await r.accept(op, { id, role: 'operator' }), true);
    assert.deepEqual(host.sent, [PAIRED_FRAME]);
    assert.deepEqual(op.sent, []);
    await r.close();
    await assert.rejects(r.accept(fake(), { id: newRendezvousId(), role: 'operator', notifyPaired: true }), /host/);
  });

  it('watchPairing: the promise settles on the signal, the frame never reaches the wsh host, the bytes after it do', async () => {
    const id = newRendezvousId();
    const hostWs = new WsClient(pipeUrl(url, id, 'host', { notifyPaired: true }));
    sockets.push(hostWs);
    await new Promise((r) => hostWs.once('open', r));
    const { socket, paired } = watchPairing(hostWs);
    const heard = [];
    socket.on('message', (d, isBinary) => heard.push([isBinary, isBinary ? String(Buffer.from(d)) : d.toString()]));
    let settled = false; paired.then(() => { settled = true; });
    await sleep(100);
    assert.equal(settled, false);
    const op = dial(id, 'operator'); await op.open;
    op.ws.send(Buffer.from('payload'));
    await paired;
    await until(() => heard.length >= 1, 'the payload');
    assert.deepEqual(heard, [[true, 'payload']], 'the signal is not in what the host reads');
  });

  it('watchPairing rejects when the socket closes before a partner arrives', async () => {
    const id = newRendezvousId();
    const hostWs = new WsClient(pipeUrl(url, id, 'host', { notifyPaired: true }));
    sockets.push(hostWs);
    hostWs.on('error', () => {});
    await new Promise((r) => hostWs.once('open', r));
    const { paired } = watchPairing(hostWs);
    hostWs.close(1000);
    await assert.rejects(paired, /closed before/);
  });

  it('a wsh host served through watchPairing completes a login, and learns of the pairing first', async () => {
    const alice = await generateKeyPair(true);
    const server = createWshServer({ auth: { authorizedKeys: `${await exportPublicKeySSH(alice.publicKey)} alice` }, exec: true });
    const id = newRendezvousId();
    const hostWs = new WsClient(pipeUrl(url, id, 'host', { notifyPaired: true }));
    sockets.push(hostWs);
    await new Promise((r) => hostWs.once('open', r));
    const { socket, paired } = watchPairing(hostWs);
    let pairedAt = null; let acceptedAt = null; let tick = 0;
    paired.then(() => { pairedAt = ++tick; });
    await server.accept(socket); acceptedAt = ++tick;
    const client = new WshClient();
    try {
      await client.connect(pipeUrl(url, id), { username: 'alice', keyPair: alice, timeout: 4000 });
      await paired;
      assert.ok(pairedAt !== null && acceptedAt !== null);
      const sess = await client.openSession({ type: 'exec', command: 'echo ok' });
      const chunks = []; await new Promise((resolve) => { sess.onData = (d) => chunks.push(Buffer.from(d)); sess.onClose = resolve; });
      assert.equal(Buffer.concat(chunks).toString(), 'ok\n');
    } finally { await client.disconnect().catch(() => {}); await server.close(); }
  });
});
