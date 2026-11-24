// `@johnhenry/wsh/testing`: an in-process pipe relay and a memory host/client pair, as test doubles for code that embeds wsh (#220).
// Not part of the stable API (the entry says so); these tests pin what a consumer's tests lean on today.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createInProcessPipeRelay, createMemoryPair } from '@johnhenry/wsh/testing';
import { pipeUrl, newRendezvousId } from '@johnhenry/wsh/pipe-relay';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw } from '@johnhenry/wsh';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, what, ms = 4000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(5); }
};
const echo = async (command, io) => { await io.write(`ran:${command}\n`); return 0; };

/** A host served over the relay: its half of the pipe goes to `host.accept`, the operator dials the other. */
async function pipeWorld({ tap, hostOptions = {} } = {}) {
  const env = await createInProcessPipeRelay({ tap });
  closers.push(() => env.close());
  const keyPair = await generateKeyPair(true);
  const raw = await exportPublicKeyRaw(keyPair.publicKey);
  const host = createMemoryHost({ auth: { authorizedKeys: [raw] }, exec: echo, hostKey: true, dataStreams: false, sealSession: 'require', ...hostOptions });
  closers.push(() => host.close());
  const id = newRendezvousId();
  const hostSocket = new env.WebSocket(pipeUrl('ws://relay.test', id, 'host'));
  void host.accept(hostSocket, { remote: { address: 'pipe' } });
  const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport({ WebSocket: env.WebSocket }), wt: () => { throw new Error('no webtransport'); } } });
  closers.push(() => client.disconnect());
  const connect = (extra = {}) => client.connect(pipeUrl('ws://relay.test', id), { transport: 'ws', username: 'alice', keyPair, ...extra });
  return { env, host, client, connect, id };
}

describe('createInProcessPipeRelay', () => {
  it('joins a host and an operator through the real pipe relay: the real handshake, no ports', async () => {
    const { env, client, connect } = await pipeWorld();
    await connect();
    assert.equal(client.state, 'authenticated');
    assert.deepEqual(env.stats(), { waiting: 0, pipes: 1 });
    assert.ok(env.recorded.length > 0);
    assert.deepEqual([...new Set(env.recorded.map((r) => r.to))].sort(), ['host', 'operator']);
    for (const r of env.recorded) { assert.ok(r.bytes instanceof Uint8Array); assert.match(r.id, /^[A-Za-z0-9_-]{22}$/); }
  });

  it('the session is sealed, so what the relay recorded after login is not the plain text of what was run', async () => {
    const { env, client, connect } = await pipeWorld();
    await connect();
    const out = [];
    const session = await client.openSession({ type: 'exec', command: 'marker-command-xyz' });
    session.onData = (d) => out.push(Buffer.from(d));
    await until(() => Buffer.concat(out).toString().includes('ran:marker-command-xyz'), 'the output');
    const all = Buffer.concat(env.recorded.map((r) => Buffer.from(r.bytes))).toString('latin1');
    assert.ok(!all.includes('marker-command-xyz'), 'the relay never saw the command');
  });

  it('tap sees every message the relay writes and may drop one: the connection then does not complete', async () => {
    const seen = [];
    const { env, connect } = await pipeWorld({ tap: ({ to, bytes }) => { seen.push(to); return to === 'operator' ? null : undefined; } });
    await assert.rejects(connect({ timeout: 300 }));
    assert.ok(seen.includes('host'), 'the operator was heard');
    assert.equal(env.recorded.filter((r) => r.to === 'operator').length > 0, true, 'a dropped message is still recorded');
  });

  it('tap may change what is written: replace a message, write it twice, or add another', async () => {
    const mode = { now: 'replace' };
    const env = await createInProcessPipeRelay({ tap: ({ bytes }) => {
      if (mode.now === 'replace') return new Uint8Array([9, 9]);
      if (mode.now === 'repeat') return [bytes, bytes];
      if (mode.now === 'add') return [bytes, new Uint8Array([7])];
      return undefined;
    } });
    closers.push(() => env.close());
    const id = newRendezvousId();
    const host = new env.WebSocket(pipeUrl('ws://relay.test', id, 'host'));
    const operator = new env.WebSocket(pipeUrl('ws://relay.test', id));
    const heard = [];
    host.addEventListener('message', (e) => heard.push([...new Uint8Array(e.data)]));
    await Promise.all([new Promise((r) => host.addEventListener('open', r)), new Promise((r) => operator.addEventListener('open', r))]);
    operator.send(new Uint8Array([1, 2, 3]));
    await until(() => heard.length >= 1, 'the replaced message');
    assert.deepEqual(heard, [[9, 9]], 'what the host got is what tap returned, not what the operator sent');
    assert.deepEqual([...env.recorded[0].bytes], [1, 2, 3], 'the record is of what the relay was given to write, before tap');
    heard.length = 0; mode.now = 'repeat';
    operator.send(new Uint8Array([4]));
    await until(() => heard.length >= 2, 'the repeat');
    assert.deepEqual(heard, [[4], [4]]);
    heard.length = 0; mode.now = 'add';
    operator.send(new Uint8Array([5]));
    await until(() => heard.length >= 2, 'the added message');
    assert.deepEqual(heard, [[5], [7]]);
    heard.length = 0; mode.now = 'pass'; env.tap = null;
    operator.send(new Uint8Array([6]));
    await until(() => heard.length >= 1, 'a message with no tap');
    assert.deepEqual(heard, [[6]]);
  });

  it('dropAll() ends every pipe at once, as a relay restart would', async () => {
    const { env, client, connect } = await pipeWorld();
    await connect();
    const closed = new Promise((r) => { client.onClose = r; });
    env.dropAll();
    await closed;
    await until(() => env.stats().pipes === 0, 'the pipe to end');
  });

  it('options go to createPipeRelay (a message size limit is enforced), and close() ends every pipe', async () => {
    const small = await createInProcessPipeRelay({ relayOptions: { maxMessageBytes: 8 } });
    closers.push(() => small.close());
    const id = newRendezvousId();
    const a = new small.WebSocket(pipeUrl('ws://relay.test', id, 'host'));
    const b = new small.WebSocket(pipeUrl('ws://relay.test', id));
    await Promise.all([new Promise((r) => a.addEventListener('open', r)), new Promise((r) => b.addEventListener('open', r))]);
    const closed = new Promise((r) => b.addEventListener('close', (e) => r(e.code)));
    a.send(new Uint8Array(64));
    assert.equal(await closed, 1009, 'a message over the relay limit closes the pipe');
    const { env, client, connect } = await pipeWorld();
    await connect();
    const gone = new Promise((r) => { client.onClose = r; });
    await env.close();
    await gone;
    assert.equal(client.state, 'closed');
  });
});

describe('createMemoryPair', () => {
  it('gives a connected client and its host, with a key it generated and authorized', async () => {
    const pair = await createMemoryPair({ host: { exec: echo } });
    closers.push(() => pair.close());
    assert.equal(pair.client.state, 'authenticated');
    assert.equal(pair.username, 'alice');
    assert.ok(pair.keyPair.privateKey && pair.host.url);
    const out = [];
    const session = await pair.client.openSession({ type: 'exec', command: 'hi' });
    session.onData = (d) => out.push(Buffer.from(d));
    await until(() => Buffer.concat(out).toString() === 'ran:hi\n', 'the output');
  });

  it('takes the host options as they are, a username, and a key of its own', async () => {
    const keyPair = await generateKeyPair(true);
    const seen = [];
    const pair = await createMemoryPair({ host: { exec: echo, hostKey: true, onLog: (l) => seen.push(l) }, username: 'bob', keyPair });
    closers.push(() => pair.close());
    assert.equal(pair.username, 'bob');
    assert.equal(pair.keyPair, keyPair);
    assert.equal(pair.client.state, 'authenticated');
  });

  it('close() closes the client and the host; the host serves nobody afterwards', async () => {
    const pair = await createMemoryPair({ host: { exec: echo } });
    await pair.close();
    assert.equal(pair.client.state, 'closed');
    await assert.rejects(pair.host.connect({ username: 'alice', keyPair: pair.keyPair, timeout: 300 }));
  });

  it('refuses host options that carry their own auth AND no key to log in with', async () => {
    await assert.rejects(createMemoryPair({ host: { auth: { password: async () => false } } }), /key|credentials|auth/i);
  });

  it('a second client of the same host is available through pair.host.connect()', async () => {
    const pair = await createMemoryPair({ host: { exec: echo } });
    closers.push(() => pair.close());
    const second = await pair.host.connect({ username: 'alice', keyPair: pair.keyPair });
    closers.push(() => second.disconnect());
    assert.equal(second.state, 'authenticated');
  });
});

describe('the entry says what it is', () => {
  it('stays marked as not stable, and the codec exports are still there', async () => {
    const testing = await import('@johnhenry/wsh/testing');
    assert.equal(testing.QMUX_TESTING_API.stable, false);
    assert.equal(typeof testing.encodeRecord, 'function');
    assert.equal(typeof testing.createInProcessPipeRelay, 'function');
    assert.equal(typeof testing.createMemoryPair, 'function');
  });
});
