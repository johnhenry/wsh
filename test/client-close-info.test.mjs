// test/client-close-info.test.mjs -- #240: why did the client's own connection close? `client.onClose(info)` and `client.closeInfo` carry
// `{ source, code, reason, wasClean }`; callers that do not read them are unaffected; `client.close()` is `disconnect()`.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw } from '@johnhenry/wsh';
import { WshTransport, WebTransportTransport } from '../src/transport.mjs';
import { MSG, serverHello } from '../src/messages.gen.mjs';
import { createInProcessPipeRelay } from '@johnhenry/wsh/testing';
import { pipeUrl, newRendezvousId } from '@johnhenry/wsh/pipe-relay';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { encodeRecord, encodeConnectionClose } from '../src/qmux.mjs';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A WebSocket the test drives: open it, close it with a code and reason, as a server or a relay would. */
class FakeWebSocket {
  static instances = [];
  readyState = 0;
  binaryType = '';
  #listeners = new Map();
  constructor(url) { this.url = url; FakeWebSocket.instances.push(this); }
  addEventListener(type, fn) { (this.#listeners.get(type) ?? this.#listeners.set(type, []).get(type)).push(fn); }
  removeEventListener() {}
  #emit(type, ev) { for (const fn of [...(this.#listeners.get(type) ?? [])]) fn(ev); }
  send() {}
  close(code = 1000, reason = '') { this.#end({ code, reason, wasClean: true }); }
  open() { this.readyState = 1; this.#emit('open', {}); }
  message(bytes) { this.#emit('message', { data: bytes }); }
  /** The socket ended: `ev` is the close event as the platform delivers it. */
  end(ev) { this.#end(ev); }
  #end(ev) { if (this.readyState === 3) return; this.readyState = 3; this.#emit('close', ev); }
}
const nextTick = () => new Promise((r) => setTimeout(r, 0));

async function connectedTransport() {
  FakeWebSocket.instances = [];
  const transport = new WebSocketTransport({ WebSocket: FakeWebSocket });
  const connecting = transport.connect('ws://test.invalid');
  const ws = FakeWebSocket.instances.at(-1);
  ws.open();
  await connecting;
  return { transport, ws };
}

describe('WebSocketTransport reports why it closed', () => {
  it('a close the peer made: the socket\'s code, reason and cleanliness', async () => {
    const { transport, ws } = await connectedTransport();
    const got = [];
    transport.onClose = (info) => got.push(info);
    ws.end({ code: 4001, reason: 'maximum lifetime reached', wasClean: true });
    await nextTick();
    assert.deepEqual(got, [{ source: 'websocket', code: 4001, reason: 'maximum lifetime reached', wasClean: true }]);
    assert.deepEqual(transport.closeInfo, got[0]);
  });

  it('an abnormal close (1006, nothing said) is not clean', async () => {
    const { transport, ws } = await connectedTransport();
    const got = [];
    transport.onClose = (info) => got.push(info);
    ws.end({ code: 1006, reason: '', wasClean: false });
    await nextTick();
    assert.deepEqual(got, [{ source: 'websocket', code: 1006, reason: '', wasClean: false }]);
  });

  it('a socket that reports no wasClean is clean only for 1000', async () => {
    const a = await connectedTransport();
    a.ws.end({ code: 1000, reason: '' });
    await nextTick();
    assert.equal(a.transport.closeInfo.wasClean, true);
    const b = await connectedTransport();
    b.ws.end({ code: 1011, reason: 'error' });
    await nextTick();
    assert.equal(b.transport.closeInfo.wasClean, false);
  });

  it('a CONNECTION_CLOSE from the peer is reported with the QMux error code', async () => {
    const { transport, ws } = await connectedTransport();
    const got = [];
    transport.onClose = (info) => got.push(info);
    ws.message(encodeRecord(encodeConnectionClose({ application: true, errorCode: 7, reason: 'going away' })));
    await nextTick();
    assert.deepEqual(got, [{ source: 'qmux', code: 7, reason: 'going away', wasClean: true }]);
  });

  it('closing it ourselves gives no info (and still calls onClose with none)', async () => {
    const { transport } = await connectedTransport();
    const got = [];
    transport.onClose = (...args) => got.push(args);
    await transport.close();
    await nextTick();
    assert.equal(transport.closeInfo, null);
    assert.ok(got.every((a) => a.length === 0 || a[0] === undefined), 'a close we made is not a reason to hear about');
  });
});

describe('WebTransportTransport reports why the session closed', () => {
  /** A WebTransport whose `closed` the test settles. */
  function fakeWebTransport() {
    let settle; let fail; let control;
    const closed = new Promise((resolve, reject) => {
      // The control stream ends with the session, as a real one does; the close is reported after it.
      settle = (v) => { control?.close(); resolve(v); };
      fail = (e) => { control?.close(); reject(e); };
    });
    class FakeWebTransport {
      ready = Promise.resolve();
      closed = closed;
      createBidirectionalStream() { return Promise.resolve({ readable: new ReadableStream({ start(c) { control = c; } }), writable: new WritableStream() }); }
      get incomingBidirectionalStreams() { return new ReadableStream({ start() {} }); }
      close() {}
    }
    return { FakeWebTransport, settle, fail };
  }
  const withGlobal = async (FakeWebTransport, fn) => {
    const saved = globalThis.WebTransport;
    globalThis.WebTransport = FakeWebTransport;
    try { await fn(); } finally { if (saved === undefined) delete globalThis.WebTransport; else globalThis.WebTransport = saved; }
  };

  it('a session closed with a code and reason: both, and clean', async () => {
    const { FakeWebTransport, settle } = fakeWebTransport();
    await withGlobal(FakeWebTransport, async () => {
      const t = new WebTransportTransport();
      await t.connect('https://example.test:4433/wsh');
      const closed = new Promise((resolve) => { t.onClose = resolve; });
      settle({ closeCode: 42, reason: 'draining' });
      assert.deepEqual(await closed, { source: 'webtransport', code: 42, reason: 'draining', wasClean: true });
    });
  });

  it('a session that failed: the error text, not clean, no code', async () => {
    const { FakeWebTransport, fail } = fakeWebTransport();
    await withGlobal(FakeWebTransport, async () => {
      const t = new WebTransportTransport();
      await t.connect('https://example.test:4433/wsh');
      t.onError = () => {};
      const closed = new Promise((resolve) => { t.onClose = resolve; });
      fail(new Error('connection lost'));
      assert.deepEqual(await closed, { source: 'webtransport', code: null, reason: 'connection lost', wasClean: false });
    });
  });
});

/** A transport that reaches `authenticated` by itself and lets the test end it with whatever info it likes. */
class ScriptedTransport extends WshTransport {
  async _doConnect() {}
  async _doClose() {}
  async _doOpenStream() { throw new Error('not used'); }
  async _doSendControl(msg) {
    if (msg.type === MSG.HELLO) {
      setTimeout(() => this._emitControl(serverHello({ sessionId: 's', features: [], fingerprints: [] })), 0);
      setTimeout(() => this._emitControl({ type: MSG.CHALLENGE, nonce: new Uint8Array(32).fill(7), session_id: 's' }), 0);
    } else if (msg.type === MSG.AUTH) setTimeout(() => this._emitControl({ type: MSG.AUTH_OK }), 0);
  }
}
async function scripted() {
  const transport = new ScriptedTransport();
  const client = new WshClient({ transportFactories: { ws: () => transport } });
  await client.connect('ws://test.invalid', { username: 'alice', keyPair: await generateKeyPair(true), transport: 'ws' });
  return { client, transport };
}

describe('WshClient.onClose and closeInfo', () => {
  it('a client that never reads them is unaffected: onClose is called, with the info as an extra argument', async () => {
    const { client, transport } = await scripted();
    assert.equal(client.closeInfo, null, 'nothing before a close');
    let calls = 0;
    client.onClose = function legacy() { calls++; };
    transport._emitClose({ source: 'websocket', code: 1001, reason: 'bye', wasClean: true });
    await sleep(10);
    assert.equal(calls, 1);
    assert.equal(client.state, 'closed');
  });

  it('onClose gets { source, code, reason, wasClean } and closeInfo keeps them', async () => {
    const { client, transport } = await scripted();
    const got = [];
    client.onClose = (info) => got.push(info);
    transport._emitClose({ source: 'websocket', code: 1008, reason: 'byte limit reached', wasClean: true });
    await sleep(10);
    assert.deepEqual(got, [{ source: 'websocket', code: 1008, reason: 'byte limit reached', wasClean: true }]);
    assert.deepEqual(client.closeInfo, got[0]);
  });

  it('a transport that says nothing (a custom one) gives an honest unknown, not an invented code', async () => {
    const { client, transport } = await scripted();
    const got = [];
    client.onClose = (info) => got.push(info);
    transport._emitClose();
    await sleep(10);
    assert.deepEqual(got, [{ source: 'transport', code: null, reason: '', wasClean: false }]);
  });

  it('what a transport hands over is copied and bounded: a long reason is cut, a wrong type is dropped', async () => {
    const { client, transport } = await scripted();
    transport._emitClose({ source: 'websocket', code: 'x', reason: 'r'.repeat(5000), wasClean: 'yes', extra: 1 });
    await sleep(10);
    assert.deepEqual(Object.keys(client.closeInfo).sort(), ['code', 'reason', 'source', 'wasClean']);
    assert.equal(client.closeInfo.code, null);
    assert.equal(client.closeInfo.wasClean, false);
    assert.ok(client.closeInfo.reason.length <= 256);
  });

  it('a close we made (disconnect()) does not call onClose and leaves closeInfo empty, as before', async () => {
    const { client } = await scripted();
    let calls = 0;
    client.onClose = () => { calls++; };
    await client.disconnect();
    await sleep(20);
    assert.equal(calls, 0);
    assert.equal(client.closeInfo, null);
  });

  it('a handler that throws does not stop the close', async () => {
    const { client, transport } = await scripted();
    client.onClose = () => { throw new Error('handler'); };
    const original = console.error; console.error = () => {};
    try { transport._emitClose({ source: 'websocket', code: 1000, reason: '', wasClean: true }); await sleep(10); } finally { console.error = original; }
    assert.equal(client.state, 'closed');
    assert.equal(client.closeInfo.code, 1000);
  });

  it('connect() again clears the last close', async () => {
    const { client, transport } = await scripted();
    transport._emitClose({ source: 'websocket', code: 1001, reason: 'a', wasClean: true });
    await sleep(10);
    assert.ok(client.closeInfo);
    const next = new ScriptedTransport();
    const again = new WshClient({ transportFactories: { ws: () => next } });
    assert.equal(again.closeInfo, null);
  });
});

describe('a relay limit reaches the client as a reason it can read (the page-to-page link of #240)', () => {
  it('maxLifetimeMs: the operator\'s onClose says maximum lifetime reached, code 1000', async () => {
    const env = await createInProcessPipeRelay({ relayOptions: { maxLifetimeMs: 400 } });
    closers.push(() => env.close());
    const keyPair = await generateKeyPair(true);
    const host = createMemoryHost({ auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] }, exec: async () => 0, hostKey: true, dataStreams: false, sealSession: 'require' });
    closers.push(() => host.close());
    const id = newRendezvousId();
    void host.accept(new env.WebSocket(pipeUrl('ws://relay.test', id, 'host')), { remote: { address: 'pipe' } });
    const client = new WshClient({ transportFactories: { ws: () => new WebSocketTransport({ WebSocket: env.WebSocket }), wt: () => { throw new Error('no webtransport'); } } });
    closers.push(() => client.disconnect());
    const closed = new Promise((resolve) => { client.onClose = resolve; });
    await client.connect(pipeUrl('ws://relay.test', id), { transport: 'ws', username: 'alice', keyPair });
    const info = await closed;
    assert.equal(info.source, 'websocket');
    assert.equal(info.code, 1000);
    assert.equal(info.reason, 'maximum lifetime reached');
    assert.equal(info.wasClean, true);
  });
});

describe('close() is disconnect()', () => {
  it('close() disconnects and resolves; it is idempotent, like disconnect()', async () => {
    const { client } = await scripted();
    assert.equal(client.state, 'authenticated');
    await client.close();
    assert.equal(client.state, 'closed');
    await client.close();
    await client.disconnect();
  });

  it('close() before a connect is a no-op', async () => {
    const client = new WshClient();
    await client.close();
    assert.equal(client.state, 'disconnected');
  });

  it('the same promise behaviour: close() on a client mid-use ends its sessions', async () => {
    const { client } = await scripted();
    const p = client.close();
    assert.ok(p instanceof Promise);
    await p;
    assert.equal(client.state, 'closed');
  });
});
