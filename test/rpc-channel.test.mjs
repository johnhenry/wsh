// wsh #85: JSON-RPC 2.0 correlation, cancellation, progress and close semantics, over an in-memory pipe.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cborEncode, RpcChannel, RpcError, RPC_ERROR, CborSequenceDecoder } from '@johnhenry/wsh';

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

function pair(optsA = {}, optsB = {}) {
  let a; let b;
  const link = (peer, chunked) => async (bytes) => {
    await tick();
    if (chunked) { const h = bytes.length >> 1; peer().feed(bytes.subarray(0, h)); peer().feed(bytes.subarray(h)); } else peer().feed(bytes);
  };
  a = new RpcChannel({ write: link(() => b, true), close: async () => { b.handleClose('peer-closed'); }, ...optsA });
  b = new RpcChannel({ write: link(() => a, false), close: async () => { a.handleClose('peer-closed'); }, ...optsB });
  return [a, b];
}

/** A channel whose peer is a raw byte sink/source, for exercising misbehaving peers. */
function raw(opts = {}) {
  const sent = []; const dec = new CborSequenceDecoder();
  const ch = new RpcChannel({ write: async (bytes) => { sent.push(...dec.feed(bytes)); }, close: async () => {}, ...opts });
  const inject = (msg) => ch.feed(cborEncode(msg));
  return { ch, sent, inject };
}

describe('RpcChannel correlation', () => {
  it('two concurrent requests answered out of order each get their own result', async () => {
    const [a, b] = pair();
    b.onRequest('slow', async () => { await tick(40); return 'slow-result'; });
    b.onRequest('fast', async () => 'fast-result');
    const [s, f] = await Promise.all([a.request('slow'), a.request('fast')]);
    assert.equal(s, 'slow-result');
    assert.equal(f, 'fast-result');
  });

  it('matches responses by id only, never by arrival order or shape', async () => {
    const { ch, sent, inject } = raw();
    const p1 = ch.request('one'); const p2 = ch.request('two');
    await tick();
    assert.deepEqual(sent.map((m) => m.method), ['one', 'two']);
    inject({ jsonrpc: '2.0', id: sent[1].id, result: 'for-two' });
    inject({ jsonrpc: '2.0', id: sent[0].id, result: 'for-one' });
    assert.equal(await p1, 'for-one');
    assert.equal(await p2, 'for-two');
  });

  it('a late response after cancel is dropped, and the callee is told', async () => {
    const { ch, sent, inject } = raw();
    const p = ch.request('work');
    await tick();
    const id = sent[0].id;
    p.cancel();
    await assert.rejects(p, (e) => e instanceof RpcError && e.code === RPC_ERROR.CANCELLED);
    await tick();
    assert.deepEqual(sent[1], { jsonrpc: '2.0', method: '$/cancel', params: { id } });
    inject({ jsonrpc: '2.0', id, result: 'too late' }); // must be ignored, not throw
    await tick();
    assert.equal(ch.pendingCount, 0);
  });

  it('an AbortSignal cancels a request', async () => {
    const [a, b] = pair();
    let calleeAborted = false;
    b.onRequest('wait', (_p, { signal }) => new Promise((_, rej) => signal.addEventListener('abort', () => { calleeAborted = true; rej(new Error('x')); })));
    const ac = new AbortController();
    const p = a.request('wait', {}, { signal: ac.signal });
    await tick(10);
    ac.abort();
    await assert.rejects(p, (e) => e.code === RPC_ERROR.CANCELLED);
    await tick(20);
    assert.equal(calleeAborted, true);
  });

  it('$/cancel makes the callee answer -32001 promptly and suppresses the handler result', async () => {
    const { ch, sent, inject } = raw();
    let release; let signalAborted = false;
    ch.onRequest('hang', (_p, { signal }) => new Promise((resolve) => { release = resolve; signal.addEventListener('abort', () => { signalAborted = true; }); }));
    inject({ jsonrpc: '2.0', id: 7, method: 'hang' });
    await tick();
    inject({ jsonrpc: '2.0', method: '$/cancel', params: { id: 7 } });
    await tick();
    assert.equal(signalAborted, true);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].id, 7);
    assert.equal(sent[0].error.code, RPC_ERROR.CANCELLED);
    release('late');
    await tick();
    assert.equal(sent.length, 1, 'the late handler result is not sent');
  });

  it('channel close rejects every pending request with -32001 channel-closed', async () => {
    const [a, b] = pair();
    b.onRequest('never', () => new Promise(() => {}));
    const ps = [a.request('never'), a.request('never')];
    ps.forEach((p) => p.catch(() => {}));
    await tick(10);
    await b.close();
    for (const p of ps) {
      await assert.rejects(p, (e) => e.code === RPC_ERROR.CANCELLED && e.reason === 'channel-closed');
    }
    await assert.rejects(a.request('after'), (e) => e.code === RPC_ERROR.CANCELLED && e.reason === 'channel-closed');
  });

  it('per-request timeout rejects with -32001 and cancels the callee', async () => {
    const { ch, sent } = raw();
    const p = ch.request('slow', {}, { timeoutMs: 20 });
    await assert.rejects(p, (e) => e.code === RPC_ERROR.CANCELLED && e.reason === 'timeout');
    await tick();
    assert.equal(sent[1].method, '$/cancel');
  });
});

describe('RpcChannel semantics', () => {
  it('is bidirectional: both sides request and notify', async () => {
    const [a, b] = pair();
    const seen = [];
    a.onRequest('ping-client', () => 'from-client');
    b.onRequest('ping-server', () => 'from-server');
    b.onNotification('hello', (p) => seen.push(p));
    assert.equal(await a.request('ping-server'), 'from-server');
    assert.equal(await b.request('ping-client'), 'from-client');
    a.notify('hello', { n: 1 });
    await tick(10);
    assert.deepEqual(seen, [{ n: 1 }]);
  });

  it('binary params and results survive as Uint8Array', async () => {
    const [a, b] = pair();
    b.onRequest('echo', (p) => ({ back: p.bytes }));
    const r = await a.request('echo', { bytes: new Uint8Array([9, 8, 7]) });
    assert.ok(r.back instanceof Uint8Array);
    assert.deepEqual([...r.back], [9, 8, 7]);
  });

  it('progress notifications reach request({ onProgress }) in order, before the result', async () => {
    const [a, b] = pair();
    b.onRequest('stream', async (_p, { progress }) => { await progress('a'); await progress('b'); await progress('c'); return 'done'; });
    const chunks = [];
    const p = a.request('stream', {}, { onProgress: (c) => chunks.push(c) });
    assert.equal(await p, 'done');
    assert.deepEqual(chunks, ['a', 'b', 'c']);
  });

  it('onProgress(id, fn) works on a request already in flight', async () => {
    const [a, b] = pair();
    b.onRequest('stream', async (_p, { progress }) => { await tick(20); await progress(1); return 'ok'; });
    const chunks = [];
    const p = a.request('stream');
    a.onProgress(p.id, (c) => chunks.push(c));
    await p;
    assert.deepEqual(chunks, [1]);
  });

  it('unknown method -> -32601; handler throw -> -32603; RpcError passes through with data', async () => {
    const [a, b] = pair();
    b.onRequest('boom', () => { throw new Error('kaput'); });
    b.onRequest('typed', () => { throw new RpcError(-32602, 'bad params', { field: 'x' }); });
    await assert.rejects(a.request('nope'), (e) => e instanceof RpcError && e.code === RPC_ERROR.METHOD_NOT_FOUND);
    await assert.rejects(a.request('boom'), (e) => e.code === RPC_ERROR.INTERNAL && /kaput/.test(e.message));
    await assert.rejects(a.request('typed'), (e) => e.code === -32602 && e.data.field === 'x');
  });

  it('a malformed message gets -32600 and an unknown notification is ignored', async () => {
    const { ch, sent, inject } = raw();
    inject({ jsonrpc: '1.0', id: 3, method: 'x' });
    inject({ jsonrpc: '2.0', method: 'who-knows' });
    inject({ jsonrpc: '2.0', id: {}, method: 'x' });
    await tick();
    assert.equal(sent[0].error.code, RPC_ERROR.INVALID_REQUEST);
    assert.equal(sent[0].id, 3);
    assert.equal(sent[1].error.code, RPC_ERROR.INVALID_REQUEST);
    assert.equal(sent[1].id, null);
    assert.equal(sent.length, 2);
    assert.equal(ch.closed, false);
  });

  it('a duplicate in-flight id is refused; the in-flight cap answers -32002', async () => {
    const { ch, sent, inject } = raw({ maxInflight: 2 });
    ch.onRequest('hang', () => new Promise(() => {}));
    inject({ jsonrpc: '2.0', id: 1, method: 'hang' });
    inject({ jsonrpc: '2.0', id: 1, method: 'hang' });
    inject({ jsonrpc: '2.0', id: 2, method: 'hang' });
    inject({ jsonrpc: '2.0', id: 3, method: 'hang' });
    await tick();
    assert.equal(sent.find((m) => m.id === 3).error.code, RPC_ERROR.STREAM_LIMIT);
    assert.equal(sent.filter((m) => m.id === 1).length, 1);
    assert.equal(sent.find((m) => m.id === 1).error.code, RPC_ERROR.INVALID_REQUEST);
  });

  it('garbage bytes: -32700 is sent and the channel closes', async () => {
    const { ch, sent } = raw();
    let closedWith = null;
    ch.onClose = (reason) => { closedWith = reason; };
    ch.feed(new Uint8Array([0x1c]));
    await tick();
    assert.equal(sent[0].error.code, RPC_ERROR.PARSE);
    assert.equal(sent[0].id, null);
    assert.equal(ch.closed, true);
    assert.equal(closedWith, 'parse-error');
  });

  it('an oversized inbound message closes the channel; an oversized outbound one is refused locally', async () => {
    const { ch, sent } = raw({ maxMessageBytes: 256 });
    await assert.rejects(ch.request('big', { b: new Uint8Array(1000) }), (e) => e.reason === 'message-too-large');
    assert.equal(sent.length, 0);
    ch.feed(cborEncode({ jsonrpc: '2.0', id: 1, method: 'x', params: { b: new Uint8Array(1000) } }));
    await tick();
    assert.equal(ch.closed, true);
    assert.equal(sent[0].error.code, RPC_ERROR.INVALID_REQUEST);
  });

  it('timeoutMs from the constructor applies to every request', async () => {
    const { ch } = raw({ timeoutMs: 15 });
    await assert.rejects(ch.request('x'), (e) => e.reason === 'timeout');
  });

  it('fallback handlers see unregistered methods and notifications', async () => {
    const [a, b] = pair();
    const notes = [];
    b.setFallbackRequestHandler(async (method, params) => ({ method, params }));
    b.setFallbackNotificationHandler((method, params) => notes.push([method, params]));
    assert.deepEqual(await a.request('anything', { q: 1 }), { method: 'anything', params: { q: 1 } });
    a.notify('whatever', [1]);
    await tick(10);
    assert.deepEqual(notes, [['whatever', [1]]]);
  });
});
