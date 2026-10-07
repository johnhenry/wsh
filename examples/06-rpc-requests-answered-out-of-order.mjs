/**
 * Typed RPC channels: JSON-RPC 2.0 over a CBOR sequence, correlated by id (wsh #85).
 *
 * Two RpcChannels are joined by an in-process pipe that fragments every write, the way a real stream would. A slow
 * and a fast request are in flight at once: the fast answer overtakes the slow one and each caller still gets its
 * own result, because responses are matched by id and never by arrival order. A streaming read delivers
 * `$/progress` chunks before its final result, and a cancelled request drops its late answer.
 */

import assert from 'node:assert/strict';
import { RpcChannel, RpcError, RPC_ERROR } from '@johnhenry/wsh';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let client; let host;
const pipe = (peer) => async (bytes) => {
  await sleep(0);
  const mid = Math.max(1, bytes.length >> 1); // split every write: CBOR items are self-delimiting
  peer().feed(bytes.subarray(0, mid));
  peer().feed(bytes.subarray(mid));
};
client = new RpcChannel({ write: pipe(() => host), close: () => host.handleClose('peer-closed') });
host = new RpcChannel({ write: pipe(() => client), close: () => client.handleClose('peer-closed') });

host.onRequest('slow', async () => { await sleep(60); return 'slow done'; });
host.onRequest('fast', () => 'fast done');
host.onRequest('blob', async (_p, { progress }) => {
  for (let i = 0; i < 3; i++) await progress(new Uint8Array([i, i, i]));
  return { chunks: 3 };
});
let abortedByCallee = false;
host.onRequest('hang', (_p, { signal }) => new Promise((resolve) => signal.addEventListener('abort', () => { abortedByCallee = true; resolve('too late'); })));

const order = [];
const [slow, fast] = await Promise.all([
  client.request('slow').then((r) => { order.push('slow'); return r; }),
  client.request('fast').then((r) => { order.push('fast'); return r; }),
]);
assert.deepEqual(order, ['fast', 'slow'], 'the fast answer overtook the slow one');
assert.equal(slow, 'slow done');
assert.equal(fast, 'fast done');

const chunks = [];
const summary = await client.request('blob', {}, { onProgress: (c) => chunks.push([...c]) });
assert.deepEqual(chunks, [[0, 0, 0], [1, 1, 1], [2, 2, 2]]);
assert.deepEqual(summary, { chunks: 3 });

const hung = client.request('hang');
await sleep(20);
hung.cancel();
await assert.rejects(hung, (e) => e instanceof RpcError && e.code === RPC_ERROR.CANCELLED);
await sleep(20);
assert.equal(abortedByCallee, true, 'the callee saw $/cancel');

await assert.rejects(client.request('missing'), (e) => e.code === RPC_ERROR.METHOD_NOT_FOUND);
console.log('ok: out-of-order answers, $/progress chunks, $/cancel, and -32601 all behaved');
