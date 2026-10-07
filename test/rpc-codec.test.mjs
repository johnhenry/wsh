// wsh #85: CBOR-sequence framing for typed RPC channels.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  cborEncode, CborSequenceDecoder, RpcError, RPC_FEATURE, RPC_ERROR, RPC_DEFAULT_MAX_MESSAGE,
  rpcProtocolFeature, parseRpcFeatures,
} from '@johnhenry/wsh';

const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

describe('CborSequenceDecoder', () => {
  const items = [
    { jsonrpc: '2.0', id: 1, method: 'a', params: { x: [1, 2, 3], s: 'héllo' } },
    { jsonrpc: '2.0', method: 'n' },
    [1, -5, 70000, 4294967296, 1.5, true, false, null],
    'plain text',
    new Uint8Array([0, 1, 2, 255]),
  ];

  it('decodes concatenated items from one buffer', () => {
    const d = new CborSequenceDecoder();
    const out = d.feed(cat(...items.map(cborEncode)));
    assert.deepEqual(out, items);
    assert.equal(d.pending, 0);
  });

  it('decodes the same sequence fed one byte at a time', () => {
    const d = new CborSequenceDecoder();
    const out = [];
    for (const b of cat(...items.map(cborEncode))) out.push(...d.feed(new Uint8Array([b])));
    assert.deepEqual(out, items);
  });

  it('decodes across arbitrary split points (item boundaries inside a chunk)', () => {
    const all = cat(...items.map(cborEncode));
    for (const cut of [1, 3, 7, 19, all.length - 1]) {
      const d = new CborSequenceDecoder();
      const out = [...d.feed(all.subarray(0, cut)), ...d.feed(all.subarray(cut))];
      assert.deepEqual(out, items, `cut at ${cut}`);
    }
  });

  it('round-trips binary values as Uint8Array, including large ones', () => {
    const big = new Uint8Array(300_000).map((_, i) => i % 251);
    const d = new CborSequenceDecoder({ maxItemBytes: 1 << 20 });
    const [out] = d.feed(cborEncode({ blob: big }));
    assert.ok(out.blob instanceof Uint8Array);
    assert.deepEqual(out.blob, big);
  });

  it('handles indefinite-length items and tags', () => {
    const d = new CborSequenceDecoder();
    // [_ 1, 2] , {_ "a": 1} , (_ h'01', h'02') , tag(1)(5)
    const bytes = new Uint8Array([0x9f, 1, 2, 0xff, 0xbf, 0x61, 0x61, 1, 0xff, 0x5f, 0x41, 1, 0x41, 2, 0xff, 0xc1, 5]);
    assert.deepEqual(d.feed(bytes), [[1, 2], { a: 1 }, new Uint8Array([1, 2]), 5]);
  });

  it('rejects an item larger than the limit as soon as its head says so', () => {
    const d = new CborSequenceDecoder({ maxItemBytes: 1024 });
    const head = new Uint8Array([0x5a, 0, 0x10, 0, 0]); // byte string of 1 MiB, no payload yet
    assert.throws(() => d.feed(head), (e) => e instanceof RpcError && e.code === RPC_ERROR.INVALID_REQUEST && e.reason === 'message-too-large');
  });

  it('rejects an item that grows past the limit across feeds', () => {
    const d = new CborSequenceDecoder({ maxItemBytes: 1024 });
    const arr = cborEncode(new Array(2000).fill(1)); // 2003 bytes, many small items
    assert.throws(() => { d.feed(arr.subarray(0, 600)); d.feed(arr.subarray(600, 1500)); }, (e) => e.reason === 'message-too-large');
  });

  it('accepts an item exactly at the limit', () => {
    const msg = cborEncode(new Uint8Array(1000));
    const d = new CborSequenceDecoder({ maxItemBytes: msg.length });
    assert.equal(d.feed(msg).length, 1);
  });

  it('reports malformed CBOR as a parse error (-32700)', () => {
    assert.throws(() => new CborSequenceDecoder().feed(new Uint8Array([0x1c])), (e) => e instanceof RpcError && e.code === RPC_ERROR.PARSE);
    assert.throws(() => new CborSequenceDecoder().feed(new Uint8Array([0xff])), (e) => e.code === RPC_ERROR.PARSE);
  });

  it('rejects absurdly deep nesting instead of overflowing the stack', () => {
    const deep = new Uint8Array(100_000).fill(0x81);
    assert.throws(() => new CborSequenceDecoder({ maxItemBytes: 1 << 20 }).feed(deep), (e) => e.code === RPC_ERROR.PARSE);
  });
});

describe('rpc feature strings', () => {
  it('names are stable', () => {
    assert.equal(RPC_FEATURE, 'rpc');
    assert.equal(rpcProtocolFeature('mcp'), 'rpc-protocol:mcp');
    assert.equal(RPC_DEFAULT_MAX_MESSAGE, 1024 * 1024);
  });

  it('parseRpcFeatures reads protocols and the max message size', () => {
    const f = parseRpcFeatures(['stream-announce', 'rpc', 'rpc-protocol:mcp', 'rpc-protocol:wsh-fs', 'rpc-max-message:2048']);
    assert.deepEqual(f, { enabled: true, protocols: ['mcp', 'wsh-fs'], maxMessageBytes: 2048 });
    assert.deepEqual(parseRpcFeatures(['rpc', 'rpc-protocol:x']), { enabled: true, protocols: ['x'], maxMessageBytes: RPC_DEFAULT_MAX_MESSAGE });
    assert.deepEqual(parseRpcFeatures(['stream-announce']), { enabled: false, protocols: [], maxMessageBytes: RPC_DEFAULT_MAX_MESSAGE });
    assert.equal(parseRpcFeatures(['rpc', 'rpc-max-message:nope']).maxMessageBytes, RPC_DEFAULT_MAX_MESSAGE);
  });
});
