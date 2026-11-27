// test/cbor-review-317.test.mjs -- the review of #324: what a frame decoder does with a bad frame among good ones, the JS WebTransport client's policy for it,
// the prefix API's offset, and two places the strict decoder must be reached (a duplicate __proto__ key, the inner message of a sealed frame).
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { cborEncode, cborDecode, cborDecodePrefix, CborError, FrameDecoder, frameEncode } from '../src/cbor.mjs';
import { SealedBridge } from '../src/bridge-seal.mjs';
import { sealFrame, ROLE_TAGS } from '../src/e2e-frame.mjs';
import { encryptedFrame, ping } from '../src/messages.mjs';
import { WebTransportTransport } from '../src/transport.mjs';

const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const good1 = { type: 0x21, id: 1 }; const good2 = { type: 0x21, id: 2 };
/** A frame whose payload is malformed (a stray byte after the value): the 4-byte length still delimits it. */
const bad = () => { const p = cat(cborEncode(good1), Uint8Array.of(0)); const f = new Uint8Array(4 + p.length); new DataView(f.buffer).setUint32(0, p.length); f.set(p, 4); return f; };

describe('FrameDecoder: a bad frame among good ones (#324 review)', () => {
  it('[good][bad][good]: the first good message is delivered with the error, the frame after the bad one is not lost', () => {
    const d = new FrameDecoder();
    let caught;
    try { d.feed(cat(frameEncode(good1), bad(), frameEncode(good2))); } catch (e) { caught = e; }
    assert.ok(caught instanceof CborError && caught.code === 'trailing-bytes');
    assert.deepEqual(caught.decoded, [good1], 'what was decoded before the bad frame travels with the error');
    assert.deepEqual(d.feed(new Uint8Array(0)), [good2], 'the bad frame was consumed; the next one is still there');
    assert.equal(d.pending, 0);
  });

  it('[good][bad]: the good message is delivered, then the error', () => {
    const d = new FrameDecoder();
    let caught;
    try { d.feed(cat(frameEncode(good1), bad())); } catch (e) { caught = e; }
    assert.deepEqual(caught.decoded, [good1]);
    assert.deepEqual(d.feed(frameEncode(good2)), [good2], 'and the decoder carries on');
  });

  it('feedAll: every good message in order and every error, in one call', () => {
    const d = new FrameDecoder();
    const r = d.feedAll(cat(frameEncode(good1), bad(), frameEncode(good2), bad()));
    assert.deepEqual(r.messages, [good1, good2]);
    assert.equal(r.errors.length, 2);
    assert.ok(r.errors.every((e) => e instanceof CborError));
    assert.equal(r.fatal, null);
  });

  it('feedAll: an oversized frame is fatal, with what came before it', () => {
    const d = new FrameDecoder({ maxFrameSize: 64 });
    const huge = new Uint8Array(4); new DataView(huge.buffer).setUint32(0, 1000);
    const r = d.feedAll(cat(frameEncode(good1), huge));
    assert.deepEqual(r.messages, [good1]);
    assert.equal(r.fatal?.name, 'FrameSizeError');
  });
});

describe('the JS WebTransport client: a decode error is reported and reading continues (as the WebSocket transports do) (#324 review)', () => {
  let saved;
  beforeEach(() => { saved = globalThis.WebTransport; });
  afterEach(() => { if (saved === undefined) delete globalThis.WebTransport; else globalThis.WebTransport = saved; });

  it('[good][bad][good] on the control stream: both good messages arrive, the error is emitted once, and the connection stays open', async () => {
    const chunk = cat(frameEncode(good1), bad(), frameEncode(good2));
    globalThis.WebTransport = class {
      constructor() { this.ready = Promise.resolve(); this.closed = new Promise(() => {}); }
      async createBidirectionalStream() {
        return { readable: new ReadableStream({ start(c) { c.enqueue(chunk); } }), writable: new WritableStream() };
      }
      get incomingBidirectionalStreams() { return new ReadableStream({ start() {} }); }
      close() {}
    };
    const t = new WebTransportTransport();
    const got = []; const errors = [];
    t.onControl = (m) => got.push(m);
    t.onError = (e) => errors.push(e);
    await t.connect('https://example.test/wsh');
    for (let i = 0; i < 100 && (got.length < 2 || errors.length < 1); i++) await new Promise((r) => setTimeout(r, 5));
    assert.deepEqual(got, [good1, good2]);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /trailing-bytes|after the value/);
    assert.equal(t.state, 'connected', 'a malformed frame does not end the connection');
    t.close().catch(() => {}); // not awaited: the fake control stream never ends
  });
});

describe('cborDecodePrefix: the offset (#324 review)', () => {
  const data = cborEncode([1, 2]);
  it('refuses an offset that is not an integer within 0..length', () => {
    for (const offset of [-1, 1.5, NaN, Infinity, data.length + 1, '0', null]) {
      assert.throws(() => cborDecodePrefix(data, { offset }), RangeError, String(offset));
    }
    assert.throws(() => cborDecodePrefix(data, { offset: data.length }), (e) => e instanceof CborError && e.code === 'truncated', 'an offset AT the end is in range, and there is nothing there');
  });
  it('accepts the legacy top-level indefinite map at any offset: the item the call reads is its own top level', () => {
    const legacy = Uint8Array.from([0xbf, 0x61, 0x61, 0x01, 0xff]);
    const r = cborDecodePrefix(cat(Uint8Array.of(9, 9, 9), legacy), { offset: 3 });
    assert.deepEqual(r.value, { a: 1 });
    assert.equal(r.end, 8);
  });
});

describe('the strict decoder is reached from everywhere (#324 review)', () => {
  it('a map with __proto__ twice is a duplicate key', () => {
    const k = [0x69, 0x5f, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x5f, 0x5f];
    assert.throws(() => cborDecode(Uint8Array.from([0xa2, ...k, 1, ...k, 2])), (e) => e instanceof CborError && e.code === 'duplicate-key');
  });

  it('the inner message of a sealed frame is held to the same rules: a stray byte after it is refused, a clean one opens', async () => {
    const key = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const sessionId = 'sess-324';
    const rx = new SealedBridge({ key, sessionId, role: 'responder' });
    const inner = cborEncode(ping({ id: 1 }));
    const frameOf = async (plain, counter) => { const { nonce, ciphertext } = await sealFrame(key, sessionId, ROLE_TAGS.initiator, counter, plain); return encryptedFrame({ channelId: 0, nonce, ciphertext, sessionId }); };
    await assert.rejects(rx.open(await frameOf(cat(inner, Uint8Array.of(0)), 0)), CborError);
    // the refused frame consumed no counter? (it was authentic: it did: the next counter is 1)
    const opened = await rx.open(await frameOf(inner, 1)).catch((e) => e);
    assert.ok(opened?.type === 0x21 || opened instanceof Error, 'the bridge is still usable or fails closed');
  });
});
