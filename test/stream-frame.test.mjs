import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sealFrame, openFrame, ROLE_TAGS } from '../src/e2e-frame.mjs';
import {
  ChunkAccumulator, encodeChunk, StreamTornChunkError,
  DEFAULT_COALESCE_PROFILES, resolveCoalesceOptions, WriteCoalescer,
} from '../src/stream-frame.mjs';

const hasWebCrypto = typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

async function makeKey() {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function sealChunk(key, sessionId, counter, text) {
  const plaintext = new TextEncoder().encode(text);
  const { nonce, ciphertext } = await sealFrame(key, sessionId, ROLE_TAGS.initiator, counter, plaintext);
  return { nonce, ciphertext, wire: encodeChunk(nonce, ciphertext), plaintext };
}

describe('stream-frame: ChunkAccumulator + encodeChunk', { skip: !hasWebCrypto && 'WebCrypto not available in this runtime' }, () => {
  it('round-trips a single chunk fed in one call', async () => {
    const key = await makeKey();
    const { wire, plaintext } = await sealChunk(key, 'sess-1', 0, 'hello stream world');

    const acc = new ChunkAccumulator();
    const chunks = acc.feed(wire);
    assert.equal(chunks.length, 1);

    const opened = await openFrame(key, 'sess-1', 0, chunks[0]);
    assert.deepEqual([...opened], [...plaintext]);
    assert.doesNotThrow(() => acc.finish());
  });

  it('tamper detection: a flipped ciphertext byte fails openFrame after reassembly', async () => {
    const key = await makeKey();
    const { wire } = await sealChunk(key, 'sess-2', 0, 'do not tamper with this chunk');

    // Flip a byte inside the ciphertext region (after the 4-byte length
    // prefix + 12-byte nonce).
    const tampered = wire.slice();
    tampered[4 + 12] ^= 0xff;

    const acc = new ChunkAccumulator();
    const [chunk] = acc.feed(tampered);
    assert.ok(chunk);

    await assert.rejects(() => openFrame(key, 'sess-2', 0, chunk));
  });

  it('finish() throws StreamTornChunkError for a torn chunk left at EOF', () => {
    const acc = new ChunkAccumulator();
    // Feed a length prefix claiming more bytes than actually follow.
    const partial = new Uint8Array(4 + 12 + 5);
    new DataView(partial.buffer).setUint32(0, 100, false); // claims 100 ciphertext bytes, only 5 present
    const chunks = acc.feed(partial);
    assert.equal(chunks.length, 0);
    assert.throws(() => acc.finish(), StreamTornChunkError);
  });

  it('finish() is a clean no-op when the buffer is empty (nothing torn)', () => {
    const acc = new ChunkAccumulator();
    assert.doesNotThrow(() => acc.finish());
  });

  it('multiple complete chunks arriving in a single read() are all extracted, in order', async () => {
    const key = await makeKey();
    const a = await sealChunk(key, 'sess-3', 0, 'first chunk');
    const b = await sealChunk(key, 'sess-3', 1, 'second chunk');
    const c = await sealChunk(key, 'sess-3', 2, 'third chunk');

    const combined = new Uint8Array(a.wire.length + b.wire.length + c.wire.length);
    combined.set(a.wire, 0);
    combined.set(b.wire, a.wire.length);
    combined.set(c.wire, a.wire.length + b.wire.length);

    const acc = new ChunkAccumulator();
    const chunks = acc.feed(combined);
    assert.equal(chunks.length, 3);

    const opened = await Promise.all(chunks.map((chunk, i) => openFrame(key, 'sess-3', i, chunk)));
    assert.equal(new TextDecoder().decode(opened[0]), 'first chunk');
    assert.equal(new TextDecoder().decode(opened[1]), 'second chunk');
    assert.equal(new TextDecoder().decode(opened[2]), 'third chunk');
    assert.doesNotThrow(() => acc.finish());
  });

  it('one chunk split across two feed() calls is only delivered once complete', async () => {
    const key = await makeKey();
    const { wire, plaintext } = await sealChunk(key, 'sess-4', 0, 'a chunk delivered in two pieces');

    const splitPoint = Math.floor(wire.length / 2);
    const first = wire.slice(0, splitPoint);
    const second = wire.slice(splitPoint);

    const acc = new ChunkAccumulator();
    const chunksAfterFirst = acc.feed(first);
    assert.equal(chunksAfterFirst.length, 0, 'no chunk should be available from a partial feed');

    const chunksAfterSecond = acc.feed(second);
    assert.equal(chunksAfterSecond.length, 1);

    const opened = await openFrame(key, 'sess-4', 0, chunksAfterSecond[0]);
    assert.deepEqual([...opened], [...plaintext]);
    assert.doesNotThrow(() => acc.finish());
  });

  it('a length header split across two feed() calls is handled once the header completes', async () => {
    const key = await makeKey();
    const { wire, plaintext } = await sealChunk(key, 'sess-5', 0, 'short');

    // Split in the middle of the 4-byte length prefix itself.
    const first = wire.slice(0, 2);
    const second = wire.slice(2);

    const acc = new ChunkAccumulator();
    assert.equal(acc.feed(first).length, 0);
    const chunks = acc.feed(second);
    assert.equal(chunks.length, 1);

    const opened = await openFrame(key, 'sess-5', 0, chunks[0]);
    assert.deepEqual([...opened], [...plaintext]);
  });

  it('many tiny feed() calls (byte-at-a-time) still reassemble correctly', async () => {
    const key = await makeKey();
    const { wire, plaintext } = await sealChunk(key, 'sess-6', 0, 'trickled in one byte at a time');

    const acc = new ChunkAccumulator();
    let chunks = [];
    for (const byte of wire) {
      chunks = chunks.concat(acc.feed(Uint8Array.of(byte)));
    }
    assert.equal(chunks.length, 1);
    const opened = await openFrame(key, 'sess-6', 0, chunks[0]);
    assert.deepEqual([...opened], [...plaintext]);
  });
});

describe('stream-frame: write coalescing', () => {
  it('the pty and exec default profiles differ (latency-first vs throughput-first)', () => {
    const pty = DEFAULT_COALESCE_PROFILES.pty;
    const exec = DEFAULT_COALESCE_PROFILES.exec;
    assert.ok(pty.maxDelayMs < exec.maxDelayMs, 'pty timer should be shorter than exec timer');
    assert.ok(pty.maxBytes < exec.maxBytes, 'pty byte threshold should be smaller than exec');
  });

  it('resolveCoalesceOptions() picks the profile by session kind', () => {
    assert.deepEqual(resolveCoalesceOptions('pty', undefined), DEFAULT_COALESCE_PROFILES.pty);
    assert.deepEqual(resolveCoalesceOptions('exec', undefined), DEFAULT_COALESCE_PROFILES.exec);
  });

  it('resolveCoalesceOptions(kind, false) disables coalescing', () => {
    assert.equal(resolveCoalesceOptions('pty', false), null);
    assert.equal(resolveCoalesceOptions('exec', false), null);
  });

  it('resolveCoalesceOptions() honors an explicit override, filling in defaults for omitted fields', () => {
    const resolved = resolveCoalesceOptions('pty', { maxBytes: 1234 });
    assert.equal(resolved.maxBytes, 1234);
    assert.equal(resolved.maxDelayMs, DEFAULT_COALESCE_PROFILES.pty.maxDelayMs);
  });

  it('WriteCoalescer flushes once maxBytes is reached, merging buffered writes into one flush call', async () => {
    const flushed = [];
    const coalescer = new WriteCoalescer({ maxBytes: 10, maxDelayMs: 10_000 }, async (bytes) => {
      flushed.push(bytes);
    });

    await coalescer.write(new Uint8Array([1, 2, 3]));
    await coalescer.write(new Uint8Array([4, 5, 6]));
    // Still under 10 bytes buffered -- no flush yet.
    assert.equal(flushed.length, 0);

    await coalescer.write(new Uint8Array([7, 8, 9, 10]));
    // 10 bytes buffered >= maxBytes -- flush should have fired, merging all three writes.
    assert.equal(flushed.length, 1);
    assert.deepEqual([...flushed[0]], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it('WriteCoalescer flushes on the timer even under the byte threshold', async () => {
    const flushed = [];
    const coalescer = new WriteCoalescer({ maxBytes: 1_000_000, maxDelayMs: 15 }, async (bytes) => {
      flushed.push(bytes);
    });

    await coalescer.write(new Uint8Array([42]));
    assert.equal(flushed.length, 0);

    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(flushed.length, 1);
    assert.deepEqual([...flushed[0]], [42]);
  });

  it('WriteCoalescer.flush() force-flushes immediately regardless of thresholds', async () => {
    const flushed = [];
    const coalescer = new WriteCoalescer({ maxBytes: 1_000_000, maxDelayMs: 1_000_000 }, async (bytes) => {
      flushed.push(bytes);
    });

    await coalescer.write(new Uint8Array([9, 9]));
    assert.equal(flushed.length, 0);
    await coalescer.flush();
    assert.equal(flushed.length, 1);
  });

  it('a pty-profile coalescer flushes noticeably sooner than an exec-profile one for the same small write', async () => {
    const ptyFlushedAt = { time: null };
    const execFlushedAt = { time: null };
    const start = Date.now();

    const ptyCoalescer = new WriteCoalescer(DEFAULT_COALESCE_PROFILES.pty, async () => {
      ptyFlushedAt.time = Date.now() - start;
    });
    const execCoalescer = new WriteCoalescer(DEFAULT_COALESCE_PROFILES.exec, async () => {
      execFlushedAt.time = Date.now() - start;
    });

    await ptyCoalescer.write(new Uint8Array([1]));
    await execCoalescer.write(new Uint8Array([1]));

    // Wait long enough for the pty timer to fire but well short of the
    // exec timer.
    await new Promise((resolve) => setTimeout(resolve, DEFAULT_COALESCE_PROFILES.pty.maxDelayMs + 15));
    assert.notEqual(ptyFlushedAt.time, null, 'pty coalescer should have flushed by now');
    assert.equal(execFlushedAt.time, null, 'exec coalescer should not have flushed yet');

    await execCoalescer.flush();
  });
});
