// test/gateway-sealed-backpressure.test.mjs -- a guarantee for embedders: through a SEALED session, an endpoint's
// `readable` / `writable` pair is flow controlled end to end by the gateway credit window, in both directions. A fast
// producer is held back by `writer.ready` / the write promise (not by dropping), memory on the producer's side stays
// bounded, and every byte arrives in order. (An embedder that buffers behind its own `onData`-style callback without
// awaiting `writer.ready` defeats this; the README says how to use it.)
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import v8 from 'node:v8';
import vm from 'node:vm';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { GATEWAY_CREDIT_WINDOW } from '../src/gateway-channel.mjs';

const MiB = 1024 * 1024;
const TOTAL = 32 * MiB;
const CHUNK = 256 * 1024;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Live (not merely not-yet-collected) ArrayBuffer memory: the sealing and framing of 32 MiB makes a lot of short-lived garbage.
v8.setFlagsFromString('--expose_gc');
const gc = vm.runInNewContext('gc');
const liveBuffers = () => { gc(); return process.memoryUsage().arrayBuffers; };
/** The pattern the producer sends: byte at global offset o is BASE[o % CHUNK] (one buffer, reused, so the test itself allocates nothing). */
const BASE = new Uint8Array(CHUNK).map((_, i) => (i * 7 + 3) & 0xff);

/** Pull `total` bytes, slowly (a pause per read), checking order and content; reports how much has been taken so far. */
function slowReader(readable, { pauseMs = 1, gate = null } = {}) {
  const state = { read: 0, done: false, bad: -1 };
  const finished = (async () => {
    const r = readable.getReader();
    for (;;) {
      if (gate) await gate;
      const { value, done } = await r.read();
      if (done) break;
      for (let i = 0; i < value.length; i++) {
        if (value[i] !== BASE[(state.read + i) % CHUNK]) { state.bad = state.read + i; break; }
      }
      state.read += value.length;
      if (pauseMs) await sleep(pauseMs);
    }
    state.done = true;
  })();
  return { state, finished };
}

describe('a sealed session: an endpoint stream applies backpressure end to end', () => {
  let keyPair; let host;
  /** the endpoint's side of each test, set by the test before it opens the endpoint */
  let serve = null;
  before(async () => {
    keyPair = await generateKeyPair(true);
    host = createMemoryHost({
      auth: { authorizedKeys: `${await exportPublicKeySSH(keyPair.publicKey)} u` },
      hostKey: true, dataStreams: false, sealSession: 'require',
      endpoints: { bulk: (duplex) => serve(duplex) },
    });
  });
  after(() => host.close());

  it('client to host: 32 MiB at a slow reader; the writer is held back by the credit window, bounded and lossless', async () => {
    const client = await host.connect({ username: 'u', keyPair });
    try {
      assert.equal(client.sessionSealed, true, 'the session under test is sealed');
      let rd;
      const hostGot = new Promise((resolve) => { serve = (d) => { rd = slowReader(d.readable); resolve(rd); }; });
      const d = await client.openEndpoint('bulk');
      const reader = await hostGot;
      const w = d.writable.getWriter();
      let accepted = 0; let maxAhead = 0; let askedWhileFull = 0;
      const heapBefore = liveBuffers(); let heapPeak = 0;
      while (accepted < TOTAL) {
        await w.ready;
        // `ready` resolved: the stream is asking for more. If the reader is far behind it must not be.
        if (accepted - reader.state.read > 2 * CHUNK) askedWhileFull++;
        await w.write(BASE);
        accepted += CHUNK;
        maxAhead = Math.max(maxAhead, accepted - reader.state.read);
        if (accepted % (4 * MiB) === 0) heapPeak = Math.max(heapPeak, liveBuffers() - heapBefore);
      }
      await w.close();
      await reader.finished;
      assert.equal(reader.state.read, TOTAL, 'every byte arrived');
      assert.equal(reader.state.bad, -1, 'in order and unchanged');
      // What the writer has handed over and the reader has not yet taken is the credit window plus the chunk in flight, never the 32 MiB.
      assert.ok(maxAhead <= GATEWAY_CREDIT_WINDOW + 2 * CHUNK, `writer ran ${maxAhead} bytes ahead of the reader (window ${GATEWAY_CREDIT_WINDOW})`);
      assert.equal(askedWhileFull, 0, '`writer.ready` did not resolve while the reader was far behind');
      assert.ok(heapPeak < 16 * MiB, `memory on the writer's side stayed bounded: peak ${(heapPeak / MiB).toFixed(1)} MiB for 32 MiB sent`);
      console.log(`# client->host 32 MiB: max ahead of the reader ${maxAhead} bytes, peak arrayBuffers growth ${(heapPeak / MiB).toFixed(1)} MiB`);
    } finally { await client.disconnect().catch(() => {}); }
  });

  it('host to client: 32 MiB from a fast producer that awaits writer.ready, at a slow reader: the same', async () => {
    const client = await host.connect({ username: 'u', keyPair });
    try {
      const stats = { accepted: 0, maxAhead: 0, askedWhileFull: 0, heapPeak: 0 };
      let rd; let producing;
      const heapBefore = liveBuffers();
      serve = (d) => {
        producing = (async () => {
          const w = d.writable.getWriter();
          while (stats.accepted < TOTAL) {
            await w.ready;
            if (rd && stats.accepted - rd.state.read > 2 * CHUNK) stats.askedWhileFull++;
            await w.write(BASE);
            stats.accepted += CHUNK;
            stats.maxAhead = Math.max(stats.maxAhead, stats.accepted - (rd?.state.read ?? 0));
            if (stats.accepted % (4 * MiB) === 0) stats.heapPeak = Math.max(stats.heapPeak, liveBuffers() - heapBefore);
          }
          await w.close();
        })();
      };
      const d = await client.openEndpoint('bulk');
      rd = slowReader(d.readable);
      await rd.finished; await producing;
      assert.equal(rd.state.read, TOTAL);
      assert.equal(rd.state.bad, -1);
      assert.ok(stats.maxAhead <= GATEWAY_CREDIT_WINDOW + 2 * CHUNK, `the producer ran ${stats.maxAhead} bytes ahead of the reader`);
      assert.equal(stats.askedWhileFull, 0);
      assert.ok(stats.heapPeak < 16 * MiB, `peak ${(stats.heapPeak / MiB).toFixed(1)} MiB`);
      console.log(`# host->client 32 MiB: max ahead of the reader ${stats.maxAhead} bytes, peak arrayBuffers growth ${(stats.heapPeak / MiB).toFixed(1)} MiB`);
    } finally { await client.disconnect().catch(() => {}); }
  });

  it('5 MiB written at once into the host side stays pending until the reader has taken nearly all of it', async () => {
    const client = await host.connect({ username: 'u', keyPair });
    try {
      let release; const gate = new Promise((r) => { release = r; });
      let rd; let writeDone = false; let writing;
      serve = (d) => {
        const w = d.writable.getWriter();
        writing = w.write(new Uint8Array(5 * MiB).map((_, i) => BASE[i % CHUNK])).then(() => { writeDone = true; return w.close(); });
      };
      const d = await client.openEndpoint('bulk');
      rd = slowReader(d.readable, { pauseMs: 0, gate });
      // Nothing is read yet: the producer is stopped at the window, not buffering 5 MiB on the far side of the seal.
      await sleep(300);
      assert.equal(writeDone, false, 'the 5 MiB write is held back while the reader has not read');
      assert.equal(rd.state.read, 0);
      release();
      await writing; await rd.finished;
      assert.equal(rd.state.read, 5 * MiB, 'nothing lost');
      assert.equal(rd.state.bad, -1);
    } finally { await client.disconnect().catch(() => {}); }
  });

  it('a producer that ignores writer.ready is still held back: write() promises are pending, so its own queue is what grows', async () => {
    const client = await host.connect({ username: 'u', keyPair });
    try {
      let release; const gate = new Promise((r) => { release = r; });
      let w; let desiredWhileStalled;
      let writes = 0; let settled = 0;
      serve = (d) => {
        w = d.writable.getWriter();
        for (let i = 0; i < 64; i++) { writes++; w.write(BASE).then(() => { settled++; }, () => {}); }
        desiredWhileStalled = w.desiredSize;
      };
      const d = await client.openEndpoint('bulk');
      const rd = slowReader(d.readable, { pauseMs: 0, gate });
      await sleep(300);
      assert.equal(writes, 64);
      assert.ok(desiredWhileStalled < 0, `writer.desiredSize says stop (${desiredWhileStalled})`);
      // 16 MiB queued by the producer, but only about a credit window of it has left the producer's stream.
      assert.ok(settled * CHUNK <= GATEWAY_CREDIT_WINDOW + 2 * CHUNK, `${settled} of ${writes} writes settled with the reader stalled`);
      release();
      await w.close();
      await rd.finished;
      assert.equal(rd.state.read, 64 * CHUNK);
      assert.equal(rd.state.bad, -1);
    } finally { await client.disconnect().catch(() => {}); }
  });
});
