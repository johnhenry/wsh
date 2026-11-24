// test/testing-entry.test.mjs -- `@johnhenry/wsh/testing`: the QMux record and frame codec primitives a test needs to read, alter and
// re-wrap what travels on a connection (the stream frame of a control message, say). Documented as NOT part of the stable API.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as testing from '@johnhenry/wsh/testing';
import * as main from '@johnhenry/wsh';
import { cborEncode, cborDecode } from '@johnhenry/wsh';

describe('@johnhenry/wsh/testing', () => {
  it('exports the codec primitives, and the main entry still does not', () => {
    for (const name of ['encodeVarint', 'decodeVarint', 'encodeRecord', 'RecordDecoder', 'decodeFrames', 'encodeStream', 'encodeDatagram', 'encodeConnectionClose', 'FRAME_TYPE', 'QMUX_TESTING_API']) {
      assert.ok(name in testing, `${name} is exported`);
    }
    for (const name of ['encodeStream', 'encodeRecord', 'RecordDecoder', 'decodeFrames', 'encodeVarint']) {
      assert.ok(!(name in main), `${name} stays out of the stable entry`);
    }
  });

  it('says it is not part of the stable API', async () => {
    assert.equal(testing.QMUX_TESTING_API.stable, false);
    assert.match(testing.QMUX_TESTING_API.notice, /not part of the stable API/i);
    const dts = await readFile(new URL('../src/testing.d.ts', import.meta.url), 'utf8');
    assert.match(dts, /@experimental/);
    assert.match(dts, /not part of the stable API/i);
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
    assert.match(readme, /`@johnhenry\/wsh\/testing`[^\n]*not part of the stable API/i);
  });

  it('a STREAM frame in a record round-trips through RecordDecoder and decodeFrames', () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    const record = testing.encodeRecord(testing.encodeStream({ streamId: 4, offset: 10, data, fin: true }));
    const decoder = new testing.RecordDecoder();
    // fed in two pieces, as a transport would deliver it
    assert.deepEqual(decoder.feed(record.subarray(0, 3)), []);
    const records = decoder.feed(record.subarray(3));
    assert.equal(records.length, 1);
    const [frame, ...rest] = testing.decodeFrames(records[0]);
    assert.equal(rest.length, 0);
    assert.equal(frame.frameType, 'STREAM');
    assert.equal(Number(frame.streamId), 4);
    assert.equal(Number(frame.offset), 10);
    assert.equal(frame.fin, true);
    assert.deepEqual([...frame.data], [1, 2, 3, 4]);
  });

  it('re-wraps a frame: decode a record, change the payload, encode it again, and the result decodes as the changed frame', () => {
    const original = cborEncode({ type: 7, reason: 'original' });
    const wire = testing.encodeRecord(testing.encodeStream({ streamId: 0, offset: 0, data: original, fin: false }));
    const [payload] = new testing.RecordDecoder().feed(wire);
    const [frame] = testing.decodeFrames(payload);
    assert.deepEqual(cborDecode(frame.data), { type: 7, reason: 'original' });
    const altered = testing.encodeRecord(testing.encodeStream({
      streamId: Number(frame.streamId), offset: Number(frame.offset), data: cborEncode({ type: 7, reason: 'altered' }), fin: frame.fin,
    }));
    const [again] = testing.decodeFrames(new testing.RecordDecoder().feed(altered)[0]);
    assert.deepEqual(cborDecode(again.data), { type: 7, reason: 'altered' });
    // And an unmodified frame re-encodes to the same bytes it came in as.
    const same = testing.encodeRecord(testing.encodeStream({ streamId: Number(frame.streamId), offset: Number(frame.offset), data: frame.data, fin: frame.fin }));
    assert.deepEqual([...same], [...wire]);
  });

  it('varints and the other frame encoders are there for a test that builds its own frames', () => {
    assert.deepEqual([...testing.encodeVarint(300)], [0x41, 0x2c]);
    assert.equal(testing.decodeVarint(testing.encodeVarint(300), 0).value, 300);
    const [dg] = testing.decodeFrames(testing.encodeDatagram(new Uint8Array([9, 9])));
    assert.equal(dg.frameType, 'DATAGRAM');
  });
});
