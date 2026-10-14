// test/recording-format.test.mjs -- what SessionRecorder.toJSON() really is, relative to asciicast v2 (#102).
// The README and recording.mjs say: asciicast-v2-*shaped* (same header names, [seconds, code, data] events with the
// o/i/r codes), but ONE JSON document with extra fields and non-asciicast event codes, so not a file `asciinema play`
// can read as-is; the README gives a conversion. These tests keep that statement true.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { SessionRecorder } from '@johnhenry/wsh';

function sample() {
  const rec = new SessionRecorder('s1', { width: 100, height: 30 });
  rec.record('open', { command: 'sh' });
  rec.record('output', 'hello\r\n');
  rec.record('input', 'ls\r');
  rec.record('resize', { cols: 120, rows: 40 });
  rec.record('exit', { code: 0 });
  return rec;
}

/** The conversion documented in the README: header line + o/i/r events, one JSON value per line. */
function toAsciicastLines(json) {
  const { version, width, height, timestamp, env, events } = json;
  const lines = [JSON.stringify({ version, width, height, timestamp, env })];
  for (const e of events) if (['o', 'i', 'r'].includes(e[1])) lines.push(JSON.stringify(e));
  return lines.join('\n') + '\n';
}

describe('SessionRecorder export vs asciicast v2 (#102)', () => {
  it('is asciicast-v2-shaped: version 2 header fields and [seconds, code, data] events', () => {
    const json = sample().toJSON();
    assert.equal(json.version, 2);
    // Deviation: asciicast's width/height are the START size; here they track the latest resize (120x40 after it).
    assert.equal(json.width, 120);
    assert.equal(json.height, 40);
    assert.equal(typeof json.timestamp, 'number');
    assert.ok(Array.isArray(json.events));
    for (const [t, code, data] of json.events) {
      assert.equal(typeof t, 'number');
      assert.equal(typeof code, 'string');
      assert.equal(typeof data, 'string');
    }
    assert.deepEqual(json.events.filter((e) => e[1] === 'o').map((e) => e[2]), ['hello\r\n']);
    assert.deepEqual(json.events.filter((e) => e[1] === 'r').map((e) => e[2]), ['120x40']);
  });

  it('is NOT a playable asciicast file: one JSON document, a non-standard header field, lifecycle codes', () => {
    const json = sample().toJSON();
    // asciicast v2 is newline-delimited JSON (header line, then one event per line); this is a single document.
    assert.ok(!Array.isArray(json) && Object.hasOwn(json, 'events'));
    assert.equal(JSON.stringify(json).includes('\n'), false);
    assert.ok(Object.hasOwn(json, 'sessionId'), 'sessionId is wsh\'s own header field');
    assert.deepEqual([...new Set(json.events.map((e) => e[1]))].sort(), ['exit', 'i', 'o', 'open', 'r']);
  });

  it('the documented conversion gives header + o/i/r lines, each valid JSON, without lifecycle events', () => {
    const text = toAsciicastLines(sample().toJSON());
    const lines = text.trimEnd().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines[0].version, 2);
    assert.ok(!('events' in lines[0]) && !('sessionId' in lines[0]));
    assert.deepEqual(lines.slice(1).map((e) => e[1]), ['o', 'i', 'r']);
  });

  it('fromJSON round-trips toJSON, and reads a v2 asciicast once its lines are gathered into the document shape', () => {
    const rec = sample();
    const back = SessionRecorder.fromJSON(rec.toJSON());
    assert.deepEqual(back.entries.map((e) => e.type), ['open', 'output', 'input', 'resize', 'exit']);
    const [header, ...events] = [
      { version: 2, width: 80, height: 24, timestamp: 1700000000 },
      [0.5, 'o', 'x'], [1, 'r', '90x30'],
    ];
    const imported = SessionRecorder.fromJSON({ ...header, events });
    assert.deepEqual(imported.entries.map((e) => [e.t, e.type]), [[500, 'output'], [1000, 'resize']]);
  });

  it('README and recording.mjs agree: neither calls the export a playable asciicast file', async () => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
    const code = await readFile(new URL('../src/recording.mjs', import.meta.url), 'utf8');
    assert.match(readme, /asciicast-v2-shaped|asciicast v2-shaped/i);
    assert.match(readme, /asciinema play/);
    assert.doesNotMatch(readme, /\(asciicast v2\) \| none/, 'the capability matrix must not call the recorder asciicast v2');
    assert.doesNotMatch(code, /is compatible with (the )?asciicast v2/i);
    assert.doesNotMatch(code, /enabling interop with standard terminal players/i);
    assert.match(code, /not (a )?(file )?(that )?(asciinema|an asciicast)/i);
  });
});
