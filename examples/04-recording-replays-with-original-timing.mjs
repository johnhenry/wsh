/**
 * A recording replays with its original timing.
 *
 * wsh records PTY sessions as timestamped event streams and exports them in
 * an asciicast-v2-compatible shape, so recordings interop with standard
 * terminal players (asciinema et al.). This example records a short session,
 * round-trips it through JSON export/import, and replays it — verifying that
 * output comes back in order and that inter-event timing is preserved
 * (sped up 20x so the example finishes quickly).
 */

import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { SessionRecorder, SessionPlayer } from '@johnhenry/wsh';

// ── Record a session ──────────────────────────────────────────────────

const recorder = new SessionRecorder('demo-session', { width: 120, height: 30 });

recorder.record('open', { command: '/bin/bash' });
recorder.record('output', '$ ');
await sleep(150);
recorder.record('input', 'echo hello\r');
recorder.record('output', 'echo hello\r\nhello\r\n$ ');
await sleep(300);
recorder.record('resize', { cols: 100, rows: 40 });
await sleep(150);
recorder.record('output', 'bye\r\n');
recorder.record('exit', { code: 0 });

console.log(`recorded ${recorder.length} events over ${recorder.duration}ms`);

// ── Round-trip through the export format ──────────────────────────────

const exported = recorder.toJSON();
assert.equal(exported.version, 2);                    // asciicast v2
assert.equal(exported.width, 100);                    // recorder tracked the mid-session resize
assert.equal(exported.height, 40);
assert.ok(exported.events.every((e) => Array.isArray(e) && e.length === 3));
console.log(`exported asciicast v2: ${exported.events.length} [time, type, data] events`);

const json = JSON.stringify(exported);                // what you'd write to disk
const reimported = SessionRecorder.fromJSON(json);
assert.equal(reimported.length, recorder.length);
assert.equal(reimported.entries.at(-1).type, 'exit');
console.log('re-imported from JSON string: event count and types intact');

// ── Replay ────────────────────────────────────────────────────────────

const player = new SessionPlayer(reimported); // accepts a recorder or plain JSON
console.log(`player metadata: ${player.metadata.width}x${player.metadata.height}, ` +
  `${player.metadata.duration}ms, ${player.metadata.eventCount} events`);

const chunks = [];
const timestamps = [];
const t0 = performance.now();

await new Promise((resolve) => {
  player.play(
    (data) => { chunks.push(data); timestamps.push(performance.now() - t0); },
    {
      speed: 20, // 20x: ~600ms of session replays in ~30ms
      onEvent: (type) => { if (type === 'exit') resolve(); },
    }
  );
});

// Output content and order survived the round trip.
assert.equal(chunks.join(''), '$ echo hello\r\nhello\r\n$ bye\r\n');
console.log(`replayed terminal output: ${JSON.stringify(chunks.join(''))}`);

// Timing survived: the last output was recorded ~600ms in, so at 20x it must
// arrive later than the first output but within a few dozen ms.
const spread = timestamps.at(-1) - timestamps[0];
assert.ok(spread > 5, `expected timed playback, got ${spread.toFixed(1)}ms spread`);
console.log(`inter-event timing preserved at 20x speed (${spread.toFixed(1)}ms spread on replay)`);

console.log('ok: record → export → import → replay round trip complete');
