// test/rust/helpers/guard.mjs -- shared by every file under test/rust/ (#152).
//
// Importing this module (for its side effects) does two things:
//   1. every child process the file spawns is tracked, and killed (SIGKILL, with its process group's children left to
//      their own parent) when the file's tests end, when the test process exits, or when it is interrupted -- so a test
//      that times out, or a `wsh` that never exits, cannot keep the run alive;
//   2. `npm run test:rust` runs with `--test-timeout` (see package.json), so a test that hangs FAILS after
//      TEST_TIMEOUT_MS with its own name in the report instead of holding the CI job until its limit.
//
// A test that needs a different limit passes `{ timeout }` to `it()`; there is no way to opt out of the kill.

import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { after } from 'node:test';

/** The per-test limit `npm run test:rust` applies (milliseconds). Keep in step with package.json. */
export const TEST_TIMEOUT_MS = 180_000;

const tracked = new Set();

if (!childProcess.spawn.__wshGuarded) {
  const realSpawn = childProcess.spawn;
  const guarded = function spawn(...args) {
    const child = realSpawn.apply(this, args);
    tracked.add(child);
    child.once('close', () => tracked.delete(child));
    return child;
  };
  guarded.__wshGuarded = true;
  childProcess.spawn = guarded;
  syncBuiltinESMExports(); // `import { spawn } from 'node:child_process'` in the test files sees the guarded one
}

/** Kill every child this file still has running. Returns how many were alive. */
export function killTracked() {
  let alive = 0;
  for (const child of tracked) {
    if (child.exitCode === null && child.signalCode === null) {
      alive += 1;
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
    }
  }
  tracked.clear();
  return alive;
}

after(() => { killTracked(); });
process.once('exit', () => { killTracked(); });
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.once(sig, () => { killTracked(); process.kill(process.pid, sig); });
}

/** Children currently tracked (for the helper's own test). */
export const trackedCount = () => tracked.size;
