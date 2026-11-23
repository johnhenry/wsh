// test/rust/guard.test.mjs -- #152: a hanging test fails in seconds, by name, and leaves no child process behind.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import './helpers/guard.mjs';
import { TEST_TIMEOUT_MS } from './helpers/guard.mjs';

const FIXTURE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'helpers', 'hang-fixture.mjs');
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

describe('the test:rust guard', () => {
  it('fails a hanging test within seconds, names it, and kills the child it spawned', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'wsh-guard-'));
    try {
      const pidFile = path.join(dir, 'pid');
      const t0 = Date.now();
      const r = spawnSync(process.execPath, ['--test', '--test-timeout=1500', FIXTURE], { env: { ...process.env, NODE_TEST_CONTEXT: undefined, PID_FILE: pidFile }, encoding: 'utf8', timeout: 30_000 });
      assert.ok(Date.now() - t0 < 20_000, 'the run ended in seconds, not at the job limit');
      assert.notEqual(r.status, 0);
      assert.match(r.stdout, /this test hangs on purpose/);
      assert.match(r.stdout, /timed out/);
      const pid = Number(readFileSync(pidFile, 'utf8'));
      assert.equal(alive(pid), false, 'the child the hung test spawned was killed');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('the per-test limit stays in step with package.json', () => {
    const pkg = JSON.parse(readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json'), 'utf8'));
    assert.ok(pkg.scripts['test:rust'].includes(`--test-timeout=${TEST_TIMEOUT_MS}`), pkg.scripts['test:rust']);
  });
});
