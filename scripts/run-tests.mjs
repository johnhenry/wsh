// scripts/run-tests.mjs -- `npm test`: the same `node --test` run of every test/*.test.mjs, one process per file as before, with
// two additions so that a hang costs minutes and names itself:
//   - every file is announced when it starts and when it ends, with how long it took, and
//   - a file that runs longer than FILE_TIMEOUT_MS is killed (its whole process group), its output so far is printed, and the
//     run fails naming the file.
// `npm test -- test/a.test.mjs test/b.test.mjs` runs just those files. FILE_TIMEOUT_MS and TEST_CONCURRENCY override the defaults.
// The output of each file is printed whole when it ends (as `node --test` does), so files do not interleave.

import { spawn } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILE_TIMEOUT_MS = Number(process.env.FILE_TIMEOUT_MS) || 5 * 60_000;
const CONCURRENCY = Number(process.env.TEST_CONCURRENCY) || Math.max(1, availableParallelism() - 1);
/** Per test, inside a file: a test that never finishes fails by name instead of waiting for the file's limit. */
const TEST_TIMEOUT_MS = Number(process.env.TEST_TIMEOUT_MS) || 2 * 60_000;

const requested = process.argv.slice(2);
const files = requested.length
  ? requested
  : readdirSync(path.join(ROOT, 'test')).filter((f) => f.endsWith('.test.mjs')).sort().map((f) => path.join('test', f));

const started = Date.now();
const failed = [];
const timedOut = [];
let passedFiles = 0;
let next = 0;

function runFile(file) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    process.stderr.write(`[gate] start ${file}\n`);
    const child = spawn(process.execPath, ['--test', '--unhandled-rejections=strict', `--test-timeout=${TEST_TIMEOUT_MS}`, file], {
      cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], detached: true, env: process.env,
    });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    let killed = false;
    const timer = setTimeout(() => {
      killed = true;
      try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* gone */ } }
    }, FILE_TIMEOUT_MS);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const secs = ((Date.now() - t0) / 1000).toFixed(1);
      process.stdout.write(`${out}${out.endsWith('\n') ? '' : '\n'}`);
      if (killed) {
        timedOut.push(file);
        process.stderr.write(`[gate] TIMED OUT ${file} after ${secs}s (limit ${FILE_TIMEOUT_MS / 1000}s): killed; its output above ends where it stopped\n`);
      } else if (code !== 0) {
        failed.push(file);
        process.stderr.write(`[gate] FAIL ${file} (${secs}s, exit ${code ?? signal})\n`);
      } else {
        passedFiles++;
        process.stderr.write(`[gate] end   ${file} (${secs}s)\n`);
      }
      resolve();
    });
  });
}

async function worker() {
  while (next < files.length) await runFile(files[next++]);
}

await Promise.all(Array.from({ length: Math.min(CONCURRENCY, files.length) }, worker));
const secs = ((Date.now() - started) / 1000).toFixed(1);
process.stderr.write(`[gate] ${files.length} files in ${secs}s: ${passedFiles} passed, ${failed.length} failed, ${timedOut.length} timed out\n`);
for (const f of failed) process.stderr.write(`[gate]   failed: ${f}\n`);
for (const f of timedOut) process.stderr.write(`[gate]   timed out: ${f}\n`);
process.exit(failed.length || timedOut.length ? 1 : 0);
