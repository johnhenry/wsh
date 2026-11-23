// Guards against a mistake that makes a test pass or fail for the wrong reason: the gateway open/listen calls take
// `timeoutMs`, not `timeout` (`connect()` and `exec()` take `timeout`). A `{ timeout }` there is silently ignored, so the
// call waits the 10 s default instead of the short deadline the test meant.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const here = new URL('.', import.meta.url).pathname;

function* files(dir) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules') continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* files(p);
    else if (/\.(mjs|ts)$/.test(name)) yield p;
  }
}

describe('test hygiene', () => {
  it('gateway open*/listen* calls in tests pass timeoutMs, never timeout', () => {
    const bad = [];
    const call = /\b(openUnix|openEndpoint|openTcp|openUdp|listenUnix|listenTcp)\s*\(([^)]*)\)/g;
    for (const file of files(here)) {
      if (file === new URL(import.meta.url).pathname) continue;
      const text = readFileSync(file, 'utf8');
      for (const m of text.matchAll(call)) {
        if (/\btimeout\s*:/.test(m[2])) bad.push(`${file.slice(here.length)}: ${m[0]}`);
      }
    }
    assert.deepEqual(bad, [], 'use { timeoutMs } for gateway opens');
  });
});
