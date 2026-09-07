#!/usr/bin/env node
/**
 * Verifies that the checked-in codegen outputs (src/messages.gen.mjs,
 * spec/wsh-v1.md, crates/wsh-core/src/messages.gen.rs) are current with
 * spec/wsh-v1.yaml — without mutating the working tree.
 *
 * Regenerates all three into a scratch directory, diffs each against the
 * checked-in file, and exits non-zero if any of them have drifted (i.e.
 * someone hand-edited a generated file, or changed wsh-v1.yaml without
 * running `npm run codegen`).
 *
 * Usage: node scripts/codegen-check.mjs   (wired up as `npm run codegen:check`)
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

const scratch = mkdtempSync(join(tmpdir(), 'wsh-codegen-check-'));

const targets = [
  {
    label: 'JS',
    checkedIn: join(REPO_ROOT, 'src/messages.gen.mjs'),
    scratchOut: join(scratch, 'messages.gen.mjs'),
    env: 'WSH_JS_OUT',
  },
  {
    label: 'Spec (Markdown)',
    checkedIn: join(REPO_ROOT, 'spec/wsh-v1.md'),
    scratchOut: join(scratch, 'wsh-v1.md'),
    env: 'WSH_MD_OUT',
  },
  {
    label: 'Rust',
    checkedIn: join(REPO_ROOT, 'crates/wsh-core/src/messages.gen.rs'),
    scratchOut: join(scratch, 'messages.gen.rs'),
    env: 'WSH_RUST_OUT',
  },
];

let drift = false;

try {
  const env = { ...process.env };
  for (const t of targets) env[t.env] = t.scratchOut;

  execFileSync(process.execPath, [join(REPO_ROOT, 'spec/codegen.mjs')], {
    env,
    stdio: 'inherit',
  });

  for (const t of targets) {
    const checkedIn = readFileSync(t.checkedIn, 'utf8');
    const fresh = readFileSync(t.scratchOut, 'utf8');
    if (checkedIn !== fresh) {
      drift = true;
      console.error(`\n✗ ${t.label} output is stale: ${t.checkedIn}`);
      console.error(`  Run \`npm run codegen\` and commit the result.`);
    }
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

if (drift) {
  console.error('\ncodegen:check FAILED — generated files do not match spec/wsh-v1.yaml.');
  process.exit(1);
}

console.log('\n✓ codegen:check passed — all generated files are current.');
