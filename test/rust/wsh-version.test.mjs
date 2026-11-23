// test/rust/wsh-version.test.mjs -- #163: `wsh --version` and `wsh-server --version` print the workspace version of the build
// (it printed a fixed "0.1.0" for every release), so documentation can say "needs rust-v0.10.0 or newer" and a user can check.
//
// Prerequisite: `cargo build --release -p wsh-cli -p wsh-server` (or WSH_BIN / WSH_SERVER_BIN). Runs with HOME in a scratch directory.

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const WORKSPACE_VERSION = /\[workspace\.package\][^[]*?\nversion\s*=\s*"([^"]+)"/.exec(readFileSync(path.join(REPO_ROOT, 'Cargo.toml'), 'utf8'))?.[1];

let home;
before(() => { home = mkdtempSync(path.join(tmpdir(), 'wsh-version-')); });
after(() => { rmSync(home, { recursive: true, force: true }); });
const run = (bin, ...args) => execFileSync(bin, args, { env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config') }, encoding: 'utf8' }).trim();

describe('--version (#163)', () => {
  it('the test can read the workspace version', () => { assert.match(WORKSPACE_VERSION ?? '', /^\d+\.\d+\.\d+/); });

  it('wsh prints the workspace version, with --version and -V', () => {
    assert.equal(run(WSH_BIN, '--version'), `wsh ${WORKSPACE_VERSION}`);
    assert.equal(run(WSH_BIN, '-V'), `wsh ${WORKSPACE_VERSION}`);
  });

  it('wsh-server prints the same version', () => {
    assert.equal(run(SERVER_BIN, '--version'), `wsh-server ${WORKSPACE_VERSION}`);
  });
});
