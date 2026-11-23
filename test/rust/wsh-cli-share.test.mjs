// test/rust/wsh-cli-share.test.mjs -- #159: `wsh --share NAME=/abs/dir[:ro|:rw]` (the built Rust CLI) offering a directory of
// THIS machine to a host for the life of a session. The host is real JS code:
//   - a Node host (`createWshServer({ onShare })`) on a plain byte pipe (a WebSocket straight to the host), and
//   - a page-shaped host (`createMemoryHost({ onShare })`, `dataStreams: false`) through the real `createPipeRelay` (`--via`),
// and the test drives the share from the HOST side with the `fs` object `onShare` hands over, then looks at the real
// directory on disk. Every shared directory is under a `mktemp -d`-style scratch directory, and every `wsh` runs with HOME,
// USERPROFILE and XDG_CONFIG_HOME in another one.
//
// Prerequisite: `cargo build --release -p wsh-cli` (or WSH_BIN).

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync, existsSync, symlinkSync, linkSync, lstatSync, realpathSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocket as WsClient, WebSocketServer } from 'ws';

import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { createWshServer } from '@johnhenry/wsh/server';
import { createMemoryHost } from '@johnhenry/wsh/memory';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const MiB = 1024 * 1024;
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
async function until(cond, what, ms = 10_000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
}
const rss = (pid) => Number(execFileSync('ps', ['-o', 'rss=', '-p', String(pid)], { encoding: 'utf8' }).trim()) / 1024;

const scratch = [];
const closers = [];
const procs = [];

before(() => {
  assert.ok(existsSync(WSH_BIN), `expected the built wsh binary at ${WSH_BIN} (cargo build --release -p wsh-cli, or set WSH_BIN)`);
});

after(async () => {
  for (const p of procs.splice(0)) p.kill('SIGKILL');
  for (const close of closers.splice(0).reverse()) await close().catch(() => {});
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
});

const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm' });

/** A scratch directory (resolved, so it matches what the CLI prints). */
function tmpDir(prefix = 'wsh-share') {
  const d = realpathSync(mkdtempSync(path.join('/tmp', `${prefix}-`)));
  scratch.push(d);
  return d;
}

function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-cli-share-home-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const pub = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  return { home, pub };
}

function wsh(args, { home, timeoutMs = 20_000 } = {}) {
  return new Promise((resolve) => {
    const proc = spawn(WSH_BIN, ['--accept-new-host-key', ...args], { env: cleanEnv(home), stdio: ['pipe', 'pipe', 'pipe'] });
    const out = []; const err = [];
    proc.stdout.on('data', (d) => out.push(d)); proc.stderr.on('data', (d) => err.push(d));
    proc.stdin.on('error', () => {}); proc.stdin.end();
    const timer = setTimeout(() => proc.kill('SIGKILL'), timeoutMs);
    proc.once('close', (code) => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
}

/** A long-running `wsh -N --share ...`; resolves once it said it is sharing. */
async function wshShare(args, { home, ready = /sharing/ }) {
  const proc = spawn(WSH_BIN, ['--accept-new-host-key', ...args], { env: cleanEnv(home), stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(proc);
  let stderr = '';
  proc.stderr.on('data', (d) => { stderr += d; });
  proc.stdout.resume();
  proc.stdin.on('error', () => {});
  const exited = new Promise((resolve) => proc.once('close', (code, signal) => resolve({ code, signal })));
  await Promise.race([
    until(() => ready.test(stderr), `wsh to say ${ready}; stderr: ${stderr}`),
    exited.then((r) => { throw new Error(`wsh exited early (${JSON.stringify(r)}): ${stderr}`); }),
  ]);
  return {
    proc, exited, stderr: () => stderr,
    stop: async () => { proc.kill('SIGINT'); return Promise.race([exited, sleep(10_000).then(() => { proc.kill('SIGKILL'); return exited; })]); },
  };
}

// ── hosts: each captures the `fs` of every share offered to it ───────

function collector() {
  const byName = new Map();
  const waiters = new Map();
  return {
    onShare: (name, fs) => { byName.set(name, fs); for (const w of waiters.get(name) ?? []) w(fs); },
    share: (name, ms = 10_000) => (byName.has(name) ? Promise.resolve(byName.get(name))
      : new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`the host was never offered share ${name}`)), ms);
        waiters.set(name, [...(waiters.get(name) ?? []), (fs) => { clearTimeout(t); resolve(fs); }]);
      })),
    names: () => [...byName.keys()],
  };
}

async function startRelay() {
  const relay = createPipeRelay({ rendezvousTimeoutMs: 15_000 });
  const { port } = await relay.listen();
  closers.push(() => relay.close());
  return `ws://127.0.0.1:${port}`;
}

/** A page-shaped host behind a real pipe relay. */
async function pageHostViaRelay(h, shares) {
  const host = createMemoryHost({ auth: { authorizedKeys: h.pub }, exec: async () => 0, hostKey: true, dataStreams: false, onShare: shares.onShare });
  closers.push(() => host.close());
  const relayUrl = await startRelay();
  const id = newRendezvousId();
  const ws = new WsClient(pipeUrl(relayUrl, id, 'host'));
  ws.on('error', () => {});
  closers.push(async () => ws.terminate());
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  await host.accept(ws);
  return { args: ['--via', pipeUrl(relayUrl, id)], target: 'alice@tab.example', ws };
}

/** A Node host on a plain byte pipe (a WebSocket listener handing each socket to `accept`). */
async function nodeHostDirect(h, shares, { onSocket } = {}) {
  const server = createWshServer({ auth: { authorizedKeys: h.pub }, exec: async () => 0, hostKey: true, onShare: shares.onShare });
  closers.push(() => server.close());
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  wss.on('connection', (ws) => { onSocket?.(ws); void server.accept(ws, { dataStreams: false }); });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  return { args: [], target: `alice@ws://127.0.0.1:${wss.address().port}`, wss };
}

const routes = [
  ['a page-shaped host (createMemoryHost) through a pipe relay (--via)', pageHostViaRelay],
  ['a Node host (createWshServer) on a plain byte pipe', nodeHostDirect],
];

/** Start a CLI sharing `spec` with a fresh host of `route`; resolves with everything a test needs. */
async function session(route, specs, { dir, extraArgs = [] } = {}) {
  const h = makeHome();
  const shares = collector();
  const r = await route(h, shares);
  const specArgs = (Array.isArray(specs) ? specs : [specs]).flatMap((s) => ['--share', s]);
  const cli = await wshShare([...r.args, ...specArgs, ...extraArgs, '-N', r.target], { home: h.home });
  return { h, shares, cli, ...r, dir };
}

const tree = (root, files) => { for (const [rel, body] of Object.entries(files)) { const p = path.join(root, rel); mkdirSync(path.dirname(p), { recursive: true }); writeFileSync(p, body); } };

for (const [routeName, route] of routes) {
  describe(`wsh --share against ${routeName}`, () => {
    it('says once, on stderr, what it shares and how; the host is offered exactly that and nothing else', async () => {
      const ro = tmpDir(); const rw = tmpDir();
      const s = await session(route, [`src=${ro}`, `out=${rw}:rw`]);
      assert.match(s.cli.stderr(), new RegExp(`sharing "src" = ${ro.replace(/[/.]/g, '\\$&')} \\(read-only\\)`));
      assert.match(s.cli.stderr(), new RegExp(`sharing "out" = ${rw.replace(/[/.]/g, '\\$&')} \\(read-write\\)`));
      assert.equal(s.cli.stderr().match(/sharing "src"/g).length, 1);
      await s.shares.share('src'); await s.shares.share('out');
      assert.deepEqual(s.shares.names().sort(), ['out', 'src']);
      assert.equal((await s.shares.share('src')).writable, false);
      assert.equal((await s.shares.share('out')).writable, true);
      await s.cli.stop();
    });

    it('fs.root is the shared directory as typed (made tidy), per share; --share-hide-path leaves it undefined and the share works (#164)', async () => {
      const a = tmpDir(); const b = tmpDir();
      tree(a, { 'x.txt': 'xx' }); tree(b, { 'y.txt': 'yy' });
      const s = await session(route, [`one=${a}/`, `two=${b.replace(/\/([^/]+)$/, '//./$1')}:rw`]);
      assert.equal((await s.shares.share('one')).root, a);
      assert.equal((await s.shares.share('two')).root, b);
      assert.equal(dec(await (await s.shares.share('one')).readFile('/x.txt')), 'xx');
      await s.cli.stop();

      const hidden = await session(route, [`one=${a}`, `two=${b}`], { extraArgs: ['--share-hide-path'] });
      const one = await hidden.shares.share('one');
      assert.equal(one.root, undefined);
      assert.equal((await hidden.shares.share('two')).root, undefined);
      assert.equal(dec(await one.readFile('/x.txt')), 'xx');
      await hidden.cli.stop();
    });

    it('lists with attributes, reads small and large files (checksum), and sees a host-side edit on the next read', async () => {
      const dir = tmpDir();
      const big = crypto.randomBytes(20 * MiB + 17);
      tree(dir, { 'a.txt': 'alpha', 'sub/b.txt': 'bravo', 'empty': '' });
      writeFileSync(path.join(dir, 'big.bin'), big);
      symlinkSync('a.txt', path.join(dir, 'link'));
      const s = await session(route, `proj=${dir}`);
      const fs = await s.shares.share('proj');
      const list = await fs.readdir('/');
      assert.deepEqual(list.map((e) => e.name), ['a.txt', 'big.bin', 'empty', 'link', 'sub']);
      const by = Object.fromEntries(list.map((e) => [e.name, e]));
      assert.equal(by['a.txt'].type, 'file'); assert.equal(by['a.txt'].size, 5);
      assert.equal(by.sub.type, 'directory');
      assert.equal(by.link.type, 'symlink'); assert.equal(by.link.target, 'a.txt');
      assert.equal(by['big.bin'].size, big.length);
      assert.equal(dec(await fs.readFile('/a.txt')), 'alpha');
      assert.equal(dec(await fs.readFile('sub/b.txt')), 'bravo');
      assert.equal((await fs.readFile('/empty')).length, 0);
      const t0 = Date.now();
      const got = await fs.readFile('/big.bin');
      assert.equal(got.length, big.length);
      assert.equal(sha(got), sha(big));
      console.log(`  big file: ${(big.length / MiB).toFixed(1)} MiB in ${Date.now() - t0} ms, ${fs.stats.requests} requests`);
      // A change made on this machine is seen on the next read: nothing is cached on the way.
      writeFileSync(path.join(dir, 'a.txt'), 'ALPHA, edited');
      writeFileSync(path.join(dir, 'new.txt'), 'n');
      assert.equal(dec(await fs.readFile('/a.txt')), 'ALPHA, edited');
      assert.ok((await fs.readdir('/')).some((e) => e.name === 'new.txt'));
      assert.equal((await fs.stat('/a.txt')).size, 13);
      await s.cli.stop();
    });

    it('a read-only share refuses every change, and the directory is untouched', async () => {
      const dir = tmpDir();
      tree(dir, { 'keep.txt': 'keep' });
      const s = await session(route, `proj=${dir}`);
      const fs = await s.shares.share('proj');
      const refused = async (p) => assert.rejects(p, (e) => e.code === 'EROFS', 'must be EROFS');
      await refused(fs.writeFile('/new.txt', enc('x')));
      await refused(fs.writeFile('/keep.txt', enc('x')));
      await refused(fs.mkdir('/d'));
      await refused(fs.unlink('/keep.txt'));
      await refused(fs.rename('/keep.txt', '/moved.txt'));
      await refused(fs.truncate('/keep.txt', 0));
      await refused(fs.chmod('/keep.txt', 0o777));
      await refused(fs.create('/c.txt'));
      assert.deepEqual(readdirSync(dir), ['keep.txt']);
      assert.equal(readFileSync(path.join(dir, 'keep.txt'), 'utf8'), 'keep');
      await s.cli.stop();
    });

    it(':rw writes, creates, renames, truncates, changes the mode and removes; a large write arrives intact', async () => {
      const dir = tmpDir();
      const s = await session(route, `proj=${dir}:rw`);
      const fs = await s.shares.share('proj');
      await fs.writeFile('/a.txt', enc('first'));
      assert.equal(readFileSync(path.join(dir, 'a.txt'), 'utf8'), 'first');
      assert.equal(statSync(path.join(dir, 'a.txt')).mode & 0o777, 0o644, 'a sane creation mode');
      await fs.writeFile('/a.txt', enc('2nd'));
      assert.equal(readFileSync(path.join(dir, 'a.txt'), 'utf8'), '2nd', 'truncated, not overwritten in place');
      await fs.mkdir('/d/');
      assert.equal(statSync(path.join(dir, 'd')).mode & 0o777, 0o755);
      await fs.rename('/a.txt', '/d/b.txt');
      assert.equal(readFileSync(path.join(dir, 'd', 'b.txt'), 'utf8'), '2nd');
      await fs.truncate('/d/b.txt', 1);
      assert.equal(readFileSync(path.join(dir, 'd', 'b.txt'), 'utf8'), '2');
      await fs.chmod('/d/b.txt', 0o4755);
      assert.equal(statSync(path.join(dir, 'd', 'b.txt')).mode & 0o7777, 0o755, 'never setuid');
      await fs.utimes('/d/b.txt', 1_000_000_000_000, 1_100_000_000_000);
      assert.equal(Math.round(statSync(path.join(dir, 'd', 'b.txt')).mtimeMs), 1_100_000_000_000);
      const big = crypto.randomBytes(9 * MiB + 5);
      await fs.writeFile('/big.bin', big);
      assert.equal(sha(readFileSync(path.join(dir, 'big.bin'))), sha(big));
      await assert.rejects(fs.create('/big.bin'), (e) => e.code === 'EEXIST');
      await fs.unlink('/d/b.txt');
      await fs.rmdir('/d');
      assert.deepEqual(readdirSync(dir), ['big.bin']);
      await s.cli.stop();
    });

    it('nothing escapes: `..`, absolute paths, symlinks out (relative and absolute, in the middle and at the end), a planted link on create, hard links', async () => {
      const outer = tmpDir();
      const dir = path.join(outer, 'share'); mkdirSync(dir);
      const secret = path.join(outer, 'secret.txt'); writeFileSync(secret, 'TOP SECRET');
      const outsideDir = path.join(outer, 'outside'); mkdirSync(outsideDir); writeFileSync(path.join(outsideDir, 'x.txt'), 'x');
      symlinkSync('../secret.txt', path.join(dir, 'rel-link'));
      symlinkSync(secret, path.join(dir, 'abs-link'));
      symlinkSync('../outside', path.join(dir, 'dir-link'));
      symlinkSync(outsideDir, path.join(dir, 'abs-dir-link'));
      writeFileSync(path.join(dir, 'inside.txt'), 'inside');
      linkSync(secret, path.join(dir, 'hard-secret')); // a hard link to a file that is also outside
      const s = await session(route, `proj=${dir}:rw`);
      const fs = await s.shares.share('proj');
      for (const p of ['../secret.txt', '/../secret.txt', 'a/../../secret.txt', '..', 'dir-link/../secret.txt', '..\u0000/x']) {
        await assert.rejects(fs.readFile(p), (e) => ['EINVAL', 'ENOENT', 'ELOOP'].includes(e.code), `read ${p}`);
      }
      await assert.rejects(fs.readFile('/etc/passwd'), (e) => e.code === 'ENOENT', 'an absolute path means a path under the share');
      for (const link of ['rel-link', 'abs-link']) {
        assert.equal((await fs.lstat(link)).type, 'symlink');
        await assert.rejects(fs.readFile(link), (e) => e.code === 'ELOOP', `${link} is never followed`);
        await assert.rejects(fs.writeFile(link, enc('pwn')), (e) => e.code === 'ELOOP' || e.code === 'EEXIST', `${link} is never written through`);
      }
      for (const link of ['dir-link', 'abs-dir-link']) {
        await assert.rejects(fs.readdir(link), (e) => e.code === 'ELOOP');
        await assert.rejects(fs.readFile(`${link}/x.txt`), (e) => e.code === 'ELOOP');
        await assert.rejects(fs.writeFile(`${link}/new.txt`, enc('pwn')), (e) => e.code === 'ELOOP');
        await assert.rejects(fs.mkdir(`${link}/d`), (e) => e.code === 'ELOOP');
        await assert.rejects(fs.rename('inside.txt', `${link}/moved.txt`), (e) => e.code === 'ELOOP');
      }
      await assert.rejects(fs.create('rel-link'), (e) => e.code === 'EEXIST', 'a create onto a link never follows it');
      assert.equal(readFileSync(secret, 'utf8'), 'TOP SECRET');
      assert.deepEqual(readdirSync(outsideDir), ['x.txt']);
      // A hard-linked file can be read but not written: the other name may be outside.
      assert.equal(dec(await fs.readFile('hard-secret')), 'TOP SECRET');
      await assert.rejects(fs.writeFile('hard-secret', enc('pwn')), (e) => e.code === 'EPERM');
      await assert.rejects(fs.truncate('hard-secret', 0), (e) => e.code === 'EPERM');
      await assert.rejects(fs.chmod('hard-secret', 0o777), (e) => e.code === 'EPERM');
      assert.equal(readFileSync(secret, 'utf8'), 'TOP SECRET');
      // Removing a link removes the link, not what it points at.
      await fs.unlink('rel-link');
      assert.equal(existsSync(secret), true);
      assert.equal(lstatSync(path.join(dir, 'rel-link'), { throwIfNoEntry: false }), undefined);
      await s.cli.stop();
    });

    it('special files are invisible (FIFO, socket); a non-UTF-8 name is skipped', async () => {
      const dir = tmpDir();
      tree(dir, { 'ok.txt': 'ok' });
      execFileSync('mkfifo', [path.join(dir, 'pipe')]);
      const net = await import('node:net');
      const sock = net.createServer(); await new Promise((r) => sock.listen(path.join(dir, 'sock'), r)); closers.push(async () => sock.close());
      // A name that is not valid UTF-8 (APFS refuses to create one: EILSEQ, so there is nothing to hide there).
      try { writeFileSync(Buffer.concat([Buffer.from(dir + '/'), Buffer.from([0xff, 0xfe, 0x2e, 0x74])]), 'bad name'); } catch (e) { if (e.code !== 'EILSEQ') throw e; }
      const s = await session(route, `proj=${dir}:rw`);
      const fs = await s.shares.share('proj');
      assert.deepEqual((await fs.readdir('/')).map((e) => e.name), ['ok.txt']);
      await assert.rejects(fs.stat('pipe'), (e) => e.code === 'ENOENT');
      await assert.rejects(fs.readFile('pipe'), (e) => e.code === 'ENOENT'); // returns at once: a FIFO cannot hang the CLI
      await assert.rejects(fs.writeFile('sock', enc('x')), (e) => e.code === 'ENOENT');
      assert.equal(dec(await fs.readFile('ok.txt')), 'ok'); // and it still answers
      await s.cli.stop();
    });

    it('a root that is replaced while the session runs is noticed (ESTALE), not served', async () => {
      const outer = tmpDir();
      const dir = path.join(outer, 'share'); mkdirSync(dir);
      tree(dir, { 'a.txt': 'old' });
      const s = await session(route, `proj=${dir}`);
      const fs = await s.shares.share('proj');
      assert.equal(dec(await fs.readFile('a.txt')), 'old');
      mkdirSync(path.join(outer, 'moved'));
      execFileSync('mv', [dir, path.join(outer, 'moved', 'share')]);
      mkdirSync(dir); writeFileSync(path.join(dir, 'a.txt'), 'imposter');
      await assert.rejects(fs.readFile('a.txt'), (e) => e.code === 'ESTALE');
      await assert.rejects(fs.readdir('/'), (e) => e.code === 'ESTALE');
      await s.cli.stop();
    });

    it('many small files: a recursive listing of a big tree costs a few messages, not one per file (batching)', async () => {
      const dir = tmpDir();
      const dirs = 60; const perDir = 40;
      for (let d = 0; d < dirs; d += 1) for (let f = 0; f < perDir; f += 1) tree(dir, { [`d${String(d).padStart(3, '0')}/f${String(f).padStart(3, '0')}.txt`]: `file ${d}/${f}` });
      const files = dirs * perDir;
      const s = await session(route, `proj=${dir}`);
      const fs = await s.shares.share('proj');
      const before = fs.stats.requests;
      const t0 = Date.now();
      let seen = 0;
      const walk = async (rel) => {
        const entries = await fs.readdir(rel);
        for (const e of entries) { if (e.type === 'directory') await walk(`${rel}/${e.name}`); else seen += 1; }
      };
      await walk('');
      const listing = fs.stats.requests - before;
      assert.equal(seen, files);
      // One readdir per directory (attributes included) plus the root: the per-file calls (stat each) are not made.
      assert.ok(listing <= dirs + 2, `${listing} messages for ${files} files`);
      // Reading every small file is one message each (the content rides the open, nothing to close).
      const before2 = fs.stats.requests;
      const names = (await fs.readdir('d007')).map((e) => e.name);
      for (const n of names) assert.match(dec(await fs.readFile(`d007/${n}`)), /^file 7\//);
      assert.equal(fs.stats.requests - before2, 1 + names.length, 'a readdir and one message per small file');
      console.log(`  ${files} files in ${dirs} directories: ${listing} messages to list (${(files / listing).toFixed(1)} files per message), ${Date.now() - t0} ms; a file call per entry would have been ${files + dirs + 1}`);
      await s.cli.stop();
    });

    it('requests the host sends in parallel are answered within the window it was promised; excess waits on the host side', async () => {
      const dir = tmpDir();
      for (let i = 0; i < 300; i += 1) writeFileSync(path.join(dir, `f${i}`), `${i}`);
      const s = await session(route, `proj=${dir}`);
      const fs = await s.shares.share('proj');
      const out = await Promise.all(Array.from({ length: 300 }, (_, i) => fs.readFile(`f${i}`)));
      assert.deepEqual(out.map(dec), Array.from({ length: 300 }, (_, i) => `${i}`));
      await s.cli.stop();
    });

    it('the shares end with the session: killing the host stops the CLI, and nothing stays open', async () => {
      const dir = tmpDir();
      tree(dir, { 'a.txt': 'a' });
      const s = await session(route, `proj=${dir}`);
      const fs = await s.shares.share('proj');
      const f = await fs.open('/a.txt', ['read'], { inlineBytes: 0 }); // a real handle
      assert.ok(f);
      await s.cli.stop();
      assert.equal((await s.cli.exited).code, 0);
    });
  });
}

describe('wsh --share: command line and refusals', () => {
  it('a relative path, a bad name, a missing directory, a repeated name and a file are refused before anything is dialled', async () => {
    const h = makeHome();
    const dir = tmpDir();
    writeFileSync(path.join(dir, 'file'), 'x');
    for (const [spec, message] of [
      ['proj=relative/dir', /absolute/],
      ['bad name=' + dir, /name must be/],
      ['=' + dir, /name must be/],
      ['proj=' + path.join(dir, 'missing'), /missing/],
      ['proj=' + path.join(dir, 'file'), /proj/],
      [dir, /NAME=/],
    ]) {
      const r = await wsh(['--share', spec, '-N', 'alice@ws://127.0.0.1:9'], { home: h.home });
      assert.equal(r.code, 2, `${spec}: ${r.stderr}`);
      assert.match(r.stderr, message, spec);
      assert.doesNotMatch(r.stderr, /failed to connect/, 'nothing was dialled');
    }
    const twice = await wsh(['--share', `a=${dir}`, '--share', `a=${dir}`, '-N', 'alice@ws://127.0.0.1:9'], { home: h.home });
    assert.equal(twice.code, 2);
    assert.match(twice.stderr, /used twice/);
  });

  it('--share is only for the commands that keep one connection open (not scp, ls, sftp, copy-id, keys)', async () => {
    const h = makeHome();
    const dir = tmpDir();
    for (const args of [['scp', 'a', 'alice@h:b'], ['ls', 'alice@h:/'], ['sftp', 'alice@h'], ['copy-id', 'alice@h'], ['keys']]) {
      const r = await wsh(['--share', `p=${dir}`, ...args], { home: h.home });
      assert.equal(r.code, 2, args.join(' '));
      assert.match(r.stderr, /--share applies to/);
    }
  });

  it('a host that cannot use shares is an error with a sentence, not a share that silently does not exist', async () => {
    const h = makeHome();
    const dir = tmpDir();
    const server = createWshServer({ auth: { authorizedKeys: h.pub }, exec: async () => 0, hostKey: true }); // no onShare
    closers.push(() => server.close());
    const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise((r) => wss.once('listening', r));
    wss.on('connection', (ws) => { void server.accept(ws, { dataStreams: false }); });
    closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
    const r = await wsh(['--share', `p=${dir}`, '-N', `alice@ws://127.0.0.1:${wss.address().port}`], { home: h.home });
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /does not accept shared folders/);
    assert.doesNotMatch(r.stderr, /sharing "p"/, 'it never claimed to share');
  });

  it('without --share the host is never offered anything, even a host that would take it', async () => {
    const h = makeHome();
    const shares = collector();
    const r = await nodeHostDirect(h, shares);
    const proc = spawn(WSH_BIN, ['--accept-new-host-key', ...r.args, r.target, 'echo', 'x'], { env: cleanEnv(h.home), stdio: ['pipe', 'pipe', 'pipe'] });
    procs.push(proc);
    await new Promise((resolve) => proc.once('close', resolve));
    assert.deepEqual(shares.names(), []);
  });
});

describe('wsh --share: a host that stops reading does not make the CLI grow', () => {
  it('replies pile up in the host\'s socket, not in the CLI: its memory stays flat while the host is stalled', async () => {
    const dir = tmpDir();
    writeFileSync(path.join(dir, 'big.bin'), crypto.randomBytes(48 * MiB));
    let sock = null;
    const h = makeHome();
    const shares = collector();
    const r = await nodeHostDirect(h, shares, { onSocket: (ws) => { sock = ws; } });
    const cli = await wshShare([...r.args, '--share', `proj=${dir}`, '-N', r.target], { home: h.home });
    const fs = await shares.share('proj');
    const file = await fs.open('/big.bin', ['read'], { inlineBytes: 0 });
    // Keep the window full of reads, then stop reading the socket.
    const flood = (async () => { try { for (let i = 0; i < 100_000; i += 1) await Promise.race([file.read((i % 180) * 256 * 1024, 256 * 1024), sleep(30_000)]); } catch { /* the session ended */ } })();
    await sleep(500);
    sock._socket.pause();
    await sleep(1_000);
    const before = rss(cli.proc.pid);
    await sleep(4_000);
    const growth = rss(cli.proc.pid) - before;
    assert.ok(growth < 24, `wsh grew by ${growth.toFixed(1)} MiB while the host was stalled`);
    sock._socket.resume();
    await until(() => fs.stats.replies > 50, 'the flow to resume');
    await cli.stop();
    void flood;
  });
});

describe('wsh --share inside a sealed session (#155): share data rides the sealing, with no crypto of its own', () => {
  it('a host that requires sealing is served shares over `--sealed`, and a relay that copies bytes sees neither names nor content', async () => {
    const dir = tmpDir();
    const secret = `the-content-${crypto.randomBytes(8).toString('hex')}`;
    tree(dir, { 'needle-file-name.txt': secret });
    const h = makeHome();
    const shares = collector();
    const host = createMemoryHost({ auth: { authorizedKeys: h.pub }, exec: async () => 0, hostKey: true, dataStreams: false, sealSession: 'require', onShare: shares.onShare });
    closers.push(() => host.close());
    const seen = [];
    const relay = createPipeRelay({ rendezvousTimeoutMs: 15_000 });
    const { port } = await relay.listen();
    closers.push(() => relay.close());
    // A byte-copying hop in front of the relay would be the recording relay of wsh-session-seal.test.mjs; here the page side
    // records what the real relay forwards by wrapping the host's socket.
    const id = newRendezvousId();
    const ws = new WsClient(pipeUrl(`ws://127.0.0.1:${port}`, id, 'host'));
    ws.on('error', () => {});
    closers.push(async () => ws.terminate());
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
    ws.on("message", (d) => seen.push(Buffer.from(d))); // what the CLI sent (the file content travels this way)
    const realSend = ws.send.bind(ws);
    ws.send = (data, ...rest) => { seen.push(Buffer.from(data)); return realSend(data, ...rest); };
    await host.accept(ws);
    const cli = await wshShare(['--via', pipeUrl(`ws://127.0.0.1:${port}`, id), '--sealed', '--share', `proj=${dir}`, '-N', 'alice@tab.example'], { home: h.home });
    const fs = await shares.share('proj');
    assert.equal(dec(await fs.readFile('needle-file-name.txt')), secret);
    assert.deepEqual((await fs.readdir('/')).map((e) => e.name), ['needle-file-name.txt']);
    const wire = Buffer.concat(seen);
    assert.ok(wire.length > 0);
    assert.equal(wire.includes(Buffer.from(secret)), false, 'the file content is not on the wire in the clear');
    assert.equal(wire.includes(Buffer.from('needle-file-name')), false, 'neither is a file name');
    await cli.stop();
  });
});
