// A browser client (the package bundled for Chromium) against a Node `createWshServer` over a real WebSocket:
// auth, exec, a pty with resize, file transfer and resuming a session (#116).
import { test, expect } from './fixtures.mjs';
import { startServer } from './nodes.mjs';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const children = new Set();
/** A pty shaped like node-pty's, over a pipe-backed shell (there is no node-pty here); records what the page asked of it. */
function fakePty(calls) {
  return (file, args, o) => {
    calls.push(['spawn', o.cols, o.rows]);
    const child = spawn(file, args, { env: o.env, stdio: ['pipe', 'pipe', 'pipe'] });
    children.add(child);
    child.on('close', () => children.delete(child));
    child.stdin.on('error', () => {});
    return {
      onData: (cb) => { child.stdout.on('data', cb); child.stderr.on('data', cb); },
      onExit: (cb) => child.on('close', (code, sig) => cb({ exitCode: code ?? 128, signal: sig })),
      write: (d) => child.stdin.write(d),
      resize: (c, r) => calls.push(['resize', c, r]),
      kill: (sig) => child.kill(sig ?? 'SIGTERM'),
    };
  };
}

test.describe('browser client -> Node host', () => {
  let root; let ctx; let ptyCalls; let authorized;
  test.beforeEach(async ({ page }) => {
    root = await mkdtemp(path.join(tmpdir(), 'wsh-browser-fs-'));
    await writeFile(path.join(root, 'a.txt'), 'hello from the host');
    ptyCalls = [];
    authorized = await page.evaluate(() => window.h.newKey('k', { extractable: false }));
    ctx = await startServer({
      auth: { authorizedKeys: authorized }, exec: true, sessions: true, fs: { root },
      pty: { spawn: fakePty(ptyCalls), shell: '/bin/sh' },
    });
  });
  test.afterEach(async () => {
    for (const c of children) c.kill('SIGKILL');
    await ctx.close();
    await rm(root, { recursive: true, force: true });
  });

  test('authenticates with a non-extractable key, and refuses a key the host does not know', async ({ page }) => {
    const result = await page.evaluate(async (url) => {
      const id = await window.h.connect(url);
      const fp = window.h.client(id).fingerprint ?? null;
      await window.h.disconnect(id);
      await window.h.newKey('stranger');
      const refused = await window.h.connect(url, { key: 'stranger' }).then(() => null, (e) => e.message);
      return { fp, refused, extractable: window.h.key('k').privateKey.extractable };
    }, ctx.url);
    expect(result.extractable).toBe(false);
    expect(result.refused).toMatch(/auth|denied|not authorized|fail/i);
  });

  test('runs exec and reports output and exit code', async ({ page }) => {
    const r = await page.evaluate(async (url) => {
      const id = await window.h.connect(url);
      const sid = await window.h.open(id, { type: 'exec', command: 'echo from-the-host; exit 3' });
      for (let i = 0; i < 100 && window.h.recorder(sid).exit === undefined; i++) await new Promise((r) => setTimeout(r, 50));
      return window.h.recorder(sid);
    }, ctx.url);
    expect(r.text).toBe('from-the-host\n');
    expect(r.exit).toBe(3);
    expect(r.dataMode).toBe('stream');
  });

  test('a pty carries input and output, and a resize reaches the host', async ({ page }) => {
    const sid = await page.evaluate(async (url) => {
      window.id = await window.h.connect(url);
      return window.h.open(window.id, { type: 'pty', cols: 100, rows: 30 });
    }, ctx.url);
    await page.evaluate(([s]) => window.h.session(s).write('echo pty-$((6*7))\n'), [sid]);
    await expect.poll(() => page.evaluate((s) => window.h.recorder(s).text, sid)).toContain('pty-42');
    await page.evaluate(([s]) => window.h.session(s).resize(132, 43), [sid]);
    await expect.poll(() => ptyCalls.filter((c) => c[0] === 'resize')).toEqual([['resize', 132, 43]]);
    expect(ptyCalls[0]).toEqual(['spawn', 100, 30]);
    expect(await page.evaluate((s) => window.h.recorder(s).dataMode, sid)).toBe('virtual');
  });

  test('uploads, downloads and lists files', async ({ page }) => {
    const r = await page.evaluate(async (url) => {
      const id = await window.h.connect(url);
      const c = window.h.client(id);
      await c.upload(window.h.enc.encode('from the page'), '/up.txt');
      const down = window.h.dec.decode(await c.download('/a.txt'));
      const list = (await new window.wsh.WshFileTransfer(c).list('/')).map((e) => e.name).sort();
      const missing = await c.download('/nope.txt').then(() => null, (e) => e.message);
      const escape = await c.download('/../../etc/passwd').then(() => null, (e) => e.message);
      return { down, list, missing, escape };
    }, ctx.url);
    expect(await readFile(path.join(root, 'up.txt'), 'utf8')).toBe('from the page');
    expect(r.down).toBe('hello from the host');
    expect(r.list).toEqual(['a.txt', 'up.txt']);
    expect(r.missing).toMatch(/no such file|ENOENT|not found/i);
    expect(r.escape).toBeTruthy();
  });

  test('resumes an exec session after the socket drops, replaying only what was missed', async ({ page }) => {
    page.allowConsoleErrors.push(/data stream read error: Error: Transport closed/); // the dropped socket, on purpose
    const first = await page.evaluate(async (url) => {
      const id = await window.h.connect(url);
      const sid = await window.h.open(id, { type: 'exec', command: 'echo one; sleep 0.4; echo two; sleep 0.2; exit 4' });
      for (let i = 0; i < 100 && window.h.recorder(sid).text !== 'one\n'; i++) await new Promise((r) => setTimeout(r, 20));
      const rec = window.h.recorder(sid);
      const token = window.h.resumeToken(sid);
      window.h.drop(id); // no Close frame: the network went away
      return { id, rec, token };
    }, ctx.url);
    expect(first.rec.text).toBe('one\n');
    const second = await page.evaluate(async ({ first, url }) => {
      const id = await window.h.connect(url);
      const sid = await window.h.resume(id, first.rec.sessionId, first.token, first.rec.seq);
      for (let i = 0; i < 200 && window.h.recorder(sid).exit === undefined; i++) await new Promise((r) => setTimeout(r, 25));
      return window.h.recorder(sid);
    }, { first, url: ctx.url });
    expect(second.text).toBe('two\n');
    expect(second.exit).toBe(4);
  });
});
