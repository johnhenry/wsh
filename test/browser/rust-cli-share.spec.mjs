// #159, the acceptance case: a host that lives in a real Chromium page reads a file that the freshly BUILT Rust `wsh` CLI shares
// (`wsh --share app=DIR`), through the byte pipe: the page has no disk, the operator's machine has one. Runs the binary named by
// WSH_CLI_BIN (CI builds it first); without it the specs are skipped locally, and fail in CI.
import { test, expect } from './fixtures.mjs';
import { startPipe } from './nodes.mjs';
import { localRustCli, runWsh, spawnWsh } from './rust-cli.mjs';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile, symlink } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';

const cli = localRustCli();
let home; let shareDir; let outsideDir; let pipe; let operatorKey;

test.describe('built Rust CLI --share -> a host in the page', () => {
  test.beforeAll(() => {
    if (!cli && process.env.CI) throw new Error('WSH_CLI_BIN must name the built wsh CLI in CI');
  });
  test.beforeEach(async () => {
    test.skip(!cli, 'set WSH_CLI_BIN to a built wsh (cargo build -p wsh-cli) to run the shared-folder acceptance case');
    home = await mkdtemp(path.join(tmpdir(), 'wsh-rust-share-home-'));
    const base = await mkdtemp(path.join(tmpdir(), 'wsh-rust-share-'));
    shareDir = path.join(base, 'app');
    outsideDir = path.join(base, 'outside');
    await mkdir(shareDir); await mkdir(outsideDir);
    const keygen = await runWsh(cli.path, home, ['keygen'], { insecureLoopbackTls: false });
    expect(keygen.code, keygen.stderr).toBe(0);
    operatorKey = (await readFile(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8')).trim();
    pipe = await startPipe();
  });
  test.afterEach(async () => {
    await pipe?.close();
    if (home) await rm(home, { recursive: true, force: true });
    if (shareDir) await rm(path.dirname(shareDir), { recursive: true, force: true });
  });

  async function share(page, spec) {
    const id = await page.evaluate((o) => window.h.startHost(o), { authorizedKeys: [operatorKey], dataStreams: false, shares: true });
    await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipe.hostUrl]);
    const child = spawnWsh(cli.path, home, ['-p', String(pipe.operatorTlsPort), '-t', 'ws', '--share', spec, '-N', 'alice@127.0.0.1']);
    for (let i = 0; i < 300 && !/sharing/.test(child.err); i++) await new Promise((r) => setTimeout(r, 50));
    expect(child.err, 'wsh said it was sharing').toMatch(/sharing "app"/);
    for (let i = 0; i < 200 && !(await page.evaluate((x) => window.h.shareNames(x), id)).includes('app'); i++) await new Promise((r) => setTimeout(r, 50));
    expect(await page.evaluate((x) => window.h.shareNames(x), id)).toEqual(['app']);
    return { id, child };
  }
  const op = (page, id, ...args) => page.evaluate(([i, ...a]) => window.h.share(i, 'app', ...a), [id, ...args]);

  test('the page lists the directory with attributes and reads a small file and a 6 MiB one (checksum), read-only', async ({ page }) => {
    await writeFile(path.join(shareDir, 'hello.txt'), 'from the operator');
    await mkdir(path.join(shareDir, 'sub'));
    await writeFile(path.join(shareDir, 'sub', 'a.txt'), 'a');
    const big = randomBytes(6 * 1024 * 1024);
    await writeFile(path.join(shareDir, 'big.bin'), big);
    const { id, child } = await share(page, `app=${shareDir}`);
    const list = await op(page, id, 'readdir', '/');
    expect(list.value.map((e) => [e.name, e.type])).toEqual([['big.bin', 'file'], ['hello.txt', 'file'], ['sub', 'directory']]);
    expect(list.value.find((e) => e.name === 'hello.txt').size).toBe(17);
    expect((await op(page, id, 'readFile', '/hello.txt')).text).toBe('from the operator');
    const got = await op(page, id, 'readFile', '/big.bin');
    expect(got.bytes).toBe(big.length);
    expect(got.sha256).toBe(createHash('sha256').update(big).digest('hex'));
    // Read-only by default: a write is refused and the file is untouched.
    expect((await op(page, id, 'writeFile', '/hello.txt', 'x')).error).toBe('EROFS');
    expect(await readFile(path.join(shareDir, 'hello.txt'), 'utf8')).toBe('from the operator');
    child.kill('SIGINT');
    expect(await child.exited).toBe(0);
  });

  test(':rw lets the page write a file; a symlink out of the share is never followed', async ({ page }) => {
    await writeFile(path.join(outsideDir, 'secret.txt'), 'TOP SECRET');
    await symlink(path.join(outsideDir, 'secret.txt'), path.join(shareDir, 'link'));
    const { id, child } = await share(page, `app=${shareDir}:rw`);
    expect((await op(page, id, 'writeFile', '/built.txt', 'built in a tab')).value).toBeTruthy();
    expect(await readFile(path.join(shareDir, 'built.txt'), 'utf8')).toBe('built in a tab');
    expect((await op(page, id, 'readFile', '/link')).error).toBe('ELOOP');
    expect((await op(page, id, 'writeFile', '/link', 'pwn')).error).toMatch(/ELOOP|EEXIST/);
    expect((await op(page, id, 'readFile', '/../outside/secret.txt')).error).toBe('EINVAL');
    expect(await readFile(path.join(outsideDir, 'secret.txt'), 'utf8')).toBe('TOP SECRET');
    child.kill('SIGINT');
    expect(await child.exited).toBe(0);
  });
});
