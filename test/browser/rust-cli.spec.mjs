// THE RELEASED RUST CLI AS OPERATOR of a host that lives in the page (#116, #132).
//
// This downloads the latest `rust-v*` release's `wsh` CLI from github.com/johnhenry/wsh/releases, verifies it against the
// release's SHA256SUMS, and runs it with HOME pointed at a temp directory (so it never reads or writes the real ~/.wsh).
// It is skipped, with the reason, on a platform with no release asset or when the download fails; on ubuntu CI it runs.
//
// The CLI only dials `wss://`, so the byte pipe terminates TLS with a self-signed certificate and the CLI is run with its
// WSH_INSECURE_LOOPBACK_TLS switch (loopback only). Everything past the pipe is the page's `createMemoryHost().accept(new WebSocket(...))`.
import { test, expect } from './fixtures.mjs';
import { startPipe } from './nodes.mjs';
import { fetchLatestRustCli, runWsh, releaseTarget } from './rust-cli.mjs';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

let cli = null; let skip = null; let work;
let home; let pipe; let operatorKey;

test.describe('released Rust CLI -> host in the page', () => {
  test.beforeAll(async () => {
    work = await mkdtemp(path.join(tmpdir(), 'wsh-rust-cli-'));
    try {
      const got = await fetchLatestRustCli(work);
      if (got.skip) skip = got.skip; else cli = got;
    } catch (e) {
      // A failed checksum must fail the suite, not skip it.
      if (/SHA256SUMS/.test(e.message)) throw e;
      skip = `could not set up the released Rust CLI (${e.message})`;
    }
    // In CI a platform that has a release asset must run these: a skip there would hide a broken release or download.
    if (skip && process.env.CI && releaseTarget()) throw new Error(`the Rust CLI tests must run in CI, but: ${skip}`);
    if (skip) console.warn(`SKIPPING the Rust CLI tests: ${skip}`);
    else console.log(`Rust CLI under test: ${cli.tag} (${releaseTarget()})`);
  });
  test.afterAll(async () => { await rm(work, { recursive: true, force: true }); });

  test.beforeEach(async () => {
    test.skip(!!skip, skip ?? '');
    home = await mkdtemp(path.join(tmpdir(), 'wsh-rust-home-'));
    const keygen = await runWsh(cli.path, home, ['keygen'], { insecureLoopbackTls: false });
    expect(keygen.code, keygen.stderr).toBe(0);
    operatorKey = (await readFile(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8')).trim();
    pipe = await startPipe();
  });
  test.afterEach(async () => {
    await pipe?.close();
    if (home) await rm(home, { recursive: true, force: true });
  });

  /** A host in the page that trusts the CLI's key, served on one pipe socket. */
  async function startHost(page, options = {}) {
    const id = await page.evaluate((o) => window.h.startHost(o), { authorizedKeys: [operatorKey], dataStreams: false, ...options });
    await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipe.hostUrl]);
    return id;
  }
  const wsh = (args, o) => runWsh(cli.path, home, ['-p', String(pipe.operatorTlsPort), '-t', 'ws', ...args], o);

  test('exec: output and exit status come back (dataStreams: false)', async ({ page }) => {
    await startHost(page);
    const r = await wsh(['alice@127.0.0.1', 'hello', 'from', 'rust']);
    expect(r.stderr).not.toMatch(/panicked|does not support real data streams/);
    expect(r.stdout).toBe('ran:hello from rust\n');
    expect(r.code).toBe(3);
  });

  test('file listing (`wsh ls`) from the page\'s file backend', async ({ page }) => {
    await startHost(page, { initialFiles: { '/hello.txt': 'file held by the page' } });
    const ls = await wsh(['ls', 'alice@127.0.0.1:/']);
    expect(ls.code, ls.stderr).toBe(0);
    expect(ls.stdout).toContain('hello.txt');
  });

  test('a pinned host key (non-extractable, in the page) is verified through known_hosts; a changed one is refused', async ({ page }) => {
    const id = await startHost(page, { hostKey: 'pair' });
    const fp = (await page.evaluate((i) => window.h.hostInfo(i), id)).hostFingerprint;
    await mkdir(path.join(home, '.wsh'), { recursive: true });
    await writeFile(path.join(home, '.wsh', 'known_hosts'), `127.0.0.1:${pipe.operatorTlsPort} ${fp}\n`);
    const ok = await wsh(['alice@127.0.0.1', 'pinned']);
    expect(ok.stdout).toBe('ran:pinned\n');
    expect(ok.code).toBe(3);

    await startHost(page, { hostKey: 'signer' }); // a different key than the one on file: the CLI wants a person to confirm
    const changed = await wsh(['alice@127.0.0.1', 'changed']);
    expect(changed.code).not.toBe(3);
    expect(changed.stdout).toBe('');
    expect(changed.stderr).toMatch(/HOST KEY CHANGED|HOST IDENTIFICATION HAS CHANGED/);
  });
});
