// A SEALED SESSION (#155, stage b), the embedder's case in a real Chromium page: a host that lives in the page, with
// `sealSession: 'require'`, reached by the freshly BUILT Rust `wsh --sealed -N -L sock:endpoint=NAME` through a byte-copying
// pipe. The pipe records every byte it copies; the endpoint's traffic must not be among them. Runs the binary named by
// WSH_CLI_BIN (CI builds it first); without it the specs are skipped locally, and fail in CI.
import { test, expect } from './fixtures.mjs';
import { startPipe } from './nodes.mjs';
import { localRustCli, runWsh, spawnWsh } from './rust-cli.mjs';
import { randomBytes } from 'node:crypto';
import net from 'node:net';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const cli = localRustCli();
let home; let sockDir; let pipe; let operatorKey;

const roundTrip = (sock, payload) => new Promise((resolve, reject) => {
  const s = net.connect(sock); const cs = [];
  s.on('connect', () => s.end(payload));
  s.on('data', (d) => cs.push(d)); s.on('close', () => resolve(Buffer.concat(cs))); s.on('error', reject);
});

test.describe('built Rust CLI --sealed -L -> named endpoint of a sealing host in the page', () => {
  test.beforeAll(() => {
    if (!cli && process.env.CI) throw new Error('WSH_CLI_BIN must name the built wsh CLI in CI');
  });
  test.beforeEach(async () => {
    test.skip(!cli, 'set WSH_CLI_BIN to a built wsh (cargo build -p wsh-cli) to run the sealed-session acceptance case');
    home = await mkdtemp(path.join(tmpdir(), 'wsh-rust-seal-home-'));
    sockDir = await mkdtemp(path.join('/tmp', 'wsh-seal-'));
    const keygen = await runWsh(cli.path, home, ['keygen'], { insecureLoopbackTls: false });
    expect(keygen.code, keygen.stderr).toBe(0);
    operatorKey = (await readFile(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8')).trim();
    pipe = await startPipe();
  });
  test.afterEach(async () => {
    await pipe?.close();
    if (home) await rm(home, { recursive: true, force: true });
    if (sockDir) await rm(sockDir, { recursive: true, force: true });
  });

  async function startHost(page, sealSession) {
    const id = await page.evaluate((o) => window.h.startHost(o), { authorizedKeys: [operatorKey], dataStreams: false, endpoints: true, hostKey: 'pair', sealSession });
    await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipe.hostUrl]);
    return id;
  }
  async function forward(args, sock) {
    const child = spawnWsh(cli.path, home, ['--accept-new-host-key', '-p', String(pipe.operatorTlsPort), '-t', 'ws', ...args, '-N', '-L', `${sock}:endpoint=echo`, 'alice@127.0.0.1']);
    for (let i = 0; i < 300 && !/forwarding|sealed|refus|requires|offer/i.test(child.err) && child.exitCode === null; i++) await new Promise((r) => setTimeout(r, 50));
    return child;
  }

  test('a host that requires sealing: data round-trips, a 12 MiB transfer is intact, and the recording pipe sees none of it', async ({ page }) => {
    const id = await startHost(page, 'require');
    const sock = path.join(sockDir, 'echo.sock');
    const child = await forward(['--sealed'], sock);
    expect(child.err).toMatch(/forwarding/);
    const marker = 'PLANTED-MARKER-QUOKKA-7731';
    expect((await roundTrip(sock, marker)).toString()).toBe(marker);
    const big = randomBytes(12 * 1024 * 1024);
    expect(Buffer.compare(await roundTrip(sock, big), big)).toBe(0); // far past the credit window: credit works through the seal
    const seen = pipe.recording().toString('latin1');
    expect(seen).not.toContain(marker);
    expect(pipe.recording().includes(Buffer.from('echo'))).toBe(false); // the endpoint's name crosses only inside a frame
    expect((await page.evaluate((i) => window.h.hostInfo(i), id)).log.join('\n')).toMatch(/session sealed/);
    child.kill('SIGINT');
    await child.exited;
  });

  test('--sealed against a host that does not offer sealing fails with a sentence, and sends nothing', async ({ page }) => {
    await startHost(page, undefined); // has a host key and offers nothing
    const child = await forward(['--sealed'], path.join(sockDir, 'y.sock'));
    expect(await child.exited).not.toBe(0);
    expect(child.err).toMatch(/does not offer "e2e-session"/);
    expect(child.err).toMatch(/nothing was sent/);
  });
});
