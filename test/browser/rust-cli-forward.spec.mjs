// THE ACCEPTANCE CASE of the forwarding epic (#131, #145): a host that lives in a real Chromium page offers a NAMED ENDPOINT,
// and the freshly BUILT Rust `wsh` CLI reaches it with `-L` through the pipe. The released CLI has no `-L`, so this runs the
// binary named by WSH_CLI_BIN (CI builds it first); without it the specs are skipped locally, and fail in CI.
import { test, expect } from './fixtures.mjs';
import { startPipe } from './nodes.mjs';
import { localRustCli, runWsh, spawnWsh } from './rust-cli.mjs';
import { createHash, randomBytes } from 'node:crypto';
import net from 'node:net';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const cli = localRustCli();
let home; let sockDir; let pipe; let operatorKey;

test.describe('built Rust CLI -L -> named endpoint of a host in the page', () => {
  test.beforeAll(() => {
    if (!cli && process.env.CI) throw new Error('WSH_CLI_BIN must name the built wsh CLI in CI');
  });
  test.beforeEach(async () => {
    test.skip(!cli, 'set WSH_CLI_BIN to a built wsh (cargo build -p wsh-cli) to run the forwarding acceptance case');
    home = await mkdtemp(path.join(tmpdir(), 'wsh-rust-fwd-home-'));
    sockDir = await mkdtemp(path.join('/tmp', 'wsh-fwd-'));
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

  async function forward(page, endpoint, sock) {
    const id = await page.evaluate((o) => window.h.startHost(o), { authorizedKeys: [operatorKey], dataStreams: false, endpoints: true });
    await page.evaluate(([i, url]) => window.h.serve(i, url), [id, pipe.hostUrl]);
    const child = spawnWsh(cli.path, home, ['-p', String(pipe.operatorTlsPort), '-t', 'ws', '-N', '-L', `${sock}:endpoint=${endpoint}`, 'alice@127.0.0.1']);
    for (let i = 0; i < 300 && !/forwarding/.test(child.err); i++) await new Promise((r) => setTimeout(r, 50));
    expect(child.err, 'wsh said it was forwarding').toMatch(/forwarding/);
    return { id, child };
  }

  test('an echo round-trips through the local socket, the socket is 0600, and it is removed when wsh stops', async ({ page }) => {
    const sock = path.join(sockDir, 'echo.sock');
    const { id, child } = await forward(page, 'echo', sock);
    expect(statSync(sock).mode & 0o777).toBe(0o600);
    const answer = await new Promise((resolve, reject) => {
      const s = net.connect(sock); const cs = [];
      s.on('connect', () => s.end('hello from the CLI'));
      s.on('data', (d) => cs.push(d)); s.on('close', () => resolve(Buffer.concat(cs).toString())); s.on('error', reject);
    });
    expect(answer).toBe('hello from the CLI');
    expect((await page.evaluate((i) => window.h.hostInfo(i), id)).endpointsOpened).toEqual([{ name: 'echo', user: 'alice' }]);
    child.kill('SIGINT');
    expect(await child.exited).toBe(0);
    expect(existsSync(sock)).toBe(false);
  });

  test('a 16 MiB transfer far past the credit window arrives intact (the endpoint counts it)', async ({ page }) => {
    const sock = path.join(sockDir, 'count.sock');
    const { child } = await forward(page, 'count', sock);
    const payload = randomBytes(16 * 1024 * 1024);
    const answer = await new Promise((resolve, reject) => {
      const s = net.connect(sock); const cs = [];
      s.on('connect', () => s.end(payload));
      s.on('data', (d) => cs.push(d)); s.on('close', () => resolve(Buffer.concat(cs).toString())); s.on('error', reject);
    });
    expect(answer).toBe(String(payload.length));
    child.kill('SIGINT');
    await child.exited;
  });

  test('an endpoint that refuses the caller is refused readably', async ({ page }) => {
    const sock = path.join(sockDir, 'private.sock');
    const { child } = await forward(page, 'private', sock);
    await new Promise((resolve) => { const s = net.connect(sock); s.on('error', () => {}); s.on('close', resolve); });
    for (let i = 0; i < 100 && !/refused/.test(child.err); i++) await new Promise((r) => setTimeout(r, 50));
    expect(child.err).toMatch(/endpoint private.*refused/s);
    child.kill('SIGINT');
    await child.exited;
  });
});
