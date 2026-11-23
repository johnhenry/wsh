// Download the latest RELEASED Rust `wsh` CLI from this repository's GitHub releases and verify it (#116, #132).
//
// The archive is checked against the release's SHA256SUMS before anything is extracted; a mismatch is a hard failure, not a
// skip. A platform with no release asset, or a download that fails (offline, rate limited), is reported as a skip with the
// reason. The binary is extracted into a directory the caller made, and never run with the user's real HOME: see `runWsh`.
import { createHash } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);
const REPO = 'johnhenry/wsh';

/** The release target names (a stable external contract, see AGENTS.md) for this platform, or null. */
export function releaseTarget(platform = process.platform, arch = process.arch) {
  if (platform === 'linux' && arch === 'x64') return 'x86_64-unknown-linux-gnu';
  if (platform === 'darwin' && arch === 'arm64') return 'aarch64-apple-darwin';
  if (platform === 'darwin' && arch === 'x64') return 'x86_64-apple-darwin';
  return null;
}

const semver = (tag) => tag.replace(/^rust-v/, '').split('.').map((n) => Number.parseInt(n, 10) || 0);
const newer = (a, b) => { const x = semver(a); const y = semver(b); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return y[i] - x[i]; return 0; };

async function getJson(url) {
  const headers = { accept: 'application/vnd.github+json', 'user-agent': 'wsh-browser-tests' };
  if (process.env.GITHUB_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}
async function getBytes(url) {
  const res = await fetch(url, { headers: { 'user-agent': 'wsh-browser-tests' }, signal: AbortSignal.timeout(120_000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

/**
 * @param {string} dir - an empty directory the caller owns; the archive and the binary go here
 * @returns {Promise<{ path: string, tag: string } | { skip: string }>}
 */
export async function fetchLatestRustCli(dir) {
  const target = releaseTarget();
  if (!target) return { skip: `no released Rust CLI archive for ${process.platform}/${process.arch}` };
  let tag; let archive; let sums;
  try {
    const releases = await getJson(`https://api.github.com/repos/${REPO}/releases?per_page=50`);
    const rust = releases.filter((r) => /^rust-v\d+\.\d+\.\d+$/.test(r.tag_name) && !r.draft && !r.prerelease).sort((a, b) => newer(a.tag_name, b.tag_name));
    if (!rust.length) return { skip: `${REPO} has no rust-v* release` };
    const release = rust[0];
    tag = release.tag_name;
    const asset = release.assets.find((a) => a.name === `wsh-cli-${target}.tar.gz`);
    const sumsAsset = release.assets.find((a) => a.name === 'SHA256SUMS');
    if (!asset || !sumsAsset) return { skip: `release ${tag} has no ${asset ? 'SHA256SUMS' : `wsh-cli-${target}.tar.gz`} asset` };
    [archive, sums] = await Promise.all([getBytes(asset.browser_download_url), getBytes(sumsAsset.browser_download_url)]);
  } catch (e) {
    return { skip: `could not download the released Rust CLI (${e.message})` };
  }
  const want = new TextDecoder().decode(sums).split('\n').map((l) => l.trim().split(/\s+/)).find(([, name]) => name === `wsh-cli-${target}.tar.gz`)?.[0];
  const got = createHash('sha256').update(archive).digest('hex');
  if (!want || want !== got) throw new Error(`${tag} wsh-cli-${target}.tar.gz does not match its SHA256SUMS (want ${want}, got ${got})`);
  const archivePath = path.join(dir, `wsh-cli-${target}.tar.gz`);
  await writeFile(archivePath, archive);
  await mkdir(path.join(dir, 'bin'), { recursive: true });
  // Only the one member we expect (the binary is `wsh`, at the archive root), so nothing in the archive picks its own path.
  await run('tar', ['-xzf', archivePath, '-C', path.join(dir, 'bin'), 'wsh']);
  const bin = path.join(dir, 'bin', 'wsh');
  await chmod(bin, 0o755);
  return { path: bin, tag };
}

/**
 * Run the CLI with HOME (and everything else it could read) pointing at `home`, a throwaway directory: its keys and
 * known_hosts are never the user's. `WSH_INSECURE_LOOPBACK_TLS=1` is the CLI's documented switch for a `wss://` loopback
 * peer with a self-signed certificate; the pipe's operator port is exactly that.
 * @returns {Promise<{ code: number | null, stdout: string, stderr: string }>}
 */
export function runWsh(bin, home, args, { timeoutMs = 30_000, insecureLoopbackTls = true } = {}) {
  return new Promise((resolve) => {
    const child = spawn(bin, args, {
      env: { HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), PATH: process.env.PATH ?? '', ...(insecureLoopbackTls ? { WSH_INSECURE_LOOPBACK_TLS: '1' } : {}) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    // The CLI's tracing output (timestamped WARN/INFO lines) goes to stdout; what a command printed is everything else.
    const strip = (t) => t.split('\n').filter((l) => !/^(\x1b\[[0-9;]*m)*\d{4}-\d\d-\d\dT\S+\s/.test(l)).join('\n');
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout: strip(stdout), stderr, rawStdout: stdout }); });
  });
}

export { readFile };
