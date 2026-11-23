// test/rust/wsh-cli-scp.test.mjs -- #140: `wsh scp` (upload and download) against the hosts that speak the file channel as `FileChunk`
// control messages: a Node host (createWshServer) behind a pipe relay and the Rust `wsh-server`. The Rust client used to read a raw
// stream (an 8-byte size, then the data), which no host sends, so a download hung and an upload never got its acknowledgement.
// The JS client's own upload/download against `wsh-server` is in wsh-rust-server.test.mjs.
//
// Every `wsh` runs with HOME in a scratch directory. Prerequisite: cargo build --release -p wsh-cli -p wsh-server (or WSH_BIN / WSH_SERVER_BIN).

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync, existsSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocket as WsClient } from 'ws';

import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { createWshServer } from '@johnhenry/wsh/server';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

const scratch = [];
const closers = [];
const procs = [];
before(() => { assert.ok(existsSync(WSH_BIN), `expected the built wsh at ${WSH_BIN} (cargo build --release -p wsh-cli, or set WSH_BIN)`); });
after(() => { for (const p of procs.splice(0)) p.kill('SIGKILL'); for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true }); });
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const cleanEnv = (home, extra = {}) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm', ...extra });
const tmpDir = () => { const d = realpathSync(mkdtempSync(path.join('/tmp', 'wscp-'))); scratch.push(d); return d; };
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const body = (n) => crypto.createHash('sha256').update('seed').digest().length && Buffer.from(Array.from({ length: n }, (_, i) => (i * 31 + (i >> 8)) & 0xff));

function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-cli-scp-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  return { home, pub: readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim() };
}

/** `wsh <args>`; a transfer that hangs is killed after `timeoutMs` and reported as `timedOut`. */
function wsh(args, { home, env = {}, timeoutMs = 15_000 } = {}) {
  return new Promise((resolve) => {
    const proc = spawn(WSH_BIN, ['--accept-new-host-key', ...args], { env: cleanEnv(home, env), stdio: ['pipe', 'pipe', 'pipe'] });
    const out = []; const err = [];
    proc.stdout.on('data', (d) => out.push(d)); proc.stderr.on('data', (d) => err.push(d));
    proc.stdin.on('error', () => {}); proc.stdin.end();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; proc.kill('SIGKILL'); }, timeoutMs);
    proc.once('close', (code) => { clearTimeout(timer); resolve({ code, timedOut, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
}

/** A Node host serving `root`, behind a real pipe relay. @returns {{ via: string[], target: string, root: string }} */
async function nodeHostViaRelay(h) {
  const root = tmpDir();
  const server = createWshServer({ auth: { authorizedKeys: h.pub }, fs: { root }, hostKey: true });
  closers.push(() => server.close());
  const relay = createPipeRelay({ rendezvousTimeoutMs: 15_000 });
  const { port } = await relay.listen();
  closers.push(() => relay.close());
  const url = `ws://127.0.0.1:${port}`;
  const id = newRendezvousId();
  const ws = new WsClient(pipeUrl(url, id, 'host'));
  ws.on('error', () => {});
  closers.push(async () => ws.terminate());
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  await server.accept(ws, { dataStreams: false });
  return { via: ['--via', pipeUrl(url, id)], target: 'alice@tab.example', root, remotePath: (name) => `/${name}`, env: {} };
}

/** The Rust wsh-server on a fresh port, serving the real filesystem. */
async function rustServer(h) {
  const port = await new Promise((resolve) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
  const serverHome = mkdtempSync(path.join(tmpdir(), 'wsh-cli-scp-server-'));
  scratch.push(serverHome);
  mkdirSync(path.join(serverHome, '.wsh'));
  writeFileSync(path.join(serverHome, '.wsh', 'authorized_keys'), `${h.pub}\n`);
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert'], { env: cleanEnv(serverHome), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  await new Promise((resolve, reject) => {
    let seen = '';
    const onData = (d) => { seen += d; if (seen.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited early (${c}): ${seen}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${seen}`)), 10_000);
  });
  const root = tmpDir();
  return { via: ['-t', 'ws', '-p', String(port)], target: 'alice@localhost', root, remotePath: (name) => path.join(root, name), env: { SSL_CERT_FILE: path.join(serverHome, '.wsh', 'cert.pem') } };
}

const hosts = [
  ['a Node host (createWshServer) behind a pipe relay', nodeHostViaRelay],
  ['the Rust wsh-server', rustServer],
];

for (const [name, start] of hosts) {
  describe(`wsh scp against ${name} (#140)`, { skip: start === rustServer && !existsSync(SERVER_BIN) && `no wsh-server at ${SERVER_BIN}` }, () => {
    for (const size of [0, 17, 64 * 1024, 300 * 1024 + 5]) {
      it(`downloads a ${size}-byte file intact`, async () => {
        const h = makeHome();
        const host = await start(h);
        const data = body(size);
        writeFileSync(path.join(host.root, 'remote.bin'), data);
        const out = path.join(tmpDir(), 'got.bin');
        const r = await wsh([...host.via, 'scp', `${host.target}:${host.remotePath('remote.bin')}`, out], { home: h.home, env: host.env });
        assert.equal(r.timedOut, false, `the download hung: ${r.stderr}`);
        assert.equal(r.code, 0, r.stderr);
        assert.equal(sha(readFileSync(out)), sha(data));
      });

      it(`uploads a ${size}-byte file intact`, async () => {
        const h = makeHome();
        const host = await start(h);
        const data = body(size);
        const local = path.join(tmpDir(), 'up.bin');
        writeFileSync(local, data);
        const r = await wsh([...host.via, 'scp', local, `${host.target}:${host.remotePath('uploaded.bin')}`], { home: h.home, env: host.env });
        assert.equal(r.timedOut, false, `the upload hung: ${r.stderr}`);
        assert.equal(r.code, 0, r.stderr);
        assert.equal(sha(readFileSync(path.join(host.root, 'uploaded.bin'))), sha(data));
      });
    }

    it('a download of a file that does not exist fails with a non-zero exit instead of hanging, and writes nothing', async () => {
      const h = makeHome();
      const host = await start(h);
      const out = path.join(tmpDir(), 'nothing.bin');
      const r = await wsh([...host.via, 'scp', `${host.target}:${host.remotePath('nope.bin')}`, out], { home: h.home, env: host.env });
      assert.equal(r.timedOut, false, `the download hung: ${r.stderr}`);
      assert.notEqual(r.code, 0);
      assert.equal(existsSync(out), false);
    });
  });
}
