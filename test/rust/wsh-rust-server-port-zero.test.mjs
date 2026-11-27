// test/rust/wsh-rust-server-port-zero.test.mjs -- #320: `wsh-server --port 0` binds first and reports the port it got.
//
// A test used to pick a free port and hand it to the server; the number could be taken between the pick and the server's bind. With
// `--port 0` the server asks the operating system, binds TCP (WebSocket) and UDP (WebTransport) to the SAME number, and only then prints
// `listening on 0.0.0.0:<port>` on stdout. A server given a fixed port prints no such line (its output is unchanged).

import { describe, it, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import dgram from 'node:dgram';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { freePort } from '../helpers/free-port.mjs'; // the fixed-port arm only
import { listeningPort } from './helpers/listening.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

const procs = []; const homes = [];
after(() => { for (const p of procs.splice(0)) p.kill(); for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true }); });

function start(port) {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-port0-'));
  homes.push(home);
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', '/dev/null/none'], { env: { PATH: process.env.PATH, HOME: home }, stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  const out = { stdout: '', all: '' };
  proc.stdout.on('data', (d) => { out.stdout += d; out.all += d; });
  proc.stderr.on('data', (d) => { out.all += d; });
  const ready = new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`not ready: ${out.all}`)), 15_000);
    proc.once('exit', (c) => { clearTimeout(t); reject(new Error(`exited (${c}): ${out.all}`)); });
    const poll = setInterval(() => { if (listeningPort(out.stdout) || /wsh-server ready/.test(out.all)) { clearInterval(poll); clearTimeout(t); resolve(); } }, 20);
  });
  return { proc, out, ready };
}

const tcpAccepts = (port) => new Promise((resolve) => { const s = net.connect({ port, host: '127.0.0.1' }); s.once('connect', () => { s.destroy(); resolve(true); }); s.once('error', () => resolve(false)); });
const udpTaken = (port) => new Promise((resolve) => { const s = dgram.createSocket('udp4'); s.once('error', () => resolve(true)); s.bind(port, '0.0.0.0', () => s.close(() => resolve(false))); });

describe('wsh-server --port 0 (#320)', { skip: !existsSync(SERVER_BIN) && `no wsh-server at ${SERVER_BIN}` }, () => {
  it('reports the port it got on stdout, and both TCP and UDP are bound to it by then', async () => {
    const s = start(0);
    await s.ready;
    const port = listeningPort(s.out.stdout);
    assert.ok(port > 0 && port !== 4422, `a port the OS chose: ${port}`);
    assert.equal(s.out.stdout.split('\n').filter((l) => l.startsWith('listening on ')).length, 1, 'exactly one such line');
    assert.equal(await tcpAccepts(port), true, 'the WebSocket listener accepts on the reported port at once');
    assert.equal(await udpTaken(port), true, 'the WebTransport listener holds the same number for UDP');
    assert.match(s.out.all.replace(/\x1b\[[0-9;]*m/g, ''), new RegExp(`websocket_port=${port}\\b`), 'the existing "ready" log line states the real port too');
  });

  it('two servers started at once get different ports', async () => {
    const [a, b] = [start(0), start(0)];
    await Promise.all([a.ready, b.ready]);
    assert.notEqual(listeningPort(a.out.stdout), listeningPort(b.out.stdout));
  });

  it('a server given a fixed port is unchanged: it prints no "listening on" line', async () => {
    const port = await freePort();
    const s = start(port);
    await s.ready;
    assert.equal(await tcpAccepts(port), true);
    assert.equal(listeningPort(s.out.all), null);
  });
});
