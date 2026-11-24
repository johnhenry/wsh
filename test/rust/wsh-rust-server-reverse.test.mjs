// test/rust/wsh-rust-server-reverse.test.mjs -- #145: the Rust `wsh-server`'s TCP reverse tunnels (`ListenRequest`) are bounded
// the way the Node host's are (test/gateway-reverse.test.mjs): a port allow-list whose default allows only ephemeral and
// unprivileged ports and which a given list replaces, a cap on listeners per client, a cap on connections per listener, an
// idle limit on an accepted connection, and a start-up refusal of a nonsense setting.
//
// Drives the real binary (cargo build -p wsh-server, WSH_SERVER_BIN) with this repo's JS client, over a self-signed wss://
// listener on loopback. Every server runs with HOME in a scratch directory.

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { WshClient, generateKeyPair, exportPublicKeySSH } from '../../src/index.mjs';
import { GatewayError } from '../../src/gateway-client.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const enc = new TextEncoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 8000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
}
const freePort = () => new Promise((resolve) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
const dial = (port) => new Promise((resolve, reject) => { const s = net.connect({ port, host: '127.0.0.1' }); s.once('connect', () => resolve(s)); s.once('error', reject); });
const refusedConnect = (port) => new Promise((resolve) => { const s = net.connect({ port, host: '127.0.0.1' }); s.once('connect', () => { s.destroy(); resolve(false); }); s.once('error', () => resolve(true)); });
const refused = (p, re) => assert.rejects(p, (e) => e instanceof GatewayError && e.code === 4 && re.test(e.message), `expected a policy refusal matching ${re}`);
/** Echo what a duplex reads. */
const echoer = async (duplex) => {
  const reader = duplex.readable.getReader(); const w = duplex.writable.getWriter();
  for (;;) { const { value, done } = await reader.read(); if (done) break; await w.write(Buffer.concat([enc.encode('echo:'), value])); }
  await w.close().catch(() => {});
};

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
before(() => {
  assert.ok(fs.existsSync(SERVER_BIN), `expected the built binary at ${SERVER_BIN} (cargo build -p wsh-server, or WSH_SERVER_BIN)`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the dev certificate is self-signed
});
after(() => {
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});

describe('Rust wsh-server: reverse tunnels are bounded as on the Node host (#145)', () => {
  const procs = []; const clients = []; const dirs = []; const sockets = [];

  afterEach(async () => {
    for (const s of sockets.splice(0)) s.destroy();
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const p of procs.splice(0)) { p.kill(); await new Promise((r) => { if (p.exitCode !== null) r(); else { p.once('exit', r); setTimeout(r, 2000); } }); }
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  /** Start wsh-server with `[gateway]` lines (reverse tunnels on) and return it with a logged-in JS client; or, with `expectExit`, what it printed when it refused to start. */
  async function setup(gatewayLines = '', { expectExit = false } = {}) {
    const kp = await generateKeyPair(true);
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-rev-home-'));
    dirs.push(home);
    fs.mkdirSync(path.join(home, '.wsh'));
    fs.writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(kp.publicKey)}\n`);
    const configPath = path.join(home, '.wsh', 'config.toml');
    fs.writeFileSync(configPath, `[gateway]\nenabled = true\nenable_reverse_tunnels = true\n${gatewayLines}\n`);
    const port = await freePort();
    const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', configPath], {
      env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config') }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    procs.push(proc);
    let logs = '';
    const exited = new Promise((resolve) => proc.once('exit', (code) => resolve(code)));
    proc.stdout.on('data', (d) => { logs += d; }); proc.stderr.on('data', (d) => { logs += d; });
    if (expectExit) return { code: await Promise.race([exited, sleep(10_000).then(() => 'still running')]), logs: () => logs };
    await until(() => logs.includes('WebSocket TLS listener started') || (proc.exitCode !== null && (() => { throw new Error(`wsh-server exited: ${logs}`); })()), 'the server to start', 10_000);
    const client = new WshClient();
    await client.connect(`wss://127.0.0.1:${port}`, { username: 'tester', keyPair: kp });
    clients.push(client);
    return { client, logs: () => logs };
  }

  it('by default a client may ask for an ephemeral or an unprivileged port, and for no port below 1024', async () => {
    const { client } = await setup();
    const h = await client.listenTcp(0, { onConnection() {} });
    assert.ok(h.port >= 1024);
    for (const p of [1, 22, 80, 443, 1023]) {
      await refused(client.listenTcp(p, { onConnection() {} }), /port \d+ is not allowed by the reverse-tunnel policy \(ports below 1024 must be listed explicitly by the host operator\)/);
    }
    const free = await freePort();
    const g = await client.listenTcp(free, { onConnection() {} });
    assert.equal(g.port, free);
  });

  it('a reverse_ports list replaces the default: only what it names, numbers and ranges, and a port below 1024 only when listed', async () => {
    const lo = await freePort();
    const { client } = await setup(`reverse_ports = [${lo}, "30000-30010", 80]\n`);
    // 80 is allowed by the list (binding it may be refused by the OS: that is a different sentence)
    await assert.rejects(client.listenTcp(80, { onConnection() {} }), (e) => !/not allowed by the reverse-tunnel policy/.test(e.message));
    await refused(client.listenTcp(0, { onConnection() {} }), /^port 0 is not allowed by the reverse-tunnel policy \(ports below 1024 must be listed/);
    await refused(client.listenTcp(40000, { onConnection() {} }), /^port 40000 is not allowed by the reverse-tunnel policy$/);
    const h = await client.listenTcp(lo, { onConnection() {} });
    assert.equal(h.port, lo);
  });

  it('a nonsense reverse_ports entry, a zero backlog or a zero per-listener cap stops the server before it listens', async () => {
    for (const [lines, what] of [
      ['reverse_ports = [70000]\n', /reverse_ports/],
      ['reverse_ports = ["9-1"]\n', /reverse_ports/],
      ['reverse_ports = ["abc"]\n', /reverse_ports/],
      ['reverse_ports = [-1]\n', /reverse_ports/],
      ['reverse_backlog = 0\n', /reverse_backlog/],
      ['reverse_max_connections_per_listener = 0\n', /reverse_max_connections_per_listener/],
    ]) {
      const r = await setup(lines, { expectExit: true });
      assert.notEqual(r.code, 0, `${lines}: ${r.logs()}`);
      assert.notEqual(r.code, 'still running', `${lines}: it must not start`);
      assert.match(r.logs(), what, lines);
    }
  });

  it('limits listeners per client, and a slot frees when one closes', async () => {
    const { client } = await setup('reverse_max_listeners = 2\n');
    const a = await client.listenTcp(0, { onConnection() {} });
    await client.listenTcp(0, { onConnection() {} });
    await refused(client.listenTcp(0, { onConnection() {} }), /too many reverse listeners \(limit 2\)/);
    await a.close();
    await until(async () => { try { await client.listenTcp(0, { onConnection() {} }); return true; } catch { return false; } }, 'a slot frees when a listener closes');
  });

  it('limits connections per listener: the extra one is closed without being announced, and a slot frees when one ends', async () => {
    const { client } = await setup('reverse_max_connections_per_listener = 2\n');
    const opened = [];
    const handle = await client.listenTcp(0, { onConnection: (d) => { opened.push(d); } });
    const a = await dial(handle.port); const b = await dial(handle.port);
    sockets.push(a, b);
    await until(() => opened.length === 2, 'two announced');
    const c = await dial(handle.port).catch(() => null);
    if (c) { sockets.push(c); c.on('error', () => {}); }
    const closed = c ? await new Promise((r) => { c.once('close', () => r(true)); setTimeout(() => r(false), 3000); }) : true;
    assert.equal(closed, true, 'the third connection is closed by the host');
    assert.equal(opened.length, 2, 'and was never announced');
    a.destroy();
    await until(async () => { const d = await dial(handle.port).catch(() => null); if (d) { sockets.push(d); d.on('error', () => {}); } await sleep(150); return opened.length === 3; }, 'a freed slot admits a new connection');
  });

  it('a connection nobody accepts does not hold its slot for ever: the slot is given back when it is dropped', async () => {
    const { client } = await setup('reverse_max_connections_per_listener = 1\n');
    let seen = 0;
    const handle = await client.listenTcp(0, { onConnection: () => { seen += 1; } });
    const a = await dial(handle.port); sockets.push(a);
    await until(() => seen === 1, 'first');
    a.destroy();
    await until(async () => { const d = await dial(handle.port).catch(() => null); if (d) { sockets.push(d); d.on('error', () => {}); } await sleep(150); return seen === 2; }, 'the next connection after the first ended');
  });

  it('closes an accepted connection that has been idle too long, and traffic keeps one alive', async () => {
    const { client } = await setup('reverse_idle_secs = 2\n');
    const handle = await client.listenTcp(0, { onConnection: echoer });
    const s = await dial(handle.port); sockets.push(s); s.on('error', () => {});
    const closed = new Promise((r) => s.once('close', () => r('closed')));
    assert.equal(await Promise.race([closed, sleep(15_000).then(() => 'still open')]), 'closed');
    const t = await dial(handle.port); sockets.push(t); t.on('error', () => {});
    const alive = new Promise((r) => t.once('close', () => r('closed')));
    for (let i = 0; i < 8; i++) { t.write('k'); await sleep(500); } // 4 s of traffic against a 2 s limit
    assert.equal(t.destroyed, false, 'kept alive by traffic');
    t.destroy(); await alive;
  });

  it('reverse_idle_secs = 0 never closes a quiet connection', async () => {
    const { client } = await setup('reverse_idle_secs = 0\n');
    const handle = await client.listenTcp(0, { onConnection: echoer });
    const s = await dial(handle.port); sockets.push(s); s.on('error', () => {});
    const closed = new Promise((r) => s.once('close', () => r('closed')));
    assert.equal(await Promise.race([closed, sleep(3500).then(() => 'still open')]), 'still open');
  });

  it('listeners and their connections end with the client, and the port is closed', async () => {
    const { client } = await setup();
    const handle = await client.listenTcp(0, { onConnection: echoer });
    const peer = await dial(handle.port); sockets.push(peer); peer.on('error', () => {});
    const closed = new Promise((r) => peer.once('close', r));
    await client.disconnect();
    await Promise.race([closed, sleep(5000).then(() => assert.fail('the accepted connection stayed open'))]);
    await until(() => refusedConnect(handle.port), 'the port is closed');
  });
});
