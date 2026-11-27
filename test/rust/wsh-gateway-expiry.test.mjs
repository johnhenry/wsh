// test/rust/wsh-gateway-expiry.test.mjs -- #297 on the real Rust `wsh-server`: a key's `expires` ends the gateway connections it already holds
// open (GatewayClose "key expired", then "discarded"), and a reverse listener it had open stops; a key with no expiry is untouched.
// The Node host does the same (test/gateway-expiry.test.mjs). Driven by this repo's JS client; HOME is a scratch directory.
//
// Prerequisite: cargo build -p wsh-server, then WSH_SERVER_BIN=<path> if it is not target/release/wsh-server.
import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import { WshClient, generateKeyPair, exportPublicKeySSH, MSG } from '../../src/index.mjs';
import { listeningPort } from './helpers/listening.mjs'; // the server binds port 0 and prints the port it got (#320)

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
// eslint-disable-next-line no-control-regex
const stripAnsi = (s) => s.replace(/\u001b\[[0-9;]*m/g, '');
const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const until = async (fn, what, ms = 10_000) => { const t = Date.now(); for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 20)); } };
const enc = new TextEncoder();
const closes = (inbox, id) => inbox.filter((m) => m.type === MSG.GATEWAY_CLOSE && m.gateway_id === id);
const refusedConnect = (port) => new Promise((resolve) => {
  const s = net.connect({ port, host: '127.0.0.1' }); s.once('connect', () => { s.destroy(); resolve(false); }); s.once('error', () => resolve(true));
});

before(() => {
  assert.ok(existsSync(SERVER_BIN), `expected the built wsh-server at ${SERVER_BIN}`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
});
after(() => {
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});

describe('the Rust server ends the gateway connections of a key that expires (#297)', () => {
  let home; let proc; let url; let echo; let echoPort; const keys = {}; const clients = []; const logs = [];
  const at = (Math.floor(Date.now() / 1000) + 4) * 1000; // whole seconds; far enough for a login and two connections
  before(async () => {
    echo = net.createServer((c) => { c.on('data', (d) => c.write(Buffer.concat([Buffer.from('echo:'), d]))); c.on('error', () => {}); });
    await new Promise((r) => echo.listen(0, '127.0.0.1', r));
    echoPort = echo.address().port;
    home = mkdtempSync(path.join(tmpdir(), 'wsh-expiry-rust-'));
    mkdirSync(path.join(home, '.wsh'));
    const lines = [];
    for (const [name, extra] of [['soon', `expires="${new Date(at).toISOString().replace(/\.\d+Z$/, 'Z')}" `], ['forever', '']]) {
      keys[name] = await generateKeyPair(true);
      lines.push(`${extra}${await exportPublicKeySSH(keys[name].publicKey)} ${name}@test`);
    }
    writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${lines.join('\n')}\n`);
    const configPath = path.join(home, '.wsh', 'config.toml');
    writeFileSync(configPath, `[gateway]\nenabled = true\nallowed_destinations = ["127.0.0.1:${echoPort}"]\nenable_reverse_tunnels = true\n`);
    proc = spawn(SERVER_BIN, ['--port', '0', '--generate-cert', '--config', configPath], {
      env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    proc.stdout.on('data', (d) => logs.push(stripAnsi(d.toString())));
    proc.stderr.on('data', (d) => logs.push(stripAnsi(d.toString())));
    await until(() => listeningPort(logs), 'the server to start', 15_000);
    url = `wss://127.0.0.1:${listeningPort(logs)}`;
  });
  after(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    proc?.kill();
    echo?.close();
    if (home) rmSync(home, { recursive: true, force: true });
  });
  async function login(name) {
    const c = new WshClient();
    await c.connect(url, { username: 'alice', keyPair: keys[name] });
    clients.push(c);
    c.inbox = [];
    c.onGatewayMessage = (m) => c.inbox.push(m);
    return c;
  }
  async function openEcho(c, id) {
    await c.sendControl({ type: MSG.OPEN_TCP, gateway_id: id, host: '127.0.0.1', port: echoPort });
    await until(() => c.inbox.find((m) => m.type === MSG.GATEWAY_OK && m.gateway_id === id), `GatewayOk ${id}`);
    await c.sendControl({ type: MSG.GATEWAY_DATA, gateway_id: id, data: enc.encode('hi') });
    await until(() => c.inbox.find((m) => m.type === MSG.GATEWAY_DATA && m.gateway_id === id), `echo ${id}`);
  }

  it('closes the open connections with the reason, stops the listener, and leaves another key alone', async () => {
    const soon = await login('soon'); const forever = await login('forever');
    await openEcho(soon, 1); await openEcho(soon, 2); await openEcho(forever, 1);
    const handle = await soon.listenTcp(0, { onConnection() {} });
    assert.equal(await refusedConnect(handle.port), false, 'listening');
    assert.ok(Date.now() < at, 'everything above happened before the expiry');
    for (const id of [1, 2]) {
      await until(() => closes(soon.inbox, id).length >= 2, `the two closes of ${id}`, 15_000);
      const [first, second] = closes(soon.inbox, id);
      assert.equal(first.reason, 'key expired');
      assert.equal(second.reason, 'discarded');
    }
    assert.ok(Date.now() >= at - 50, 'not before the expiry');
    await until(() => refusedConnect(handle.port), 'the listener to stop');
    assert.equal(closes(forever.inbox, 1).length, 0, 'a key with no expiry is not touched');
    await forever.sendControl({ type: MSG.GATEWAY_DATA, gateway_id: 1, data: enc.encode('again') });
    await until(() => forever.inbox.filter((m) => m.type === MSG.GATEWAY_DATA).length >= 2, 'its connection still echoes');
  });
});
