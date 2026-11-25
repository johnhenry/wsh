// test/rust/wsh-capabilities.test.mjs -- per-key capabilities (wsh #122, step two) on the real Rust `wsh-server`, driven by this repo's
// JS client: a key with `capabilities="..."` is served what it names and refused (naming the capability) what it does not, at every
// entry the Rust server has: Open (pty, exec, file upload/download), FileOp, the gateway (TCP, DNS, unix, reverse listeners), MCP, the
// relay, and login (expires). The server has no endpoints and no targets, so those are refused whatever a key holds. The grammar and
// the allow/refuse table are the shared vectors (spec/key-options.vectors.json), run by `cargo test` and by test/key-options.test.mjs.
//
// Each server runs with HOME in a scratch directory. It throttles logins per address (10 a minute), so the keys are spread over two
// short-lived servers. Prerequisite: cargo build -p wsh-server, then WSH_SERVER_BIN=<path> if it is not target/release/wsh-server.

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG } from '../../src/index.mjs';
import { freePort } from '../helpers/free-port.mjs'; // free for TCP and UDP: the server binds both (#248)

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const dec = new TextDecoder();
// eslint-disable-next-line no-control-regex
const stripAnsi = (s) => s.replace(/\u001b\[[0-9;]*m/g, '');
const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const until = async (fn, what, ms = 5000) => { const t = Date.now(); while (!(await fn())) { if (Date.now() - t > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 20)); } };
const toml = (a) => `[${a.map((s) => JSON.stringify(s)).join(', ')}]`;

before(() => {
  assert.ok(existsSync(SERVER_BIN), `expected the built wsh-server at ${SERVER_BIN}`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the server's --generate-cert certificate is self-signed
});
after(() => {
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});

/**
 * A Rust server whose authorized_keys has one key per `caps` entry (`name: [capabilities, extra options]`), with `config` (a config.toml
 * body) and `args`. `login(name)` connects once per key; `stop()` ends it and removes what it made.
 */
async function startServer({ caps, config = '', args = [] }) {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-caps-rust-'));
  mkdirSync(path.join(home, '.wsh'));
  const keys = {}; const lines = [];
  for (const [name, [list, extra = '']] of Object.entries(caps)) {
    const keyPair = await generateKeyPair(true);
    keys[name] = { keyPair, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)) };
    lines.push(`capabilities="${list}"${extra} ${await exportPublicKeySSH(keyPair.publicKey)} ${name}@test`);
  }
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${lines.join('\n')}\n`);
  const configPath = path.join(home, '.wsh', 'config.toml');
  writeFileSync(configPath, config);
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', configPath, ...args], {
    env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = [];
  proc.stdout.on('data', (d) => logs.push(stripAnsi(d.toString())));
  proc.stderr.on('data', (d) => logs.push(stripAnsi(d.toString())));
  const url = `wss://127.0.0.1:${port}`;
  await until(() => logs.some((l) => l.includes('WebSocket TLS listener started')), 'the server to start', 15_000);
  const clients = []; const connected = new Map();
  return {
    url, keys, logs: () => logs.join(''), home, clients,
    async login(name) {
      if (!connected.has(name)) {
        const c = new WshClient();
        await c.connect(url, { username: 'alice', keyPair: keys[name].keyPair });
        clients.push(c);
        c.gwInbox = [];
        c.onGatewayMessage = (m) => c.gwInbox.push(m);
        connected.set(name, c);
      }
      return connected.get(name);
    },
    async stop() {
      for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
      proc.kill();
      rmSync(home, { recursive: true, force: true });
    },
  };
}

/** Refused with a reason matching `re`: a rejection (an Open, a gateway open) or a failed FileResult. */
const refusedWith = async (promise, re) => {
  let r;
  try { r = await promise; } catch (e) { assert.match(String(e.message), re); return; }
  assert.equal(r?.success, false, `the request was served: ${JSON.stringify(r)}`);
  assert.match(String(r.error_message ?? r.errorMessage), re);
};
const runExec = async (c) => {
  const s = await c.openSession({ type: 'exec', command: 'echo cap-ok' });
  return new Promise((resolve) => { const out = []; s.onData = (d) => out.push(dec.decode(d)); s.onClose = () => resolve(out.join('')); });
};

describe('Rust wsh-server: per-key capabilities on Open and FileOp (#122)', () => {
  let s; let dir;
  before(async () => {
    dir = realpathSync(mkdtempSync(path.join('/tmp', 'wsh-caps-files-')));
    s = await startServer({ caps: { exec: ['exec'], pty: ['pty'], nothing: [''], fsRead: ['fs:read'], fsWrite: ['fs:write'] } });
  });
  after(async () => { await s.stop(); rmSync(dir, { recursive: true, force: true }); });

  it('exec and pty: each needs its own capability, and an empty list can do nothing', async () => {
    const e = await s.login('exec');
    assert.match(await runExec(e), /cap-ok/);
    await refusedWith(e.openSession({ type: 'pty' }), /missing capability pty/);
    const p = await s.login('pty');
    assert.ok(await p.openSession({ type: 'pty' }));
    await refusedWith(p.openSession({ type: 'exec', command: 'echo no' }), /missing capability exec/);
    const none = await s.login('nothing');
    await refusedWith(none.openSession({ type: 'exec', command: 'echo no' }), /missing capability exec/);
    await refusedWith(none.fileOperation('list', dir), /missing capability fs:read/);
  });

  it('files: fs:read lists and downloads, fs:write uploads, and neither does the other\'s', async () => {
    const r = await s.login('fsRead');
    assert.equal((await r.fileOperation('list', dir)).success, true);
    await refusedWith(r.fileOperation('remove', path.join(dir, 'w.txt')), /missing capability fs:write/);
    await refusedWith(r.upload(new Blob(['x']), path.join(dir, 'up.txt')), /missing capability fs:write/);
    const w = await s.login('fsWrite');
    await w.upload(new Blob(['up']), path.join(dir, 'up.txt'));
    assert.equal(dec.decode(await r.download(path.join(dir, 'up.txt'))), 'up');
    await refusedWith(w.fileOperation('list', dir), /missing capability fs:read/);
    await refusedWith(w.download(path.join(dir, 'up.txt')), /missing capability fs:read/);
  });

});

describe('Rust wsh-server: per-key capabilities on MCP and login (#122)', () => {
  let s; const soon = Math.floor(Date.now() / 1000) + 3;
  before(async () => {
    s = await startServer({
      caps: {
        exec: ['exec'], mcpAll: ['mcp:*'],
        expired: ['exec', ',expires="2020-01-01T00:00:00Z"'],
        soon: ['exec', `,expires="${new Date(soon * 1000).toISOString().replace(/\.\d+Z$/, 'Z')}"`],
      },
    });
  });
  after(async () => { await s.stop(); });

  it('mcp: a call is refused naming the tool, and a key with mcp:* gets through to the bridge', async () => {
    const none = await s.login('exec');
    const refusal = await none.callTool('anything', {});
    assert.match(String(refusal.error), /missing capability mcp:anything/);
    const all = await s.login('mcpAll');
    assert.doesNotMatch(String((await all.callTool('anything', {})).error), /missing capability/);
  });

  it('expires: a key past its expiry does not log in; one about to expire is served, then refused as expired', async () => {
    const c = new WshClient();
    await assert.rejects(c.connect(s.url, { username: 'alice', keyPair: s.keys.expired.keyPair }), /expired/);
    assert.match(s.logs(), /key refused at login/);
    const k = await s.login('soon');
    assert.match(await runExec(k), /cap-ok/);
    await new Promise((r) => setTimeout(r, Math.max(0, soon * 1000 - Date.now()) + 100));
    await refusedWith(k.openSession({ type: 'exec', command: 'echo late' }), /expired/);
  });
});

describe('Rust wsh-server: per-key capabilities on the gateway and the relay (#122)', () => {
  let s; let sockDir; let echo; let echoPort; let unixServer;
  before(async () => {
    sockDir = realpathSync(mkdtempSync(path.join('/tmp', 'wsh-caps-sock-')));
    echo = net.createServer((c) => { c.on('data', (d) => c.write(Buffer.concat([Buffer.from('echo:'), d]))); c.on('error', () => {}); });
    echoPort = await new Promise((r) => echo.listen(0, '127.0.0.1', () => r(echo.address().port)));
    unixServer = net.createServer((c) => { c.on('data', (d) => c.write(Buffer.concat([Buffer.from('unix:'), d]))); c.on('error', () => {}); });
    await new Promise((r) => unixServer.listen(path.join(sockDir, 'ok.sock'), r));
    s = await startServer({
      caps: {
        exec: ['exec'], relay: ['relay'], dns: ['gateway:tcp:localhost:*'],
        gateway: [`gateway:tcp:127.0.0.1:${echoPort},gateway:listen:tcp:*,unix:${sockDir}/ok.sock,unix:listen:${sockDir}/l.sock,endpoint:logs,target:web`],
      },
      config: `[gateway]\nenabled = true\nallowed_destinations = ${toml([`127.0.0.1:${echoPort}`, 'localhost'])}\nunix_connect = ${toml([`${sockDir}/`])}\nunix_listen = ${toml([`${sockDir}/`])}\nenable_reverse_tunnels = true\n`,
      args: ['--enable-relay'],
    });
  });
  after(async () => { await s.stop(); echo.close(); unixServer.close(); rmSync(sockDir, { recursive: true, force: true }); });

  it('tcp, listen and unix: only what the capability names, and listening is not connecting', async () => {
    const g = await s.login('gateway');
    const d = await g.openTcp('127.0.0.1', echoPort);
    await d.writable.getWriter().write(new TextEncoder().encode('hi'));
    assert.equal(dec.decode((await d.readable.getReader().read()).value), 'echo:hi');
    await assert.rejects(g.openTcp('127.0.0.1', echoPort + 1), /missing capability gateway:tcp:127.0.0.1:/);
    const handle = await g.listenTcp(0, { onConnection() {} });
    assert.ok(handle.port > 0);
    await handle.close();
    const u = await g.openUnix(path.join(sockDir, 'ok.sock'));
    await u.writable.getWriter().write(new TextEncoder().encode('yo'));
    assert.equal(dec.decode((await u.readable.getReader().read()).value), 'unix:yo');
    await assert.rejects(g.openUnix(path.join(sockDir, 'other.sock')), /missing capability unix:/);
    const l = await g.listenUnix(path.join(sockDir, 'l.sock'), { onConnection() {} });
    await l.close();
    await assert.rejects(g.listenUnix(path.join(sockDir, 'x.sock'), { onConnection() {} }), /missing capability unix:listen:/);
    const e = await s.login('exec');
    await assert.rejects(e.openTcp('127.0.0.1', echoPort), /missing capability gateway:tcp:127.0.0.1:/);
    await assert.rejects(e.listenTcp(0, { onConnection() {} }), /missing capability gateway:listen:tcp:0/);
    await assert.rejects(e.openUnix(path.join(sockDir, 'ok.sock')), /missing capability unix:/);
  });

  it('dns: a name the key may connect to', async () => {
    const dns = await s.login('dns');
    const e = await s.login('exec');
    await dns.sendControl({ type: MSG.RESOLVE_DNS, gateway_id: 11, name: 'localhost', record_type: 'A' });
    await e.sendControl({ type: MSG.RESOLVE_DNS, gateway_id: 12, name: 'localhost', record_type: 'A' });
    await until(() => dns.gwInbox.length && e.gwInbox.some((m) => m.gateway_id === 12), 'DNS answers');
    assert.ok(!JSON.stringify(dns.gwInbox).includes('missing capability'), 'the capability covers the name');
    assert.ok(JSON.stringify(e.gwInbox).includes('missing capability gateway:tcp:localhost:*'));
  });

  it('endpoints and targets do not exist here: refused whatever the key holds', async () => {
    const g = await s.login('gateway');
    const before = g.gwInbox.length;
    await g.sendControl({ type: MSG.OPEN_ENDPOINT, gateway_id: 21, name: 'logs' });
    await until(() => g.gwInbox.length > before, 'an endpoint answer');
    const answer = g.gwInbox.at(-1);
    assert.equal(answer.type, MSG.GATEWAY_FAIL, JSON.stringify(answer));
    assert.doesNotMatch(JSON.stringify(answer), /missing capability/, 'the key holds endpoint:logs; the server has no endpoints');
    // a request that names a target is refused by the server (never run on it), as for any key, whatever `target:web` says
    await assert.rejects(g.openSession({ type: 'exec', command: 'echo no', target: 'web' }), /targets/);
  });

  it('relay: a key without the capability cannot register', async () => {
    const ok = new WshClient();
    await ok.connectReverse(s.url, { username: 'alice', keyPair: s.keys.relay.keyPair, expose: { exec: true }, transport: 'ws' });
    s.clients.push(ok);
    const denied = new WshClient();
    await denied.connectReverse(s.url, { username: 'alice', keyPair: s.keys.exec.keyPair, expose: { exec: true }, transport: 'ws' }).catch(() => {});
    s.clients.push(denied);
    await until(() => s.logs().includes('relay request refused by the key'), 'the relay refusal');
    const peers = await ok.listPeers();
    assert.equal(peers.filter((p) => p.fingerprint === s.keys.exec.fp).length, 0, 'the key without relay is not registered');
  });
});
