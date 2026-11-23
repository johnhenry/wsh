// test/rust/wsh-rust-server-defaults.test.mjs -- what the Rust `wsh-server` does with NO configuration:
// the gateway, reverse listeners and password login are all off, and the settings that turn them on
// behave as documented in the README's Security model and the CHANGELOG's breaking-change notes.
//
// Drives the real binary (cargo build --release -p wsh-server, or WSH_SERVER_BIN) with this repo's own
// JS client. Every server runs with HOME in a scratch directory.

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir, networkInterfaces } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  WshClient, generateKeyPair, exportPublicKeySSH, openTcp, listenRequest, resolveDns, MSG,
} from '../../src/index.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = [];
const procs = [];

before(() => {
  assert.ok(existsSync(SERVER_BIN), `expected the built binary at ${SERVER_BIN} (cargo build --release -p wsh-server)`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the dev certificate is self-signed
});

after(() => {
  for (const p of procs.splice(0)) p.kill();
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});

const freePort = () => new Promise((resolve) => {
  const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});

/** Hash a password with the server's own `--hash-password`, the way an operator would. */
function hashPassword(password) {
  return execFileSync(SERVER_BIN, ['--hash-password'], { input: password, encoding: 'utf8' }).trim();
}

async function startServer({ config = '' } = {}) {
  const kp = await generateKeyPair(true);
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-defaults-'));
  scratch.push(home);
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(kp.publicKey)}\n`);
  const configPath = path.join(home, '.wsh', 'config.toml');
  writeFileSync(configPath, config);
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', configPath], {
    env: { PATH: process.env.PATH, HOME: home }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  procs.push(proc);
  let logs = '';
  await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  return { url: `wss://127.0.0.1:${port}`, kp, logs: () => logs };
}

async function connect(server, extra = {}) {
  const client = new WshClient();
  await client.connect(server.url, { username: 'tester', keyPair: server.kp, ...extra });
  return client;
}

/** Send a gateway request and wait for the reply with `type`(s). */
function ask(client, msg, ...types) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no reply to ${JSON.stringify(msg)}`)), 5000);
    client.onGatewayMessage = (reply) => {
      if (types.includes(reply.type)) { clearTimeout(timer); resolve(reply); }
    };
    client.sendControl(msg).catch(reject);
  });
}

/** A TCP service on loopback the gateway could be pointed at. */
async function localService() {
  const sockets = [];
  const server = net.createServer((s) => { sockets.push(s); s.on('error', () => {}); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  after(() => { for (const s of sockets) s.destroy(); server.close(); });
  return server.address().port;
}

describe('Rust wsh-server: the gateway is off, deny-by-default, and loopback-only', () => {
  it('with no configuration it does not advertise the gateway and refuses every gateway request', async () => {
    const server = await startServer();
    const client = await connect(server);
    try {
      assert.equal(client.hasFeature('gateway'), false);
      const port = await localService();
      const tcp = await ask(client, openTcp({ gatewayId: 1, host: '127.0.0.1', port }), MSG.GATEWAY_FAIL, MSG.GATEWAY_OK);
      assert.equal(tcp.type, MSG.GATEWAY_FAIL);
      const listen = await ask(client, listenRequest({ listenerId: 2, port: 0 }), MSG.LISTEN_FAIL, MSG.LISTEN_OK);
      assert.equal(listen.type, MSG.LISTEN_FAIL);
    } finally { await client.disconnect().catch(() => {}); }
  });

  it('`enabled = true` alone still refuses every destination and every reverse listener', async () => {
    const server = await startServer({ config: '[gateway]\nenabled = true\n' });
    const client = await connect(server);
    try {
      assert.equal(client.hasFeature('gateway'), true);
      const port = await localService();
      const tcp = await ask(client, openTcp({ gatewayId: 1, host: '127.0.0.1', port }), MSG.GATEWAY_FAIL, MSG.GATEWAY_OK);
      assert.equal(tcp.type, MSG.GATEWAY_FAIL);
      assert.equal(tcp.code, 4, 'policy denied');
      const listen = await ask(client, listenRequest({ listenerId: 2, port: 0 }), MSG.LISTEN_FAIL, MSG.LISTEN_OK);
      assert.equal(listen.type, MSG.LISTEN_FAIL);
    } finally { await client.disconnect().catch(() => {}); }
  });

  it('a "*" rule reaches the public internet but not this machine\'s own network', async () => {
    const server = await startServer({ config: '[gateway]\nenabled = true\nallowed_destinations = ["*"]\n' });
    const client = await connect(server);
    try {
      const port = await localService();
      for (const host of ['127.0.0.1', 'localhost']) {
        const reply = await ask(client, openTcp({ gatewayId: 1, host, port }), MSG.GATEWAY_FAIL, MSG.GATEWAY_OK);
        assert.equal(reply.type, MSG.GATEWAY_FAIL, host);
        assert.equal(reply.code, 4, host);
      }
      const dns = await ask(client, resolveDns({ gatewayId: 3, name: 'localhost' }), MSG.DNS_RESULT, MSG.GATEWAY_FAIL);
      assert.equal(dns.type, MSG.GATEWAY_FAIL, 'a lookup that only answers with loopback has nothing to return');
    } finally { await client.disconnect().catch(() => {}); }
  });

  it('a rule that names the address lets exactly that through (the lines in the CHANGELOG)', async () => {
    const port = await localService();
    const server = await startServer({ config: `[gateway]\nenabled = true\nallowed_destinations = ["127.0.0.1:${port}"]\n` });
    const client = await connect(server);
    try {
      const ok = await ask(client, openTcp({ gatewayId: 1, host: '127.0.0.1', port }), MSG.GATEWAY_FAIL, MSG.GATEWAY_OK);
      assert.equal(ok.type, MSG.GATEWAY_OK);
      const other = await ask(client, openTcp({ gatewayId: 2, host: '127.0.0.1', port: port === 65535 ? port - 1 : port + 1 }), MSG.GATEWAY_FAIL, MSG.GATEWAY_OK);
      assert.equal(other.type, MSG.GATEWAY_FAIL);
    } finally { await client.disconnect().catch(() => {}); }
  });

  it('a reverse listener binds to loopback even when the client asks for 0.0.0.0,', async () => {
    const lan = Object.values(networkInterfaces()).flat().find((i) => i && i.family === 'IPv4' && !i.internal);
    const server = await startServer({ config: '[gateway]\nenabled = true\nenable_reverse_tunnels = true\n' });
    const client = await connect(server);
    try {
      const reply = await ask(client, listenRequest({ listenerId: 1, port: 0, bindAddr: '0.0.0.0' }), MSG.LISTEN_OK, MSG.LISTEN_FAIL);
      assert.equal(reply.type, MSG.LISTEN_OK);
      const port = reply.actual_port;
      await new Promise((resolve, reject) => {
        const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(); });
        s.on('error', reject);
      });
      if (lan) {
        await assert.rejects(new Promise((resolve, reject) => {
          const s = net.connect({ port, host: lan.address, timeout: 2000 }, () => { s.destroy(); resolve(); });
          s.on('error', reject);
          s.on('timeout', () => { s.destroy(); reject(new Error('timeout')); });
        }), `the listener must not answer on ${lan.address}`);
      }
    } finally { await client.disconnect().catch(() => {}); }
  });
});

describe('Rust wsh-server: password login', () => {
  const hashes = (obj) => Object.entries(obj).map(([u, h]) => `${u} = '${h}'`).join('\n');

  it('is off by default even when hashes are configured', async () => {
    const server = await startServer({ config: `[auth.password_hashes]\n${hashes({ alice: hashPassword('correct horse') })}\n` });
    await assert.rejects(connect(server, { keyPair: undefined, password: 'correct horse', username: 'alice' }));
    assert.match(server.logs(), /password login is off/);
  });

  it('with allow_password and an Argon2id hash: the right password logs in, a wrong one and an unknown user fail alike', async () => {
    const hash = hashPassword('correct horse');
    assert.match(hash, /^\$argon2id\$v=19\$/);
    assert.notEqual(hash, hashPassword('correct horse'), 'a fresh salt each time');
    const server = await startServer({ config: `[auth]\nallow_password = true\n[auth.password_hashes]\n${hashes({ alice: hash })}\n` });

    const ok = await connect(server, { keyPair: undefined, username: 'alice', password: 'correct horse' });
    await ok.disconnect();

    const wrong = await connect(server, { keyPair: undefined, username: 'alice', password: 'wrong' }).catch((e) => e);
    const unknown = await connect(server, { keyPair: undefined, username: 'mallory', password: 'correct horse' }).catch((e) => e);
    assert.ok(wrong instanceof Error && unknown instanceof Error);
    assert.equal(unknown.message, wrong.message, 'the failure must not say whether the user exists');
  });

  it('refuses an unsalted sha256: entry, says so at start-up, and accepts it only with allow_legacy_sha256', async () => {
    const legacy = 'sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'; // "password"
    const refused = await startServer({ config: `[auth]\nallow_password = true\n[auth.password_hashes]\nbob = '${legacy}'\n` });
    await assert.rejects(connect(refused, { keyPair: undefined, username: 'bob', password: 'password' }));
    assert.match(refused.logs(), /unsalted sha256 hashes are no longer accepted/);

    const allowed = await startServer({ config: `[auth]\nallow_password = true\nallow_legacy_sha256 = true\n[auth.password_hashes]\nbob = '${legacy}'\n` });
    assert.match(allowed.logs(), /DEPRECATED/);
    const client = await connect(allowed, { keyPair: undefined, username: 'bob', password: 'password' });
    await client.disconnect();
  });

  it('public-key login is unaffected', async () => {
    const server = await startServer();
    const client = await connect(server);
    await client.disconnect();
  });
});

// ── #145: AuthOk.ttl, the clientEnv allow-list and Signal ────────────────────────────────────────────────────

/** Open an exec session on `client` and resolve with what it printed and how it ended. */
async function runExec(client, opts, { signalAfterMs } = {}) {
  const session = await client.openSession({ type: 'exec', ...opts });
  const chunks = [];
  let exitCode = null;
  const done = new Promise((resolve) => {
    session.onData = (d) => chunks.push(Buffer.from(d));
    session.onStderr = (d) => chunks.push(Buffer.from(d));
    session.onExit = (c) => { exitCode = c; };
    session.onClose = resolve;
  });
  if (signalAfterMs !== undefined) setTimeout(() => session.signal('INT').catch(() => {}), signalAfterMs);
  await done;
  return { text: Buffer.concat(chunks).toString(), exitCode, session };
}

describe('Rust wsh-server: AuthOk.ttl (#125)', () => {
  it('promises no connection lifetime it does not enforce: ttl is 0', async () => {
    const server = await startServer({ config: '[server]\nsession_ttl = 5\n' });
    const client = await connect(server);
    try {
      assert.equal(client.authTtl, 0);
      assert.ok(client.authToken instanceof Uint8Array && client.authToken.length > 0, 'released clients require the field');
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(client.state, 'authenticated');
    } finally { await client.disconnect().catch(() => {}); }
  });
});

describe('Rust wsh-server: clientEnv allow-list (#126)', () => {
  const env = { TERM: 'screen', LC_ALL: 'C', LANG: 'C', WSH_TEST_VAR: 'leaked', LD_PRELOAD: '/nonexistent.so' };
  const probe = 'echo "T=$TERM L=$LC_ALL V=$WSH_TEST_VAR P=$LD_PRELOAD"';

  for (const stdio of [undefined, 'pipes']) {
    it(`by default only TERM, COLORTERM, LANG, LANGUAGE and LC_* are applied (${stdio ?? 'pty'})`, async () => {
      const server = await startServer();
      const client = await connect(server);
      try {
        const { text } = await runExec(client, { command: probe, env, ...(stdio ? { stdio } : {}) });
        assert.match(text, /T=screen L=C V= P=\s/, text);
      } finally { await client.disconnect().catch(() => {}); }
    });
  }

  it('`client_env = true` under [server] accepts everything again (the line the CHANGELOG gives)', async () => {
    const server = await startServer({ config: '[server]\nclient_env = true\n' });
    const client = await connect(server);
    try {
      const { text } = await runExec(client, { command: 'echo "V=$WSH_TEST_VAR"', env });
      assert.match(text, /V=leaked/, text);
    } finally { await client.disconnect().catch(() => {}); }
  });

  it('a list names exactly what is accepted (and replaces the default list)', async () => {
    const server = await startServer({ config: '[server]\nclient_env = ["WSH_TEST_*"]\n' });
    const client = await connect(server);
    try {
      const { text } = await runExec(client, { command: 'echo "T=$TERM L=$LC_ALL V=$WSH_TEST_VAR"', env, stdio: 'pipes' });
      assert.match(text, /L= V=leaked/, text);
    } finally { await client.disconnect().catch(() => {}); }
  });

  it('`client_env = false` accepts nothing', async () => {
    const server = await startServer({ config: '[server]\nclient_env = false\n' });
    const client = await connect(server);
    try {
      const { text } = await runExec(client, { command: probe, env, stdio: 'pipes' });
      assert.match(text, /L= V= P=/, text);
    } finally { await client.disconnect().catch(() => {}); }
  });
});

describe('Rust wsh-server: Signal stops a command', () => {
  for (const [label, extra] of [['exec on a pty', {}], ['exec on pipes', { stdio: 'pipes' }]]) {
    it(`SIGINT ends a running ${label} (the shell and what it started)`, async () => {
      const server = await startServer();
      const client = await connect(server);
      try {
        const t0 = Date.now();
        // `sh -c 'sleep 30; echo unreachable'` does not exec its last command: the signal has to reach the group.
        const { text, exitCode } = await runExec(client, { command: 'sleep 30; echo unreachable', ...extra }, { signalAfterMs: 400 });
        assert.ok(Date.now() - t0 < 10_000, `still ran after ${Date.now() - t0}ms`);
        assert.doesNotMatch(text, /unreachable/);
        assert.notEqual(exitCode, 0);
      } finally { await client.disconnect().catch(() => {}); }
    });
  }

  it('a name the server does not deliver is ignored and the command carries on', async () => {
    const server = await startServer();
    const client = await connect(server);
    try {
      const session = await client.openSession({ type: 'exec', command: 'sleep 1; echo survived', stdio: 'pipes' });
      const chunks = [];
      const done = new Promise((resolve) => { session.onData = (d) => chunks.push(Buffer.from(d)); session.onExit = () => {}; session.onClose = resolve; });
      await session.signal('SEGV');
      await session.signal('9; kill -9 1');
      await done;
      assert.match(Buffer.concat(chunks).toString(), /survived/);
    } finally { await client.disconnect().catch(() => {}); }
  });
});
