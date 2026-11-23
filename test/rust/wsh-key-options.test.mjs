// test/rust/wsh-key-options.test.mjs -- authorized_keys options (wsh #122) on the real Rust `wsh-server`, driven by this repo's JS
// client. Every key line of spec/key-options.vectors.json is put in an authorized_keys file (each with its own key); the server
// must let in exactly the keys the vectors say it does, and serve each key exactly what its `can` list says. The Node host is held
// to the same file by test/key-options.test.mjs and test/server-key-options.test.mjs, so the two hosts give the same answers.
//
// The server throttles logins per address (10 a minute), so the lines are served by a few short-lived servers, three keys each.
// Each runs with HOME in a scratch directory (it reads $HOME/.wsh/authorized_keys). Prerequisite: cargo build -p wsh-server
// (release or debug), then WSH_SERVER_BIN=<path> if it is not target/release/wsh-server.

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint } from '../../src/index.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const vectors = JSON.parse(readFileSync(path.join(REPO_ROOT, 'spec', 'key-options.vectors.json'), 'utf8'));
const dec = new TextDecoder();
// eslint-disable-next-line no-control-regex
const stripAnsi = (s) => s.replace(/\u001b\[[0-9;]*m/g, '');
const CHUNK = 3;

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const freePort = () => new Promise((resolve) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });

before(() => {
  assert.ok(existsSync(SERVER_BIN), `expected the built wsh-server at ${SERVER_BIN}`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the server's --generate-cert certificate is self-signed
});
after(() => {
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});

/** Start a server with these authorized_keys lines and extra flags; resolves `{ url, logs, stop() }`. */
async function startServer(lines, extraArgs = []) {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-keyopts-rust-'));
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${lines.join('\n')}\n`);
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', '/dev/null/none', ...extraArgs], {
    env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = [];
  proc.stdout.on('data', (d) => logs.push(stripAnsi(d.toString())));
  proc.stderr.on('data', (d) => logs.push(stripAnsi(d.toString())));
  const t = Date.now();
  while (!logs.some((l) => l.includes('WebSocket TLS listener started'))) {
    if (Date.now() - t > 15_000) throw new Error(`the server did not start: ${logs.join('')}`);
    await new Promise((r) => setTimeout(r, 50));
  }
  return { url: `wss://127.0.0.1:${port}`, logs, home, stop() { proc.kill(); rmSync(home, { recursive: true, force: true }); } };
}

describe('Rust wsh-server: permit-relay gates the relay (#122)', () => {
  it('a key without permit-relay cannot register, list or connect; one with it can', async () => {
    const [peer, operator, outsider] = await Promise.all([generateKeyPair(true), generateKeyPair(true), generateKeyPair(true)]);
    const line = async (opts, kp) => `${opts}${await exportPublicKeySSH(kp.publicKey)}`;
    const server = await startServer([await line('restrict,permit-relay ', peer), await line('restrict,permit-relay ', operator), await line('restrict,permit-exec ', outsider)], ['--enable-relay']);
    const clients = [];
    try {
      const registered = new WshClient();
      clients.push(registered);
      await registered.connectReverse(server.url, { username: 'peer', keyPair: peer, expose: { exec: true }, transport: 'ws' });
      const op = new WshClient();
      clients.push(op);
      await op.connect(server.url, { username: 'operator', keyPair: operator });
      const peers = await op.listPeers();
      assert.equal(peers.length, 1, 'the permitted peer is registered and listed');

      const blocked = new WshClient();
      clients.push(blocked);
      await blocked.connect(server.url, { username: 'outsider', keyPair: outsider });
      await assert.rejects(blocked.listPeers(300), /./, 'a key without permit-relay gets no list');
      const rejected = await blocked.reverseConnect(peers[0].fingerprint, 1000).then((r) => r, (e) => e);
      assert.match(String(rejected instanceof Error ? rejected.message : rejected.reason), /relay not permitted/);
      assert.ok(server.logs.join('').includes('relay request refused by the key'), 'the refusal is logged');
    } finally {
      for (const c of clients) await c.disconnect().catch(() => {});
      server.stop();
    }
  });
});

describe('Rust wsh-server: a restricted key cannot install an unrestricted one (#122)', () => {
  it('AuthorizedKeyAdd is refused for restrict / command= / no-pty keys and served for a key with no options', async () => {
    const [full, restricted, forced, nopty, added] = await Promise.all([1, 2, 3, 4, 5].map(() => generateKeyPair(true)));
    const line = async (opts, kp) => `${opts}${await exportPublicKeySSH(kp.publicKey)}`;
    const server = await startServer([await line('', full), await line('restrict,permit-exec ', restricted), await line('command="uptime" ', forced), await line('no-pty ', nopty)]);
    const clients = [];
    const file = path.join(server.home, '.wsh', 'authorized_keys');
    try {
      const newKey = await exportPublicKeyRaw(added.publicKey);
      for (const [name, kp] of [['restricted', restricted], ['forced', forced], ['nopty', nopty]]) {
        const c = new WshClient();
        clients.push(c);
        await c.connect(server.url, { username: 'alice', keyPair: kp });
        const r = await c.addAuthorizedKey(newKey, 'minted').then((x) => x, (e) => e);
        assert.ok(r instanceof Error || r.success === false, `${name}: a restricted key installed a key: ${JSON.stringify(r)}`);
        assert.ok(!readFileSync(file, 'utf8').includes('minted'), `${name}: the file was changed`);
      }
      const c = new WshClient();
      clients.push(c);
      await c.connect(server.url, { username: 'alice', keyPair: full });
      assert.equal((await c.addAuthorizedKey(newKey, 'minted')).added, true);
      assert.ok(readFileSync(file, 'utf8').includes('minted'));
    } finally {
      for (const c of clients) await c.disconnect().catch(() => {});
      server.stop();
    }
  });
});

const cases = vectors.lines.filter((v) => v.result !== 'skip');
for (let from = 0; from < cases.length; from += CHUNK) {
  const group = cases.slice(from, from + CHUNK);
  describe(`Rust wsh-server: authorized_keys options follow the shared vectors (#122), lines ${from + 1}-${from + group.length}`, () => {
    let home; let proc; let url; const logs = []; const keys = []; const clients = [];

    before(async () => {
      home = mkdtempSync(path.join(tmpdir(), 'wsh-keyopts-rust-'));
      mkdirSync(path.join(home, '.wsh'));
      const lines = [];
      for (const v of group) {
        const keyPair = await generateKeyPair(true);
        const ssh = await exportPublicKeySSH(keyPair.publicKey);
        lines.push(v.line.replaceAll(vectors.keyPlaceholder, ssh));
        keys.push({ v, keyPair, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)) });
      }
      writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${lines.join('\n')}\n`);
      const port = await freePort();
      proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', '/dev/null/none'], {
        env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester' },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      proc.stdout.on('data', (d) => logs.push(stripAnsi(d.toString())));
      proc.stderr.on('data', (d) => logs.push(stripAnsi(d.toString())));
      url = `wss://127.0.0.1:${port}`;
      const t = Date.now();
      while (!logs.some((l) => l.includes('WebSocket TLS listener started'))) {
        if (Date.now() - t > 15_000) throw new Error(`the server did not start: ${logs.join('')}`);
        await new Promise((r) => setTimeout(r, 50));
      }
    });
    after(async () => {
      for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
      proc?.kill();
      rmSync(home, { recursive: true, force: true });
    });

    const login = async (keyPair) => {
      const c = new WshClient();
      await c.connect(url, { username: 'alice', keyPair });
      clients.push(c);
      return c;
    };
    const served = (p) => p.then(() => true, () => false);

    group.forEach((v, i) => {
      it(`line: ${v.name}`, async () => {
        const { keyPair, fp } = keys[i];
        if (v.result === 'refused') {
          // never loaded, and the log says why
          assert.ok(logs.join('').includes(`fingerprint=${fp.slice(0, 8)} code="${v.code}"`), `no log line for ${v.code}:\n${logs.join('')}`);
          await assert.rejects(login(keyPair), /not authorized|Authentication failed/, 'a key with an option the server does not understand must not log in');
          return;
        }
        const c = await login(keyPair);
        // A key with a capability list is served only what the list also names (`fs:read` is what a list needs).
        const named = v.capabilities ?? null;
        const can = new Set(v.can.filter((c) => named === null || named.includes({ pty: 'pty', exec: 'exec', fileTransfer: 'fs:read' }[c] ?? c)));
        const run = async () => {
          const s = await c.openSession({ type: 'exec', command: 'echo vector-ok' });
          return new Promise((resolve) => { const out = []; s.onData = (d) => out.push(dec.decode(d)); s.onClose = () => resolve(out.join('')); });
        };
        assert.equal(await served(run()), can.has('exec'), 'exec');
        assert.equal(await served(c.openSession({ type: 'pty' })), can.has('pty'), 'pty');
        const listed = await c.fileOperation('list', home).then((r) => r.success !== false, () => false);
        assert.equal(listed, can.has('fileTransfer'), 'file list');
        if (v.forcedCommand !== null) assert.ok(!(await run()).includes('vector-ok'), 'a forced command replaces the command the client asked for');
      });
    });
  });
}
