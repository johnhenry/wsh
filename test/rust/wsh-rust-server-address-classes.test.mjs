// test/rust/wsh-rust-server-address-classes.test.mjs -- #260: the Rust `wsh-server` gateway accepts only the addresses the
// JavaScript guard accepts (`@johnhenry/wsh/address-guard`, spec/address-class.vectors.json), including the IPv6 forms that
// wrap an IPv4 address: an IPv6 address that carries a loopback, private or metadata address is refused (POLICY_DENIED) under a
// "*" rule, whatever it wraps it with, and a rule that names an address does not reach the forms that wrap it.
//
// Nothing here leaves the machine: every refused destination is refused before any connection is made, and the one destination
// that is allowed is a listener on loopback that the test itself opened.
//
// Drives the real binary (cargo build --release -p wsh-server, or WSH_SERVER_BIN) with this repo's own JS client. Every server
// runs with HOME in a scratch directory.

import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { WshClient, generateKeyPair, exportPublicKeySSH, openTcp, MSG } from '../../src/index.mjs';
import { classifyAddress } from '../../src/address-guard.mjs';
import { freePort } from '../helpers/free-port.mjs'; // free for TCP and UDP: the server binds both (#248)

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

async function startServer(config) {
  const kp = await generateKeyPair(true);
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-addrclass-'));
  scratch.push(home);
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(kp.publicKey)}\n`);
  const configPath = path.join(home, '.wsh', 'config.toml');
  writeFileSync(configPath, config);
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', configPath], {
    env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config') }, stdio: ['ignore', 'pipe', 'pipe'],
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
  const client = new WshClient();
  await client.connect(`wss://127.0.0.1:${port}`, { username: 'tester', keyPair: kp });
  return { client, logs: () => logs };
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

/** A TCP listener on loopback that counts the connections it gets. */
async function localService() {
  const sockets = [];
  const seen = { connections: 0 };
  const server = net.createServer((s) => { seen.connections++; sockets.push(s); s.on('error', () => {}); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  after(() => { for (const s of sockets) s.destroy(); server.close(); });
  return { port: server.address().port, seen };
}

// IPv6 addresses that wrap an address a "*" rule must not reach, and the class the JavaScript guard gives them.
const WRAPPED = [
  ['2002:7f00:1::', 'loopback'], // 6to4 carrying 127.0.0.1
  ['2002:7f00:1::1', 'loopback'],
  ['2002:a00:1::1', 'private'], // 6to4 carrying 10.0.0.1
  ['2002:c0a8:101::1', 'private'], // 6to4 carrying 192.168.1.1
  ['2002:a9fe:a9fe::1', 'metadata'], // 6to4 carrying 169.254.169.254
  ['2002:6440:1::', 'carrier-nat'], // 6to4 carrying 100.64.0.1
  ['2002::', 'unspecified'], // 6to4 carrying 0.0.0.0
  ['::ffff:127.0.0.1', 'loopback'], // IPv4-mapped
  ['64:ff9b::7f00:1', 'loopback'], // NAT64
  ['64:ff9b::a9fe:a9fe', 'metadata'],
  ['64:ff9b:1::1', 'reserved'], // local-use NAT64
  ['::127.0.0.1', 'reserved'], // IPv4-compatible
  ['2001::1', 'teredo'],
  ['2001:db8::1', 'documentation'],
];

describe('Rust wsh-server: the gateway accepts what the JavaScript guard accepts (#260)', () => {
  it('the table agrees with the JavaScript classifier', () => {
    for (const [address, cls] of WRAPPED) assert.equal(classifyAddress(address), cls, address);
  });

  it('a "*" rule refuses every IPv6 form that wraps a non-public address, and nothing reaches a local listener', async () => {
    const { seen } = await localService();
    const server = await startServer('[gateway]\nenabled = true\nallowed_destinations = ["*"]\n');
    try {
      let id = 0;
      for (const [address] of WRAPPED) {
        const reply = await ask(server.client, openTcp({ gatewayId: ++id, host: address, port: 80 }), MSG.GATEWAY_FAIL, MSG.GATEWAY_OK);
        assert.equal(reply.type, MSG.GATEWAY_FAIL, address);
        assert.equal(reply.code, 4, `${address}: refused by policy, not a failed connection`);
      }
      assert.equal(seen.connections, 0);
    } finally { await server.client.disconnect().catch(() => {}); }
  });

  it('a rule that names a loopback address allows exactly that address, and not the 6to4 form that wraps it', async () => {
    const { port, seen } = await localService();
    const server = await startServer(`[gateway]\nenabled = true\nallowed_destinations = ["*", "127.0.0.1:${port}"]\n`);
    try {
      const ok = await ask(server.client, openTcp({ gatewayId: 1, host: '127.0.0.1', port }), MSG.GATEWAY_FAIL, MSG.GATEWAY_OK);
      assert.equal(ok.type, MSG.GATEWAY_OK, 'the rule still allows the address it names');
      for (const [i, address] of ['2002:7f00:1::', '::ffff:127.0.0.1', '64:ff9b::7f00:1'].entries()) {
        const reply = await ask(server.client, openTcp({ gatewayId: 10 + i, host: address, port }), MSG.GATEWAY_FAIL, MSG.GATEWAY_OK);
        assert.equal(reply.type, MSG.GATEWAY_FAIL, address);
        assert.equal(reply.code, 4, address);
      }
      const deadline = Date.now() + 5000; // wait for the accepted connection to be counted, not for a fixed time
      while (seen.connections < 1 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 10));
      assert.equal(seen.connections, 1, 'only the allowed connection reached the listener');
    } finally { await server.client.disconnect().catch(() => {}); }
  });

  it('the refusal log names the class of the address, as the JavaScript guard does', async () => {
    const server = await startServer('[gateway]\nenabled = true\nallowed_destinations = ["*"]\n');
    try {
      const reply = await ask(server.client, openTcp({ gatewayId: 1, host: '2002:a9fe:a9fe::1', port: 80 }), MSG.GATEWAY_FAIL, MSG.GATEWAY_OK);
      assert.equal(reply.code, 4);
      // The server logs before it replies; the pipe to this process is read asynchronously, so wait for the line.
      const plain = () => server.logs().replace(/\x1b\[[0-9;]*m/g, '');
      const deadline = Date.now() + 5000;
      while (!/classes=metadata/.test(plain()) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
      assert.match(plain(), /destination=\[?2002:a9fe:a9fe::1\]?:80 classes=metadata/);
    } finally { await server.client.disconnect().catch(() => {}); }
  });
});
