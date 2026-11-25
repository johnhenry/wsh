// test/rust/wsh-rpc-virtual.test.mjs -- #191, the Rust halves: rpc channels in virtual data mode.
//
// A host on a connection with no client-opened data streams (a sealed session, a host behind a relay) states `rpc-virtual` instead of
// `rpc`; the channel's CBOR sequence rides SessionData (inside EncryptedFrame when sealed), metered by GatewayCredit. Both directions
// against the JS side (which merged as #194):
//
//   A. the Rust `wsh-server` with `seal_session = "require"`, driven by the JS client's `openRpc` (`wsh-host`, and `wsh-fs` with
//      `[rpc] fs_root`) behind a recording relay (no method name or payload marker visible) and a tampering relay (a flipped byte ends
//      the session); the per-key capability checks of stream-mode rpc; a slow reader on either side bounds the other; a peer that
//      overruns its credit is closed; a released-shape peer (one that only knows `rpc`) is refused before any rpc byte; and with
//      `seal_session` off the channels are stream-mode as before.
//   B. the Rust `wsh mcp` (with `--sealed`, and `--via` a pipe relay) against a JS memory host in a page, driven by the MCP SDK's own
//      stdio client, behind the same recording and tampering relays; a slow reader on either side bounds the other; and a host that
//      states only `rpc` is still served with streams.
//
// Every process runs with HOME in a scratch directory. Prerequisite: cargo build -p wsh-cli -p wsh-server (or --release), with
// WSH_BIN / WSH_SERVER_BIN pointing at them.

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer, WebSocket as WsClient } from 'ws';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { WshClient, generateKeyPair, exportPublicKeySSH, MSG, cborEncode } from '../../src/index.mjs';
import { RPC_ERROR, RPC_FEATURE, RPC_VIRTUAL_FEATURE } from '../../src/rpc.mjs';
import { RPC_CREDIT_WINDOW } from '../../src/rpc-virtual.mjs';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer, mcpServerAdapter } from '@johnhenry/wsh/server';
import { newRendezvousId } from '@johnhenry/wsh/pipe-relay';
import { hostileRelay } from '../helpers/hostile-relay.mjs';
import { freePort } from '../helpers/free-port.mjs'; // free for TCP and UDP: the server binds both (#248)

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const MARKER = 'SECRET-MARKER-ZEBRA-7731';
const METHOD_TOOL = 'zebra_secret_tool';
const MiB = 1024 * 1024;

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = [];
const procs = [];
const closers = [];
before(() => {
  assert.ok(existsSync(SERVER_BIN), `expected the built wsh-server at ${SERVER_BIN} (cargo build -p wsh-server, or set WSH_SERVER_BIN)`);
  assert.ok(existsSync(WSH_BIN), `expected the built wsh at ${WSH_BIN} (cargo build -p wsh-cli, or set WSH_BIN)`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the dev certificate of the server under test is self-signed
});
after(() => {
  for (const p of procs.splice(0)) p.kill('SIGKILL');
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, what, ms = 10_000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
};
const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'alice', TERM: 'xterm' });
const tmpDir = (prefix) => { const d = realpathSync(mkdtempSync(path.join(tmpdir(), prefix))); scratch.push(d); return d; };
const dec = new TextDecoder();
const enc = new TextEncoder();

// ── A. the Rust wsh-server, driven by the JS client ─────────────────────────────────────────────────────────────────

/**
 * A wsh-server with `seal_session = <seal>` (when given), a host key, and `[rpc] fs_root = <home>/files`. `keyLines(pub)` is the
 * authorized_keys content for the test key (its options go in front of it).
 */
async function startServer({ seal, keyLine = (pub) => pub, rpcExtra = '' } = {}) {
  const kp = await generateKeyPair(true);
  const pub = await exportPublicKeySSH(kp.publicKey);
  const home = tmpDir('wsh-rpcv-srv-');
  mkdirSync(path.join(home, '.wsh'));
  const root = path.join(home, 'files');
  mkdirSync(root);
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${keyLine(pub)}\n`);
  const configPath = path.join(home, '.wsh', 'config.toml');
  writeFileSync(configPath, `[server]\nhost_key = ${JSON.stringify(path.join(home, '.wsh', 'host_key'))}\n${seal ? `seal_session = "${seal}"\n` : ''}\n[rpc]\nfs_root = ${JSON.stringify(root)}\n${rpcExtra}`);
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', configPath], { env: { ...cleanEnv(home), USER: 'tester' }, stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  return { url: `wss://127.0.0.1:${port}`, port, kp, home, root, logs: () => logs };
}

async function viaRelay(server, hooks = {}) {
  const relay = await hostileRelay(server.url, hooks);
  closers.push(() => relay.close());
  return relay;
}

async function login(server, url, opts = {}) {
  const client = new WshClient();
  closers.push(() => client.disconnect());
  await client.connect(url ?? server.url, { username: 'tester', keyPair: server.kp, transport: 'ws', timeout: 8000, ...opts });
  return client;
}

const wire = (relay) => relay.seen.map((e) => ({ dir: e.dir, type: e.msg.type, bytes: Buffer.from(cborEncode(e.msg)) }));
const hasText = (relay, text) => wire(relay).some((w) => w.bytes.includes(Buffer.from(text)));
/** Bytes of sealed (or plain) session data the relay carried in one direction. */
const carried = (relay, dir) => relay.seen.filter((e) => e.dir === dir && (e.msg.type === MSG.ENCRYPTED_FRAME || e.msg.type === MSG.SESSION_DATA))
  .reduce((n, e) => n + (e.msg.ciphertext?.length ?? e.msg.data?.length ?? 0), 0);

describe('the Rust wsh-server with seal_session = "require": typed rpc channels ride the sealed session (#191)', () => {
  it('offers rpc-virtual (not rpc) and serves wsh-host and wsh-fs through a recording relay that sees no method name and no payload', async () => {
    const s = await startServer({ seal: 'require' });
    const relay = await viaRelay(s);
    const c = await login(s, relay.url, { sealSession: true });
    assert.equal(c.sessionSealed, true);
    assert.ok(c.hasFeature(RPC_VIRTUAL_FEATURE) && !c.hasFeature(RPC_FEATURE), 'states rpc-virtual instead of rpc');
    assert.ok(c.hasFeature('rpc-protocol:wsh-host') && c.hasFeature('rpc-protocol:wsh-fs'));
    assert.ok(c.hasFeature('rpc-max-message:1048576'));

    const host = await c.openRpc('wsh-host');
    const info = await host.request('host.info');
    assert.equal(info.user, 'tester');
    assert.deepEqual(info.rpc.protocols, ['wsh-host', 'wsh-fs']);
    assert.ok(info.features.includes(RPC_VIRTUAL_FEATURE));
    assert.equal(typeof (await host.request('host.ping')).time, 'number');
    await assert.rejects(host.request('host.nope'), (e) => e.code === RPC_ERROR.METHOD_NOT_FOUND);

    const fs = await c.openRpc('wsh-fs');
    assert.deepEqual(await fs.request('write', { path: 'secret.txt', data: enc.encode(MARKER) }), { written: MARKER.length });
    assert.equal((await fs.request('stat', { path: 'secret.txt' })).size, MARKER.length);
    assert.deepEqual((await fs.request('list', { path: '/' })).entries.map((e) => e.name), ['secret.txt']);
    const got = [];
    await fs.request('read', { path: 'secret.txt' }, { onProgress: (b) => got.push(...b) });
    assert.equal(dec.decode(Uint8Array.from(got)), MARKER);
    assert.equal(readFileSync(path.join(s.root, 'secret.txt'), 'utf8'), MARKER, 'the write reached the file');
    // a file larger than the credit window comes back in chunks, each waiting for credit
    const big = Buffer.alloc(900_000); for (let i = 0; i < big.length; i++) big[i] = (i * 7) % 251;
    writeFileSync(path.join(s.root, 'big.bin'), big);
    const chunks = [];
    const summary = await fs.request('read', { path: 'big.bin' }, { onProgress: (b) => chunks.push(Buffer.from(b)) });
    assert.deepEqual(Buffer.concat(chunks), big);
    assert.equal(summary.size, 900_000);
    await fs.request('remove', { path: 'secret.txt' });
    await host.close(); await fs.close();

    // (the ServerHello, before the login, lists the protocols in the clear; everything after the login is sealed)
    const authOk = relay.seen.findIndex((e) => e.dir === 'to-client' && e.msg.type === MSG.AUTH_OK);
    const after = relay.seen.slice(authOk + 1);
    assert.ok(after.length > 10);
    for (const e of after) {
      assert.ok([MSG.KEY_EXCHANGE, MSG.ENCRYPTED_FRAME, MSG.PING, MSG.PONG].includes(e.msg.type), `a plain message of type ${e.msg.type} crossed after the login`);
    }
    for (const word of [MARKER, 'host.info', 'host.ping', 'host.nope', 'secret.txt', 'wsh-fs', 'wsh-host', 'write', 'jsonrpc']) {
      assert.ok(!after.some((e) => Buffer.from(cborEncode(e.msg)).includes(Buffer.from(word))), `"${word}" crossed the relay in the clear`);
    }
  });

  it('control: with seal_session = "offer" and a client that does not seal, the same channel is plain (the relay reads it) and still works', async () => {
    const s = await startServer({ seal: 'offer' });
    const relay = await viaRelay(s);
    const c = await login(s, relay.url, { sealSession: false });
    assert.equal(c.sessionSealed, false);
    assert.ok(c.hasFeature(RPC_VIRTUAL_FEATURE) && !c.hasFeature(RPC_FEATURE));
    const fs = await c.openRpc('wsh-fs');
    await fs.request('write', { path: 'a.txt', data: enc.encode(MARKER) });
    assert.equal(readFileSync(path.join(s.root, 'a.txt'), 'utf8'), MARKER);
    assert.ok(hasText(relay, MARKER) && hasText(relay, 'write'), 'unsealed, the relay sees the method and the data');
    // and a sealed client on the same server is sealed
    const sealed = await login(s, undefined, { sealSession: true });
    assert.equal(sealed.sessionSealed, true);
    assert.equal(typeof (await (await sealed.openRpc('wsh-host')).request('host.ping')).time, 'number');
  });

  it('with seal_session off the channels are stream-mode, as before: `rpc`, not `rpc-virtual`', async () => {
    for (const seal of [undefined, 'off']) {
      const s = await startServer({ seal });
      const c = await login(s);
      assert.ok(c.hasFeature(RPC_FEATURE) && !c.hasFeature(RPC_VIRTUAL_FEATURE));
      const rpc = await c.openRpc('wsh-host');
      assert.equal(typeof (await rpc.request('host.ping')).time, 'number');
      await rpc.close();
    }
  });

  it('a flipped byte in a frame toward the server ends the session; nothing is delivered', async () => {
    const s = await startServer({ seal: 'require' });
    let armed = false;
    const relay = await viaRelay(s, { toRelay: (m) => { if (armed && m.type === MSG.ENCRYPTED_FRAME) { armed = false; const ct = new Uint8Array(m.ciphertext); ct[ct.length - 1] ^= 1; return { ...m, ciphertext: ct }; } return m; } });
    const c = await login(s, relay.url, { sealSession: true });
    const fs = await c.openRpc('wsh-fs');
    await fs.request('write', { path: 'one.txt', data: enc.encode('first') });
    armed = true;
    await assert.rejects(fs.request('write', { path: 'two.txt', data: enc.encode(MARKER) }));
    await until(() => /did not open/.test(s.logs()), `the server to refuse the frame: ${s.logs()}`);
    assert.ok(!existsSync(path.join(s.root, 'two.txt')), 'the tampered request delivered nothing');
    assert.equal(readFileSync(path.join(s.root, 'one.txt'), 'utf8'), 'first');
  });

  it('a flipped byte in a frame toward the client ends the client\'s session', async () => {
    const s = await startServer({ seal: 'require' });
    let armed = false;
    const relay = await viaRelay(s, { toClient: (m) => { if (armed && m.type === MSG.ENCRYPTED_FRAME) { armed = false; const ct = new Uint8Array(m.ciphertext); ct[0] ^= 1; return { ...m, ciphertext: ct }; } return m; } });
    const c = await login(s, relay.url, { sealSession: true });
    const host = await c.openRpc('wsh-host');
    assert.equal(typeof (await host.request('host.ping')).time, 'number');
    armed = true;
    await assert.rejects(host.request('host.ping', undefined, { timeoutMs: 4000 }));
    await until(() => host.closed, 'the channel to close');
  });

  it('the per-key capabilities of stream-mode rpc apply in virtual mode: rpc:NAME, and fs:read + fs:write for wsh-fs', async () => {
    const cases = [
      { options: 'capabilities="rpc:wsh-host"', host: true, fs: false },
      { options: 'capabilities="fs:read,fs:write,rpc:wsh-host"', host: true, fs: true },
      { options: 'capabilities="fs:read,rpc:wsh-host"', host: true, fs: false },
      { options: 'capabilities="exec"', host: false, fs: false },
      { options: 'restrict', host: true, fs: false },
      { options: 'restrict,permit-file-transfer', host: true, fs: true },
    ];
    for (const { options, host, fs } of cases) {
      const s = await startServer({ seal: 'require', keyLine: (pub) => `${options} ${pub}` });
      const c = await login(s, undefined, { sealSession: true });
      const ok = (protocol) => c.openRpc(protocol).then(async (r) => { await r.close(); return true; }, () => false);
      assert.equal(await ok('wsh-host'), host, `${options}: wsh-host`);
      assert.equal(await ok('wsh-fs'), fs, `${options}: wsh-fs`);
      await c.disconnect();
    }
  });

  it('the same checks against a server that does not serve a protocol or has no file root', async () => {
    const s = await startServer({ seal: 'require' });
    const c = await login(s, undefined, { sealSession: true });
    await assert.rejects(c.openRpc('mcp'), /UNSUPPORTED_PROTOCOL/);
    c.hasFeature = () => true; // a peer that skipped the feature check is refused by the server
    await assert.rejects(c.openRpc('mcp'), /UNSUPPORTED_PROTOCOL|not supported/);
  });

  it('a slow reader bounds the server: it sends one credit window and waits, and the rest follows when the client reads', async () => {
    const s = await startServer({ seal: 'require' });
    const size = 4 * MiB;
    const file = Buffer.alloc(size); for (let i = 0; i < size; i++) file[i] = (i * 13) % 251;
    writeFileSync(path.join(s.root, 'big.bin'), file);
    const relay = await viaRelay(s);
    const c = await login(s, relay.url, { sealSession: true });
    const fs = await c.openRpc('wsh-fs');
    fs.hold(); // the application does not read: no credit goes back
    const before = carried(relay, 'to-client');
    const chunks = [];
    const read = fs.request('read', { path: 'big.bin' }, { onProgress: (b) => chunks.push(Buffer.from(b)) });
    read.catch(() => {});
    // the server fills the window it was given...
    await until(() => carried(relay, 'to-client') - before >= RPC_CREDIT_WINDOW * 0.9, 'the server to fill its credit window');
    // ...and then waits: it does not send the other ~3.7 MiB while nobody reads
    await sleep(500);
    const sent = carried(relay, 'to-client') - before;
    assert.ok(sent <= RPC_CREDIT_WINDOW + 64 * 1024, `the server sent ${sent} bytes against a ${RPC_CREDIT_WINDOW} byte window`);
    assert.equal(chunks.length, 0, 'nothing was delivered while the channel was held');
    fs.release();
    const summary = await read;
    assert.equal(summary.size, size);
    assert.deepEqual(Buffer.concat(chunks), file);
  });

  it('a slow reader bounds the client: a server that cannot answer takes no more than its credit', async () => {
    const s = await startServer({ seal: 'require' });
    const relay = await viaRelay(s);
    const c = await login(s, relay.url, { sealSession: true });
    const host = await c.openRpc('wsh-host');
    host.hold(); // answers pile up unread: the server's answers use up the credit it holds, then it stops reading
    const before = carried(relay, 'to-relay');
    const pad = 'p'.repeat(2000);
    const attempts = 3000; // ~6 MB of requests
    const calls = [];
    for (let i = 0; i < attempts; i++) { const p = host.request('host.info', { pad }); p.catch(() => {}); calls.push(p); }
    // the sender stops at the credit it holds plus what the server consumed before it ran out of room to answer
    await until(() => carried(relay, 'to-relay') - before >= RPC_CREDIT_WINDOW * 0.9, 'the client to use its credit');
    await sleep(500);
    const sent = carried(relay, 'to-relay') - before;
    assert.ok(sent < 3 * MiB, `the client sent ${sent} of ~6 MB while the server could not answer`);
    host.release();
    const settled = await Promise.allSettled(calls);
    assert.equal(settled.filter((r) => r.status === 'fulfilled' || r.reason?.code === RPC_ERROR.STREAM_LIMIT).length, attempts);
  });

  it('a client that overruns its credit has the channel closed; the connection and its other channels carry on', async () => {
    const s = await startServer({ seal: 'require' });
    const c = await login(s, undefined, { sealSession: true });
    const other = await c.openRpc('wsh-host');
    const session = await c.openSession({ type: 'rpc', protocol: 'wsh-host' });
    const closed = new Promise((resolve) => { session.onClose = resolve; });
    session.onData = () => {};
    // One write per chunk with no regard for credit: 40 x 32 KiB is far more than the 256 KiB window.
    for (let i = 0; i < 40; i++) await session.write(new Uint8Array(32 * 1024).fill(0x61)).catch(() => {});
    await Promise.race([closed, sleep(10_000).then(() => { throw new Error('the channel was not closed'); })]);
    assert.equal(typeof (await other.request('host.ping')).time, 'number', 'another channel on the same connection is unaffected');
    const again = await c.openRpc('wsh-host');
    assert.equal(typeof (await again.request('host.ping')).time, 'number');
  });

  it('a message over the bound is refused from its header, before it is assembled, and the channel is closed', async () => {
    const s = await startServer({ seal: 'require', rpcExtra: 'max_message_bytes = 1024\n' });
    const c = await login(s, undefined, { sealSession: true });
    const session = await c.openSession({ type: 'rpc', protocol: 'wsh-host' });
    const received = [];
    session.onData = (d) => received.push(Buffer.from(d));
    const closed = new Promise((resolve) => { session.onClose = resolve; });
    // the header of a 1 MiB text string, and none of its body
    await session.write(Uint8Array.of(0x7a, 0x00, 0x10, 0x00, 0x00));
    await Promise.race([closed, sleep(5000).then(() => { throw new Error('the channel was not closed'); })]);
    assert.ok(received.length > 0, 'the host said why');
    const again = await c.openRpc('wsh-host');
    assert.equal(typeof (await again.request('host.ping')).time, 'number');
  });
});

describe('a released-shape peer against the new Rust wsh-server', () => {
  it('a client that only knows stream-mode rpc looks for `rpc`: refused cleanly, before any rpc byte', async () => {
    const s = await startServer({ seal: 'require' });
    const relay = await viaRelay(s);
    const c = await login(s, relay.url, { sealSession: true });
    // what a released client sees: the same features, minus the one it does not know
    const had = c.hasFeature.bind(c);
    c.hasFeature = (f) => f !== RPC_VIRTUAL_FEATURE && had(f);
    const opens = () => relay.seen.filter((e) => e.dir === 'to-relay').length;
    const before = opens();
    await assert.rejects(c.openRpc('wsh-host'), (e) => e.code === RPC_ERROR.UNSUPPORTED_PROTOCOL);
    assert.equal(opens(), before, 'nothing was sent');
  });

  it('a released client that does not seal gets no rpc channel from `seal_session = "require"`: nothing is served in the clear', async () => {
    const s = await startServer({ seal: 'require' });
    const c = await login(s, undefined, { sealSession: false });
    await assert.rejects(c.openRpc('wsh-host'));
    await until(() => /requires a sealed session/.test(s.logs()), `the server to refuse it: ${s.logs()}`);
  });
});

// ── B. the Rust `wsh mcp`, against a JS host in a page behind a relay ───────────────────────────────────────────────

function makeHome() {
  const home = tmpDir('wsh-rpcv-home-');
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  return { home, pub: readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim() };
}

/** A pipe relay that copies bytes, records them, and mutates what the test says (`mutate(dir, data, count)`). */
async function copyingRelay() {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  const pending = new Map();
  const relay = { seen: [], bytes: { toHost: 0, toOperator: 0 }, mutate: null, url: `ws://127.0.0.1:${wss.address().port}` };
  relay.text = () => Buffer.concat(relay.seen).toString('latin1');
  wss.on('connection', (ws, req) => {
    const u = new URL(req.url, 'ws://x');
    const id = u.pathname.split('/').pop();
    const role = u.searchParams.get('role') === 'host' ? 'host' : 'operator';
    const other = pending.get(id);
    if (!other) { pending.set(id, { ws, role }); return; }
    pending.delete(id);
    const [host, operator] = role === 'host' ? [ws, other.ws] : [other.ws, ws];
    let counts = { toHost: 0, toOperator: 0 };
    const wire = (from, to, dir) => from.on('message', (data, isBinary) => {
      let out = Buffer.from(data);
      counts[dir] += 1;
      relay.seen.push(out);
      relay.bytes[dir] += out.length;
      if (relay.mutate) { const r = relay.mutate(dir, out, counts[dir]); if (r === null) return; out = r; }
      if (to.readyState === 1) to.send(out, { binary: isBinary });
    });
    wire(operator, host, 'toHost');
    wire(host, operator, 'toOperator');
    for (const [a, b] of [[host, operator], [operator, host]]) a.on('close', () => { if (b.readyState === 1) b.close(); });
  });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  return relay;
}

function makeMcpServer() {
  const server = new Server({ name: 'behind-wsh', version: '1.0.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      { name: METHOD_TOOL, description: 'Echo text back', inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } },
      { name: 'big', description: 'A result of about 900 KB', inputSchema: { type: 'object' } },
    ],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args = {} } = req.params;
    if (name === 'big') return { content: [{ type: 'text', text: 'x'.repeat(900_000) }] };
    return { content: [{ type: 'text', text: `echo: ${args.text}` }] };
  });
  return server;
}

/** A host in a page: no client-opened streams, a host key, and rpc offered (as `rpc-virtual`); behind a pipe relay. */
async function pageHost(h, relay, { sealSession, rpc, logs = [] } = {}) {
  const host = createMemoryHost({
    auth: { authorizedKeys: h.pub }, exec: async () => 0, hostKey: true, dataStreams: false, requireChannelBinding: true, sealSession,
    rpc: rpc ?? { mcp: mcpServerAdapter(() => makeMcpServer()) },
    onLog: (l) => logs.push(l),
  });
  closers.push(() => host.close());
  const id = newRendezvousId();
  const ws = new WsClient(`${relay.url}/r/${id}?role=host`);
  ws.on('error', () => {});
  closers.push(async () => ws.terminate());
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  await host.accept(ws);
  return { host, id, logs };
}

/** The MCP SDK's stdio client launching `wsh [--sealed] --via <relay> mcp alice@tab.example`. */
async function mcpClient(h, relay, id, { sealed = true, extra = [] } = {}) {
  const args = ['--accept-new-host-key', '--via', `${relay.url}/r/${id}`, ...(sealed ? ['--sealed'] : []), 'mcp', ...extra, 'alice@tab.example'];
  const transport = new StdioClientTransport({ command: WSH_BIN, args, env: cleanEnv(h.home), stderr: 'pipe' });
  let stderr = '';
  transport.stderr?.on('data', (d) => { stderr += d; });
  const client = new Client({ name: 'an-mcp-client', version: '1.0.0' }, { capabilities: {} });
  closers.push(() => client.close());
  await client.connect(transport);
  return { client, transport, stderr: () => stderr };
}

describe('wsh mcp --sealed / --via against a JS host in a page (#191)', () => {
  it('--sealed: the MCP SDK client lists and calls tools through a recording relay that sees no tool name, no method and no payload', async () => {
    const h = makeHome(); const relay = await copyingRelay();
    const { id } = await pageHost(h, relay, { sealSession: 'require' });
    const { client } = await mcpClient(h, relay, id);
    assert.equal(client.getServerVersion().name, 'behind-wsh');
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), [METHOD_TOOL, 'big']);
    assert.equal((await client.callTool({ name: METHOD_TOOL, arguments: { text: MARKER } })).content[0].text, `echo: ${MARKER}`);
    const big = await client.callTool({ name: 'big', arguments: {} }); // 900 KB: more than the credit window, in both directions' accounting
    assert.equal(big.content[0].text.length, 900_000);
    const seen = relay.text();
    for (const word of [MARKER, METHOD_TOOL, 'tools/call', 'tools/list', 'initialize', 'behind-wsh']) assert.ok(!seen.includes(word), `"${word}" crossed the relay in the clear`);
  });

  it('control: --via without sealing, the relay reads the same traffic (and it works: the channel is virtual, not a stream)', async () => {
    const h = makeHome(); const relay = await copyingRelay();
    const { id } = await pageHost(h, relay, {});
    const { client } = await mcpClient(h, relay, id, { sealed: false });
    assert.equal((await client.callTool({ name: METHOD_TOOL, arguments: { text: MARKER } })).content[0].text, `echo: ${MARKER}`);
    const seen = relay.text();
    assert.ok(seen.includes(MARKER) && seen.includes('tools/call'), 'unsealed, the relay sees the method and the data');
  });

  it('a flipped byte in a frame ends the session: the call fails, nothing is delivered, the host says why', async () => {
    const h = makeHome(); const relay = await copyingRelay(); const logs = [];
    const { id } = await pageHost(h, relay, { sealSession: 'require', logs });
    const { client, stderr } = await mcpClient(h, relay, id);
    assert.equal((await client.callTool({ name: METHOD_TOOL, arguments: { text: 'warm up' } })).content[0].text, 'echo: warm up');
    // a byte in the middle of the next record toward the host: inside the sealed frame's ciphertext, not its framing
    relay.mutate = (dir, data) => { if (dir === 'toHost' && data.length > 40) { relay.mutate = null; const d = Buffer.from(data); d[Math.floor(d.length / 2)] ^= 1; return d; } return data; };
    const call = client.callTool({ name: METHOD_TOOL, arguments: { text: MARKER } }, undefined, { timeout: 20_000 }).then((r) => r.content[0].text, (e) => `error: ${e.message}`);
    await until(() => logs.some((l) => /did not open/.test(l)), `the host to refuse the frame: ${logs.join(' | ')}`);
    const outcome = await call;
    assert.notEqual(outcome, `echo: ${MARKER}`, 'a tampered frame delivered nothing');
    assert.match(outcome, /^error: /, `the call fails (stderr: ${stderr()})`);
    assert.doesNotMatch(outcome, /timed out|Request timed out/i, `the bridge noticed the host go (stderr: ${stderr()})`);
  });

  it('a slow reader bounds the host: with the client not reading stdout, the host sends about one credit window and waits', async () => {
    const h = makeHome(); const relay = await copyingRelay();
    const { id } = await pageHost(h, relay, { sealSession: 'require' });
    const { client, transport } = await mcpClient(h, relay, id);
    await client.listTools();
    transport._process.stdout.pause(); // the MCP client stops reading what `wsh mcp` writes to stdout
    const before = relay.bytes.toOperator;
    const calls = [];
    for (let i = 0; i < 8; i++) { const p = client.callTool({ name: 'big', arguments: {} }, undefined, { timeout: 120_000 }); p.catch(() => {}); calls.push(p); }
    await until(() => relay.bytes.toOperator - before >= RPC_CREDIT_WINDOW * 0.9, 'the host to fill its credit window');
    await sleep(500);
    const sent = relay.bytes.toOperator - before;
    // one window, plus the message `wsh mcp` was writing when its pipe filled, plus the pipe: far less than the 8 x 900 KB asked for
    assert.ok(sent < 3 * MiB, `the host sent ${sent} bytes of ~7.2 MB to a reader that was not reading`);
    transport._process.stdout.resume();
    const results = await Promise.all(calls);
    assert.ok(results.every((r) => r.content[0].text.length === 900_000), 'every result arrived, intact, once the reader read');
  });

  it('a slow reader bounds `wsh mcp`: a host that does not read takes no more than its credit', async () => {
    const h = makeHome(); const relay = await copyingRelay();
    let release;
    const gate = new Promise((r) => { release = r; });
    let got = 0;
    const sink = async (channel) => {
      channel.hold(); // the host application does not read: no credit goes back
      channel.onNotification('sink/data', () => { got += 1; });
      await gate;
      channel.release();
    };
    const { id } = await pageHost(h, relay, { sealSession: 'require', rpc: { sink } });
    const proc = spawn(WSH_BIN, ['--accept-new-host-key', '--via', `${relay.url}/r/${id}`, '--sealed', 'mcp', '--channel', 'sink', 'alice@tab.example'], { env: cleanEnv(h.home), stdio: ['pipe', 'pipe', 'pipe'] });
    closers.push(async () => proc.kill('SIGKILL'));
    let stderr = ''; proc.stderr.on('data', (d) => { stderr += d; }); proc.stdout.resume(); proc.stdin.on('error', () => {});
    const line = `${JSON.stringify({ jsonrpc: '2.0', method: 'sink/data', params: { pad: 'p'.repeat(500_000) } })}\n`;
    // `wsh mcp` forwards the first message it sees (the MCP initialize) too; send notifications, which need no answer
    const before = relay.bytes.toHost;
    for (let i = 0; i < 16; i++) proc.stdin.write(line); // ~8 MB
    await until(() => relay.bytes.toHost - before >= RPC_CREDIT_WINDOW * 0.9, `wsh mcp to use its credit (${stderr})`);
    await sleep(500);
    const sent = relay.bytes.toHost - before;
    assert.ok(sent < 3 * MiB, `wsh mcp sent ${sent} bytes of ~8 MB to a host that was not reading`);
    assert.equal(got, 0);
    release();
    await until(() => got === 16, `the host to read all 16 messages (${got})`, 30_000);
    proc.stdin.end();
  });
});

describe('a host that states only `rpc` is served with streams, as today (a released host, from the new Rust client)', () => {
  it('wsh mcp against a Node host over WebSocket: stream mode, no rpc-virtual in sight', async () => {
    const h = makeHome();
    const server = createWshServer({ auth: { authorizedKeys: `${h.pub}\n` }, rpc: { mcp: mcpServerAdapter(() => makeMcpServer()) } });
    const { port } = await server.listen();
    closers.push(() => server.close());
    const transport = new StdioClientTransport({ command: WSH_BIN, args: ['--accept-new-host-key', 'mcp', `alice@ws://127.0.0.1:${port}`], env: cleanEnv(h.home), stderr: 'pipe' });
    const client = new Client({ name: 'an-mcp-client', version: '1.0.0' }, { capabilities: {} });
    closers.push(() => client.close());
    await client.connect(transport);
    assert.equal((await client.callTool({ name: METHOD_TOOL, arguments: { text: 'streams' } })).content[0].text, 'echo: streams');
    // the Node host (with data streams) states `rpc` and never `rpc-virtual`: the bridge could only have used a stream
    const { parseRpcFeatures } = await import('../../src/rpc.mjs');
    assert.deepEqual(parseRpcFeatures(['rpc', 'rpc-protocol:mcp']).enabled, true);
  });
});
