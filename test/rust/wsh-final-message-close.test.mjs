// test/rust/wsh-final-message-close.test.mjs -- #256: the Rust `wsh-server` writes a refusal (the AuthFail at the login deadline, the Error at the seal
// deadline) and then closes. A peer that completed the QMux handshake but granted no flow-control credit used to make that write wait without end, and
// the close behind it never ran: the deadline did not close the connection. The write is now a bounded best effort; the server closes whether or not
// the message went. A peer that does read still gets the refusal.
//
// Every wait below is for an event (the close of the connection), bounded; none is a count of milliseconds. 1 s is the smallest deadline the key takes.
// Every process runs with HOME in a scratch directory. Prerequisite: cargo build -p wsh-server (or --release), WSH_SERVER_BIN pointing at it.

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocket } from 'ws';

import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeySSH } from '../../src/index.mjs';
import { QMuxConnection } from '../../src/qmux-connection.mjs';
import { encodeRecord, encodeTransportParameters } from '../../src/qmux.mjs';
import { listeningPort } from './helpers/listening.mjs'; // the server binds port 0 and prints the port it got (#320)

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

const scratch = [];
const procs = [];
const closers = [];
const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
before(() => {
  assert.ok(existsSync(SERVER_BIN), `expected the built binary at ${SERVER_BIN} (cargo build -p wsh-server, WSH_SERVER_BIN)`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the dev certificate is self-signed
});
after(() => {
  for (const p of procs.splice(0)) p.kill();
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm' });
/** Resolves with `true` when `promise` settles, with `false` after `ms`: a missing close is a failed assertion, not a hang. */
const within = (promise, ms) => Promise.race([promise.then(() => true), new Promise((r) => setTimeout(() => r(false), ms))]);

async function startServer({ loginTimeoutSecs = 1, sealTimeoutSecs, seal } = {}) {
  const kp = await generateKeyPair(true);
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-final-srv-'));
  scratch.push(home);
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(kp.publicKey)}\n`);
  const configPath = path.join(home, '.wsh', 'config.toml');
  const hostKeyPath = path.join(home, '.wsh', 'host_key');
  writeFileSync(configPath, `[server]\nlogin_timeout_secs = ${loginTimeoutSecs}\n${seal ? `host_key = ${JSON.stringify(hostKeyPath)}\nseal_session = "${seal}"\nseal_timeout_secs = ${sealTimeoutSecs}\n` : ''}`);
  const proc = spawn(SERVER_BIN, ['--port', '0', '--generate-cert', '--config', configPath], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  const port = await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; const p = listeningPort(logs); if (p) resolve(p); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(Object.assign(new Error(`wsh-server exited (${c}): ${logs}`), { logs })));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  return { url: `wss://127.0.0.1:${port}`, kp, logs: () => logs };
}

/** A QMux transport-parameters record that grants the host `maxData` bytes on the whole connection. */
const grant = (maxData) => encodeRecord(encodeTransportParameters({
  initial_max_data: maxData, initial_max_stream_data_bidi_local: 1_048_576, initial_max_stream_data_bidi_remote: 1_048_576, initial_max_streams_bidi: 100,
}));

/**
 * A WebSocket class for a `WebSocketTransport`: the QMux handshake the client sends is replaced by one that grants only `maxData`, and the bytes the
 * host sends (after its own handshake) are counted in `seen.bytes`. Everything else is the real client.
 */
function creditedSocket(maxData, seen = { bytes: 0, closed: false, closedP: null }) {
  let resolveClosed;
  seen.closedP = new Promise((r) => { resolveClosed = r; });
  class Credited extends WebSocket {
    #sent = 0;
    #received = 0;
    constructor(...args) {
      super(...args);
      this.on('message', (d) => { if (this.#received++ > 0) seen.bytes += d.byteLength; });
      this.on('close', () => { seen.closed = true; resolveClosed(); });
      this.on('error', () => {});
    }
    send(data, ...rest) { return super.send(this.#sent++ === 0 ? grant(maxData) : data, ...rest); }
  }
  return { Socket: Credited, seen };
}

function clientOver(Socket) {
  return new WshClient({ transportFactories: { ws: () => new WebSocketTransport({ WebSocket: Socket }), wt: () => { throw new Error('no webtransport'); } } });
}

describe('the refusal at a deadline is a bounded best effort (#256)', () => {
  it('login-timeout: a peer that opened the control stream, granted no credit and never reads, is closed at the deadline', async () => {
    const s = await startServer({ loginTimeoutSecs: 1 });
    const ws = new WebSocket(s.url);
    closers.push(async () => ws.terminate());
    const closed = new Promise((r) => ws.once('close', r));
    ws.on('error', () => {});
    await new Promise((r) => ws.once('open', r));
    const peer = new QMuxConnection({ isClient: true, send: (b) => ws.send(b), initialMaxData: 0, initialMaxStreamData: 0 });
    peer.sendHandshake();
    (await peer.openStream()).announce();
    // The server's bytes are never given to `peer`: it reads nothing, and so grants nothing.
    assert.equal(await within(closed, 6_000), true, `the server closed the connection: ${s.logs()}`);
    assert.match(s.logs(), /login-timeout/);
  });

  it('login-timeout: a client that says Hello and has granted no credit (the host cannot even answer) is closed at the deadline', async () => {
    const s = await startServer({ loginTimeoutSecs: 1 });
    const { Socket, seen } = creditedSocket(0);
    const client = clientOver(Socket);
    closers.push(() => client.disconnect());
    client.connect(s.url, { username: 'tester', keyPair: s.kp, transport: 'ws', sealSession: false, timeout: 60_000 }).catch(() => {});
    assert.equal(await within(seen.closedP, 6_000), true, `the server closed the connection: ${s.logs()}`);
    assert.match(s.logs(), /login-timeout/);
  });

  it('login-timeout: a peer that reads is still told why (the AuthFail arrives before the close)', async () => {
    const s = await startServer({ loginTimeoutSecs: 1 });
    const ws = new WebSocket(s.url);
    closers.push(async () => ws.terminate());
    const closed = new Promise((r) => ws.once('close', r));
    ws.on('error', () => {});
    await new Promise((r) => ws.once('open', r));
    const heard = [];
    const peer = new QMuxConnection({ isClient: true, send: (b) => ws.send(b) });
    ws.on('message', (d) => peer.receiveBytes(new Uint8Array(d)));
    peer.sendHandshake();
    const control = await peer.openStream();
    control.onData = (d) => heard.push(Buffer.from(d));
    control.announce();
    assert.equal(await within(closed, 6_000), true, 'closed');
    assert.match(Buffer.concat(heard).toString('latin1'), /login-timeout/);
  });

  it('seal-timeout: a client that logs in under seal_session = "require" and then grants no more credit is closed at the deadline', async () => {
    const s = await startServer({ loginTimeoutSecs: 60, sealTimeoutSecs: 1, seal: 'require' });
    // How many bytes the host sends for one login: the second connection grants exactly that many, so the Error at the seal deadline has no room.
    const measure = creditedSocket(1_000_000);
    const first = clientOver(measure.Socket);
    await first.connect(s.url, { username: 'tester', keyPair: s.kp, transport: 'ws', sealSession: false, timeout: 8_000 });
    const loginBytes = measure.seen.bytes;
    assert.ok(loginBytes > 0);
    await first.disconnect();

    const { Socket, seen } = creditedSocket(loginBytes);
    const client = clientOver(Socket);
    closers.push(() => client.disconnect());
    await client.connect(s.url, { username: 'tester', keyPair: s.kp, transport: 'ws', sealSession: false, timeout: 8_000 });
    assert.equal(client.state, 'authenticated');
    assert.equal(await within(seen.closedP, 8_000), true, `the server closed the connection: ${s.logs()}`);
    assert.match(s.logs(), /not sealed in time/);
  });
});
