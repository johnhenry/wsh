// test/rust/wsh-rust-server-udp-bounds.test.mjs -- #145: the Rust `wsh-server`'s UDP flows (`OpenUdp`) are bounded the way the Node
// host's are (test/gateway-datagram.test.mjs, the parts that do not need WebTransport): flows per client, datagrams per second
// per flow and per client, payload bytes per second per client (both directions), and an idle limit counted in both directions.
// Over the reliable control stream (wss://). The same bounds over WebTransport datagrams: wsh-rust-server-udp-datagrams.test.mjs.
//
// Drives the real binary (cargo build -p wsh-server, WSH_SERVER_BIN) with this repo's JS client, against a UDP echo on
// loopback. Every server runs with HOME in a scratch directory.

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { WshClient, generateKeyPair, exportPublicKeySSH } from '../../src/index.mjs';
import { GatewayError } from '../../src/gateway-client.mjs';
import { freePort } from '../helpers/free-port.mjs'; // free for TCP and UDP: the server binds both (#248)

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 8000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
}

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
before(() => {
  assert.ok(fs.existsSync(SERVER_BIN), `expected the built binary at ${SERVER_BIN} (cargo build -p wsh-server, or WSH_SERVER_BIN)`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the dev certificate is self-signed
});
after(() => {
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});

describe('Rust wsh-server: UDP flows are bounded as on the Node host (#145)', () => {
  const procs = []; const clients = []; const dirs = []; const socks = [];

  afterEach(async () => {
    for (const s of socks.splice(0)) { try { s.close(); } catch { /* closed */ } }
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const p of procs.splice(0)) { p.kill(); await new Promise((r) => { if (p.exitCode !== null) r(); else { p.once('exit', r); setTimeout(r, 2000); } }); }
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  async function echoServer() {
    const s = dgram.createSocket('udp4'); socks.push(s);
    await new Promise((r) => s.bind(0, '127.0.0.1', r));
    s.on('message', (msg, rinfo) => s.send(msg, rinfo.port, rinfo.address));
    return s.address().port;
  }

  /** wsh-server with the gateway on, `127.0.0.1:<port>` allowed, and `lines` more `[gateway]` settings. */
  async function setup(port, lines = '', { expectExit = false } = {}) {
    const kp = await generateKeyPair(true);
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-udp-home-'));
    dirs.push(home);
    fs.mkdirSync(path.join(home, '.wsh'));
    fs.writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(kp.publicKey)}\n`);
    const configPath = path.join(home, '.wsh', 'config.toml');
    fs.writeFileSync(configPath, `[gateway]\nenabled = true\nallowed_destinations = ["127.0.0.1:${port}"]\n${lines}\n`);
    const sport = await freePort();
    const proc = spawn(SERVER_BIN, ['--port', String(sport), '--generate-cert', '--config', configPath], {
      env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config') }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    procs.push(proc);
    let logs = '';
    const exited = new Promise((resolve) => proc.once('exit', (code) => resolve(code)));
    proc.stdout.on('data', (d) => { logs += d; }); proc.stderr.on('data', (d) => { logs += d; });
    if (expectExit) return { code: await Promise.race([exited, sleep(10_000).then(() => 'still running')]), logs: () => logs };
    await until(() => logs.includes('WebSocket TLS listener started') || (proc.exitCode !== null && (() => { throw new Error(`wsh-server exited: ${logs}`); })()), 'the server to start', 10_000);
    const client = new WshClient();
    await client.connect(`wss://127.0.0.1:${sport}`, { username: 'tester', keyPair: kp });
    clients.push(client);
    return { client, logs: () => logs };
  }

  /** Send `count` datagrams of `size` bytes as fast as the stream takes them and count what is echoed back within `waitMs`. */
  async function blast(flow, count, size, waitMs = 1500) {
    const w = flow.writable.getWriter(); const r = flow.readable.getReader();
    let received = 0; let bytes = 0;
    const pump = (async () => { for (;;) { const { value, done } = await r.read(); if (done) return; received += 1; bytes += value.length; } })().catch(() => {});
    const payload = new Uint8Array(size).fill(9);
    for (let i = 0; i < count; i++) await w.write(payload);
    await sleep(waitMs);
    flow.destroy();
    await Promise.race([pump, sleep(200)]);
    return { received, bytes };
  }

  /**
   * Send `count` datagrams with at most `window` unanswered: the next goes out as an echo comes back, and the call returns once
   * all `count` have. UDP over loopback is not lossless when a burst meets a socket buffer (the OS owes no more), so a test that
   * asserts "nothing was dropped by the server" must not offer the sockets a burst; the window keeps every socket nearly empty.
   * The 30 s race is only a hang guard: a datagram the server really dropped would leave this waiting for an echo that never comes.
   */
  async function windowed(flow, count, size, window = 8) {
    const w = flow.writable.getWriter(); const r = flow.readable.getReader();
    const payload = new Uint8Array(size).fill(9);
    let sent = 0; let received = 0; let bytes = 0;
    const run = (async () => {
      for (; sent < Math.min(window, count); sent++) await w.write(payload);
      while (received < count) {
        const { value, done } = await r.read();
        if (done) break;
        received += 1; bytes += value.length;
        if (sent < count) { await w.write(payload); sent += 1; }
      }
    })();
    await Promise.race([run, sleep(30_000).then(() => { throw new Error(`only ${received} of ${count} datagrams came back`); })]);
    flow.destroy();
    return { received, bytes };
  }

  it('with the defaults a flow round-trips ordinary datagrams (the bounds are generous)', async () => {
    const port = await echoServer();
    const { client } = await setup(port);
    const flow = await client.openUdp('127.0.0.1', port);
    const { received } = await windowed(flow, 50, 100);
    assert.equal(received, 50);
  });

  it('limits flows per client, and a slot frees when one closes', async () => {
    const port = await echoServer();
    const { client } = await setup(port, 'udp_max_flows = 2\n');
    const a = await client.openUdp('127.0.0.1', port);
    await client.openUdp('127.0.0.1', port);
    await assert.rejects(client.openUdp('127.0.0.1', port), (e) => e instanceof GatewayError && e.code === 7 && /too many UDP flows \(limit 2\)/.test(e.message));
    a.destroy();
    await until(async () => { try { (await client.openUdp('127.0.0.1', port)); return true; } catch { return false; } }, 'a slot frees when a flow closes');
  });

  // What a token bucket guarantees whatever the scheduling: over T seconds since it was made it admits at most burst + rate * T
  // datagrams. An echoed datagram costs two (the one sent and the one that comes back), so received * 2 <= burst + rate * T.
  // These tests assert that ceiling, computed from the measured wall time, and NOT a floor: a fast sender drains the whole burst
  // with its own datagrams before any answer is back, so an exact or minimum count depends on how slow the machine is (CI saw 0).
  // That the limit lets traffic through at all is asserted by a sender paced well inside the rate, which never runs dry.
  const ceiling = (burst, rate, startedAt) => (burst + rate * ((Date.now() - startedAt) / 1000)) / 2 + 1;

  /** `count` datagrams of 50 bytes, one every `everyMs`, and how many are echoed back. */
  async function paced(flow, count, everyMs) {
    const w = flow.writable.getWriter(); const r = flow.readable.getReader();
    let received = 0;
    const pump = (async () => { for (;;) { const { done } = await r.read(); if (done) return; received += 1; } })().catch(() => {});
    for (let i = 0; i < count; i++) { await w.write(new Uint8Array(50).fill(9)); await sleep(everyMs); }
    await until(() => received >= count, `${count} echoes`, 5000).catch(() => {});
    flow.destroy();
    await Promise.race([pump, sleep(200)]);
    return received;
  }

  it('rate-limits a flow: a burst beyond udp_packets_per_second_per_flow is dropped, not queued', async () => {
    const port = await echoServer();
    const t0 = Date.now();
    const { client } = await setup(port, 'udp_packets_per_second_per_flow = 20\n');
    const flow = await client.openUdp('127.0.0.1', port);
    const { received } = await blast(flow, 200, 50, 1000);
    // burst max(20/4, 16) = 16 tokens, both directions drawing on the same bucket
    assert.ok(received <= ceiling(16, 20, t0), `${received} echoed of 200, at most ${ceiling(16, 20, t0)} allowed`);
  });

  it('a flow sending inside udp_packets_per_second_per_flow is not limited', async () => {
    const port = await echoServer();
    const { client } = await setup(port, 'udp_packets_per_second_per_flow = 20\n');
    const flow = await client.openUdp('127.0.0.1', port);
    // 10 datagrams, 2 tokens each: 20 tokens in about a second against a burst of 16 and a refill of 20 a second, so never dry
    assert.equal(await paced(flow, 10, 100), 10);
  });

  it('rate-limits a client over all its flows: udp_packets_per_second_per_client', async () => {
    const port = await echoServer();
    const t0 = Date.now();
    const { client } = await setup(port, 'udp_packets_per_second_per_client = 20\n');
    const a = await client.openUdp('127.0.0.1', port);
    const b = await client.openUdp('127.0.0.1', port);
    const [ra, rb] = await Promise.all([blast(a, 100, 50, 1000), blast(b, 100, 50, 1000)]);
    // burst max(5, 32) = 32 tokens shared by both flows and both directions
    assert.ok(ra.received + rb.received <= ceiling(32, 20, t0), `${ra.received + rb.received} echoed of 200, at most ${ceiling(32, 20, t0)} allowed`);
  });

  it('two flows paced inside udp_packets_per_second_per_client together are not limited', async () => {
    const port = await echoServer();
    const { client } = await setup(port, 'udp_packets_per_second_per_client = 20\n');
    const a = await client.openUdp('127.0.0.1', port);
    const b = await client.openUdp('127.0.0.1', port);
    // 2 x 6 datagrams, 2 tokens each: 24 tokens against a burst of 32, whatever the refill: never dry
    const [ra, rb] = await Promise.all([paced(a, 6, 100), paced(b, 6, 100)]);
    assert.equal(ra + rb, 12);
  });

  it('bounds the payload bytes per second per client (the amplification bound): small queries, big answers', async () => {
    // an origin that answers every 10-byte query with 8000 bytes: 40 queries over about a second ask for 320 kB
    const amp = dgram.createSocket('udp4'); socks.push(amp);
    await new Promise((r) => amp.bind(0, '127.0.0.1', r));
    amp.on('message', (_m, ri) => amp.send(Buffer.alloc(8000, 7), ri.port, ri.address));
    const port = amp.address().port;
    const t0 = Date.now();
    const { client } = await setup(port, 'udp_bytes_per_second_per_client = 40000\nudp_packets_per_second_per_client = 0\nudp_packets_per_second_per_flow = 0\n');
    const flow = await client.openUdp('127.0.0.1', port);
    const w = flow.writable.getWriter(); const r = flow.readable.getReader();
    let bytes = 0;
    const pump = (async () => { for (;;) { const { value, done } = await r.read(); if (done) return; bytes += value.length; } })().catch(() => {});
    for (let i = 0; i < 40; i++) { await w.write(new Uint8Array(10)); await sleep(25); }
    await sleep(500);
    flow.destroy(); await Promise.race([pump, sleep(200)]);
    // The burst is max(10000, 65536) bytes and the refill 40000 a second; the 10-byte queries draw on the same bucket. Whatever
    // the scheduling, no more than burst + rate * T bytes can have been admitted over T seconds; and the first answer, which
    // finds the burst full, always passes.
    const allowed = 65536 + 40000 * ((Date.now() - t0) / 1000);
    assert.ok(bytes >= 8000 && bytes <= allowed, `${bytes} bytes of 320000 offered reached the client, at most ${allowed} allowed`);
  });

  it('zero means no limit: nothing is dropped', async () => {
    const port = await echoServer();
    const { client } = await setup(port, 'udp_packets_per_second_per_flow = 0\nudp_packets_per_second_per_client = 0\nudp_bytes_per_second_per_client = 0\n');
    const flow = await client.openUdp('127.0.0.1', port);
    // Paced by the echoes (a burst of 300 can overflow an OS socket buffer, which is the OS dropping, not the server): with
    // no limit, every one of the 300 must come back.
    const { received, bytes } = await windowed(flow, 300, 200);
    assert.equal(received, 300);
    assert.equal(bytes, 300 * 200);
  });

  it('closes a flow that has been idle too long, and traffic in either direction keeps it alive', async () => {
    const port = await echoServer();
    const { client } = await setup(port, 'udp_idle_secs = 2\n');
    const idle = await client.openUdp('127.0.0.1', port);
    assert.equal(await Promise.race([idle.closed.then(() => 'closed'), sleep(15_000).then(() => 'still open')]), 'closed');
    const busy = await client.openUdp('127.0.0.1', port);
    const w = busy.writable.getWriter();
    const r = busy.readable.getReader();
    void (async () => { for (;;) { const { done } = await r.read(); if (done) return; } })().catch(() => {});
    for (let i = 0; i < 8; i++) { await w.write(new Uint8Array(10)); await sleep(500); } // 4 s of traffic against a 2 s limit
    const stillOpen = await Promise.race([busy.closed.then(() => false), sleep(100).then(() => true)]);
    assert.equal(stillOpen, true, 'kept alive by traffic');
    busy.destroy();
  });

  it('traffic from the client alone (the origin never answers) also keeps a flow open', async () => {
    const silent = dgram.createSocket('udp4'); socks.push(silent);
    await new Promise((r) => silent.bind(0, '127.0.0.1', r));
    const port = silent.address().port; // bound, reads, never answers
    const { client } = await setup(port, 'udp_idle_secs = 2\n');
    const flow = await client.openUdp('127.0.0.1', port);
    const w = flow.writable.getWriter();
    for (let i = 0; i < 8; i++) { await w.write(new Uint8Array(10)); await sleep(500); } // 4 s against a 2 s limit
    assert.equal(await Promise.race([flow.closed.then(() => false), sleep(100).then(() => true)]), true, 'one-way traffic keeps it alive');
    assert.equal(await Promise.race([flow.closed.then(() => 'closed'), sleep(15_000).then(() => 'still open')]), 'closed', 'and it closes once the traffic stops');
  });

  it('a zero idle, and nothing else nonsensical, stops the server before it listens', async () => {
    const port = await echoServer();
    const r = await setup(port, 'udp_idle_secs = 0\n', { expectExit: true });
    assert.notEqual(r.code, 0, r.logs());
    assert.notEqual(r.code, 'still running');
    assert.match(r.logs(), /udp_idle_secs/);
  });
});
