// test/rust/wsh-rust-server-udp-datagrams.test.mjs -- #124, #145: the Rust `wsh-server` serves UDP flows (`OpenUdp`) as WebTransport datagrams
// when the client lists `gateway-datagram`, as the Node host does (test/gateway-datagram.test.mjs): a real QUIC connection from this repo's JS
// client (the native WebTransport of @fails-components/webtransport, pinned to the server's self-signed certificate) to the real binary, and a
// real UDP echo on loopback. A client that does not list the feature (WebSocket, or `udp_datagrams = false`) is served over the control stream
// exactly as before, and the UDP bounds of #145 apply to the datagram path too.
//
// Every server runs with HOME in a scratch directory. Drives the real binary (cargo build -p wsh-server, WSH_SERVER_BIN).

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebTransport as RealWebTransport, quicheLoaded } from '@fails-components/webtransport';

import { WshClient, generateKeyPair, exportPublicKeySSH } from '../../src/index.mjs';
import { GATEWAY_DATAGRAM_FEATURE } from '../../src/gateway-datagram.mjs';
import { freePort } from '../helpers/free-port.mjs'; // free for TCP and UDP: the server binds both (#248)

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 8000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
}

// `WebTransportTransport` calls the bare global `new WebTransport(url)`: install the native one, pinned to the certificate of the server
// the current test started (the WebTransport spec's serverCertificateHashes; the dev certificate is valid for 13 days, as that needs).
let pinned = null;
const ORIGINAL_WT = globalThis.WebTransport;
const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
before(async () => {
  assert.ok(fs.existsSync(SERVER_BIN), `expected the built binary at ${SERVER_BIN} (cargo build -p wsh-server, or WSH_SERVER_BIN)`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the WebSocket client of the fallback test
  await quicheLoaded;
  globalThis.WebTransport = class extends RealWebTransport {
    constructor(url) { super(url, { serverCertificateHashes: [{ algorithm: 'sha-256', value: pinned }] }); }
  };
});
after(() => {
  if (ORIGINAL_WT === undefined) delete globalThis.WebTransport; else globalThis.WebTransport = ORIGINAL_WT;
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});

describe('Rust wsh-server: UDP flows as WebTransport datagrams (gateway-datagram, #124)', () => {
  const procs = []; const clients = []; const dirs = []; const socks = [];

  afterEach(async () => {
    for (const s of socks.splice(0)) { try { s.close(); } catch { /* closed */ } }
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const p of procs.splice(0)) { p.kill(); await new Promise((r) => { if (p.exitCode !== null) r(); else { p.once('exit', r); setTimeout(r, 2000); } }); }
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  /** A UDP echo on loopback; `onPacket` sees every datagram it receives. */
  async function echoServer(onPacket) {
    const s = dgram.createSocket('udp4'); socks.push(s);
    await new Promise((r) => s.bind(0, '127.0.0.1', r));
    s.on('message', (msg, rinfo) => { onPacket?.(msg); s.send(msg, rinfo.port, rinfo.address); });
    return s.address().port;
  }

  /** wsh-server with the gateway on, `127.0.0.1:<port>` allowed and `lines` more `[gateway]` settings; a client over `transport`. */
  async function setup(port, lines = '', transport = 'wt') {
    const kp = await generateKeyPair(true);
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-udpdg-home-'));
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
    proc.stdout.on('data', (d) => { logs += d; }); proc.stderr.on('data', (d) => { logs += d; });
    await until(() => logs.includes('WebSocket TLS listener started') || (proc.exitCode !== null && (() => { throw new Error(`wsh-server exited: ${logs}`); })()), 'the server to start', 10_000);
    await until(() => logs.includes('WebTransport listener started'), 'the WebTransport listener', 10_000);
    const fp = execFileSync('openssl', ['x509', '-in', path.join(home, '.wsh', 'cert.pem'), '-noout', '-fingerprint', '-sha256']).toString().split('=')[1].trim();
    pinned = Uint8Array.from(fp.split(':').map((h) => parseInt(h, 16)));
    const client = new WshClient();
    const url = transport === 'wt' ? `https://127.0.0.1:${sport}` : `wss://127.0.0.1:${sport}`;
    await client.connect(url, { username: 'tester', keyPair: kp, transport });
    clients.push(client);
    return { client, logs: () => logs };
  }

  /** Read `flow` for `ms` and count what arrives. */
  function collect(flow) {
    const got = { count: 0, bytes: 0, sizes: [] };
    const r = flow.readable.getReader();
    void (async () => { for (;;) { const { value, done } = await r.read(); if (done) return; got.count += 1; got.bytes += value.length; got.sizes.push(value.length); } })().catch(() => {});
    return got;
  }

  it('negotiates gateway-datagram over WebTransport, and a flow round-trips as datagrams, not as GatewayData', async () => {
    const seen = []; const port = await echoServer((m) => seen.push(m.length));
    const { client } = await setup(port);
    assert.equal(client.hasFeature(GATEWAY_DATAGRAM_FEATURE), true, 'the host listed it');
    const flow = await client.openUdp('127.0.0.1', port);
    assert.equal(flow.transport, 'datagram');
    const got = collect(flow);
    for (let i = 0; i < 20; i++) { assert.equal(await flow.send(new Uint8Array(100).fill(i)), true); await sleep(10); }
    await until(() => got.count >= 18, 'the echoes', 5000);
    assert.equal(flow.stats.sentReliable, 0, 'nothing went on the control stream');
    assert.equal(flow.stats.receivedReliable, 0, 'nothing came back on it either');
    assert.ok(flow.stats.sent === 20 && flow.stats.received >= 18, JSON.stringify(flow.stats));
    assert.ok(seen.length >= 18 && seen.every((n) => n === 100), 'the origin got the payloads, header removed');
    flow.destroy();
  });

  it('reads the size limit from the transport: a payload that fits goes as a datagram, one that does not goes on the control stream, both ways', async () => {
    const port = await echoServer();
    const { client } = await setup(port);
    const flow = await client.openUdp('127.0.0.1', port);
    assert.ok(flow.maxDatagramSize > 500 && flow.maxDatagramSize < 1400, `maxDatagramSize ${flow.maxDatagramSize}`);
    const got = collect(flow);
    await flow.send(new Uint8Array(500).fill(1)); // fits
    await until(() => got.count === 1, 'the small echo');
    assert.equal(flow.stats.received, 1);
    await flow.send(new Uint8Array(5000).fill(2)); // does not: sent reliably, answered reliably (the default)
    await until(() => got.count === 2, 'the big echo');
    assert.deepEqual(got.sizes, [500, 5000]);
    assert.equal(flow.stats.sentReliable, 1);
    assert.equal(flow.stats.receivedReliable, 1);
    flow.destroy();
  });

  it('udp_oversize = "drop": a reply that does not fit one datagram is dropped, a small one still comes back', async () => {
    const seen = []; const port = await echoServer((m) => seen.push(m.length));
    const { client } = await setup(port, 'udp_oversize = "drop"\n');
    const flow = await client.openUdp('127.0.0.1', port);
    const got = collect(flow);
    await flow.send(new Uint8Array(5000).fill(2)); // on the control stream to the origin, which echoes it...
    await until(() => seen.includes(5000), 'the origin to get the big payload');
    await sleep(500);
    assert.equal(got.count, 0, '...but the reply does not fit and is dropped');
    await flow.send(new Uint8Array(100).fill(3));
    await until(() => got.count === 1, 'the small echo');
    assert.deepEqual(got.sizes, [100]);
    flow.destroy();
  });

  it('udp_datagrams = false keeps every flow on the control stream: the feature is not offered, and the flow works', async () => {
    const port = await echoServer();
    const { client } = await setup(port, 'udp_datagrams = false\n');
    assert.equal(client.hasFeature(GATEWAY_DATAGRAM_FEATURE), false);
    const flow = await client.openUdp('127.0.0.1', port);
    assert.equal(flow.transport, 'stream');
    const got = collect(flow);
    await flow.send(new Uint8Array(100).fill(1));
    await flow.send(new Uint8Array(5000).fill(2));
    await until(() => got.count === 2, 'both echoes');
    assert.deepEqual(got.sizes, [100, 5000]);
    assert.equal(flow.stats.sent, 0);
    assert.equal(flow.stats.sentReliable, 2);
    flow.destroy();
  });

  it('a client on WebSocket does not see the feature, and its flow is served over the control stream as before', async () => {
    const port = await echoServer();
    const { client } = await setup(port, '', 'ws');
    assert.equal(client.hasFeature(GATEWAY_DATAGRAM_FEATURE), false, 'a WebSocket server hello does not list it');
    const flow = await client.openUdp('127.0.0.1', port);
    assert.equal(flow.transport, 'stream');
    const got = collect(flow);
    await flow.send(new Uint8Array(300).fill(1));
    await until(() => got.count === 1, 'the echo');
    flow.destroy();
  });

  // What a token bucket guarantees whatever the scheduling: over T seconds it admits at most burst + rate * T datagrams, and each echoed one
  // costs two. A fast sender drains the burst before any answer is back, so a minimum is not asserted for a blast; "not limited" is asserted
  // with a sender paced well inside the rate.
  it('the UDP bounds of #145 apply to the datagram path: a blast over two flows is held to the client rate', async () => {
    let atOrigin = 0;
    const port = await echoServer(() => { atOrigin += 1; });
    const t0 = Date.now();
    const { client } = await setup(port, 'udp_packets_per_second_per_client = 20\n');
    const a = await client.openUdp('127.0.0.1', port);
    const b = await client.openUdp('127.0.0.1', port);
    assert.equal(a.transport, 'datagram');
    const ga = collect(a); const gb = collect(b);
    const payload = new Uint8Array(50).fill(9);
    for (let i = 0; i < 100; i++) { await Promise.all([a.send(payload), b.send(payload)]); }
    await sleep(1000);
    const burst = 32; // max(20 / 4, 32)
    const tokens = burst + 20 * ((Date.now() - t0) / 1000);
    // Toward the origin each datagram costs a token; an echo costs a second one on the way back.
    assert.ok(atOrigin <= tokens + 1, `${atOrigin} of 200 reached the origin, at most ${tokens + 1} allowed`);
    assert.ok(ga.count + gb.count <= tokens / 2 + 1, `${ga.count + gb.count} echoed of 200, at most ${tokens / 2 + 1}`);
    a.destroy(); b.destroy();
  });

  it('a paced sender inside the client rate is not limited on the datagram path', async () => {
    const port = await echoServer();
    const { client } = await setup(port, 'udp_packets_per_second_per_client = 20\n');
    const flow = await client.openUdp('127.0.0.1', port);
    assert.equal(flow.transport, 'datagram');
    const got = collect(flow);
    // 10 datagrams, 2 tokens each: 20 tokens against a burst of 32, so the bucket never runs dry whatever the refill
    for (let i = 0; i < 10; i++) { await flow.send(new Uint8Array(50).fill(1)); await sleep(60); }
    await until(() => got.count >= 9, 'the echoes', 5000);
    flow.destroy();
  });

  it('the amplification bound holds on datagrams: small queries, big answers', async () => {
    // an origin that answers every 10-byte query with 1000 bytes (fits a datagram): 200 queries ask for 200 kB
    const amp = dgram.createSocket('udp4'); socks.push(amp);
    await new Promise((r) => amp.bind(0, '127.0.0.1', r));
    amp.on('message', (_m, ri) => amp.send(Buffer.alloc(1000, 7), ri.port, ri.address));
    const port = amp.address().port;
    const t0 = Date.now();
    const { client } = await setup(port, 'udp_bytes_per_second_per_client = 20000\nudp_packets_per_second_per_client = 0\nudp_packets_per_second_per_flow = 0\n');
    const flow = await client.openUdp('127.0.0.1', port);
    assert.equal(flow.transport, 'datagram');
    const got = collect(flow);
    // one query while the burst is full: its answer passes, so the bound is seen to let traffic through
    await flow.send(new Uint8Array(10)); await until(() => got.count >= 1, 'the first answer');
    for (let i = 0; i < 199; i++) { await flow.send(new Uint8Array(10)); await sleep(5); }
    await sleep(500);
    const allowed = 65536 + 20000 * ((Date.now() - t0) / 1000); // burst max(5000, 65536) bytes, then 20000 a second; queries draw on it too
    assert.ok(got.bytes >= 1000 && got.bytes <= allowed, `${got.bytes} bytes of 200000 offered reached the client, at most ${allowed} allowed`);
    flow.destroy();
  });

  it('closing a flow ends it, and a datagram for a closed flow does no harm', async () => {
    const port = await echoServer();
    const { client } = await setup(port);
    const a = await client.openUdp('127.0.0.1', port);
    a.destroy();
    await a.closed;
    const b = await client.openUdp('127.0.0.1', port); // a fresh flow on the same connection still works
    const got = collect(b);
    await b.send(new Uint8Array(40).fill(4));
    await until(() => got.count === 1, 'the echo');
    b.destroy();
  });
});
