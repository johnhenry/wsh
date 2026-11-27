// test/rust/wsh-relay-gateway-per-operator.test.mjs -- #296: the Rust CLI reverse host grants its gateway PER OPERATOR.
//
// `--relay-gateway-allow FINGERPRINT=RULE` is that operator's rule only; a rule without `FINGERPRINT=` is every allowed operator's (what
// it always was); `--relay-gateway-udp-for` / `-dns-for` / `-listen-for` scope the three switches the same way. An operator that no rule
// reaches gets nothing (its requests are refused with a sentence). Three operators are served at once (`--max-operators 3` behind the
// Rust relay, which allows three per peer), each of which is asked to reach its own origin, another's and nobody's.
//
// Every `wsh` and `wsh-server` runs with HOME, USERPROFILE and XDG_CONFIG_HOME in a scratch directory.
// Prerequisite: `cargo build -p wsh-cli -p wsh-server` (or --release), then WSH_BIN and WSH_SERVER_BIN if not in target/release.

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync, spawnSync } from 'node:child_process';
import net from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG } from '@johnhenry/wsh';
import { listeningPort } from './helpers/listening.mjs'; // the server binds port 0 and prints the port it got (#320)

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 10_000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
const cleanEnv = (home, extra = {}) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm', ...extra });
const dec = new TextDecoder();

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = []; const procs = []; const closers = [];
before(() => {
  assert.ok(existsSync(WSH_BIN), `expected the built wsh binary at ${WSH_BIN}`);
  assert.ok(existsSync(SERVER_BIN), `expected the built wsh-server binary at ${SERVER_BIN}`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
});
after(() => {
  for (const p of procs.splice(0)) p.kill('SIGKILL');
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const scratchHome = () => { const d = mkdtempSync(path.join(tmpdir(), 'wsh-pergw-')); scratch.push(d); return d; };

async function hostIdentity() {
  const home = scratchHome();
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const pub = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  const wire = Buffer.from(pub.split(/\s+/)[1], 'base64');
  return { home, pub, fp: await fingerprint(new Uint8Array(wire.subarray(wire.length - 32))) };
}

async function rustRelay(authorizedKeys, maxOperators) {
  const home = scratchHome();
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${authorizedKeys}\n`);
  const configPath = path.join(home, 'wsh-server.toml');
  writeFileSync(configPath, `[relay]\nmax_operators_per_peer = ${maxOperators}\n`);
  const proc = spawn(SERVER_BIN, ['--port', '0', '--generate-cert', '--enable-relay', '--config', configPath], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  const port = await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; const p = listeningPort(logs); if (p) resolve(p); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  return { url: `wss://127.0.0.1:${port}`, target: `wss://localhost:${port}/`, certFile: path.join(home, '.wsh', 'cert.pem') };
}

/** An origin answering `<tag>:<what it got>`. */
async function origin(tag) {
  const sockets = [];
  const server = net.createServer((s) => { sockets.push(s); s.on('data', (d) => s.write(Buffer.concat([Buffer.from(`${tag}:`), d]))); s.on('error', () => {}); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  closers.push(async () => { for (const s of sockets) s.destroy(); server.close(); });
  return { port: server.address().port, sockets };
}

async function roundTrip(d, text) {
  const writer = d.writable.getWriter();
  await writer.write(new TextEncoder().encode(text));
  const { value } = await d.readable.getReader().read();
  d.destroy();
  return dec.decode(value);
}

/** A relay, a Rust host with `hostArgs(fp)` (the operators' fingerprints) and three operators, connected. */
async function setup(hostArgs) {
  const host = await hostIdentity();
  const ops = {};
  for (const name of ['a', 'b', 'c']) {
    const keyPair = await generateKeyPair(true);
    ops[name] = { keyPair, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)), line: `${await exportPublicKeySSH(keyPair.publicKey)} ${name}` };
  }
  const relay = await rustRelay(`${host.pub}\n${Object.values(ops).map((o) => o.line).join('\n')}`, 3);
  const extra = hostArgs(Object.fromEntries(Object.entries(ops).map(([n, o]) => [n, o.fp])));
  const proc = spawn(WSH_BIN, ['-t', 'ws', '--accept-new-host-key', '--max-operators', '3', '--relay-gateway-trust-relay', ...extra, 'reverse', relay.target, '--capability', 'exec', '--capability', 'gateway'],
    { env: cleanEnv(host.home, { SSL_CERT_FILE: relay.certFile }), stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(proc);
  let out = ''; let err = '';
  proc.stdout.on('data', (d) => { out += d; }); proc.stderr.on('data', (d) => { err += d; });
  proc.stdin.on('error', () => {});
  await until(() => /Registered as peer/.test(out) || /error|failed/i.test(err), `the host to register (${err})`);
  assert.match(out, /Registered as peer/, err);
  const clients = {}; const accepts = {};
  for (const [name, o] of Object.entries(ops)) {
    const c = new WshClient();
    await c.connect(relay.url, { username: name, keyPair: o.keyPair });
    closers.push(() => c.disconnect());
    await until(async () => (await c.listPeers()).length, 'the host in the peer list');
    const res = await c.reverseConnect(host.fp);
    assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
    clients[name] = c;
    accepts[name] = res;
  }
  return { ops, clients, accepts, logs: () => `${out}${err}` };
}

const refused = (p, re) => assert.rejects(p, (e) => e.code === 4 && re.test(e.message), `expected a policy refusal matching ${re}`);

describe('the Rust CLI reverse host grants its gateway per operator (#296)', () => {
  it('operator A reaches what its rules name and not B\'s; an operator with no rule gets nothing', async () => {
    const oa = await origin('A'); const ob = await origin('B');
    const { clients } = await setup((fp) => [
      '--allow-operator', fp.a, '--allow-operator', fp.b, '--allow-operator', fp.c,
      '--relay-gateway-allow', `${fp.a.slice(0, 12)}=127.0.0.1:${oa.port}`,
      '--relay-gateway-allow', `${fp.b.slice(0, 12)}=127.0.0.1:${ob.port}`,
    ]);
    assert.equal(await roundTrip(await clients.a.openTcp('127.0.0.1', oa.port), 'x'), 'A:x');
    assert.equal(await roundTrip(await clients.b.openTcp('127.0.0.1', ob.port), 'y'), 'B:y');
    await refused(clients.a.openTcp('127.0.0.1', ob.port), /not allowed/);
    await refused(clients.b.openTcp('127.0.0.1', oa.port), /not allowed/);
    // no rule reaches C: its requests are refused with a sentence that says so, and nothing is dialled
    await refused(clients.c.openTcp('127.0.0.1', oa.port), /no gateway rule for this operator/);
    await refused(clients.c.openTcp('127.0.0.1', ob.port), /no gateway rule for this operator/);
    assert.equal(oa.sockets.length, 1);
    assert.equal(ob.sockets.length, 1);
  });

  it('gateway-lossless-close is negotiated per operator: an operator with a rule gets it (each acknowledged), and its vanished origin releases only its own connection (#286)', async () => {
    const gone = { a: [], b: [] };
    const mk = async (tag) => {
      const s = net.createServer((x) => { x.on('error', () => {}); gone[tag].push(x); x.end('bye'); });
      await new Promise((r) => s.listen(0, '127.0.0.1', r));
      closers.push(async () => { s.close(); for (const x of gone[tag]) x.destroy(); });
      return s.address().port;
    };
    const pa = await mk('a'); const pb = await mk('b');
    const { clients, accepts } = await setup((fp) => [
      '--allow-operator', fp.a, '--allow-operator', fp.b, '--allow-operator', fp.c,
      '--relay-gateway-allow', `${fp.a.slice(0, 12)}=127.0.0.1:${pa}`,
      '--relay-gateway-allow', `${fp.b.slice(0, 12)}=127.0.0.1:${pb}`,
    ]);
    for (const n of ['a', 'b', 'c']) assert.ok(accepts[n].features.includes('gateway-lossless-close-ack'), `${n}: ${accepts[n].features}`);
    const va = await clients.a.openTcp('127.0.0.1', pa); const vb = await clients.b.openTcp('127.0.0.1', pb);
    assert.ok(va.releasable && vb.releasable && !va.lossless && !vb.lossless, 'unsealed: negotiated, best-effort (#318)');
    for (const v of [va, vb]) { const r = v.readable.getReader(); for (;;) { const { done } = await r.read(); if (done) break; } }
    await until(() => gone.a.length === 1 && gone.b.length === 1, 'both origins to have been dialled');
    gone.a[0].resetAndDestroy();
    assert.equal(await Promise.race([va.closed, sleep(20_000).then(() => 'open')]), 'released');
    assert.equal(await Promise.race([vb.closed, sleep(400).then(() => 'open')]), 'open', 'B\'s origin is alive: B\'s connection is untouched');
  });

  it('an unscoped rule is still every allowed operator\'s, and a scoped one adds to it for one operator', async () => {
    const shared = await origin('S'); const oa = await origin('A');
    const { clients } = await setup((fp) => [
      '--allow-operator', fp.a, '--allow-operator', fp.b, '--allow-operator', fp.c,
      '--relay-gateway-allow', `127.0.0.1:${shared.port}`,
      '--relay-gateway-allow', `${fp.a.slice(0, 12)}=127.0.0.1:${oa.port}`,
    ]);
    for (const c of Object.values(clients)) assert.equal(await roundTrip(await c.openTcp('127.0.0.1', shared.port), 'z'), 'S:z');
    assert.equal(await roundTrip(await clients.a.openTcp('127.0.0.1', oa.port), 'x'), 'A:x');
    await refused(clients.b.openTcp('127.0.0.1', oa.port), /not allowed/);
    await refused(clients.c.openTcp('127.0.0.1', oa.port), /not allowed/);
  });

  it('a switch scoped to one operator is that operator\'s: UDP for A, not for B', async () => {
    const { clients } = await setup((fp) => [
      '--allow-operator', fp.a, '--allow-operator', fp.b, '--allow-operator', fp.c,
      '--relay-gateway-allow', '127.0.0.1', '--relay-gateway-udp-for', fp.a.slice(0, 12),
    ]);
    // A may open a UDP flow (the origin need not answer: opening is what is permitted), B is refused by the host's switch
    const flow = await clients.a.openUdp('127.0.0.1', 9);
    assert.ok(flow);
    flow.destroy?.();
    await refused(clients.b.openUdp('127.0.0.1', 9), /UDP is not enabled/);
  });
});

describe('what the command line refuses', () => {
  const run = (args) => {
    const home = scratchHome();
    execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
    const r = spawnSync(WSH_BIN, ['-t', 'ws', ...args, 'reverse', 'ws://127.0.0.1:1/', '--capability', 'gateway'], { env: cleanEnv(home), encoding: 'utf8', timeout: 15_000 });
    return { code: r.status, text: `${r.stdout}${r.stderr}` };
  };
  const base = ['--relay-gateway-trust-relay', '--allow-operator', 'aaaaaaaa11112222'];
  it('a scope that no --allow-operator covers, a scope that is not a fingerprint, a rule without a scope target, and a switch no rule reaches', () => {
    for (const [args, re] of [
      [[...base, '--relay-gateway-allow', 'cccccccc=x.example.com'], /not covered by any --allow-operator/],
      [[...base, '--relay-gateway-allow', 'zzzzzzzz=x.example.com'], /not an operator/],
      [[...base, '--relay-gateway-allow', 'aaaaaaaa='], /no rule after the/],
      [[...base, '--relay-gateway-allow', 'aaaaaaaa=x.example.com', '--relay-gateway-udp-for', 'bbbbbbbb'], /not covered|no --relay-gateway-allow rule/],
    ]) {
      const r = run(args);
      assert.notEqual(r.code, 0, args.join(' '));
      assert.match(r.text, re, args.join(' '));
    }
  });
});
