// test/rust/wsh-relay-multi-operator.test.mjs -- several operators per peer on the RUST relay (#93):
//
//   * the relay (`wsh-server --enable-relay`, `[relay] max_operators_per_peer`) with JS peers and JS operators: the opt-in a
//     peer states in ReverseAccept.features, replies addressed with RelayForward.to_fingerprint, ReverseClose when an operator
//     leaves, the cap, the busy reasons, the drops. The same scenarios `test/relay-multi-operator.test.mjs` runs against the JS relay.
//   * the Rust peer (`wsh reverse --max-operators`, `wsh agent run`) serving two JS operators at once through that relay.
//   * a relay left at its default (one operator per peer) behaves as before, and a released-style peer is held to one.
//
// Every binary runs with HOME in a scratch directory. Prerequisites: cargo build --release -p wsh-cli -p wsh-server
// (or WSH_BIN / WSH_SERVER_BIN).

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, cborEncode, MSG,
  reverseAccept, relayForward, sessionData,
} from '@johnhenry/wsh';
import { BUSY_PEER, BUSY_OPERATOR, busyPeerFull, MULTI_OPERATOR_FEATURE } from '../../src/server/relay.mjs';
import { freePort } from '../helpers/free-port.mjs'; // free for TCP and UDP: the server binds both (#248)

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = [];
const procs = [];
const closers = [];
const dec = new TextDecoder();

before(() => {
  assert.ok(existsSync(WSH_BIN), `expected the built wsh at ${WSH_BIN}`);
  assert.ok(existsSync(SERVER_BIN), `expected the built wsh-server at ${SERVER_BIN}`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the Rust relay's dev certificate is self-signed
});
after(() => {
  for (const p of procs.splice(0)) p.kill('SIGKILL');
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 10_000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); }
}
const cleanEnv = (home, extra = {}) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'tester', TERM: 'xterm', ...extra });

async function jsIdentity(name) {
  const keyPair = await generateKeyPair(true);
  const raw = await exportPublicKeyRaw(keyPair.publicKey);
  return { name, keyPair, raw, fp: await fingerprint(raw), ssh: `${await exportPublicKeySSH(keyPair.publicKey)} ${name}` };
}

async function rustIdentity(name) {
  const home = mkdtempSync(path.join(tmpdir(), `wsh-multi-${name}-`));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const ssh = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  const [, b64] = ssh.split(/\s+/);
  const wire = Buffer.from(b64, 'base64');
  const raw = new Uint8Array(wire.subarray(wire.length - 32));
  return { name, home, ssh, raw, fp: await fingerprint(raw) };
}

/** The Rust relay with `[relay] max_operators_per_peer = max` (the default when `max` is omitted). */
async function rustRelay(identities, { max } = {}) {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-multi-relay-'));
  scratch.push(home);
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${identities.map((i) => i.ssh).join('\n')}\n`);
  let config = '/dev/null/none';
  if (max !== undefined) {
    config = path.join(home, '.wsh', 'config.toml');
    writeFileSync(config, `[relay]\nmax_operators_per_peer = ${max}\n`);
  }
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--enable-relay', '--config', config], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  return { url: `wss://127.0.0.1:${port}`, port, logs: () => logs, cli: (h) => ({ target: `wss://localhost:${port}/`, env: cleanEnv(h, { SSL_CERT_FILE: path.join(home, '.wsh', 'cert.pem') }), args: ['-t', 'ws'] }) };
}

const login = async (relay, id) => {
  const c = new WshClient();
  await c.connect(relay.url, { username: id.name, keyPair: id.keyPair });
  closers.push(() => c.disconnect());
  return c;
};

/** A JS peer: accepts every operator, states `features`, records what it is sent. */
async function stockPeer(relay, host, { features } = {}) {
  const c = new WshClient();
  await c.connectReverse(relay.url, { username: 'host', keyPair: host.keyPair, expose: { exec: true } });
  const seen = [];
  c.addControlListener((m) => seen.push(m));
  c.onReverseConnect = async (req) => {
    c.trustRelayPeer(req.from_fingerprint);
    await c.sendRelayControl(reverseAccept({ targetFingerprint: host.fp, username: 'host', features }));
  };
  closers.push(() => c.disconnect());
  return { c, seen };
}

const toOperator = (op, text) => relayForward({ fromFingerprint: '', toFingerprint: op.fp, inner: cborEncode(sessionData({ channelId: 1, data: new TextEncoder().encode(text) })) });
const data = (n) => sessionData({ channelId: 1, data: new Uint8Array([n]) });

/** Wait until the relay lists the peer, as an operator sees it. */
const listed = (op) => until(async () => (await op.listPeers()).length, 'the peer in the list');

describe('Rust relay: several operators per peer (#93)', () => {
  it('advertises relay-multi-operator only when configured for more than one; e2e-sign either way', async () => {
    const [bob, host] = [await jsIdentity('bob'), await jsIdentity('host')];
    for (const [max, advertised] of [[undefined, false], [1, false], [3, true]]) {
      const relay = await rustRelay([bob, host], { max });
      const op = await login(relay, bob);
      assert.equal(op.hasFeature(MULTI_OPERATOR_FEATURE), advertised, `max=${max}`);
      assert.equal(op.hasFeature('e2e-sign'), true, 'the relay carries KeyExchange.signature');
      await op.disconnect();
    }
  });

  it('a relay configured with 0 or too many is refused at start', async () => {
    const home = mkdtempSync(path.join(tmpdir(), 'wsh-multi-badcfg-'));
    scratch.push(home);
    mkdirSync(path.join(home, '.wsh'));
    for (const bad of ['0', '1000']) {
      writeFileSync(path.join(home, '.wsh', 'config.toml'), `[relay]\nmax_operators_per_peer = ${bad}\n`);
      let failed = false;
      try { execFileSync(SERVER_BIN, ['--port', String(await freePort()), '--generate-cert', '--enable-relay', '--config', path.join(home, '.wsh', 'config.toml')], { env: cleanEnv(home), stdio: 'pipe', timeout: 5000 }); } catch (e) { failed = /max_operators_per_peer/.test(String(e.stderr) + String(e.stdout)); }
      assert.ok(failed, `${bad} is refused with a message naming the option`);
    }
  });

  describe('the default relay (one operator per peer)', () => {
    it('a peer that states multi-operator support still gets one operator; the second is told why', async () => {
      const [host, bob, dave] = await Promise.all(['host', 'bob', 'dave'].map(jsIdentity));
      const relay = await rustRelay([host, bob, dave]);
      await stockPeer(relay, host, { features: [MULTI_OPERATOR_FEATURE] });
      const b = await login(relay, bob);
      await listed(b);
      assert.equal((await b.reverseConnect(host.fp)).type, MSG.REVERSE_ACCEPT);
      const d = await login(relay, dave);
      const refused = await d.reverseConnect(host.fp);
      assert.equal(refused.type, MSG.REVERSE_REJECT);
      assert.equal(refused.reason, BUSY_PEER);
    });

    it('an operator leaving a single-operator peer frees it, and the peer stays connected (as before)', async () => {
      const [host, bob, dave] = await Promise.all(['host', 'bob', 'dave'].map(jsIdentity));
      const relay = await rustRelay([host, bob, dave]);
      const { c } = await stockPeer(relay, host);
      let closed = false;
      c.onClose = () => { closed = true; };
      const b = await login(relay, bob);
      await listed(b);
      await b.reverseConnect(host.fp);
      await b.disconnect();
      await sleep(300);
      assert.equal(closed, false);
      const d = await login(relay, dave);
      assert.equal((await d.reverseConnect(host.fp)).type, MSG.REVERSE_ACCEPT);
    });
  });

  describe('routing', () => {
    async function bridgeTwo(relay, ids, features = [MULTI_OPERATOR_FEATURE]) {
      const { host, bob, dave } = ids;
      const { c: peer, seen } = await stockPeer(relay, host, { features });
      const b = await login(relay, bob);
      const d = await login(relay, dave);
      await listed(b);
      assert.equal((await b.reverseConnect(host.fp)).type, MSG.REVERSE_ACCEPT);
      assert.equal((await d.reverseConnect(host.fp)).type, MSG.REVERSE_ACCEPT);
      const got = { bob: [], dave: [] };
      b.addControlListener((m) => got.bob.push(m));
      d.addControlListener((m) => got.dave.push(m));
      return { peer, seen, bob: b, dave: d, got };
    }
    const ids = async () => { const [host, bob, dave, erin] = await Promise.all(['host', 'bob', 'dave', 'erin'].map(jsIdentity)); return { host, bob, dave, erin, all: [host, bob, dave, erin] }; };

    it('a peer addresses a reply to one operator with to_fingerprint; only that operator gets it, from the peer', async () => {
      const i = await ids();
      const relay = await rustRelay(i.all, { max: 2 });
      const { peer, got, bob } = await bridgeTwo(relay, i);
      const from = [];
      bob.onRelayMessage = (msg, fromFingerprint) => from.push(fromFingerprint);
      await peer.sendRelayControl(toOperator(i.dave, 'for dave'));
      await until(() => got.dave.some((m) => m.type === MSG.SESSION_DATA), 'dave to receive it');
      await sleep(150);
      assert.deepEqual(got.bob.filter((m) => m.type === MSG.SESSION_DATA), [], 'bob did not');
      assert.equal(dec.decode(got.dave.find((m) => m.type === MSG.SESSION_DATA).data), 'for dave');
      // the peer claims to be dave and addresses bob: the relay stamps the peer
      await peer.sendRelayControl(relayForward({ fromFingerprint: i.dave.fp, toFingerprint: i.bob.fp, inner: cborEncode(data(1)) }));
      await until(() => from.length === 1, 'delivery to bob');
      assert.deepEqual(from, [i.host.fp]);
    });

    it('a forward to nobody, to a non-operator, or without an address while two are bridged is dropped, not guessed', async () => {
      const i = await ids();
      const relay = await rustRelay(i.all, { max: 2 });
      const { peer, got } = await bridgeTwo(relay, i);
      await peer.sendRelayControl(toOperator(i.erin, 'nobody'));
      await peer.sendRelayControl(relayForward({ fromFingerprint: '', inner: cborEncode(data(2)) }));
      await peer.sendRelayControl(data(3)); // a bare message: ambiguous with two operators
      await sleep(300);
      assert.deepEqual([...got.bob, ...got.dave].filter((m) => m.type === MSG.SESSION_DATA), []);
    });

    it('a forward wrapping something that is not forwardable, or garbage, is dropped (the relay checks the inner)', async () => {
      const i = await ids();
      const relay = await rustRelay(i.all, { max: 2 });
      const { peer, got } = await bridgeTwo(relay, i);
      // a ReverseList is a real message but not on the forwardable list; garbage bytes do not decode
      await peer.sendRelayControl(relayForward({ fromFingerprint: '', toFingerprint: i.bob.fp, inner: cborEncode({ type: MSG.REVERSE_LIST }) }));
      await peer.sendRelayControl(relayForward({ fromFingerprint: '', toFingerprint: i.bob.fp, inner: new Uint8Array([0xff, 0x00, 0x13]) }));
      await peer.sendRelayControl(toOperator(i.bob, 'still works'));
      await until(() => got.bob.some((m) => m.type === MSG.SESSION_DATA), 'bob to receive the valid one');
      assert.equal(got.bob.filter((m) => m.type !== undefined && m.type !== MSG.SESSION_DATA && m.type === MSG.REVERSE_LIST).length, 0);
      assert.equal(got.dave.filter((m) => m.type === MSG.SESSION_DATA).length, 0);
    });

    it('with a single operator an unaddressed reply still goes to it (every peer written before this)', async () => {
      const i = await ids();
      const relay = await rustRelay(i.all, { max: 2 });
      const { c: peer } = await stockPeer(relay, i.host, { features: [MULTI_OPERATOR_FEATURE] });
      const b = await login(relay, i.bob);
      await listed(b);
      await b.reverseConnect(i.host.fp);
      const got = [];
      b.addControlListener((m) => got.push(m));
      await peer.sendRelayControl(data(9));
      await peer.sendRelayControl(relayForward({ fromFingerprint: '', inner: cborEncode(data(8)) }));
      await until(() => got.filter((m) => m.type === MSG.SESSION_DATA).length === 2, 'both replies');
    });

    it('an operator reaches only its own peer: a plain message from an operator is relayed to its peer, wrapped with its key', async () => {
      const i = await ids();
      const relay = await rustRelay(i.all, { max: 2 });
      const { bob, peer } = await bridgeTwo(relay, i);
      const from = [];
      peer.onRelayMessage = (msg, fromFingerprint) => from.push([msg.type, fromFingerprint]);
      await bob.sendRelayControl(data(5));
      await until(() => from.length === 1, 'the peer to be sent it');
      assert.deepEqual(from, [[MSG.SESSION_DATA, i.bob.fp]], 'wrapped with the sender\'s authenticated key');
    });

    it('the operator cap applies with a reason that says so; a bridged operator connecting again is refused', async () => {
      const i = await ids();
      const relay = await rustRelay(i.all, { max: 2 });
      const { bob } = await bridgeTwo(relay, i);
      const e = await login(relay, i.erin);
      const refused = await e.reverseConnect(i.host.fp);
      assert.equal(refused.type, MSG.REVERSE_REJECT);
      assert.equal(refused.reason, busyPeerFull(2));
      assert.equal((await bob.reverseConnect(i.host.fp)).reason, BUSY_OPERATOR);
    });

    it('a peer that never stated support keeps one operator even on a multi-operator relay', async () => {
      const i = await ids();
      const relay = await rustRelay(i.all, { max: 3 });
      await stockPeer(relay, i.host); // no features: a peer written before this existed
      const b = await login(relay, i.bob);
      await listed(b);
      assert.equal((await b.reverseConnect(i.host.fp)).type, MSG.REVERSE_ACCEPT);
      const d = await login(relay, i.dave);
      assert.equal((await d.reverseConnect(i.host.fp)).reason, BUSY_PEER);
    });

    it('a peer answers one request at a time: a second connect while the first is pending is told to retry', async () => {
      const i = await ids();
      const relay = await rustRelay(i.all, { max: 2 });
      const peer = new WshClient();
      await peer.connectReverse(relay.url, { username: 'host', keyPair: i.host.keyPair, expose: { exec: true } });
      closers.push(() => peer.disconnect());
      const requests = [];
      peer.onReverseConnect = (req) => { requests.push(req.from_fingerprint); }; // never answers
      const b = await login(relay, i.bob);
      const d = await login(relay, i.dave);
      await listed(b);
      const first = b.reverseConnect(i.host.fp, 400).catch((e) => e);
      await until(() => requests.length === 1, 'the first request to reach the peer');
      const second = await d.reverseConnect(i.host.fp);
      assert.equal(second.type, MSG.REVERSE_REJECT);
      assert.match(second.reason, /^busy: /);
      assert.deepEqual(requests, [i.bob.fp]);
      await first;
    });
  });

  describe('a bridge ends: ReverseClose to the peer, the others carry on', () => {
    it('the peer is told which operator left, stays registered, keeps serving the other, and the slot is free again', async () => {
      const [host, bob, dave, erin] = await Promise.all(['host', 'bob', 'dave', 'erin'].map(jsIdentity));
      const relay = await rustRelay([host, bob, dave, erin], { max: 2 });
      const { c: peer, seen } = await stockPeer(relay, host, { features: [MULTI_OPERATOR_FEATURE] });
      const b = await login(relay, bob);
      const d = await login(relay, dave);
      await listed(b);
      await b.reverseConnect(host.fp);
      await d.reverseConnect(host.fp);
      await b.disconnect();
      const notice = await until(() => seen.find((m) => m.type === MSG.REVERSE_CLOSE), 'the ReverseClose notice');
      assert.equal(notice.target_fingerprint, bob.fp);
      await sleep(200);
      const got = [];
      d.addControlListener((m) => got.push(m));
      await peer.sendRelayControl(toOperator(dave, 'still here'));
      await until(() => got.some((m) => m.type === MSG.SESSION_DATA), 'dave still served');
      const e = await login(relay, erin);
      assert.equal((await e.reverseConnect(host.fp)).type, MSG.REVERSE_ACCEPT);
    });

    it('a peer that stated nothing is not sent a ReverseClose (a released peer would reject the message)', async () => {
      const [host, bob] = await Promise.all(['host', 'bob'].map(jsIdentity));
      const relay = await rustRelay([host, bob], { max: 2 });
      const { seen } = await stockPeer(relay, host);
      const b = await login(relay, bob);
      await listed(b);
      await b.reverseConnect(host.fp);
      await b.disconnect();
      await sleep(400);
      assert.equal(seen.some((m) => m.type === MSG.REVERSE_CLOSE), false);
    });
  });
});

// ── the Rust peer ──────────────────────────────────────────────────────

function spawnWsh(args, env) {
  const proc = spawn(WSH_BIN, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
  procs.push(proc);
  let out = ''; let err = '';
  proc.stdout.on('data', (d) => { out += d; });
  proc.stderr.on('data', (d) => { err += d; });
  proc.stdin.on('error', () => {});
  const done = new Promise((resolve) => proc.once('close', (code) => resolve(code)));
  closers.push(async () => { proc.kill('SIGKILL'); });
  return { proc, out: () => out, err: () => err, done };
}

/** A Rust reverse host (`wsh reverse`) on `relay`. */
async function rustHost(relay, host, flags = []) {
  const c = relay.cli(host.home);
  const p = spawnWsh([...c.args, ...flags, 'reverse', c.target], c.env);
  await until(() => /Registered as peer/.test(p.out()), `the Rust host to register (${p.err()})`);
  assert.match(p.out(), /Registered as peer/, p.err());
  return p;
}

/** The JS relay with `maxOperatorsPerPeer`. */
async function jsRelay(identities, maxOperatorsPerPeer) {
  const { createWshServer } = await import('@johnhenry/wsh/server');
  const server = createWshServer({ auth: { authorizedKeys: identities.map((i) => i.ssh).join('\n') }, relay: { canRegister: () => true, canConnect: () => true, maxOperatorsPerPeer } });
  const { port } = await server.listen();
  closers.push(() => server.close());
  return { url: `ws://127.0.0.1:${port}`, cli: (home) => ({ target: `ws://127.0.0.1:${port}/`, env: cleanEnv(home), args: ['-t', 'ws'] }) };
}

const run = async (client, command) => {
  const session = await client.openSession({ type: 'exec', command });
  return new Promise((resolve) => {
    const chunks = [];
    session.onData = (d) => chunks.push(d);
    session.onClose = () => resolve(dec.decode(Buffer.concat(chunks)).replaceAll('\r\n', '\n')); // the Rust host runs on a pty
  });
};
const gone = (pid) => { try { process.kill(pid, 0); return false; } catch { return true; } };

describe('the Rust host kills what an operator started when the channel closes', () => {
  // A bug found on the way (#93): the host's kill took the lock the waiting task holds for the whole life of the child,
  // so closing a channel (or an operator leaving) did not kill a running command, and blocked the host until it ended.
  it('a running command dies when the operator closes its channel, and the host keeps serving meanwhile', async () => {
    const [bob, host] = [await jsIdentity('bob'), await rustIdentity('host')];
    const relay = await rustRelay([bob, host]);
    await rustHost(relay, host);
    const b = await login(relay, bob);
    await until(async () => (await b.listPeers()).length, 'the host in the peer list');
    assert.equal((await b.reverseConnect(host.fp, 8000)).type, MSG.REVERSE_ACCEPT);
    const pids = [];
    const long = await b.openSession({ type: 'exec', command: 'echo $$; exec sleep 30' });
    long.onData = (x) => pids.push(Number(dec.decode(x).trim()));
    await until(() => pids.length === 1, 'the long-running command to start');
    long.close();
    await until(() => gone(pids[0]), 'the command to be killed', 5000);
    assert.equal(await run(b, 'echo still-serving'), 'still-serving\n');
  });
});

describe('the Rust peer serves several operators (#93)', () => {
  for (const relayKind of ['rust', 'js']) {
    const makeRelay = (ids) => (relayKind === 'rust' ? rustRelay(ids, { max: 2 }) : jsRelay(ids, 2));

    it(`through the ${relayKind} relay: two operators at once, each with its own sessions; the cap holds; a leaver's processes die and the other carries on`, async () => {
      const [bob, dave, erin, host] = [await jsIdentity('bob'), await jsIdentity('dave'), await jsIdentity('erin'), await rustIdentity('host')];
      const relay = await makeRelay([bob, dave, erin, host]);
      const h = await rustHost(relay, host, ['--max-operators', '2']);
      const b = await login(relay, bob);
      const d = await login(relay, dave);
      await until(async () => (await b.listPeers()).length, 'the host in the peer list');
      const accepted = await b.reverseConnect(host.fp, 8000);
      assert.equal(accepted.type, MSG.REVERSE_ACCEPT, accepted.reason);
      assert.ok(accepted.features?.includes(MULTI_OPERATOR_FEATURE), 'the host states relay-multi-operator');
      assert.equal((await d.reverseConnect(host.fp, 8000)).type, MSG.REVERSE_ACCEPT);

      // channel ids are each operator's own: both open channel 1, and neither hears the other
      const [outB, outD] = await Promise.all([run(b, 'echo from-bob; sleep 0.3; echo bob-done'), run(d, 'echo from-dave; sleep 0.3; echo dave-done')]);
      assert.equal(outB, 'from-bob\nbob-done\n');
      assert.equal(outD, 'from-dave\ndave-done\n');

      const e = await login(relay, erin);
      const refused = await e.reverseConnect(host.fp, 8000);
      assert.equal(refused.type, MSG.REVERSE_REJECT);
      assert.match(refused.reason, /^busy: /);

      // bob starts something long and leaves: it is killed; dave is untouched; bob's slot is free
      const pids = [];
      const long = await b.openSession({ type: 'exec', command: 'echo $$; exec sleep 30' });
      long.onData = (x) => pids.push(Number(dec.decode(x).trim()));
      await until(() => pids.length === 1, 'the long-running command to start');
      await b.disconnect();
      await until(() => gone(pids[0]), "bob's process to be killed when he left");
      assert.equal(await run(d, 'echo dave-still-here'), 'dave-still-here\n');
      assert.equal((await e.reverseConnect(host.fp, 8000)).type, MSG.REVERSE_ACCEPT);
      assert.equal(await run(e, 'echo erin-here'), 'erin-here\n');
      assert.equal(h.proc.exitCode, null, 'the host is still running');
    });
  }

  it('a host given --max-operators on a relay that does not advertise it serves one operator, and states nothing new', async () => {
    const [bob, dave, host] = [await jsIdentity('bob'), await jsIdentity('dave'), await rustIdentity('host')];
    const relay = await rustRelay([bob, dave, host]); // [relay] max_operators_per_peer left at 1
    await rustHost(relay, host, ['--max-operators', '4']);
    const b = await login(relay, bob);
    const d = await login(relay, dave);
    await until(async () => (await b.listPeers()).length, 'the host in the peer list');
    const accepted = await b.reverseConnect(host.fp, 8000);
    assert.equal(accepted.type, MSG.REVERSE_ACCEPT, accepted.reason);
    assert.ok(!accepted.features?.includes(MULTI_OPERATOR_FEATURE), 'the accept is the one a host without the flag sends');
    assert.equal(await run(b, 'echo single'), 'single\n');
    const refused = await d.reverseConnect(host.fp, 8000);
    assert.equal(refused.reason, BUSY_PEER);
  });

  it('a host started without the flag is held to one operator on a multi-operator relay (released hosts: nothing changes)', async () => {
    const [bob, dave, host] = [await jsIdentity('bob'), await jsIdentity('dave'), await rustIdentity('host')];
    const relay = await rustRelay([bob, dave, host], { max: 3 });
    await rustHost(relay, host);
    const b = await login(relay, bob);
    const d = await login(relay, dave);
    await until(async () => (await b.listPeers()).length, 'the host in the peer list');
    const accepted = await b.reverseConnect(host.fp, 8000);
    assert.equal(accepted.type, MSG.REVERSE_ACCEPT, accepted.reason);
    assert.ok(!accepted.features?.includes(MULTI_OPERATOR_FEATURE));
    assert.equal(await run(b, 'echo one'), 'one\n');
    assert.equal((await d.reverseConnect(host.fp, 8000)).reason, BUSY_PEER);
  });

  it('--max-operators with --require-operator-proof is refused at start, and a bad count too', async () => {
    const host = await rustIdentity('host');
    const relay = await rustRelay([host], { max: 2 });
    const c = relay.cli(host.home);
    const p = spawnWsh([...c.args, '--max-operators', '2', '--require-operator-proof', 'reverse', c.target], c.env);
    assert.notEqual(await p.done, 0);
    assert.match(p.err(), /--max-operators above 1 cannot be combined with --require-operator-proof/);
    const q = spawnWsh([...c.args, '--max-operators', '0', 'reverse', c.target], c.env);
    assert.notEqual(await q.done, 0);
    assert.match(q.err(), /max-operators/);
  });

  it('wsh agent run takes the same flag and serves two operators at once, and two more once they have left', async () => {
    const [bob, dave, host] = [await jsIdentity('bob'), await jsIdentity('dave'), await rustIdentity('host')];
    const relay = await rustRelay([bob, dave, host], { max: 2 });
    const c = relay.cli(host.home);
    const agent = spawnWsh([...c.args, '--max-operators', '2', 'agent', 'run', '--reconnect-delay-secs', '1', c.target], c.env);
    const b = await login(relay, bob);
    const d = await login(relay, dave);
    await until(async () => (await b.listPeers()).length, `the agent in the peer list (${agent.out()} ${agent.err()})`);
    assert.equal((await b.reverseConnect(host.fp, 8000)).type, MSG.REVERSE_ACCEPT);
    assert.equal((await d.reverseConnect(host.fp, 8000)).type, MSG.REVERSE_ACCEPT);
    const [outB, outD] = await Promise.all([run(b, 'echo agent-bob'), run(d, 'echo agent-dave')]);
    assert.equal(outB, 'agent-bob\n');
    assert.equal(outD, 'agent-dave\n');
    // both leave: the agent is told (ReverseClose) and stays registered, with both slots free
    await b.disconnect();
    await d.disconnect();
    const b2 = await login(relay, bob);
    const d2 = await login(relay, dave);
    await until(async () => (await b2.listPeers()).length, 'the agent to still be in the peer list');
    await sleep(300);
    assert.equal((await b2.reverseConnect(host.fp, 8000)).type, MSG.REVERSE_ACCEPT);
    assert.equal((await d2.reverseConnect(host.fp, 8000)).type, MSG.REVERSE_ACCEPT);
    assert.equal(await run(d2, 'echo again'), 'again\n');
  });

  it('with several operators --allow-operator still decides who is served', async () => {
    const [bob, dave, host] = [await jsIdentity('bob'), await jsIdentity('dave'), await rustIdentity('host')];
    const relay = await rustRelay([bob, dave, host], { max: 2 });
    await rustHost(relay, host, ['--max-operators', '2', '--allow-operator', bob.fp.slice(0, 16)]);
    const b = await login(relay, bob);
    const d = await login(relay, dave);
    await until(async () => (await b.listPeers()).length, 'the host in the peer list');
    const refused = await d.reverseConnect(host.fp, 8000);
    assert.equal(refused.type, MSG.REVERSE_REJECT);
    assert.match(refused.reason, /operator not allowed/);
    assert.equal((await b.reverseConnect(host.fp, 8000)).type, MSG.REVERSE_ACCEPT);
    assert.equal(await run(b, 'echo bob'), 'bob\n');
  });
});
