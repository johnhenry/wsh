// test/rust/wsh-reverse-proof.test.mjs -- operator proof in reverse mode with Rust on one end (#145 step 4, #117):
//
//   JS operator  -> Rust host (`wsh reverse`)          through the JS relay and through the Rust relay (`wsh-server --enable-relay`)
//   Rust operator (`wsh reverse-connect`) -> JS host   Node (`@johnhenry/wsh/server`) and browser-safe (`@johnhenry/wsh/reverse`),
//                                                      through both relays
//   a hostile hop in front of a Rust host that REQUIRES proof: a rewritten from_fingerprint, a replayed proof, a swapped key.
//
// The Rust host's accept policy is `--require-operator-proof` and `--allow-operator <fingerprint>`; "proven" is what the
// operator signed, not what the relay stamped. Every binary runs with HOME in a scratch directory.
// Prerequisites: cargo build --release -p wsh-cli -p wsh-server (or WSH_BIN / WSH_SERVER_BIN).

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { createReverseHost as createBrowserSafeReverseHost } from '@johnhenry/wsh/reverse';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG } from '@johnhenry/wsh';
import { hostileRelay } from '../helpers/hostile-relay.mjs';
import { listeningPort } from './helpers/listening.mjs'; // the server binds port 0 and prints the port it got (#320)
import { createOperatorProof } from '../../src/operator-proof.mjs';
import { resolveSigner } from '../../src/auth.mjs';
import { reverseProof } from '../../src/messages.gen.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
const scratch = [];
const procs = [];
const closers = [];

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
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/** A JS identity: key pair, SSH line, raw key and fingerprint. */
async function jsIdentity(name) {
  const keyPair = await generateKeyPair(true);
  const raw = await exportPublicKeyRaw(keyPair.publicKey);
  return { name, keyPair, raw, fp: await fingerprint(raw), ssh: `${await exportPublicKeySSH(keyPair.publicKey)} ${name}` };
}

/** A scratch HOME holding a Rust `wsh` identity. */
async function rustIdentity(name) {
  const home = mkdtempSync(path.join(tmpdir(), `wsh-proof-${name}-`));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  const ssh = readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim();
  const [, b64] = ssh.split(/\s+/);
  const wire = Buffer.from(b64, 'base64');
  const raw = new Uint8Array(wire.subarray(wire.length - 32));
  return { name, home, ssh, raw, fp: await fingerprint(raw) };
}

/** The JS relay (`createWshServer({ relay })`). `keys`: every identity's SSH line. */
async function jsRelay(identities) {
  const server = createWshServer({ auth: { authorizedKeys: identities.map((i) => i.ssh).join('\n') }, relay: { canRegister: () => true, canConnect: () => true, connectTimeoutMs: 8000 } });
  const { port } = await server.listen();
  closers.push(() => server.close());
  return { kind: 'js', url: `ws://127.0.0.1:${port}`, cli: (home) => ({ target: `ws://127.0.0.1:${port}/`, env: cleanEnv(home), args: ['-t', 'ws'] }) };
}

/** The Rust relay (`wsh-server --enable-relay`). */
async function rustRelay(identities) {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-proof-relay-'));
  scratch.push(home);
  mkdirSync(path.join(home, '.wsh'));
  writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${identities.map((i) => i.ssh).join('\n')}\n`);
  const proc = spawn(SERVER_BIN, ['--port', '0', '--generate-cert', '--enable-relay', '--config', '/dev/null/none'], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  const port = await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; const p = listeningPort(logs); if (p) resolve(p); };
    proc.stdout.on('data', onData); proc.stderr.on('data', onData);
    proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
    setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
  });
  const certFile = path.join(home, '.wsh', 'cert.pem');
  return { kind: 'rust', url: `wss://127.0.0.1:${port}`, cli: (h) => ({ target: `wss://localhost:${port}/`, env: cleanEnv(h, { SSL_CERT_FILE: certFile }), args: ['-t', 'ws'] }) };
}

/** Spawn a `wsh` process; resolves with handles. */
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

/** A Rust reverse host (`wsh reverse`) on `relay` (or the URL `via`, e.g. a hostile hop). */
async function rustHost(relay, host, { flags = [], via } = {}) {
  const c = relay.cli(host.home);
  const target = via ?? c.target;
  const p = spawnWsh([...c.args, ...flags, 'reverse', target], c.env);
  await until(() => /Registered as peer/.test(p.out()) || (p.err() && /error|failed/i.test(p.err()) && p.err()), `the Rust host to register (${p.err()})`);
  assert.match(p.out(), /Registered as peer/, p.err());
  return p;
}

const login = async (relay, id) => {
  const c = new WshClient();
  await c.connect(relay.url, { username: id.name, keyPair: id.keyPair });
  closers.push(() => c.disconnect());
  return c;
};

for (const relayKind of ['js', 'rust']) {
  const makeRelay = relayKind === 'js' ? jsRelay : rustRelay;

  describe(`JS operator -> Rust host, through the ${relayKind} relay`, () => {
    it('a host that requires proof serves the proven allowed operator; a stranger, and an operator that does not prove, are refused', async () => {
      const [bob, mallory, host] = [await jsIdentity('bob'), await jsIdentity('mallory'), await rustIdentity('host')];
      const relay = await makeRelay([bob, mallory, host]);
      const h = await rustHost(relay, host, { flags: ['--require-operator-proof', '--allow-operator', bob.fp.slice(0, 16)] });

      const op = await login(relay, bob);
      const peers = await until(async () => { const p = await op.listPeers(); return p.length ? p : null; }, 'the host in the peer list');
      assert.ok(peers[0].capabilities.includes('operator-proof'), 'a host that can challenge says so, so operators know to prove');
      const res = await op.reverseConnect(host.fp);
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      await op.disconnect();
      h.proc.kill('SIGKILL');

      // A second host run for the refusals (a host serves one bridge, then its relay connection ends).
      const h2 = await rustHost(relay, host, { flags: ['--require-operator-proof', '--allow-operator', bob.fp.slice(0, 16)] });
      const stranger = await login(relay, mallory);
      await until(async () => (await stranger.listPeers()).length, 'the host in the peer list');
      const refused = await stranger.reverseConnect(host.fp, 6000);
      assert.equal(refused.type, MSG.REVERSE_REJECT);
      assert.match(refused.reason, /operator not allowed/, 'proven, and not on the list');
      const unproven = await stranger.reverseConnect(host.fp, 6000, { proof: false });
      assert.equal(unproven.type, MSG.REVERSE_REJECT);
      assert.match(unproven.reason, /operator proof required/);
      h2.proc.kill('SIGKILL');
    });

    it('a host that does not require proof still proves the operator when it offers, and serves one that does not offer (released operators)', async () => {
      const [bob, host] = [await jsIdentity('bob'), await rustIdentity('host')];
      const relay = await makeRelay([bob, host]);
      await rustHost(relay, host);
      const op = await login(relay, bob);
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const plain = await op.reverseConnect(host.fp, 6000, { proof: false });
      assert.equal(plain.type, MSG.REVERSE_ACCEPT, plain.reason);
    });
  });

  describe(`Rust operator -> JS host, through the ${relayKind} relay`, () => {
    for (const [label, factory] of [['Node host (@johnhenry/wsh/server)', createReverseHost], ['browser-safe host (@johnhenry/wsh/reverse)', createBrowserSafeReverseHost]]) {
      it(`${label}: the host verifies the Rust operator's proof before accept runs and hears its key`, async () => {
        const [host, op] = [await jsIdentity('host'), await rustIdentity('op')];
        const relay = await makeRelay([host, { ssh: op.ssh }]);
        const accepted = [];
        const reverse = factory({
          url: relay.url, username: 'host', keyPair: host.keyPair, exec: async (c, io) => { io.write(`ran:${c}\n`); return 0; }, reconnect: false, proofTimeoutMs: 3000,
          accept: (who) => { accepted.push(who); return true; },
        });
        await reverse.start();
        closers.push(() => reverse.close());
        await sleep(300);
        const c = relay.cli(op.home);
        const p = spawnWsh([...c.args, '--operator-proof', 'reverse-connect', host.fp.slice(0, 12), c.target], c.env);
        await until(() => accepted.length || p.err(), `the host to see the operator (${p.err()})`);
        assert.equal(accepted.length, 1, p.err());
        assert.equal(accepted[0].proven, true, 'the operator proved its key');
        assert.equal(accepted[0].fingerprint, op.fp);
        assert.ok(same(accepted[0].publicKey, op.raw));
        await until(() => /Peer accepted/.test(p.out()), `the CLI to report acceptance (${p.out()} ${p.err()})`);
        p.proc.kill('SIGKILL');
      });
    }

    it('--no-operator-proof is a plain operator: the host serves it and says it was not proven', async () => {
      const [host, op] = [await jsIdentity('host'), await rustIdentity('op')];
      const relay = await makeRelay([host, { ssh: op.ssh }]);
      const accepted = [];
      const reverse = createReverseHost({ url: relay.url, username: 'host', keyPair: host.keyPair, exec: true, reconnect: false, accept: (who) => { accepted.push(who); return true; } });
      await reverse.start();
      closers.push(() => reverse.close());
      await sleep(300);
      const c = relay.cli(op.home);
      const p = spawnWsh([...c.args, '--no-operator-proof', 'reverse-connect', host.fp.slice(0, 12), c.target], c.env);
      await until(() => accepted.length || p.err(), `the host to see the operator (${p.err()})`);
      assert.equal(accepted[0].proven, false);
      p.proc.kill('SIGKILL');
    });
  });
}

describe('a hostile relay in front of a Rust host that requires operator proof', () => {
  const requireFor = (bob) => ['--require-operator-proof', '--allow-operator', bob.fp.slice(0, 16)];

  async function world({ hop }) {
    const [bob, mallory, host] = [await jsIdentity('bob'), await jsIdentity('mallory'), await rustIdentity('host')];
    const relay = await jsRelay([bob, mallory, host]);
    const mitm = await hostileRelay(relay.url, hop);
    closers.push(() => mitm.close());
    const proc = await rustHost(relay, host, { flags: requireFor(bob), via: `${mitm.url}/` });
    return { bob, mallory, host, relay, mitm, proc };
  }

  it('a malicious operator that signs the challenge anyway is caught by the host: its key is not the one the relay named', async () => {
    let bobFp = null;
    let hostConn = null;
    const signerId = await jsIdentity('mallory-signer');
    const w = await world({
      hop: {
        toClient: (m, ctx) => { hostConn = ctx; return m.type === MSG.REVERSE_CONNECT && bobFp ? { ...m, from_fingerprint: bobFp } : m; },
        // The hop plays the malicious operator: it answers the challenge addressed to "bob" with another key.
        toRelay: async (m) => {
          if (m.type === MSG.REVERSE_CHALLENGE) {
            const f = await createOperatorProof(await resolveSigner({ keyPair: signerId.keyPair }), { peerPublicKey: m.public_key, nonce: m.nonce, sessionId: m.session_id }, 'mallory');
            await hostConn.injectToClient(reverseProof({ targetFingerprint: m.target_fingerprint, ...f }));
          }
          return m;
        },
      },
    });
    bobFp = w.bob.fp;
    const op = await login(w.relay, w.mallory);
    await until(async () => (await op.listPeers()).length, 'the host in the peer list');
    const res = await op.reverseConnect(w.host.fp, 9000).catch((e) => e);
    assert.ok(res instanceof Error || res.type === MSG.REVERSE_REJECT, 'the connect did not succeed');
    await until(() => /another key than the relay asserted/.test(w.proc.err()), `the host to name the mismatch: ${w.proc.err()}`);
  });

  it('rewrites from_fingerprint to the allowed operator: the real operator will not answer a challenge that names someone else, and the host never accepts', async () => {
    let bobFp = null;
    const w = await world({ hop: { toClient: (m) => (m.type === MSG.REVERSE_CONNECT && bobFp ? { ...m, from_fingerprint: bobFp } : m) } });
    bobFp = w.bob.fp;
    const mallory = await login(w.relay, w.mallory);
    await until(async () => (await mallory.listPeers()).length, 'the host in the peer list');
    const res = await mallory.reverseConnect(w.host.fp, 9000).catch((e) => e);
    assert.ok(res instanceof Error, 'the operator refused to answer');
    assert.match(res.message, /different operator fingerprint|relay rewrote/);
  });

  it('a proof replayed from an earlier request is not the proof for this challenge: the host refuses', async () => {
    let recorded = null;
    let replay = false;
    const w = await world({
      hop: {
        toClient: (m) => {
          if (m.type !== MSG.REVERSE_PROOF) return m;
          if (!replay) { recorded = m; return m; }
          return recorded;
        },
      },
    });
    const bob = await login(w.relay, w.bob);
    await until(async () => (await bob.listPeers()).length, 'the host in the peer list');
    const first = await bob.reverseConnect(w.host.fp, 6000);
    assert.equal(first.type, MSG.REVERSE_ACCEPT, 'the genuine proof is accepted');
    assert.ok(recorded, 'the proof crossed the hostile hop');
    await bob.disconnect();
    // The host's relay connection ended with the bridge; bring one up again, behind the same hop, and replay.
    replay = true;
    await rustHost(w.relay, w.host, { flags: requireFor(w.bob), via: `${w.mitm.url}/` });
    const again = await login(w.relay, w.bob);
    await until(async () => (await again.listPeers()).length, 'the host in the peer list');
    const res = await again.reverseConnect(w.host.fp, 9000).catch((e) => e);
    assert.ok(res instanceof Error || res.type === MSG.REVERSE_REJECT, 'a replayed proof is not accepted');
  });

  it('a proof whose public key was swapped for the relay\'s own choice does not verify: the host refuses', async () => {
    let malloryRaw = null;
    const w = await world({ hop: { toClient: (m) => (m.type === MSG.REVERSE_PROOF && malloryRaw ? { ...m, public_key: malloryRaw } : m) } });
    malloryRaw = w.mallory.raw;
    const bob = await login(w.relay, w.bob);
    await until(async () => (await bob.listPeers()).length, 'the host in the peer list');
    const res = await bob.reverseConnect(w.host.fp, 9000).catch((e) => e);
    assert.ok(res instanceof Error || res.type === MSG.REVERSE_REJECT, 'a swapped key is not accepted');
    if (res.type === MSG.REVERSE_REJECT) assert.match(res.reason, /does not verify|did not answer/);
  });
});
