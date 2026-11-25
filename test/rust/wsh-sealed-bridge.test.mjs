// test/rust/wsh-sealed-bridge.test.mjs -- the sealed bridge with Rust on one or both ends (#145 step 5, #117):
//
//   JS operator (reverseConnect({ sealed })) -> Rust host (`wsh reverse --require-operator-proof`), through the JS relay and the Rust relay
//   Rust operator (`wsh --sealed reverse-connect`) -> JS host (Node, browser-safe) and -> Rust host
//   a recording and a tampering relay in front of a sealed Rust host: no plaintext marker crosses, an injected plain Open does not
//   run, a replayed or altered sealed frame closes the bridge.
//
// "Ran" means a file the command writes appears in a scratch directory. Every binary runs with HOME in a scratch directory.
// Prerequisites: cargo build --release -p wsh-cli -p wsh-server (or WSH_BIN / WSH_SERVER_BIN).

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import { createReverseHost as createBrowserSafeReverseHost } from '@johnhenry/wsh/reverse';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, MSG, cborEncode, cborDecode, open as openMsg, relayForward } from '@johnhenry/wsh';
import { hostileRelay } from '../helpers/hostile-relay.mjs';
import { freePort } from '../helpers/free-port.mjs'; // free for TCP and UDP: the server binds both (#248)

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
  const port = await freePort();
  const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--enable-relay', '--config', '/dev/null/none'], { env: cleanEnv(home), stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(proc);
  let logs = '';
  await new Promise((resolve, reject) => {
    const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
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


/** A scratch directory the host's commands write their marker files in. */
const markerDir = () => { const d = mkdtempSync(path.join('/tmp', 'wsh-seal-')); scratch.push(d); return d; };
/** The types of every RelayForward's inner message that crossed a hostile hop, and the whole traffic as bytes. */
const innerType = (m) => { try { return cborDecode(m.inner).type; } catch { return undefined; } };
const wire = (mitm) => Buffer.concat(mitm.seen.map((x) => Buffer.from(cborEncode(x.msg)))).toString('latin1');
const collectExec = (session) => new Promise((resolve) => { const ch = []; session.onData = (d) => ch.push(d); session.onClose = () => resolve(Buffer.concat(ch).toString()); });
const sealedProof = ['--require-operator-proof'];

for (const relayKind of ['js', 'rust']) {
  const makeRelay = relayKind === 'js' ? jsRelay : rustRelay;

  describe(`JS operator -> Rust host, sealed, through the ${relayKind} relay`, () => {
    it('runs the command, and a recording hop in front of the host never sees the command, the output or a plain Open', async () => {
      const [bob, host] = [await jsIdentity('bob'), await rustIdentity('host')];
      const relay = await makeRelay([bob, host]);
      // The recording hop dials the JS relay only (the Rust relay is wss); for it, run the host through the hop with the JS relay.
      const world = relayKind === 'js' ? { relay, hop: await hostileRelay(relay.url, {}) } : { relay, hop: null };
      if (world.hop) closers.push(() => world.hop.close());
      const dir = markerDir();
      const h = await rustHost(relay, host, { flags: [...sealedProof, '--allow-operator', bob.fp.slice(0, 16)], via: world.hop ? `${world.hop.url}/` : undefined });
      const op = await login(relay, bob);
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp, 8000, { sealed: true });
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      assert.ok(res.features.includes('e2e-sealed'));
      const s = await op.openSession({ type: 'exec', command: `echo SECRET-ZEBRA > ${dir}/legit; sleep 0.4; echo ECHOED-BACK-QUOKKA` });
      const out = await collectExec(s);
      assert.match(out, /ECHOED-BACK-QUOKKA/, `host stderr: ${h.err()} | host stdout: ${h.out()}`);
      await until(() => existsSync(path.join(dir, 'legit')), 'the command to run');
      assert.match(h.err() + h.out(), /[Bb]ridge sealed/);
      if (world.hop) {
        const blob = wire(world.hop);
        for (const secret of ['SECRET-ZEBRA', 'ECHOED-BACK-QUOKKA']) assert.ok(!blob.includes(secret), `${secret} crossed the relay in the clear`);
        const forwardedTypes = world.hop.seen.filter((x) => x.msg.type === MSG.RELAY_FORWARD).map((x) => innerType(x.msg));
        assert.ok(forwardedTypes.includes(MSG.KEY_EXCHANGE) && forwardedTypes.includes(MSG.ENCRYPTED_FRAME), `forwarded: ${forwardedTypes}`);
        assert.ok(forwardedTypes.every((t) => t === MSG.KEY_EXCHANGE || t === MSG.ENCRYPTED_FRAME), `plaintext types: ${forwardedTypes}`);
      }
    });

    it('keeps all of the output of a command that exits right after writing it (the exit does not overtake the last reads)', async () => {
      const [bob, host] = [await jsIdentity('bob'), await rustIdentity('host')];
      const relay = await makeRelay([bob, host]);
      await rustHost(relay, host, { flags: [...sealedProof, '--allow-operator', bob.fp.slice(0, 16)] });
      const op = await login(relay, bob);
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp, 8000, { sealed: true });
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      // The exit watcher and the output reader of a host session are independent: a child that writes and exits
      // at once can have its exit handled before the reader has taken everything out of the pty.
      for (let i = 0; i < 60; i++) {
        const s = await op.openSession({ type: 'exec', command: 'sleep 0.05; echo ECHOED-BACK-QUOKKA' });
        const out = await collectExec(s);
        assert.match(out, /ECHOED-BACK-QUOKKA/, `run ${i}: the output was lost`);
      }
    });

    it('a host that requires proof does not take an operator that does not seal: its plain messages are not heard', async () => {
      const [bob, host] = [await jsIdentity('bob'), await rustIdentity('host')];
      const relay = await makeRelay([bob, host]);
      const dir = markerDir();
      await rustHost(relay, host, { flags: [...sealedProof, '--allow-operator', bob.fp.slice(0, 16)] });
      const op = await login(relay, bob);
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      const res = await op.reverseConnect(host.fp, 8000); // proves, does not seal
      assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
      const s = op.openSession({ type: 'exec', command: `touch ${dir}/plain`, timeout: 2000 }).catch(() => null);
      // No positive event exists here: the host's gate drops a plain message without a log line or an answer, and the only later event
      // (the host giving up the unsealed bridge) comes after 10 s. So the one wait left is the open's own 2 s timeout, which is an answer
      // that did not come (a host that ran the Open answers in milliseconds); nothing is slept on top of it.
      assert.equal(await s, null, 'the plain Open was not answered');
      assert.equal(existsSync(path.join(dir, 'plain')), false, 'a plain Open on a bridge that must be sealed does not run');
    });
  });
}

for (const relayKind of ['js', 'rust']) {
  const makeRelay = relayKind === 'js' ? jsRelay : rustRelay;
  describe(`Rust operator (--sealed) -> JS host, through the ${relayKind} relay`, () => {
    for (const [label, factory] of [['Node host', createReverseHost], ['browser-safe host', createBrowserSafeReverseHost]]) {
      it(`${label} that requires operator proof: the bridge is sealed (hybrid) and the host hears an Open only as a frame`, async () => {
        const [host, op] = [await jsIdentity('host'), await rustIdentity('op')];
        const relay = await makeRelay([host, { ssh: op.ssh }]);
        const logs = [];
        const reverse = factory({
          url: relay.url, username: 'host', keyPair: host.keyPair, exec: async (c, io) => { io.write(`ran:${c}\n`); return 0; }, reconnect: false, proofTimeoutMs: 3000,
          requireOperatorProof: true, accept: () => true, onLog: (l) => logs.push(l),
        });
        await reverse.start();
        closers.push(() => reverse.close());
        await sleep(300);
        const c = relay.cli(op.home);
        const p = spawnWsh([...c.args, '--operator-proof', '--sealed', 'reverse-connect', host.fp.slice(0, 12), c.target], c.env);
        await until(() => /bridge sealed/.test(p.out()) || p.err(), `the CLI to report a sealed bridge (${p.out()} ${p.err()})`);
        assert.match(p.out(), /bridge sealed/, p.err());
        await until(() => logs.some((l) => /sealed \(hybrid\)/.test(l)), `the host to seal with the hybrid exchange: ${logs.join(' | ')}`);
        p.proc.kill('SIGKILL');
      });
    }

    it('--sealed against a host that cannot seal fails at once, and sends nothing', async () => {
      const [host, op] = [await jsIdentity('host'), await rustIdentity('op')];
      const relay = await makeRelay([host, { ssh: op.ssh }]);
      const logs = [];
      const reverse = createReverseHost({ url: relay.url, username: 'host', keyPair: host.keyPair, exec: true, reconnect: false, e2e: false, accept: () => true, onLog: (l) => logs.push(l) });
      await reverse.start();
      closers.push(() => reverse.close());
      await sleep(300);
      const c = relay.cli(op.home);
      const p = spawnWsh([...c.args, '--operator-proof', '--sealed', 'reverse-connect', host.fp.slice(0, 12), c.target], c.env);
      const code = await Promise.race([p.done, sleep(8000).then(() => 'still running')]);
      assert.notEqual(code, 'still running', p.out() + p.err());
      assert.notEqual(code, 0);
      assert.match(p.err(), /e2e-sealed|sealed bridge/);
      assert.ok(!/bridge sealed/.test(p.out()));
    });
  });
}

for (const relayKind of ['js', 'rust']) {
describe(`Rust operator -> Rust host, sealed, through the ${relayKind} relay`, () => {
  it('both ends are Rust: the bridge is sealed', async () => {
    const [host, op] = [await rustIdentity('host'), await rustIdentity('op')];
    const relay = await (relayKind === 'js' ? jsRelay : rustRelay)([host, op]);
    const h = await rustHost(relay, host, { flags: [...sealedProof] });
    const c = relay.cli(op.home);
    const p = spawnWsh([...c.args, '--sealed', 'reverse-connect', host.fp.slice(0, 12), c.target], c.env);
    await until(() => /bridge sealed/.test(p.out()) || p.err(), `the CLI to report a sealed bridge (${p.out()} ${p.err()})`);
    assert.match(p.out(), /bridge sealed/, p.err());
    await until(() => /[Bb]ridge sealed/.test(h.err() + h.out()), `the host to report it (${h.err()})`);
    p.proc.kill('SIGKILL');
  });
});

}

describe('a hostile relay in front of a sealed Rust host', () => {
  async function world() {
    const [bob, host] = [await jsIdentity('bob'), await rustIdentity('host')];
    const relay = await jsRelay([bob, host]);
    const state = { frames: [], tamper: false, replayCtx: null };
    const mitm = await hostileRelay(relay.url, {
      toClient: (m, ctx) => {
        state.ctx = ctx;
        if (m.type === MSG.RELAY_FORWARD && innerType(m) === MSG.ENCRYPTED_FRAME) {
          state.frames.push(m);
          if (state.tamper) {
            state.tamper = false;
            const inner = cborDecode(m.inner);
            inner.ciphertext = new Uint8Array(inner.ciphertext); inner.ciphertext[3] ^= 1;
            return { ...m, inner: cborEncode(inner) };
          }
        }
        return m;
      },
    });
    closers.push(() => mitm.close());
    const dir = markerDir();
    const h = await rustHost(relay, host, { flags: [...sealedProof, '--allow-operator', bob.fp.slice(0, 16)], via: `${mitm.url}/` });
    const op = await login(relay, bob);
    await until(async () => (await op.listPeers()).length, 'the host in the peer list');
    const res = await op.reverseConnect(host.fp, 8000, { sealed: true });
    assert.equal(res.type, MSG.REVERSE_ACCEPT, res.reason);
    return { bob, host, relay, mitm, state, dir, h, op };
  }

  it('an injected plain Open stamped with the operator\'s fingerprint does not run, before or after the bridge is sealed', async () => {
    const w = await world();
    const plain = relayForward({ fromFingerprint: w.bob.fp, inner: cborEncode(openMsg({ kind: 'exec', command: `touch ${w.dir}/INJECTED` })) });
    await w.state.ctx.injectToClient(plain);
    // The genuine operator's command is the marker: its frame reaches the host after the injected message on the same connection, so by
    // the time it has run the injected Open was already handled; and it shows the injection did not end the bridge.
    const s = await w.op.openSession({ type: 'exec', command: `touch ${w.dir}/legit` });
    await collectExec(s);
    await until(() => existsSync(path.join(w.dir, 'legit')), 'the genuine command to run');
    assert.equal(existsSync(path.join(w.dir, 'INJECTED')), false, 'the plain Open did not run');
  });

  it('a replayed sealed frame is not run again, and closes the bridge', async () => {
    const w = await world();
    const s = await w.op.openSession({ type: 'exec', command: `echo x >> ${w.dir}/count` });
    await collectExec(s);
    await until(() => existsSync(path.join(w.dir, 'count')), 'the command to run');
    const openFrame = w.state.frames[0];
    assert.ok(openFrame, 'a sealed frame crossed the hop');
    await w.state.ctx.injectToClient(openFrame);
    // The host says so when the replayed frame has not opened and it has ended the bridge: that, not a stretch of time, is when "not run again" can be judged.
    await until(() => /ending the bridge/.test(w.h.err()), `the host to end the bridge: ${w.h.err()}`);
    assert.equal(readFileSync(path.join(w.dir, 'count'), 'utf8').trim().split('\n').length, 1, 'the replay did not run the command again');
    // No positive event exists for a request on an ended bridge (the host drops it without a log line or an answer, shown only at its debug
    // level), so the one wait left is the open's own 1.5 s timeout: an answer that did not come (a host that served it answers in milliseconds).
    const after = await w.op.openSession({ type: 'exec', command: `touch ${w.dir}/after`, timeout: 1500 }).catch(() => null);
    assert.equal(after, null, 'a request on an ended bridge was not answered');
    assert.equal(existsSync(path.join(w.dir, 'after')), false, 'a closed bridge runs nothing more');
  });

  it('a flipped bit in a sealed frame closes the bridge and the command does not run', async () => {
    const w = await world();
    w.state.tamper = true;
    void w.op.openSession({ type: 'exec', command: `touch ${w.dir}/tampered`, timeout: 1500 }).catch(() => null); // not waited for: its answer is not the event
    // The host says so when the tampered frame has not opened and it has ended the bridge: that, not a stretch of time, is when "did not run" can be judged.
    await until(() => /ending the bridge/.test(w.h.err()), `the host to end the bridge: ${w.h.err()}`);
    assert.equal(existsSync(path.join(w.dir, 'tampered')), false);
  });
});
