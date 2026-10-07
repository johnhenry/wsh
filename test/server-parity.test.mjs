// test/server-parity.test.mjs -- host key / TOFU, password auth, fileWrite / fileRename
// for `@johnhenry/wsh/server`, driven by the stock client.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, mkdir, symlink, stat, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createWshServer } from '@johnhenry/wsh/server';
import { FailureLimiter } from '../src/server/auth.mjs';
import {
  WshClient, WshKnownHosts, HostKeyError, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw,
  fingerprint, sign, MSG, WshTransport,
} from '@johnhenry/wsh';
import { hostKeyProofMessage, newHostKeyNonce, toHex } from '../src/host-key.mjs';

const dec = new TextDecoder();

async function start(opts) {
  const server = createWshServer(opts);
  const { port } = await server.listen();
  return { server, port, url: `ws://127.0.0.1:${port}` };
}

async function refusal(promise) {
  try { await promise; } catch (e) { return e; }
  assert.fail('expected the call to be refused');
}

let keyPair;
let authorizedKeys;
before(async () => {
  keyPair = await generateKeyPair(true);
  authorizedKeys = await exportPublicKeySSH(keyPair.publicKey);
});

describe('host key advertisement and pinning', () => {
  it('surfaces the verified host key (client.hostKey, onHostKey) with no policy', async () => {
    const { server, url } = await start({ auth: { authorizedKeys }, hostKey: true });
    try {
      const seen = [];
      const client = new WshClient();
      client.onHostKey = (hk) => { seen.push(hk); };
      await client.connect(url, { username: 'alice', keyPair });
      const advertised = server.hostKey();
      assert.equal(client.hostKey.fingerprint, advertised.fingerprint);
      assert.equal(client.hostKey.openssh, advertised.openssh);
      assert.deepEqual(client.hostKey.publicKey, advertised.publicKey);
      assert.equal(client.hostKey.status, 'unpinned');
      assert.equal(seen.length, 1);
      assert.equal(seen[0].fingerprint, advertised.fingerprint);
      await client.disconnect();
    } finally { await server.close(); }
  });

  it('expectHostKey accepts a fingerprint, an ssh-ed25519 line, or raw key bytes', async () => {
    const { server, url } = await start({ auth: { authorizedKeys }, hostKey: true });
    try {
      const hk = server.hostKey();
      for (const expectHostKey of [hk.fingerprint, `sha256:${hk.fingerprint}`, hk.openssh, hk.publicKey]) {
        const client = new WshClient();
        await client.connect(url, { username: 'alice', keyPair, expectHostKey });
        assert.equal(client.hostKey.status, 'pinned');
        await client.disconnect();
      }
    } finally { await server.close(); }
  });

  it('refuses a mismatched pin BEFORE sending any credential', async () => {
    let authorizeCalls = 0;
    let passwordCalls = 0;
    const { server, url } = await start({
      auth: { authorizedKeys, authorize: () => { authorizeCalls++; return true; }, password: () => { passwordCalls++; return true; } },
      hostKey: true,
    });
    try {
      const wrong = 'ab'.repeat(32);
      for (const creds of [{ keyPair }, { password: 'hunter2' }]) {
        const err = await refusal(new WshClient().connect(url, { username: 'alice', ...creds, expectHostKey: wrong }));
        assert.ok(err instanceof HostKeyError);
        assert.equal(err.code, 'HOST_KEY_MISMATCH');
        assert.equal(err.expected, wrong);
        assert.equal(err.actual, server.hostKey().fingerprint);
      }
      assert.equal(authorizeCalls, 0, 'no signature reached the host');
      assert.equal(passwordCalls, 0, 'the password was never sent');
    } finally { await server.close(); }
  });

  it('refuses when a pin is requested but the host has no host key', async () => {
    const { server, url } = await start({ auth: { authorizedKeys } });
    try {
      const plain = new WshClient();
      await plain.connect(url, { username: 'alice', keyPair });
      assert.equal(plain.hostKey, null);
      await plain.disconnect();
      const err = await refusal(new WshClient().connect(url, { username: 'alice', keyPair, expectHostKey: 'ab'.repeat(32) }));
      assert.equal(err.code, 'HOST_KEY_MISSING');
      const err2 = await refusal(new WshClient().connect(url, { username: 'alice', keyPair, knownHosts: new WshKnownHosts() }));
      assert.equal(err2.code, 'HOST_KEY_MISSING');
    } finally { await server.close(); }
  });

  it('knownHosts: refuses an unseen host unless trustOnFirstUse, then pins and refuses a changed key', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'wsh-hk-'));
    const file = path.join(dir, 'host_key');
    const knownHosts = new WshKnownHosts();
    try {
      let ctx = await start({ auth: { authorizedKeys }, hostKey: { file } });
      const label = 'myhost:22';
      const unknown = await refusal(new WshClient().connect(ctx.url, { username: 'alice', keyPair, knownHosts, hostLabel: label }));
      assert.equal(unknown.code, 'HOST_KEY_UNKNOWN');
      assert.equal(knownHosts.list().length, 0, 'a refused host is not pinned');

      const first = new WshClient();
      await first.connect(ctx.url, { username: 'alice', keyPair, knownHosts, hostLabel: label, trustOnFirstUse: true });
      assert.equal(first.hostKey.status, 'unknown');
      await first.disconnect();
      assert.deepEqual(knownHosts.list(), [{ host: label, fingerprint: ctx.server.hostKey().fingerprint }]);
      const pinnedFp = ctx.server.hostKey().fingerprint;

      // Restart with the same persisted key: still the same host.
      await ctx.server.close();
      ctx = await start({ auth: { authorizedKeys }, hostKey: { file } });
      assert.equal(ctx.server.hostKey().fingerprint, pinnedFp, 'file-backed host key survives a restart');
      assert.equal((await stat(file)).mode & 0o077, 0, 'host key file is private');
      const again = new WshClient();
      await again.connect(ctx.url, { username: 'alice', keyPair, knownHosts, hostLabel: label });
      assert.equal(again.hostKey.status, 'known');
      await again.disconnect();

      // An impostor / reinstalled host on the same label.
      await ctx.server.close();
      ctx = await start({ auth: { authorizedKeys }, hostKey: true });
      const err = await refusal(new WshClient().connect(ctx.url, { username: 'alice', keyPair, knownHosts, hostLabel: label, trustOnFirstUse: true }));
      assert.equal(err.code, 'HOST_KEY_MISMATCH');
      assert.equal(err.expected, pinnedFp);
      assert.equal(knownHosts.list()[0].fingerprint, pinnedFp, 'a changed key never overwrites the pin');
      await ctx.server.close();
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it('onHostKey can refuse a host (return false) or accept an unseen one for pinning', async () => {
    const { server, url } = await start({ auth: { authorizedKeys }, hostKey: true });
    try {
      const err = await refusal(new WshClient().connect(url, { username: 'alice', keyPair, onHostKey: () => false }));
      assert.equal(err.code, 'HOST_KEY_REJECTED');
      const knownHosts = new WshKnownHosts();
      const ok = new WshClient();
      await ok.connect(url, { username: 'alice', keyPair, knownHosts, onHostKey: (hk) => hk.status === 'unknown' });
      assert.equal(knownHosts.list().length, 1);
      await ok.disconnect();
    } finally { await server.close(); }
  });

  it('WshClient.exec passes the pin through', async () => {
    const { server, url } = await start({ auth: { authorizedKeys }, hostKey: true, exec: true });
    try {
      const { stdout } = await WshClient.exec(url, 'echo hello', {
        username: 'alice', keyPair, expectHostKey: server.hostKey().fingerprint, timeout: 5000,
      });
      assert.equal(dec.decode(stdout), 'hello\n');
      const err = await refusal(WshClient.exec(url, 'echo hello', { username: 'alice', keyPair, expectHostKey: 'cd'.repeat(32) }));
      assert.equal(err.code, 'HOST_KEY_MISMATCH');
    } finally { await server.close(); }
  });

  describe('a forged advertisement', () => {
    /** A transport that plays a server, letting each test choose what ServerHello claims. */
    class FakeHost extends WshTransport {
      constructor(makeHello) { super(); this.makeHello = makeHello; }
      async _doConnect() {}
      async _doClose() {}
      async _doOpenStream() { throw new Error('unused'); }
      async _doSendControl(msg) {
        if (msg.type !== MSG.HELLO) return;
        const nonce = msg.features.find((f) => f.startsWith('host-key-nonce:')).slice('host-key-nonce:'.length);
        const hello = await this.makeHello({ nonce, username: msg.username });
        setTimeout(() => this._emitControl(hello), 0);
      }
    }
    const advert = (hostKeys, sessionId, sig, fp) => ({
      type: MSG.SERVER_HELLO, session_id: sessionId, host_fingerprint: fp,
      features: [`host-key:${toHex(hostKeys.raw)}`, `host-key-sig:${toHex(sig)}`],
    });
    const attempt = (makeHello) => new WshClient().connectWithTransport(new FakeHost(makeHello), 'wsh://x/', {
      username: 'alice', keyPair, timeout: 500,
    });

    it('rejects a replayed proof (signed over a different client nonce), a bad signature, and a fingerprint mismatch', async () => {
      const kp = await generateKeyPair(true);
      const raw = await exportPublicKeyRaw(kp.publicKey);
      const fp = await fingerprint(raw);
      const hostKeys = { raw };
      // Proof is genuine for a nonce the client did not send -> replay.
      const replay = await refusal(attempt(async ({ username }) =>
        advert(hostKeys, 'sid', await sign(kp.privateKey, hostKeyProofMessage({ sessionId: 'sid', clientNonce: newHostKeyNonce(), username })), fp)));
      assert.equal(replay.code, 'HOST_KEY_INVALID');
      const garbage = await refusal(attempt(async () => advert(hostKeys, 'sid', new Uint8Array(64), fp)));
      assert.equal(garbage.code, 'HOST_KEY_INVALID');
      const wrongFp = await refusal(attempt(async ({ nonce, username }) =>
        advert(hostKeys, 'sid', await sign(kp.privateKey, hostKeyProofMessage({ sessionId: 'sid', clientNonce: nonce, username })), 'ee'.repeat(32))));
      assert.equal(wrongFp.code, 'HOST_KEY_INVALID');
    });

    it('a bare fingerprint with no key or proof cannot satisfy a pin', async () => {
      const err = await new WshClient().connectWithTransport(
        new FakeHost(async () => ({ type: MSG.SERVER_HELLO, session_id: 's', host_fingerprint: 'ab'.repeat(32), features: [] })),
        'wsh://x/', { username: 'alice', keyPair, timeout: 500, expectHostKey: 'ab'.repeat(32) },
      ).catch((e) => e);
      assert.equal(err.code, 'HOST_KEY_MISSING');
    });
  });
});

describe('password auth', () => {
  const users = { alice: 'correct horse', bob: 'battery staple' };
  const password = async (u, p) => users[u] === p;

  it('accepts the right password and refuses the wrong one, unknown users, and non-strings', async () => {
    const { server, url } = await start({ auth: { password, rateLimit: { failureDelayMs: 0 } }, exec: true });
    try {
      const { stdout } = await WshClient.exec(url, 'echo hi', { username: 'bob', password: 'battery staple', timeout: 5000 });
      assert.equal(dec.decode(stdout), 'hi\n');
      const bad = await refusal(new WshClient().connect(url, { username: 'alice', password: 'nope' }));
      assert.match(bad.message, /authentication failed/);
      const nobody = await refusal(new WshClient().connect(url, { username: 'mallory', password: 'x' }));
      assert.match(nobody.message, /authentication failed/);
    } finally { await server.close(); }
  });

  it('is independent of key auth: a password-only host refuses keys, a key-only host refuses passwords', async () => {
    const pwOnly = await start({ auth: { password } });
    const keyOnly = await start({ auth: { authorizedKeys } });
    try {
      const a = await refusal(new WshClient().connect(pwOnly.url, { username: 'alice', keyPair }));
      assert.match(a.message, /pubkey auth is not enabled/);
      const b = await refusal(new WshClient().connect(keyOnly.url, { username: 'alice', password: 'correct horse' }));
      assert.match(b.message, /password auth is not enabled/);
    } finally { await pwOnly.server.close(); await keyOnly.server.close(); }
  });

  it('a host with both methods serves both', async () => {
    const { server, url } = await start({ auth: { authorizedKeys, password, rateLimit: { failureDelayMs: 0 } } });
    try {
      const k = new WshClient(); await k.connect(url, { username: 'alice', keyPair }); await k.disconnect();
      const p = new WshClient(); await p.connect(url, { username: 'alice', password: 'correct horse' }); await p.disconnect();
    } finally { await server.close(); }
  });

  it('a throwing password callback is a refusal, not a crash', async () => {
    const { server, url } = await start({ auth: { password: () => { throw new Error('db down'); }, rateLimit: { failureDelayMs: 0 } } });
    try {
      const err = await refusal(new WshClient().connect(url, { username: 'alice', password: 'x' }));
      assert.match(err.message, /authentication failed/);
    } finally { await server.close(); }
  });

  it('rate-limits failures: after maxFailures the callback is no longer consulted, even for the right password', async () => {
    let calls = 0;
    const { server, url } = await start({
      auth: { password: async (u, p) => { calls++; return users[u] === p; }, rateLimit: { maxFailures: 3, lockoutMs: 60_000, failureDelayMs: 0 } },
    });
    try {
      for (let i = 0; i < 3; i++) await refusal(new WshClient().connect(url, { username: 'alice', password: `wrong${i}` }));
      assert.equal(calls, 3);
      const locked = await refusal(new WshClient().connect(url, { username: 'alice', password: 'correct horse' }));
      assert.match(locked.message, /too many failed attempts/);
      assert.equal(calls, 3, 'the callback was not called while locked out');
    } finally { await server.close(); }
  });

  it('a success clears the failure count; a custom key separates callers', async () => {
    const { server, url } = await start({
      auth: { password, rateLimit: { maxFailures: 2, failureDelayMs: 0, key: ({ username }) => username } },
    });
    try {
      await refusal(new WshClient().connect(url, { username: 'alice', password: 'bad' }));
      const ok = new WshClient(); await ok.connect(url, { username: 'alice', password: 'correct horse' }); await ok.disconnect();
      await refusal(new WshClient().connect(url, { username: 'alice', password: 'bad' }));
      const still = new WshClient(); await still.connect(url, { username: 'alice', password: 'correct horse' }); await still.disconnect();
      // bob is a different key: alice's failures never touched him
      await refusal(new WshClient().connect(url, { username: 'alice', password: 'bad' }));
      await refusal(new WshClient().connect(url, { username: 'alice', password: 'bad' }));
      const bob = new WshClient(); await bob.connect(url, { username: 'bob', password: 'battery staple' }); await bob.disconnect();
    } finally { await server.close(); }
  });

  it('FailureLimiter: window expiry and lockout expiry', () => {
    let t = 0;
    const l = new FailureLimiter({ maxFailures: 2, windowMs: 1000, lockoutMs: 500, now: () => t });
    l.fail('k'); assert.equal(l.lockedFor('k'), 0);
    l.fail('k'); assert.equal(l.lockedFor('k'), 500);
    t = 499; assert.equal(l.lockedFor('k'), 1);
    t = 501; assert.equal(l.lockedFor('k'), 0);
    t = 5000; l.fail('k'); assert.equal(l.lockedFor('k'), 0, 'old failures aged out of the window');
  });

  it('works together with a verified host key (password sent only to the pinned host)', async () => {
    const { server, url } = await start({ auth: { password, rateLimit: { failureDelayMs: 0 } }, hostKey: true });
    try {
      const c = new WshClient();
      await c.connect(url, { username: 'alice', password: 'correct horse', expectHostKey: server.hostKey().fingerprint });
      assert.equal(c.hostKey.status, 'pinned');
      await c.disconnect();
    } finally { await server.close(); }
  });
});

describe('fileWrite / fileRename through the stock client', () => {
  let root; let outside; let ctx; let client;
  before(async () => {
    root = await mkdtemp(path.join(tmpdir(), 'wsh-fs-'));
    outside = await mkdtemp(path.join(tmpdir(), 'wsh-out-'));
    await writeFile(path.join(root, 'a.txt'), 'hello world');
    await mkdir(path.join(root, 'sub'));
    await writeFile(path.join(outside, 'secret.txt'), 'secret');
    await symlink(outside, path.join(root, 'escape'));
    ctx = await start({ auth: { authorizedKeys }, fs: { root, maxFileBytes: 300_000 } });
    client = new WshClient();
    await client.connect(ctx.url, { username: 'alice', keyPair });
  });
  after(async () => {
    await client.disconnect();
    await ctx.server.close();
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });

  it('advertises file-write and file-rename only when fs is configured', async () => {
    assert.ok(client.hasFeature('file-write'));
    assert.ok(client.hasFeature('file-rename'));
    const bare = await start({ auth: { authorizedKeys } });
    try {
      const c = new WshClient();
      await c.connect(bare.url, { username: 'alice', keyPair });
      await assert.rejects(c.fileWrite('x', 'y'), /does not support file write/);
      await assert.rejects(c.fileRename('x', 'y'), /does not support file rename/);
      await c.disconnect();
    } finally { await bare.server.close(); }
  });

  it('round trip: write, read back, rename, list, remove', async () => {
    const w = await client.fileWrite('note.txt', 'first draft');
    assert.equal(w.success, true);
    assert.equal(w.metadata.written, 11);
    assert.equal(await readFile(path.join(root, 'note.txt'), 'utf8'), 'first draft');
    const r = await client.fileRead('note.txt', 0, 100);
    assert.equal(dec.decode(r.metadata.data), 'first draft');

    const mv = await client.fileRename('note.txt', 'sub/final.txt');
    assert.equal(mv.success, true, mv.error_message);
    await assert.rejects(stat(path.join(root, 'note.txt')));
    assert.equal(await readFile(path.join(root, 'sub/final.txt'), 'utf8'), 'first draft');
    const ls = await client.fileList('sub');
    assert.deepEqual(ls.entries.map((e) => e.name), ['final.txt']);
    assert.equal((await client.fileRemove('sub/final.txt')).success, true);
  });

  it('write replaces by default, writes in place at an offset, and sends binary and multi-chunk data intact', async () => {
    await client.fileWrite('b.bin', 'AAAAAAAA');
    await client.fileWrite('b.bin', 'xy', 3);
    assert.equal(await readFile(path.join(root, 'b.bin'), 'utf8'), 'AAAxyAAA');
    await client.fileWrite('b.bin', 'Z');
    assert.equal(await readFile(path.join(root, 'b.bin'), 'utf8'), 'Z');

    const big = new Uint8Array(200_000).map((_, i) => (i * 31) % 256);
    assert.equal((await client.fileWrite('big.bin', big)).success, true);
    assert.deepEqual(new Uint8Array(await readFile(path.join(root, 'big.bin'))), big);
    assert.equal((await client.fileWrite('empty.bin', new Uint8Array(0))).success, true);
    assert.equal((await stat(path.join(root, 'empty.bin'))).size, 0);
  });

  it('refuses traversal, symlink escapes and the root for both write and rename', async () => {
    for (const bad of ['../evil.txt', '/../evil.txt', 'escape/evil.txt', 'escape/secret.txt']) {
      const w = await client.fileWrite(bad, 'pwn');
      assert.equal(w.success, false, `write ${bad}`);
      assert.match(w.error_message, /escapes the file root/);
    }
    await assert.rejects(stat(path.join(outside, 'evil.txt')));
    assert.equal(await readFile(path.join(outside, 'secret.txt'), 'utf8'), 'secret');

    // out of the root, via ..
    const out = await client.fileRename('a.txt', '../stolen.txt');
    assert.equal(out.success, false);
    assert.match(out.error_message, /escapes the file root/);
    // out of the root, via a symlinked directory
    const viaLink = await client.fileRename('a.txt', 'escape/stolen.txt');
    assert.equal(viaLink.success, false);
    assert.match(viaLink.error_message, /escapes the file root/);
    // IN from outside, via a symlink
    const inFrom = await client.fileRename('escape/secret.txt', 'got.txt');
    assert.equal(inFrom.success, false);
    assert.match(inFrom.error_message, /escapes the file root/);
    assert.equal(await readFile(path.join(root, 'a.txt'), 'utf8'), 'hello world');
    assert.equal(await readFile(path.join(outside, 'secret.txt'), 'utf8'), 'secret');
    assert.deepEqual((await readdir(outside)).sort(), ['secret.txt']);

    for (const [from, to] of [['/', 'x'], ['a.txt', '/'], ['.', 'x']]) {
      const r = await client.fileRename(from, to);
      assert.equal(r.success, false, `${from} -> ${to}`);
    }
    assert.equal((await client.fileWrite('a\0b', 'x')).success, false);
  });

  it('rename refuses to clobber, to move a directory into itself, and reports a missing source', async () => {
    await client.fileWrite('one.txt', '1');
    await client.fileWrite('two.txt', '2');
    const clobber = await client.fileRename('one.txt', 'two.txt');
    assert.equal(clobber.success, false);
    assert.match(clobber.error_message, /already exists/);
    assert.equal(await readFile(path.join(root, 'two.txt'), 'utf8'), '2');
    const into = await client.fileRename('sub', 'sub/inner');
    assert.equal(into.success, false);
    assert.match(into.error_message, /into itself/);
    const missing = await client.fileRename('nope.txt', 'x.txt');
    assert.equal(missing.success, false);
    assert.match(missing.error_message, /no such file/);
  });

  it('enforces maxFileBytes, and a failed write leaves the file untouched', async () => {
    const r = await client.fileWrite('huge.bin', new Uint8Array(300_001));
    assert.equal(r.success, false);
    assert.match(r.error_message, /exceeds/);
    await assert.rejects(stat(path.join(root, 'huge.bin')));
    const sparse = await client.fileWrite('sparse.bin', 'x', 299_999_999);
    assert.equal(sparse.success, false);
    await assert.rejects(stat(path.join(root, 'sparse.bin')));
  });

  it('readOnly refuses write and rename', async () => {
    const ro = await start({ auth: { authorizedKeys }, fs: { root, readOnly: true } });
    try {
      const c = new WshClient();
      await c.connect(ro.url, { username: 'alice', keyPair });
      const w = await c.fileWrite('ro.txt', 'x');
      assert.equal(w.success, false);
      assert.match(w.error_message, /read-only/);
      const mv = await c.fileRename('a.txt', 'ro.txt');
      assert.equal(mv.success, false);
      assert.match(mv.error_message, /read-only/);
      await assert.rejects(stat(path.join(root, 'ro.txt')));
      await c.disconnect();
    } finally { await ro.server.close(); }
  });
});
