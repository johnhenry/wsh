// test/unix-listen.test.mjs -- src/unix-listen.mjs: listening on a unix socket path so that closing removes only what
// the listener created. Node's net.Server unlinks, when it closes, whatever is at the NAME it bound; the helper binds
// inside a private directory, hard-links the socket to the requested name and removes that name only while it is still
// the same inode. Real sockets in temp directories, a second process for "someone else's live socket".
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { listenUnixSocket, removeIfIdentity, MAX_SOCKET_PATH } from '../src/unix-listen.mjs';

const answer = (p) => new Promise((resolve, reject) => { const s = net.connect(p); const cs = []; s.on('data', (d) => cs.push(d)); s.on('close', () => resolve(Buffer.concat(cs).toString())); s.on('error', reject); });
const serverThatSays = (word) => net.createServer((c) => { c.on('error', () => {}); c.end(word); });

describe('listenUnixSocket: a unix listener that removes only its own socket', () => {
  let dir; const servers = []; const children = []; const bounds = [];
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-ul-')); });
  afterEach(async () => {
    for (const b of bounds.splice(0)) await b.close().catch(() => {});
    for (const s of servers.splice(0)) await new Promise((r) => { s.close(() => r()); s.closeAllConnections?.(); });
    for (const c of children.splice(0)) { c.stdin.end(); await new Promise((r) => c.once('exit', r)); }
    fs.rmSync(dir, { recursive: true, force: true }); // a directory this test made
  });

  const up = async (p, word = 'mine') => {
    const server = serverThatSays(word); servers.push(server);
    const bound = await listenUnixSocket(server, p); bounds.push(bound);
    return { server, bound };
  };
  /** Another process listening at `p`. */
  const anotherProcessListens = async (p) => {
    const child = spawn(process.execPath, [new URL('./live-socket-child.mjs', import.meta.url).pathname, p], { stdio: ['pipe', 'pipe', 'inherit'] });
    children.push(child);
    await new Promise((resolve, reject) => { child.stdout.once('data', resolve); child.once('exit', () => reject(new Error('the other process exited'))); });
  };

  it('while up: the path is a socket nobody but the owner can use, it answers, and the only other thing in the directory is a private directory', async () => {
    const p = path.join(dir, 'a.sock');
    const { bound } = await up(p);
    const st = fs.lstatSync(p);
    assert.equal(st.isSocket(), true);
    assert.equal(st.mode & 0o777, 0o600);
    assert.equal(bound.path, p);
    assert.deepEqual({ dev: bound.identity.dev, ino: bound.identity.ino }, { dev: st.dev, ino: st.ino });
    assert.equal(await answer(p), 'mine');
    const others = fs.readdirSync(dir).filter((n) => n !== 'a.sock');
    assert.equal(others.length, 1, `unexpected entries ${others}`);
    const priv = fs.lstatSync(path.join(dir, others[0]));
    assert.equal(priv.isDirectory(), true);
    assert.equal(priv.mode & 0o777, 0o700, 'the directory the socket was made in is owner-only');
    assert.deepEqual(fs.readdirSync(path.join(dir, others[0])), [], 'nothing else is kept in it');
  });

  it('close() leaves nothing behind: no socket, no private directory, and closing twice is harmless', async () => {
    const p = path.join(dir, 'b.sock');
    const { bound } = await up(p);
    await bound.close();
    assert.deepEqual(fs.readdirSync(dir), []);
    await bound.close();
    await assert.rejects(answer(p), (e) => e.code === 'ENOENT');
  });

  it('a regular file put at the path while the listener is up survives close()', async () => {
    const p = path.join(dir, 'c.sock');
    const { bound } = await up(p);
    fs.unlinkSync(p); fs.writeFileSync(p, 'someone else\'s data');
    await bound.close();
    assert.equal(fs.readFileSync(p, 'utf8'), 'someone else\'s data');
    assert.deepEqual(fs.readdirSync(dir), ['c.sock'], 'and the private directory is gone');
  });

  it('another process\'s live socket put at the path while the listener is up survives close() and keeps answering', async () => {
    const p = path.join(dir, 'd.sock');
    const { bound } = await up(p);
    fs.unlinkSync(p);
    await anotherProcessListens(p);
    const theirs = fs.lstatSync(p);
    await bound.close();
    assert.equal(fs.lstatSync(p).ino, theirs.ino);
    assert.equal(await answer(p), 'other');
    assert.deepEqual(fs.readdirSync(dir), ['d.sock']);
  });

  it('a socket of this same process put at the path survives too (a different inode with the same name)', async () => {
    const p = path.join(dir, 'e.sock');
    const { bound } = await up(p);
    fs.unlinkSync(p);
    const other = serverThatSays('other'); servers.push(other);
    await new Promise((r) => other.listen(p, r));
    await bound.close();
    assert.equal(await answer(p), 'other');
  });

  it('a path that something already occupies is refused with EADDRINUSE and touched in no way', async () => {
    const p = path.join(dir, 'f.sock');
    fs.writeFileSync(p, 'data');
    const server = serverThatSays('mine'); servers.push(server);
    await assert.rejects(listenUnixSocket(server, p), (e) => e.code === 'EADDRINUSE');
    assert.equal(server.listening, false);
    assert.equal(fs.readFileSync(p, 'utf8'), 'data');
    assert.deepEqual(fs.readdirSync(dir), ['f.sock'], 'no private directory is left over');
  });

  it('a directory that does not exist is an ENOENT, as for a plain listen', async () => {
    const server = serverThatSays('mine'); servers.push(server);
    await assert.rejects(listenUnixSocket(server, path.join(dir, 'nope', 'x.sock')), (e) => e.code === 'ENOENT');
  });

  it('many listeners at once in one directory: every one answers, and closing them all leaves the directory empty', async () => {
    const names = Array.from({ length: 40 }, (_, i) => path.join(dir, `m${i}.sock`));
    const all = await Promise.all(names.map((p, i) => up(p, `n${i}`)));
    assert.equal(new Set(all.map((a) => a.bound.identity.ino)).size, 40);
    for (let i = 0; i < names.length; i++) assert.equal(await answer(names[i]), `n${i}`);
    await Promise.all(all.map((a) => a.bound.close()));
    assert.deepEqual(fs.readdirSync(dir), []);
  });

  it('a path too long to stage a directory next to still works, listening directly as before', async () => {
    // A parent of MAX - 8 bytes makes the requested path fit (MAX - 1) while the staged one (parent + 11) does not.
    const root = fs.mkdtempSync('/tmp/wsh-ull-');
    try {
      let parent = root;
      while (Buffer.byteLength(parent) < MAX_SOCKET_PATH - 8) parent = path.join(parent, 'd'.repeat(Math.max(1, Math.min(30, MAX_SOCKET_PATH - 8 - Buffer.byteLength(parent) - 1))));
      fs.mkdirSync(parent, { recursive: true });
      const p = path.join(parent, 's.sock');
      assert.ok(Buffer.byteLength(p) <= MAX_SOCKET_PATH && Buffer.byteLength(p) + 11 > MAX_SOCKET_PATH, `${Buffer.byteLength(p)} vs ${MAX_SOCKET_PATH}`);
      const server = serverThatSays('mine'); servers.push(server);
      const bound = await listenUnixSocket(server, p); bounds.push(bound);
      assert.equal(bound.staged, false);
      assert.equal(fs.lstatSync(p).mode & 0o777, 0o600);
      assert.equal(await answer(p), 'mine');
      await bound.close();
      assert.deepEqual(fs.readdirSync(parent), []);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });

  it('a short path next to a long one is staged: the usual case sets staged', async () => {
    const { bound } = await up(path.join(dir, 'g.sock'));
    assert.equal(bound.staged, true);
  });

  it('an abstract or empty path is not a file: it is passed straight to listen', async () => {
    if (process.platform !== 'linux') return;
    const server = serverThatSays('mine'); servers.push(server);
    const bound = await listenUnixSocket(server, `\0wsh-ul-${process.pid}`); bounds.push(bound);
    assert.equal(bound.staged, false);
    assert.equal(bound.identity, null);
    await bound.close();
  });

  describe('removeIfIdentity: remove a name only while it is still the same file', () => {
    const idOf = (p) => { const st = fs.lstatSync(p); return { dev: st.dev, ino: st.ino }; };

    it('removes the socket it is given the identity of, and leaves no directory behind', async () => {
      const p = path.join(dir, 'r.sock');
      const s = serverThatSays('x'); servers.push(s);
      await new Promise((r) => s.listen(p, r));
      assert.equal(await removeIfIdentity(p, idOf(p)), true);
      assert.deepEqual(fs.readdirSync(dir), []);
    });

    it('leaves a regular file, a socket with another inode, and a directory untouched', async () => {
      const p = path.join(dir, 'r.sock');
      const s = serverThatSays('x'); servers.push(s);
      await new Promise((r) => s.listen(p, r));
      const old = idOf(p);
      fs.unlinkSync(p);

      fs.writeFileSync(p, 'file');
      assert.equal(await removeIfIdentity(p, old), false);
      assert.equal(fs.readFileSync(p, 'utf8'), 'file');
      fs.unlinkSync(p);

      const t = serverThatSays('t'); servers.push(t);
      await new Promise((r) => t.listen(p, r));
      assert.equal(await removeIfIdentity(p, old), false);
      assert.equal(await answer(p), 't');

      assert.equal(await removeIfIdentity(path.join(dir, 'missing.sock'), old), false);
      fs.mkdirSync(path.join(dir, 'subdir'));
      assert.equal(await removeIfIdentity(path.join(dir, 'subdir'), old), false);
      assert.equal(fs.lstatSync(path.join(dir, 'subdir')).isDirectory(), true);
      assert.deepEqual(fs.readdirSync(dir).sort(), ['r.sock', 'subdir']);
    });

    it('a file that is not a socket is never removed even when its inode number is the one asked for', async () => {
      const p = path.join(dir, 'plain');
      fs.writeFileSync(p, 'x');
      assert.equal(await removeIfIdentity(p, idOf(p)), false);
      assert.equal(fs.readFileSync(p, 'utf8'), 'x');
    });
  });
});
