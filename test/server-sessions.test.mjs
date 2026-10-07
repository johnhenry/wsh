// test/server-sessions.test.mjs -- attach / resume / detach of `@johnhenry/wsh/server`
// sessions (#68), driven by the stock client.
//
// `seq` is the cumulative count of session output BYTES. A client counts what it
// received (`WshSession.seq`), the host replays only what follows, and the process
// is the same one throughout (its pid is printed and checked).
import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createWshServer } from '@johnhenry/wsh/server';
import { WebSocketTransport } from '../src/transport-ws.mjs';
import { WshClient, generateKeyPair, exportPublicKeySSH, MSG } from '@johnhenry/wsh';
import { ByteRing, mintToken, verifyToken } from '../src/server/sessions.mjs';

const dec = new TextDecoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 4000) {
  const t0 = Date.now();
  for (;;) {
    const v = await cond();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(10);
  }
}
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

/** A stand-in for node-pty: a child process on pipes. */
const children = new Set();
function fakeSpawn(file, args, o) {
  const child = spawn(file, args, { env: o.env, stdio: ['pipe', 'pipe', 'pipe'] });
  children.add(child);
  child.on('close', () => children.delete(child));
  child.stdin.on('error', () => {});
  return {
    pid: child.pid,
    onData: (cb) => { child.stdout.on('data', cb); child.stderr.on('data', cb); },
    onExit: (cb) => child.on('close', (code, sig) => cb({ exitCode: code ?? 128, signal: sig })),
    write: (d) => child.stdin.write(d),
    resize() {},
    kill: (sig) => child.kill(sig ?? 'SIGTERM'),
  };
}

/** Collects a session's output as text. */
function record(session) {
  const rec = { text: '', exit: undefined, closed: false };
  session.onData = (d) => { rec.text += dec.decode(d); };
  session.onExit = (c) => { rec.exit = c; };
  session.onClose = () => { rec.closed = true; };
  return rec;
}

describe('server sessions: attach / resume / detach', () => {
  let keyA; let keyB; let authorizedKeys;
  const servers = [];
  const clients = [];

  before(async () => {
    keyA = await generateKeyPair(true);
    keyB = await generateKeyPair(true);
    authorizedKeys = `${await exportPublicKeySSH(keyA.publicKey)} a\n${await exportPublicKeySSH(keyB.publicKey)} b\n`;
  });
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
    for (const c of children) c.kill('SIGKILL');
  });

  async function start(sessions = {}, extra = {}) {
    const server = createWshServer({
      auth: { authorizedKeys }, exec: true, pty: { spawn: fakeSpawn, shell: '/bin/sh' }, sessions, ...extra,
    });
    const { port } = await server.listen();
    servers.push(server);
    return `ws://127.0.0.1:${port}`;
  }
  const transports = new WeakMap();
  async function connect(url, key = keyA, username = 'alice') {
    const transport = new WebSocketTransport();
    const client = new WshClient({ transportFactories: { ws: () => transport } });
    await client.connect(url, { username, keyPair: key, transport: 'ws' });
    transports.set(client, transport);
    clients.push(client);
    return client;
  }
  /** The network goes away: the socket closes with no Close/Detach message, unlike `disconnect()`. */
  const drop = (client) => transports.get(client).close();

  const SCRIPT = 'echo pid:$$; echo first; sleep 0.3; echo second; while read l; do echo "pid:$$ $l"; done';
  const pidOf = (text) => Number(/pid:(\d+)/.exec(text)[1]);

  it('open a pty, drop the socket, resume from a fresh client: only the bytes after last_seq arrive, same process', async () => {
    const url = await start();
    const c1 = await connect(url);
    const s1 = await c1.openSession({ type: 'pty', command: SCRIPT });
    const r1 = record(s1);
    await until(() => r1.text.includes('first\n'), 'first output');
    assert.equal(r1.text, `pid:${pidOf(r1.text)}\nfirst\n`);
    assert.equal(s1.seq, Buffer.byteLength(r1.text), 'the client counts output bytes as seq');
    const pid = pidOf(r1.text);
    const { sessionId, resumeToken } = s1;
    const lastSeq = s1.seq;
    await drop(c1);                        // the socket drops; `second` is produced while detached
    await sleep(500);
    assert.ok(alive(pid), 'the process outlives its connection');

    const c2 = await connect(url);
    const presence = await c2.resumeSession(sessionId, resumeToken, { lastSeq });
    assert.equal(presence.type, MSG.PRESENCE);
    const s2 = presence.session;
    assert.ok(s2, 'the Presence carries the session built for the new channel');
    assert.equal(s2.sessionId, sessionId);
    assert.equal(s2.seq, lastSeq, 'the resumed session starts counting at last_seq');
    const r2 = record(s2);
    await until(() => r2.text === 'second\n', 'the replay');
    await s2.write('hi\n');
    await until(() => r2.text.includes(`pid:${pid} hi\n`), 'live output from the same process');
    assert.equal(r2.text, `second\npid:${pid} hi\n`, 'nothing before last_seq is repeated');
    assert.equal(s2.seq, lastSeq + Buffer.byteLength(r2.text));
  });

  it('works for an exec session too (its output, opened on a data stream, is resumed over a message channel), and reports the exit', async () => {
    const url = await start();
    const c1 = await connect(url);
    const s1 = await c1.openSession({ type: 'exec', command: 'echo one; sleep 0.3; echo two; sleep 0.3; exit 3' });
    const r1 = record(s1);
    await until(() => r1.text === 'one\n', 'one');
    const { sessionId, resumeToken } = s1;
    await drop(c1);
    await sleep(100);

    const c2 = await connect(url);
    const { session } = await c2.resumeSession(sessionId, resumeToken, { lastSeq: s1.seq });
    const r2 = record(session);
    await until(() => r2.exit !== undefined, 'the exit');
    assert.equal(r2.text, 'two\n');
    assert.equal(r2.exit, 3);
    await until(() => r2.closed, 'close');
  });

  it('a wrong, missing or foreign token is refused for Resume', async () => {
    const url = await start();
    const c1 = await connect(url);
    const s1 = await c1.openSession({ type: 'pty', command: 'sleep 5' });
    const other = await c1.openSession({ type: 'pty', command: 'sleep 5' });
    const c2 = await connect(url);
    await assert.rejects(() => c2.resumeSession(s1.sessionId, new Uint8Array(40), { lastSeq: 0 }), /Failed to resume: unknown session or not authorized/);
    await assert.rejects(() => c2.resumeSession(s1.sessionId, new Uint8Array(3), { lastSeq: 0 }), /Failed to resume/);
    await assert.rejects(() => c2.resumeSession(s1.sessionId, other.resumeToken, { lastSeq: 0 }), /Failed to resume/, "another session's token");
    await assert.rejects(() => c2.resumeSession('no-such-session', s1.resumeToken, { lastSeq: 0 }), /Failed to resume/);
    // A flipped bit anywhere in the token.
    const bent = Uint8Array.from(s1.resumeToken);
    bent[39] ^= 1;
    await assert.rejects(() => c2.resumeSession(s1.sessionId, bent, { lastSeq: 0 }), /Failed to resume/);
    // The right token, from the right principal, works.
    assert.ok((await c2.resumeSession(s1.sessionId, s1.resumeToken, { lastSeq: 0 })).session);
  });

  it('Resume needs the token AND ownership; Attach needs the token OR ownership', async () => {
    const url = await start();
    const owner = await connect(url, keyA, 'alice');
    const s = await owner.openSession({ type: 'pty', command: 'sleep 5' });
    const stranger = await connect(url, keyB, 'bob');

    await assert.rejects(() => stranger.attachSession(s.sessionId), /Failed to attach: unknown session or not authorized/);
    await assert.rejects(() => stranger.resumeSession(s.sessionId, s.resumeToken, { lastSeq: 0 }), /Failed to resume/, 'a token is not enough to Resume');
    assert.ok((await stranger.attachSession(s.sessionId, { token: s.resumeToken, readOnly: true })).session, 'a token holder may Attach');

    const again = await connect(url, keyA, 'alice');
    assert.ok((await again.attachSession(s.sessionId)).session, 'the owner may Attach without a token');
    const sameKeyOtherName = await connect(url, keyA, 'carol');
    assert.ok(sameKeyOtherName, 'sanity');
  });

  it('a detached session is killed when detachTtlMs elapses, and can no longer be resumed', async () => {
    const url = await start({ detachTtlMs: 250 });
    const c1 = await connect(url);
    const s1 = await c1.openSession({ type: 'pty', command: 'echo pid:$$; exec sleep 30' });
    const r1 = record(s1);
    await until(() => r1.text.includes('pid:'), 'pid');
    const pid = pidOf(r1.text);
    const { sessionId, resumeToken } = s1;
    await drop(c1);
    await sleep(100);
    assert.ok(alive(pid));
    await until(() => !alive(pid), 'the TTL kill', 3000);
    const c2 = await connect(url);
    await assert.rejects(() => c2.resumeSession(sessionId, resumeToken, { lastSeq: 0 }), /Failed to resume/);
  });

  it('resuming before the TTL cancels it', async () => {
    const url = await start({ detachTtlMs: 400 });
    const c1 = await connect(url);
    const s1 = await c1.openSession({ type: 'pty', command: 'echo pid:$$; exec sleep 30' });
    const r1 = record(s1);
    await until(() => r1.text.includes('pid:'), 'pid');
    const pid = pidOf(r1.text);
    await drop(c1);
    await sleep(150);
    const c2 = await connect(url);
    await c2.resumeSession(s1.sessionId, s1.resumeToken, { lastSeq: s1.seq });
    await sleep(700);
    assert.ok(alive(pid), 'still running past the original deadline');
  });

  it('detachTtlMs: 0 kills a session as soon as its connection goes', async () => {
    const url = await start({ detachTtlMs: 0 });
    const c1 = await connect(url);
    const s1 = await c1.openSession({ type: 'pty', command: 'echo pid:$$; exec sleep 30' });
    const r1 = record(s1);
    await until(() => r1.text.includes('pid:'), 'pid');
    const pid = pidOf(r1.text);
    await drop(c1);
    await until(() => !alive(pid), 'immediate kill', 2000);
  });

  it('maxDetached evicts the longest-detached session', async () => {
    const url = await start({ maxDetached: 2, detachTtlMs: 60_000 });
    const pids = [];
    for (let i = 0; i < 3; i++) {
      const c = await connect(url);
      const s = await c.openSession({ type: 'pty', command: 'echo pid:$$; exec sleep 30' });
      const r = record(s);
      await until(() => r.text.includes('pid:'), 'pid');
      pids.push(pidOf(r.text));
      await drop(c);
      await sleep(30);
    }
    await until(() => !alive(pids[0]), 'eviction of the oldest', 2000);
    assert.ok(alive(pids[1]) && alive(pids[2]));
  });

  it('a ring overflow is reported as a gap by Resume; Attach still gets the retained tail', async () => {
    const url = await start({ ringBytes: 64 });
    const c1 = await connect(url);
    // 200 bytes of output while nobody is attached.
    const s1 = await c1.openSession({ type: 'pty', command: 'echo ready; sleep 0.3; i=0; while [ $i -lt 20 ]; do echo 123456789; i=$((i+1)); done; exec sleep 30' });
    const r1 = record(s1);
    await until(() => r1.text === 'ready\n', 'ready');
    const { sessionId, resumeToken } = s1;
    const lastSeq = s1.seq;
    await drop(c1);
    await sleep(600);

    const c2 = await connect(url);
    await assert.rejects(() => c2.resumeSession(sessionId, resumeToken, { lastSeq }), /Failed to resume: output gap: .*starts at seq 142.*last_seq is 6/);
    const { session } = await c2.attachSession(sessionId, { token: resumeToken });
    assert.equal(session.seq, 142, 'Attach starts at the oldest retained byte (206 produced, 64 kept)');
    const r2 = record(session);
    await until(() => Buffer.byteLength(r2.text) === 64, 'the retained tail');
    assert.equal(session.seq, 206);
    assert.ok(/^[\n0-9]+$/.test(r2.text));
    // A position past what the session has produced is refused as well.
    const c3 = await connect(url);
    await assert.rejects(() => c3.resumeSession(sessionId, resumeToken, { lastSeq: 9999 }), /ahead of the session/);
  });

  it('listRemoteSessions() shows the principal\'s sessions only', async () => {
    const url = await start();
    const a = await connect(url, keyA, 'alice');
    const s = await a.openSession({ type: 'pty', command: 'sleep 5' });
    const listed = await a.listRemoteSessions();
    assert.equal(listed.length, 1);
    assert.equal(listed[0].session_id, s.sessionId);
    assert.equal(listed[0].username, 'alice');
    assert.equal(listed[0].attached_count, 1);
    assert.equal(listed[0].fingerprint_short.length, 8);
    const b = await connect(url, keyB, 'bob');
    assert.deepEqual(await b.listRemoteSessions(), []);
    // After a drop the session is still listed, now with nobody attached.
    await drop(a);
    const a2 = await connect(url, keyA, 'alice');
    const again = await a2.listRemoteSessions();
    assert.equal(again.length, 1);
    assert.equal(again[0].attached_count, 0);
  });

  it('detach() leaves the process running, and the session can be resumed later', async () => {
    const url = await start();
    const c = await connect(url);
    const s = await c.openSession({ type: 'pty', command: SCRIPT });
    const r = record(s);
    await until(() => r.text.includes('first\n'), 'first');
    const pid = pidOf(r.text);
    const seq = s.seq;
    await c.detach(s.sessionId);
    await until(() => r.closed, 'the local channel to close');
    await assert.rejects(() => c.detach(s.sessionId), /Failed to detach/, 'no longer attached');
    await sleep(500);
    assert.ok(alive(pid));
    const { session } = await c.resumeSession(s.sessionId, s.resumeToken, { lastSeq: seq });
    const r2 = record(session);
    await until(() => r2.text === 'second\n', 'second');
  });

  it('a graceful disconnect() ends the session (it sends Close); detach() first keeps it', async () => {
    const url = await start();
    const c1 = await connect(url);
    const s1 = await c1.openSession({ type: 'pty', command: 'echo pid:$$; exec sleep 30' });
    const r1 = record(s1);
    await until(() => r1.text.includes('pid:'), 'pid');
    const gone = pidOf(r1.text);
    await c1.disconnect();
    await until(() => !alive(gone), 'Close ending the process even though the socket closed right behind it', 2000);

    const c2 = await connect(url);
    const s2 = await c2.openSession({ type: 'pty', command: 'echo pid:$$; exec sleep 30' });
    const r2 = record(s2);
    await until(() => r2.text.includes('pid:'), 'pid');
    const kept = pidOf(r2.text);
    await c2.detach(s2.sessionId);
    await c2.disconnect();
    await sleep(300);
    assert.ok(alive(kept), 'a detached session survives a graceful disconnect');
    const c3 = await connect(url);
    assert.ok((await c3.resumeSession(s2.sessionId, s2.resumeToken, { lastSeq: s2.seq })).session);
  });

  it('several connections can attach: output fans out, a readonly attachment cannot write, and Presence tells everyone', async () => {
    const url = await start();
    const owner = await connect(url);
    const s = await owner.openSession({ type: 'pty', command: 'echo pid:$$; while read l; do echo "pid:$$ $l"; done' });
    const ro = record(s);
    await until(() => ro.text.includes('pid:'), 'pid');
    const pid = pidOf(ro.text);

    const presences = [];
    owner.addControlListener((m) => { if (m.type === MSG.PRESENCE) presences.push(m); });

    const viewer = await connect(url);
    const view = await viewer.attachSession(s.sessionId, { readOnly: true });
    assert.equal(view.attachments[0].mode, 'readonly');
    assert.equal(view.attachments[0].channel_id, view.session.channelId);
    assert.deepEqual(view.attachments.slice(1).map((a) => [a.mode, a.channel_id]), [['control', undefined]], 'then the others, without channel ids');
    const rv = record(view.session);
    await until(() => rv.text === `pid:${pid}\n`, 'the replay to the viewer');

    const driver = await connect(url);
    const drive = await driver.attachSession(s.sessionId);
    const rd = record(drive.session);
    await until(() => rd.text === `pid:${pid}\n`, 'the replay to the driver');

    await until(() => presences.length >= 2, 'presence broadcasts');
    assert.deepEqual(presences.at(-1).attachments.map((a) => a.mode).sort(), ['control', 'control', 'readonly']);

    await view.session.write('from-viewer\n');                    // dropped
    await drive.session.write('from-driver\n');
    const line = `pid:${pid} from-driver\n`;
    await until(() => ro.text.endsWith(line) && rv.text.endsWith(line) && rd.text.endsWith(line), 'fan-out');
    await sleep(100);
    assert.ok(!ro.text.includes('from-viewer'), 'a readonly attachment\'s input never reaches the process');

    // The viewer leaves; everyone else is told.
    const before = presences.length;
    await viewer.detach(s.sessionId);
    await until(() => presences.length > before, 'presence after detach');
    assert.deepEqual(presences.at(-1).attachments.map((a) => a.mode).sort(), ['control', 'control']);
  });

  it('closing the channel ends the session for its owner, but only detaches anyone else', async () => {
    const url = await start();
    const owner = await connect(url);
    const s = await owner.openSession({ type: 'pty', command: 'echo pid:$$; exec sleep 30' });
    const r = record(s);
    await until(() => r.text.includes('pid:'), 'pid');
    const pid = pidOf(r.text);

    const guest = await connect(url, keyB, 'bob');
    const { session } = await guest.attachSession(s.sessionId, { token: s.resumeToken });
    await session.close();
    await sleep(200);
    assert.ok(alive(pid), 'a guest closing its channel does not end the session');
    assert.equal((await owner.listRemoteSessions())[0].attached_count, 1);

    await s.close();
    await until(() => !alive(pid), 'the owner\'s close ending the process');
  });

  it('a client without the new Attach/Resume session support still gets the data (on the control stream)', async () => {
    const url = await start();
    const c1 = await connect(url);
    const s1 = await c1.openSession({ type: 'pty', command: SCRIPT });
    const r1 = record(s1);
    await until(() => r1.text.includes('first\n'), 'first');
    const { sessionId, resumeToken } = s1;
    const lastSeq = s1.seq;
    await drop(c1);
    await sleep(500);

    // Observe the raw control messages, as any client would.
    const c2 = await connect(url);
    const seen = [];
    c2.addControlListener((m) => seen.push(m));
    const presence = await c2.resumeSession(sessionId, resumeToken, { lastSeq });
    const own = presence.attachments[0];
    assert.equal(typeof own.channel_id, 'number');
    assert.equal(own.seq, lastSeq);
    await until(() => seen.some((m) => m.type === MSG.SESSION_DATA), 'SessionData');
    const data = seen.filter((m) => m.type === MSG.SESSION_DATA);
    assert.ok(data.every((m) => m.channel_id === own.channel_id));
    assert.equal(dec.decode(Buffer.concat(data.map((m) => m.data))), 'second\n');
  });

  it('without the `sessions` option, Attach/Resume are answered (not ignored) and nothing survives a disconnect', async () => {
    const server = createWshServer({ auth: { authorizedKeys }, pty: { spawn: fakeSpawn, shell: '/bin/sh' } });
    const { port } = await server.listen();
    servers.push(server);
    const url = `ws://127.0.0.1:${port}`;
    const c1 = await connect(url);
    const s = await c1.openSession({ type: 'pty', command: 'echo pid:$$; exec sleep 30' });
    const r = record(s);
    await until(() => r.text.includes('pid:'), 'pid');
    const pid = pidOf(r.text);
    await assert.rejects(() => c1.resumeSession(s.sessionId, s.resumeToken, { lastSeq: 0 }), /not enabled/);
    await assert.rejects(() => c1.attachSession(s.sessionId), /not enabled/);
    assert.deepEqual(await c1.listRemoteSessions(), []);
    await drop(c1);
    await until(() => !alive(pid), 'the session dying with its connection', 2000);
  });

  it('plain exec still runs to completion with sessions enabled', async () => {
    const url = await start();
    const { stdout, exitCode } = await WshClient.exec(url, 'echo hello', { username: 'alice', keyPair: keyA, timeout: 5000 });
    assert.equal(dec.decode(stdout), 'hello\n');
    assert.equal(exitCode, 0);
  });

  it('sessionSecret fixes the key tokens are minted with, so they can be checked across restarts', async () => {
    const url = await start({ sessionSecret: 'stable-secret' });
    const c = await connect(url);
    const s = await c.openSession({ type: 'pty', command: 'sleep 5' });
    assert.ok(verifyToken(Buffer.from('stable-secret'), s.sessionId, s.resumeToken));
    assert.ok(!verifyToken(Buffer.from('another-secret'), s.sessionId, s.resumeToken));
    // The top-level alias is the same option.
    const url2 = await start({}, { sessionSecret: 'alias-secret' });
    const c2 = await connect(url2);
    const s2 = await c2.openSession({ type: 'pty', command: 'sleep 5' });
    assert.ok(verifyToken(Buffer.from('alias-secret'), s2.sessionId, s2.resumeToken));
  });

  it('a hosted exec session keeps its own stdin, output and exit code on the opening connection', async () => {
    const url = await start();
    const c = await connect(url);
    const s = await c.openSession({ type: 'exec', command: 'read x; echo "got:$x"; exit 7' });
    const r = record(s);
    await s.write('hello\n');
    await until(() => r.exit !== undefined, 'exit');
    assert.equal(r.text, 'got:hello\n');
    assert.equal(r.exit, 7);
    await until(() => r.closed, 'close');
  });

  it('closing the server kills hosted sessions', async () => {
    const url = await start();
    const c = await connect(url);
    const s = await c.openSession({ type: 'pty', command: 'echo pid:$$; exec sleep 30' });
    const r = record(s);
    await until(() => r.text.includes('pid:'), 'pid');
    const pid = pidOf(r.text);
    await servers.pop().close();
    await until(() => !alive(pid), 'the server shutdown kill', 2000);
  });
});

describe('session tokens and the ring buffer', () => {
  it('tokens are 40 bytes (8B expiry + HMAC-SHA256), bound to the session id and the secret', () => {
    const t = mintToken('secret', 'sess-1');
    assert.equal(t.byteLength, 40);
    assert.ok(verifyToken('secret', 'sess-1', t));
    assert.ok(!verifyToken('secret', 'sess-2', t), 'another session');
    assert.ok(!verifyToken('other', 'sess-1', t), 'another secret');
    assert.ok(!verifyToken('secret', 'sess-1', t.subarray(0, 39)), 'truncated');
    assert.ok(!verifyToken('secret', 'sess-1', 'x'));
    const expired = Uint8Array.from(t);
    expired.fill(0, 0, 8);
    assert.ok(!verifyToken('secret', 'sess-1', expired), 'a forged expiry fails the MAC (and is in the past)');
  });

  it('ByteRing keeps the newest bytes and addresses them by absolute position', () => {
    const ring = new ByteRing(10);
    ring.push(Uint8Array.of(1, 2, 3, 4));
    ring.push(Uint8Array.of(5, 6, 7, 8, 9, 10, 11, 12));
    assert.equal(ring.start, 2);
    assert.equal(ring.end, 12);
    assert.deepEqual([...ring.read()], [3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert.deepEqual([...ring.read(7)], [8, 9, 10, 11, 12]);
    assert.deepEqual([...ring.read(12)], []);
    assert.deepEqual([...ring.read(0)], [3, 4, 5, 6, 7, 8, 9, 10, 11, 12], 'before the start clamps to it');
  });
});
