// test/gateway-half-close-abort.test.mjs -- a side that has already half-closed (sent its GatewayClose, still reading) and then
// loses its reader (destroy(), a stream cancelled, a local socket that went away) tells the peer, as a TCP reset tells a sender
// its reader is gone. Before, destroy() after a half-close put nothing on the wire, so with `halfCloseIdleMs: 0` a silent
// connection was never reaped while the session lived.
//
// The signal is a SECOND GatewayClose with the reason "discarded" on a connection whose close this side already sent. A peer that
// predates it ignores a second close for a connection it already saw closed (see "older peers" below).
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { generateKeyPair, exportPublicKeySSH, WshClient } from '@johnhenry/wsh';
import { GatewayChannel } from '../src/gateway-channel.mjs';
import { fixture, until, sleep, listen } from './gateway-fixture.mjs';

const CHILD = fileURLToPath(new URL('./gateway-half-close-abort-child.mjs', import.meta.url));
const stateAfter = (closed, ms) => Promise.race([closed, sleep(ms).then(() => 'open')]);

/** A channel with nothing behind it: it records what it would put on the wire. */
function mk(o = {}) {
  const sent = { close: [], data: 0 };
  const events = { closed: [], remote: [] };
  const ch = new GatewayChannel({
    id: 1, credit: true, writeAfterRemoteClose: true, halfCloseIdleMs: 0,
    sendData: async (b) => { sent.data += b.byteLength; },
    sendCredit: () => {},
    sendClose: (r) => { sent.close.push(r); },
    onClose: (r) => events.closed.push(r),
    onRemoteClose: (r) => events.remote.push(r),
    ...o,
  });
  return { ch, sent, events };
}

describe('GatewayChannel: a destroy after our own half-close is told to the peer', () => {
  it('end() then destroy() sends a second GatewayClose with "discarded", once', () => {
    const { ch, sent } = mk();
    ch.end();
    assert.deepEqual(sent.close, [undefined]);
    ch.destroy();
    assert.deepEqual(sent.close, [undefined, 'discarded']);
    ch.destroy();
    ch.abandon();
    assert.equal(sent.close.length, 2, 'only once');
    assert.equal(ch.closed, true);
  });

  it('whatever reason the destroy has, the second close says "discarded" (the receiver acts on that one word)', () => {
    const { ch, sent } = mk();
    ch.end('done');
    ch.destroy('idle timeout');
    assert.deepEqual(sent.close, ['done', 'discarded']);
  });

  it('a cancelled readable after a closed writable is the same abort', async () => {
    const { ch, sent } = mk();
    const { readable, writable } = ch.streams();
    await writable.getWriter().close();
    await readable.cancel();
    assert.deepEqual(sent.close, [undefined, 'discarded']);
  });

  it('nothing extra when the peer had already closed: that connection is over once both closes are in', () => {
    const { ch, sent } = mk();
    ch.end();
    ch.remoteClosed();
    assert.equal(ch.closed, true);
    ch.destroy();
    assert.deepEqual(sent.close, [undefined]);
    // ...also when the peer's close arrived with data nobody has read yet (the connection is not finished until it is read)
    const b = mk();
    b.ch.end();
    b.ch.receive(new Uint8Array(3));
    b.ch.remoteClosed();
    assert.equal(b.ch.closed, false);
    b.ch.destroy();
    assert.deepEqual(b.sent.close, [undefined]);
  });

  it('abandon() (the transport is gone) stays silent', () => {
    const { ch, sent } = mk();
    ch.end();
    ch.abandon('connection closed');
    assert.deepEqual(sent.close, [undefined]);
  });

  it('destroy() with no half-close first is unchanged: one close, "discarded"', () => {
    const { ch, sent } = mk();
    ch.destroy();
    assert.deepEqual(sent.close, ['discarded']);
  });
});

describe('GatewayChannel: a second "discarded" from a peer that had half-closed ends our direction at once', () => {
  it('peer close, then peer "discarded": our writers fail, the connection finishes, nothing goes back', async () => {
    const { ch, sent, events } = mk();
    ch.remoteClosed(); // a plain half-close: we may go on sending
    assert.equal(ch.closed, false);
    await ch.write(new Uint8Array(4));
    ch.remoteClosed('discarded'); // its reader is gone
    assert.equal(ch.closed, true);
    assert.deepEqual(events.closed, ['discarded']);
    assert.deepEqual(sent.close, [], 'we owe it nothing: it reads nothing more');
    await assert.rejects(ch.write(new Uint8Array(4)));
  });

  it('what the peer sent and nothing has read does not keep the connection open (an application that never reads)', () => {
    const { ch, events } = mk();
    ch.receive(new Uint8Array(10));
    ch.remoteClosed();
    ch.remoteClosed('discarded');
    assert.equal(ch.closed, true);
    assert.equal(ch.queuedBytes, 0);
    assert.deepEqual(events.closed, ['discarded']);
  });

  it('a writer parked on credit is woken with an error', async () => {
    const { ch } = mk({ window: 8 });
    ch.remoteClosed();
    const parked = ch.write(new Uint8Array(64)).then(() => 'wrote', (e) => e.message);
    await sleep(10);
    ch.remoteClosed('discarded');
    assert.match(await parked, /closed/);
  });

  it('a second close WITHOUT the reason is still ignored (a peer that duplicates its close is not an abort)', () => {
    const { ch, sent } = mk();
    ch.remoteClosed();
    ch.remoteClosed();
    ch.remoteClosed('idle timeout');
    assert.equal(ch.closed, false);
    assert.deepEqual(sent.close, []);
  });

  it('the idle bound still applies to a plain half-close, and the discard ends it before that', async () => {
    const { ch, events } = mk({ halfCloseIdleMs: 60_000 });
    ch.remoteClosed();
    ch.remoteClosed('discarded');
    assert.deepEqual(events.closed, ['discarded']);
  });

  it('a first-time "discarded" is unchanged (already the rule)', () => {
    const { ch, sent, events } = mk();
    ch.remoteClosed('discarded');
    assert.equal(ch.closed, true);
    assert.deepEqual(sent.close, []);
    assert.deepEqual(events.closed, ['discarded']);
  });
});

describe('end to end: the peer of a half-closed side that is destroyed learns of it, with the idle bound off', () => {
  let keyPair; let authorizedKeys;
  const hosts = [];
  afterEach(async () => { for (const h of hosts.splice(0)) await h.close(); });
  const ensureKeys = async () => { keyPair ??= await generateKeyPair(true); authorizedKeys ??= `${await exportPublicKeySSH(keyPair.publicKey)} u`; };

  it('client half-closes, then destroys: the host endpoint\'s stream ends at once instead of being held for ever', async () => {
    await ensureKeys();
    const seen = [];
    const host = createMemoryHost({ auth: { authorizedKeys }, endpoints: { quiet: (d) => { seen.push(d); } }, gatewayHalfCloseIdleMs: 0 });
    hosts.push(host);
    const client = await host.connect({ username: 'u', keyPair });
    const d = await client.openEndpoint('quiet');
    await d.writable.getWriter().close();
    assert.equal(await stateAfter(seen[0].closed, 150), 'open', 'a half-closed silent stream is held (the bound is off)');
    d.destroy();
    assert.equal(await seen[0].closed, 'discarded');
    await client.disconnect().catch(() => {});
  });

  it('host endpoint half-closes, then destroys: the client\'s connection ends at once', async () => {
    await ensureKeys();
    const host = createMemoryHost({
      auth: { authorizedKeys }, gatewayHalfCloseIdleMs: 0,
      endpoints: { talk: async (d) => { await d.writable.getWriter().close(); setTimeout(() => d.destroy(), 100); } },
    });
    hosts.push(host);
    const client = await host.connect({ username: 'u', keyPair, gatewayHalfCloseIdleMs: 0 });
    const d = await client.openEndpoint('talk');
    assert.equal(await d.closed, 'discarded');
    await client.disconnect().catch(() => {});
  });

  it('a Node server: the slot of a TCP connection is freed when its client half-closes and destroys', async () => {
    const fx = fixture();
    try {
      const origin = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.resume(); });
      const port = await listen(origin); fx.nets.push(origin);
      const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`], halfCloseIdleMs: 0, maxConnections: 1 });
      const d = await client.openTcp('127.0.0.1', port);
      await d.writable.getWriter().close();
      await assert.rejects(client.openTcp('127.0.0.1', port), /too many/, 'the half-closed connection holds the only slot');
      d.destroy();
      await until(async () => { try { (await client.openTcp('127.0.0.1', port)).destroy(); return true; } catch { return false; } }, 'the slot to be freed');
    } finally { await fx.teardown(); }
  });

  it('a Node server: an origin that half-closed and is then gone ends the client\'s connection once the client writes', async () => {
    const fx = fixture();
    try {
      let gone;
      const goneP = new Promise((r) => { gone = r; });
      const origin = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.on('close', gone); s.end(); setTimeout(() => s.destroy(), 50); });
      const port = await listen(origin); fx.nets.push(origin);
      const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`], halfCloseIdleMs: 0 });
      const d = await client.openTcp('127.0.0.1', port);
      await goneP;
      assert.equal(await pokeUntilClosed(d), 'discarded');
    } finally { await fx.teardown(); }
  });
});

/**
 * A half-closed peer that vanished is only seen by the transport when something is written to it (a FIN already received tells
 * nothing about a later close): write a byte now and then until the connection ends, and say how it ended.
 */
async function pokeUntilClosed(d, ms = 8000) {
  const w = d.writable.getWriter();
  const t0 = Date.now();
  let closed;
  void d.closed.then((r) => { closed = r ?? 'closed'; });
  while (closed === undefined && Date.now() - t0 < ms) { await w.write(new Uint8Array(1)).catch(() => {}); await sleep(20); }
  return closed ?? 'open';
}

describe('forwards: a local program that half-closes and is then killed ends the connection on the host', () => {
  let dir; const procs = []; const forwards = [];
  const fx = fixture();
  const tmp = () => { dir ??= fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-ha-')); return fs.realpathSync(dir); };
  afterEach(async () => {
    for (const p of procs.splice(0)) p.kill('SIGKILL');
    for (const f of forwards.splice(0)) await f.close().catch(() => {});
    await fx.teardown();
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; } // a directory this test made
  });

  /** A local program that connects, sends `hello`, half-closes, then reads and says nothing more until it is killed. */
  async function startChild(target) {
    const child = spawn(process.execPath, [CHILD, ...target], { stdio: ['ignore', 'pipe', 'inherit'] });
    procs.push(child);
    await new Promise((resolve, reject) => {
      let buf = '';
      child.stdout.on('data', (d) => { buf += d; if (buf.includes('half-closed')) resolve(); });
      child.once('exit', () => reject(new Error('the local program exited early')));
    });
    return child;
  }
  const killed = (child) => new Promise((r) => { child.once('exit', r); child.kill('SIGKILL'); });

  async function quietEndpointHost() {
    const keyPair = await generateKeyPair(true);
    const authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} u`;
    const seen = [];
    const server = createWshServer({ auth: { authorizedKeys }, gateway: { allow: [], tcp: false, halfCloseIdleMs: 0, endpoints: { quiet: (d) => { seen.push(d); } } } });
    const { port } = await server.listen();
    fx.servers.push(server);
    const client = new WshClient();
    await client.connect(`ws://127.0.0.1:${port}`, { username: 'u', keyPair });
    fx.clients.push(client);
    return { client, seen };
  }

  it('forwardEndpoint: the endpoint\'s stream ends when the local program is killed after its half-close', async () => {
    const { client, seen } = await quietEndpointHost();
    const local = path.join(tmp(), 'e.sock');
    forwards.push(await client.forwardEndpoint({ local, endpoint: 'quiet' }));
    const child = await startChild(['unix', local]);
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    assert.equal(await stateAfter(seen[0].closed, 200), 'open');
    await killed(child);
    // The kernel tells a socket whose peer half-closed and then died nothing until something is written to it.
    assert.equal(await pokeUntilClosed(seen[0]), 'discarded');
  });

  it('forwardUnix to an endpoint, over a local TCP port: the same', async () => {
    const { client, seen } = await quietEndpointHost();
    const fwd = await client.forwardUnix({ local: '127.0.0.1:0', remote: 'endpoint=quiet' });
    forwards.push(fwd);
    const child = await startChild(['tcp', String(fwd.address.port)]);
    await until(() => seen.length === 1, 'the endpoint to see the connection');
    await killed(child);
    assert.equal(await pokeUntilClosed(seen[0]), 'discarded');
  });

  it('forwardUnix to a TCP origin: the host\'s slot is freed once the origin writes to the dead program', async () => {
    const origins = [];
    const origin = net.createServer({ allowHalfOpen: true }, (s) => { origins.push(s); s.on('error', () => {}); s.resume(); });
    const port = await listen(origin); fx.nets.push(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`], halfCloseIdleMs: 0, maxConnections: 1 });
    const local = path.join(tmp(), 't.sock');
    forwards.push(await client.forwardUnix({ local, remote: `127.0.0.1:${port}` }));
    const child = await startChild(['unix', local]);
    await until(() => origins.length === 1 && origins[0].readableEnded, 'the origin to see the FIN');
    await assert.rejects(client.openTcp('127.0.0.1', port), /too many/, 'the forward holds the only slot');
    await killed(child);
    const poke = setInterval(() => origins[0].write('x'), 20);
    try {
      await until(async () => { try { (await client.openTcp('127.0.0.1', port)).destroy(); return true; } catch { return false; } }, 'the slot to be freed');
    } finally { clearInterval(poke); }
  });

  it('a reverse forward: the host closes the caller\'s connection once the local service, which half-closed, is gone and the caller writes', async () => {
    const services = [];
    const service = net.createServer({ allowHalfOpen: true }, (s) => { services.push(s); s.on('error', () => {}); s.end(); });
    const servicePort = await listen(service); fx.nets.push(service);
    const hostSock = path.join(tmp(), 'r.sock');
    const { client } = await fx.setup({ allow: [], unix: { listen: [hostSock] }, halfCloseIdleMs: 0 });
    forwards.push(await client.forwardUnix({ local: `127.0.0.1:${servicePort}`, remote: hostSock, reverse: true }));
    const caller = net.connect({ path: hostSock, allowHalfOpen: true });
    caller.on('error', () => {});
    const callerClosed = new Promise((r) => caller.on('close', r));
    await until(() => services.length === 1, 'the local service to see the connection');
    services[0].destroy();
    const poke = setInterval(() => { if (!caller.destroyed) caller.write('x'); }, 20);
    try {
      assert.notEqual(await stateAfter(callerClosed.then(() => 'closed'), 8000), 'open', 'the host\'s end of the caller\'s connection was closed');
    } finally { clearInterval(poke); caller.destroy(); }
  });
});
