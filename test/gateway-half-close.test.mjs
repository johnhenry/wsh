// test/gateway-half-close.test.mjs -- a half-close in one direction does not end the other (#271).
//
// GatewayClose means "I will send no more"; the sender keeps receiving. A connection is over when both sides have sent one,
// on an error, or when nothing has moved in EITHER direction for `halfCloseIdleMs` (default 5 minutes; 0 turns it off).
// There used to be fixed timers instead (one second on the host after the client's close, five on the client), so what the
// far side sent later than that was lost while the client saw a normal end of stream.
//
// Layers: the channel on a mocked clock; the host against real origins (TCP and unix); an older host and an older client
// pinned at the message level. Local and reverse forwards are in test/forward-half-close.test.mjs.
import { describe, it, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { MSG } from '@johnhenry/wsh';
import { GatewayChannel } from '../src/gateway-channel.mjs';
import { GatewayConnections } from '../src/gateway-client.mjs';
import { normalizeGateway } from '../src/server/gateway.mjs';
import { fixture, until, sleep, listen } from './gateway-fixture.mjs';

const MiB = 1024 * 1024;
const enc = new TextEncoder();
const frame = (n) => new Uint8Array(n).fill(7);
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const bulk = (n) => { const b = Buffer.alloc(n); for (let i = 0; i < b.length; i += 4096) b.writeUInt32LE(i, i); return b; };

/** Read a duplex to its end. */
async function readAll(duplex) {
  const chunks = [];
  const reader = duplex.readable.getReader();
  for (;;) { const { value, done } = await reader.read(); if (done) break; chunks.push(value); }
  return Buffer.concat(chunks);
}

/**
 * An origin that, once the client has half-closed, waits `delayMs` and then answers with `reply` (a string or a Buffer) and
 * closes. `state.sawEnd` is when it saw the FIN; `state.sock` the connection.
 */
function delayedOrigin(delayMs, reply, state = {}) {
  return net.createServer({ allowHalfOpen: true }, (s) => {
    state.sock = s;
    s.on('error', () => {});
    s.on('end', () => { state.sawEnd = Date.now(); setTimeout(() => { if (!s.destroyed) s.end(reply); }, delayMs); });
    s.resume();
  });
}

describe('GatewayChannel: the half-closed idle rule on a mocked clock', () => {
  const IDLE = 60_000;
  afterEach(() => mock.timers.reset());
  const mk = (o = {}) => {
    mock.timers.reset();
    mock.timers.enable({ apis: ['setTimeout', 'Date'] });
    const sent = { data: 0, close: [], credit: [] };
    const ch = new GatewayChannel({
      id: 1, credit: true, writeAfterRemoteClose: true, halfCloseIdleMs: IDLE,
      sendData: async (b) => { sent.data += b.byteLength; },
      sendCredit: (n) => { sent.credit.push(n); },
      sendClose: (r) => { sent.close.push(r); },
      ...o,
    });
    return { ch, sent };
  };

  it('the peer half-closing does not end our direction: we write long after, and nothing closes', async () => {
    const { ch, sent } = mk();
    ch.remoteClosed();
    mock.timers.tick(IDLE - 1);
    await ch.write(frame(1000));
    assert.equal(sent.data, 1000);
    assert.equal(ch.closed, false);
    assert.deepEqual(sent.close, [], 'we did not send a GatewayClose of our own');
  });

  it('our half-closing does not end the peer\'s direction: its data is accepted long after', async () => {
    const { ch, sent } = mk();
    const reader = ch.streams().readable.getReader();
    ch.end();
    mock.timers.tick(IDLE - 1);
    ch.receive(frame(10));
    assert.equal((await reader.read()).value.length, 10);
    assert.equal(ch.closed, false);
    assert.deepEqual(sent.close, [undefined], 'one GatewayClose, ours');
  });

  it('both sides finished: over at once, no timer involved', () => {
    const { ch } = mk();
    ch.end();
    ch.remoteClosed();
    assert.equal(ch.closed, true);
  });

  it('half-closed and quiet in both directions for halfCloseIdleMs: ended, with a reason', () => {
    const { ch, sent } = mk();
    ch.end();
    mock.timers.tick(IDLE - 1);
    assert.equal(ch.closed, false, 'not sooner');
    mock.timers.tick(1);
    assert.equal(ch.closed, true);
    // Our close went out at end(); the peer has not closed and still holds its direction for us, so the bound's end is told
    // to it as a second close saying "discarded" (before it was silent: with the peer's own bound at 0 it was held for ever).
    assert.deepEqual(sent.close, [undefined, 'discarded']);
  });

  it('a peer that half-closed and never reads: our writes stall for credit, nothing moves, and the idle rule ends it', async () => {
    const { ch, sent } = mk({ window: 1000 });
    ch.remoteClosed();
    const w = ch.write(frame(5000)).catch((e) => e); // sends 1000, then waits for credit that never comes
    await Promise.resolve();
    mock.timers.tick(IDLE - 1);
    assert.equal(ch.closed, false, 'not sooner');
    mock.timers.tick(1);
    assert.equal(ch.closed, true);
    assert.match(String(await w), /closed/);
    assert.equal(sent.close[0], 'idle timeout', 'the host told the peer why');
  });

  it('bytes in EITHER direction restart the idle clock', async () => {
    const { ch } = mk({ onData() {} });
    ch.end();
    mock.timers.tick(IDLE - 100);
    ch.receive(frame(5)); // from the peer
    mock.timers.tick(IDLE - 100);
    ch.consumed(5); // the application taking it
    mock.timers.tick(IDLE - 100);
    assert.equal(ch.closed, false);
    mock.timers.tick(100);
    assert.equal(ch.closed, true);
    const b = mk();
    b.ch.remoteClosed();
    mock.timers.tick(IDLE - 100);
    await b.ch.write(frame(5)); // ours
    mock.timers.tick(IDLE - 100);
    b.ch.grant(10); // the peer reading and returning credit
    mock.timers.tick(IDLE - 100);
    assert.equal(b.ch.closed, false);
    mock.timers.tick(100);
    assert.equal(b.ch.closed, true);
  });

  it('a peer that discarded the connection (destroy, no reason) says so, and we end our direction at once; a half-close does not', async () => {
    const a = mk();
    a.ch.destroy();
    assert.deepEqual(a.sent.close, ['discarded']);
    const b = mk({ window: 1000 });
    const w = b.ch.write(frame(5000)).catch((e) => e); // waits for credit
    b.ch.remoteClosed('discarded');
    assert.equal(b.ch.closed, true, 'nothing queued: over');
    assert.match(String(await w), /closed/);
    assert.deepEqual(b.sent.close, [], 'nothing goes back');
    const c = mk();
    c.ch.remoteClosed(); // a plain GatewayClose is a half-close
    assert.equal(c.ch.closed, false);
    await c.ch.write(frame(10));
  });

  it('halfCloseIdleMs: 0 turns the rule off', () => {
    const { ch } = mk({ halfCloseIdleMs: 0 });
    ch.end();
    mock.timers.tick(7 * 24 * 3600 * 1000);
    assert.equal(ch.closed, false);
  });

  it('a connection that is not half-closed has no idle bound of this kind', () => {
    const { ch } = mk();
    mock.timers.tick(10 * IDLE);
    assert.equal(ch.closed, false);
  });
});

describe('the Node host: a half-close does not end the other direction', () => {
  const fx = fixture();
  let dir;
  const tmp = () => { dir ??= fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-hc-')); return fs.realpathSync(dir); };
  afterEach(async () => {
    await fx.teardown();
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; } // a directory this test made
  });
  const serve = async (server) => { const port = await listen(server); fx.nets.push(server); return port; };

  it('TCP: an answer sent 6 s after the client half-closed arrives whole', async () => {
    const st = {};
    const port = await serve(delayedOrigin(6000, 'done\n', st));
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`] });
    const duplex = await client.openTcp('127.0.0.1', port);
    await duplex.writable.getWriter().close(); // nothing to send: half-close at once, keep reading
    const got = await readAll(duplex);
    assert.equal(got.toString(), 'done\n');
    assert.ok(Date.now() - st.sawEnd >= 5900, 'the answer really was late');
  });

  it('unix socket: an answer sent 2.5 s after the half-close arrives whole', async () => {
    const t = tmp();
    const server = delayedOrigin(2500, 'unix done\n');
    await new Promise((r) => server.listen(`${t}/o.sock`, r)); fx.nets.push(server);
    const { client } = await fx.setup({ allow: [], unix: { connect: [`${t}/o.sock`] } });
    const duplex = await client.openUnix(`${t}/o.sock`);
    await duplex.writable.getWriter().close();
    assert.equal((await readAll(duplex)).toString(), 'unix done\n');
  });

  it('a 20 MiB answer after the half-close arrives whole, with backpressure while the reader is not reading', async () => {
    const data = bulk(20 * MiB);
    const st = {};
    const origin = net.createServer({ allowHalfOpen: true }, (s) => {
      st.sock = s; s.on('error', () => {});
      s.on('end', () => { st.flushed = false; s.end(data, () => { st.flushed = true; }); });
      s.resume();
    });
    const port = await serve(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`] });
    const duplex = await client.openTcp('127.0.0.1', port);
    await duplex.writable.getWriter().close();
    await sleep(1500); // longer than the old one-second limit, and nobody reads
    assert.equal(st.flushed, false, 'the origin is held back by credit while nothing reads');
    assert.ok(st.sock.writableLength > 4 * MiB, `the origin still has most of it queued (${st.sock.writableLength})`);
    const got = await readAll(duplex);
    assert.equal(got.length, data.length);
    assert.equal(sha(got), sha(data));
  });

  it('both sides half-close: the connection ends promptly, not by a timer', async () => {
    const port = await serve(delayedOrigin(0, ''));
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`], halfCloseIdleMs: 600_000 });
    const duplex = await client.openTcp('127.0.0.1', port);
    const t0 = Date.now();
    await duplex.writable.getWriter().close();
    assert.equal((await readAll(duplex)).length, 0);
    await duplex.closed;
    assert.ok(Date.now() - t0 < 2000, `ended in ${Date.now() - t0} ms`);
  });

  it('the origin half-closes first and the client goes on sending: what it sends after 2.5 s still arrives', async () => {
    const st = { got: [] };
    const origin = net.createServer({ allowHalfOpen: true }, (s) => {
      st.ended = new Promise((r) => { s.on('end', r); });
      s.on('error', () => {}); s.on('data', (d) => st.got.push(d));
      s.end('bye'); // says goodbye and finishes its own side; it still reads
    });
    const port = await serve(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`] });
    const duplex = await client.openTcp('127.0.0.1', port);
    const reader = duplex.readable.getReader();
    const bye = await reader.read();
    assert.equal(Buffer.from(bye.value).toString(), 'bye');
    assert.equal((await reader.read()).done, true, 'the origin\'s end reaches us as a half-close');
    await sleep(2500);
    const w = duplex.writable.getWriter();
    await w.write(enc.encode('late words'));
    await w.close();
    await st.ended;
    assert.equal(Buffer.concat(st.got).toString(), 'late words');
    await duplex.closed;
  });

  it('a peer that half-closes and then never reads is ended by the idle rule: not sooner, and it does end', async () => {
    const IDLE = 1500;
    const st = {};
    const origin = net.createServer({ allowHalfOpen: true }, (s) => {
      st.sock = s; s.on('error', () => {});
      s.on('end', () => { s.write(Buffer.alloc(4 * MiB, 1)); }); // more than the credit window: the host cannot send it all
      s.resume();
    });
    const port = await serve(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`], halfCloseIdleMs: IDLE });
    const duplex = await client.openTcp('127.0.0.1', port);
    // The host ending the connection shows at the origin: its socket is closed. (The client never reads, so its own stream
    // stays unfinished until it does, or until its own idle bound.)
    let over = false;
    await until(() => st.sock, 'the origin to be connected');
    st.sock.once('close', () => { over = true; });
    const t0 = Date.now();
    await duplex.writable.getWriter().close();
    await sleep(IDLE - 700);
    assert.equal(over, false, 'still open before the idle bound');
    await until(() => over, 'the idle rule to end the connection', IDLE + 5000);
    const took = Date.now() - t0;
    assert.ok(took >= IDLE - 100, `ended after ${took} ms, sooner than ${IDLE}`);
  });

  it('a half-closed stream that is quiet but alive stays: the far side trickles bytes more often than the idle bound', async () => {
    const IDLE = 1000;
    const origin = net.createServer({ allowHalfOpen: true }, (s) => {
      s.on('error', () => {});
      s.on('end', () => {
        let n = 0;
        const tick = setInterval(() => { s.write('x'); if (++n === 6) { clearInterval(tick); s.end(); } }, 400); // 2.4 s, longer than IDLE
      });
      s.resume();
    });
    const port = await serve(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`], halfCloseIdleMs: IDLE });
    const duplex = await client.openTcp('127.0.0.1', port);
    await duplex.writable.getWriter().close();
    assert.equal((await readAll(duplex)).toString(), 'xxxxxx');
  });

  it('the bound is validated: a negative or fractional value is refused', () => {
    for (const bad of [-1, 1.5, '1000', NaN]) assert.throws(() => normalizeGateway({ allow: ['*'], halfCloseIdleMs: bad }), /halfCloseIdleMs/, String(bad));
    assert.equal(normalizeGateway({ allow: ['*'] }).halfCloseIdleMs, 300_000, 'the default is five minutes');
    assert.equal(normalizeGateway({ allow: ['*'], halfCloseIdleMs: 0 }).halfCloseIdleMs, 0, '0 turns it off');
  });
});

describe('interop: a peer that predates the rule', () => {
  const fx = fixture();
  afterEach(() => fx.teardown());

  it('a new client against an older host (pinned at the message level): the host closes about one second after our half-close; the client ends cleanly, no hang, no error', async () => {
    const sent = [];
    const gc = new GatewayConnections({ send: async (m) => { sent.push(m); }, hasFeature: (f) => f === 'gateway-unix' || f === 'gateway-credit', halfCloseIdleMs: 600_000 });
    const p = gc.openUnix('/x.sock');
    const open = sent.find((m) => m.type === MSG.OPEN_UNIX);
    gc.handle({ type: MSG.GATEWAY_OK, gateway_id: open.gateway_id });
    const duplex = await p;
    await duplex.writable.getWriter().close();
    assert.equal(sent.filter((m) => m.type === MSG.GATEWAY_CLOSE).length, 1, 'our half-close went out');
    // What an older host does: its own GatewayClose after its one-second timer, and nothing the origin sends later.
    await sleep(1100);
    gc.handle({ type: MSG.GATEWAY_CLOSE, gateway_id: open.gateway_id, reason: 'grace period over' });
    assert.equal((await readAll(duplex)).length, 0);
    await duplex.closed;
  });

  it('an older client (raw messages: it half-closes and keeps reading, as before) against a new host: the answer 2.5 s later arrives', async () => {
    const st = {};
    const origin = delayedOrigin(2500, 'late answer', st);
    const port = await listen(origin); fx.nets.push(origin);
    const { client, inbox } = await fx.setup({ allow: [`127.0.0.1:${port}`] });
    await client.sendControl({ type: MSG.OPEN_TCP, gateway_id: 9, host: '127.0.0.1', port });
    await until(() => inbox.find((m) => m.type === MSG.GATEWAY_OK), 'GatewayOk');
    await client.sendControl({ type: MSG.GATEWAY_CLOSE, gateway_id: 9 });
    await until(() => inbox.filter((m) => m.type === MSG.GATEWAY_CLOSE).length, 'the host\'s own GatewayClose', 8000);
    const data = Buffer.concat(inbox.filter((m) => m.type === MSG.GATEWAY_DATA).map((m) => Buffer.from(m.data)));
    assert.equal(data.toString(), 'late answer');
  });
});
