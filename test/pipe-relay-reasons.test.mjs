// test/pipe-relay-reasons.test.mjs -- #240: when the relay closes one half for a limit, the partner is closed with the same code and the
// same reason text, so the far side can tell a limit from the other person leaving ('peer closed'). The texts are a stable list
// (`PIPE_CLOSE_REASONS`), documented in the README.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { WebSocket as WsClient } from 'ws';
import { createPipeRelay, newRendezvousId, pipeUrl, PIPE_CLOSE_REASONS } from '@johnhenry/wsh/pipe-relay';

function fake() {
  const s = Object.assign(new EventEmitter(), {
    readyState: 1, bufferedAmount: 0, sent: [], closedWith: null,
    send(d) { s.sent.push(d); },
    close(code, reason) { s.closedWith = [code, reason]; s.readyState = 3; },
    pause() {}, resume() {},
  });
  return s;
}
async function paired(relay) {
  const id = newRendezvousId();
  const host = fake(); const op = fake();
  await relay.accept(host, { id, role: 'host' });
  await relay.accept(op, { id, role: 'operator' });
  return { host, op };
}
const bytes = (n) => Buffer.alloc(n, 1);

describe('PIPE_CLOSE_REASONS: the stable list', () => {
  it('is frozen and is exactly the texts the relay sends', () => {
    assert.ok(Object.isFrozen(PIPE_CLOSE_REASONS));
    assert.deepEqual({ ...PIPE_CLOSE_REASONS }, {
      peerClosed: 'peer closed',
      noPartner: 'no partner arrived',
      idle: 'idle',
      lifetime: 'maximum lifetime reached',
      byteLimit: 'byte limit reached',
      messageTooLarge: 'message too large',
      binaryOnly: 'binary messages only',
      earlyOverflow: 'too much before the partner arrived',
      receiverTooSlow: 'receiver too slow',
      sendFailed: 'send failed',
      shuttingDown: 'relay is shutting down',
      badId: 'bad rendezvous id',
      badRole: 'bad role',
      notPermitted: 'not permitted',
      idInUse: 'rendezvous id in use',
      idRetired: 'rendezvous id already used',
      tooManyWaiting: 'too many waiting connections',
    });
  });
});

describe('a limit closes both halves with its reason (sockets handed to accept())', () => {
  const cases = [
    ['maxBytes', { maxBytes: 100 }, (h) => h.emit('message', bytes(101), true), 1008, PIPE_CLOSE_REASONS.byteLimit],
    ['maxMessageBytes', { maxMessageBytes: 100 }, (h) => h.emit('message', bytes(101), true), 1009, PIPE_CLOSE_REASONS.messageTooLarge],
    ['a text frame', {}, (h) => h.emit('message', 'hi', false), 1003, PIPE_CLOSE_REASONS.binaryOnly],
    ['a receiver that cannot pause', { highWaterBytes: 10 }, (h, o) => { o.bufferedAmount = 1000; delete h.pause; h.emit('message', bytes(1), true); }, 1013, PIPE_CLOSE_REASONS.receiverTooSlow],
  ];
  for (const [name, options, trigger, code, reason] of cases) {
    it(`${name}: ${code} '${reason}' on both`, async () => {
      const relay = createPipeRelay(options);
      const { host, op } = await paired(relay);
      trigger(host, op);
      assert.deepEqual(host.closedWith, [code, reason]);
      assert.deepEqual(op.closedWith, [code, reason]);
      await relay.close();
    });
  }

  it('the partner leaving is the one case that says peer closed, with the partner\'s own code', async () => {
    const relay = createPipeRelay();
    const { host, op } = await paired(relay);
    op.emit('close', 4001);
    assert.deepEqual(host.closedWith, [4001, PIPE_CLOSE_REASONS.peerClosed]);
    await relay.close();
  });

  it('the relay shutting down says so on both', async () => {
    const relay = createPipeRelay();
    const { host, op } = await paired(relay);
    await relay.close();
    assert.deepEqual(host.closedWith, [1001, PIPE_CLOSE_REASONS.shuttingDown]);
    assert.deepEqual(op.closedWith, [1001, PIPE_CLOSE_REASONS.shuttingDown]);
  });

  it('a half that sent too much before its partner came is closed with that reason; a partner arriving later is not told its peer left', async () => {
    const relay = createPipeRelay({ earlyBytes: 100 });
    const id = newRendezvousId();
    const a = fake();
    await relay.accept(a, { id, role: 'host' });
    a.emit('message', bytes(101), true);
    assert.deepEqual(a.closedWith, [1009, PIPE_CLOSE_REASONS.earlyOverflow]);
    a.emit('close', 1009); // the socket then reports its close
    const b = fake();
    assert.equal(await relay.accept(b, { id, role: 'operator' }), true, 'the id is free: the partner waits as a new half');
    assert.equal(b.closedWith, null);
    await relay.close();
  });
});

describe('a limit closes both halves with its reason (real WebSockets through listen())', () => {
  const live = [];
  after(() => { for (const s of live) s.terminate(); });

  async function pairLive(relay, url) {
    const id = newRendezvousId();
    const dial = (role) => {
      const ws = new WsClient(pipeUrl(url, id, role));
      live.push(ws);
      const out = { ws, closed: null, whenClosed: new Promise((r) => ws.once('close', (code, reason) => { out.closed = { code, reason: reason.toString() }; r(out.closed); })), open: new Promise((r) => ws.once('open', r)) };
      ws.on('error', () => {});
      return out;
    };
    const host = dial('host'); const op = dial('operator');
    await Promise.all([host.open, op.open]);
    // A pong comes back only after the relay has read everything sent before the ping: the pair exists.
    for (const h of [host, op]) await new Promise((r) => { h.ws.once('pong', r); h.ws.ping(); });
    await until(() => relay.stats().pipes === 1);
    return { host, op };
  }
  const until = async (cond) => { while (!cond()) await new Promise((r) => setImmediate(r)); };

  it('an oversize message: the sender and the partner both get 1009 and the reason, not peer closed', async () => {
    const relay = createPipeRelay({ maxMessageBytes: 1000 });
    const { port } = await relay.listen();
    try {
      const { host, op } = await pairLive(relay, `ws://127.0.0.1:${port}`);
      host.ws.send(bytes(2000));
      const [h, o] = await Promise.all([host.whenClosed, op.whenClosed]);
      assert.equal(h.code, 1009);
      assert.equal(o.code, 1009);
      assert.equal(o.reason, PIPE_CLOSE_REASONS.messageTooLarge);
    } finally { await relay.close(); }
  });

  it('the byte budget: both get 1008 and the reason', async () => {
    const relay = createPipeRelay({ maxBytes: 100 });
    const { port } = await relay.listen();
    try {
      const { host, op } = await pairLive(relay, `ws://127.0.0.1:${port}`);
      host.ws.send(bytes(101));
      const [h, o] = await Promise.all([host.whenClosed, op.whenClosed]);
      assert.deepEqual([h.code, h.reason], [1008, PIPE_CLOSE_REASONS.byteLimit]);
      assert.deepEqual([o.code, o.reason], [1008, PIPE_CLOSE_REASONS.byteLimit]);
    } finally { await relay.close(); }
  });

  it('the lifetime: both get 1000 and the reason', async () => {
    const relay = createPipeRelay({ maxLifetimeMs: 150 });
    const { port } = await relay.listen();
    try {
      const { host, op } = await pairLive(relay, `ws://127.0.0.1:${port}`);
      const [h, o] = await Promise.all([host.whenClosed, op.whenClosed]);
      assert.deepEqual([h.code, h.reason], [1000, PIPE_CLOSE_REASONS.lifetime]);
      assert.deepEqual([o.code, o.reason], [1000, PIPE_CLOSE_REASONS.lifetime]);
    } finally { await relay.close(); }
  });

  it('idle: both get 1000 and the reason', async () => {
    const relay = createPipeRelay({ idleTimeoutMs: 50 });
    const { port } = await relay.listen();
    try {
      const { host, op } = await pairLive(relay, `ws://127.0.0.1:${port}`);
      const [h, o] = await Promise.all([host.whenClosed, op.whenClosed]);
      assert.deepEqual([h.code, h.reason], [1000, PIPE_CLOSE_REASONS.idle]);
      assert.deepEqual([o.code, o.reason], [1000, PIPE_CLOSE_REASONS.idle]);
    } finally { await relay.close(); }
  });

  it('a partner that simply closes (even with 1009 of its own) is still peer closed', async () => {
    const relay = createPipeRelay();
    const { port } = await relay.listen();
    try {
      const { host, op } = await pairLive(relay, `ws://127.0.0.1:${port}`);
      op.ws.close(1009, 'my own limit');
      const h = await host.whenClosed;
      assert.deepEqual([h.code, h.reason], [1009, PIPE_CLOSE_REASONS.peerClosed]);
    } finally { await relay.close(); }
  });
});
