// test/login-clock-waiting.test.mjs -- #253: the login deadline (#248, `loginTimeoutMs`, 60 s) counts from the moment the far side is THERE. For a direct
// connection that is the accept; for a half a host holds while its partner has not arrived (the socket a page dialled to a pipe relay, a relay half
// given to `host.accept`) it is the partner's arrival: the first byte it sends, or the relay's paired signal. A half that waits is neither refused
// nor closed however long it waits, an operator who then arrives logs in, and a far side that IS there and never logs in is still closed at the
// deadline. The 30 s seal deadline (#244) starts at login, so it is unaffected. The clock is node:test's mock timers (setTimeout only): nothing here
// waits out a real deadline.
import { describe, it, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { createMemoryHost, createSocketPair } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { createConnectionFactory } from '@johnhenry/wsh/host';
import { createInProcessPipeRelay } from '@johnhenry/wsh/testing';
import { pipeUrl, newRendezvousId, watchPairing } from '@johnhenry/wsh/pipe-relay';
import { createPageHost, captureWebMcp } from '@johnhenry/wsh/page';
import { serveWshOverDuplex, connectWshOverDuplex } from '@johnhenry/wsh/duplex';
import { WshClient, WebSocketTransport, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw } from '@johnhenry/wsh';
import { createFakeWindow } from './helpers/fake-window.mjs';

const BASE = 'ws://relay.test';
const DAY = 24 * 60 * 60 * 1000;
const closers = [];
// What a test leaves behind finishes on REAL timers (the hosts close their connections 50 ms after the last message): wait for it here, so that it cannot run
// during the next test, whose mocked clock would take a stale timer of this one for its own (node's mock `clearTimeout` removes by queue position).
afterEach(async () => {
  mock.timers.reset();
  for (const c of closers.splice(0).reverse()) await c().catch(() => {});
  await sleep(200);
});

/** Let queued promise work run; mock timers do not drive microtasks. */
const settle = async () => { for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r)); };
/** Parts of a login yield with `setTimeout(..., 0)`, which a mocked clock does not run: advance 1 ms at a time until `promise` settles. */
async function drive(promise) {
  let done = false;
  const watched = promise.finally(() => { done = true; });
  watched.catch(() => {});
  for (let i = 0; i < 5_000 && !done; i++) { mock.timers.tick(1); await new Promise((r) => setImmediate(r)); }
  assert.ok(done, 'settled within 5 s of mock time');
  return watched;
}
/** Advance the mocked clock `ms` and let what it started finish (the host lets its last message drain 50 ms before it closes). */
async function pass(ms) {
  mock.timers.tick(ms);
  await settle();
  mock.timers.tick(100);
  await settle();
}
/** The host lets its last message drain before it closes (a 50 ms timer set once that message has gone): tick on, 10 ms at a time, until `pred()` holds (bounded), and say whether it does. */
async function eventually(pred) {
  for (let i = 0; i < 100 && !pred(); i++) { mock.timers.tick(10); await settle(); }
  return pred();
}
const closedFlag =(socket) => { const flag = { done: false }; socket.addEventListener('close', () => { flag.done = true; }); return flag; };

async function world({ relayOptions, host: hostOptions = {} } = {}) {
  mock.timers.enable({ apis: ['setTimeout'] });
  const env = await createInProcessPipeRelay({ relayOptions: { rendezvousTimeoutMs: 10 * DAY, idleTimeoutMs: 10 * DAY, maxLifetimeMs: 10 * DAY, ...relayOptions } });
  closers.push(() => env.close());
  const keyPair = await generateKeyPair(true);
  const refused = [];
  const host = createMemoryHost({
    auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] }, hostKey: true, dataStreams: false, onRefused: (r) => refused.push(r), ...hostOptions,
  });
  closers.push(() => host.close());
  const id = newRendezvousId();
  const operator = () => new WshClient({ transportFactories: { ws: () => new WebSocketTransport({ WebSocket: env.WebSocket }), wt: () => { throw new Error('no webtransport'); } } });
  return { env, keyPair, refused, host, id, operator };
}

describe('a relay half that waits for its partner (#253)', { timeout: 60_000 }, () => {
  it('a half accepted with waitForPeer is neither refused nor closed however long it waits; the operator who then arrives logs in', async () => {
    const w = await world();
    const half = new w.env.WebSocket(pipeUrl(BASE, w.id, 'host'));
    const closed = closedFlag(half);
    await w.host.accept(half, { waitForPeer: true });
    await pass(100_000);
    await pass(DAY);
    assert.equal(closed.done, false, 'still open after a day');
    assert.deepEqual(w.refused, []);
    const client = w.operator();
    closers.push(() => client.disconnect());
    await drive(client.connect(pipeUrl(BASE, w.id), { transport: 'ws', username: 'u', keyPair: w.keyPair, sealSession: false }));
    assert.equal(client.state, 'authenticated');
    await pass(10 * 60_000);
    assert.equal(client.state, 'authenticated', 'and logged in, nothing else counts');
    assert.deepEqual(w.refused, []);
  });

  it('the same without the option is what a plain accept() does: the clock starts at the accept (the 60 s deadline of #248 is unchanged)', async () => {
    const w = await world();
    const half = new w.env.WebSocket(pipeUrl(BASE, w.id, 'host'));
    const closed = closedFlag(half);
    await w.host.accept(half);
    await pass(59_000);
    assert.equal(closed.done, false);
    await pass(1_000);
    assert.equal(await eventually(() => closed.done), true);
    assert.equal(w.refused[0]?.reason, 'login-timeout');
  });

  it('once the partner has sent a byte, a login that never completes is closed at the deadline from that byte, not from the accept', async () => {
    const w = await world();
    const half = new w.env.WebSocket(pipeUrl(BASE, w.id, 'host'));
    const closed = closedFlag(half);
    await w.host.accept(half, { waitForPeer: true });
    await pass(50_000);
    const op = new w.env.WebSocket(pipeUrl(BASE, w.id));
    await settle();
    op.send(new Uint8Array([1, 2, 3])); // not a QMux handshake, but a byte: the far side is there
    await settle();
    await pass(59_000);
    assert.equal(closed.done, false, 'not yet: 59 s after the byte');
    assert.deepEqual(w.refused, []);
    await pass(1_000);
    assert.equal(await eventually(() => closed.done), true, 'closed 60 s after the byte');
    assert.equal(w.refused[0]?.reason, 'login-timeout');
  });

  it('with the relay\'s paired signal a partner that arrives and never says a word is closed at the deadline from the pairing; before it nothing is refused', async () => {
    const w = await world();
    const { socket, paired } = watchPairing(new w.env.WebSocket(pipeUrl(BASE, w.id, 'host', { notifyPaired: true })));
    const closed = closedFlag(socket);
    await w.host.accept(socket, { waitForPeer: paired });
    await pass(DAY);
    assert.equal(closed.done, false);
    assert.deepEqual(w.refused, []);
    const op = new w.env.WebSocket(pipeUrl(BASE, w.id)); // pairs, and stays silent
    const opClosed = closedFlag(op);
    await settle();
    await pass(59_000);
    assert.equal(closed.done, false, 'not yet: 59 s after the pairing');
    await pass(1_000);
    assert.equal(await eventually(() => closed.done), true, 'closed 60 s after the pairing');
    assert.equal(await eventually(() => opClosed.done), true);
    assert.equal(w.refused[0]?.reason, 'login-timeout');
  });

  it('with the paired signal an operator that arrives late still logs in, however long the host waited', async () => {
    const w = await world();
    const { socket, paired } = watchPairing(new w.env.WebSocket(pipeUrl(BASE, w.id, 'host', { notifyPaired: true })));
    await w.host.accept(socket, { waitForPeer: paired });
    await pass(10 * 60_000);
    const client = w.operator();
    closers.push(() => client.disconnect());
    await drive(client.connect(pipeUrl(BASE, w.id), { transport: 'ws', username: 'u', keyPair: w.keyPair, sealSession: false }));
    assert.equal(client.state, 'authenticated');
    assert.deepEqual(w.refused, []);
  });

  it('a promise that rejects (the pipe closed first) starts nothing and changes nothing', async () => {
    const w = await world();
    const half = new w.env.WebSocket(pipeUrl(BASE, w.id, 'host'));
    const never = Promise.reject(new Error('the pipe closed before a partner arrived'));
    never.catch(() => {});
    await w.host.accept(half, { waitForPeer: never });
    await pass(DAY);
    assert.deepEqual(w.refused, []);
  });

  it('waitForPeer must be true, false or a promise', async () => {
    const w = await world();
    const [, server] = createSocketPair();
    for (const bad of ['yes', 1, {}, null]) await assert.rejects(async () => w.host.accept(server, { waitForPeer: bad }), /waitForPeer/, JSON.stringify(bad));
  });

  it('createWshServer().accept takes the same option (it is the same socket binding)', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const refused = [];
    const server = createWshServer({ auth: { authorizedKeys: `${await exportPublicKeySSH((await generateKeyPair(true)).publicKey)} u` }, onRefused: (r) => refused.push(r) });
    closers.push(() => server.close());
    const [client, half] = createSocketPair();
    const closed = closedFlag(client);
    await server.accept(half, { waitForPeer: true });
    await pass(DAY);
    assert.equal(closed.done, false);
    assert.deepEqual(refused, []);
    client.send(new Uint8Array([9])); // the far side is there now, and never logs in
    await settle();
    await pass(60_000);
    assert.equal(await eventually(() => closed.done), true);
    assert.equal(refused[0]?.reason, 'login-timeout');
  });

  it('createWshServer\'s own sockets are unchanged: a client that connects and says nothing is closed at the deadline (#248)', async () => {
    const { WebSocket } = await import('ws');
    const refused = [];
    const server = createWshServer({ auth: { authorizedKeys: `${await exportPublicKeySSH((await generateKeyPair(true)).publicKey)} u` }, loginTimeoutMs: 100, onRefused: (r) => refused.push(r) });
    const { port } = await server.listen();
    closers.push(() => server.close());
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    closers.push(async () => ws.terminate());
    await new Promise((resolve, reject) => { ws.once('close', resolve); ws.once('error', reject); });
    assert.equal(refused[0]?.reason, 'login-timeout');
  });

  it('serveWshOverDuplex passes it on; without it the duplex is the far side arriving and the clock starts at once', async () => {
    const w = await world();
    const waiting = serveWshOverDuplex(w.host, { send: () => {}, close: () => {}, waitForPeer: true });
    await waiting.ready;
    await pass(DAY);
    assert.deepEqual(w.refused, []);
    waiting.receive(new Uint8Array([1]));
    await settle();
    await pass(60_000);
    assert.equal(w.refused.length, 1);
    assert.equal(w.refused[0].reason, 'login-timeout');

    const here = serveWshOverDuplex(w.host, { send: () => {}, close: () => {} });
    await here.ready;
    await pass(60_000);
    assert.equal(w.refused.length, 2);
  });

  it('the connection factory: waitForPeer arms nothing until the first byte or startLoginClock(); an authenticated connection and loginTimeoutMs: 0 stay as they were', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const refused = [];
    const attach = createConnectionFactory({ authorize: async () => false, loginTimeoutMs: 1_000, onRefused: (r) => refused.push(r) });
    let ended = 0;
    const a = attach({ send: () => {}, waitForPeer: true, closeTransport: () => { ended += 1; } });
    await pass(DAY);
    assert.equal(ended, 0);
    a.startLoginClock();
    a.startLoginClock(); // idempotent
    await pass(1_000);
    assert.equal(await eventually(() => ended === 1), true);
    assert.equal(refused.length, 1);

    const b = attach({ send: () => {}, waitForPeer: true, closeTransport: () => { ended += 1; } });
    b.receive(new Uint8Array(0)); // nothing is not a byte
    await pass(DAY);
    assert.equal(ended, 1);
    b.receive(new Uint8Array([0]));
    await pass(1_000);
    assert.equal(await eventually(() => ended === 2), true);

    const c = attach({ sendMessage: () => {}, authenticated: { username: 'u', fingerprint: 'f' }, waitForPeer: true, dataStreams: false, closeTransport: () => { ended += 1; } });
    c.startLoginClock();
    await pass(DAY);
    assert.equal(ended, 2, 'an already authenticated connection has no login to bound');
    c.close(); b.close(); a.close();
  });
});

describe('the seal deadline is unaffected (#253)', { timeout: 60_000 }, () => {
  it('it starts at login: a host that waited a day for its operator still gives a login 30 s to seal, not less and not more', async () => {
    const w = await world({ host: { sealSession: 'require' } });
    const half = new w.env.WebSocket(pipeUrl(BASE, w.id, 'host'));
    await w.host.accept(half, { waitForPeer: true });
    await pass(DAY);
    assert.deepEqual(w.refused, []);
    const client = w.operator();
    closers.push(() => client.disconnect());
    const closed = { done: false };
    await drive(client.connect(pipeUrl(BASE, w.id), { transport: 'ws', username: 'u', keyPair: w.keyPair, sealSession: false }));
    client.onClose = () => { closed.done = true; };
    assert.equal(client.state, 'authenticated');
    await pass(29_000);
    assert.equal(closed.done, false, 'not yet: 29 s after the login');
    assert.deepEqual(w.refused, []);
    await pass(1_000);
    assert.equal(await eventually(() => closed.done), true);
    assert.equal(w.refused.length, 1);
    assert.equal(w.refused[0].reason, 'seal-timeout');
  });
});

describe('a page host waits for its operator (#253)', { timeout: 60_000 }, () => {
  const tool = { name: 'search', description: 'Search', inputSchema: { type: 'object', properties: {} }, annotations: { readOnlyHint: true }, execute: () => ({ hits: [] }) };

  /** A page host over a fake window whose WebSocket dials the in-process relay (or `WebSocket` of the test). */
  async function page(w, { WebSocket, relay = true, hostOptions = {} } = {}) {
    const dialled = [];
    const sent = [];
    const Base = WebSocket ?? w.env.WebSocket;
    // What the page writes: its host speaks first, so a first write says the host has started serving this half (its key is ready, it is attached).
    const Dial = class extends Base {
      constructor(url) {
        super(url);
        dialled.push(url);
        const send = this.send;
        this.send = (d) => { sent.push(d); return send.call(this, d); };
      }
    };
    const win = createFakeWindow({ WebSocket: Dial });
    captureWebMcp(win);
    await win.document.modelContext.registerTool(tool);
    const log = [];
    const refused = [];
    const host = await createPageHost({
      window: win, ...(relay ? { relay: BASE } : { connect: 'ws://operator.test/' }), name: 'shop-tab', authorizedKeys: [await exportPublicKeySSH(w.keyPair.publicKey)], mcp: { allow: ['search'] },
      onLog: (l) => log.push(l), onRefused: (r) => refused.push(r), ...hostOptions,
    });
    closers.push(() => host.close());
    /** Real turns of the event loop (the host's key is made by the platform) until the page has started serving its half: only then does time pass. */
    const attached = async () => {
      for (let i = 0; i < 20_000 && sent.length === 0; i++) await new Promise((r) => setImmediate(r));
      assert.ok(sent.length > 0, 'the page host started serving its half');
    };
    return { host, dialled, log, refused, attached };
  }
  const login = (w, host, extra = {}) => {
    const client = w.operator();
    closers.push(() => client.disconnect());
    return { client, done: client.connect(host.operatorUrl, { transport: 'ws', username: 'alice', keyPair: w.keyPair, sealSession: true, ...extra }) };
  };

  it('behind a relay: after a day with nobody there it has dialled once, refused nothing and kept its half; the operator who then arrives logs in', async () => {
    const w = await world();
    const p = await page(w);
    await p.attached();
    assert.equal(p.dialled.length, 1);
    await pass(100_000);
    await pass(DAY);
    assert.equal(p.dialled.length, 1, 'it did not have to redial');
    assert.deepEqual(p.refused, []);
    assert.equal(w.env.stats().waiting, 1, 'its half is still waiting at the relay');
    assert.equal(p.host.closed, false);
    const { client, done } = login(w, p.host);
    await drive(done);
    assert.equal(client.state, 'authenticated');
    assert.equal(client.sessionSealed, true);
    assert.deepEqual(p.refused, []);
    assert.equal(p.host.sessions.length, 1);
  });

  it('behind a relay: an operator who arrives and never logs in is closed at the deadline (loginTimeoutMs of the page host), counted from its arrival', async () => {
    const w = await world();
    const p = await page(w, { hostOptions: { loginTimeoutMs: 5_000 } });
    await p.attached();
    await pass(DAY);
    assert.deepEqual(p.refused, []);
    const op = new w.env.WebSocket(pipeUrl(BASE, p.host.rendezvousId)); // pairs, and says nothing
    const opClosed = closedFlag(op);
    await settle();
    await pass(4_800); // pass() adds the 100 ms the host takes to drain: 4.9 s in all
    assert.equal(opClosed.done, false);
    assert.deepEqual(p.refused, []);
    await pass(100);
    assert.equal(await eventually(() => opClosed.done), true);
    assert.equal(p.refused[0]?.reason, 'login-timeout');
  });

  it('behind a relay: the default deadline is the library\'s 60 s from the arrival', async () => {
    const w = await world();
    const p = await page(w);
    await p.attached();
    await pass(DAY);
    const op = new w.env.WebSocket(pipeUrl(BASE, p.host.rendezvousId));
    const opClosed = closedFlag(op);
    await settle();
    await pass(59_000);
    assert.equal(opClosed.done, false);
    await pass(1_000);
    assert.equal(await eventually(() => opClosed.done), true);
    assert.equal(p.refused[0]?.reason, 'login-timeout');
  });

  it('loginTimeoutMs of a page host is validated like every other host\'s', async () => {
    const w = await world();
    for (const bad of [-1, 'soon', NaN, Infinity]) await assert.rejects(page(w, { hostOptions: { loginTimeoutMs: bad } }), /loginTimeoutMs/);
  });

  describe('the dial-out form', () => {
    /** A WebSocket constructor for the window that hands the test the end the "operator that listens" holds. */
    function listener() {
      const accepted = [];
      class Dial {
        constructor() { const [client, server] = createSocketPair(); accepted.push(server); return client; }
      }
      return { Dial, accepted };
    }

    it('a listener that accepted and has said nothing for a day has not had the page host\'s half refused or closed; the operator who then speaks logs in', async () => {
      const w = await world();
      const { Dial, accepted } = listener();
      const p = await page(w, { WebSocket: Dial, relay: false });
      await p.attached();
      assert.equal(accepted.length, 1);
      const closed = closedFlag(accepted[0]);
      await pass(100_000);
      await pass(DAY);
      assert.equal(closed.done, false);
      assert.equal(accepted.length, 1, 'no redial');
      assert.deepEqual(p.refused, []);
      const server = accepted[0];
      const link = connectWshOverDuplex({ send: (b) => server.send(b), close: () => server.close(1000) }, { username: 'alice', keyPair: w.keyPair, trustOnFirstUse: true, timeout: 120_000 });
      server.addEventListener('message', (ev) => link.receive(ev.data));
      closers.push(() => link.close());
      const client = await drive(link.connected);
      assert.equal(client.state, 'authenticated');
      assert.deepEqual(p.refused, []);
    });

    it('a listener that sends something and then never logs in is closed at the deadline, counted from its first byte', async () => {
      const w = await world();
      const { Dial, accepted } = listener();
      const p = await page(w, { WebSocket: Dial, relay: false, hostOptions: { loginTimeoutMs: 5_000 } });
      await p.attached();
      await pass(DAY);
      const server = accepted[0];
      const closed = closedFlag(server);
      server.send(new Uint8Array([1]));
      await settle();
      await pass(4_800);
      assert.equal(closed.done, false);
      await pass(100);
      assert.equal(await eventually(() => closed.done), true);
      assert.equal(p.refused[0]?.reason, 'login-timeout');
    });
  });
});
