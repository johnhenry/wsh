// test/session-seal-deadline.test.mjs -- #244: with a required seal, a client that logs in and then never seals is dropped at a
// deadline (`sealTimeoutMs`, default 30 s), named `seal-timeout`. A client that seals in time, and a host that does not require
// sealing, are unaffected. The clock is node:test's mock timers (setTimeout only): nothing here waits out a real deadline.
import { describe, it, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { createConnectionFactory } from '@johnhenry/wsh/host';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { REFUSAL_REASONS } from '../src/refusal.mjs';

const echo = { echo: (d) => { d.readable.pipeTo(d.writable).catch(() => {}); } };

async function setup(hostOptions) {
  const keyPair = await generateKeyPair(true);
  const authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} u`;
  const refused = [];
  const host = createMemoryHost({
    auth: { authorizedKeys }, hostKey: true, dataStreams: false, endpoints: echo, onRefused: (r) => refused.push(r), ...hostOptions,
  });
  return { keyPair, host, refused };
}

/** `{ done }`: whether the client was closed (a flag, so a missing close is a failed assertion, not a hang). */
const closedOf = (client) => { const flag = { done: false }; client.onClose = () => { flag.done = true; }; return flag; };
/** Let queued promise work (the login, the close) run; mock timers do not drive microtasks. */
const settle = async () => { for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r)); };

/**
 * The key exchange itself yields to the event loop with `setTimeout(..., 0)` (e2e-exchange.mjs), which a mocked clock does not run: advance it
 * 1 ms at a time (far inside any deadline here) until `promise` settles.
 */
async function untilDone(promise) {
  let settled = false;
  const watched = promise.finally(() => { settled = true; });
  watched.catch(() => {});
  while (!settled) { mock.timers.tick(1); await new Promise((r) => setImmediate(r)); }
  return watched;
}

describe('sealed-session deadline (#244)', { timeout: 30_000 }, () => {
  afterEach(() => { mock.timers.reset(); });

  it('is a named refusal reason', () => {
    assert.ok(REFUSAL_REASONS.includes('seal-timeout'));
  });

  it('a client that logs in under sealSession: require and never seals is closed at the default 30 s, with a named reason', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const { keyPair, host, refused } = await setup({ sealSession: 'require' });
    try {
      const client = await host.connect({ username: 'u', keyPair, sealSession: false });
      const closed = closedOf(client);
      mock.timers.tick(29_999);
      await settle();
      assert.equal(client.state, 'authenticated', 'not yet at 29.999 s');
      assert.deepEqual(refused, []);
      mock.timers.tick(1);
      await settle();
      mock.timers.tick(100); // the host lets its last message drain before it closes
      await settle();
      assert.equal(closed.done, true, 'the host closed the connection');
      assert.equal(refused.length, 1);
      assert.equal(refused[0].reason, 'seal-timeout');
      assert.match(refused[0].detail, /sealed/i);
      assert.equal(refused[0].who.username, 'u');
    } finally { mock.timers.reset(); await host.close(); }
  });

  it('sealTimeoutMs changes the deadline; 0 turns it off', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const a = await setup({ sealSession: 'require', sealTimeoutMs: 5_000 });
    try {
      const client = await a.host.connect({ username: 'u', keyPair: a.keyPair, sealSession: false });
      const closed = closedOf(client);
      mock.timers.tick(5_000);
      await settle();
      mock.timers.tick(100);
      await settle();
      assert.equal(closed.done, true, 'the host closed the connection');
      assert.equal(a.refused[0]?.reason, 'seal-timeout');
    } finally { mock.timers.reset(); await a.host.close(); mock.timers.enable({ apis: ['setTimeout'] }); }

    const b = await setup({ sealSession: 'require', sealTimeoutMs: 0 });
    try {
      const client = await b.host.connect({ username: 'u', keyPair: b.keyPair, sealSession: false });
      mock.timers.tick(24 * 60 * 60 * 1000);
      await settle();
      assert.equal(client.state, 'authenticated');
      assert.deepEqual(b.refused, []);
      mock.timers.reset(); // a real clock again, so a disconnect that has a timeout fallback is not left waiting on a frozen one
      await client.disconnect().catch(() => {});
    } finally { mock.timers.reset(); await b.host.close(); }
  });

  it('a client that seals promptly is not dropped, past the deadline', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const { keyPair, host, refused } = await setup({ sealSession: 'require' });
    try {
      const client = await untilDone(host.connect({ username: 'u', keyPair, sealSession: true }));
      assert.equal(client.sessionSealed, true);
      await settle(); // the host finishes its side of the exchange (it replies, then records the seal)
      mock.timers.tick(10 * 60 * 1000);
      await settle();
      assert.equal(client.state, 'authenticated');
      assert.deepEqual(refused, []);
      mock.timers.reset();
      await client.disconnect().catch(() => {});
    } finally { mock.timers.reset(); await host.close(); }
  });

  it('a host that does not require sealing has no deadline (offer, and off)', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    for (const sealSession of ['offer', false]) {
      const { keyPair, host, refused } = await setup({ sealSession });
      try {
        const client = await host.connect({ username: 'u', keyPair, sealSession: false });
        mock.timers.tick(10 * 60 * 1000);
        await settle();
        assert.equal(client.state, 'authenticated', String(sealSession));
        assert.deepEqual(refused, [], String(sealSession));
        mock.timers.reset();
        await client.disconnect().catch(() => {});
      } finally { mock.timers.reset(); await host.close(); mock.timers.enable({ apis: ['setTimeout'] }); }
    }
  });

  it('sealTimeoutMs is validated on every host factory', () => {
    for (const bad of [-1, 'soon', NaN, Infinity]) {
      assert.throws(() => createMemoryHost({ hostKey: true, dataStreams: false, sealSession: 'require', sealTimeoutMs: bad }), /sealTimeoutMs/);
      assert.throws(() => createConnectionFactory({ authorize: async () => true, sealSession: 'require', sealTimeoutMs: bad }), /sealTimeoutMs/);
      assert.throws(() => createWshServer({ hostKey: true, sealSession: 'require', sealTimeoutMs: bad }), /sealTimeoutMs/);
    }
  });
});
