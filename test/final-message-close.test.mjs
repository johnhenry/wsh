// test/final-message-close.test.mjs -- #256: the host's last message to a peer it is about to drop (the refusal at the login deadline, the Error at the
// seal deadline, a refused login, a plaintext message on a sealed-only host) is a bounded best effort. A peer that never reads, or granted no
// flow-control credit, must not be able to keep the connection open by making that write wait: the host closes within a short grace whether or
// not the message went. A peer that does read still gets the refusal. The clock is node:test's mock timers (setTimeout only).
import { describe, it, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createConnectionFactory, resolveHostKey } from '@johnhenry/wsh/host';
import { QMuxConnection } from '../src/qmux-connection.mjs';
import { MSG, hello, reverseList } from '../src/messages.mjs';

afterEach(() => { mock.timers.reset(); });

/** Let queued promise work run; mock timers do not drive microtasks. */
const settle = async () => { for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r)); };
/** Advance the mocked clock `ms`, let what it started finish, then let the host's own grace period pass (2 x 100 ms covers the send wait and the drain). */
async function pass(ms) {
  mock.timers.tick(ms);
  await settle();
  for (let i = 0; i < 2; i++) { mock.timers.tick(100); await settle(); }
}

/** A message transport whose write never settles: a WebTransport writer under back-pressure. */
const stuck = () => new Promise(() => {});

/** The host's side of a connection a peer attached with no credit: `{ ended }` counts closeTransport() calls. */
function stuckMessagePeer(attach, extra = {}) {
  const peer = { ended: 0, sent: [] };
  peer.conn = attach({ sendMessage: (m) => { peer.sent.push(m); return stuck(); }, dataStreams: false, closeTransport: () => { peer.ended += 1; }, ...extra });
  return peer;
}

describe('the final message before a close is a bounded best effort (#256)', { timeout: 60_000 }, () => {
  it('login-timeout: a QMux peer that granted no credit does not keep the connection open', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const refused = [];
    const attach = createConnectionFactory({ authorize: async () => false, loginTimeoutMs: 1_000, onRefused: (r) => refused.push(r) });
    let ended = 0;
    // The host's bytes go nowhere: the peer never reads. It completes its own handshake with every window 0, opens the control stream, and goes quiet.
    const host = attach({ send: () => {}, closeTransport: () => { ended += 1; } });
    const peer = new QMuxConnection({ isClient: true, send: (b) => host.receive(b), initialMaxData: 0, initialMaxStreamData: 0 });
    peer.sendHandshake();
    (await peer.openStream()).announce();
    await settle();
    await pass(1_000);
    assert.equal(refused[0]?.reason, 'login-timeout');
    assert.equal(ended, 1, 'the host closed the transport although the AuthFail could not be written');
  });

  it('login-timeout: a message transport whose write never settles', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const refused = [];
    const attach = createConnectionFactory({ authorize: async () => false, loginTimeoutMs: 1_000, onRefused: (r) => refused.push(r) });
    const p = stuckMessagePeer(attach);
    await pass(1_000);
    assert.equal(refused[0]?.reason, 'login-timeout');
    assert.equal(p.sent.length, 1, 'the refusal was attempted');
    assert.equal(p.ended, 1);
  });

  it('seal-timeout: a message transport whose write never settles', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const refused = [];
    const hostKey = await resolveHostKey(true);
    const attach = createConnectionFactory({ authorize: async () => false, hostKey, sealSession: 'require', sealTimeoutMs: 1_000, onRefused: (r) => refused.push(r) });
    const p = stuckMessagePeer(attach, { authenticated: { username: 'u', fingerprint: 'f' }, sealSession: 'require' });
    await pass(1_000);
    assert.equal(refused[0]?.reason, 'seal-timeout');
    assert.equal(p.sent.length, 1);
    assert.equal(p.ended, 1);
  });

  it('a plaintext message on a host that requires sealing: the Error is bounded too', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const refused = [];
    const hostKey = await resolveHostKey(true);
    const attach = createConnectionFactory({ authorize: async () => false, hostKey, sealSession: 'require', sealTimeoutMs: 0, onRefused: (r) => refused.push(r) });
    const p = stuckMessagePeer(attach, { authenticated: { username: 'u', fingerprint: 'f' }, sealSession: 'require' });
    p.conn.receiveMessage(reverseList());
    await settle();
    await pass(0);
    assert.equal(refused[0]?.reason, 'not-sealed');
    assert.equal(p.ended, 1);
  });

  it('a refused login (bad username): the AuthFail is bounded too', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const refused = [];
    const attach = createConnectionFactory({ authorize: async () => false, loginTimeoutMs: 0, onRefused: (r) => refused.push(r) });
    const p = stuckMessagePeer(attach);
    p.conn.receiveMessage(hello({ username: 'not a valid name' }));
    await settle();
    await pass(0);
    assert.equal(refused[0]?.reason, 'bad-request');
    assert.equal(p.ended, 1);
  });

  it('a peer that does read still gets the refusal before the close', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const attach = createConnectionFactory({ authorize: async () => false, loginTimeoutMs: 1_000 });
    const events = [];
    const conn = attach({ sendMessage: (m) => { events.push(`sent ${m.type}`); }, dataStreams: false, closeTransport: () => { events.push('closed'); } });
    await pass(1_000);
    assert.deepEqual(events, [`sent ${MSG.AUTH_FAIL}`, 'closed']);
    conn.close();
  });
});
