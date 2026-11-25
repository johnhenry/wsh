// test/login-deadline.test.mjs -- #248: a connection that never completes its login (Hello and Auth) is closed at a deadline
// (`loginTimeoutMs`, default 60 s, counted from the moment the host accepted the connection), named `login-timeout`. A client that logs
// in promptly, even one that takes most of the deadline, is unaffected. The clock is node:test's mock timers (setTimeout only): nothing
// here waits out a real deadline.
import { describe, it, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { createConnectionFactory } from '@johnhenry/wsh/host';
import { generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, sign } from '@johnhenry/wsh';
import { REFUSAL_REASONS } from '../src/refusal.mjs';

async function setup({ authorize, ...hostOptions } = {}) {
  const keyPair = await generateKeyPair(true);
  const authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} u`;
  const refused = [];
  const host = createMemoryHost({ auth: { authorizedKeys, ...(authorize ? { authorize } : {}) }, onRefused: (r) => refused.push(r), ...hostOptions });
  return { keyPair, host, refused };
}

/** A socket the host has accepted and nobody writes to: `{ done }` says whether the host closed it (a flag, so a missing close fails an assertion, not a hang). */
async function silentSocket(host) {
  const [client, server] = host.socketPair();
  const flag = { done: false };
  client.addEventListener('close', () => { flag.done = true; });
  await host.accept(server, { remote: { address: 'silent' } });
  return flag;
}

/** Let queued promise work (the login, the close) run; mock timers do not drive microtasks. */
const settle = async () => { for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r)); };

/**
 * Parts of a login yield to the event loop with `setTimeout(..., 0)`, which a mocked clock does not run: advance it 1 ms at a time (far inside
 * any deadline here) until `pred()` holds. Bounded, so a login that never gets there fails the assertion instead of hanging.
 */
async function until(pred, what) {
  for (let i = 0; i < 2_000 && !pred(); i++) { mock.timers.tick(1); await new Promise((r) => setImmediate(r)); }
  assert.ok(pred(), `${what} (within 2 s of mock time)`);
}

describe('login deadline (#248)', { timeout: 30_000 }, () => {
  afterEach(() => { mock.timers.reset(); });

  it('is a named refusal reason', () => {
    assert.ok(REFUSAL_REASONS.includes('login-timeout'));
  });

  it('a connection that never says Hello is closed at the default 60 s, with a named reason', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const { host, refused } = await setup({});
    try {
      const closed = await silentSocket(host);
      mock.timers.tick(59_999);
      await settle();
      assert.equal(closed.done, false, 'not yet at 59.999 s');
      assert.deepEqual(refused, []);
      mock.timers.tick(1);
      await settle();
      mock.timers.tick(100); // the host lets its last message drain before it closes
      await settle();
      assert.equal(closed.done, true, 'the host closed the connection');
      assert.equal(refused.length, 1);
      assert.equal(refused[0].reason, 'login-timeout');
      assert.match(refused[0].detail, /login/i);
    } finally { mock.timers.reset(); await host.close(); }
  });

  it('a login that is started and never finished (the host is still deciding) is refused at the deadline and the client is told why; the late decision changes nothing', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    let decide;
    const decision = new Promise((r) => { decide = r; });
    let asked = false;
    const { keyPair, host, refused } = await setup({ authorize: async () => { asked = true; return decision; } });
    try {
      // The client has sent Hello and signed the challenge; `auth.authorize` is where the login waits. Its own timeout is raised so that it is
      // the host's deadline, not the client's, that ends this.
      const client = host.createClient();
      const outcome = client.connect(host.url, { transport: 'ws', username: 'u', keyPair, sealSession: false, timeout: 120_000 }).then(() => 'logged in', (e) => e);
      await until(() => asked, 'the host asked authorize');
      mock.timers.tick(60_000);
      await settle();
      mock.timers.tick(100);
      await settle();
      const error = await outcome;
      assert.match(String(error?.message), /login-timeout/, 'the client is told why');
      assert.equal(refused.length, 1);
      assert.equal(refused[0].reason, 'login-timeout');
      assert.equal(refused[0].who.username, 'u');
      decide(true); // too late: the connection is gone and nothing is granted
      await settle();
      assert.equal(refused.length, 1);
      assert.notEqual(client.state, 'authenticated');
    } finally { mock.timers.reset(); await host.close(); }
  });

  it('loginTimeoutMs changes the deadline; 0 turns it off', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const a = await setup({ loginTimeoutMs: 5_000 });
    try {
      const closed = await silentSocket(a.host);
      mock.timers.tick(5_000);
      await settle();
      mock.timers.tick(100);
      await settle();
      assert.equal(closed.done, true, 'the host closed the connection');
      assert.equal(a.refused[0]?.reason, 'login-timeout');
    } finally { mock.timers.reset(); await a.host.close(); mock.timers.enable({ apis: ['setTimeout'] }); }

    const b = await setup({ loginTimeoutMs: 0 });
    try {
      const closed = await silentSocket(b.host);
      mock.timers.tick(24 * 60 * 60 * 1000);
      await settle();
      assert.equal(closed.done, false);
      assert.deepEqual(b.refused, []);
    } finally { mock.timers.reset(); await b.host.close(); }
  });

  it('a client that logs in promptly is not dropped, past the deadline; one that takes nearly all of it is not either', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const { keyPair, host, refused } = await setup({});
    try {
      const prompt = host.connect({ username: 'u', keyPair, sealSession: false });
      let promptDone = false;
      prompt.then(() => { promptDone = true; }, () => {});
      await until(() => promptDone, 'the prompt login completed');
      const promptClient = await prompt;
      assert.equal(promptClient.state, 'authenticated');

      // A login that waits 59 s on its signer (a person confirming on a device), with the client's own timeout raised to allow it:
      // inside the deadline, so it completes.
      const publicKey = await exportPublicKeyRaw(keyPair.publicKey);
      let release;
      let signing = false;
      const gate = new Promise((r) => { release = r; });
      const slow = host.createClient();
      const slowLogin = slow.connect(host.url, { transport: 'ws', username: 'u', sealSession: false, timeout: 120_000, signer: { publicKey, sign: async (data) => { signing = true; await gate; return sign(keyPair.privateKey, data); } } });
      slowLogin.catch(() => {});
      await until(() => signing, 'the slow client reached its signature');
      mock.timers.tick(59_000);
      await settle();
      release();
      let slowDone = false;
      slowLogin.then(() => { slowDone = true; }, () => {});
      await until(() => slowDone, 'the slow login completed');
      await slowLogin;
      assert.equal(slow.state, 'authenticated');

      mock.timers.tick(10 * 60 * 1000);
      await settle();
      assert.equal(promptClient.state, 'authenticated');
      assert.equal(slow.state, 'authenticated');
      assert.deepEqual(refused, []);
      mock.timers.reset();
      await promptClient.disconnect().catch(() => {});
      await slow.disconnect().catch(() => {});
    } finally { mock.timers.reset(); await host.close(); }
  });

  it('createWshServer closes a socket that connects and stays silent (a real socket and a short deadline: the wait is for the close event)', async () => {
    const { WebSocket } = await import('ws');
    const refused = [];
    const server = createWshServer({ auth: { authorizedKeys: `${await exportPublicKeySSH((await generateKeyPair(true)).publicKey)} u` }, loginTimeoutMs: 100, onRefused: (r) => refused.push(r) });
    const { port } = await server.listen();
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    try {
      await new Promise((resolve, reject) => { ws.once('close', resolve); ws.once('error', reject); });
      assert.equal(refused.length, 1);
      assert.equal(refused[0].reason, 'login-timeout');
    } finally { ws.terminate(); await server.close(); }
  });

  it('a connection attached as already authenticated (a relay bridge) has no login to bound', async () => {
    mock.timers.enable({ apis: ['setTimeout'] });
    const refused = [];
    const attach = createConnectionFactory({ authorize: async () => false, loginTimeoutMs: 1_000, onRefused: (r) => refused.push(r) });
    let ended = false;
    const conn = attach({ sendMessage: () => {}, authenticated: { username: 'u', fingerprint: 'f' }, dataStreams: false, closeTransport: () => { ended = true; } });
    try {
      mock.timers.tick(60 * 60 * 1000);
      await settle();
      assert.equal(ended, false);
      assert.deepEqual(refused, []);
    } finally { mock.timers.reset(); conn.close(); }
  });

  it('loginTimeoutMs is validated on every host factory', () => {
    for (const bad of [-1, 'soon', NaN, Infinity]) {
      assert.throws(() => createMemoryHost({ loginTimeoutMs: bad }), /loginTimeoutMs/);
      assert.throws(() => createConnectionFactory({ authorize: async () => true, loginTimeoutMs: bad }), /loginTimeoutMs/);
      assert.throws(() => createWshServer({ loginTimeoutMs: bad }), /loginTimeoutMs/);
    }
  });
});
