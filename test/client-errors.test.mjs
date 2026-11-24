// test/client-errors.test.mjs -- authentication and connection refusals reach the caller as typed errors with stable codes
// (`WshAuthError`, `WshConnectionError`), the way a host-key mismatch is a `HostKeyError`. The message text stays what it was.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import {
  WshClient, WshAuthError, WshConnectionError, WSH_ERROR_CODES, classifyAuthRefusal, HostKeyError,
  generateKeyPair, exportPublicKeySSH,
} from '@johnhenry/wsh';

const until = async (cond, what, ms = 4000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 10)); }
};
const identity = async () => {
  const keyPair = await generateKeyPair(true);
  return { keyPair, ssh: `${await exportPublicKeySSH(keyPair.publicKey)} test` };
};
async function rejection(promise) {
  try { await promise; } catch (e) { return e; }
  assert.fail('expected a refusal');
}

describe('WshAuthError', () => {
  it('is an Error whose message is what it was, with a code, the host text and the refusal reason', async () => {
    const alice = await identity();
    const mallory = await identity();
    const refused = [];
    const host = createMemoryHost({ auth: { authorizedKeys: alice.ssh }, onRefused: (r) => refused.push(r) });
    try {
      const e = await rejection(host.connect({ username: 'mallory', keyPair: mallory.keyPair }));
      assert.ok(e instanceof Error && e instanceof WshAuthError);
      assert.equal(e.name, 'WshAuthError');
      assert.equal(e.message, 'Authentication failed: key not authorized', 'the text existing callers match on');
      assert.equal(e.code, 'AUTH_UNAUTHORIZED');
      assert.equal(e.reason, 'key not authorized');
      assert.equal(e.refusal, 'unauthorized');
      await until(() => refused.length, 'the host-side refusal');
      assert.equal(refused[0].reason, e.refusal, 'the client names the reason the host reported to onRefused');
      assert.ok(!(e instanceof HostKeyError));
    } finally { await host.close(); }
  });

  it('names, for each refusal the host reports to onRefused, the same reason (the table the client uses is tested against the host)', async () => {
    const alice = await identity();
    const mallory = await identity();
    const expired = await identity();
    const cases = [];

    const keyHost = (opts = {}, refused) => createMemoryHost({ auth: { authorizedKeys: alice.ssh, ...opts.auth }, onRefused: (r) => refused.push(r), ...opts.host });
    const run = async (label, make, attempt) => {
      const refused = [];
      const host = make(refused);
      try {
        const e = await rejection(attempt(host));
        await until(() => refused.length, `${label}: the host-side refusal`);
        cases.push([label, e, refused[0]]);
      } finally { await host.close(); }
    };

    await run('unauthorized key', (r) => keyHost({}, r), (h) => h.connect({ username: 'mallory', keyPair: mallory.keyPair }));
    await run('method-disabled', (r) => keyHost({}, r), (h) => h.connect({ username: 'pw', password: 'x' }));
    await run('wrong password', (r) => createMemoryHost({ auth: { password: async () => false, rateLimit: { failureDelayMs: 0 } }, onRefused: (x) => r.push(x) }), (h) => h.connect({ username: 'pw', password: 'x' }));
    await run('bad-request', (r) => keyHost({}, r), (h) => h.connect({ username: 'not a user!', keyPair: alice.keyPair }));
    await run('key-expired', (r) => createMemoryHost({ auth: { authorizedKeys: `expires="2020-01-01T00:00:00Z" ${expired.ssh}` }, onRefused: (x) => r.push(x) }), (h) => h.connect({ username: 'alice', keyPair: expired.keyPair }));

    for (const [label, error, hostSide] of cases) {
      assert.ok(error instanceof WshAuthError, `${label}: ${error?.message}`);
      assert.equal(error.refusal, hostSide.reason, `${label}: client says ${error.refusal}, host reported ${hostSide.reason}`);
      assert.equal(error.code, `AUTH_${hostSide.reason.toUpperCase().replace(/-/g, '_')}`, label);
    }
  });

  it('a throttled password login is AUTH_RATE_LIMITED', async () => {
    const refused = [];
    const host = createMemoryHost({ auth: { password: async () => false, rateLimit: { maxFailures: 1, windowMs: 60_000, lockoutMs: 60_000, failureDelayMs: 0 } }, onRefused: (r) => refused.push(r) });
    try {
      await rejection(host.connect({ username: 'pw', password: 'x' }));
      const e = await rejection(host.connect({ username: 'pw', password: 'x' }));
      assert.equal(e.code, 'AUTH_RATE_LIMITED');
      assert.equal(e.refusal, 'rate-limited');
      await until(() => refused.some((r) => r.reason === 'rate-limited'), 'the rate-limit refusal');
    } finally { await host.close(); }
  });

  it('over a real WebSocket too', async () => {
    const alice = await identity();
    const mallory = await identity();
    const server = createWshServer({ auth: { authorizedKeys: alice.ssh } });
    const { port } = await server.listen();
    try {
      const e = await rejection(new WshClient().connect(`ws://127.0.0.1:${port}`, { username: 'mallory', keyPair: mallory.keyPair, timeout: 4000 }));
      assert.ok(e instanceof WshAuthError);
      assert.equal(e.code, 'AUTH_UNAUTHORIZED');
    } finally { await server.close(); }
  });
});

describe('classifyAuthRefusal (what a host says, as the stable codes)', () => {
  it('knows the reasons the Node host and the Rust server send, and falls back to AUTH_FAILED', () => {
    const table = {
      'key not authorized': 'unauthorized',
      'authentication failed': 'unauthorized',
      'invalid password': 'unauthorized',
      'signature does not verify over the transcript': 'bad-signature',
      'signature verification failed': 'bad-signature',
      'password auth is not enabled on this host': 'method-disabled',
      'pubkey auth disabled': 'method-disabled',
      'too many failed attempts; try again in 30s': 'rate-limited',
      'rate limited: too many auth attempts': 'rate-limited',
      'key has expired': 'key-expired',
      'channel binding required: the signature is not bound to this connection': 'binding-required',
      'this host requires a sealed session, which needs a key login': 'not-sealed',
      'a sealed session is required': 'not-sealed',
      'bad username "x y"': 'bad-request',
    };
    for (const [reason, refusal] of Object.entries(table)) {
      assert.equal(classifyAuthRefusal(reason).refusal, refusal, reason);
    }
    for (const unknown of ['', 'because', undefined, null, 42]) {
      assert.deepEqual(classifyAuthRefusal(unknown), { code: 'AUTH_FAILED', refusal: null });
    }
  });

  it('the codes are a frozen, documented set', () => {
    assert.ok(Object.isFrozen(WSH_ERROR_CODES));
    for (const code of ['AUTH_FAILED', 'AUTH_UNAUTHORIZED', 'AUTH_BAD_SIGNATURE', 'AUTH_METHOD_DISABLED', 'AUTH_RATE_LIMITED', 'AUTH_KEY_EXPIRED', 'AUTH_BINDING_REQUIRED', 'AUTH_NOT_SEALED', 'AUTH_BAD_REQUEST', 'CONNECTION_FAILED', 'HANDSHAKE_TIMEOUT']) {
      assert.equal(WSH_ERROR_CODES[code], code);
    }
  });
});

describe('WshConnectionError', () => {
  it('a host that never answers the handshake is HANDSHAKE_TIMEOUT, with the same message as before', async () => {
    // A listener that accepts the socket and says nothing.
    const { WebSocketServer } = await import('ws');
    const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    await new Promise((r) => wss.once('listening', r));
    try {
      const e = await rejection(new WshClient().connect(`ws://127.0.0.1:${wss.address().port}`, { username: 'a', keyPair: (await identity()).keyPair, timeout: 300 }));
      assert.ok(e instanceof WshConnectionError, e.message);
      assert.equal(e.code, 'HANDSHAKE_TIMEOUT');
      assert.match(e.message, /Auth handshake timed out/);
    } finally { await new Promise((r) => wss.close(r)); }
  });

  it('no listener at all is CONNECTION_FAILED, keeping the message and listing each attempt', async () => {
    const e = await rejection(new WshClient().connect('ws://127.0.0.1:1', { username: 'a', keyPair: (await identity()).keyPair, timeout: 1500 }));
    assert.ok(e instanceof WshConnectionError, e.message);
    assert.equal(e.code, 'CONNECTION_FAILED');
    assert.match(e.message, /^Connection failed across transports \(/);
    assert.ok(Array.isArray(e.attempts) && e.attempts.length >= 1 && e.attempts.every((a) => typeof a === 'string'));
  });
});
