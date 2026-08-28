import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { WshTransport } from '../src/transport.mjs';
import { MSG } from '../src/messages.gen.mjs';

// Note: Web Crypto API (crypto.subtle) with Ed25519 requires Node 20+ or a browser.
// These tests will skip gracefully if Ed25519 is not available.

let auth;
let clientMod;
try {
  auth = await import('../src/auth.mjs');
  clientMod = await import('../src/client.mjs');
} catch {
  // Module import may fail in environments without Web Crypto Ed25519
}

const hasEd25519 = auth && typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

/**
 * A minimal in-memory transport that skips SERVER_HELLO and replies to
 * HELLO with CHALLENGE directly (carrying a real, unique-per-connection
 * session_id — a legitimate server always includes one), then replies to
 * AUTH with AUTH_OK that does *not* include a session_id — so the
 * client's final sessionId can only have come from the CHALLENGE message,
 * proving the client never synthesizes one client-side.
 */
class ChallengeFirstMockTransport extends WshTransport {
  sentMessages = [];
  #sessionId;

  constructor(sessionId) {
    super();
    this.#sessionId = sessionId;
  }

  async _doConnect() {
    // no-op: immediately "connected"
  }

  async _doClose() {
    // no-op
  }

  async _doSendControl(msg) {
    this.sentMessages.push(msg);
    // Reply on a macrotask (not queueMicrotask): the caller registers its
    // response waiter via a microtask continuation right after this call
    // resolves, so replying via another microtask can race ahead of that
    // registration and get silently dropped.
    if (msg.type === MSG.HELLO) {
      setTimeout(() => {
        this._emitControl({ type: MSG.CHALLENGE, nonce: new Uint8Array(32).fill(7), session_id: this.#sessionId });
      }, 0);
    } else if (msg.type === MSG.AUTH) {
      setTimeout(() => {
        this._emitControl({ type: MSG.AUTH_OK });
      }, 0);
    }
  }

  async _doOpenStream() {
    throw new Error('not needed for this test');
  }
}

describe('WshClient auth handshake', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  // Regression test for: the client used to synthesize a session-id
  // placeholder (previously the literal string 'pending', later
  // crypto.randomUUID()) whenever a server skipped SERVER_HELLO and sent
  // CHALLENGE directly. Now that Challenge.session_id is a required wire
  // field, the client must use exactly what the server provides — never
  // synthesize its own value, and never silently fall back to a fixed
  // literal that would collapse the transcript's session-id component
  // across every connection taking this path.

  it('connect(): CHALLENGE-first handshake uses exactly the session id the server provided', async () => {
    const keyPair = await auth.generateKeyPair(true);

    async function runOnce(sessionId) {
      const client = new clientMod.WshClient({
        transportFactories: { ws: () => new ChallengeFirstMockTransport(sessionId) },
      });
      return client.connect('ws://test.invalid', {
        username: 'alice',
        keyPair,
        transport: 'ws',
      });
    }

    const id1 = await runOnce('server-session-1');
    const id2 = await runOnce('server-session-2');

    assert.equal(id1, 'server-session-1');
    assert.equal(id2, 'server-session-2');
  });

  it('connectWithTransport()/#performAuth(): CHALLENGE-first handshake uses exactly the session id the server provided', async () => {
    const keyPair = await auth.generateKeyPair(true);

    async function runOnce(sessionId) {
      const client = new clientMod.WshClient();
      const transport = new ChallengeFirstMockTransport(sessionId);
      return client.connectWithTransport(transport, 'ws://test.invalid', {
        username: 'bob',
        keyPair,
      });
    }

    const id1 = await runOnce('server-session-3');
    const id2 = await runOnce('server-session-4');

    assert.equal(id1, 'server-session-3');
    assert.equal(id2, 'server-session-4');
  });
});

/**
 * Extends the auth handshake with scriptable replies to the session-
 * management messages this file's second describe block exercises:
 * DETACH, SESSION_LIST_REQUEST, SESSION_GRANT, SESSION_REVOKE. Each
 * reply is queued explicitly so a test can control success/failure.
 */
class SessionManagementMockTransport extends ChallengeFirstMockTransport {
  #replies = new Map(); // request MSG.* -> reply message (or null to send nothing)

  queueReply(requestType, reply) {
    this.#replies.set(requestType, reply);
  }

  async _doSendControl(msg) {
    await super._doSendControl(msg);
    if (!this.#replies.has(msg.type)) return;
    const reply = this.#replies.get(msg.type);
    if (reply === null) return;
    setTimeout(() => this._emitControl(reply), 0);
  }
}

describe('WshClient session management', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  async function connectedClient(transport) {
    const keyPair = await auth.generateKeyPair(true);
    const client = new clientMod.WshClient({
      transportFactories: { ws: () => transport },
    });
    await client.connect('ws://test.invalid', { username: 'alice', keyPair, transport: 'ws' });
    return client;
  }

  it('detach() resolves on DETACH_OK', async () => {
    const transport = new SessionManagementMockTransport('sess-detach-ok');
    transport.queueReply(MSG.DETACH, { type: MSG.DETACH_OK, session_id: 'target-1' });
    const client = await connectedClient(transport);

    await client.detach('target-1');

    const sent = transport.sentMessages.find((m) => m.type === MSG.DETACH);
    assert.equal(sent.session_id, 'target-1');
  });

  it('detach() throws on DETACH_FAIL with the server-provided reason', async () => {
    const transport = new SessionManagementMockTransport('sess-detach-fail');
    transport.queueReply(MSG.DETACH, { type: MSG.DETACH_FAIL, reason: 'no such session' });
    const client = await connectedClient(transport);

    await assert.rejects(() => client.detach('missing'), /no such session/);
  });

  it('listRemoteSessions() returns the SESSION_LIST payload, distinct from the local listSessions()', async () => {
    const transport = new SessionManagementMockTransport('sess-list');
    const sessions = [{ session_id: 'a', username: 'alice' }, { session_id: 'b', username: 'alice' }];
    transport.queueReply(MSG.SESSION_LIST_REQUEST, { type: MSG.SESSION_LIST, sessions });
    const client = await connectedClient(transport);

    const result = await client.listRemoteSessions();

    assert.deepEqual(result, sessions);
    // The purely-local method must stay unaffected -- no channels are open.
    assert.deepEqual(client.listSessions(), []);
  });

  it('grantSessionAccess() sends SESSION_GRANT with the given principal and permissions', async () => {
    const transport = new SessionManagementMockTransport('sess-grant');
    const client = await connectedClient(transport);

    await client.grantSessionAccess('sess-1', 'bob', ['read', 'write']);

    const sent = transport.sentMessages.find((m) => m.type === MSG.SESSION_GRANT);
    assert.ok(sent);
    assert.equal(sent.session_id, 'sess-1');
    assert.equal(sent.principal, 'bob');
    assert.deepEqual(sent.permissions, ['read', 'write']);
  });

  it('revokeSessionAccess() sends SESSION_REVOKE with the given principal', async () => {
    const transport = new SessionManagementMockTransport('sess-revoke');
    const client = await connectedClient(transport);

    await client.revokeSessionAccess('sess-1', 'bob', 'no longer needed');

    const sent = transport.sentMessages.find((m) => m.type === MSG.SESSION_REVOKE);
    assert.ok(sent);
    assert.equal(sent.session_id, 'sess-1');
    assert.equal(sent.principal, 'bob');
    assert.equal(sent.reason, 'no longer needed');
  });
});

/**
 * A mock transport that walks the *standard* handshake path (SERVER_HELLO
 * -> CHALLENGE -> AUTH -> AUTH_OK), as opposed to ChallengeFirstMockTransport's
 * deliberately-nonstandard CHALLENGE-first path. Doesn't perform real
 * signature verification -- it's exercising the client's state machine,
 * not the crypto (that's auth.test.mjs's job).
 */
class StandardHandshakeMockTransport extends WshTransport {
  sentMessages = [];
  #sessionId;
  #rejectAuth;

  constructor(sessionId, { rejectAuth = false } = {}) {
    super();
    this.#sessionId = sessionId;
    this.#rejectAuth = rejectAuth;
  }

  async _doConnect() {}
  async _doClose() {}
  async _doOpenStream() { throw new Error('not needed for this test'); }

  async _doSendControl(msg) {
    this.sentMessages.push(msg);
    if (msg.type === MSG.HELLO) {
      setTimeout(() => {
        this._emitControl({
          type: MSG.SERVER_HELLO,
          session_id: this.#sessionId,
          features: ['reverse'],
        });
      }, 0);
    } else if (msg.type === MSG.AUTH) {
      setTimeout(() => {
        if (this.#rejectAuth) {
          this._emitControl({ type: MSG.AUTH_FAIL, reason: 'signature verification failed' });
        } else {
          this._emitControl({ type: MSG.AUTH_OK, session_id: this.#sessionId, token: 'resume-token-xyz' });
        }
      }, 0);
    }
  }

  /** Server sends CHALLENGE after SERVER_HELLO, once the client asks (i.e. after HELLO). Triggered manually via emitChallenge() below since the base HELLO handler already replies with SERVER_HELLO. */
  emitChallenge(nonce = new Uint8Array(32).fill(3)) {
    this._emitControl({ type: MSG.CHALLENGE, session_id: this.#sessionId, nonce });
  }
}

describe('WshClient auth handshake (standard SERVER_HELLO-first path)', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  it('walks SERVER_HELLO -> CHALLENGE -> AUTH -> AUTH_OK and authenticates', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const transport = new StandardHandshakeMockTransport('server-session-std');

    // Intercept HELLO to also schedule a CHALLENGE right after SERVER_HELLO,
    // matching a real server's normal pubkey-auth flow.
    const originalSend = transport._doSendControl.bind(transport);
    transport._doSendControl = async (msg) => {
      await originalSend(msg);
      if (msg.type === MSG.HELLO) {
        setTimeout(() => transport.emitChallenge(), 1);
      }
    };

    const client = new clientMod.WshClient({
      transportFactories: { ws: () => transport },
    });

    const sessionId = await client.connect('ws://test.invalid', {
      username: 'carol',
      keyPair,
      transport: 'ws',
    });

    assert.equal(sessionId, 'server-session-std');
    const authSent = transport.sentMessages.find((m) => m.type === MSG.AUTH);
    assert.ok(authSent, 'client should have sent an AUTH message after CHALLENGE');
    assert.equal(authSent.method, 'pubkey');
  });

  it('rejects with a clear error when the server sends AUTH_FAIL', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const transport = new StandardHandshakeMockTransport('server-session-reject', { rejectAuth: true });
    const originalSend = transport._doSendControl.bind(transport);
    transport._doSendControl = async (msg) => {
      await originalSend(msg);
      if (msg.type === MSG.HELLO) {
        setTimeout(() => transport.emitChallenge(), 1);
      }
    };

    const client = new clientMod.WshClient({
      transportFactories: { ws: () => transport },
    });

    await assert.rejects(
      () => client.connect('ws://test.invalid', { username: 'carol', keyPair, transport: 'ws' }),
      /signature verification failed/
    );
  });
});
