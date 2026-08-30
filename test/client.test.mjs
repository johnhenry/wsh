import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { WshTransport } from '../src/transport.mjs';
import { MSG, keyExchange } from '../src/messages.gen.mjs';
import { generateMlKemKeyPair, mlKemEncapsulate, mlKemDecapsulate } from '../src/mlkem.mjs';

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

  // ── clawser #48: OpenOk.session_id/token, attachSession/resumeSession ──
  //
  // Regression coverage for the actual bug: attachSession() used to send
  // this connection's own AUTH-level token (bound to a different
  // session_id) and wait on OPEN_OK/OPEN_FAIL, which the server's Attach
  // handler never sends on success (it replies with PRESENCE) -- so it
  // would have hung even once the token itself was fixed. Both are fixed
  // together here.

  it('openSession() exposes the server-provided session_id/token from OPEN_OK on the returned WshSession', async () => {
    const transport = new SessionManagementMockTransport('sess-open-creds');
    const token = new Uint8Array(40).fill(7);
    transport.queueReply(MSG.OPEN, {
      type: MSG.OPEN_OK,
      channel_id: 1,
      data_mode: 'virtual',
      session_id: 'pty-sess-1',
      token,
    });
    const client = await connectedClient(transport);

    const session = await client.openSession({ type: 'pty' });

    assert.equal(session.sessionId, 'pty-sess-1');
    assert.deepEqual(session.resumeToken, token);
  });

  it('openSession() leaves sessionId/resumeToken undefined when OPEN_OK omits them (e.g. file channels)', async () => {
    const transport = new SessionManagementMockTransport('sess-open-no-creds');
    transport.queueReply(MSG.OPEN, { type: MSG.OPEN_OK, channel_id: 1, data_mode: 'virtual' });
    const client = await connectedClient(transport);

    const session = await client.openSession({ type: 'pty' });

    assert.equal(session.sessionId, undefined);
    assert.equal(session.resumeToken, undefined);
  });

  it('attachSession() sends no token by default (ACL/ownership-only attach) and resolves on PRESENCE', async () => {
    const transport = new SessionManagementMockTransport('sess-attach-no-token');
    transport.queueReply(MSG.ATTACH, {
      type: MSG.PRESENCE,
      attachments: [{ session_id: 'target-1', mode: 'control', username: 'alice' }],
    });
    const client = await connectedClient(transport);

    const response = await client.attachSession('target-1');

    const sent = transport.sentMessages.find((m) => m.type === MSG.ATTACH);
    assert.ok(sent);
    assert.equal(sent.session_id, 'target-1');
    assert.equal(sent.token, undefined);
    assert.equal(response.type, MSG.PRESENCE);
  });

  it('attachSession() forwards an explicit token when the caller provides one', async () => {
    const transport = new SessionManagementMockTransport('sess-attach-token');
    const token = new Uint8Array(40).fill(3);
    transport.queueReply(MSG.ATTACH, {
      type: MSG.PRESENCE,
      attachments: [{ session_id: 'target-2', mode: 'control', username: 'alice' }],
    });
    const client = await connectedClient(transport);

    await client.attachSession('target-2', { token });

    const sent = transport.sentMessages.find((m) => m.type === MSG.ATTACH);
    assert.deepEqual(sent.token, token);
  });

  it('attachSession() throws with the server-provided message on ERROR', async () => {
    const transport = new SessionManagementMockTransport('sess-attach-fail');
    transport.queueReply(MSG.ATTACH, {
      type: MSG.ERROR,
      code: 2,
      message: 'not authorized to attach to this session',
    });
    const client = await connectedClient(transport);

    await assert.rejects(
      () => client.attachSession('target-3'),
      /not authorized to attach to this session/
    );
  });

  it('resumeSession() sends the required token and resolves on PRESENCE', async () => {
    const transport = new SessionManagementMockTransport('sess-resume-ok');
    const token = new Uint8Array(40).fill(4);
    transport.queueReply(MSG.RESUME, {
      type: MSG.PRESENCE,
      attachments: [{ session_id: 'target-4', mode: 'control', username: 'alice' }],
    });
    const client = await connectedClient(transport);

    const response = await client.resumeSession('target-4', token);

    const sent = transport.sentMessages.find((m) => m.type === MSG.RESUME);
    assert.ok(sent);
    assert.equal(sent.session_id, 'target-4');
    assert.deepEqual(sent.token, token);
    assert.equal(sent.last_seq, 0);
    assert.equal(response.type, MSG.PRESENCE);
  });

  it('resumeSession() throws with the server-provided message on ERROR (e.g. invalid/expired token)', async () => {
    const transport = new SessionManagementMockTransport('sess-resume-fail');
    const token = new Uint8Array(40).fill(4);
    transport.queueReply(MSG.RESUME, {
      type: MSG.ERROR,
      code: 2,
      message: 'invalid token: token error: invalid token signature',
    });
    const client = await connectedClient(transport);

    await assert.rejects(
      () => client.resumeSession('target-5', token),
      /invalid token signature/
    );
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

// ── initiateE2E: classical + hybrid PQ key exchange (wsh #18) ────────
//
// Simulates the "peer" side of the two-party KeyExchange protocol
// directly in the mock transport, using real crypto (mlkem.mjs, WebCrypto
// X25519/HKDF) -- not by calling the client.mjs functions under test, so
// these tests can't pass just because both sides share the same bug.
// compareBytesForRole/combineViaHkdf below are an independently-written
// reimplementation of client.mjs's private compareBytes/
// combineHybridSecret, not an import of them.

function compareBytesForRole(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

async function combineViaHkdf(x25519Bits, kemSharedSecret) {
  const ikm = new Uint8Array(x25519Bits.length + kemSharedSecret.length);
  ikm.set(x25519Bits, 0);
  ikm.set(kemSharedSecret, x25519Bits.length);
  const hkdfKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('wsh-hybrid-e2e-v1') },
    hkdfKey,
    256
  );
  return new Uint8Array(bits);
}

/**
 * The client's derived `sharedSecret` is deliberately non-extractable
 * (`crypto.subtle.importKey(..., false, ...)` in `initiateE2E`), so
 * these tests can't compare it against the mock's independently-derived
 * bytes via `exportKey`. Instead: encrypt a probe plaintext with the
 * client's key, decrypt it with an AES-GCM key imported from the mock's
 * raw bytes, and check the plaintext round-trips -- this only works if
 * the two keys are byte-identical, and additionally proves the client's
 * key is actually usable for AES-GCM (not just structurally present).
 */
async function assertSameAesKey(clientCryptoKey, peerRawKeyBytes) {
  const peerKey = await crypto.subtle.importKey('raw', peerRawKeyBytes, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode('wsh-e2e-key-agreement-probe');
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, clientCryptoKey, plaintext);
  const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, peerKey, ciphertext));
  assert.deepEqual([...decrypted], [...plaintext]);
}

/**
 * Plays the "peer" side of initiateE2E's KeyExchange protocol against a
 * real WshClient under test, on top of the auth-handshake scripting
 * ChallengeFirstMockTransport already provides.
 * @param {boolean} peerSupportsHybrid - if false, the mock never sends
 *   back kem_public_key even if the client-under-test requests hybrid,
 *   simulating an older/non-hybrid peer.
 */
class E2EMockTransport extends ChallengeFirstMockTransport {
  /** @type {Uint8Array|null} set once this mock has computed its final combined secret */
  peerCombinedSecret = null;
  hybridUsed = false;
  #peerSupportsHybrid;
  #peerEphemeral = null;
  #peerKem = null;
  #storedSharedBits = null;

  constructor(sessionId, { peerSupportsHybrid = true } = {}) {
    super(sessionId);
    this.#peerSupportsHybrid = peerSupportsHybrid;
  }

  async _doSendControl(msg) {
    await super._doSendControl(msg);
    if (msg.type !== MSG.KEY_EXCHANGE) return;

    if (msg.public_key) {
      // Round 1 from the client under test: reply with our own ephemeral
      // X25519 key (and, if requested and supported, an ML-KEM-768 key).
      this.#peerEphemeral = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
      const peerPub = new Uint8Array(await crypto.subtle.exportKey('raw', this.#peerEphemeral.publicKey));

      const clientPubKey = await crypto.subtle.importKey('raw', msg.public_key, { name: 'X25519' }, false, []);
      this.#storedSharedBits = new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'X25519', public: clientPubKey }, this.#peerEphemeral.privateKey, 256
      ));

      const wantHybrid = this.#peerSupportsHybrid && !!msg.kem_public_key;
      this.hybridUsed = wantHybrid;
      let kemPub;
      let ciphertextToSend = null;

      if (wantHybrid) {
        this.#peerKem = await generateMlKemKeyPair();
        kemPub = this.#peerKem.publicKey;

        const mockIsEncapsulator = compareBytesForRole(peerPub, new Uint8Array(msg.public_key)) < 0;
        if (mockIsEncapsulator) {
          const { ciphertext, sharedSecret } = await mlKemEncapsulate(new Uint8Array(msg.kem_public_key));
          this.peerCombinedSecret = await combineViaHkdf(this.#storedSharedBits, sharedSecret);
          ciphertextToSend = ciphertext;
        }
        // else: the client under test is the encapsulator -- this mock's
        // combined secret is finalized below when its round-2 ciphertext arrives.
      } else {
        this.peerCombinedSecret = this.#storedSharedBits;
      }

      setTimeout(() => {
        this._emitControl(keyExchange({ algorithm: msg.algorithm, publicKey: peerPub, sessionId: msg.session_id, kemPublicKey: kemPub }));
        if (ciphertextToSend) {
          setTimeout(() => {
            this._emitControl(keyExchange({ algorithm: msg.algorithm, sessionId: msg.session_id, kemCiphertext: ciphertextToSend }));
          }, 0);
        }
      }, 0);
      return;
    }

    if (msg.kem_ciphertext) {
      // Round 2 from the client under test: it was the encapsulator, we're the decapsulator.
      const kemSharedSecret = await mlKemDecapsulate(this.#peerKem.secretKeySeed, new Uint8Array(msg.kem_ciphertext));
      this.peerCombinedSecret = await combineViaHkdf(this.#storedSharedBits, kemSharedSecret);
    }
  }
}

/**
 * Retries `fn` up to `times` extra attempts if it rejects with a message
 * matching `pattern` -- used below only for the specific, root-caused
 * "Timed out waiting for peer ML-KEM-768 ciphertext" flake (see the
 * comment on the hybrid-mode test): a real protocol bug would fail
 * every attempt, including a fresh one with new transports/keys/timers,
 * so a retry can't paper over a genuine correctness problem here, only
 * the known Node-experimental-provider instability under concurrent
 * multi-process load. `node:test`'s built-in `{ retries }` test option
 * isn't available in the Node version this repo currently targets.
 */
async function retryOnKnownFlake(fn, { times = 2, pattern = /Timed out waiting for peer ML-KEM-768 ciphertext/ } = {}) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt >= times || !pattern.test(err.message)) throw err;
    }
  }
}

describe('WshClient initiateE2E', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  async function connectedClient(transport) {
    const keyPair = await auth.generateKeyPair(true);
    const client = new clientMod.WshClient({ transportFactories: { ws: () => transport } });
    await client.connect('ws://test.invalid', { username: 'alice', keyPair, transport: 'ws' });
    return client;
  }

  it('classical X25519 mode: client and peer derive the same AES-256-GCM key', async () => {
    const transport = new E2EMockTransport('sess-e2e-classical');
    const client = await connectedClient(transport);

    const result = await client.initiateE2E('session-1', 'X25519');

    assert.equal(result.hybrid, false);
    await assertSameAesKey(result.sharedSecret, transport.peerCombinedSecret);
  });

  it('hybrid X25519+ML-KEM-768 mode: client and peer derive the same combined AES-256-GCM key, and both mark it hybrid', async () => {
    // Runs several times since which side ends up as the ML-KEM
    // encapsulator vs decapsulator is determined by comparing randomly
    // generated ephemeral keys -- looping gives reasonable odds of
    // exercising both role assignments across the suite's lifetime,
    // rather than only ever testing whichever role wins on one run.
    //
    // Timeout is deliberately generous (30s, well above initiateE2E's
    // 10s default) and the iteration count kept modest: on a machine
    // where `node --test` runs this file concurrently with another
    // process that's *also* exercising Node's native ML-KEM-768
    // WebCrypto implementation (still explicitly experimental, see the
    // ExperimentalWarning it emits), the two processes' calls can
    // occasionally stall for many seconds -- confirmed via repeated
    // isolated runs of just this file (100% reliable, always <100ms
    // total) vs. paired with test/mlkem.test.mjs (occasionally hangs
    // tens of seconds). That's an instability in Node's still-
    // experimental provider under concurrent multi-process load, not a
    // bug in the protocol logic here or in mlkem.mjs.
    for (let i = 0; i < 3; i++) {
      await retryOnKnownFlake(async () => {
        const transport = new E2EMockTransport(`sess-e2e-hybrid-${i}`);
        const client = await connectedClient(transport);

        const result = await client.initiateE2E(`session-hybrid-${i}`, 'X25519+ML-KEM-768', 30_000);

        assert.equal(result.hybrid, true);
        assert.equal(transport.hybridUsed, true);
        await assertSameAesKey(result.sharedSecret, transport.peerCombinedSecret);
      });
    }
  });

  it('falls back to classical mode when the peer does not support hybrid, without failing the exchange', async () => {
    const transport = new E2EMockTransport('sess-e2e-fallback', { peerSupportsHybrid: false });
    const client = await connectedClient(transport);

    const result = await client.initiateE2E('session-fallback', 'X25519+ML-KEM-768', 30_000);

    assert.equal(result.hybrid, false);
    assert.equal(transport.hybridUsed, false);
    // The fallback key must be the *classical* X25519-only secret, not
    // some partially-hybrid value -- proves the client didn't try to
    // combine in a KEM secret that was never actually established.
    await assertSameAesKey(result.sharedSecret, transport.peerCombinedSecret);
  });

  it('classical and hybrid modes for otherwise-identical key material produce different final keys', async () => {
    // Sanity check that hybrid mode's HKDF combination step actually
    // changes the derived key rather than being a no-op: encrypt with
    // the hybrid client's key, then confirm the *classical* peer's
    // X25519-only-derived key fails to decrypt it (AES-GCM's auth tag
    // check throws on any key mismatch, including a valid-but-wrong key).
    const hybridResult = await retryOnKnownFlake(async () => {
      const hybridTransport = new E2EMockTransport('sess-e2e-diff-hybrid');
      const hybridClient = await connectedClient(hybridTransport);
      return hybridClient.initiateE2E('session-diff-2', 'X25519+ML-KEM-768', 30_000);
    });

    const classicalTransport = new E2EMockTransport('sess-e2e-diff-classical');
    const classicalClient = await connectedClient(classicalTransport);
    await classicalClient.initiateE2E('session-diff-1', 'X25519');

    await assert.rejects(() => assertSameAesKey(hybridResult.sharedSecret, classicalTransport.peerCombinedSecret));
  });
});

// ── EncryptedFrame end-to-end integration (wsh #19) ───────────────────
//
// Wires two *real* WshClient instances together (not one under test
// against a scripted mock, unlike E2EMockTransport above) so both sides
// of initiateE2E()'s KeyExchange are the actual production code path,
// then activates two real WshSession instances in virtual mode and
// exercises the actual enableE2E()/write()/_handleControlMessage()
// plumbing this PR adds. An "eavesdropper" observes every control
// message exchanged between the two sides and asserts the plaintext
// never appears on the wire.

/**
 * A transport whose KeyExchange (and, once linked, EncryptedFrame)
 * control messages are delivered directly to a paired transport's
 * onControl, simulating a relay that only shuttles opaque control
 * messages between two peers -- exactly the role a real wsh server
 * plays for E2E traffic (it relays KeyExchange/EncryptedFrame without
 * being able to read session content). `wireLog` records every message
 * that crosses the link, standing in for what an eavesdropping relay
 * would see on the wire.
 */
class E2ELinkedTransport extends WshTransport {
  #sessionId;
  #peer = null;
  wireLog = [];

  constructor(sessionId) {
    super();
    this.#sessionId = sessionId;
  }

  link(peer) {
    this.#peer = peer;
  }

  async _doConnect() {}
  async _doClose() {}

  async _doSendControl(msg) {
    if (msg.type === MSG.HELLO) {
      setTimeout(() => this._emitControl({ type: MSG.CHALLENGE, nonce: new Uint8Array(32).fill(7), session_id: this.#sessionId }), 0);
      return;
    }
    if (msg.type === MSG.AUTH) {
      setTimeout(() => this._emitControl({ type: MSG.AUTH_OK }), 0);
      return;
    }
    if (msg.type === MSG.KEY_EXCHANGE || msg.type === MSG.ENCRYPTED_FRAME) {
      this.wireLog.push(msg);
      setTimeout(() => this.#peer?._emitControl(msg), 0);
    }
  }

  async _doOpenStream() {
    throw new Error('not needed for this test');
  }
}

describe('EncryptedFrame end-to-end integration', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  it('two real WshClient/WshSession pairs exchange sealed data that an eavesdropper on the raw wire cannot read', async () => {
    const keyPairA = await auth.generateKeyPair(true);
    const keyPairB = await auth.generateKeyPair(true);

    const transportA = new E2ELinkedTransport('sess-e2e-integ');
    const transportB = new E2ELinkedTransport('sess-e2e-integ');
    transportA.link(transportB);
    transportB.link(transportA);

    const clientA = new clientMod.WshClient({ transportFactories: { ws: () => transportA } });
    const clientB = new clientMod.WshClient({ transportFactories: { ws: () => transportB } });
    await clientA.connect('ws://test.invalid', { username: 'alice', keyPair: keyPairA, transport: 'ws' });
    await clientB.connect('ws://test.invalid', { username: 'bob', keyPair: keyPairB, transport: 'ws' });

    // Real, production initiateE2E() calls on both sides, linked directly
    // to each other via the transports above -- not a scripted mock peer.
    const [resultA, resultB] = await Promise.all([
      clientA.initiateE2E('sess-e2e-integ', 'X25519', 30_000),
      clientB.initiateE2E('sess-e2e-integ', 'X25519', 30_000),
    ]);
    assert.equal(resultA.hybrid, false);
    assert.equal(resultB.hybrid, false);

    // Build two WshSession instances directly in virtual mode, wired to
    // each other exactly like transportA/transportB above -- standing in
    // for the relay a real server would provide between two session
    // participants without being able to read the content.
    const sessionModule = await import('../src/session.mjs');
    const { WshSession } = sessionModule;

    const dummyTransport = { sendControl: async () => {} };
    const sessionA = new WshSession(dummyTransport, 1, {}, 'pty', { dataMode: 'virtual', sessionId: 'sess-e2e-integ' });
    const sessionB = new WshSession(dummyTransport, 1, {}, 'pty', { dataMode: 'virtual', sessionId: 'sess-e2e-integ' });

    const wireLog = [];
    sessionA._activateVirtual(async (msg) => {
      wireLog.push(msg);
      sessionB._handleControlMessage(msg);
    });
    sessionB._activateVirtual(async (msg) => {
      wireLog.push(msg);
      sessionA._handleControlMessage(msg);
    });

    sessionA.enableE2E(resultA.sharedSecret, { role: 'initiator' });
    sessionB.enableE2E(resultB.sharedSecret, { role: 'responder' });

    const plaintext = 'this is a secret message from A to B';
    const received = new Promise((resolve) => {
      sessionB.onData = (data) => resolve(new TextDecoder().decode(data));
    });

    await sessionA.write(plaintext);
    const receivedText = await received;

    assert.equal(receivedText, plaintext);

    // The eavesdropper (wireLog, standing in for a relay/server reading
    // raw control-message bytes) must never see the plaintext, or any
    // substring of it, in the frame it observed.
    assert.equal(wireLog.length, 1);
    const frame = wireLog[0];
    assert.equal(frame.type, MSG.ENCRYPTED_FRAME);
    const ciphertextAsLatin1 = Buffer.from(frame.ciphertext).toString('latin1');
    assert.equal(ciphertextAsLatin1.includes(plaintext), false);
    // Also confirm the raw nonce+ciphertext bytes, concatenated, don't
    // contain the plaintext -- belt-and-suspenders over the ciphertext-
    // only check above.
    const wireBytes = Buffer.concat([Buffer.from(frame.nonce), Buffer.from(frame.ciphertext)]).toString('latin1');
    assert.equal(wireBytes.includes(plaintext), false);
  });

  it('a tampered EncryptedFrame on the wire is silently dropped, not delivered as corrupted plaintext', async () => {
    const keyPairA = await auth.generateKeyPair(true);
    const keyPairB = await auth.generateKeyPair(true);

    const transportA = new E2ELinkedTransport('sess-e2e-tamper');
    const transportB = new E2ELinkedTransport('sess-e2e-tamper');
    transportA.link(transportB);
    transportB.link(transportA);

    const clientA = new clientMod.WshClient({ transportFactories: { ws: () => transportA } });
    const clientB = new clientMod.WshClient({ transportFactories: { ws: () => transportB } });
    await clientA.connect('ws://test.invalid', { username: 'alice', keyPair: keyPairA, transport: 'ws' });
    await clientB.connect('ws://test.invalid', { username: 'bob', keyPair: keyPairB, transport: 'ws' });

    const [resultA, resultB] = await Promise.all([
      clientA.initiateE2E('sess-e2e-tamper', 'X25519', 30_000),
      clientB.initiateE2E('sess-e2e-tamper', 'X25519', 30_000),
    ]);

    const sessionModule = await import('../src/session.mjs');
    const { WshSession } = sessionModule;
    const dummyTransport = { sendControl: async () => {} };
    const sessionA = new WshSession(dummyTransport, 1, {}, 'pty', { dataMode: 'virtual', sessionId: 'sess-e2e-tamper' });
    const sessionB = new WshSession(dummyTransport, 1, {}, 'pty', { dataMode: 'virtual', sessionId: 'sess-e2e-tamper' });

    sessionA._activateVirtual(async (msg) => {
      // Flip a ciphertext byte before delivery, simulating an active
      // tamperer on the wire.
      if (msg.type === MSG.ENCRYPTED_FRAME) {
        msg.ciphertext = msg.ciphertext.slice();
        msg.ciphertext[0] ^= 0xff;
      }
      sessionB._handleControlMessage(msg);
    });
    sessionB._activateVirtual(async (msg) => sessionA._handleControlMessage(msg));

    sessionA.enableE2E(resultA.sharedSecret, { role: 'initiator' });
    sessionB.enableE2E(resultB.sharedSecret, { role: 'responder' });

    let delivered = false;
    sessionB.onData = () => { delivered = true; };

    await sessionA.write('will be tampered with');
    // Give the async openFrame()/catch() a turn to run.
    await new Promise((resolve) => setTimeout(resolve, 10));

    assert.equal(delivered, false);
  });
});

// ── Stream-mode chunk-framed EncryptedFrame end-to-end integration (wsh #22) ──
//
// Mirrors the virtual-mode integration tests above, but wires two real
// WshSession instances in stream mode (`_bind()` with actual
// ReadableStream/WritableStream pairs, like a real WebTransport data
// stream) instead of `_activateVirtual()`. Confirms the whole PR-1 path
// end to end: enableE2E() on a stream-mode session, write()'s chunk
// sealing + framing (src/stream-frame.mjs's encodeChunk), and
// _pumpDataStream()'s ChunkAccumulator + openFrame reassembly, all using
// real production initiateE2E() key exchange.

/**
 * Builds a linked ReadableStream/WritableStream pair standing in for one
 * direction of a raw WebTransport data stream: bytes written to
 * `writable` are recorded in `wireLog` (standing in for what an
 * eavesdropping relay/server would see) and then delivered to
 * `readable`, optionally mutated by `mutate` first (to simulate an
 * active tamperer).
 */
function makeLinkedStreamPair(wireLog, mutate) {
  let controller;
  const readable = new ReadableStream({
    start(c) {
      controller = c;
    },
  });
  const writable = new WritableStream({
    write(chunk) {
      wireLog.push(chunk);
      controller.enqueue(mutate ? mutate(chunk) : chunk);
    },
    close() {
      controller.close();
    },
    abort(reason) {
      controller.error(reason);
    },
  });
  return { readable, writable };
}

describe('Stream-mode EncryptedFrame chunk framing end-to-end integration', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  it('two real WshClient/WshSession pairs exchange chunk-framed sealed data over a raw stream that an eavesdropper cannot read', async () => {
    const keyPairA = await auth.generateKeyPair(true);
    const keyPairB = await auth.generateKeyPair(true);

    const transportA = new E2ELinkedTransport('sess-e2e-stream');
    const transportB = new E2ELinkedTransport('sess-e2e-stream');
    transportA.link(transportB);
    transportB.link(transportA);

    const clientA = new clientMod.WshClient({ transportFactories: { ws: () => transportA } });
    const clientB = new clientMod.WshClient({ transportFactories: { ws: () => transportB } });
    await clientA.connect('ws://test.invalid', { username: 'alice', keyPair: keyPairA, transport: 'ws' });
    await clientB.connect('ws://test.invalid', { username: 'bob', keyPair: keyPairB, transport: 'ws' });

    const [resultA, resultB] = await Promise.all([
      clientA.initiateE2E('sess-e2e-stream', 'X25519', 30_000),
      clientB.initiateE2E('sess-e2e-stream', 'X25519', 30_000),
    ]);

    const sessionModule = await import('../src/session.mjs');
    const { WshSession } = sessionModule;

    const dummyTransport = { sendControl: async () => {} };
    // 'exec' kind, matching the design's revised PR-3 plan to switch
    // exec-type sessions to stream-mode data planes.
    const sessionA = new WshSession(dummyTransport, 1, {}, 'exec', { dataMode: 'stream', sessionId: 'sess-e2e-stream' });
    const sessionB = new WshSession(dummyTransport, 1, {}, 'exec', { dataMode: 'stream', sessionId: 'sess-e2e-stream' });

    const wireLog = [];
    const pipeAtoB = makeLinkedStreamPair(wireLog);
    // sessionA never receives; sessionB never sends -- only the A -> B
    // direction is exercised here, so the other halves are unused stubs.
    sessionA._bind(new ReadableStream(), pipeAtoB.writable);
    sessionB._bind(pipeAtoB.readable, new WritableStream());

    // coalesce: false so this single write() seals and sends immediately
    // (no timer/threshold to wait out in the test).
    sessionA.enableE2E(resultA.sharedSecret, { role: 'initiator', coalesce: false });
    sessionB.enableE2E(resultB.sharedSecret, { role: 'responder', coalesce: false });

    const plaintext = 'this is a secret message sent over the raw chunk-framed stream';
    const received = new Promise((resolve) => {
      sessionB.onData = (data) => resolve(new TextDecoder().decode(data));
    });

    await sessionA.write(plaintext);
    const receivedText = await received;

    assert.equal(receivedText, plaintext);

    // The eavesdropper must never see the plaintext, or any substring of
    // it, anywhere in the raw bytes that crossed the "wire".
    assert.equal(wireLog.length, 1);
    const wireBytes = Buffer.concat(wireLog.map((chunk) => Buffer.from(chunk))).toString('latin1');
    assert.equal(wireBytes.includes(plaintext), false);
  });

  it('a tampered chunk on the raw stream is not delivered as corrupted plaintext', async () => {
    const keyPairA = await auth.generateKeyPair(true);
    const keyPairB = await auth.generateKeyPair(true);

    const transportA = new E2ELinkedTransport('sess-e2e-stream-tamper');
    const transportB = new E2ELinkedTransport('sess-e2e-stream-tamper');
    transportA.link(transportB);
    transportB.link(transportA);

    const clientA = new clientMod.WshClient({ transportFactories: { ws: () => transportA } });
    const clientB = new clientMod.WshClient({ transportFactories: { ws: () => transportB } });
    await clientA.connect('ws://test.invalid', { username: 'alice', keyPair: keyPairA, transport: 'ws' });
    await clientB.connect('ws://test.invalid', { username: 'bob', keyPair: keyPairB, transport: 'ws' });

    const [resultA, resultB] = await Promise.all([
      clientA.initiateE2E('sess-e2e-stream-tamper', 'X25519', 30_000),
      clientB.initiateE2E('sess-e2e-stream-tamper', 'X25519', 30_000),
    ]);

    const sessionModule = await import('../src/session.mjs');
    const { WshSession } = sessionModule;
    const dummyTransport = { sendControl: async () => {} };
    const sessionA = new WshSession(dummyTransport, 1, {}, 'exec', { dataMode: 'stream', sessionId: 'sess-e2e-stream-tamper' });
    const sessionB = new WshSession(dummyTransport, 1, {}, 'exec', { dataMode: 'stream', sessionId: 'sess-e2e-stream-tamper' });

    const wireLog = [];
    // Flip a byte inside the ciphertext region of the wire-format chunk
    // ([4-byte len][12-byte nonce][ciphertext+tag]), simulating an
    // active tamperer on the raw stream.
    const pipeAtoB = makeLinkedStreamPair(wireLog, (chunk) => {
      const tampered = chunk.slice();
      tampered[4 + 12] ^= 0xff;
      return tampered;
    });
    sessionA._bind(new ReadableStream(), pipeAtoB.writable);
    sessionB._bind(pipeAtoB.readable, new WritableStream());

    sessionA.enableE2E(resultA.sharedSecret, { role: 'initiator', coalesce: false });
    sessionB.enableE2E(resultB.sharedSecret, { role: 'responder', coalesce: false });

    let delivered = false;
    sessionB.onData = () => {
      delivered = true;
    };

    await sessionA.write('will be tampered with on the raw stream');
    // Give the async openFrame()/pump loop a turn to run.
    await new Promise((resolve) => setTimeout(resolve, 20));

    assert.equal(delivered, false);
  });
});

// ── Data-stream EOF vs EXIT/CLOSE control-message race (wsh #24) ──────
//
// Stream-mode sessions carry data and control on two independently-
// multiplexed transport streams with no guaranteed relative delivery
// order. A server that ends the data stream and sends EXIT+CLOSE around
// the same time (as on process exit) can have the data-stream FIN reach
// the client first. Before the wsh #24 fix, _pumpDataStream() treated
// that FIN alone as sufficient to close the session, so callers waiting
// on onClose could resolve before onExit ever fired -- silently losing
// the exit code. These tests deliberately control the delivery order
// (something a naive "everything arrives in the expected order" test
// would never exercise) via the real dispatch entry points --
// `_bind()`'s pump loop for the data stream and `_handleControlMessage()`
// for control messages -- rather than poking at session internals.

/**
 * A stream-mode WshSession bound to a controllable ReadableStream, so
 * the test can decide exactly when the data stream reaches EOF
 * independently of when control messages are delivered via
 * `_handleControlMessage()`.
 */
async function makeControllableStreamSession() {
  const sessionModule = await import('../src/session.mjs');
  const { WshSession } = sessionModule;
  const dummyTransport = { sendControl: async () => {} };

  let controller;
  const readable = new ReadableStream({
    start(c) {
      controller = c;
    },
  });
  const session = new WshSession(dummyTransport, 1, {}, 'exec', { dataMode: 'stream' });
  session._bind(readable, new WritableStream());

  return { session, closeDataStream: () => controller.close() };
}

describe('WshSession data-stream EOF vs EXIT/CLOSE control-message race (wsh #24)', () => {
  it('data-stream EOF arriving before EXIT/CLOSE does not lose the exit code (adversarial ordering)', async () => {
    const { session, closeDataStream } = await makeControllableStreamSession();

    const events = [];
    const closed = new Promise((resolve) => {
      session.onClose = () => {
        events.push('close');
        resolve();
      };
    });
    session.onExit = (code) => {
      events.push(`exit:${code}`);
    };

    // Unlucky delivery order: the data stream's FIN reaches the client
    // first...
    closeDataStream();
    // ...give the pump loop a turn to observe EOF and schedule its grace
    // timer before the control messages "arrive" (simulating them
    // actually being in flight on a separate stream at data-EOF time).
    await new Promise((resolve) => setTimeout(resolve, 5));

    // ...and only afterwards do EXIT and CLOSE land, via the real
    // control-message dispatch path.
    session._handleControlMessage({ type: MSG.EXIT, code: 42 });
    session._handleControlMessage({ type: MSG.CLOSE });

    await closed;

    assert.deepEqual(events, ['exit:42', 'close']);
    assert.equal(session.exitCode, 42);
  });

  it('CLOSE arriving promptly short-circuits the grace period instead of waiting it out', async () => {
    const { session, closeDataStream } = await makeControllableStreamSession();

    const closed = new Promise((resolve) => {
      session.onClose = resolve;
    });

    closeDataStream();
    await new Promise((resolve) => setTimeout(resolve, 5));

    const start = Date.now();
    session._handleControlMessage({ type: MSG.EXIT, code: 0 });
    session._handleControlMessage({ type: MSG.CLOSE });
    await closed;
    const elapsed = Date.now() - start;

    // The session-level DATA_EOF_CLOSE_GRACE_MS fallback is 300ms; a
    // prompt CLOSE must resolve onClose well before that, not idle out
    // the timer.
    assert.ok(elapsed < 150, `expected CLOSE to short-circuit the wait, took ${elapsed}ms`);
  });

  it('control messages arriving before data-stream EOF close normally (non-adversarial ordering)', async () => {
    const { session, closeDataStream } = await makeControllableStreamSession();

    const events = [];
    const closed = new Promise((resolve) => {
      session.onClose = () => {
        events.push('close');
        resolve();
      };
    });
    session.onExit = (code) => {
      events.push(`exit:${code}`);
    };

    session._handleControlMessage({ type: MSG.EXIT, code: 7 });
    session._handleControlMessage({ type: MSG.CLOSE });
    closeDataStream();

    await closed;

    assert.deepEqual(events, ['exit:7', 'close']);
    assert.equal(session.state, 'closed');
  });

  it('falls back to closing after the grace period if CLOSE never arrives (no hang)', async () => {
    const { session, closeDataStream } = await makeControllableStreamSession();

    const closed = new Promise((resolve) => {
      session.onClose = resolve;
    });

    const start = Date.now();
    closeDataStream();
    // Deliberately never send CLOSE.
    await closed;
    const elapsed = Date.now() - start;

    assert.equal(session.state, 'closed');
    // Must have waited out (approximately) the grace period, not closed
    // instantly on data-EOF alone...
    assert.ok(elapsed >= 250, `expected the grace-period fallback (~300ms), closed after only ${elapsed}ms`);
    // ...but also must not hang indefinitely.
    assert.ok(elapsed < 2000, `grace-period fallback took far too long: ${elapsed}ms`);
  });
});
