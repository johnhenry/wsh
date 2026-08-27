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
