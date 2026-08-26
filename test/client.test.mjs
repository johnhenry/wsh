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
 * HELLO with CHALLENGE directly, then replies to AUTH with AUTH_OK that
 * does *not* include a session_id — so the client's final sessionId is
 * exactly the fallback `tempSessionId` computed for the CHALLENGE branch.
 * This isolates the value under test (regression for the 'pending'
 * hardcoded session-id finding).
 */
class ChallengeFirstMockTransport extends WshTransport {
  sentMessages = [];

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
        this._emitControl({ type: MSG.CHALLENGE, nonce: new Uint8Array(32).fill(7) });
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
  // Regression test for: the client used the literal string 'pending' as
  // the transcript session-id placeholder whenever a server skipped
  // SERVER_HELLO and sent CHALLENGE directly, making the session-id
  // component of the auth transcript identical across every connection
  // taking that path.

  it('connect(): CHALLENGE-first handshake uses a fresh per-connection session id, not "pending"', async () => {
    const keyPair = await auth.generateKeyPair(true);

    async function runOnce() {
      const client = new clientMod.WshClient({
        transportFactories: { ws: () => new ChallengeFirstMockTransport() },
      });
      return client.connect('ws://test.invalid', {
        username: 'alice',
        keyPair,
        transport: 'ws',
      });
    }

    const id1 = await runOnce();
    const id2 = await runOnce();

    assert.notEqual(id1, 'pending');
    assert.notEqual(id2, 'pending');
    assert.notEqual(id1, id2, 'two separate connections must not reuse the same fallback session id');
  });

  it('connectWithTransport()/#performAuth(): CHALLENGE-first handshake uses a fresh per-connection session id, not "pending"', async () => {
    const keyPair = await auth.generateKeyPair(true);

    async function runOnce() {
      const client = new clientMod.WshClient();
      const transport = new ChallengeFirstMockTransport();
      return client.connectWithTransport(transport, 'ws://test.invalid', {
        username: 'bob',
        keyPair,
      });
    }

    const id1 = await runOnce();
    const id2 = await runOnce();

    assert.notEqual(id1, 'pending');
    assert.notEqual(id2, 'pending');
    assert.notEqual(id1, id2, 'two separate connections must not reuse the same fallback session id');
  });
});
