import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sealFrame, openFrame, buildNonce, ROLE_TAGS, E2E_NONCE_LENGTH } from '../src/e2e-frame.mjs';

const hasWebCrypto = typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

async function makeKey() {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

describe('e2e-frame', { skip: !hasWebCrypto && 'WebCrypto not available in this runtime' }, () => {
  it('sealFrame/openFrame round-trip correctly', async () => {
    const key = await makeKey();
    const plaintext = new TextEncoder().encode('hello from the initiator');

    const frame = await sealFrame(key, 'session-a', ROLE_TAGS.initiator, 0, plaintext);
    assert.equal(frame.nonce.length, E2E_NONCE_LENGTH);

    const opened = await openFrame(key, 'session-a', 0, { ...frame, expectedRoleTag: ROLE_TAGS.initiator });
    assert.deepEqual([...opened], [...plaintext]);
  });

  it('round-trips multiple sequential frames with increasing counters', async () => {
    const key = await makeKey();
    const messages = ['one', 'two', 'three'].map((s) => new TextEncoder().encode(s));

    const frames = [];
    for (let i = 0; i < messages.length; i++) {
      frames.push(await sealFrame(key, 'session-b', ROLE_TAGS.initiator, i, messages[i]));
    }
    for (let i = 0; i < messages.length; i++) {
      const opened = await openFrame(key, 'session-b', i, { ...frames[i], expectedRoleTag: ROLE_TAGS.initiator });
      assert.deepEqual([...opened], [...messages[i]]);
    }
  });

  it('tamper detection: a flipped ciphertext byte fails to open', async () => {
    const key = await makeKey();
    const plaintext = new TextEncoder().encode('do not tamper with me');
    const frame = await sealFrame(key, 'session-c', ROLE_TAGS.initiator, 0, plaintext);

    const tampered = { nonce: frame.nonce, ciphertext: frame.ciphertext.slice() };
    tampered.ciphertext[0] ^= 0xff;

    await assert.rejects(() => openFrame(key, 'session-c', 0, { ...tampered, expectedRoleTag: ROLE_TAGS.initiator }));
  });

  it('tamper detection: a flipped AAD (session_id) fails to open', async () => {
    const key = await makeKey();
    const plaintext = new TextEncoder().encode('bound to session-d only');
    const frame = await sealFrame(key, 'session-d', ROLE_TAGS.initiator, 0, plaintext);

    // Attempting to open under a different session_id (simulating a
    // relay splicing ciphertext from one session onto another) must fail.
    await assert.rejects(() => openFrame(key, 'session-e', 0, { ...frame, expectedRoleTag: ROLE_TAGS.initiator }));
  });

  it('replay/reorder rejection: an out-of-order or replayed counter is rejected', async () => {
    const key = await makeKey();
    const plaintext = new TextEncoder().encode('sequenced message');

    const frame0 = await sealFrame(key, 'session-f', ROLE_TAGS.initiator, 0, plaintext);
    const frame1 = await sealFrame(key, 'session-f', ROLE_TAGS.initiator, 1, plaintext);

    // Replaying frame0 when counter 1 is expected must fail.
    await assert.rejects(() => openFrame(key, 'session-f', 1, { ...frame0, expectedRoleTag: ROLE_TAGS.initiator }));
    // Skipping ahead (frame1 when 0 is expected) must also fail.
    await assert.rejects(() => openFrame(key, 'session-f', 0, { ...frame1, expectedRoleTag: ROLE_TAGS.initiator }));
    // The correctly-ordered sequence succeeds.
    await openFrame(key, 'session-f', 0, { ...frame0, expectedRoleTag: ROLE_TAGS.initiator });
    await openFrame(key, 'session-f', 1, { ...frame1, expectedRoleTag: ROLE_TAGS.initiator });
  });

  it('wrong key fails to open (authentication failure, not silent success)', async () => {
    const key = await makeKey();
    const otherKey = await makeKey();
    const plaintext = new TextEncoder().encode('secret');
    const frame = await sealFrame(key, 'session-g', ROLE_TAGS.initiator, 0, plaintext);

    await assert.rejects(() => openFrame(otherKey, 'session-g', 0, { ...frame, expectedRoleTag: ROLE_TAGS.initiator }));
  });

  it('nonce uniqueness: two consecutive seals from the same sender never produce the same nonce', async () => {
    const key = await makeKey();
    const plaintext = new TextEncoder().encode('x');

    const frameA = await sealFrame(key, 'session-h', ROLE_TAGS.initiator, 0, plaintext);
    const frameB = await sealFrame(key, 'session-h', ROLE_TAGS.initiator, 1, plaintext);

    assert.notDeepEqual([...frameA.nonce], [...frameB.nonce]);
  });

  it('nonce uniqueness: the two peers of a session cannot collide even at the same counter (distinct role tags)', async () => {
    const initiatorNonce = buildNonce(0, ROLE_TAGS.initiator);
    const responderNonce = buildNonce(0, ROLE_TAGS.responder);

    assert.notDeepEqual([...initiatorNonce], [...responderNonce]);
  });

  it('buildNonce lays out an 8-byte big-endian counter followed by the 4-byte role tag', () => {
    const nonce = buildNonce(1, ROLE_TAGS.initiator);
    assert.equal(nonce.length, 12);
    // First 8 bytes: big-endian counter = 1.
    assert.deepEqual([...nonce.slice(0, 8)], [0, 0, 0, 0, 0, 0, 0, 1]);
    // Last 4 bytes: the role tag, verbatim.
    assert.deepEqual([...nonce.slice(8, 12)], [...ROLE_TAGS.initiator]);
  });

  it('openFrame rejects a malformed nonce length rather than misbehaving', async () => {
    const key = await makeKey();
    await assert.rejects(() => openFrame(key, 'session-i', 0, { nonce: new Uint8Array(4), ciphertext: new Uint8Array(16) }));
  });
});

describe('e2e-frame role tag enforcement (#35)', { skip: !hasWebCrypto && 'WebCrypto not available' }, () => {
  /*
   * The tag exists so the two directions of one session are structurally
   * distinguishable, which is what makes a colliding nonce impossible when
   * both directions share one AES-GCM key. It was computed, stored on the
   * session, and never read: `grep -rn e2eRecvRoleTag src/` returned the
   * declaration and the assignment and no third line.
   *
   * So a receiver accepted a frame sealed with its OWN tag, and the relay
   * this layer exists to distrust could echo a peer's sealed frame back at
   * it. Both counters start at zero, so the first frame of a session
   * reflects cleanly.
   *
   * The old test for this compared ROLE_TAGS.initiator against
   * ROLE_TAGS.responder -- two frozen constants the test computed itself. It
   * could only fail if someone edited the constants, and said nothing about
   * what the receive path does.
   */
  it('rejects a frame sealed by the wrong side of the session', async () => {
    const key = await makeKey();
    const plaintext = new TextEncoder().encode('reflected back at the sender');

    // The initiator seals. A relay echoes it straight back, so the initiator
    // sees a frame carrying its own tag where the responder's belongs.
    const reflected = await sealFrame(key, 'session-reflect', ROLE_TAGS.initiator, 0, plaintext);

    await assert.rejects(
      () => openFrame(key, 'session-reflect', 0, { ...reflected, expectedRoleTag: ROLE_TAGS.responder }),
      /role tag mismatch/,
    );

    // The genuine direction still opens, so the check is not simply refusing.
    const genuine = await sealFrame(key, 'session-reflect', ROLE_TAGS.responder, 0, plaintext);
    const opened = await openFrame(key, 'session-reflect', 0, { ...genuine, expectedRoleTag: ROLE_TAGS.responder });
    assert.deepEqual([...opened], [...plaintext]);
  });

  it('refuses to open a frame at all when no tag is supplied', async () => {
    // An optional check is the same as no check -- which is how this got
    // shipped. A caller that forgets gets an error, not a silent skip.
    const key = await makeKey();
    const frame = await sealFrame(key, 'session-nofail', ROLE_TAGS.initiator, 0, new Uint8Array([1]));
    await assert.rejects(
      () => openFrame(key, 'session-nofail', 0, frame),
      /requires expectedRoleTag/,
    );
  });
});
