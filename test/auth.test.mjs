import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Note: Web Crypto API (crypto.subtle) with Ed25519 requires Node 20+ or a browser.
// These tests will skip gracefully if Ed25519 is not available.

let auth;
try {
  auth = await import('../src/auth.mjs');
} catch {
  // Module import may fail in environments without Web Crypto Ed25519
}

const hasEd25519 = auth && typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

describe('auth', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {

  it('generateKeyPair creates a key pair', async () => {
    const keyPair = await auth.generateKeyPair(true);
    assert.ok(keyPair.publicKey);
    assert.ok(keyPair.privateKey);
  });

  it('exportPublicKeyRaw returns 32 bytes', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const raw = await auth.exportPublicKeyRaw(keyPair.publicKey);
    assert.equal(raw.length, 32);
  });

  it('exportPublicKeySSH returns ssh-ed25519 format', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const ssh = await auth.exportPublicKeySSH(keyPair.publicKey);
    assert.ok(ssh.startsWith('ssh-ed25519 '));
  });

  it('sign and verify round-trip', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const signature = await auth.sign(keyPair.privateKey, data);
    assert.equal(signature.length, 64);

    const valid = await auth.verify(keyPair.publicKey, signature, data);
    assert.ok(valid);
  });

  it('verify rejects wrong data', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const data = new Uint8Array([1, 2, 3]);
    const signature = await auth.sign(keyPair.privateKey, data);

    const wrongData = new Uint8Array([4, 5, 6]);
    const valid = await auth.verify(keyPair.publicKey, signature, wrongData);
    assert.ok(!valid);
  });

  it('buildTranscript returns 32-byte hash', async () => {
    const nonce = new Uint8Array(32);
    const transcript = await auth.buildTranscript('session-1', nonce);
    assert.equal(transcript.length, 32);
  });

  it('buildTranscript is deterministic', async () => {
    const nonce = new Uint8Array(32).fill(42);
    const t1 = await auth.buildTranscript('s1', nonce);
    const t2 = await auth.buildTranscript('s1', nonce);
    assert.deepEqual([...t1], [...t2]);
  });

  it('buildTranscript differs for different inputs', async () => {
    const nonce = new Uint8Array(32).fill(1);
    const t1 = await auth.buildTranscript('s1', nonce);
    const t2 = await auth.buildTranscript('s2', nonce);
    assert.notDeepEqual([...t1], [...t2]);
  });

  it('signChallenge + verifyChallenge round-trip', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const nonce = auth.generateNonce();
    const sessionId = 'test-session';

    const { signature, publicKeyRaw } = await auth.signChallenge(
      keyPair.privateKey, keyPair.publicKey, sessionId, nonce
    );

    assert.equal(signature.length, 64);
    assert.equal(publicKeyRaw.length, 32);

    const imported = await auth.importPublicKeyRaw(publicKeyRaw);
    const valid = await auth.verifyChallenge(imported, signature, sessionId, nonce);
    assert.ok(valid);
  });

  it('buildPeerRecordTranscript returns 32-byte hash', async () => {
    const transcript = await auth.buildPeerRecordTranscript({ username: 'peer', seq: 1 });
    assert.equal(transcript.length, 32);
  });

  it('buildPeerRecordTranscript is deterministic for identical records', async () => {
    const record = { username: 'peer', peerType: 'host', shellBackend: 'pty', capabilities: ['exec'], seq: 42 };
    const t1 = await auth.buildPeerRecordTranscript(record);
    const t2 = await auth.buildPeerRecordTranscript({ ...record });
    assert.deepEqual([...t1], [...t2]);
  });

  it('buildPeerRecordTranscript differs when any field changes, including seq and each boolean flag', async () => {
    const base = { username: 'peer', peerType: 'host', shellBackend: 'pty', capabilities: ['exec'], seq: 1 };
    const baseline = await auth.buildPeerRecordTranscript(base);
    const variants = [
      { ...base, username: 'other' },
      { ...base, peerType: 'vm-guest' },
      { ...base, shellBackend: 'virtual-shell' },
      { ...base, capabilities: ['shell'] },
      { ...base, seq: 2 },
      { ...base, supportsAttach: true },
      { ...base, supportsReplay: true },
      { ...base, supportsEcho: true },
      { ...base, supportsTermSync: true },
    ];
    for (const variant of variants) {
      const t = await auth.buildPeerRecordTranscript(variant);
      assert.notDeepEqual([...t], [...baseline], `expected a different transcript for ${JSON.stringify(variant)}`);
    }
  });

  it('signPeerRecord + verifyPeerRecord round-trip', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const record = { username: 'browser-tab', capabilities: ['shell', 'exec'], peerType: 'browser-shell', shellBackend: 'virtual-shell', seq: Date.now() };

    const { signature, publicKeyRaw } = await auth.signPeerRecord(keyPair.privateKey, keyPair.publicKey, record);
    assert.equal(signature.length, 64);
    assert.equal(publicKeyRaw.length, 32);

    const imported = await auth.importPublicKeyRaw(publicKeyRaw);
    assert.ok(await auth.verifyPeerRecord(imported, signature, record));
  });

  it('verifyPeerRecord rejects a signature for a different record (e.g. tampered capabilities)', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const record = { username: 'browser-tab', capabilities: ['exec'], seq: 1 };
    const { signature, publicKeyRaw } = await auth.signPeerRecord(keyPair.privateKey, keyPair.publicKey, record);
    const imported = await auth.importPublicKeyRaw(publicKeyRaw);

    assert.equal(await auth.verifyPeerRecord(imported, signature, { ...record, capabilities: ['exec', 'shell'] }), false);
  });

  it('verifyPeerRecord rejects a record signed by a different key', async () => {
    const signer = await auth.generateKeyPair(true);
    const impostor = await auth.generateKeyPair(true);
    const record = { username: 'browser-tab', capabilities: ['exec'], seq: 1 };
    const { signature } = await auth.signPeerRecord(signer.privateKey, signer.publicKey, record);

    assert.equal(await auth.verifyPeerRecord(impostor.publicKey, signature, record), false);
  });

  it('a peer-record signature does not verify as an auth-challenge signature and vice versa (domain separation)', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const nonce = auth.generateNonce();
    const sessionId = 'session-1';

    const { signature: challengeSig } = await auth.signChallenge(keyPair.privateKey, keyPair.publicKey, sessionId, nonce, { username: 'u' });
    const record = { username: 'u', seq: 1 };
    const { signature: recordSig } = await auth.signPeerRecord(keyPair.privateKey, keyPair.publicKey, record);

    // Cross-domain: an auth-challenge signature must not verify as a peer
    // record, even reusing the same identity key and even if a peer
    // record happened to be constructed with matching fields.
    assert.equal(await auth.verifyPeerRecord(keyPair.publicKey, challengeSig, record), false);
    // And the reverse: a peer-record signature must not verify as an
    // auth-challenge response.
    assert.equal(await auth.verifyChallenge(keyPair.publicKey, recordSig, sessionId, nonce, { username: 'u' }), false);
  });

  it('fingerprint returns 64-char hex', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const raw = await auth.exportPublicKeyRaw(keyPair.publicKey);
    const fp = await auth.fingerprint(raw);
    assert.equal(fp.length, 64);
    assert.ok(/^[0-9a-f]+$/.test(fp));
  });

  it('shortFingerprint returns min 4 chars', () => {
    const short = auth.shortFingerprint('a3f8c2d1', ['b1c2d3e4'], 4);
    assert.equal(short.length, 4);
    assert.equal(short, 'a3f8');
  });

  it('shortFingerprint extends for collisions', () => {
    const short = auth.shortFingerprint('a3f8c2d1', ['a3f8d5e6'], 4);
    assert.equal(short, 'a3f8c');
  });

  it('generateNonce returns 32 random bytes', () => {
    const n1 = auth.generateNonce();
    const n2 = auth.generateNonce();
    assert.equal(n1.length, 32);
    assert.equal(n2.length, 32);
    // Extremely unlikely to be equal
    assert.notDeepEqual([...n1], [...n2]);
  });

  it('parseSSHPublicKey parses ed25519 keys', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const sshLine = await auth.exportPublicKeySSH(keyPair.publicKey);
    const parsed = auth.parseSSHPublicKey(sshLine);
    assert.ok(parsed);
    assert.equal(parsed.type, 'ssh-ed25519');
    assert.ok(parsed.data instanceof Uint8Array);
  });

  it('parseSSHPublicKey rejects non-ed25519', () => {
    const result = auth.parseSSHPublicKey('ssh-rsa AAAA... user@host');
    assert.equal(result, null);
  });

  it('extractRawFromSSHWire extracts 32-byte key', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const sshLine = await auth.exportPublicKeySSH(keyPair.publicKey);
    const parsed = auth.parseSSHPublicKey(sshLine);
    const raw = auth.extractRawFromSSHWire(parsed.data);
    assert.equal(raw.length, 32);

    // Should match direct export
    const directRaw = await auth.exportPublicKeyRaw(keyPair.publicKey);
    assert.deepEqual([...raw], [...directRaw]);
  });

  it('import/export PKCS8 round-trip', async () => {
    const keyPair = await auth.generateKeyPair(true);
    const pkcs8 = await auth.exportPrivateKeyPKCS8(keyPair.privateKey);
    assert.ok(pkcs8 instanceof Uint8Array);
    assert.ok(pkcs8.length > 0);

    const imported = await auth.importPrivateKeyPKCS8(pkcs8, true);
    // Sign with imported key, verify with original public key
    const data = new Uint8Array([10, 20, 30]);
    const sig = await auth.sign(imported, data);
    const valid = await auth.verify(keyPair.publicKey, sig, data);
    assert.ok(valid);
  });
});

describe('Ed25519 capability floor', { skip: !hasEd25519 && 'Ed25519 not available in this runtime' }, () => {
  // wsh has no pure-JS Ed25519 fallback -- deliberately, because one
  // would need the private scalar as ordinary bytes and give up the
  // non-extractable CryptoKey property WshKeyStore is built around. What
  // it owes callers instead is a way to ask, and a comprehensible failure
  // where the answer is no.

  it('isEd25519Supported() reports true on a runtime that has it', async () => {
    assert.equal(await auth.isEd25519Supported(), true);
  });

  it('isEd25519Supported() memoizes rather than re-probing', async () => {
    const first = auth.isEd25519Supported();
    const second = auth.isEd25519Supported();
    assert.equal(await first, await second);
  });

  it('generateKeyPair() explains the floor instead of forwarding "Unrecognized name"', async () => {
    const original = crypto.subtle.generateKey;
    crypto.subtle.generateKey = async () => {
      const err = new Error('Unrecognized name.');
      err.name = 'NotSupportedError';
      throw err;
    };
    try {
      await assert.rejects(
        () => auth.generateKeyPair(),
        (err) => {
          // The message must name the missing primitive, the versions
          // that have it, and what a caller can do instead -- none of
          // which the platform's own error says.
          assert.match(err.message, /WebCrypto Ed25519/);
          assert.match(err.message, /Safari 17\+/);
          assert.match(err.message, /isEd25519Supported/);
          assert.equal(err.cause?.name, 'NotSupportedError');
          return true;
        }
      );
    } finally {
      crypto.subtle.generateKey = original;
    }
  });

  it('a working runtime is unaffected by that wrapping', async () => {
    const keyPair = await auth.generateKeyPair(true);
    assert.ok(keyPair.publicKey);
    assert.ok(keyPair.privateKey);
  });
});
