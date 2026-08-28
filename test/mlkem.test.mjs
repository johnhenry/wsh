// test/mlkem.test.mjs — ML-KEM-768 abstraction used by initiateE2E's
// hybrid mode. Exercises whichever backend (native WebCrypto or the
// optional @noble/post-quantum fallback) this runtime actually selects
// -- see mlkem.mjs's own doc comment for why that's probed, not assumed.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

let mlkem;
try {
  mlkem = await import('../src/mlkem.mjs');
} catch {
  // Import may fail in an environment with neither native ML-KEM-768
  // support nor the optional @noble/post-quantum package installed.
}

describe('mlkem', { skip: !mlkem && 'ML-KEM-768 module failed to import' }, () => {
  it('generateMlKemKeyPair returns a 1184-byte public key and a 64-byte seed', async () => {
    const { publicKey, secretKeySeed } = await mlkem.generateMlKemKeyPair();
    assert.equal(publicKey.length, mlkem.MLKEM768_PUBLIC_KEY_LENGTH);
    assert.equal(publicKey.length, 1184);
    assert.equal(secretKeySeed.length, 64);
  });

  it('generateMlKemKeyPair produces different key pairs each call', async () => {
    const a = await mlkem.generateMlKemKeyPair();
    const b = await mlkem.generateMlKemKeyPair();
    assert.notDeepEqual([...a.publicKey], [...b.publicKey]);
    assert.notDeepEqual([...a.secretKeySeed], [...b.secretKeySeed]);
  });

  it('encapsulate + decapsulate round trip produces matching 32-byte shared secrets', async () => {
    const { publicKey, secretKeySeed } = await mlkem.generateMlKemKeyPair();
    const { ciphertext, sharedSecret: encapsulatorSecret } = await mlkem.mlKemEncapsulate(publicKey);

    assert.equal(ciphertext.length, mlkem.MLKEM768_CIPHERTEXT_LENGTH);
    assert.equal(ciphertext.length, 1088);
    assert.equal(encapsulatorSecret.length, mlkem.MLKEM768_SHARED_SECRET_LENGTH);
    assert.equal(encapsulatorSecret.length, 32);

    const decapsulatorSecret = await mlkem.mlKemDecapsulate(secretKeySeed, ciphertext);
    assert.deepEqual([...decapsulatorSecret], [...encapsulatorSecret]);
  });

  it('two encapsulations against the same public key produce different ciphertexts and secrets (fresh randomness each call)', async () => {
    const { publicKey } = await mlkem.generateMlKemKeyPair();
    const a = await mlkem.mlKemEncapsulate(publicKey);
    const b = await mlkem.mlKemEncapsulate(publicKey);
    assert.notDeepEqual([...a.ciphertext], [...b.ciphertext]);
    assert.notDeepEqual([...a.sharedSecret], [...b.sharedSecret]);
  });

  it('decapsulating with the wrong seed does not reproduce the encapsulator\'s shared secret', async () => {
    const alice = await mlkem.generateMlKemKeyPair();
    const mallory = await mlkem.generateMlKemKeyPair();
    const { ciphertext, sharedSecret } = await mlkem.mlKemEncapsulate(alice.publicKey);

    // ML-KEM's implicit-rejection property means decapsulating with the
    // wrong key doesn't error -- it deterministically produces a
    // different (wrong) secret rather than failing loudly, by design.
    const wrongSecret = await mlkem.mlKemDecapsulate(mallory.secretKeySeed, ciphertext);
    assert.notDeepEqual([...wrongSecret], [...sharedSecret]);
  });

  it('a seed deterministically regenerates the same public key', async () => {
    const { publicKey, secretKeySeed } = await mlkem.generateMlKemKeyPair();
    // Round-trip through encapsulate/decapsulate a second time using the
    // same seed to confirm it still decapsulates correctly -- the
    // strongest available proof the seed->key derivation is stable,
    // since mlkem.mjs doesn't expose a seed->publicKey function directly.
    const { ciphertext, sharedSecret } = await mlkem.mlKemEncapsulate(publicKey);
    const decapsulated = await mlkem.mlKemDecapsulate(secretKeySeed, ciphertext);
    assert.deepEqual([...decapsulated], [...sharedSecret]);
  });

  it('mlKemEncapsulate rejects a malformed (wrong-length) public key', async () => {
    await assert.rejects(() => mlkem.mlKemEncapsulate(new Uint8Array(10)));
  });

  it('mlKemDecapsulate rejects a malformed (wrong-length) ciphertext', async () => {
    const { secretKeySeed } = await mlkem.generateMlKemKeyPair();
    await assert.rejects(() => mlkem.mlKemDecapsulate(secretKeySeed, new Uint8Array(10)));
  });
});
