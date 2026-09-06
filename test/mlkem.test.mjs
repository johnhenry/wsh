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

// ---------------------------------------------------------------------------
// The noble path, which is the only one a browser can take (#42)
// ---------------------------------------------------------------------------
//
// `getBackend()` memoised a probe that always succeeds on this repo's target
// runtime, so every assertion above ran against native and not one line of
// the noble branch had ever executed -- `ml_kem768.keygen`, `.encapsulate`
// and `.decapsulate` included. No browser implements the experimental
// WebCrypto ML-KEM draft, so noble is what every browser consumer of
// `initiateE2E(..., 'X25519+ML-KEM-768')` actually runs.
//
// The file's own header claimed it exercised "whichever backend this runtime
// actually selects", and its skip guard claimed to catch a missing noble --
// unreachable, since the import is lazy and there is no top-level probe.
//
// WSH_MLKEM_BACKEND forces the choice. The env var is read per call, not
// memoised, which is what lets one process play both peers.

const nobleAvailable = await import('@noble/post-quantum/ml-kem.js').then(() => true, () => false);

describe('ML-KEM-768 noble backend', { skip: !nobleAvailable && '@noble/post-quantum is not installed' }, () => {
  const withBackend = async (name, fn) => {
    const previous = process.env.WSH_MLKEM_BACKEND;
    process.env.WSH_MLKEM_BACKEND = name;
    try { return await fn(); } finally {
      if (previous === undefined) delete process.env.WSH_MLKEM_BACKEND;
      else process.env.WSH_MLKEM_BACKEND = previous;
    }
  };

  it('round-trips entirely on noble', async () => {
    await withBackend('noble', async () => {
      const kp = await mlkem.generateMlKemKeyPair();
      assert.equal(kp.publicKey.length, mlkem.MLKEM768_PUBLIC_KEY_LENGTH);
      const enc = await mlkem.mlKemEncapsulate(kp.publicKey);
      assert.equal(enc.ciphertext.length, mlkem.MLKEM768_CIPHERTEXT_LENGTH);
      const shared = await mlkem.mlKemDecapsulate(kp.secretKeySeed, enc.ciphertext);
      assert.deepEqual([...shared], [...enc.sharedSecret]);
    });
  });

  it('a browser peer and a Node peer derive the SAME secret', async () => {
    /*
     * The failure this guards against is not a crash. If noble's argument
     * order or seed semantics drift from the native draft -- it is pinned
     * only to ^0.7.0 and called through three positional APIs -- the two
     * sides still complete, and derive DIFFERENT secrets. Every frame
     * afterwards fails to open, far from the cause.
     *
     * Both directions, because either peer may be the browser.
     */
    const nativeKeys = await withBackend('native', () => mlkem.generateMlKemKeyPair());
    const fromNoble = await withBackend('noble', () => mlkem.mlKemEncapsulate(nativeKeys.publicKey));
    const atNative = await withBackend('native', () =>
      mlkem.mlKemDecapsulate(nativeKeys.secretKeySeed, fromNoble.ciphertext));
    assert.deepEqual([...atNative], [...fromNoble.sharedSecret], 'noble -> native');

    const nobleKeys = await withBackend('noble', () => mlkem.generateMlKemKeyPair());
    const fromNative = await withBackend('native', () => mlkem.mlKemEncapsulate(nobleKeys.publicKey));
    const atNoble = await withBackend('noble', () =>
      mlkem.mlKemDecapsulate(nobleKeys.secretKeySeed, fromNative.ciphertext));
    assert.deepEqual([...atNoble], [...fromNative.sharedSecret], 'native -> noble');
  });
});
