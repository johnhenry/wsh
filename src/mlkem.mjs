/**
 * ML-KEM-768 (FIPS 203) for the hybrid X25519+ML-KEM-768 E2E key exchange
 * (see `client.mjs`'s `initiateE2E` "hybrid" mode).
 *
 * Prefers the native WebCrypto `ML-KEM-768` algorithm (Node 24.7+; an
 * experimental W3C draft also implemented by some browsers) so this
 * library adds no *required* runtime dependency, matching its existing
 * zero-runtime-dependency design (see `EncryptedFrame`'s spec note on why
 * AES-GCM was picked over ChaCha20-Poly1305 for the same reason). Falls
 * back to the optional `@noble/post-quantum` package's pure-JS
 * implementation only when native support is absent -- most browsers
 * today -- via a dynamic import, so it's never loaded unless hybrid mode
 * is actually used AND native support is missing.
 *
 * Public keys are always raw ML-KEM-768 bytes (1184 bytes); private keys
 * are always represented as a 64-byte keygen seed -- the one format both
 * backends already agree on (native WebCrypto's `raw-seed` import/export,
 * and noble's `keygen(seed)`) -- never a `CryptoKey` or an expanded
 * secret key, so callers never need to know which backend is active.
 *
 * Native support is unreliable to assume from feature presence alone: a
 * runtime can expose `encapsulateBits` and friends while not actually
 * implementing them correctly, so support is probed with a full
 * generate/encapsulate/decapsulate round trip on first use, not just a
 * `typeof` check.
 */

const ALG = { name: 'ML-KEM-768' };
export const MLKEM768_PUBLIC_KEY_LENGTH = 1184;
export const MLKEM768_CIPHERTEXT_LENGTH = 1088;
export const MLKEM768_SHARED_SECRET_LENGTH = 32;
const MLKEM768_SEED_LENGTH = 64;

let backendPromise = null; // Promise<'native' | 'noble'>, memoized after first probe
let noblePromise = null;   // Promise<typeof import('@noble/post-quantum/ml-kem.js')>, memoized

async function loadNoble() {
  if (!noblePromise) {
    noblePromise = import('@noble/post-quantum/ml-kem.js').catch((err) => {
      noblePromise = null;
      throw new Error(
        'Hybrid PQ key exchange requires either native WebCrypto ML-KEM-768 support ' +
        '(Node 24.7+, or a browser implementing the experimental draft) or the optional ' +
        `"@noble/post-quantum" package installed as a fallback. (${err.message})`
      );
    });
  }
  return noblePromise;
}

async function probeNativeSupport() {
  try {
    const { publicKey, privateKey } = await crypto.subtle.generateKey(ALG, true, ['encapsulateBits', 'decapsulateBits']);
    const { ciphertext, sharedKey } = await crypto.subtle.encapsulateBits(ALG, publicKey);
    const decapsulated = await crypto.subtle.decapsulateBits(ALG, privateKey, ciphertext);
    return bytesEqual(new Uint8Array(sharedKey), new Uint8Array(decapsulated));
  } catch {
    return false;
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function getBackend() {
  if (!backendPromise) {
    backendPromise = probeNativeSupport().then((supported) => (supported ? 'native' : 'noble'));
  }
  return backendPromise;
}

/** Import a 64-byte seed as a native ML-KEM-768 private key, usable for decapsulation. */
async function importNativePrivateKey(seed) {
  return crypto.subtle.importKey('raw-seed', seed, ALG, false, ['decapsulateBits']);
}

/** Derive the raw public key bytes for a 64-byte seed, via whichever backend is active. */
async function publicKeyFromSeed(seed, backend) {
  if (backend === 'native') {
    const privateKey = await importNativePrivateKey(seed);
    const publicKey = await crypto.subtle.getPublicKey(privateKey, ['encapsulateBits']);
    return new Uint8Array(await crypto.subtle.exportKey('raw-public', publicKey));
  }
  const { ml_kem768 } = await loadNoble();
  return ml_kem768.keygen(seed).publicKey;
}

/**
 * Generate a fresh ML-KEM-768 key pair.
 * @returns {Promise<{ publicKey: Uint8Array, secretKeySeed: Uint8Array }>}
 */
export async function generateMlKemKeyPair() {
  const seed = new Uint8Array(MLKEM768_SEED_LENGTH);
  crypto.getRandomValues(seed);
  const backend = await getBackend();
  const publicKey = await publicKeyFromSeed(seed, backend);
  return { publicKey, secretKeySeed: seed };
}

/**
 * Encapsulate against a peer's raw ML-KEM-768 public key.
 * @param {Uint8Array} publicKey - 1184-byte raw public key
 * @returns {Promise<{ ciphertext: Uint8Array, sharedSecret: Uint8Array }>}
 */
export async function mlKemEncapsulate(publicKey) {
  if (publicKey.length !== MLKEM768_PUBLIC_KEY_LENGTH) {
    throw new Error(`ML-KEM-768 public key must be ${MLKEM768_PUBLIC_KEY_LENGTH} bytes, got ${publicKey.length}`);
  }
  const backend = await getBackend();
  if (backend === 'native') {
    const importedPublicKey = await crypto.subtle.importKey('raw-public', publicKey, ALG, false, ['encapsulateBits']);
    const { ciphertext, sharedKey } = await crypto.subtle.encapsulateBits(ALG, importedPublicKey);
    return { ciphertext: new Uint8Array(ciphertext), sharedSecret: new Uint8Array(sharedKey) };
  }
  const { ml_kem768 } = await loadNoble();
  const randomness = new Uint8Array(32);
  crypto.getRandomValues(randomness);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, randomness);
  return { ciphertext: cipherText, sharedSecret };
}

/**
 * Decapsulate a ciphertext with a previously-generated seed's private key.
 * @param {Uint8Array} secretKeySeed - 64-byte seed from `generateMlKemKeyPair`
 * @param {Uint8Array} ciphertext - 1088-byte ciphertext from `mlKemEncapsulate`
 * @returns {Promise<Uint8Array>} 32-byte shared secret
 */
export async function mlKemDecapsulate(secretKeySeed, ciphertext) {
  if (ciphertext.length !== MLKEM768_CIPHERTEXT_LENGTH) {
    throw new Error(`ML-KEM-768 ciphertext must be ${MLKEM768_CIPHERTEXT_LENGTH} bytes, got ${ciphertext.length}`);
  }
  const backend = await getBackend();
  if (backend === 'native') {
    const privateKey = await importNativePrivateKey(secretKeySeed);
    const sharedKey = await crypto.subtle.decapsulateBits(ALG, privateKey, ciphertext);
    return new Uint8Array(sharedKey);
  }
  const { ml_kem768 } = await loadNoble();
  return ml_kem768.decapsulate(ciphertext, ml_kem768.keygen(secretKeySeed).secretKey);
}
