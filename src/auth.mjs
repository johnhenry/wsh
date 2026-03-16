/**
 * Ed25519 key generation, signing, and verification via Web Crypto API.
 * Also builds authentication transcripts for the wsh challenge-response flow.
 */

import { PROTOCOL_VERSION } from './messages.mjs';

// ── Key Generation ────────────────────────────────────────────────────

/**
 * Generate a new Ed25519 key pair.
 * @param {boolean} [extractable=false] - Whether private key can be exported
 * @returns {Promise<CryptoKeyPair>} { publicKey, privateKey }
 */
export async function generateKeyPair(extractable = false) {
  return crypto.subtle.generateKey('Ed25519', extractable, ['sign', 'verify']);
}

// ── Export / Import ───────────────────────────────────────────────────

/**
 * Export public key as raw 32-byte Ed25519 point.
 * @param {CryptoKey} publicKey
 * @returns {Promise<Uint8Array>}
 */
export async function exportPublicKeyRaw(publicKey) {
  const buf = await crypto.subtle.exportKey('raw', publicKey);
  return new Uint8Array(buf);
}

/**
 * Export public key in SSH wire format: ssh-ed25519 AAAA...
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
export async function exportPublicKeySSH(publicKey) {
  const raw = await exportPublicKeyRaw(publicKey);
  const keyType = 'ssh-ed25519';
  const typeBytes = new TextEncoder().encode(keyType);

  // SSH wire format: [4-byte len][key type string][4-byte len][key data]
  const buf = new Uint8Array(4 + typeBytes.length + 4 + raw.length);
  const view = new DataView(buf.buffer);
  let offset = 0;

  view.setUint32(offset, typeBytes.length);
  offset += 4;
  buf.set(typeBytes, offset);
  offset += typeBytes.length;

  view.setUint32(offset, raw.length);
  offset += 4;
  buf.set(raw, offset);

  return `${keyType} ${base64Encode(buf)}`;
}

/**
 * Import a raw 32-byte Ed25519 public key.
 * @param {Uint8Array} raw
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKeyRaw(raw) {
  return crypto.subtle.importKey('raw', raw, 'Ed25519', true, ['verify']);
}

/**
 * Export private key as PKCS8 bytes.
 * @param {CryptoKey} privateKey - Must have been created with extractable=true
 * @returns {Promise<Uint8Array>}
 */
export async function exportPrivateKeyPKCS8(privateKey) {
  const buf = await crypto.subtle.exportKey('pkcs8', privateKey);
  return new Uint8Array(buf);
}

/**
 * Import a PKCS8-encoded Ed25519 private key.
 * @param {Uint8Array} pkcs8
 * @param {boolean} [extractable=false]
 * @returns {Promise<CryptoKey>}
 */
export async function importPrivateKeyPKCS8(pkcs8, extractable = false) {
  return crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', extractable, ['sign']);
}

// ── Signing / Verification ────────────────────────────────────────────

/**
 * Sign data with an Ed25519 private key.
 * @param {CryptoKey} privateKey
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>} 64-byte signature
 */
export async function sign(privateKey, data) {
  const sig = await crypto.subtle.sign('Ed25519', privateKey, data);
  return new Uint8Array(sig);
}

/**
 * Verify an Ed25519 signature.
 * @param {CryptoKey} publicKey
 * @param {Uint8Array} signature
 * @param {Uint8Array} data
 * @returns {Promise<boolean>}
 */
export async function verify(publicKey, signature, data) {
  return crypto.subtle.verify('Ed25519', publicKey, signature, data);
}

// ── Authentication Transcript ─────────────────────────────────────────

/**
 * Build the authentication transcript hash for challenge-response signing.
 *
 * transcript = SHA-256("wsh-v1\0" || session_id || nonce || channel_binding)
 *
 * @param {string} sessionId
 * @param {Uint8Array} nonce - 32-byte server nonce
 * @param {Uint8Array} [channelBinding] - Optional TLS channel binding
 * @returns {Promise<Uint8Array>} 32-byte SHA-256 hash
 */
export async function buildTranscript(sessionId, nonce, channelBinding = new Uint8Array(0)) {
  const enc = new TextEncoder();
  const versionBytes = enc.encode(PROTOCOL_VERSION + '\0');
  const sessionBytes = enc.encode(sessionId);

  const total = versionBytes.length + sessionBytes.length + nonce.length + channelBinding.length;
  const data = new Uint8Array(total);
  let offset = 0;

  data.set(versionBytes, offset); offset += versionBytes.length;
  data.set(sessionBytes, offset); offset += sessionBytes.length;
  data.set(nonce, offset); offset += nonce.length;
  data.set(channelBinding, offset);

  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

/**
 * Perform the full client-side auth signing:
 * 1. Build transcript hash
 * 2. Sign with private key
 * 3. Export public key for sending to server
 *
 * @param {CryptoKey} privateKey
 * @param {CryptoKey} publicKey
 * @param {string} sessionId
 * @param {Uint8Array} nonce
 * @param {Uint8Array} [channelBinding]
 * @returns {Promise<{ signature: Uint8Array, publicKeyRaw: Uint8Array }>}
 */
export async function signChallenge(privateKey, publicKey, sessionId, nonce, channelBinding) {
  const transcript = await buildTranscript(sessionId, nonce, channelBinding);
  const [signature, publicKeyRaw] = await Promise.all([
    sign(privateKey, transcript),
    exportPublicKeyRaw(publicKey),
  ]);
  return { signature, publicKeyRaw };
}

/**
 * Server-side: verify a client's challenge response.
 *
 * @param {CryptoKey} publicKey
 * @param {Uint8Array} signature
 * @param {string} sessionId
 * @param {Uint8Array} nonce
 * @param {Uint8Array} [channelBinding]
 * @returns {Promise<boolean>}
 */
export async function verifyChallenge(publicKey, signature, sessionId, nonce, channelBinding) {
  const transcript = await buildTranscript(sessionId, nonce, channelBinding);
  return verify(publicKey, signature, transcript);
}

// ── Fingerprint ───────────────────────────────────────────────────────

/**
 * Compute the SHA-256 fingerprint of a raw public key.
 * @param {Uint8Array} publicKeyRaw - 32-byte raw Ed25519 public key
 * @returns {Promise<string>} hex-encoded fingerprint
 */
export async function fingerprint(publicKeyRaw) {
  const hash = await crypto.subtle.digest('SHA-256', publicKeyRaw);
  return hexEncode(new Uint8Array(hash));
}

/**
 * Compute the base64url-encoded SHA-256 pod ID of a raw public key.
 * This is the BrowserMesh identity format (43 chars).
 * @param {Uint8Array} publicKeyRaw - 32-byte raw Ed25519 public key
 * @returns {Promise<string>} base64url-encoded pod ID
 */
export async function podId(publicKeyRaw) {
  const hash = await crypto.subtle.digest('SHA-256', publicKeyRaw);
  return base64urlEncode(new Uint8Array(hash));
}

/**
 * Convert a hex fingerprint to a base64url pod ID.
 * @param {string} hexFingerprint - 64-char hex fingerprint
 * @returns {string} base64url pod ID
 */
export function fingerprintToPodId(hexFingerprint) {
  const bytes = new Uint8Array(hexFingerprint.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexFingerprint.slice(i * 2, i * 2 + 2), 16);
  }
  return base64urlEncode(bytes);
}

/**
 * Convert a base64url pod ID to a hex fingerprint.
 * @param {string} podIdStr - base64url pod ID
 * @returns {string} hex fingerprint
 */
export function podIdToFingerprint(podIdStr) {
  const bytes = base64urlDecode(podIdStr);
  return hexEncode(bytes);
}

/**
 * Get the shortest unique prefix of a fingerprint within a set.
 * @param {string} fp - Full hex fingerprint
 * @param {string[]} allFingerprints - All fingerprints in the context
 * @param {number} [minLen=4] - Minimum prefix length
 * @returns {string}
 */
export function shortFingerprint(fp, allFingerprints = [], minLen = 4) {
  const others = allFingerprints.filter(f => f !== fp);
  for (let len = minLen; len <= fp.length; len++) {
    const prefix = fp.slice(0, len);
    if (!others.some(f => f.startsWith(prefix))) return prefix;
  }
  return fp;
}

// ── Nonce ─────────────────────────────────────────────────────────────

/**
 * Generate a random 32-byte nonce.
 * @returns {Uint8Array}
 */
export function generateNonce() {
  return crypto.getRandomValues(new Uint8Array(32));
}

// ── Helpers ───────────────────────────────────────────────────────────

function hexEncode(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64urlEncode(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64Encode(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64Decode(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Parse an SSH public key string ("ssh-ed25519 AAAA... comment").
 * @param {string} line
 * @returns {{ type: string, data: Uint8Array, comment: string } | null}
 */
export function parseSSHPublicKey(line) {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 2) return null;
  const [type, b64, ...rest] = parts;
  if (type !== 'ssh-ed25519') return null;
  try {
    const data = base64Decode(b64);
    return { type, data, comment: rest.join(' ') };
  } catch {
    return null;
  }
}

/**
 * Extract the raw 32-byte Ed25519 public key from SSH wire format.
 * @param {Uint8Array} wireData - SSH wire-encoded public key
 * @returns {Uint8Array} 32-byte raw key
 */
export function extractRawFromSSHWire(wireData) {
  const view = new DataView(wireData.buffer, wireData.byteOffset, wireData.byteLength);
  // Skip key type string
  const typeLen = view.getUint32(0);
  const keyOffset = 4 + typeLen + 4;
  const keyLen = view.getUint32(4 + typeLen);
  return wireData.slice(keyOffset, keyOffset + keyLen);
}
