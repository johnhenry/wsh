/**
 * A tampered challenge fails authentication.
 *
 * wsh authenticates clients with an Ed25519 challenge-response (spec/wsh-v1.md,
 * "Crypto Primitives"): the server sends a random nonce, the client signs the
 * transcript SHA-256("wsh-v1\0" || session_id || nonce || channel_binding),
 * and the server verifies the signature against the client's public key.
 *
 * Signing the *transcript* — not the bare nonce — binds the signature to this
 * protocol version and this session, so a signature can never be replayed
 * against a different session or spliced into another connection. This example
 * runs the whole flow in-process (no network) and shows exactly which
 * manipulations make verification fail.
 */

import assert from 'node:assert/strict';
import {
  generateKeyPair, exportPublicKeyRaw, exportPublicKeySSH,
  importPublicKeyRaw, signChallenge, verifyChallenge,
  fingerprint, shortFingerprint, generateNonce, parseSSHPublicKey,
} from '@johnhenry/wsh';

// ── Client: generate an identity ──────────────────────────────────────

const { publicKey, privateKey } = await generateKeyPair();
const sshKey = await exportPublicKeySSH(publicKey);
const raw = await exportPublicKeyRaw(publicKey);
const fp = await fingerprint(raw);

console.log('client identity:');
console.log(`  ${sshKey.slice(0, 40)}... (authorized_keys format)`);
console.log(`  fingerprint ${shortFingerprint(fp)}… (${fp.length}-char hex)`);

// The SSH-format key parses back to the same 32 raw bytes the server stores.
const parsed = parseSSHPublicKey(sshKey);
assert.ok(parsed, 'SSH key line parses');

// ── Server: issue a challenge ─────────────────────────────────────────

const sessionId = 'sess-42';
const nonce = generateNonce(); // 32 random bytes
console.log(`server challenge: session "${sessionId}", ${nonce.length}-byte nonce`);

// ── Client: sign the transcript ───────────────────────────────────────

const { signature, publicKeyRaw } = await signChallenge(
  privateKey, publicKey, sessionId, nonce
);
console.log(`client response: ${signature.length}-byte signature + ${publicKeyRaw.length}-byte public key`);

// ── Server: verify ────────────────────────────────────────────────────

// The server imports the raw key the client sent (after checking it against
// authorized keys) and verifies the transcript signature.
const serverSideKey = await importPublicKeyRaw(publicKeyRaw);

const genuine = await verifyChallenge(serverSideKey, signature, sessionId, nonce);
assert.equal(genuine, true);
console.log('genuine response:            verified ✓');

// Tampering 1: replay against a different session — transcript changes, fails.
const replayed = await verifyChallenge(serverSideKey, signature, 'sess-43', nonce);
assert.equal(replayed, false);
console.log('same signature, other session: rejected ✓');

// Tampering 2: stale/forged nonce — fails.
const forgedNonce = await verifyChallenge(serverSideKey, signature, sessionId, generateNonce());
assert.equal(forgedNonce, false);
console.log('same signature, fresh nonce:   rejected ✓');

// Tampering 3: a different key pair claiming the same identity — fails.
const impostor = await generateKeyPair();
const impostorSig = await signChallenge(impostor.privateKey, impostor.publicKey, sessionId, nonce);
const impostorOk = await verifyChallenge(serverSideKey, impostorSig.signature, sessionId, nonce);
assert.equal(impostorOk, false);
console.log('impostor key pair:             rejected ✓');

console.log('ok: only the untampered challenge-response authenticates');
