/**
 * A tampered challenge fails authentication.
 *
 * wsh authenticates clients with an Ed25519 challenge-response (spec/wsh-v1.md,
 * "Crypto Primitives"): the server sends a random nonce, the client signs the
 * transcript SHA-256("wsh-v1\0" || lp(username) || lp(session_id) || nonce ||
 * channel_binding) — lp() is a 4-byte length prefix on the variable-length
 * fields — and the server verifies the signature against the client's public
 * key.
 *
 * Signing the *transcript* — not the bare nonce — binds the signature to this
 * protocol version, this username, and this session, so a signature can never
 * be replayed against a different session, relabeled to another identity, or
 * spliced into another connection. This example runs the whole flow in-process
 * (no network) and shows exactly which manipulations make verification fail.
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

const username = 'alice';
const sessionId = 'sess-42';
const nonce = generateNonce(); // 32 random bytes
console.log(`server challenge: session "${sessionId}", ${nonce.length}-byte nonce`);

// ── Client: sign the transcript ───────────────────────────────────────

const { signature, publicKeyRaw } = await signChallenge(
  privateKey, publicKey, sessionId, nonce, { username }
);
console.log(`client response: ${signature.length}-byte signature + ${publicKeyRaw.length}-byte public key`);

// ── Server: verify ────────────────────────────────────────────────────

// The server imports the raw key the client sent (after checking it against
// authorized keys) and verifies the transcript signature.
const serverSideKey = await importPublicKeyRaw(publicKeyRaw);

const genuine = await verifyChallenge(serverSideKey, signature, sessionId, nonce, { username });
assert.equal(genuine, true);
console.log('genuine response:            verified ✓');

// Tampering 1: replay against a different session — transcript changes, fails.
const replayed = await verifyChallenge(serverSideKey, signature, 'sess-43', nonce, { username });
assert.equal(replayed, false);
console.log('same signature, other session: rejected ✓');

// Tampering 2: stale/forged nonce — fails.
const forgedNonce = await verifyChallenge(serverSideKey, signature, sessionId, generateNonce(), { username });
assert.equal(forgedNonce, false);
console.log('same signature, fresh nonce:   rejected ✓');

// Tampering 3: the same signature presented under a different username — fails.
const relabeled = await verifyChallenge(serverSideKey, signature, sessionId, nonce, { username: 'mallory' });
assert.equal(relabeled, false);
console.log('same signature, other username: rejected ✓');

// Tampering 4: a different key pair claiming the same identity — fails.
const impostor = await generateKeyPair();
const impostorSig = await signChallenge(impostor.privateKey, impostor.publicKey, sessionId, nonce, { username });
const impostorOk = await verifyChallenge(serverSideKey, impostorSig.signature, sessionId, nonce, { username });
assert.equal(impostorOk, false);
console.log('impostor key pair:             rejected ✓');

console.log('ok: only the untampered challenge-response authenticates');
