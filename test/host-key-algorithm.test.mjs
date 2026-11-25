// test/host-key-algorithm.test.mjs -- #240: a `hostKey` wsh cannot use as a host key (it is Ed25519 only) is refused when the host is
// created, with a message that names the algorithm and what is accepted, instead of failing at accept() while the client waits.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { createPageHost } from '@johnhenry/wsh/page';
import { resolveHostKey } from '@johnhenry/wsh/host';
import { generateKeyPair, exportPublicKeyRaw, exportPublicKeySSH } from '@johnhenry/wsh';

const p256 = () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const rsa = () => crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
const names = (re) => (e) => { assert.ok(e instanceof TypeError, `a TypeError, got ${e?.constructor?.name}`); assert.match(e.message, re); return true; };
const NAMES_P256 = /hostKey.*Ed25519.*ECDSA \(P-256\)|ECDSA \(P-256\).*Ed25519/s;

describe('createMemoryHost refuses a host key that is not Ed25519, at creation', () => {
  const auth = { authorizedKeys: [new Uint8Array(32).fill(1)] };

  it('an ECDSA P-256 key pair: a TypeError that names the algorithm and what is accepted', async () => {
    const pair = await p256();
    assert.throws(() => createMemoryHost({ auth, hostKey: pair }), names(NAMES_P256));
    assert.throws(() => createMemoryHost({ auth, hostKey: pair }), /createMemoryHost: hostKey/);
  });

  it('an RSA key pair is named too', async () => {
    const hostKey = await rsa();
    assert.throws(() => createMemoryHost({ auth, hostKey }), names(/RSASSA-PKCS1-v1_5.*Ed25519|Ed25519.*RSASSA-PKCS1-v1_5/s));
  });

  it('a signer whose public key is a P-256 CryptoKey, or raw bytes that are not 32', async () => {
    const pair = await p256();
    assert.throws(() => createMemoryHost({ auth, hostKey: { publicKey: pair.publicKey, sign: async () => new Uint8Array(64) } }), names(NAMES_P256));
    assert.throws(() => createMemoryHost({ auth, hostKey: { publicKey: new Uint8Array(65), sign: async () => new Uint8Array(64) } }), names(/65 bytes.*Ed25519|Ed25519.*65 bytes/s));
  });

  it('a value that is no key at all still gets the old message', () => {
    assert.throws(() => createMemoryHost({ auth, hostKey: 'host.key' }), names(/hostKey must be true, a CryptoKeyPair, or a signer/));
  });

  it('what is accepted still is: true, an Ed25519 pair (extractable or not), an Ed25519 signer', async () => {
    createMemoryHost({ auth, hostKey: true });
    createMemoryHost({ auth, hostKey: await generateKeyPair(false) });
    const pair = await generateKeyPair(true);
    createMemoryHost({ auth, hostKey: pair });
    createMemoryHost({ auth, hostKey: { publicKey: await exportPublicKeyRaw(pair.publicKey), sign: async () => new Uint8Array(64) } });
    createMemoryHost({ auth }); // no host key at all is still allowed
  });

  it('sealSession with a bad key says the key is the problem, not that one is missing', async () => {
    const hostKey = await p256();
    assert.throws(() => createMemoryHost({ auth, hostKey, sealSession: 'require', dataStreams: false }), names(NAMES_P256));
  });
});

describe('every other host factory that takes hostKey refuses it too', () => {
  it('createWshServer: at creation, before listen()', async () => {
    const hostKey = await p256();
    assert.throws(() => createWshServer({ auth: { authorizedKeys: [new Uint8Array(32).fill(1)] }, exec: true, hostKey }), (e) => names(/createWshServer: hostKey.*Ed25519.*ECDSA \(P-256\)/s)(e));
  });

  it('createPageHost: the promise rejects before any relay is dialled', async () => {
    const dialled = [];
    const window = { location: { origin: 'https://page.test' }, crypto, setTimeout, clearTimeout, setInterval, clearInterval, addEventListener() {}, removeEventListener() {}, WebSocket: class { constructor(u) { dialled.push(u); } } };
    const authorizedKeys = `${await exportPublicKeySSH((await generateKeyPair(true)).publicKey)} op\n`;
    await assert.rejects(createPageHost({ window, relay: 'wss://relay.test', name: 'p', authorizedKeys, mcp: { allow: ['t'] }, indicator: false, unattended: true, hostKey: await p256() }), names(/createPageHost: hostKey.*Ed25519.*ECDSA \(P-256\)/s));
    assert.deepEqual(dialled, []);
  });

  it('resolveHostKey (the shared entry point of @johnhenry/wsh/host) names it as well', async () => {
    await assert.rejects(resolveHostKey(await p256(), 'myHost: hostKey'), names(/myHost: hostKey.*Ed25519.*ECDSA \(P-256\)/s));
  });
});
