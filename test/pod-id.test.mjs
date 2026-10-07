// test/pod-id.test.mjs -- podId() / fingerprintToPodId() / podIdToFingerprint() (#66).
//
// The package's pod ID must be the BrowserMesh one: for the same Ed25519 key,
// base64url(SHA-256(raw key)) as @johnhenry/browsermesh-primitives derives it.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PodIdentity, derivePodId } from '@johnhenry/browsermesh-primitives';
import * as wsh from '@johnhenry/wsh';
import { generateKeyPair, exportPublicKeyRaw, fingerprint, podId, fingerprintToPodId, podIdToFingerprint } from '@johnhenry/wsh';

describe('pod ID helpers are part of the package index', () => {
  it('exports the three functions', () => {
    assert.equal(typeof wsh.podId, 'function');
    assert.equal(typeof wsh.fingerprintToPodId, 'function');
    assert.equal(typeof wsh.podIdToFingerprint, 'function');
  });
});

describe('parity with @johnhenry/browsermesh-primitives', () => {
  it('podId(raw) === derivePodId(cryptoKey) for generated keys', async () => {
    for (let i = 0; i < 3; i++) {
      const { publicKey } = await generateKeyPair(true);
      const raw = await exportPublicKeyRaw(publicKey);
      assert.equal(await podId(raw), await derivePodId(publicKey));
    }
  });

  it('podId(raw) === PodIdentity.podId for a mesh identity, and the wsh fingerprint is the same hash', async () => {
    const identity = await PodIdentity.generate();
    const raw = await exportPublicKeyRaw(identity.keyPair.publicKey);
    const id = await podId(raw);
    assert.equal(id, identity.podId);
    assert.match(id, /^[A-Za-z0-9_-]{43}$/);
    const fp = await fingerprint(raw);
    assert.equal(fingerprintToPodId(fp), identity.podId);
    assert.equal(podIdToFingerprint(identity.podId), fp);
  });

  it('a known key gives a known pod ID (fixed vector)', async () => {
    const raw = new Uint8Array(32); // all-zero "key": only the hash matters
    const identityHash = Buffer.from(await crypto.subtle.digest('SHA-256', raw));
    assert.equal(await podId(raw), identityHash.toString('base64url'));
    assert.equal(await fingerprint(raw), identityHash.toString('hex'));
  });
});

describe('fingerprint <-> pod ID conversion', () => {
  it('round-trips and is pure', async () => {
    const { publicKey } = await generateKeyPair(true);
    const fp = await fingerprint(await exportPublicKeyRaw(publicKey));
    assert.equal(podIdToFingerprint(fingerprintToPodId(fp)), fp);
    const id = fingerprintToPodId(fp);
    assert.equal(fingerprintToPodId(podIdToFingerprint(id)), id);
  });

  it('refuses something that is not a hex fingerprint rather than emit a wrong ID', () => {
    for (const bad of ['', 'xyz', 'abc', 'zz'.repeat(32), null, undefined, 5]) {
      assert.throws(() => fingerprintToPodId(bad), TypeError, String(bad));
    }
  });
});
