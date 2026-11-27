// test/memory-host-fingerprint.test.mjs -- #292: the memory host's own key fingerprint, so a client can pin it in one line
//   expectHostKey: await host.hostFingerprint
// (before, an example generated the host key pair, exported the public key and computed the fingerprint itself).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { WshClient, generateKeyPair, exportPublicKeyRaw, fingerprint } from '@johnhenry/wsh';
import { createMemoryHost } from '@johnhenry/wsh/memory';

describe('memory host hostFingerprint', () => {
  it('is the fingerprint of the host key it was given, and what a client pins', async () => {
    const hostKey = await generateKeyPair(true);
    const keyPair = await generateKeyPair(true);
    const expected = await fingerprint(await exportPublicKeyRaw(hostKey.publicKey));
    const host = createMemoryHost({ auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] }, hostKey, exec: async () => 0 });
    assert.equal(await host.hostFingerprint, expected);
    const client = await host.connect({ username: 'alice', keyPair, expectHostKey: await host.hostFingerprint });
    assert.equal(client.hostKey.fingerprint, expected);
    await client.disconnect(); await host.close();
  });

  it('with hostKey: true the host makes its own key, and the fingerprint is that key\'s', async () => {
    const keyPair = await generateKeyPair(true);
    const host = createMemoryHost({ auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] }, hostKey: true, exec: async () => 0 });
    const fp = await host.hostFingerprint;
    assert.match(fp, /^SHA256:/);
    const client = await host.connect({ username: 'alice', keyPair, expectHostKey: fp });
    assert.equal(client.hostKey.fingerprint, fp);
    await client.disconnect(); await host.close();
  });

  it('is null for a host with no key, and never rejects', async () => {
    const host = createMemoryHost({ auth: { anonymous: true }, exec: async () => 0 });
    assert.equal(await host.hostFingerprint, null);
    await host.close();
  });
});
