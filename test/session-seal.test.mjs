// test/session-seal.test.mjs -- #155, host side: `sealSession` is validated, advertised by a feature string, and with 'require' a
// plain client is refused. (The key exchange itself is exercised by test/rust/wsh-session-seal.test.mjs, with the Rust CLI as the
// initiator; the JS client's sealed session is the next stage of #155.)
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

describe('sealSession (host option)', () => {
  it('is validated: a value other than false/offer/require, or no hostKey, is a TypeError', () => {
    assert.throws(() => createMemoryHost({ sealSession: 'yes', hostKey: true }), /sealSession must be/);
    assert.throws(() => createMemoryHost({ sealSession: 'offer' }), /needs a hostKey/);
    assert.doesNotThrow(() => createMemoryHost({ sealSession: false }));
  });

  it("'offer' advertises e2e-session and serves a plain client; 'require' also says so and serves it nothing", async () => {
    const keyPair = await generateKeyPair(true);
    const authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} u`;
    for (const mode of ['offer', 'require']) {
      const host = createMemoryHost({ auth: { authorizedKeys }, hostKey: true, dataStreams: false, sealSession: mode, endpoints: { echo: (d) => { d.readable.pipeTo(d.writable).catch(() => {}); } } });
      try {
        const client = await host.connect({ username: 'u', keyPair });
        assert.ok(client.hasFeature('e2e-session'), `${mode}: advertised`);
        assert.equal(client.hasFeature('e2e-session-required'), mode === 'require');
        if (mode === 'offer') {
          const d = await client.openEndpoint('echo');
          d.destroy();
        } else {
          await assert.rejects(client.openEndpoint('echo', { timeout: 1500 }));
        }
        await client.disconnect().catch(() => {});
      } finally { await host.close(); }
    }
  });

  it('is not advertised where there are client-opened data streams (their bytes are not frames)', async () => {
    const keyPair = await generateKeyPair(true);
    const host = createMemoryHost({ auth: { authorizedKeys: `${await exportPublicKeySSH(keyPair.publicKey)} u` }, hostKey: true, dataStreams: true, sealSession: 'offer' });
    try {
      const client = await host.connect({ username: 'u', keyPair });
      assert.equal(client.hasFeature('e2e-session'), false);
      await client.disconnect().catch(() => {});
    } finally { await host.close(); }
  });
});
