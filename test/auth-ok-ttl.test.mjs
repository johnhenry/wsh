// test/auth-ok-ttl.test.mjs -- #125: AuthOk.ttl is the connection lifetime the host enforces (0 = none);
// AuthOk.token is an opaque identifier that carries no authority.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

describe('AuthOk ttl and token (#125)', () => {
  let keyPair;
  let authorizedKeys;
  before(async () => {
    keyPair = await generateKeyPair(true);
    authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} alice@test\n`;
  });

  async function withServer(opts, fn) {
    const server = createWshServer({ auth: { authorizedKeys }, exec: true, ...opts });
    const { port } = await server.listen();
    const client = new WshClient();
    try {
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
      await fn(client);
    } finally { await client.disconnect().catch(() => {}); await server.close(); }
  }

  it('by default no lifetime is promised: ttl is 0, and the connection is not ended', async () => {
    await withServer({}, async (client) => {
      assert.equal(client.authTtl, 0);
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(client.state, 'authenticated');
    });
  });

  it('connectionTtlMs is advertised in whole seconds (rounded up) and enforced: the host ends the connection', async () => {
    await withServer({ connectionTtlMs: 300 }, async (client) => {
      assert.equal(client.authTtl, 1);
      const closed = new Promise((resolve) => { client.onClose = resolve; });
      const t0 = Date.now();
      await closed;
      const waited = Date.now() - t0;
      assert.ok(waited >= 150 && waited < 3000, `closed after ${waited}ms`);
    });
  });

  it('a connection that ends at its ttl takes its sessions with it', async () => {
    let aborted = false;
    const exec = async (_c, io) => { await new Promise((r) => io.signal.addEventListener('abort', () => { aborted = true; r(); })); return 0; };
    await withServer({ exec, connectionTtlMs: 300 }, async (client) => {
      await client.openSession({ type: 'exec', command: 'x' });
      await new Promise((resolve) => { client.onClose = resolve; });
      await new Promise((r) => setTimeout(r, 50));
      assert.equal(aborted, true);
    });
  });

  it('rejects a nonsensical connectionTtlMs', () => {
    assert.throws(() => createWshServer({ connectionTtlMs: -1 }), /connectionTtlMs/);
    assert.throws(() => createWshServer({ connectionTtlMs: 'soon' }), /connectionTtlMs/);
  });

  it('the token is present (released peers require the field) but not accepted as a credential anywhere', async () => {
    await withServer({ sessions: true }, async (client) => {
      assert.ok(client.authToken instanceof Uint8Array && client.authToken.length > 0);
      // Resume needs the SESSION token from OpenOk; the connection's AuthOk token does not stand in for it.
      const s = await client.openSession({ type: 'exec', command: 'sleep 5' });
      await client.detach(s.sessionId).catch(() => {});
      await assert.rejects(() => client.resumeSession(s.sessionId, client.authToken, { lastSeq: 0 }));
    });
  });
});
