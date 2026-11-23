// test/host-refused.test.mjs -- #163: a host tells its embedder, through `onRefused({ reason, who, detail })`, that it turned a client
// away, with a stable `reason` code (no parsing of log lines).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { createReverseHost } from '@johnhenry/wsh/reverse';
import { REFUSAL_REASONS } from '@johnhenry/wsh/host';
import { WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint } from '@johnhenry/wsh';

const until = async (cond, what, ms = 4000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 10)); }
};
const identity = async (name) => {
  const keyPair = await generateKeyPair(true);
  return { name, keyPair, ssh: `${await exportPublicKeySSH(keyPair.publicKey)} ${name}`, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)) };
};

describe('onRefused (host option)', () => {
  it('exports the list of reason codes, and must be a function', async () => {
    assert.ok(Array.isArray(REFUSAL_REASONS) && REFUSAL_REASONS.includes('not-sealed') && REFUSAL_REASONS.includes('unauthorized') && REFUSAL_REASONS.includes('binding-required'));
    assert.throws(() => createMemoryHost({ onRefused: 'yes' }), /onRefused must be a function/);
  });

  it("'not-sealed': a host that requires a sealed session refuses a plain client, and says who", async () => {
    const alice = await identity('alice');
    const refused = [];
    const host = createMemoryHost({
      auth: { authorizedKeys: alice.ssh }, hostKey: true, dataStreams: false, sealSession: 'require',
      endpoints: { echo: (d) => { d.readable.pipeTo(d.writable).catch(() => {}); } },
      onRefused: (r) => refused.push(r),
    });
    try {
      const client = await host.connect({ username: 'alice', keyPair: alice.keyPair, sealSession: false });
      await assert.rejects(client.openEndpoint('echo', { timeout: 1500 }));
      await until(() => refused.length, 'the refusal');
      assert.equal(refused.length, 1, 'one refusal per connection, however many plain messages arrive');
      assert.equal(refused[0].reason, 'not-sealed');
      assert.equal(refused[0].who.username, 'alice');
      assert.equal(refused[0].who.fingerprint, alice.fp);
      assert.equal(typeof refused[0].detail, 'string');
      await client.disconnect().catch(() => {});
    } finally { await host.close(); }
  });

  it("'unauthorized' for a key that is not allowed and for a wrong password; 'method-disabled' for a method the host does not offer", async () => {
    const alice = await identity('alice');
    const mallory = await identity('mallory');
    const refused = [];
    const host = createMemoryHost({ auth: { authorizedKeys: alice.ssh }, onRefused: (r) => refused.push(r) });
    try {
      await assert.rejects(host.connect({ username: 'mallory', keyPair: mallory.keyPair }), /not authorized/);
      await until(() => refused.length, 'the refusal');
      assert.equal(refused[0].reason, 'unauthorized');
      assert.equal(refused[0].who.username, 'mallory');
      assert.equal(refused[0].who.fingerprint, mallory.fp);

      await assert.rejects(host.connect({ username: 'pw', password: 'x' }), /password auth is not enabled/);
      await until(() => refused.length > 1, 'the second refusal');
      assert.equal(refused[1].reason, 'method-disabled');
      assert.equal(refused[1].who.username, 'pw');
    } finally { await host.close(); }

    const pwRefused = [];
    const pwHost = createMemoryHost({ auth: { password: async (u, p) => u === 'pw' && p === 'secret' }, onRefused: (r) => pwRefused.push(r) });
    try {
      await assert.rejects(pwHost.connect({ username: 'pw', password: 'nope' }), /Authentication failed/);
      await until(() => pwRefused.length, 'the password refusal');
      assert.equal(pwRefused[0].reason, 'unauthorized');
      assert.equal(pwRefused[0].who.username, 'pw');
      assert.equal(pwRefused[0].who.fingerprint, undefined);
    } finally { await pwHost.close(); }
  });

  it("'binding-required' on createWshServer: a login that cannot be bound to the connection to a host that requires it", async () => {
    const alice = await identity('alice');
    const refused = [];
    const server = createWshServer({ auth: { authorizedKeys: alice.ssh }, requireChannelBinding: true, onRefused: (r) => refused.push(r) });
    const { port } = await server.listen(); const url = `ws://127.0.0.1:${port}`;
    try {
      const client = new WshClient();
      await assert.rejects(client.connect(url, { username: 'alice', keyPair: alice.keyPair, timeout: 4000 }), /channel binding required/);
      await until(() => refused.length, 'the refusal');
      assert.equal(refused[0].reason, 'binding-required');
      assert.equal(refused[0].who.username, 'alice');
    } finally { await server.close(); }
  });

  it('a callback that throws does not stop the refusal', async () => {
    const alice = await identity('alice');
    const mallory = await identity('mallory');
    let called = 0;
    const host = createMemoryHost({ auth: { authorizedKeys: alice.ssh }, onLog: () => {}, onRefused: () => { called += 1; throw new Error('boom'); } });
    try {
      await assert.rejects(host.connect({ username: 'mallory', keyPair: mallory.keyPair }), /not authorized/);
      assert.equal(called, 1);
    } finally { await host.close(); }
  });

  it('a reverse host reports an operator it did not accept as \'unauthorized\'', async () => {
    const host = await identity('host');
    const bob = await identity('bob');
    const refused = [];
    const relay = createWshServer({ auth: { authorizedKeys: [host.ssh, bob.ssh].join('\n') }, relay: { canRegister: () => true, canConnect: () => true, connectTimeoutMs: 4000 } });
    const { port } = await relay.listen(); const url = `ws://127.0.0.1:${port}`;
    const rh = createReverseHost({ url, username: 'host', keyPair: host.keyPair, accept: async () => false, reconnect: false, onRefused: (r) => refused.push(r) });
    const op = new WshClient();
    try {
      await rh.start();
      await op.connect(url, { username: 'bob', keyPair: bob.keyPair, timeout: 4000 });
      await until(async () => (await op.listPeers()).length, 'the host in the peer list');
      await op.reverseConnect(host.fp, 4000).catch(() => {});
      await until(() => refused.length, 'the refusal');
      assert.equal(refused[0].reason, 'unauthorized');
      assert.equal(refused[0].who.fingerprint, bob.fp);
      assert.equal(refused[0].who.username, 'bob');
    } finally { await op.disconnect().catch(() => {}); await rh.close(); await relay.close(); }
  });
});
