// test/memory-host-identity.test.mjs -- what #117, #119, #125 and #126 mean for a host that lives in a page (createMemoryHost,
// accept(socket)): channel binding kind `host` from the injected host key, `requireChannelBinding`, `connectionTtlMs`, and
// the `clientEnv` allow-list on an injected exec.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeyRaw } from '@johnhenry/wsh';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function setup(hostOptions = {}) {
  const keyPair = await generateKeyPair(true);
  const raw = await exportPublicKeyRaw(keyPair.publicKey);
  const host = createMemoryHost({ auth: { authorizedKeys: [raw] }, exec: async (_c, io) => { io.write(JSON.stringify(io.env)); return 0; }, ...hostOptions });
  return { keyPair, host };
}

describe('createMemoryHost: channel binding (#119)', () => {
  it('with a host key the login is bound to it (kind `host`)', async () => {
    const { keyPair, host } = await setup({ hostKey: true });
    const client = host.createClient();
    await client.connect(host.url, { username: 'alice', keyPair, transport: 'ws', requireChannelBinding: true, timeout: 4000 });
    try { assert.deepEqual(client.channelBinding, ['host']); } finally { await client.disconnect(); await host.close(); }
  });

  it('without a host key nothing can be bound, and the connection still works', async () => {
    const { keyPair, host } = await setup();
    const client = host.createClient();
    await client.connect(host.url, { username: 'alice', keyPair, transport: 'ws', timeout: 4000 });
    try { assert.deepEqual(client.channelBinding, []); } finally { await client.disconnect(); await host.close(); }
  });

  it('requireChannelBinding is passed on: the host states it, and a client that binds gets in', async () => {
    const { keyPair, host } = await setup({ hostKey: true, requireChannelBinding: ['host'] });
    try {
      const client = host.createClient();
      await client.connect(host.url, { username: 'alice', keyPair, transport: 'ws', timeout: 4000 });
      assert.deepEqual(client.channelBinding, ['host']);
      assert.ok(client.hasFeature('channel-binding-required'));
      await client.disconnect();
    } finally { await host.close(); }
  });

  it('requireChannelBinding needs a host key (the only kind a memory host can bind), and rejects other kinds', async () => {
    assert.throws(() => createMemoryHost({ requireChannelBinding: true }), /hostKey/);
    assert.throws(() => createMemoryHost({ hostKey: true, requireChannelBinding: ['tls-exporter'] }), /requireChannelBinding/);
    assert.throws(() => createMemoryHost({ hostKey: true, requireChannelBinding: 'yes' }), /requireChannelBinding/);
  });
});

describe('createMemoryHost: connectionTtlMs (#125)', () => {
  it('ends the connection when the lifetime it advertised is over', async () => {
    const { keyPair, host } = await setup({ connectionTtlMs: 1200 });
    const client = host.createClient();
    let closed = false;
    client.onClose = () => { closed = true; };
    await client.connect(host.url, { username: 'alice', keyPair, transport: 'ws', timeout: 4000 });
    try {
      assert.equal(client.authTtl, 2); // whole seconds, rounded up
      assert.equal(closed, false);
      await sleep(1800);
      assert.equal(closed, true);
    } finally { await client.disconnect().catch(() => {}); await host.close(); }
  });

  it('defaults to no limit (ttl 0)', async () => {
    const { keyPair, host } = await setup();
    const client = host.createClient();
    await client.connect(host.url, { username: 'alice', keyPair, transport: 'ws', timeout: 4000 });
    try { assert.equal(client.authTtl, 0); } finally { await client.disconnect(); await host.close(); }
  });
});

describe('createMemoryHost: clientEnv (#126)', () => {
  const run = async (host, keyPair, env) => {
    const client = host.createClient();
    await client.connect(host.url, { username: 'alice', keyPair, transport: 'ws', timeout: 4000 });
    try {
      const chunks = [];
      const s = await client.openSession({ type: 'exec', command: 'x', env });
      await new Promise((resolve) => { s.onData = (d) => chunks.push(d); s.onClose = resolve; });
      return JSON.parse(new TextDecoder().decode(Uint8Array.from(chunks.flatMap((c) => [...c]))));
    } finally { await client.disconnect(); }
  };

  it('by default only the terminal-ish names reach the runner', async () => {
    const { keyPair, host } = await setup();
    assert.deepEqual(await run(host, keyPair, { TERM: 'xterm', LANG: 'C', PATH: '/evil', SECRET: 'x' }), { TERM: 'xterm', LANG: 'C' });
    await host.close();
  });

  it('a list of names, a predicate and `true` are accepted', async () => {
    const mk = async (clientEnv) => { const { keyPair, host } = await setup({ exec: { run: async (_c, io) => { io.write(JSON.stringify(io.env)); return 0; }, clientEnv } }); return { keyPair, host }; };
    let { keyPair, host } = await mk(['FOO']);
    assert.deepEqual(await run(host, keyPair, { FOO: '1', BAR: '2' }), { FOO: '1' });
    await host.close();
    ({ keyPair, host } = await mk((name) => name.startsWith('B')));
    assert.deepEqual(await run(host, keyPair, { FOO: '1', BAR: '2' }), { BAR: '2' });
    await host.close();
    ({ keyPair, host } = await mk(true));
    assert.deepEqual(await run(host, keyPair, { FOO: '1', BAR: '2' }), { FOO: '1', BAR: '2' });
    await host.close();
  });
});
