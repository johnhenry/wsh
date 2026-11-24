// test/rpc-key-capabilities.test.mjs -- an rpc handler is told what the key it serves may do (additive, #190), and a handler that
// declares it narrows by capability (`capabilityScoped`) can be opened by a key whose capabilities name tools (`mcp:NAME`),
// where every other `mcp` handler still needs `mcp:*`.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

let keyPair; let line;
before(async () => {
  keyPair = await generateKeyPair(true);
  line = await exportPublicKeySSH(keyPair.publicKey);
});

async function serve(options, rpc) {
  const host = createMemoryHost({ auth: { authorizedKeys: options }, dataStreams: false, rpc });
  closers.push(() => host.close());
  const client = host.createClient();
  closers.push(() => client.disconnect());
  await client.connect(host.url, { username: 'alice', keyPair, transport: 'ws' });
  return client;
}

describe('the context an rpc handler gets', () => {
  it('names the key\'s capabilities and answers permits(), live, for a key that has a list', async () => {
    const seen = {};
    const client = await serve(`capabilities="rpc:calc,mcp:search" ${line} alice`, { calc: (_c, ctx) => { Object.assign(seen, { capabilities: ctx.capabilities, search: ctx.permits({ kind: 'mcp-tool', tool: 'search' }), other: ctx.permits({ kind: 'mcp-tool', tool: 'other' }) }); } });
    await client.openRpc('calc');
    assert.deepEqual(seen.capabilities, ['rpc:calc', 'mcp:search']);
    assert.equal(seen.search, true);
    assert.equal(seen.other, false);
  });

  it('a key without capabilities has capabilities null and permits everything', async () => {
    const seen = {};
    const client = await serve(`${line} alice`, { calc: (_c, ctx) => { Object.assign(seen, { capabilities: ctx.capabilities, any: ctx.permits({ kind: 'mcp-tool', tool: 'anything' }) }); } });
    await client.openRpc('calc');
    assert.equal(seen.capabilities, null);
    assert.equal(seen.any, true);
  });

  it('a key past its expires is not permitted anything by permits()', async () => {
    const seen = {};
    const client = await serve(`capabilities="rpc:calc,mcp:*",expires="2099-01-01T00:00:00Z" ${line} alice`, { calc: (_c, ctx) => { seen.ctx = ctx; } });
    await client.openRpc('calc');
    assert.equal(seen.ctx.permits({ kind: 'mcp-tool', tool: 'x' }), true);
    assert.equal(seen.ctx.permits({ kind: 'mcp-tool', tool: 'x' }, { now: Date.parse('2100-01-01T00:00:00Z') / 1000 }), false);
  });
});

describe('opening the mcp rpc channel with tool capabilities', () => {
  const handler = () => {};
  it('an ordinary mcp handler is still refused to a key that holds only mcp:TOOL (it would show every tool)', async () => {
    const client = await serve(`capabilities="mcp:search" ${line} alice`, { mcp: handler });
    await assert.rejects(client.openRpc('mcp'), /mcp:\*/);
  });

  it('a handler that declares capabilityScoped is opened by a key that holds any mcp capability', async () => {
    const scoped = Object.assign(() => {}, { capabilityScoped: true });
    const client = await serve(`capabilities="mcp:search" ${line} alice`, { mcp: scoped });
    assert.ok(await client.openRpc('mcp'));
  });

  it('a scoped handler is still refused to a key with a capability list that names no mcp tool', async () => {
    const scoped = Object.assign(() => {}, { capabilityScoped: true });
    const client = await serve(`capabilities="exec" ${line} alice`, { mcp: scoped });
    await assert.rejects(client.openRpc('mcp'), /capability/);
  });
});
