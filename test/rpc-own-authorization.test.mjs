// A rpc handler that authorizes for itself (`handler.authorizesItself = true`, #220): the channel-open check of a key's capability list defers to it
// instead of demanding `mcp:*` (or `rpc:NAME`) of the key. Without the flag nothing changes: key capabilities decide, as before.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { parseKeyOptions, checkKeyRequest } from '../src/key-options.mjs';

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

const ping = (channel) => { channel.onRequest('ping', () => ({ pong: true })); };

async function open(handler, keyOptions) {
  const keyPair = await generateKeyPair(true);
  const line = await exportPublicKeySSH(keyPair.publicKey);
  const host = createMemoryHost({ auth: { authorizedKeys: `${keyOptions} ${line}` }, rpc: { mcp: handler } });
  closers.push(() => host.close());
  const client = await host.connect({ username: 'alice', keyPair });
  closers.push(() => client.disconnect());
  return client;
}

describe('the channel-open check of a rpc handler', () => {
  it('a key with capabilities but no mcp:* is refused an ordinary mcp handler (unchanged)', async () => {
    const client = await open(ping, 'capabilities="exec"');
    await assert.rejects(client.openRpc('mcp'), /mcp:\*/);
  });

  it('a capabilityScoped handler still needs the key to name some tool (unchanged)', async () => {
    const scoped = Object.assign((c) => ping(c), { capabilityScoped: true });
    await assert.rejects((await open(scoped, 'capabilities="exec"')).openRpc('mcp'), /mcp:<tool>/);
    const ok = await open(scoped, 'capabilities="mcp:search"');
    assert.deepEqual(await (await ok.openRpc('mcp')).request('ping', {}), { pong: true });
  });

  it('a handler that authorizes for itself is opened by a key whose list does not name mcp at all, and it decides', async () => {
    const own = Object.assign((c, ctx) => { c.onRequest('ping', () => ({ pong: true, permitsSeen: typeof ctx.permits })); }, { capabilityScoped: true, authorizesItself: true });
    const client = await open(own, 'capabilities="exec"');
    const channel = await client.openRpc('mcp');
    assert.deepEqual(await channel.request('ping', {}), { pong: true, permitsSeen: 'function' });
  });

  it('the options still apply: restrict without permit-mcp refuses even a handler that authorizes for itself', async () => {
    const own = Object.assign(ping, { authorizesItself: true });
    const client = await open(own, 'restrict,permit-exec');
    await assert.rejects(client.openRpc('mcp'), /MCP not permitted/);
  });

  it('an expired key is refused first, and a key-admin request is not widened', () => {
    const p = parseKeyOptions('capabilities="exec",expires="2030-01-01T00:00:00Z"').permissions;
    const req = { kind: 'open', channel: 'rpc', protocol: 'mcp', authorizesItself: true };
    assert.equal(checkKeyRequest(p, req, { now: 1893455999 }), null);
    assert.equal(checkKeyRequest(p, req, { now: 1893456000 })?.code, 'key-expired');
    assert.equal(checkKeyRequest(p, { ...req, authorizesItself: false }, { now: 1 })?.code, 'capability-missing');
    assert.equal(checkKeyRequest(p, { kind: 'key-admin' }, { now: 1 })?.code, 'key-admin-not-permitted');
  });
});
