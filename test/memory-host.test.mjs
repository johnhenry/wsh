// test/memory-host.test.mjs -- the browser-safe in-memory host (`@johnhenry/wsh/memory`, #99).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createMemoryHost, createSocketPair } from '@johnhenry/wsh/memory';
import { WshClient, generateKeyPair, exportPublicKeyRaw, sign } from '@johnhenry/wsh';

const dec = new TextDecoder();

describe('createMemoryHost (#99)', () => {
  let keyPair; let raw; let host;
  const echo = async (command, io) => { await io.write(`ran:${command} as ${io.user}\n`); return 3; };
  before(async () => {
    keyPair = await generateKeyPair(true);
    raw = await exportPublicKeyRaw(keyPair.publicKey);
    host = createMemoryHost({ auth: { authorizedKeys: [raw] }, exec: echo });
  });
  after(() => host.close());

  it('runs the real handshake, auth and an exec channel with no sockets', async () => {
    const client = await host.connect({ username: 'alice', keyPair });
    try {
      const { stdout, exitCode } = await new Promise((resolve, reject) => {
        client.openSession({ type: 'exec', command: 'hello' }).then((session) => {
          const chunks = [];
          session.onData = (d) => chunks.push(d);
          session.onExit = (code) => resolve({ stdout: Buffer.concat(chunks), exitCode: code });
          session.onClose = () => resolve({ stdout: Buffer.concat(chunks), exitCode: 3 });
        }, reject);
      });
      assert.equal(dec.decode(stdout), 'ran:hello as alice\n');
      assert.equal(exitCode, 3);
    } finally { await client.disconnect(); }
  });

  it('WshClient.exec works through host.createClient() with a page-held signer', async () => {
    const client = host.createClient();
    const signer = { publicKey: raw, sign: (d) => sign(keyPair.privateKey, d) };
    try {
      await client.connect(host.url, { username: 'bob', signer, transport: 'ws' });
      assert.ok(client.hasFeature('stream-announce'));
    } finally { await client.disconnect(); }
  });

  it('refuses a key that is not authorized, and everyone when no auth is given', async () => {
    const stranger = await generateKeyPair(true);
    await assert.rejects(host.connect({ username: 'eve', keyPair: stranger }), /Authentication failed/);
    const closedHost = createMemoryHost({ exec: echo });
    await assert.rejects(closedHost.connect({ username: 'alice', keyPair }), /Authentication failed/);
    await closedHost.close();
  });

  it('serves password auth, mcp tools and extensions', async () => {
    const seen = [];
    const h = createMemoryHost({
      auth: { password: async (u, p) => u === 'pw' && p === 'secret' },
      mcp: { tools: [{ name: 'add', description: 'add', inputSchema: { type: 'object' }, call: ({ a, b }) => ({ sum: a + b }) }] },
      extensions: { hello: (msg, ctx) => seen.push([msg.type, ctx.username]) },
    });
    try {
      await assert.rejects(h.connect({ username: 'pw', password: 'nope' }), /Authentication failed/);
      const client = await h.connect({ username: 'pw', password: 'secret' });
      const tools = await client.discoverTools();
      assert.deepEqual(tools.map((t) => t.name), ['add']);
      await client.sendRelayControl({ type: 'hello', n: 7 });
      for (let i = 0; i < 100 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 10));
      assert.deepEqual(seen, [['hello', 'pw']]);
      await client.disconnect();
    } finally { await h.close(); }
  });

  it('accept() takes any pre-upgraded socket pair', async () => {
    const [clientSide, serverSide] = createSocketPair();
    const handle = await host.accept(serverSide);
    assert.equal(typeof handle.close, 'function');
    clientSide.close();
  });

  it('rejects exec: true (there is no shell) and a malformed exec', () => {
    assert.throws(() => createMemoryHost({ exec: true }), /function/);
    assert.throws(() => createMemoryHost({ exec: {} }), /function/);
  });

  it('close() ends the live connections', async () => {
    const h = createMemoryHost({ auth: { authorizedKeys: [raw] }, exec: echo });
    const client = await h.connect({ username: 'alice', keyPair });
    const closed = new Promise((resolve) => { client.onClose = resolve; });
    await h.close();
    await Promise.race([closed, new Promise((r) => setTimeout(r, 1000))]);
    assert.notEqual(client.state, 'authenticated');
  });

  it('imports nothing from node: or ws, transitively', async () => {
    const seen = new Set();
    const bad = [];
    async function walk(rel) {
      const url = new URL(rel, import.meta.url);
      if (seen.has(url.href)) return;
      seen.add(url.href);
      const src = (await readFile(url, 'utf8')).replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
      // Static imports only: a dynamic `import()` is lazy and cannot pull Node into a bundle's startup path.
      for (const m of src.matchAll(/^\s*(?:import|export)\s[^'"]*?from\s+['"]([^'"]+)['"]|^\s*import\s+['"]([^'"]+)['"]/gm)) {
        const spec = m[1] ?? m[2];
        if (spec.startsWith('node:') || spec === 'ws' || !spec.startsWith('.')) bad.push(`${url.pathname.split('/src/')[1]} -> ${spec}`);
        else await walk(new URL(spec, url).href);
      }
    }
    await walk('../src/memory-host.mjs');
    assert.deepEqual(bad, []);
    assert.ok(seen.size > 10);
  });
});
