// test/mcp-stdio.test.mjs -- `wsh-mcp` (wsh #127): the stdio bridge in bin/wsh-mcp.mjs. An MCP client that launches the command lists
// and calls the tools of an MCP server behind a Node host and behind a memory host; a host with no `mcp` channel, a refused login and
// a pinned host key that does not match are clear errors; a dropped connection is re-made and the session carries on.
//
// The bridge runs as a real child process with HOME in a scratch directory (it reads a key file given by --identity; nothing else).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createWshServer, mcpServerAdapter } from '@johnhenry/wsh/server';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, exportPrivateKeyPKCS8 } from '@johnhenry/wsh';
import { loadIdentity } from '../src/mcp-stdio.mjs';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'wsh-mcp.mjs');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, what, ms = 8000) => { const t = Date.now(); while (!(await fn())) { if (Date.now() - t > ms) throw new Error(`timed out waiting for ${what}`); await sleep(20); } };

/** An MCP server with `echo` and a slow `wait` tool; `seen` counts what it has been through. */
function makeMcpServer(seen = {}) {
  const server = new Server({ name: 'behind-wsh', version: '1.0.0' }, { capabilities: { tools: {} } });
  server.oninitialized = () => { seen.initialized = (seen.initialized ?? 0) + 1; };
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      { name: 'echo', description: 'Echo text back', inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } },
      { name: 'wait', description: 'Answers after a while', inputSchema: { type: 'object', properties: { ms: { type: 'number' } } } },
    ],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args = {} } = req.params;
    if (name === 'wait') { await sleep(args.ms ?? 100); return { content: [{ type: 'text', text: 'waited' }] }; }
    return { content: [{ type: 'text', text: `echo: ${args.text}` }] };
  });
  return server;
}

describe('wsh-mcp: an MCP client reaches an MCP server behind a wsh host (#127)', () => {
  let scratch; let keyPair; let identity; let pkcs8Identity; let authorizedKeys;
  const cleanups = [];

  before(async () => {
    scratch = await mkdtemp(path.join(tmpdir(), 'wsh-mcp-'));
    await mkdir(path.join(scratch, 'keys'));
    keyPair = await generateKeyPair(true);
    authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} alice@test\n`;
    const pkcs8 = await exportPrivateKeyPKCS8(keyPair.privateKey);
    const seed = Buffer.from(pkcs8).subarray(-32).toString('base64');
    identity = path.join(scratch, 'keys', 'default.pem');
    await writeFile(identity, `-----BEGIN WSH PRIVATE KEY-----\n${seed}\n-----END WSH PRIVATE KEY-----\n`, { mode: 0o600 });
    pkcs8Identity = path.join(scratch, 'keys', 'pkcs8.pem');
    await writeFile(pkcs8Identity, `-----BEGIN PRIVATE KEY-----\n${Buffer.from(pkcs8).toString('base64')}\n-----END PRIVATE KEY-----\n`, { mode: 0o600 });
  });
  after(async () => {
    for (const c of cleanups.splice(0).reverse()) await c().catch(() => {});
    await rm(scratch, { recursive: true, force: true });
  });

  const env = () => ({ HOME: scratch, USERPROFILE: scratch, XDG_CONFIG_HOME: path.join(scratch, '.config'), USER: 'alice' });

  async function nodeHost(extra = {}, seen) {
    const server = createWshServer({ auth: { authorizedKeys }, rpc: { mcp: mcpServerAdapter(() => makeMcpServer(seen)) }, ...extra });
    const { port } = await server.listen();
    cleanups.push(() => server.close());
    return { server, url: `ws://127.0.0.1:${port}`, port };
  }

  /** A memory host (what a browser tab runs) reached through a WebSocket: each connection is handed to `host.accept()`. */
  async function memoryHostOverWs(seen) {
    const host = createMemoryHost({ auth: { authorizedKeys: `${await exportPublicKeySSH(keyPair.publicKey)}` }, rpc: { mcp: mcpServerAdapter(() => makeMcpServer(seen)) } });
    const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise((r) => wss.once('listening', r));
    wss.on('connection', (ws) => { host.accept(ws).catch(() => {}); });
    cleanups.push(async () => { for (const c of wss.clients) c.terminate(); await new Promise((r) => wss.close(r)); await host.close(); });
    return { url: `ws://127.0.0.1:${wss.address().port}` };
  }

  /** The bridge as a child process speaking NDJSON, for tests that need the raw messages. */
  function bridge(args, { cwdEnv = env() } = {}) {
    const proc = spawn(process.execPath, [BIN, ...args], { env: { PATH: process.env.PATH, ...cwdEnv }, stdio: ['pipe', 'pipe', 'pipe'] });
    const lines = []; const rawOut = []; let stderr = ''; let buf = '';
    proc.stdout.on('data', (d) => { rawOut.push(d.toString()); buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1); } });
    proc.stderr.on('data', (d) => { stderr += d; });
    const exited = new Promise((resolve) => proc.once('exit', (code, signal) => resolve({ code, signal })));
    cleanups.push(async () => { proc.kill('SIGKILL'); });
    const api = {
      proc, exited, lines, stderr: () => stderr,
      send: (m) => proc.stdin.write(`${typeof m === 'string' ? m : JSON.stringify(m)}\n`),
      /** The next message (parsed) matching `want`, from those already received or still to come. */
      async next(want = () => true, ms = 8000) {
        const seenAt = new Set();
        const t = Date.now();
        for (;;) {
          for (let i = 0; i < lines.length; i++) { if (seenAt.has(i)) continue; seenAt.add(i); const m = JSON.parse(lines[i]); if (want(m)) return m; }
          if (Date.now() - t > ms) throw new Error(`timed out waiting for a message; got ${JSON.stringify(lines)}; stderr: ${stderr}`);
          await sleep(20);
        }
      },
      async initialize() {
        api.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'raw', version: '1' } } });
        const r = await api.next((m) => m.id === 1);
        api.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
        return r;
      },
    };
    return api;
  }

  async function viaSdkClient(args) {
    const client = new Client({ name: 'an-mcp-client', version: '1.0.0' }, { capabilities: {} });
    const transport = new StdioClientTransport({ command: process.execPath, args: [BIN, ...args], env: env(), stderr: 'pipe' });
    await client.connect(transport);
    cleanups.push(() => client.close());
    return client;
  }

  it('an MCP client configured with the command lists and calls the tools of a server behind a Node host', async () => {
    const { url } = await nodeHost();
    const client = await viaSdkClient(['--identity', identity, '--user', 'alice', url]);
    assert.equal(client.getServerVersion().name, 'behind-wsh');
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['echo', 'wait']);
    assert.equal((await client.callTool({ name: 'echo', arguments: { text: 'hi' } })).content[0].text, 'echo: hi');
    await client.close();
  });

  it('... and behind a memory host (a host in a page, reached through a WebSocket)', async () => {
    const { url } = await memoryHostOverWs();
    const client = await viaSdkClient(['--identity', identity, '--user', 'alice', url]);
    assert.equal(client.getServerVersion().name, 'behind-wsh');
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['echo', 'wait']);
    assert.equal((await client.callTool({ name: 'echo', arguments: { text: 'in a tab' } })).content[0].text, 'echo: in a tab');
  });

  it('the login name can ride in the URL, the default identity is ~/.wsh/keys/default.pem, and a PKCS#8 key works', async () => {
    const { url } = await nodeHost();
    await mkdir(path.join(scratch, '.wsh', 'keys'), { recursive: true });
    await writeFile(path.join(scratch, '.wsh', 'keys', 'default.pem'), (await import('node:fs')).readFileSync(identity));
    const a = bridge([url.replace('ws://', 'alice@ws://')]);
    assert.equal((await a.initialize()).result.serverInfo.name, 'behind-wsh');
    a.proc.stdin.end();
    assert.equal((await a.exited).code, 0);
    const b = bridge(['--identity', pkcs8Identity, '--user', 'alice', url]);
    assert.equal((await b.initialize()).result.serverInfo.name, 'behind-wsh');
    b.proc.stdin.end();
    assert.equal((await b.exited).code, 0);
  });

  it('stdout carries MCP messages only: every line parses, a bad line is a JSON-RPC error, and nothing else is written there', async () => {
    const { url } = await nodeHost();
    const b = bridge(['--identity', identity, '--user', 'alice', url]);
    await b.initialize();
    b.send('this is not json');
    b.send({ jsonrpc: '1.0', id: 7, method: 'tools/list' });
    b.send([{ jsonrpc: '2.0', id: 8, method: 'tools/list' }]);
    b.send({ jsonrpc: '2.0', id: 9, method: 'tools/list' });
    assert.equal((await b.next((m) => m.error?.code === -32700)).id, null);
    assert.equal((await b.next((m) => m.id === 7)).error.code, -32600);
    assert.equal((await b.next((m) => m.error?.code === -32600 && m.id === null)).error.code, -32600);
    assert.equal((await b.next((m) => m.id === 9)).result.tools.length, 2);
    for (const line of b.lines) assert.doesNotThrow(() => JSON.parse(line), line);
    b.proc.stdin.end();
    assert.equal((await b.exited).code, 0);
  });

  it('a host with no mcp channel: exit 2 and an error that says what the host offers and how to serve one', async () => {
    const server = createWshServer({ auth: { authorizedKeys }, rpc: { 'wsh-host': true } });
    const { port } = await server.listen();
    cleanups.push(() => server.close());
    const b = bridge(['--identity', identity, '--user', 'alice', `ws://127.0.0.1:${port}`]);
    assert.equal((await b.exited).code, 2);
    assert.match(b.stderr(), /offers no "mcp" channel \(it offers: wsh-host\)/);
    assert.match(b.stderr(), /mcpServerAdapter/);
    assert.equal(b.lines.length, 0, 'nothing on stdout');
    const none = await nodeHost({ rpc: undefined });
    const c = bridge(['--identity', identity, '--user', 'alice', none.url]);
    assert.equal((await c.exited).code, 2);
    assert.match(c.stderr(), /offers no rpc channels/);
  });

  it('--channel opens another rpc protocol by name', async () => {
    const server = createWshServer({ auth: { authorizedKeys }, rpc: { 'tools-v2': mcpServerAdapter(() => makeMcpServer()) } });
    const { port } = await server.listen();
    cleanups.push(() => server.close());
    const b = bridge(['--identity', identity, '--user', 'alice', '--channel', 'tools-v2', `ws://127.0.0.1:${port}`]);
    assert.equal((await b.initialize()).result.serverInfo.name, 'behind-wsh');
    b.proc.stdin.end();
    await b.exited;
    const c = bridge(['--identity', identity, '--user', 'alice', `ws://127.0.0.1:${port}`]);
    assert.equal((await c.exited).code, 2, 'the default channel is mcp, which this host does not offer');
    assert.match(c.stderr(), /offers no "mcp" channel \(it offers: tools-v2\)/);
  });

  it('a refused login exits 2 with the host\'s reason; a key file that is missing or not a key says so', async () => {
    const { url } = await nodeHost();
    const stranger = await generateKeyPair(true);
    const seed = Buffer.from(await exportPrivateKeyPKCS8(stranger.privateKey)).subarray(-32).toString('base64');
    const strangerFile = path.join(scratch, 'stranger.pem');
    await writeFile(strangerFile, `-----BEGIN WSH PRIVATE KEY-----\n${seed}\n-----END WSH PRIVATE KEY-----\n`);
    const a = bridge(['--identity', strangerFile, '--user', 'alice', url]);
    assert.equal((await a.exited).code, 2);
    assert.match(a.stderr(), /Authentication failed: key not authorized/);
    const b = bridge(['--identity', path.join(scratch, 'nope.pem'), '--user', 'alice', url]);
    assert.equal((await b.exited).code, 2);
    assert.match(b.stderr(), /no such file \(make one with `wsh keygen`/);
    const junk = path.join(scratch, 'junk.pem');
    await writeFile(junk, 'hello');
    const c = bridge(['--identity', junk, '--user', 'alice', url]);
    assert.equal((await c.exited).code, 2);
    assert.match(c.stderr(), /not a WSH PRIVATE KEY/);
    await assert.rejects(loadIdentity(path.join(scratch, 'nope.pem')), /cannot read the identity file/);
    const id = await loadIdentity(identity);
    assert.deepEqual(id.publicKey, await exportPublicKeyRaw(keyPair.publicKey));
    assert.equal((await id.sign(new Uint8Array([1, 2, 3]))).byteLength, 64);
  });

  it('--host-key pins the host: the right fingerprint connects, a wrong one is refused before anything is signed', async () => {
    const hostKey = await generateKeyPair(true);
    const { server, url } = await nodeHost({ hostKey });
    const fp = server.hostKey().fingerprint;
    const ok = bridge(['--identity', identity, '--user', 'alice', '--host-key', fp, url]);
    assert.equal((await ok.initialize()).result.serverInfo.name, 'behind-wsh');
    assert.doesNotMatch(ok.stderr(), /not pinned/);
    ok.proc.stdin.end();
    await ok.exited;
    const bad = bridge(['--identity', identity, '--user', 'alice', '--host-key', 'ab'.repeat(32), url]);
    assert.equal((await bad.exited).code, 2);
    assert.match(bad.stderr(), /cannot connect/);
    const unpinned = bridge(['--identity', identity, '--user', 'alice', url]);
    await unpinned.initialize();
    assert.match(unpinned.stderr(), /host key of ws:\/\/127\.0\.0\.1:\d+ is not pinned/);
    unpinned.proc.stdin.end();
    await unpinned.exited;
  });

  it('--target is refused: rpc channels are not per target', async () => {
    const b = bridge(['--target', 'web', 'ws://127.0.0.1:1']);
    assert.equal((await b.exited).code, 2);
    assert.match(b.stderr(), /rpc channels are not per target/);
  });

  it('--help and --version exit 0 and print on stdout', async () => {
    const h = bridge(['--help']);
    assert.equal((await h.exited).code, 0);
    assert.match(h.lines.join('\n'), /Usage: wsh-mcp/);
    const v = bridge(['--version']);
    assert.equal((await v.exited).code, 0);
    assert.match(v.lines[0], /^\d+\.\d+\.\d+/);
  });

  it('a dropped connection is re-made: the session is re-initialized behind the client\'s back and the next request is answered', async () => {
    const seen = {};
    let { server, url, port } = await nodeHost({}, seen);
    const b = bridge(['--identity', identity, '--user', 'alice', url]);
    await b.initialize();
    b.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    assert.equal((await b.next((m) => m.id === 2)).result.tools.length, 2);
    assert.equal(seen.initialized, 1);
    // an in-flight call is answered with an error when the connection goes, and the host comes back on the same port
    b.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'wait', arguments: { ms: 5000 } } });
    await sleep(150);
    await server.close();
    const lost = await b.next((m) => m.id === 3);
    assert.equal(lost.error.code, -32603);
    assert.match(lost.error.message, /connection to the wsh host was lost/);
    // held while it is down, delivered once it is back
    b.send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'echo', arguments: { text: 'after' } } });
    await sleep(300);
    server = createWshServer({ auth: { authorizedKeys }, port, rpc: { mcp: mcpServerAdapter(() => makeMcpServer(seen)) } });
    await server.listen();
    cleanups.push(() => server.close());
    const answered = await b.next((m) => m.id === 4, 15_000);
    assert.equal(answered.result.content[0].text, 'echo: after');
    assert.equal(seen.initialized, 2, 'the new channel was initialized once more');
    assert.ok(!b.lines.some((l) => JSON.parse(l).id?.toString().startsWith('wsh-mcp-replay')), 'the replayed initialize is not shown to the client');
    assert.match(b.stderr(), /connection lost; reconnecting/);
    assert.match(b.stderr(), /reconnected/);
    b.proc.stdin.end();
    assert.equal((await b.exited).code, 0);
  });

  it('--no-reconnect: exit 1 when the connection is lost; and exit 1 after the attempts when it does not come back', async () => {
    const a = await nodeHost();
    const b = bridge(['--identity', identity, '--user', 'alice', '--no-reconnect', a.url]);
    await b.initialize();
    await a.server.close();
    assert.equal((await b.exited).code, 1);
    assert.match(b.stderr(), /connection lost/);
    const c0 = await nodeHost();
    const c = bridge(['--identity', identity, '--user', 'alice', '--reconnect-attempts', '2', '--timeout', '1000', c0.url]);
    await c.initialize();
    await c0.server.close();
    c.send({ jsonrpc: '2.0', id: 5, method: 'tools/list' });
    const refused = await c.next((m) => m.id === 5, 20_000);
    assert.equal(refused.error.code, -32603);
    assert.equal((await c.exited).code, 1);
    assert.match(c.stderr(), /could not reconnect; giving up/);
  });

  it('the client closing stdin ends the bridge with 0, and a signal ends it cleanly', async () => {
    const { url } = await nodeHost();
    const a = bridge(['--identity', identity, '--user', 'alice', url]);
    await a.initialize();
    a.proc.stdin.end();
    assert.equal((await a.exited).code, 0);
    const b = bridge(['--identity', identity, '--user', 'alice', url]);
    await b.initialize();
    b.proc.kill('SIGTERM');
    assert.equal((await b.exited).code, 0);
  });

  it('a message over the size limit is refused with a JSON-RPC error and the bridge goes on', async () => {
    const { url } = await nodeHost();
    const { runMcpStdioBridge } = await import('../src/mcp-stdio.mjs');
    const { PassThrough } = await import('node:stream');
    const input = new PassThrough(); const out = []; const err = [];
    const signer = await loadIdentity(identity);
    const run = runMcpStdioBridge({ url, username: 'alice', signer, input, output: { write: (s) => out.push(s) }, errorOutput: { write: (s) => err.push(s) }, maxLineBytes: 2000 });
    input.write(`${'x'.repeat(5000)}\n`);
    input.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'n', version: '1' } } })}\n`);
    await until(() => out.length >= 2, 'two answers');
    assert.equal(JSON.parse(out[0]).error.code, -32600);
    assert.match(JSON.parse(out[0]).error.message, /too large/);
    assert.equal(JSON.parse(out[1]).result.serverInfo.name, 'behind-wsh');
    input.end();
    assert.equal(await run, 0);
  });
});
