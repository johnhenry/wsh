// test/rust/wsh-mcp.test.mjs -- `wsh mcp` (wsh #127, the Rust side): the built Rust `wsh` as a stdio bridge to the `mcp` rpc
// channel of a host. An MCP client that launches the command lists and calls the tools of an MCP server behind a Node host
// and behind a memory host (driven by the MCP SDK's own stdio client); a host with no such channel, a refused login and a
// pinned host key that does not match are clear errors; a dropped connection is re-made; and the same command speaks the
// Rust `wsh-server`'s own rpc channel (`--channel wsh-host`), which is the Rust client's rpc channel against a Rust host.
//
// Prerequisite: `cargo build -p wsh-cli -p wsh-server` (or --release), WSH_BIN / WSH_SERVER_BIN to point at them.
// Every process runs with HOME in a scratch directory: the keys, known_hosts and config of the real home are never touched.
import { describe, it, before, after } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createWshServer, mcpServerAdapter } from '@johnhenry/wsh/server';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WSH_BIN = process.env.WSH_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const scratch = [];
const cleanups = [];
before(() => { assert.ok(existsSync(WSH_BIN), `expected the built wsh binary at ${WSH_BIN} (cargo build -p wsh-cli, or set WSH_BIN)`); });
after(async () => {
  for (const c of cleanups.splice(0).reverse()) await c().catch(() => {});
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
});

const cleanEnv = (home) => ({ PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), USER: 'alice', WSH_INSECURE_LOOPBACK_TLS: '1' });

/** A scratch home with a key made by `wsh keygen`; `pub` is the line a host authorizes. */
function makeHome() {
  const home = mkdtempSync(path.join(tmpdir(), 'wsh-mcp-rs-'));
  scratch.push(home);
  execFileSync(WSH_BIN, ['keygen', 'default'], { env: cleanEnv(home), stdio: 'ignore' });
  return { home, pub: readFileSync(path.join(home, '.wsh', 'keys', 'default.pub'), 'utf8').trim() };
}

/** An MCP server with `echo`, a slow `wait` tool and `hang` (which records that its request was cancelled). */
function makeMcpServer(seen = {}) {
  const server = new Server({ name: 'behind-wsh', version: '1.0.0' }, { capabilities: { tools: {} } });
  server.oninitialized = () => { seen.initialized = (seen.initialized ?? 0) + 1; };
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      { name: 'echo', description: 'Echo text back', inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } },
      { name: 'wait', description: 'Answers after a while', inputSchema: { type: 'object', properties: { ms: { type: 'number' } } } },
      { name: 'hang', description: 'Never answers; notes when it is cancelled', inputSchema: { type: 'object' } },
    ],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
    const { name, arguments: args = {} } = req.params;
    if (name === 'wait') { await sleep(args.ms ?? 100); return { content: [{ type: 'text', text: 'waited' }] }; }
    if (name === 'hang') {
      seen.hanging = (seen.hanging ?? 0) + 1;
      await new Promise((resolve) => { extra.signal.addEventListener('abort', () => { seen.cancelled = (seen.cancelled ?? 0) + 1; resolve(); }); });
      return { content: [{ type: 'text', text: 'cancelled' }] };
    }
    return { content: [{ type: 'text', text: `echo: ${args.text}` }] };
  });
  return server;
}

describe('wsh mcp: an MCP client reaches an MCP server behind a wsh host (#127, Rust)', () => {
  let me;
  before(() => { me = makeHome(); });
  const env = () => cleanEnv(me.home);

  async function nodeHost(extra = {}, seen) {
    const server = createWshServer({ auth: { authorizedKeys: `${me.pub}\n` }, rpc: { mcp: mcpServerAdapter(() => makeMcpServer(seen)) }, ...extra });
    const { port } = await server.listen();
    cleanups.push(() => server.close());
    return { server, url: `ws://127.0.0.1:${port}`, port };
  }

  /** A memory host (what a browser tab runs) reached through a WebSocket: each connection is handed to `host.accept()`. */
  async function memoryHostOverWs(seen) {
    const host = createMemoryHost({ auth: { authorizedKeys: me.pub }, rpc: { mcp: mcpServerAdapter(() => makeMcpServer(seen)) } });
    const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise((r) => wss.once('listening', r));
    wss.on('connection', (ws) => { host.accept(ws).catch(() => {}); });
    cleanups.push(async () => { for (const c of wss.clients) c.terminate(); await new Promise((r) => wss.close(r)); await host.close(); });
    return { url: `ws://127.0.0.1:${wss.address().port}` };
  }

  /** `wsh mcp` as a child process speaking NDJSON, for tests that need the raw messages. */
  function bridge(args, { home = env() } = {}) {
    const proc = spawn(WSH_BIN, ['mcp', ...args], { env: home, stdio: ['pipe', 'pipe', 'pipe'] });
    const lines = []; let stderr = ''; let buf = '';
    proc.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { lines.push(buf.slice(0, i)); buf = buf.slice(i + 1); } });
    proc.stderr.on('data', (d) => { stderr += d; });
    proc.stdin.on('error', () => {});
    const exited = new Promise((resolve) => proc.once('exit', (code, signal) => resolve({ code, signal })));
    cleanups.push(async () => { proc.kill('SIGKILL'); });
    const api = {
      proc, exited, lines, stderr: () => stderr,
      send: (m) => proc.stdin.write(`${typeof m === 'string' ? m : JSON.stringify(m)}\n`),
      async next(want = () => true, ms = 10_000) {
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
    const transport = new StdioClientTransport({ command: WSH_BIN, args: ['mcp', ...args], env: env(), stderr: 'pipe' });
    await client.connect(transport);
    cleanups.push(() => client.close());
    return client;
  }

  it('an MCP client configured with the command lists and calls the tools of a server behind a Node host', async () => {
    const { url } = await nodeHost();
    const client = await viaSdkClient([`alice@${url}`]);
    assert.equal(client.getServerVersion().name, 'behind-wsh');
    assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['echo', 'wait', 'hang']);
    assert.equal((await client.callTool({ name: 'echo', arguments: { text: 'hi' } })).content[0].text, 'echo: hi');
    await client.close();
  });

  it('... and behind a memory host (a host in a page, reached through a WebSocket)', async () => {
    const { url } = await memoryHostOverWs();
    const client = await viaSdkClient([`alice@${url}`]);
    assert.equal(client.getServerVersion().name, 'behind-wsh');
    assert.equal((await client.callTool({ name: 'echo', arguments: { text: 'in a tab' } })).content[0].text, 'echo: in a tab');
  });

  it('concurrent calls are answered by id, each its own', async () => {
    const { url } = await nodeHost();
    const client = await viaSdkClient([`alice@${url}`]);
    const [slow, fast] = await Promise.all([
      client.callTool({ name: 'wait', arguments: { ms: 300 } }),
      client.callTool({ name: 'echo', arguments: { text: 'quick' } }),
    ]);
    assert.equal(slow.content[0].text, 'waited');
    assert.equal(fast.content[0].text, 'echo: quick');
  });

  it('the client aborting a call reaches the tool: notifications/cancelled becomes the channel cancel and the abort fires', async () => {
    const seen = {};
    const { url } = await nodeHost({}, seen);
    const client = await viaSdkClient([`alice@${url}`]);
    const controller = new AbortController();
    const call = client.callTool({ name: 'hang', arguments: {} }, undefined, { signal: controller.signal });
    const settled = call.then(() => 'answered', (e) => e);
    while (!seen.hanging) await sleep(20);
    controller.abort();
    const outcome = await settled;
    assert.notEqual(outcome, 'answered');
    const deadline = Date.now() + 5000;
    while (!seen.cancelled && Date.now() < deadline) await sleep(20);
    assert.equal(seen.cancelled, 1, 'the tool handler saw its signal abort');
    // and the session is still good, and the channel's own answer to the cancelled call did not reach the client
    assert.equal((await client.callTool({ name: 'echo', arguments: { text: 'after' } })).content[0].text, 'echo: after');
  });

  it('a request the client cancelled gets no answer at all: the channel\'s own -32001 is not passed on', async () => {
    const seen = {};
    const { url } = await nodeHost({}, seen);
    const b = bridge([`alice@${url}`]);
    await b.initialize();
    b.send({ jsonrpc: '2.0', id: 20, method: 'tools/call', params: { name: 'hang', arguments: {} } });
    while (!seen.hanging) await sleep(20);
    b.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 20, reason: 'user' } });
    while (!seen.cancelled) await sleep(20);
    b.send({ jsonrpc: '2.0', id: 21, method: 'tools/list' });
    await b.next((m) => m.id === 21);
    assert.ok(!b.lines.some((l) => JSON.parse(l).id === 20), `nothing for the cancelled id: ${b.lines.join('\n')}`);
    b.proc.stdin.end();
    assert.equal((await b.exited).code, 0);
  });

  it('notifications/cancelled for a request in flight is the channel\'s $/cancel: a plain rpc handler sees its signal abort', async () => {
    // An rpc handler that is not an MCP SDK, so only the channel's own cancel can stop it.
    const seen = { waiting: 0, aborted: 0 };
    const server = createWshServer({
      auth: { authorizedKeys: `${me.pub}\n` },
      rpc: { plain: (channel) => channel.onRequest('wait', (_params, { signal }) => new Promise((resolve) => { seen.waiting += 1; signal.addEventListener('abort', () => { seen.aborted += 1; resolve('late'); }); })) },
    });
    const { port } = await server.listen();
    cleanups.push(() => server.close());
    const b = bridge(['--channel', 'plain', `alice@ws://127.0.0.1:${port}`]);
    b.send({ jsonrpc: '2.0', id: 30, method: 'wait' });
    while (!seen.waiting) await sleep(20);
    b.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 30 } });
    const deadline = Date.now() + 5000;
    while (!seen.aborted && Date.now() < deadline) await sleep(20);
    assert.equal(seen.aborted, 1, 'the handler\'s signal aborted');
    b.send({ jsonrpc: '2.0', id: 31, method: 'wait' });
    await sleep(300);
    assert.ok(!b.lines.some((l) => JSON.parse(l).id === 30), 'no answer for the cancelled id');
    b.proc.stdin.end();
    assert.equal((await b.exited).code, 0);
  });

  it('stdout carries MCP messages only: every line parses, a bad line is a JSON-RPC error, and nothing else is written there', async () => {
    const { url } = await nodeHost();
    const b = bridge([`alice@${url}`]);
    await b.initialize();
    b.send('this is not json');
    b.send({ jsonrpc: '1.0', id: 7, method: 'tools/list' });
    b.send([{ jsonrpc: '2.0', id: 8, method: 'tools/list' }]);
    b.send({ jsonrpc: '2.0', id: 9, method: 'tools/list' });
    assert.equal((await b.next((m) => m.error?.code === -32700)).id, null);
    assert.equal((await b.next((m) => m.id === 7)).error.code, -32600);
    assert.equal((await b.next((m) => m.error?.code === -32600 && m.id === null)).error.code, -32600);
    assert.equal((await b.next((m) => m.id === 9)).result.tools.length, 3);
    for (const line of b.lines) assert.doesNotThrow(() => JSON.parse(line), line);
    b.proc.stdin.end();
    assert.equal((await b.exited).code, 0);
  });

  it('a message over the host\'s limit is answered with an error and the bridge goes on', async () => {
    const { url } = await nodeHost({ rpcMaxMessageBytes: 2048 });
    const b = bridge([`alice@${url}`]);
    await b.initialize();
    b.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: { text: 'x'.repeat(5000) } } });
    const refused = await b.next((m) => m.id === 2);
    assert.equal(refused.error.code, -32603);
    assert.match(refused.error.message, /exceeds the 2048 byte rpc message limit/);
    b.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { text: 'small' } } });
    assert.equal((await b.next((m) => m.id === 3)).result.content[0].text, 'echo: small');
    b.proc.stdin.end();
    assert.equal((await b.exited).code, 0);
  });

  it('a host with no mcp channel: exit 2 and an error that says what the host offers', async () => {
    const server = createWshServer({ auth: { authorizedKeys: `${me.pub}\n` }, rpc: { 'wsh-host': true } });
    const { port } = await server.listen();
    cleanups.push(() => server.close());
    const b = bridge([`alice@ws://127.0.0.1:${port}`]);
    assert.equal((await b.exited).code, 2);
    assert.match(b.stderr(), /offers no "mcp" channel \(it offers: wsh-host\)/);
    assert.match(b.stderr(), /mcpServerAdapter/);
    assert.equal(b.lines.length, 0, 'nothing on stdout');
    const none = await nodeHost({ rpc: undefined });
    const c = bridge([`alice@${none.url}`]);
    assert.equal((await c.exited).code, 2);
    assert.match(c.stderr(), /offers no rpc channels/);
  });

  it('--channel opens another rpc protocol by name', async () => {
    const server = createWshServer({ auth: { authorizedKeys: `${me.pub}\n` }, rpc: { 'tools-v2': mcpServerAdapter(() => makeMcpServer()) } });
    const { port } = await server.listen();
    cleanups.push(() => server.close());
    const b = bridge(['--channel', 'tools-v2', `alice@ws://127.0.0.1:${port}`]);
    assert.equal((await b.initialize()).result.serverInfo.name, 'behind-wsh');
    b.proc.stdin.end();
    await b.exited;
    const c = bridge([`alice@ws://127.0.0.1:${port}`]);
    assert.equal((await c.exited).code, 2, 'the default channel is mcp, which this host does not offer');
    assert.match(c.stderr(), /offers no "mcp" channel \(it offers: tools-v2\)/);
    const d = bridge(['--channel', '../etc', `alice@ws://127.0.0.1:${port}`]);
    assert.equal((await d.exited).code, 2);
    assert.match(d.stderr(), /not a valid channel name/);
  });

  it('a refused login exits 2 with the host\'s reason, and the identity is a keystore name (-i)', async () => {
    const { url } = await nodeHost();
    const stranger = makeHome();
    const a = bridge([`alice@${url}`], { home: cleanEnv(stranger.home) });
    assert.equal((await a.exited).code, 2);
    assert.match(a.stderr(), /Authentication failed|not authorized/i);
    // a second key in the stranger's home, authorized by the host, chosen with -i
    execFileSync(WSH_BIN, ['keygen', 'work'], { env: cleanEnv(stranger.home), stdio: 'ignore' });
    const workPub = readFileSync(path.join(stranger.home, '.wsh', 'keys', 'work.pub'), 'utf8').trim();
    const host = await nodeHost({ auth: { authorizedKeys: `${workPub}\n` } });
    const b = bridge(['-i', 'work', `alice@${host.url}`], { home: cleanEnv(stranger.home) });
    assert.equal((await b.initialize()).result.serverInfo.name, 'behind-wsh');
    b.proc.stdin.end();
    assert.equal((await b.exited).code, 0);
    const c = bridge(['-i', 'nope', `alice@${host.url}`], { home: cleanEnv(stranger.home) });
    assert.equal((await c.exited).code, 2);
  });

  it('--host-key pins the host: the right fingerprint connects, a wrong one is refused before anything is signed', async () => {
    const hostKey = await generateKeyPair(true);
    const { server, url } = await nodeHost({ hostKey });
    const fp = server.hostKey().fingerprint;
    const ok = bridge(['--host-key', fp, `alice@${url}`]);
    assert.equal((await ok.initialize()).result.serverInfo.name, 'behind-wsh');
    ok.proc.stdin.end();
    await ok.exited;
    assert.equal(readKnownHosts(me.home), '', 'a pin names the key: known_hosts is not written');
    const bad = bridge(['--host-key', 'ab'.repeat(32), `alice@${url}`]);
    assert.equal((await bad.exited).code, 2);
    assert.match(bad.stderr(), /HOST KEY MISMATCH/);
    const junk = bridge(['--host-key', 'not-a-key', `alice@${url}`]);
    assert.equal((await junk.exited).code, 2);
    assert.match(junk.stderr(), /--host-key/);
    // a host that proves no key is refused when one is pinned
    const keyless = await nodeHost();
    const none = bridge(['--host-key', fp, `alice@${keyless.url}`]);
    assert.equal((await none.exited).code, 2);
    assert.match(none.stderr(), /proved no host key/);
  });

  it('without --host-key the first use of a host key is refused (known_hosts), and --accept-new-host-key trusts it', async () => {
    const hostKey = await generateKeyPair(true);
    const { url } = await nodeHost({ hostKey });
    const refused = bridge([`alice@${url}`]);
    assert.equal((await refused.exited).code, 2);
    assert.match(refused.stderr(), /authenticity of host/);
    const accepted = bridge(['--accept-new-host-key', `alice@${url}`]);
    assert.equal((await accepted.initialize()).result.serverInfo.name, 'behind-wsh');
    accepted.proc.stdin.end();
    await accepted.exited;
    assert.notEqual(readKnownHosts(me.home), '');
  });

  it('--target is refused: rpc channels are not per target', async () => {
    const t = spawn(WSH_BIN, ['--target', 'web', 'mcp', 'ws://127.0.0.1:1'], { env: env(), stdio: ['ignore', 'pipe', 'pipe'] });
    let err = ''; t.stderr.on('data', (d) => { err += d; });
    const { code } = await new Promise((resolve) => t.once('exit', (c) => resolve({ code: c })));
    assert.equal(code, 2);
    assert.match(err, /--target applies to/);
  });

  it('a dropped connection is re-made: the session is re-initialized behind the client\'s back and the next request is answered', async () => {
    const seen = {};
    let { server, url, port } = await nodeHost({}, seen);
    const b = bridge([`alice@${url}`]);
    await b.initialize();
    b.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    assert.equal((await b.next((m) => m.id === 2)).result.tools.length, 3);
    assert.equal(seen.initialized, 1);
    // an in-flight call is answered with an error when the connection goes, and the host comes back on the same port
    b.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'wait', arguments: { ms: 5000 } } });
    await sleep(300);
    await server.close();
    const lost = await b.next((m) => m.id === 3);
    assert.equal(lost.error.code, -32603);
    assert.match(lost.error.message, /connection to the wsh host was lost/);
    // held while it is down, delivered once it is back
    b.send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'echo', arguments: { text: 'after' } } });
    await sleep(300);
    server = createWshServer({ auth: { authorizedKeys: `${me.pub}\n` }, port, rpc: { mcp: mcpServerAdapter(() => makeMcpServer(seen)) } });
    await server.listen();
    cleanups.push(() => server.close());
    const answered = await b.next((m) => m.id === 4, 20_000);
    assert.equal(answered.result.content[0].text, 'echo: after');
    assert.equal(seen.initialized, 2, 'the new channel was initialized once more');
    assert.ok(!b.lines.some((l) => String(JSON.parse(l).id ?? '').startsWith('wsh-mcp-replay')), 'the replayed initialize is not shown to the client');
    assert.match(b.stderr(), /connection lost; reconnecting/);
    assert.match(b.stderr(), /reconnected/);
    b.proc.stdin.end();
    assert.equal((await b.exited).code, 0);
  });

  it('--no-reconnect: exit 1 when the connection is lost; and exit 1 after the attempts when it does not come back', async () => {
    const a = await nodeHost();
    const b = bridge(['--no-reconnect', `alice@${a.url}`]);
    await b.initialize();
    await a.server.close();
    assert.equal((await b.exited).code, 1);
    assert.match(b.stderr(), /connection lost/);
    const c0 = await nodeHost();
    const c = bridge(['--reconnect-attempts', '2', '--timeout', '1000', `alice@${c0.url}`]);
    await c.initialize();
    await c0.server.close();
    c.send({ jsonrpc: '2.0', id: 5, method: 'tools/list' });
    const refused = await c.next((m) => m.id === 5, 30_000);
    assert.equal(refused.error.code, -32603);
    assert.equal((await c.exited).code, 1);
    assert.match(c.stderr(), /could not reconnect; giving up/);
  });

  it('more than 200 messages held while reconnecting: the rest of the requests are answered with an error', async () => {
    const a = await nodeHost();
    const b = bridge(['--reconnect-attempts', '3', '--timeout', '1000', `alice@${a.url}`]);
    await b.initialize();
    await a.server.close();
    const until = Date.now() + 10_000;
    while (!/reconnecting \(attempt 1 of 3\)/.test(b.stderr()) && Date.now() < until) await sleep(10);
    for (let i = 0; i < 210; i++) b.send({ jsonrpc: '2.0', id: 1000 + i, method: 'tools/list' });
    const over = await b.next((m) => m.error?.message === 'too many messages while reconnecting', 20_000);
    assert.equal(over.error.code, -32603);
    assert.equal(b.lines.filter((l) => JSON.parse(l).error?.message === 'too many messages while reconnecting').length, 10, 'the 10 past the 200 held');
    // the 200 held are answered when it gives up
    await b.next((m) => m.error?.message === 'the wsh host is unreachable', 30_000);
    assert.equal((await b.exited).code, 1);
    assert.equal(b.lines.filter((l) => JSON.parse(l).error?.message === 'the wsh host is unreachable').length, 200);
  });

  it('the client closing stdin ends the bridge with 0, and a signal ends it cleanly', async () => {
    const { url } = await nodeHost();
    const a = bridge([`alice@${url}`]);
    await a.initialize();
    a.proc.stdin.end();
    assert.equal((await a.exited).code, 0);
    const b = bridge([`alice@${url}`]);
    await b.initialize();
    b.proc.kill('SIGTERM');
    assert.equal((await b.exited).code, 0);
  });

  it('through a pipe relay: --via carries the bridge to a host that dialled the relay', async () => {
    const { createPipeRelay, newRendezvousId, pipeUrl } = await import('@johnhenry/wsh/pipe-relay');
    const relay = createPipeRelay({ rendezvousTimeoutMs: 15_000 });
    const { port } = await relay.listen();
    cleanups.push(() => relay.close());
    const id = newRendezvousId();
    const server = createWshServer({ auth: { authorizedKeys: `${me.pub}\n` }, rpc: { mcp: mcpServerAdapter(() => makeMcpServer()) } });
    cleanups.push(() => server.close());
    const { WebSocket: WsClient } = await import('ws');
    const hostSide = new WsClient(pipeUrl(`ws://127.0.0.1:${port}`, id, 'host'));
    await new Promise((resolve, reject) => { hostSide.once('open', resolve); hostSide.once('error', reject); });
    server.accept(hostSide).catch(() => {});
    const b = spawn(WSH_BIN, ['--via', pipeUrl(`ws://127.0.0.1:${port}`, id, 'operator'), 'mcp', 'alice@pod.example'], { env: env(), stdio: ['pipe', 'pipe', 'pipe'] });
    cleanups.push(async () => b.kill('SIGKILL'));
    let out = ''; b.stdout.on('data', (d) => { out += d; });
    b.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'raw', version: '1' } } })}\n`);
    const deadline = Date.now() + 10_000;
    while (!out.includes('\n') && Date.now() < deadline) await sleep(20);
    assert.equal(JSON.parse(out.split('\n')[0]).result.serverInfo.name, 'behind-wsh');
    b.stdin.end();
  });
});

const readKnownHosts = (home) => { try { return readFileSync(path.join(home, '.wsh', 'known_hosts'), 'utf8'); } catch { return ''; } };

describe('wsh mcp against the Rust wsh-server (#127)', { skip: !existsSync(SERVER_BIN) && `no wsh-server at ${SERVER_BIN}` }, () => {
  const freePort = () => new Promise((resolve) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
  let me; let server; let port;
  before(async () => {
    me = makeHome();
    const sh = mkdtempSync(path.join(tmpdir(), 'wsh-mcp-srv-'));
    scratch.push(sh);
    mkdirSync(path.join(sh, '.wsh'));
    writeFileSync(path.join(sh, '.wsh', 'authorized_keys'), `${me.pub}\n`);
    writeFileSync(path.join(sh, '.wsh', 'config.toml'), '');
    port = await freePort();
    server = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', path.join(sh, '.wsh', 'config.toml')], { env: { PATH: process.env.PATH, HOME: sh }, stdio: ['ignore', 'pipe', 'pipe'] });
    cleanups.push(async () => server.kill());
    let logs = '';
    await new Promise((resolve, reject) => {
      const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
      server.stdout.on('data', onData); server.stderr.on('data', onData);
      server.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
      setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
    });
  });
  const run = (args, input) => new Promise((resolve) => {
    const proc = spawn(WSH_BIN, ['mcp', ...args], { env: cleanEnv(me.home), stdio: ['pipe', 'pipe', 'pipe'] });
    let out = ''; let err = '';
    proc.stdout.on('data', (d) => { out += d; }); proc.stderr.on('data', (d) => { err += d; });
    proc.stdin.on('error', () => {});
    if (input) proc.stdin.write(input);
    const done = () => { proc.stdin.end(); };
    const timer = setTimeout(() => proc.kill('SIGKILL'), 20_000);
    proc.once('close', (code) => { clearTimeout(timer); resolve({ code, out, err }); });
    if (input) setTimeout(done, 1500); else done();
  });

  it('the default "mcp" channel is refused (exit 2): the Rust server offers wsh-host only, and says so', async () => {
    const r = await run(['--accept-new-host-key', `alice@wss://127.0.0.1:${port}`]);
    assert.equal(r.code, 2, r.err);
    assert.match(r.err, /offers no "mcp" channel \(it offers: wsh-host\)/);
    assert.equal(r.out, '');
  });

  it('the Rust client\'s rpc channel works against the Rust host: --channel wsh-host answers host.ping and host.info', async () => {
    const r = await run(['--channel', 'wsh-host', `alice@wss://127.0.0.1:${port}`],
      `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'host.ping' })}\n${JSON.stringify({ jsonrpc: '2.0', id: 'two', method: 'host.info' })}\n${JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'nope' })}\n`);
    assert.equal(r.code, 0, r.err);
    const answers = r.out.trim().split('\n').map((l) => JSON.parse(l));
    const byId = Object.fromEntries(answers.map((m) => [m.id, m]));
    assert.equal(typeof byId[1].result.time, 'number');
    assert.equal(byId.two.result.user, 'alice');
    assert.ok(byId.two.result.rpc.protocols.includes('wsh-host'));
    assert.equal(byId[3].error.code, -32601);
  });
});
