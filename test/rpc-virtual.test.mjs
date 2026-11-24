// test/rpc-virtual.test.mjs -- wsh #191: rpc channels in virtual data mode (the CBOR sequence rides SessionData, and
// EncryptedFrame on a sealed session, metered by credit), so a sealed session and a host behind a relay can carry rpc.
//
// The first block runs the same scenarios over both modes (a client-opened data stream, and the control plane); the rest
// is what only the virtual mode has: credit, sealing behind a recording and a tampering relay, a host behind a pipe relay and
// behind a wsh relay offering `mcp` to the MCP SDK's client, and a released peer on either side.
import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket as WsClient, WebSocketServer } from 'ws';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createReverseHost as createBrowserReverseHost } from '@johnhenry/wsh/reverse';
import { createWshServer, createReverseHost, mcpServerAdapter } from '@johnhenry/wsh/server';
import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import {
  WshClient, RpcChannel, RpcError, RPC_ERROR, RPC_FEATURE, RPC_VIRTUAL_FEATURE, rpcProtocolFeature, parseRpcFeatures,
  MSG, cborEncode, cborDecode, ping, mcpClientTransport,
  generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint,
} from '@johnhenry/wsh';
import { RpcCreditLink, RPC_CREDIT_WINDOW, rpcCreditId, rpcChannelOfCredit } from '../src/rpc-virtual.mjs';
import { hostileRelay } from './helpers/hostile-relay.mjs';

const enc = new TextEncoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tick = () => new Promise((r) => setImmediate(r));
async function until(cond, what, ms = 5000) {
  const t0 = Date.now();
  for (;;) {
    const v = await cond();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(5);
  }
}

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

let keyPair; let authorizedKeys; let raw;
before(async () => {
  keyPair = await generateKeyPair(true);
  authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} alice`;
  raw = await exportPublicKeyRaw(keyPair.publicKey);
});

/** The protocol every mode-parameterised test talks to. */
function calc(state = {}) {
  return (channel, ctx) => {
    state.ctx = ctx; state.channel = channel;
    channel.onRequest('add', ({ a, b }) => ({ sum: a + b }));
    channel.onRequest('echo', (p) => p);
    channel.onRequest('boom', () => { throw new RpcError(RPC_ERROR.INVALID_PARAMS, 'nope'); });
    channel.onRequest('big', ({ n }) => ({ data: new Uint8Array(n).fill(7) }));
    channel.onRequest('count', async ({ n }, c) => { for (let i = 1; i <= n; i++) await c.progress({ i }); return { done: n }; });
    channel.onRequest('hang', (_p, c) => new Promise((_resolve, reject) => { state.hung = true; c.signal.addEventListener('abort', () => { state.aborted = true; reject(c.signal.reason); }); }));
    channel.onNotification('note', (p) => { (state.notes ??= []).push(p); });
    channel.onRequest('tell', ({ text }) => { void channel.notify('told', { text }); return null; });
    channel.onRequest('flood', async ({ n, size }) => {
      state.flooded = 0;
      for (let i = 0; i < n; i++) { await channel.notify('pad', { i, pad: new Uint8Array(size) }); state.flooded = i + 1; }
      return { sent: n };
    });
  };
}

function memoryHost(opts = {}) {
  const host = createMemoryHost({ auth: { authorizedKeys: [raw] }, ...opts });
  closers.push(() => host.close());
  return host;
}
async function open(host) {
  const client = await host.connect({ username: 'alice', keyPair });
  closers.push(() => client.disconnect());
  return client;
}

const MODES = [{ name: 'stream', dataStreams: true }, { name: 'virtual', dataStreams: false }];

for (const mode of MODES) {
  describe(`rpc over a ${mode.name} channel`, () => {
    const boot = async (extra = {}) => {
      const state = {};
      const host = memoryHost({ dataStreams: mode.dataStreams, rpc: { calc: calc(state) }, ...extra });
      return { state, host, client: await open(host) };
    };

    it('negotiates: one form of the feature, the protocol, the size', async () => {
      const { client } = await boot();
      assert.equal(client.hasFeature(RPC_FEATURE), mode.dataStreams);
      assert.equal(client.hasFeature(RPC_VIRTUAL_FEATURE), !mode.dataStreams);
      assert.ok(client.hasFeature(rpcProtocolFeature('calc')));
      assert.ok(client.hasFeature('rpc-max-message:1048576'));
    });

    it('answers a request and an error, and reaches a missing method', async () => {
      const { client } = await boot();
      const rpc = await client.openRpc('calc');
      assert.deepEqual(await rpc.request('add', { a: 2, b: 40 }), { sum: 42 });
      await assert.rejects(rpc.request('boom', {}), (e) => e instanceof RpcError && e.code === RPC_ERROR.INVALID_PARAMS && /nope/.test(e.message));
      await assert.rejects(rpc.request('missing', {}), (e) => e.code === RPC_ERROR.METHOD_NOT_FOUND);
      await rpc.close();
    });

    it('carries notifications both ways, and binary values natively', async () => {
      const { client, state } = await boot();
      const rpc = await client.openRpc('calc');
      const told = [];
      rpc.onNotification('told', (p) => told.push(p));
      rpc.notify('note', { hi: 1 });
      await until(() => state.notes?.length === 1, 'the notification');
      await rpc.request('tell', { text: 'back' });
      await until(() => told.length === 1, 'the notification from the host');
      assert.deepEqual(told[0], { text: 'back' });
      const bytes = new Uint8Array([0, 1, 2, 255]);
      const back = await rpc.request('echo', { bytes });
      assert.ok(back.bytes instanceof Uint8Array);
      assert.deepEqual([...back.bytes], [0, 1, 2, 255]);
    });

    it('streams progress and cancels a request in flight', async () => {
      const { client, state } = await boot();
      const rpc = await client.openRpc('calc');
      const seen = [];
      assert.deepEqual(await rpc.request('count', { n: 5 }, { onProgress: (c) => seen.push(c.i) }), { done: 5 });
      assert.deepEqual(seen, [1, 2, 3, 4, 5]);
      const pending = rpc.request('hang', {});
      await until(() => state.hung, 'the handler to start');
      pending.cancel();
      await assert.rejects(pending, (e) => e.code === RPC_ERROR.CANCELLED);
      await until(() => state.aborted, 'the handler to be aborted');
    });

    it('carries a message larger than the credit window (a 700 KiB result) and refuses one over the cap before it is sent', async () => {
      const { client } = await boot();
      const rpc = await client.openRpc('calc');
      const res = await rpc.request('big', { n: 700 * 1024 });
      assert.equal(res.data.length, 700 * 1024);
      assert.ok(res.data.every((b) => b === 7));
      await assert.rejects(rpc.request('echo', { data: new Uint8Array(2 * 1024 * 1024) }), (e) => e.reason === 'message-too-large');
      assert.equal(rpc.closed, false, 'refusing it locally does not end the channel');
      assert.deepEqual(await rpc.request('add', { a: 1, b: 1 }), { sum: 2 });
    });

    it('a peer that declares a message over the cap has the channel closed before it is assembled', async () => {
      const { client } = await boot();
      const session = await client.openSession({ type: 'rpc', protocol: 'calc' });
      const closed = new Promise((resolve) => { session.onClose = resolve; });
      const replies = [];
      session.onData = (d) => replies.push(d);
      // A CBOR byte string that declares 2 MiB: five bytes, and the host refuses it without waiting for the rest.
      await session.write(new Uint8Array([0x5a, 0x00, 0x20, 0x00, 0x00]));
      await closed;
      const [first] = replies.flatMap((d) => { try { return [cborDecode(d)]; } catch { return []; } });
      assert.equal(first?.error?.data?.reason, 'message-too-large', JSON.stringify(first));
    });

    it('enforces rpcMaxInflight and closes every channel when the client disconnects', async () => {
      const releases = [];
      const host = memoryHost({ dataStreams: mode.dataStreams, rpc: { slow: (c) => { c.onRequest('wait', () => new Promise((r) => releases.push(r))); } }, rpcMaxInflight: 2 });
      const client = await open(host);
      const rpc = await client.openRpc('slow');
      const a = rpc.request('wait', {}); const b = rpc.request('wait', {});
      await until(() => releases.length === 2, 'two requests in flight');
      await assert.rejects(rpc.request('wait', {}), (e) => e.code === -32002);
      releases.forEach((r) => r('ok'));
      assert.equal(await a, 'ok'); assert.equal(await b, 'ok');
    });

    it('an unadvertised protocol is refused client-side, and a host without rpc advertises neither form', async () => {
      const { client } = await boot();
      await assert.rejects(client.openRpc('other'), (e) => e.code === RPC_ERROR.UNSUPPORTED_PROTOCOL);
      const bare = await open(memoryHost({ dataStreams: mode.dataStreams }));
      assert.ok(!bare.hasFeature(RPC_FEATURE) && !bare.hasFeature(RPC_VIRTUAL_FEATURE));
      await assert.rejects(bare.openRpc('calc'), (e) => e.code === RPC_ERROR.UNSUPPORTED_PROTOCOL);
    });

    it('the host ending the channel, and the client disconnecting, both end it cleanly', async () => {
      const { client, state } = await boot();
      const rpc = await client.openRpc('calc');
      const closed = new Promise((r) => { rpc.onClose = r; });
      await rpc.request('add', { a: 1, b: 2 });
      await state.channel.close('host-done');
      await closed;
      assert.equal(rpc.closed, true);
      const again = await client.openRpc('calc');
      await client.disconnect();
      await assert.rejects(again.request('add', { a: 1, b: 2 }), (e) => e.code === RPC_ERROR.CANCELLED);
    });
  });
}

describe('credit (the flow control of a virtual-mode channel)', () => {
  it('RpcCreditLink: a writer sends the window and waits; credit moves it on; the bytes are all delivered, in order', async () => {
    const sent = [];
    const link = new RpcCreditLink({ sendData: (b) => { sent.push(...b); }, sendCredit: () => {} });
    const payload = Uint8Array.from({ length: 1_000_000 }, (_, i) => i & 0xff);
    const writing = link.write(payload);
    await tick();
    assert.equal(sent.length, RPC_CREDIT_WINDOW, 'exactly the window was sent, then it waited');
    link.grant(100_000);
    await tick();
    assert.equal(sent.length, RPC_CREDIT_WINDOW + 100_000);
    link.grant(10_000_000);
    await writing;
    assert.deepEqual(Uint8Array.from(sent), payload);
  });

  it('RpcCreditLink: credit is returned as bytes are consumed, in halves of the window; a peer that overruns is reported', () => {
    const credits = []; const violations = [];
    const link = new RpcCreditLink({ sendData: () => {}, sendCredit: (n) => credits.push(n), onViolation: (w) => violations.push(w) });
    assert.equal(link.receive(RPC_CREDIT_WINDOW / 2), true);
    link.consumed(RPC_CREDIT_WINDOW / 4);
    assert.deepEqual(credits, [], 'nothing is returned for a quarter');
    link.consumed(RPC_CREDIT_WINDOW / 4);
    assert.deepEqual(credits, [RPC_CREDIT_WINDOW / 2]);
    assert.equal(link.receive(RPC_CREDIT_WINDOW), true, 'what was returned may be sent again');
    assert.equal(link.receive(RPC_CREDIT_WINDOW), false);
    assert.equal(violations.length, 1);
  });

  it('credit ids are a number space of their own beside the gateway ids', () => {
    assert.equal(rpcChannelOfCredit(rpcCreditId(5)), 5);
    assert.equal(rpcChannelOfCredit(5), undefined);
    assert.equal(rpcChannelOfCredit(1), undefined);
  });

  it('a slow reader bounds the sender: while the client is not consuming, the host cannot send past the window; then it all arrives', async () => {
    const state = {};
    const host = memoryHost({ dataStreams: false, rpc: { calc: calc(state) } });
    const client = await open(host);
    const rpc = await client.openRpc('calc');
    const got = [];
    rpc.onNotification('pad', (p) => got.push(p.i));
    rpc.hold(); // the reader takes nothing in: its credit is not returned
    const total = 60; const size = 10_000;
    const flooding = rpc.request('flood', { n: total, size });
    await until(() => state.flooded > 0, 'the host to start sending');
    // A round trip on the connection itself (FIFO behind everything the host could still send) says the wire has gone quiet.
    const pong = new Promise((resolve) => { const off = client.addControlListener((m) => { if (m.type === MSG.PONG && m.id === 4242) { off?.(); resolve(); } }); });
    await client.sendRelayControl(ping({ id: 4242 }));
    await pong; await tick();
    const stalledAt = state.flooded;
    assert.ok(stalledAt > 0 && stalledAt <= Math.ceil(RPC_CREDIT_WINDOW / size) + 1, `${stalledAt} messages of ${size} bytes went out against a ${RPC_CREDIT_WINDOW}-byte window`);
    assert.ok(stalledAt < total);
    assert.equal(got.length, 0, 'nothing was dispatched while the channel was held');
    rpc.release();
    await flooding.catch(() => {});
    await until(() => got.length === total, 'every message once the reader reads');
    assert.deepEqual(got, Array.from({ length: total }, (_, i) => i));
    assert.equal(state.flooded, total);
  });

  it('a peer that sends more than its credit has the channel closed (the sender cannot ignore the window)', async () => {
    const state = {};
    // A handler that never finishes registering keeps the channel held, so nothing it receives is consumed and no credit returns.
    const host = memoryHost({ dataStreams: false, rpc: { stuck: () => new Promise(() => {}) }, onLog: (l) => (state.logs ??= []).push(l) });
    const client = await open(host);
    const session = await client.openSession({ type: 'rpc', protocol: 'stuck' });
    const closed = new Promise((resolve) => { session.onClose = resolve; });
    // One write per chunk, with no regard for credit: 12 x 32 KiB is more than the 256 KiB window (never a complete message).
    for (let i = 0; i < 12; i++) await session.write(new Uint8Array(32 * 1024).fill(0x41)).catch(() => {});
    await closed;
    assert.ok(state.logs.some((l) => /more rpc data than the credit/.test(l)), (state.logs ?? []).join(' | '));
  });
});

describe('a released peer', () => {
  it('a client that only knows stream-mode rpc looks for `rpc`, which a virtual host does not state: it is refused before anything is sent', async () => {
    const host = memoryHost({ dataStreams: false, rpc: { calc: calc() } });
    const client = await open(host);
    const features = client.serverFeatures;
    assert.equal(parseRpcFeatures(features).enabled, false);
    assert.ok(features.includes(RPC_VIRTUAL_FEATURE));
    assert.ok(!features.includes(RPC_FEATURE));
  });

  it('a host with data streams states exactly what it stated before, and no virtual feature', async () => {
    const host = memoryHost({ dataStreams: true, rpc: { calc: calc() } });
    const client = await open(host);
    const rpcFeatures = client.serverFeatures.filter((f) => f === RPC_FEATURE || f.startsWith('rpc'));
    assert.deepEqual(rpcFeatures.sort(), ['rpc', 'rpc-max-message:1048576', 'rpc-protocol:calc']);
  });

  it('this client against a host that states neither form opens nothing and sends nothing', async () => {
    const host = memoryHost({ dataStreams: false, rpc: { calc: calc() } });
    const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise((r) => wss.once('listening', r));
    wss.on('connection', (ws) => { void host.accept(ws); });
    closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
    const strip = (m) => (m.type === MSG.SERVER_HELLO ? { ...m, features: (m.features ?? []).filter((f) => !f.startsWith('rpc')) } : m);
    const relay = await hostileRelay(`ws://127.0.0.1:${wss.address().port}`, { toClient: strip });
    closers.push(() => relay.close());
    const client = new WshClient();
    closers.push(() => client.disconnect());
    await client.connect(relay.url, { username: 'alice', keyPair, transport: 'ws' });
    await assert.rejects(client.openRpc('calc'), (e) => e.code === RPC_ERROR.UNSUPPORTED_PROTOCOL);
    assert.ok(!relay.seen.some((e) => e.dir === 'to-relay' && e.msg.type === MSG.OPEN), 'no Open was sent');
  });

  it('the host refuses an Open that arrives where it offers no rpc (a peer that did not read the features)', async () => {
    const host = memoryHost({ dataStreams: false, rpc: { calc: calc() } });
    const client = await open(host);
    client.hasFeature = () => true;
    await assert.rejects(client.openRpc('nope'), /UNSUPPORTED_PROTOCOL|not supported/);
  });
});

// ── Sealed sessions, behind a recording and a tampering relay ───────────────────────────────────────────────────────

const MARKER = 'SECRET-MARKER-ZEBRA-7731';
const METHOD = 'zebra.secretMethodName';

async function sealedSetup({ sealSession = 'require', relayHooks = {}, onLog } = {}) {
  const state = {};
  const logs = [];
  const host = createMemoryHost({
    auth: { authorizedKeys }, hostKey: true, dataStreams: false, sealSession,
    rpc: { calc: (channel, ctx) => { state.ctx = ctx; channel.onRequest(METHOD, (p) => { (state.delivered ??= []).push(p); return { echoed: p.text }; }); } },
    onLog: (l) => { logs.push(l); onLog?.(l); },
  });
  closers.push(() => host.close());
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  wss.on('connection', (ws) => { void host.accept(ws); });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  const relay = await hostileRelay(`ws://127.0.0.1:${wss.address().port}`, relayHooks);
  closers.push(() => relay.close());
  return { host, relay, logs, state };
}
async function sealedLogin(s, opts = {}) {
  const client = new WshClient();
  closers.push(() => client.disconnect());
  await client.connect(s.relay.url, { username: 'alice', keyPair, transport: 'ws', ...opts });
  return client;
}
const wireBytes = (relay) => relay.seen.map((e) => Buffer.from(cborEncode(e.msg)));
const seenText = (relay, text) => wireBytes(relay).some((b) => b.includes(Buffer.from(text)));

describe('rpc on a sealed session', () => {
  it('a sealed session carries rpc: the method name and the payload cross a recording relay only as ciphertext', async () => {
    const s = await sealedSetup();
    const client = await sealedLogin(s);
    assert.equal(client.sessionSealed, true);
    assert.ok(client.hasFeature(RPC_VIRTUAL_FEATURE));
    const rpc = await client.openRpc('calc');
    assert.deepEqual(await rpc.request(METHOD, { text: MARKER }), { echoed: MARKER });
    assert.ok(!seenText(s.relay, MARKER), 'the payload crossed the relay in the clear');
    assert.ok(!seenText(s.relay, METHOD), 'the method name crossed the relay in the clear');
    const authOk = s.relay.seen.findIndex((e) => e.dir === 'to-client' && e.msg.type === MSG.AUTH_OK);
    for (const e of s.relay.seen.slice(authOk + 1)) assert.ok([MSG.KEY_EXCHANGE, MSG.ENCRYPTED_FRAME, MSG.PING, MSG.PONG].includes(e.msg.type), `a plain message of type ${e.msg.type} crossed after the login`);
  });

  it('control: the same rpc on an unsealed session shows the relay the method and the payload', async () => {
    const s = await sealedSetup({ sealSession: 'offer' });
    const client = await sealedLogin(s, { sealSession: false });
    const rpc = await client.openRpc('calc');
    assert.deepEqual(await rpc.request(METHOD, { text: MARKER }), { echoed: MARKER });
    assert.ok(seenText(s.relay, MARKER));
  });

  it('a large message, more than the window, crosses a sealed session intact', async () => {
    const s = await sealedSetup();
    const client = await sealedLogin(s);
    const rpc = await client.openRpc('calc');
    const text = 'x'.repeat(600 * 1024);
    assert.deepEqual(await rpc.request(METHOD, { text }), { echoed: text });
  });

  it('a flipped byte in a sealed frame ends the session and nothing forged is delivered', async () => {
    let armed = false;
    const flip = (m) => {
      if (armed && m.type === MSG.ENCRYPTED_FRAME) { armed = false; const ct = new Uint8Array(m.ciphertext); ct[ct.length - 1] ^= 1; return { ...m, ciphertext: ct }; }
      return m;
    };
    const s = await sealedSetup({ relayHooks: { toRelay: flip } });
    const client = await sealedLogin(s);
    const rpc = await client.openRpc('calc');
    assert.deepEqual(await rpc.request(METHOD, { text: 'before' }), { echoed: 'before' });
    armed = true;
    const lost = new Promise((resolve) => { client.onClose = resolve; });
    await assert.rejects(rpc.request(METHOD, { text: 'forged' }, { timeoutMs: 3000 }));
    await lost;
    assert.deepEqual(s.state.delivered, [{ text: 'before' }], 'only the genuine request was delivered');
    assert.ok(s.logs.some((l) => /did not open/.test(l)), s.logs.join(' | '));
  });

  it('a plain message injected into a sealed session is not heard: an Open for rpc, or credit, changes nothing', async () => {
    const s = await sealedSetup();
    const client = await sealedLogin(s);
    const rpc = await client.openRpc('calc');
    await rpc.request(METHOD, { text: 'one' });
    const ctx = s.relay.context();
    const before = s.state.delivered.length;
    await ctx.injectToRelay({ type: MSG.SESSION_DATA, channel_id: 1, data: cborEncode({ jsonrpc: '2.0', id: 99, method: METHOD, params: { text: 'injected' } }) });
    await ctx.injectToRelay({ type: MSG.OPEN, kind: 'rpc', command: 'calc' });
    await until(() => s.logs.some((l) => /dropped a plaintext message/.test(l)), 'the host to drop it');
    assert.equal(s.state.delivered.length, before);
  });
});

// ── A host behind a relay ──────────────────────────────────────────────────────────────────────────────────────────

function mcpServer(info = { name: 'behind-a-relay', version: '1.0.0' }) {
  const server = new Server(info, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: 'echo', description: 'Echo text back', inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } }] }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => ({ content: [{ type: 'text', text: `echo: ${req.params.arguments?.text}` }] }));
  return server;
}

describe('a page host behind a pipe relay serves mcp, sealed', () => {
  it('the MCP SDK client lists and calls a tool through the pipe relay, and the relay sees no tool name', async () => {
    const relay = createPipeRelay();
    const { port } = await relay.listen();
    closers.push(() => relay.close());
    const relayUrl = `ws://127.0.0.1:${port}`;
    const host = createMemoryHost({ auth: { authorizedKeys }, hostKey: true, dataStreams: false, sealSession: 'require', rpc: { mcp: mcpServerAdapter(() => mcpServer()) } });
    closers.push(() => host.close());
    const id = newRendezvousId();
    const hostSocket = new WsClient(pipeUrl(relayUrl, id, 'host'));
    await new Promise((resolve, reject) => { hostSocket.once('open', resolve); hostSocket.once('error', reject); });
    await host.accept(hostSocket);
    // The operator reaches the pipe through a recording hop.
    const recorder = await hostileRelay(pipeUrl(relayUrl, id));
    closers.push(() => recorder.close());
    const wsh = new WshClient();
    closers.push(() => wsh.disconnect());
    await wsh.connect(recorder.url, { username: 'alice', keyPair, transport: 'ws', sealSession: true });
    assert.equal(wsh.sessionSealed, true);
    const channel = await wsh.openRpc('mcp');
    const mcp = new Client({ name: 'sdk-client', version: '0.0.1' }, { capabilities: {} });
    await mcp.connect(mcpClientTransport(channel));
    assert.equal(mcp.getServerVersion().name, 'behind-a-relay');
    assert.deepEqual((await mcp.listTools()).tools.map((t) => t.name), ['echo']);
    assert.equal((await mcp.callTool({ name: 'echo', arguments: { text: MARKER } })).content[0].text, `echo: ${MARKER}`);
    assert.ok(!seenText(recorder, MARKER) && !seenText(recorder, 'echo'), 'the relay saw a tool name or an argument');
    await mcp.close();
  });
});

describe('a reverse host behind a wsh relay offers rpc', () => {
  const keys = {};
  before(async () => {
    for (const name of ['host', 'bob']) {
      const kp = await generateKeyPair(true);
      keys[name] = { keyPair: kp, fp: await fingerprint(await exportPublicKeyRaw(kp.publicKey)) };
    }
    keys.authorized = (await Promise.all(['host', 'bob'].map(async (n) => `${await exportPublicKeySSH(keys[n].keyPair.publicKey)} ${n}`))).join('\n');
  });

  async function relayAndHost(factory, hostOptions = {}, reverseOptions) {
    const server = createWshServer({ auth: { authorizedKeys: keys.authorized }, relay: { canRegister: (w) => w.username === 'host', canConnect: (f) => f.username !== 'host' } });
    const { port } = await server.listen();
    closers.push(() => server.close());
    const url = `ws://127.0.0.1:${port}`;
    const host = factory({ url, username: 'host', keyPair: keys.host.keyPair, accept: () => true, reconnect: false, ...hostOptions });
    await host.start();
    closers.push(() => host.close());
    await until(() => server.peerFingerprints().includes(keys.host.fp), 'the host to register');
    const bob = new WshClient();
    closers.push(() => bob.disconnect());
    await bob.connect(url, { username: 'bob', keyPair: keys.bob.keyPair });
    const accepted = await bob.reverseConnect(keys.host.fp, 5000, reverseOptions);
    assert.equal(accepted.type, MSG.REVERSE_ACCEPT);
    return { bob, host };
  }

  it('the browser-safe createReverseHost({ rpc }) serves mcp to the MCP SDK client', async () => {
    const { bob } = await relayAndHost(createBrowserReverseHost, { rpc: { mcp: mcpServerAdapter(() => mcpServer()) } });
    assert.ok(bob.hasFeature(RPC_VIRTUAL_FEATURE), bob.serverFeatures.join(','));
    assert.ok(!bob.hasFeature(RPC_FEATURE));
    assert.ok(bob.hasFeature(rpcProtocolFeature('mcp')));
    const channel = await bob.openRpc('mcp');
    const mcp = new Client({ name: 'sdk-client', version: '0.0.1' }, { capabilities: {} });
    await mcp.connect(mcpClientTransport(channel));
    assert.deepEqual((await mcp.listTools()).tools.map((t) => t.name), ['echo']);
    assert.equal((await mcp.callTool({ name: 'echo', arguments: { text: 'hi' } })).content[0].text, 'echo: hi');
    await mcp.close();
  });

  it("@johnhenry/wsh/server's createReverseHost takes rpc, with the wsh-host built-in", async () => {
    const { bob } = await relayAndHost(createReverseHost, { exec: false, rpc: { 'wsh-host': true, calc: calc() } });
    const rpc = await bob.openRpc('wsh-host');
    const info = await rpc.request('host.info', {});
    assert.equal(info.protocol, 'wsh-v1');
    const c = await bob.openRpc('calc');
    assert.deepEqual(await c.request('add', { a: 1, b: 2 }), { sum: 3 });
  });

  it('rpc needs reportFeatures (the operator learns the protocols from ReverseAccept), and a reverse host without rpc offers none', async () => {
    assert.throws(() => createBrowserReverseHost({ url: 'ws://x', username: 'host', keyPair: keys.host.keyPair, rpc: { calc: calc() }, reportFeatures: false }), /reportFeatures/);
    assert.throws(() => createBrowserReverseHost({ url: 'ws://x', username: 'host', keyPair: keys.host.keyPair, rpc: { calc: 'nope' } }), /handler function/);
    const { bob } = await relayAndHost(createBrowserReverseHost);
    assert.ok(!bob.hasFeature(RPC_VIRTUAL_FEATURE));
    await assert.rejects(bob.openRpc('calc'), (e) => e.code === RPC_ERROR.UNSUPPORTED_PROTOCOL);
  });

  it('with the bridge sealed (requireOperatorProof), rpc rides inside the sealed frames', async () => {
    const { bob } = await relayAndHost(createBrowserReverseHost, { rpc: { calc: calc() }, requireOperatorProof: true }, { sealed: true });
    const rpc = await bob.openRpc('calc');
    assert.deepEqual(await rpc.request('add', { a: 20, b: 22 }), { sum: 42 });
    assert.equal((await rpc.request('big', { n: 400 * 1024 })).data.length, 400 * 1024);
  });
});
