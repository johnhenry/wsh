/**
 * `wsh-mcp` (wsh #127): a stdio bridge so an MCP client that launches a command can reach an MCP server behind a wsh host.
 *
 * The client speaks MCP over stdio (one JSON-RPC message per line); this connects to a wsh host, opens the host's `mcp` rpc
 * channel (`createWshServer({ rpc: { mcp: mcpServerAdapter(server) } })`, or `createMemoryHost({ rpc: { mcp } })` reached through
 * any WebSocket) and passes the messages both ways, verbatim: ids, notifications, progress and cancellation (`src/rpc-mcp.mjs`).
 *
 * If the connection drops after it was up, the bridge reconnects with a backoff and, when the client had already initialized,
 * replays that `initialize` / `notifications/initialized` to the new channel (its answer is not shown to the client), so the
 * session carries on. A request that was in flight when the connection dropped is answered with a JSON-RPC error (the client may
 * retry); messages the client sends meanwhile are held (bounded) and delivered once the channel is back.
 *
 * Node only (it reads a key file and talks to stdio); the package root never imports it.
 */

import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { WshClient, mcpClientTransport, rpcProtocolFeature, RPC_PROTOCOL_NAME_RE } from './index.mjs';

/** A failure the bridge cannot recover from, with the process exit status it asks for (2: could not start; 1: lost for good). */
export class McpBridgeError extends Error {
  constructor(message, { code = 'bridge', exitCode = 2, cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = 'McpBridgeError';
    this.code = code;
    this.exitCode = exitCode;
  }
}

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** The default identity: the key `wsh keygen` makes (`~/.wsh/keys/default.pem`). */
export const defaultIdentityPath = () => path.join(homedir(), '.wsh', 'keys', 'default.pem');

/**
 * Read an Ed25519 private key file: the `wsh keygen` format (`-----BEGIN WSH PRIVATE KEY-----`, the 32-byte secret in base64) or
 * a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`). Returns a signer for `WshClient.connect`.
 *
 * @param {string} file
 * @returns {Promise<{ publicKey: Uint8Array, sign(data: Uint8Array): Promise<Uint8Array> }>}
 */
export async function loadIdentity(file) {
  let text;
  try { text = await readFile(file, 'utf8'); } catch (e) {
    throw new McpBridgeError(`cannot read the identity file ${file}: ${e.code === 'ENOENT' ? 'no such file (make one with `wsh keygen`, or pass --identity)' : e.message}`, { code: 'identity' });
  }
  let key;
  try {
    const wsh = /-----BEGIN WSH PRIVATE KEY-----([\s\S]*?)-----END WSH PRIVATE KEY-----/.exec(text);
    if (wsh) {
      const seed = Buffer.from(wsh[1].replace(/\s+/g, ''), 'base64');
      if (seed.length !== 32) throw new Error('the secret is not 32 bytes');
      key = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
    } else if (/-----BEGIN PRIVATE KEY-----/.test(text)) {
      key = createPrivateKey(text);
    } else {
      throw new Error('not a WSH PRIVATE KEY or PKCS#8 PRIVATE KEY PEM');
    }
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('not an Ed25519 key');
  } catch (e) {
    throw new McpBridgeError(`cannot use the identity file ${file}: ${e.message}`, { code: 'identity' });
  }
  const jwk = createPublicKey(key).export({ format: 'jwk' });
  const publicKey = new Uint8Array(Buffer.from(jwk.x, 'base64url'));
  return { publicKey, sign: async (data) => new Uint8Array(nodeSign(null, data, key)) };
}

const sleep = (ms) => new Promise((resolve) => { const t = setTimeout(resolve, ms); t.unref?.(); });
const errorResponse = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

/**
 * Bridge `input` / `output` (newline-delimited JSON-RPC, as MCP stdio does) to the `mcp` channel of the host at `url`.
 * Resolves with the exit status once `input` ends (0) or the connection is lost for good (1); rejects with an `McpBridgeError`
 * (exit status 2) when it cannot start: no connection, a refused login, or a host with no such channel.
 *
 * @param {object} options
 * @param {string} options.url - `ws://`, `wss://` or `https://` URL of the host
 * @param {string} options.username
 * @param {{ publicKey: Uint8Array, sign(data: Uint8Array): Promise<Uint8Array> }} options.signer - see `loadIdentity`
 * @param {string} [options.channel='mcp'] - the rpc protocol to open
 * @param {string | Uint8Array} [options.expectHostKey] - pin the host key (hex fingerprint, raw key or `ssh-ed25519` line)
 * @param {boolean | 'auto'} [options.sealSession] - the client's `sealSession` (#155): `true` seals the whole session end to end and
 *   refuses a host that cannot (the `--sealed` flag); needs a key login. Omitted: the client's default (`'auto'`).
 * @param {false | { attempts?: number, delayMs?: number, maxDelayMs?: number }} [options.reconnect] - default 5 attempts from 500 ms, doubling
 * @param {number} [options.timeoutMs=15000] - to log in and to open the channel
 * @param {number} [options.maxLineBytes=8388608] - longest message accepted from the client
 * @param {number} [options.maxQueued=200] - messages held while reconnecting
 * @param {AsyncIterable<Uint8Array | string>} [options.input=process.stdin]
 * @param {{ write(chunk: string): unknown }} [options.output=process.stdout] - protocol only; nothing else is ever written here
 * @param {{ write(chunk: string): unknown }} [options.errorOutput=process.stderr]
 * @param {() => WshClient} [options.clientFactory]
 * @param {{ close(): Promise<void> } | null} [options.signalHandle] - set `close` to end the bridge from outside (a signal)
 * @returns {Promise<number>}
 */
export async function runMcpStdioBridge({
  url, username, signer, channel = 'mcp', expectHostKey, sealSession, reconnect, timeoutMs = 15_000, maxLineBytes = 8 * 1024 * 1024, maxQueued = 200,
  input = process.stdin, output = process.stdout, errorOutput = process.stderr, clientFactory = () => new WshClient(), signalHandle = null,
}) {
  if (typeof url !== 'string' || !url) throw new McpBridgeError('a host URL is required');
  if (!username) throw new McpBridgeError('a login name is required (--user)');
  if (!RPC_PROTOCOL_NAME_RE.test(channel)) throw new McpBridgeError(`${JSON.stringify(channel)} is not a valid channel name`);
  const policy = reconnect === false ? { attempts: 0 } : { attempts: 5, delayMs: 500, maxDelayMs: 10_000, ...(reconnect ?? {}) };
  const note = (line) => { try { errorOutput.write(`wsh-mcp: ${line}\n`); } catch { /* stderr gone */ } };
  const emit = (message) => { output.write(`${JSON.stringify(message)}\n`); };

  /** @type {{ client: WshClient, transport: ReturnType<typeof mcpClientTransport> } | null} */
  let current = null;
  let closing = false;
  let finished = false;
  let exitCode = 0;
  let resolveDone;
  const done = new Promise((resolve) => { resolveDone = resolve; });
  /** Ids of requests forwarded to the host and not answered yet. */
  const inflight = new Set();
  /** What the client sent to initialize, kept to replay on a new channel. */
  let initializeRequest = null;
  let initializedNotification = null;
  let replaySeq = 0;
  /** Messages from the client while the connection is being re-made. */
  const held = [];
  let reconnecting = false;
  let warnedUnpinned = false;

  async function open() {
    const client = clientFactory();
    try {
      await client.connect(url, { username, signer, timeout: timeoutMs, ...(expectHostKey ? { expectHostKey } : {}), ...(sealSession !== undefined ? { sealSession } : {}) });
    } catch (e) {
      throw new McpBridgeError(`cannot connect to ${url}: ${e?.message ?? e}`, { code: /Authentication failed|not authorized|host key/i.test(String(e?.message)) ? 'auth' : 'connect', cause: e });
    }
    try {
      if (!warnedUnpinned && client.hostKey?.status === 'unpinned') {
        warnedUnpinned = true;
        note(`the host key of ${url} is not pinned (${client.hostKey.fingerprint ?? 'none proven'}); pass --host-key to verify it`);
      }
      if (!client.hasFeature(rpcProtocolFeature(channel))) {
        const offered = client.serverFeatures.filter((f) => f.startsWith('rpc-protocol:')).map((f) => f.slice('rpc-protocol:'.length));
        throw new McpBridgeError(
          `the host at ${url} offers no "${channel}" channel${offered.length ? ` (it offers: ${offered.join(', ')})` : ' (it offers no rpc channels)'}. `
          + 'Serve one with createWshServer({ rpc: { mcp: mcpServerAdapter(server) } }) or createMemoryHost({ rpc: { mcp } }).',
          { code: 'no-channel' },
        );
      }
      let rpc;
      try { rpc = await client.openRpc(channel, { openTimeout: timeoutMs }); } catch (e) {
        throw new McpBridgeError(`the host at ${url} did not open the "${channel}" channel: ${e?.message ?? e}`, { code: 'no-channel', cause: e });
      }
      const transport = mcpClientTransport(rpc);
      transport.onmessage = (message) => fromHost(transport, message);
      transport.onclose = () => lost(transport);
      transport.onerror = (e) => note(`channel error: ${e?.message ?? e}`);
      client.onClose = () => lost(transport);
      await transport.start();
      return { client, transport };
    } catch (e) {
      await client.disconnect().catch(() => {});
      throw e;
    }
  }

  function fromHost(transport, message) {
    if (!current || current.transport !== transport) return;
    const isResponse = message && message.id !== undefined && message.id !== null && typeof message.method !== 'string';
    if (isResponse) inflight.delete(message.id);
    try { emit(message); } catch (e) { note(`cannot write to the client: ${e.message}`); }
  }

  /** The channel or the connection is gone. */
  function lost(transport) {
    if (finished || !current || current.transport !== transport) return;
    const { client } = current;
    current = null;
    client.disconnect().catch(() => {});
    if (closing) return;
    for (const id of inflight) emit(errorResponse(id, -32603, 'the connection to the wsh host was lost before this request was answered'));
    inflight.clear();
    void recover();
  }

  async function recover() {
    if (reconnecting) return;
    reconnecting = true;
    try {
      let delay = policy.delayMs ?? 500;
      for (let attempt = 1; attempt <= policy.attempts && !closing; attempt++) {
        note(`connection lost; reconnecting (attempt ${attempt} of ${policy.attempts})`);
        await sleep(delay);
        delay = Math.min(delay * 2, policy.maxDelayMs ?? 10_000);
        if (closing) return;
        let next;
        try {
          next = await open();
          await replayInitialization(next);
        } catch (e) {
          note(`reconnect failed: ${e?.message ?? e}`);
          if (next) await next.client.disconnect().catch(() => {});
          if (e instanceof McpBridgeError && (e.code === 'auth' || e.code === 'no-channel')) break;
          continue;
        }
        current = next;
        note('reconnected');
        for (const message of held.splice(0)) await forward(message);
        return;
      }
      if (closing) return;
      note(policy.attempts > 0 ? 'could not reconnect; giving up' : 'connection lost');
      for (const message of held.splice(0)) if (message.id !== undefined && message.id !== null && typeof message.method === 'string') emit(errorResponse(message.id, -32603, 'the wsh host is unreachable'));
      exitCode = 1;
      await finish();
    } finally {
      reconnecting = false;
    }
  }

  /** On a new channel the MCP server has not been initialized: do it again, as the client did, and keep the answer to ourselves. */
  async function replayInitialization(next) {
    if (!initializeRequest) return;
    const id = `wsh-mcp-replay-${++replaySeq}`;
    // `current` is not this channel yet: its answer is caught here and never reaches the client.
    const normal = next.transport.onmessage;
    const reply = new Promise((resolve) => {
      next.transport.onmessage = (message) => {
        if (message?.id === id && typeof message.method !== 'string') resolve(message);
        else normal(message);
      };
    });
    await next.transport.send({ ...initializeRequest, id });
    const message = await Promise.race([reply, sleep(timeoutMs).then(() => null)]);
    next.transport.onmessage = normal;
    if (!message || message.error) throw new McpBridgeError(`the host did not accept the replayed initialize: ${message?.error?.message ?? 'no answer'}`, { code: 'replay' });
    if (initializedNotification) await next.transport.send(initializedNotification);
  }

  async function forward(message) {
    const isRequest = typeof message.method === 'string' && message.id !== undefined && message.id !== null;
    if (isRequest) inflight.add(message.id);
    try {
      await current.transport.send(message);
    } catch (e) {
      if (isRequest) { inflight.delete(message.id); emit(errorResponse(message.id, -32603, `wsh: ${e?.message ?? e}`)); }
      else note(`could not send ${message.method ?? 'a response'}: ${e?.message ?? e}`);
    }
  }

  async function fromClient(line) {
    let message;
    try { message = JSON.parse(line); } catch { emit(errorResponse(null, -32700, 'Parse error')); return; }
    if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0') {
      emit(errorResponse(message?.id ?? null, -32600, 'Invalid Request: expected one JSON-RPC 2.0 message per line'));
      return;
    }
    if (message.method === 'initialize' && message.id !== undefined) initializeRequest = message;
    else if (message.method === 'notifications/initialized') initializedNotification = message;
    if (!current) {
      if (held.length >= maxQueued) {
        if (message.id !== undefined && message.id !== null && typeof message.method === 'string') emit(errorResponse(message.id, -32603, 'too many messages while reconnecting'));
        return;
      }
      held.push(message);
      return;
    }
    await forward(message);
  }

  async function finish() {
    if (finished) return;
    finished = true;
    closing = true;
    const c = current;
    current = null;
    if (c) { await c.transport.close().catch(() => {}); await c.client.disconnect().catch(() => {}); }
    resolveDone(exitCode);
  }

  if (signalHandle) signalHandle.close = finish;

  current = await open(); // a failure to start is the caller's (exit status 2)

  // Read the client's side: lines, in order, bounded.
  (async () => {
    let buf = '';
    let skipping = false;
    let chain = Promise.resolve();
    const decoder = new TextDecoder();
    const push = (line) => { chain = chain.then(() => fromClient(line)).catch((e) => note(`internal error: ${e?.message ?? e}`)); };
    try {
      for await (const chunk of input) {
        buf += typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true });
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl).replace(/\r$/, '');
          buf = buf.slice(nl + 1);
          if (skipping) { skipping = false; continue; }
          if (line.length > maxLineBytes) { emit(errorResponse(null, -32600, `message too large (more than ${maxLineBytes} bytes)`)); continue; }
          if (line.trim()) push(line);
        }
        if (buf.length > maxLineBytes) {
          emit(errorResponse(null, -32600, `message too large (more than ${maxLineBytes} bytes)`));
          buf = '';
          skipping = true;
        }
      }
      if (buf.trim() && !skipping) push(buf);
    } catch (e) { note(`cannot read the client: ${e?.message ?? e}`); }
    await chain;
    await finish();
  })();

  return done;
}
