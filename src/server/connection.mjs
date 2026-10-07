/**
 * One wsh-v1 server connection, written against a byte pipe so it knows
 * nothing about WebSocket: `attach({ send })` returns `{ receive, close }`.
 * Speaks the same QMux-over-WebSocket framing the stock client's
 * `WebSocketTransport` does.
 *
 * Exec data plane: exec sessions use `data_mode: 'stream'` -- output flows on
 * the second, client-opened QMux stream. The client's transport announces that
 * stream the moment it opens it (an empty STREAM frame), so the host sees it
 * with no help; the host advertises `stream-announce` in ServerHello so the
 * client knows not to write a primer byte. A client that does write one anyway
 * (hosts that predate the announce required it) has the lone leading `0x00`
 * dropped rather than forwarded to the process's stdin.
 */

import { randomUUID } from 'node:crypto';
import { QMuxConnection } from '../qmux-connection.mjs';
import { FrameDecoder, frameEncode } from '../cbor.mjs';
import {
  MSG, serverHello, challenge, authOk, authFail, openOk, openFail, sessionData,
  exit as exitMsg, close as closeMsg, pong, fileResult, fileChunk, mcpTools, mcpResult,
  presence as presenceMsg, error as errorMsg, sessionList, detachOk, detachFail, reversePeers, reverseReject,
} from '../messages.gen.mjs';
import {
  generateNonce, verifyChallenge, fingerprint, importPublicKeyRaw,
} from '../auth.mjs';
import { FILE_CHUNK_BYTES } from './fs.mjs';
import { MAX_ATTACHMENTS } from './sessions.mjs';
import { MCP_CALL_ID_FEATURE } from '../client.mjs';
import { RpcChannel, RPC_FEATURE, RPC_MAX_MESSAGE_PREFIX, rpcProtocolFeature } from '../rpc.mjs';
import { HOST_KEY_PREFIX, HOST_KEY_SIG_PREFIX, findClientNonce, hostKeyProofMessage, toHex } from '../host-key.mjs';

export const STREAM_ANNOUNCE = 'stream-announce';

/**
 * The features a host built from `cfg` advertises (`ServerHello.features`, minus the host-key proof).
 * Over a relay bridge (`dataStreams: false`) there are no client-opened streams, so the
 * stream-based ones (`stream-announce`, `rpc`) are not offered; a reverse host reports this
 * list to the operator in `ReverseAccept.features`.
 */
export function hostFeatures(cfg, { dataStreams = true } = {}) {
  const features = dataStreams ? [STREAM_ANNOUNCE] : [];
  if (cfg.mcp) features.push(MCP_CALL_ID_FEATURE);
  if (cfg.files) features.push('file-transfer', 'file-write', 'file-rename');
  if (cfg.rpc && dataStreams && cfg.rpc.protocols.size) {
    features.push(RPC_FEATURE, ...[...cfg.rpc.protocols.keys()].map(rpcProtocolFeature), RPC_MAX_MESSAGE_PREFIX + cfg.rpc.maxMessageBytes);
  }
  return features;
}
const MAX_PENDING_WRITES = 8;
const MAX_RENAME_PATH_BYTES = 4096;
const WRITE_IDLE_MS = 30_000;

const MAX_CHANNELS = 64;
const REPLAY_CHUNK_BYTES = 32 * 1024;
const USERNAME_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const enc = new TextEncoder();

const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
const toBytes = (d) => (typeof d === 'string' ? enc.encode(d) : d);

/**
 * @param {object} cfg
 * @param {(who: object) => Promise<boolean>} cfg.authorize
 * @param {Function | null} cfg.execRunner
 * @param {object} cfg.execOptions
 * @param {object | null} cfg.pty - normalized (see pty.mjs)
 * @param {object | null} cfg.files - from createFileAccess
 * @param {{ pubkey: boolean, password: Function | null }} cfg.methods - which auth methods are on
 * @param {object | null} cfg.hostKey - from loadHostKey
 * @param {object | null} cfg.mcp - from createMcpHost
 * @param {{ protocols: Map<string, Function>, maxMessageBytes: number, maxInflight: number } | null} cfg.rpc - from createRpcHost
 * @param {object | null} cfg.relay - a RelayHub (see relay.mjs); null = not a relay
 * @param {object | null} cfg.sessions - a SessionRegistry (see sessions.mjs); null = sessions die with their connection
 * @param {{ limiter: object, key: Function, failureDelayMs: number } | null} cfg.rateLimit - password throttle
 * @param {number} cfg.bindTimeoutMs - how long exec output waits for the data stream
 * @param {(line: string) => void} cfg.log
 */
export function createConnectionFactory(cfg) {
  let counter = 0;

  /**
   * Attach one connection. Two shapes:
   *  - bytes (the normal one): `{ send(bytes), remote, closeTransport() }` -> `{ receive(bytes), close() }`, speaking QMux.
   *  - messages: `{ sendMessage(msg), authenticated, dataStreams }` -> `{ receiveMessage(msg), bindStream(s), close() }`,
   *    for a transport that already frames messages itself (a relay bridge, WebTransport). `authenticated`
   *    (`{ username, fingerprint }`) skips the handshake for a peer something else has already authenticated;
   *    `dataStreams: false` means there are no client-opened streams to bind, so exec output rides SessionData.
   */
  return function attach({ send: sendBytes, sendMessage = null, remote = {}, authenticated = null, dataStreams = true, closeTransport = null }) {
    const cid = ++counter;
    const log = (m) => cfg.log(`[conn ${cid}] ${m}`);
    const state = {
      sessionId: randomUUID(), nonce: null, username: authenticated?.username ?? null, authed: !!authenticated,
      closed: false, nextChannel: 0, fingerprint: authenticated?.fingerprint ?? null,
    };
    /** @type {Map<number, any>} */
    const channels = new Map();
    /** FileOp `write`/`rename`s awaiting their FileChunk frames, by client-chosen channel id. */
    const fileWrites = new Map();
    /** AbortControllers of in-flight MCP calls: aborted on disconnect, counted for the cap. */
    const mcpCalls = new Set();
    /** Channel ids awaiting their client-opened data stream, in OpenOk order. */
    const pendingStreams = [];
    const decoder = new FrameDecoder();
    const pendingSends = [];
    let control = null;
    let chain = Promise.resolve();
    /** This connection as the relay hub sees it (created on first need). */
    let relayHandle = null;

    const qmux = sendMessage ? null : new QMuxConnection({ isClient: false, send: (b) => { if (!state.closed) sendBytes(b); } });

    const send = (msg) => {
      if (state.closed) return Promise.resolve();
      if (sendMessage) {
        try { return Promise.resolve(sendMessage(msg)).catch(() => {}); } catch { return Promise.resolve(); }
      }
      const bytes = frameEncode(msg);
      if (control) return control.write(bytes).catch(() => {});
      pendingSends.push(bytes);
      return Promise.resolve();
    };

    function shutdown(why) {
      if (state.closed) return;
      state.closed = true;
      // A hosted session survives its connection (it is detached, then expires or is resumed);
      // everything else dies with it.
      for (const ch of [...channels.values()]) (ch.detach ?? ch.kill)?.call(ch);
      channels.clear();
      for (const c of mcpCalls) c.abort(new Error('connection closed'));
      mcpCalls.clear();
      for (const w of fileWrites.values()) clearTimeout(w.timer);
      fileWrites.clear();
      try { qmux?.destroy(new Error(why)); } catch { /* already gone */ }
      // The host ending the connection (a relay bridge ending, a refused login) must end the socket too.
      try { closeTransport?.(); } catch { /* already gone */ }
      relayHandle && cfg.relay?.drop(relayHandle);
      log(`closed (${why})`);
    }

    // A transport that closes right behind a message (a client's `disconnect()` sends Close for
    // every channel and then goes) must not make the host forget that message: it is processed
    // first, then the connection is torn down.
    const shutdownAfterQueue = (why) => { chain = chain.then(() => shutdown(why)); };

    if (qmux) {
    qmux.onError = (e) => log(`qmux error: ${e.message}`);
    qmux.onClose = () => shutdownAfterQueue('peer sent CONNECTION_CLOSE');
    qmux.onStreamOpen = (s) => {
      if (s.id !== 0) { bindDataStream(s); return; }
      control = s;
      s.onData = (d) => {
        let msgs;
        try { msgs = decoder.feed(d); } catch (e) { log(`frame decode error: ${e.message}`); return; }
        for (const m of msgs) chain = chain.then(() => handle(m)).catch((e) => log(`handler error: ${e.message}`));
      };
      s.onEnd = () => shutdownAfterQueue('control stream FIN');
      s.onReset = () => shutdownAfterQueue('control stream reset');
      for (const b of pendingSends.splice(0)) s.write(b).catch(() => {});
    };
    qmux.sendHandshake();
    }

    function bindDataStream(s) {
      const channelId = pendingStreams.shift();
      const ch = channelId !== undefined ? channels.get(channelId) : undefined;
      if (!ch?.bind) { s.close().catch(() => {}); return; }
      ch.bind(s);
    }

    // ── Auth ──────────────────────────────────────────────────────────

    async function handle(m) {
      if (state.closed) return;
      if (!state.authed) return handleAuth(m);
      if (await handleRelay(m)) return;
      switch (m.type) {
        case MSG.PING: return send(pong({ id: m.id }));
        case MSG.OPEN: return handleOpen(m);
        case MSG.SESSION_DATA: channels.get(m.channel_id)?.input?.(m.data); return;
        case MSG.RESIZE: channels.get(m.channel_id)?.resize?.(m.cols, m.rows); return;
        case MSG.SIGNAL: channels.get(m.channel_id)?.signal?.(String(m.signal ?? '')); return;
        case MSG.CLOSE: { const ch = channels.get(m.channel_id); if (ch) { ch.kill?.(); } return; }
        case MSG.FILE_OP: return handleFileOp(m);
        case MSG.FILE_CHUNK: return (fileWrites.has(m.channel_id) ? handleWriteChunk(m) : channels.get(m.channel_id)?.chunk?.(m));
        case MSG.ATTACH: return handleAttach(m, false);
        case MSG.RESUME: return handleAttach(m, true);
        case MSG.DETACH: return handleDetach(m);
        case MSG.SESSION_LIST_REQUEST: return handleSessionList();
        case MSG.MCP_DISCOVER: return handleMcpDiscover();
        // Not awaited: the handler chain is serial, and a slow tool must not hold up
        // the next call (or a Close) behind it.
        case MSG.MCP_CALL: handleMcpCall(m); return;
        default: log(`ignored message type 0x${m.type.toString(16)}`);
      }
    }

    async function refuse(reason) {
      log(`AUTH_FAIL: ${reason}`);
      await send(authFail({ reason }));
      setTimeout(() => shutdown('auth failed'), 50);
    }

    async function handleAuth(m) {
      if (m.type === MSG.HELLO) {
        const user = String(m.username ?? '');
        if (!USERNAME_RE.test(user)) return refuse(`bad username ${JSON.stringify(user)}`);
        const method = m.auth_method || 'pubkey';
        if (method === 'password') {
          if (!cfg.methods.password) return refuse('password auth is not enabled on this host');
        } else if (method === 'pubkey') {
          if (!cfg.methods.pubkey) return refuse('pubkey auth is not enabled on this host');
        } else {
          return refuse(`unsupported auth method ${JSON.stringify(method)}`);
        }
        state.username = user;
        state.method = method;
        const features = hostFeatures(cfg, { dataStreams });
        let hostFingerprint;
        if (cfg.hostKey) {
          hostFingerprint = cfg.hostKey.fingerprint;
          const clientNonce = findClientNonce(m.features);
          if (clientNonce) {
            const sig = await cfg.hostKey.sign(hostKeyProofMessage({ sessionId: state.sessionId, clientNonce, username: user }));
            features.push(HOST_KEY_PREFIX + toHex(cfg.hostKey.publicKey), HOST_KEY_SIG_PREFIX + toHex(sig));
          }
        }
        state.features = features;
        state.hostFingerprint = hostFingerprint ?? null;
        await send(serverHello({ sessionId: state.sessionId, features, hostFingerprint }));
        if (method === 'pubkey') {
          state.nonce = generateNonce();
          await send(challenge({ nonce: state.nonce, sessionId: state.sessionId }));
        } else {
          state.awaitingPassword = true;
        }
        return;
      }
      if (m.type === MSG.AUTH && state.awaitingPassword) return handlePasswordAuth(m);
      if (m.type === MSG.AUTH) {
        if (!state.nonce) return;
        if (m.method !== 'pubkey' || !(m.public_key instanceof Uint8Array) || !(m.signature instanceof Uint8Array)) {
          return refuse('expected a pubkey AUTH with public_key and signature');
        }
        let fp;
        let key;
        try {
          fp = await fingerprint(m.public_key);
          key = await importPublicKeyRaw(m.public_key);
        } catch { return refuse('malformed public key'); }
        // Verify the signature first: nothing about who is on the allowlist
        // is revealed to a caller who cannot even prove they hold a key.
        let ok = false;
        try {
          ok = await verifyChallenge(key, m.signature, state.sessionId, state.nonce, { username: state.username });
        } catch { ok = false; }
        if (!ok) return refuse('signature does not verify over the transcript');
        let allowed = false;
        try {
          allowed = await cfg.authorize({ username: state.username, fingerprint: fp, publicKey: m.public_key });
        } catch (e) { log(`authorize threw: ${e.message}`); }
        if (!allowed) return refuse('key not authorized');
        state.authed = true;
        state.fingerprint = fp;
        state.nonce = null;
        await send(authOk({ sessionId: state.sessionId, token: randomBytes(16), ttl: 3600 }));
        log(`authenticated ${state.username} (${fp.slice(0, 12)}...)`);
      }
    }

    async function handlePasswordAuth(m) {
      state.awaitingPassword = false; // one guess per connection
      if (m.method !== 'password' || typeof m.password !== 'string') return refuse('expected a password AUTH');
      const rl = cfg.rateLimit;
      const key = rl.key({ address: remote.address, headers: remote.headers, username: state.username });
      const locked = rl.limiter.lockedFor(key);
      if (locked > 0) {
        // Not even evaluated: a locked-out caller learns nothing and costs nothing.
        return refuse(`too many failed attempts; try again in ${Math.ceil(locked / 1000)}s`);
      }
      let ok = false;
      try { ok = (await cfg.methods.password(state.username, m.password)) === true; } catch (e) { log(`password check threw: ${e.message}`); }
      if (!ok) {
        rl.limiter.fail(key);
        if (rl.failureDelayMs > 0) await new Promise((r) => setTimeout(r, rl.failureDelayMs));
        return refuse('authentication failed');
      }
      rl.limiter.succeed(key);
      state.authed = true;
      await send(authOk({ sessionId: state.sessionId, token: randomBytes(16), ttl: 3600 }));
      log(`authenticated ${state.username} (password)`);
    }

    // ── Relay (createWshServer({ relay })) ────────────────────────────

    const RELAY_TYPES = new Set([MSG.REVERSE_REGISTER, MSG.REVERSE_LIST, MSG.REVERSE_CONNECT, MSG.REVERSE_ACCEPT, MSG.REVERSE_REJECT, MSG.RELAY_FORWARD]);

    function hubHandle() {
      relayHandle ??= {
        send, fingerprint: state.fingerprint, username: state.username,
        close: () => shutdownAfterQueue('relay bridge ended'),
      };
      return relayHandle;
    }

    /** @returns {Promise<boolean>} true when the message was the relay's and has been dealt with */
    async function handleRelay(m) {
      const hub = cfg.relay;
      if (!hub) {
        // Not a relay: answer instead of leaving the client to time out.
        if (m.type === MSG.REVERSE_LIST) { await send(reversePeers({ peers: [] })); return true; }
        if (m.type === MSG.REVERSE_CONNECT) { await send(reverseReject({ targetFingerprint: String(m.target_fingerprint ?? ''), username: '', reason: 'relay is not enabled on this server' })); return true; }
        if (m.type === MSG.REVERSE_REGISTER) { await send(errorMsg({ code: 3, message: 'relay is not enabled on this server' })); return true; }
        return false;
      }
      if (!RELAY_TYPES.has(m.type)) {
        // Anything else a bridged connection sends that may cross a bridge, does.
        if (!relayHandle) return false;
        hub.touch(relayHandle);
        return hub.forward(relayHandle, m);
      }
      // Relay roles are keyed by an authenticated key: from_fingerprint means nothing for a password login.
      if (!state.fingerprint) {
        await send(errorMsg({ code: 2, message: 'relay operations need a key login' }));
        return true;
      }
      const h = hubHandle();
      switch (m.type) {
        case MSG.REVERSE_REGISTER: {
          const reason = await hub.register(h, m, { username: state.username, fingerprint: state.fingerprint });
          if (reason) {
            log(`ReverseRegister refused: ${reason}`);
            await send(errorMsg({ code: 2, message: `registration refused: ${reason}` }));
          }
          return true;
        }
        case MSG.REVERSE_LIST: await send(await hub.list({ username: state.username, fingerprint: state.fingerprint })); return true;
        case MSG.REVERSE_CONNECT: await hub.connect(h, m); return true;
        case MSG.REVERSE_ACCEPT: case MSG.REVERSE_REJECT: hub.answer(h, m); return true;
        default: hub.forward(h, m); return true; // a RelayForward the client wrote itself
      }
    }

    // ── MCP ───────────────────────────────────────────────────────────

    const principal = () => ({ username: state.username, fingerprint: state.fingerprint });

    async function handleMcpDiscover() {
      let tools = [];
      if (cfg.mcp) {
        try { tools = await cfg.mcp.list(state.username, principal()); } catch (e) { log(`mcp discover failed: ${e.message}`); }
      }
      return send(mcpTools({ tools }));
    }

    function handleMcpCall(m) {
      const callId = typeof m.call_id === 'string' ? m.call_id : undefined;
      const reply = (result) => {
        try { return send(mcpResult({ result, callId })); } catch (e) {
          log(`mcp result for ${m.tool} not encodable: ${e.message}`);
          return send(mcpResult({ result: { success: false, error: 'tool result could not be encoded' }, callId }));
        }
      };
      const fail = (error) => reply({ success: false, error });
      if (!cfg.mcp) { fail('mcp is not enabled on this server'); return; }
      if (mcpCalls.size >= cfg.mcp.maxConcurrent) { fail('too many concurrent MCP calls'); return; }

      const abort = new AbortController();
      mcpCalls.add(abort);
      (async () => {
        const name = typeof m.tool === 'string' ? m.tool : '';
        const tool = name ? await cfg.mcp.find(name, state.username, principal()) : null;
        if (!tool) return fail(`unknown tool: ${name || String(m.tool)}`);
        const args = m.arguments ?? {};
        const problem = cfg.mcp.validate(tool, args);
        if (problem) return fail(`invalid arguments: ${problem}`);

        let timer = null;
        const aborted = new Promise((_, reject) => {
          abort.signal.addEventListener('abort', () => reject(abort.signal.reason ?? new Error('aborted')), { once: true });
        });
        aborted.catch(() => {});
        if (cfg.mcp.timeoutMs > 0) {
          timer = setTimeout(() => abort.abort(new Error(`tool ${name} timed out after ${cfg.mcp.timeoutMs}ms`)), cfg.mcp.timeoutMs);
        }
        try {
          const ctx = { user: state.username, fingerprint: state.fingerprint, signal: abort.signal };
          const out = await Promise.race([Promise.resolve().then(() => tool.call(args, ctx)), aborted]);
          return reply(out === undefined ? null : out);
        } catch (e) {
          if (!state.closed) log(`mcp tool ${name} failed: ${e?.message ?? e}`);
          return fail(String(e?.message ?? e));
        } finally {
          clearTimeout(timer);
        }
      })()
        .catch((e) => log(`mcp call ${m.tool}: ${e.message}`))
        .finally(() => mcpCalls.delete(abort));
    }

    // ── Open ──────────────────────────────────────────────────────────

    function handleOpen(m) {
      if (channels.size >= MAX_CHANNELS) return send(openFail({ reason: 'too many open channels' }));
      switch (m.kind) {
        case 'exec': return openExec(m);
        case 'pty': return openPty(m);
        case 'file': return openFile(m);
        case 'rpc': return openRpc(m);
        default: return send(openFail({ reason: `kind "${m.kind}" is not supported by this server` }));
      }
    }

    function finishChannel(channelId, code) {
      if (!channels.has(channelId) || state.closed) return Promise.resolve();
      channels.delete(channelId);
      return send(exitMsg({ channelId, code })).then(() => send(closeMsg({ channelId })));
    }

    // ── Hosted sessions (createWshServer({ sessions })) ───────────────

    /** Who this connection authenticated as: its key, or its username for a password login. */
    const principalKey = () => state.fingerprint ?? `password:${state.username}`;
    const ownerRecord = () => ({ username: state.username, fingerprint: state.fingerprint, principal: principalKey() });

    /**
     * This connection's message-backed attachment to a hosted session: output, Presence and the
     * final Exit/Close all go through one ordered chain, so a replay is never overtaken by live output.
     */
    function virtualAttachment(hosted, channelId, mode) {
      let out = Promise.resolve();
      const enqueue = (fn) => { out = out.then(fn).catch(() => {}); return out; };
      return {
        connId: cid, channelId, mode, username: state.username, principal: principalKey(),
        write: (bytes) => enqueue(() => send(sessionData({ channelId, data: bytes }))),
        notify: (msg) => enqueue(() => send(presenceMsg(msg))),
        exit: (code) => enqueue(async () => {
          channels.delete(channelId);
          await send(exitMsg({ channelId, code }));
          await send(closeMsg({ channelId }));
        }),
        flush: () => out,
      };
    }

    /** The `channels` entry for a virtual attachment (an Attach/Resume, or a pty's own channel). */
    function attachedChannel(hosted, att) {
      const control = () => att.mode === 'control';
      const ch = {
        session: hosted, attachment: att,
        input: (d) => { if (control()) hosted.handlers.input?.(d); },
        resize: (c, r) => { if (control()) hosted.handlers.resize?.(c, r); },
        signal: (name) => { if (control()) hosted.handlers.signal?.(name); },
        // The client closed the channel: the session's owner ends it, anyone else just leaves it.
        kill: () => {
          if (att.principal === hosted.owner.principal && control()) hosted.kill();
          else ch.detach();
        },
        detach: () => { channels.delete(att.channelId); hosted.detach(att); },
      };
      channels.set(att.channelId, ch);
      return ch;
    }

    async function handleAttach(m, isResume) {
      const reg = cfg.sessions;
      const fail = (code, message) => send(errorMsg({ code, message }));
      if (!reg) return fail(3, `${isResume ? 'resume' : 'attach'} is not enabled on this server (no "sessions" option)`);
      const s = reg.get(m.session_id);
      const mine = !!s && s.owner.principal === principalKey();
      const tokenOk = !!s && m.token !== undefined && reg.checkToken(s, m.token);
      // Attach: the token OR ownership. Resume: the token AND ownership (the credentialed connection coming back).
      if (!s || !(isResume ? tokenOk && mine : tokenOk || mine)) {
        log(`${isResume ? 'resume' : 'attach'} refused for ${String(m.session_id).slice(0, 8)}`);
        return fail(2, 'unknown session or not authorized');
      }
      if ([...channels.values()].some((c) => c.session === s)) return fail(3, 'already attached to this session on this connection');
      if (s.attachments.size >= MAX_ATTACHMENTS) return fail(3, 'too many attachments to this session');
      if (channels.size >= MAX_CHANNELS) return fail(3, 'too many open channels');

      let from = s.ring.start;
      if (isResume) {
        const last = m.last_seq;
        if (!Number.isSafeInteger(last) || last < 0) return fail(3, 'last_seq must be a non-negative integer');
        if (last > s.ring.end) return fail(4, `last_seq ${last} is ahead of the session (it has produced ${s.ring.end} bytes)`);
        if (last < s.ring.start) {
          return fail(4, `output gap: this session's retained output starts at seq ${s.ring.start} but last_seq is ${last}; attach for the retained output instead`);
        }
        from = last;
      }
      const mode = !isResume && /^(readonly|read|view|ro)$/i.test(String(m.mode ?? '')) ? 'readonly' : 'control';
      const channelId = ++state.nextChannel;
      const att = virtualAttachment(s, channelId, mode);
      attachedChannel(s, att);

      // Reply, replay, then (if the process is already over) its exit -- all before any live output,
      // which only reaches `att` once `s.attach(att)` registers it, after these are queued.
      const self = { session_id: s.id, mode, username: state.username, channel_id: channelId, seq: from };
      att.notify({ attachments: [self, ...s.roster()] });
      const replay = s.ring.read(from);
      for (let off = 0; off < replay.byteLength; off += REPLAY_CHUNK_BYTES) att.write(replay.subarray(off, off + REPLAY_CHUNK_BYTES));
      if (s.state === 'exited') att.exit(s.exitCode ?? 0);
      else s.attach(att);
      log(`${isResume ? 'resumed' : `attached (${mode})`} session ${s.id.slice(0, 8)} on channel ${channelId} from seq ${from}`);
    }

    async function handleDetach(m) {
      const s = cfg.sessions?.get(m.session_id);
      const entry = s && [...channels.entries()].find(([, c]) => c.session === s);
      if (!entry) return send(detachFail({ reason: 'not attached to this session on this connection' }));
      const [channelId, ch] = entry;
      const flushed = ch.attachment.flush();
      ch.detach();
      await flushed;
      await send(closeMsg({ channelId }));
      return send(detachOk({ sessionId: s.id }));
    }

    function handleSessionList() {
      const now = Date.now();
      const sessions = (cfg.sessions?.listFor(principalKey()) ?? []).map((s) => ({
        session_id: s.id,
        username: s.owner.username,
        fingerprint_short: (s.owner.fingerprint ?? '').slice(0, 8),
        created_at_secs: Math.floor(s.createdAt / 1000),
        idle_secs: Math.max(0, Math.floor((now - s.lastActivity) / 1000)),
        attached_count: s.attachments.size,
      }));
      return send(sessionList({ sessions }));
    }

    async function openExec(m) {
      if (!cfg.execRunner) return send(openFail({ reason: 'exec is not enabled on this server' }));
      const command = String(m.command ?? '').trim();
      if (!command) return send(openFail({ reason: 'command is required for kind "exec"' }));

      const channelId = ++state.nextChannel;
      const abort = new AbortController();
      const hosted = cfg.sessions ? cfg.sessions.create({ owner: ownerRecord(), kind: 'exec', command }) : null;
      let stream = null;
      let primerChecked = false;
      let wq = Promise.resolve();
      const buffered = [];
      const boundWaiters = [];
      const inputCbs = [];
      const endCbs = [];
      const signalCbs = [];

      const signalTo = (name) => {
        const n = name.replace(/^SIG/, '').toUpperCase();
        for (const cb of signalCbs) cb(n);
        if (/^(INT|TERM|KILL|HUP)$/.test(n) && signalCbs.length === 0) abort.abort();
      };
      const ch = {
        kill: () => abort.abort(),
        signal: signalTo,
        bind(s) {
          stream = s;
          s.onData = (d) => {
            // A client that primes (see header) sends one lone 0x00 first.
            if (!primerChecked) {
              primerChecked = true;
              if (d.byteLength === 1 && d[0] === 0) return;
            }
            if (d.byteLength) for (const cb of inputCbs) cb(d);
          };
          s.onEnd = () => { for (const cb of endCbs) cb(); };
          // A hosted session outlives its stream; an unhosted one dies with it.
          s.onReset = () => { if (!hosted) abort.abort(); };
          const pending = buffered.splice(0);
          wq = wq.then(async () => { for (const b of pending) await s.write(b).catch(() => {}); });
          for (const r of boundWaiters.splice(0)) r();
        },
      };
      channels.set(channelId, ch);
      if (dataStreams) pendingStreams.push(channelId);
      // No client-opened streams on this connection (a relay bridge): stdin arrives as SessionData.
      else ch.input = (d) => { for (const cb of inputCbs) cb(d); };

      let timer = null;
      if (cfg.execOptions.timeoutMs > 0) timer = setTimeout(() => abort.abort(), cfg.execOptions.timeoutMs);

      // Output to the opening connection's data stream (held until the client has opened it).
      const toStream = (bytes) => {
        if (!dataStreams) {
          wq = wq.then(() => send(sessionData({ channelId, data: bytes })));
          return wq;
        }
        if (!stream) { buffered.push(bytes); return Promise.resolve(); }
        const s = stream;
        wq = wq.then(() => s.write(bytes).catch(() => {}));
        return wq;
      };
      // Output is ready but the client's stream may not have been bound yet (a host without
      // announce support waits for the first byte): give it a bounded chance rather than
      // dropping the output or hanging forever.
      const closeStream = async (code) => {
        if (dataStreams && !stream) await Promise.race([new Promise((r) => boundWaiters.push(r)), new Promise((r) => setTimeout(r, cfg.bindTimeoutMs))]);
        if (dataStreams && !stream) log(`exec channel ${channelId}: data stream never appeared; output dropped`);
        await wq;
        try { await stream?.close(); } catch { /* peer gone */ }
        await finishChannel(channelId, Number.isInteger(code) ? code : 0);
      };

      if (hosted) {
        const att = {
          connId: cid, channelId, mode: 'control', username: state.username, principal: principalKey(),
          write: toStream,
          notify: (msg) => send(presenceMsg(msg)),
          exit: (code) => closeStream(code),
          flush: () => wq,
        };
        hosted.handlers = {
          input: (d) => { for (const cb of inputCbs) cb(d); },
          inputEnd: () => { for (const cb of endCbs) cb(); },
          signal: signalTo,
          resize: () => {},
          kill: () => abort.abort(),
        };
        ch.session = hosted;
        ch.attachment = att;
        ch.detach = () => {
          channels.delete(channelId);
          hosted.detach(att);
          try { stream?.close().catch(() => {}); } catch { /* gone */ }
        };
        hosted.attach(att);
      }

      const io = {
        user: state.username,
        env: m.env && typeof m.env === 'object' && cfg.execOptions.clientEnv !== false ? m.env : {},
        cols: m.cols || 80,
        rows: m.rows || 24,
        signal: abort.signal,
        write(data) {
          const bytes = toBytes(data);
          if (!hosted) return toStream(bytes);
          hosted.push(bytes);
          return wq;
        },
        onInput: (cb) => inputCbs.push(cb),
        onInputEnd: (cb) => endCbs.push(cb),
        onSignal: (cb) => signalCbs.push(cb),
      };

      await send(openOk({
        channelId, dataMode: dataStreams ? 'stream' : 'virtual', capabilities: ['signal'],
        sessionId: hosted?.id ?? randomUUID(), token: hosted?.token ?? randomBytes(16),
      }));
      log(`exec channel ${channelId}: ${command}`);

      // Detached: the message chain must stay free to deliver this
      // session's Signal/Close/SessionData while the command runs.
      runExec().catch((e) => log(`exec channel ${channelId}: ${e.message}`));

      async function runExec() {
        let code;
        try { code = await cfg.execRunner(command, io); } catch (e) {
          await io.write(`wsh: ${e.message}\n`);
          code = 1;
        }
        if (timer) clearTimeout(timer);
        // Hosted: everyone attached (this connection's stream included, if it is still there) hears the exit.
        if (hosted) { hosted.finish(Number.isInteger(code) ? code : 0); return; }
        await closeStream(code);
      }
    }

    // A typed RPC channel (wsh #85): `Open { kind: 'rpc', command: <protocol> }` is answered like an exec channel's -- OpenOk,
    // then the client's data stream binds in OpenOk order -- but the stream carries a CBOR sequence of JSON-RPC messages
    // handled by the protocol's handler, not process I/O.
    async function openRpc(m) {
      const rpc = cfg.rpc;
      const protocol = typeof m.command === 'string' ? m.command : '';
      const handler = rpc?.protocols.get(protocol);
      if (!rpc || !dataStreams || !handler) {
        const why = !rpc || !dataStreams ? 'rpc is not enabled on this server' : `protocol "${protocol}" is not supported by this server`;
        return send(openFail({ reason: `UNSUPPORTED_PROTOCOL: ${why}` }));
      }
      const channelId = ++state.nextChannel;
      let chan = null;
      let stream = null;
      const ch = {
        // The peer closed the channel (or the connection is going away).
        kill: () => {
          channels.delete(channelId);
          chan?.handleClose('peer-closed');
          try { stream?.close().catch(() => {}); } catch { /* gone */ }
        },
        bind(s) {
          stream = s;
          chan = new RpcChannel({
            maxMessageBytes: rpc.maxMessageBytes,
            maxInflight: rpc.maxInflight,
            write: (bytes) => s.write(bytes),
            // The host ended it: close our end of the stream, then tell the client the channel is over.
            close: async () => { try { await s.close(); } catch { /* peer gone */ } await finishChannel(channelId, 0); },
          });
          s.onData = (d) => chan.feed(d);
          s.onEnd = () => { void chan.close('stream-end'); };
          s.onReset = () => chan.handleClose('stream-reset');
          const ctx = {
            protocol, channelId, user: state.username, fingerprint: state.fingerprint, remote,
            features: state.features ?? [], hostFingerprint: state.hostFingerprint,
            log: (line) => log(`rpc ${protocol} channel ${channelId}: ${line}`),
          };
          // Inbound messages wait until the handler (possibly async) has registered its methods.
          chan.hold();
          let ready;
          try { ready = Promise.resolve(handler(chan, ctx)); } catch (e) { ready = Promise.reject(e); }
          ready.then(() => chan.release(), (e) => {
            log(`rpc ${protocol} channel ${channelId}: handler failed: ${e?.message ?? e}`);
            void chan.close('handler-error');
          });
        },
      };
      channels.set(channelId, ch);
      pendingStreams.push(channelId);
      await send(openOk({ channelId, dataMode: 'stream', capabilities: [] }));
      log(`rpc channel ${channelId}: ${protocol}`);
    }

    async function openPty(m) {
      if (!cfg.pty) return send(openFail({ reason: 'pty is not enabled on this server' }));
      const channelId = ++state.nextChannel;
      const cols = m.cols || 80;
      const rows = m.rows || 24;
      const p = cfg.pty;
      let proc;
      try {
        const args = m.command ? ['-c', String(m.command)] : [];
        proc = p.spawn(p.shell, args, {
          name: p.term, cols, rows, cwd: p.cwd,
          env: { ...(p.env ?? process.env), TERM: p.term, ...(m.env && typeof m.env === 'object' ? m.env : {}) },
        });
      } catch (e) {
        return send(openFail({ reason: `pty spawn failed: ${e.message}` }));
      }
      const ctl = {
        input: (data) => { try { proc.write(Buffer.from(data)); } catch { /* exited */ } },
        resize: (c, r) => { try { proc.resize(c || cols, r || rows); } catch { /* exited */ } },
        signal: (name) => { try { proc.kill(`SIG${name.replace(/^SIG/, '').toUpperCase()}`); } catch { /* exited */ } },
        kill: () => { try { proc.kill(); } catch { /* exited */ } },
      };

      if (cfg.sessions) {
        const hosted = cfg.sessions.create({ owner: ownerRecord(), kind: 'pty', command: m.command });
        hosted.handlers = ctl;
        const att = virtualAttachment(hosted, channelId, 'control');
        attachedChannel(hosted, att);
        proc.onData((d) => hosted.push(Uint8Array.from(toBytes(d))));
        proc.onExit(({ exitCode }) => hosted.finish(exitCode ?? 0));
        const opened = send(openOk({
          channelId, dataMode: 'virtual', capabilities: ['resize', 'signal'],
          sessionId: hosted.id, token: hosted.token,
        }));
        hosted.attach(att);
        await opened;
        log(`pty channel ${channelId} opened (${cols}x${rows}), session ${hosted.id.slice(0, 8)}`);
        return;
      }

      channels.set(channelId, ctl);
      let out = Promise.resolve();
      proc.onData((d) => { out = out.then(() => send(sessionData({ channelId, data: toBytes(d) }))); });
      proc.onExit(({ exitCode }) => { out.then(() => finishChannel(channelId, exitCode ?? 0)); });
      await send(openOk({
        channelId, dataMode: 'virtual', capabilities: ['resize', 'signal'],
        sessionId: randomUUID(), token: randomBytes(16),
      }));
      log(`pty channel ${channelId} opened (${cols}x${rows})`);
    }

    async function openFile(m) {
      if (!cfg.files) return send(openFail({ reason: 'file access is not enabled on this server' }));
      const spec = String(m.command ?? '');
      const mm = spec.match(/^(upload|download):(.*)$/s);
      if (!mm) return send(openFail({ reason: 'file channel expects upload:<path> or download:<path>' }));
      const [, direction, filePath] = mm;
      const channelId = ++state.nextChannel;

      if (direction === 'download') {
        let data;
        try { data = await cfg.files.readWhole(filePath); } catch (e) { return send(openFail({ reason: e.message })); }
        channels.set(channelId, { kill: () => channels.delete(channelId) });
        await send(openOk({ channelId, dataMode: 'virtual', capabilities: [] }));
        let off = 0;
        do {
          const end = Math.min(off + FILE_CHUNK_BYTES, data.byteLength);
          await send(fileChunk({ channelId, offset: off, data: data.subarray(off, end), isFinal: end >= data.byteLength, totalSize: data.byteLength }));
          off = end;
        } while (off < data.byteLength);
        log(`download ${filePath} (${data.byteLength} B)`);
        return;
      }

      const ch = { buf: null, kill: () => channels.delete(channelId) };
      channels.set(channelId, ch);
      const done = async (code, why) => {
        if (why) log(`upload ${filePath}: ${why}`);
        await finishChannel(channelId, code);
      };
      ch.chunk = async (c) => {
        if (ch.failed) return;
        const total = Number(c.total_size ?? 0);
        if (total > cfg.files.maxFileBytes) { ch.failed = true; return done(1, `refused: ${total} B exceeds ${cfg.files.maxFileBytes} B`); }
        ch.buf ??= new Uint8Array(total);
        const data = c.data instanceof Uint8Array ? c.data : new Uint8Array(0);
        if (c.offset + data.byteLength > ch.buf.byteLength) { ch.failed = true; return done(1, 'chunk past total_size'); }
        ch.buf.set(data, c.offset);
        if (c.is_final) {
          try { await cfg.files.writeWhole(filePath, ch.buf); } catch (e) { ch.failed = true; return done(1, e.message); }
          return done(0, `stored ${ch.buf.byteLength} B`);
        }
      };
      await send(openOk({ channelId, dataMode: 'virtual', capabilities: [] }));
    }

    async function handleFileOp(m) {
      const channelId = m.channel_id;
      if (!cfg.files) return send(fileResult({ channelId, success: false, errorMessage: 'file access is not enabled on this server' }));
      if (m.op === 'write' || m.op === 'rename') return startPayloadOp(m);
      try {
        const r = await cfg.files.operate(m.op, m.path, { offset: m.offset, length: m.length });
        return send(fileResult({ channelId, success: true, metadata: r.metadata ?? {}, entries: r.entries ?? [] }));
      } catch (e) {
        const message = e.wsh ? e.message : (e.code === 'ENOENT' ? 'no such file or directory' : `${m.op} failed`);
        if (!e.wsh && e.code !== 'ENOENT') log(`file ${m.op} ${m.path}: ${e.message}`);
        return send(fileResult({ channelId, success: false, errorMessage: message }));
      }
    }

    // write / rename = FileOp then FileChunk frame(s) on the same channel id
    // (rename's payload is the UTF-8 destination path); one FileResult once
    // the last chunk lands (see WshClient.fileOperation).
    async function startPayloadOp(m) {
      const channelId = m.channel_id;
      const failWrite = (errorMessage) => send(fileResult({ channelId, success: false, errorMessage }));
      const rename = m.op === 'rename';
      const length = Number(m.length);
      if (!Number.isSafeInteger(length) || length < 0) return failWrite(`${m.op} needs a length`);
      const limit = rename ? MAX_RENAME_PATH_BYTES : cfg.files.maxFileBytes;
      if (length > limit) return failWrite(`${m.op} payload of ${length} bytes exceeds the ${limit} byte limit`);
      if (channels.has(channelId) || fileWrites.has(channelId)) return failWrite('channel id already in use');
      if (fileWrites.size >= MAX_PENDING_WRITES) return failWrite('too many writes in flight');
      const w = { rename, path: m.path, offset: m.offset, length, buf: new Uint8Array(length), next: 0, timer: null };
      const arm = () => {
        clearTimeout(w.timer);
        w.timer = setTimeout(() => {
          if (fileWrites.delete(channelId)) failWrite('write timed out waiting for data');
        }, WRITE_IDLE_MS);
        w.timer.unref?.();
      };
      arm();
      w.arm = arm;
      fileWrites.set(channelId, w);
    }

    async function handleWriteChunk(m) {
      const channelId = m.channel_id;
      const w = fileWrites.get(channelId);
      const abort = (errorMessage) => {
        clearTimeout(w.timer);
        fileWrites.delete(channelId);
        return send(fileResult({ channelId, success: false, errorMessage }));
      };
      const data = m.data instanceof Uint8Array ? m.data : new Uint8Array(0);
      if (m.offset !== w.next) return abort('chunks must arrive in order');
      if (w.next + data.byteLength > w.length) return abort('chunk past the declared length');
      w.buf.set(data, w.next);
      w.next += data.byteLength;
      if (!m.is_final) { w.arm(); return; }
      clearTimeout(w.timer);
      fileWrites.delete(channelId);
      if (w.next !== w.length) return send(fileResult({ channelId, success: false, errorMessage: 'payload ended short of the declared length' }));
      try {
        const r = w.rename
          ? await cfg.files.operate('rename', w.path, { newPath: new TextDecoder('utf-8', { fatal: true }).decode(w.buf) })
          : await cfg.files.operate('write', w.path, { offset: w.offset, data: w.buf });
        return send(fileResult({ channelId, success: true, metadata: r.metadata ?? {} }));
      } catch (e) {
        const message = e.wsh ? e.message : (e.code === 'ENOENT' ? 'no such file or directory' : `${w.rename ? 'rename' : 'write'} failed`);
        if (!e.wsh && e.code !== 'ENOENT') log(`file write ${w.path}: ${e.message}`);
        return send(fileResult({ channelId, success: false, errorMessage: message }));
      }
    }

    return {
      receive(bytes) { if (!state.closed) qmux?.receiveBytes(bytes); },
      receiveMessage(msg) { if (!state.closed) chain = chain.then(() => handle(msg)).catch((e) => log(`handler error: ${e.message}`)); },
      bindStream: bindDataStream,
      close() { shutdownAfterQueue('transport closed'); },
    };
  };
}
