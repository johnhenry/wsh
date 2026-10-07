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
  exit as exitMsg, close as closeMsg, pong, fileResult, fileChunk,
} from '../messages.gen.mjs';
import {
  generateNonce, verifyChallenge, fingerprint, importPublicKeyRaw,
} from '../auth.mjs';
import { FILE_CHUNK_BYTES } from './fs.mjs';

export const STREAM_ANNOUNCE = 'stream-announce';

const MAX_CHANNELS = 64;
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
 * @param {number} cfg.bindTimeoutMs - how long exec output waits for the data stream
 * @param {(line: string) => void} cfg.log
 */
export function createConnectionFactory(cfg) {
  let counter = 0;

  return function attach({ send: sendBytes }) {
    const cid = ++counter;
    const log = (m) => cfg.log(`[conn ${cid}] ${m}`);
    const state = {
      sessionId: randomUUID(), nonce: null, username: null, authed: false,
      closed: false, nextChannel: 0,
    };
    /** @type {Map<number, any>} */
    const channels = new Map();
    /** Channel ids awaiting their client-opened data stream, in OpenOk order. */
    const pendingStreams = [];
    const decoder = new FrameDecoder();
    const pendingSends = [];
    let control = null;
    let chain = Promise.resolve();

    const qmux = new QMuxConnection({ isClient: false, send: (b) => { if (!state.closed) sendBytes(b); } });

    const send = (msg) => {
      if (state.closed) return Promise.resolve();
      const bytes = frameEncode(msg);
      if (control) return control.write(bytes).catch(() => {});
      pendingSends.push(bytes);
      return Promise.resolve();
    };

    function shutdown(why) {
      if (state.closed) return;
      state.closed = true;
      for (const ch of channels.values()) ch.kill?.();
      channels.clear();
      try { qmux.destroy(new Error(why)); } catch { /* already gone */ }
      log(`closed (${why})`);
    }

    qmux.onError = (e) => log(`qmux error: ${e.message}`);
    qmux.onClose = () => shutdown('peer sent CONNECTION_CLOSE');
    qmux.onStreamOpen = (s) => {
      if (s.id !== 0) { bindDataStream(s); return; }
      control = s;
      s.onData = (d) => {
        let msgs;
        try { msgs = decoder.feed(d); } catch (e) { log(`frame decode error: ${e.message}`); return; }
        for (const m of msgs) chain = chain.then(() => handle(m)).catch((e) => log(`handler error: ${e.message}`));
      };
      s.onEnd = () => shutdown('control stream FIN');
      s.onReset = () => shutdown('control stream reset');
      for (const b of pendingSends.splice(0)) s.write(b).catch(() => {});
    };
    qmux.sendHandshake();

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
      switch (m.type) {
        case MSG.PING: return send(pong({ id: m.id }));
        case MSG.OPEN: return handleOpen(m);
        case MSG.SESSION_DATA: channels.get(m.channel_id)?.input?.(m.data); return;
        case MSG.RESIZE: channels.get(m.channel_id)?.resize?.(m.cols, m.rows); return;
        case MSG.SIGNAL: channels.get(m.channel_id)?.signal?.(String(m.signal ?? '')); return;
        case MSG.CLOSE: { const ch = channels.get(m.channel_id); if (ch) { ch.kill?.(); } return; }
        case MSG.FILE_OP: return handleFileOp(m);
        case MSG.FILE_CHUNK: return channels.get(m.channel_id)?.chunk?.(m);
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
        if (m.auth_method && m.auth_method !== 'pubkey') return refuse('this host only accepts Ed25519 pubkey auth');
        state.username = user;
        state.nonce = generateNonce();
        const features = [STREAM_ANNOUNCE];
        if (cfg.files) features.push('file-transfer');
        await send(serverHello({ sessionId: state.sessionId, features }));
        await send(challenge({ nonce: state.nonce, sessionId: state.sessionId }));
        return;
      }
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
        state.nonce = null;
        await send(authOk({ sessionId: state.sessionId, token: randomBytes(16), ttl: 3600 }));
        log(`authenticated ${state.username} (${fp.slice(0, 12)}...)`);
      }
    }

    // ── Open ──────────────────────────────────────────────────────────

    function handleOpen(m) {
      if (channels.size >= MAX_CHANNELS) return send(openFail({ reason: 'too many open channels' }));
      switch (m.kind) {
        case 'exec': return openExec(m);
        case 'pty': return openPty(m);
        case 'file': return openFile(m);
        default: return send(openFail({ reason: `kind "${m.kind}" is not supported by this server` }));
      }
    }

    function finishChannel(channelId, code) {
      if (!channels.has(channelId) || state.closed) return Promise.resolve();
      channels.delete(channelId);
      return send(exitMsg({ channelId, code })).then(() => send(closeMsg({ channelId })));
    }

    async function openExec(m) {
      if (!cfg.execRunner) return send(openFail({ reason: 'exec is not enabled on this server' }));
      const command = String(m.command ?? '').trim();
      if (!command) return send(openFail({ reason: 'command is required for kind "exec"' }));

      const channelId = ++state.nextChannel;
      const abort = new AbortController();
      let stream = null;
      let primerChecked = false;
      let wq = Promise.resolve();
      const buffered = [];
      const boundWaiters = [];
      const inputCbs = [];
      const endCbs = [];
      const signalCbs = [];

      const ch = {
        kill: () => abort.abort(),
        signal: (name) => {
          const n = name.replace(/^SIG/, '').toUpperCase();
          for (const cb of signalCbs) cb(n);
          if (/^(INT|TERM|KILL|HUP)$/.test(n) && signalCbs.length === 0) abort.abort();
        },
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
          s.onReset = () => abort.abort();
          const pending = buffered.splice(0);
          wq = wq.then(async () => { for (const b of pending) await s.write(b).catch(() => {}); });
          for (const r of boundWaiters.splice(0)) r();
        },
      };
      channels.set(channelId, ch);
      pendingStreams.push(channelId);

      let timer = null;
      if (cfg.execOptions.timeoutMs > 0) timer = setTimeout(() => abort.abort(), cfg.execOptions.timeoutMs);

      const io = {
        user: state.username,
        env: m.env && typeof m.env === 'object' && cfg.execOptions.clientEnv !== false ? m.env : {},
        cols: m.cols || 80,
        rows: m.rows || 24,
        signal: abort.signal,
        write(data) {
          const bytes = toBytes(data);
          if (!stream) { buffered.push(bytes); return Promise.resolve(); }
          const s = stream;
          wq = wq.then(() => s.write(bytes).catch(() => {}));
          return wq;
        },
        onInput: (cb) => inputCbs.push(cb),
        onInputEnd: (cb) => endCbs.push(cb),
        onSignal: (cb) => signalCbs.push(cb),
      };

      await send(openOk({
        channelId, dataMode: 'stream', capabilities: ['signal'],
        sessionId: randomUUID(), token: randomBytes(16),
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
      // Output is ready but the client's stream may not have been bound yet
      // (a host without announce support waits for the first byte): give it
      // a bounded chance rather than dropping the output or hanging forever.
      if (!stream) await Promise.race([new Promise((r) => boundWaiters.push(r)), new Promise((r) => setTimeout(r, cfg.bindTimeoutMs))]);
      if (!stream) log(`exec channel ${channelId}: data stream never appeared; output dropped`);
      await wq;
      try { await stream?.close(); } catch { /* peer gone */ }
      await finishChannel(channelId, Number.isInteger(code) ? code : 0);
      }
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
      const ch = {
        input: (data) => { try { proc.write(Buffer.from(data)); } catch { /* exited */ } },
        resize: (c, r) => { try { proc.resize(c || cols, r || rows); } catch { /* exited */ } },
        signal: (name) => { try { proc.kill(`SIG${name.replace(/^SIG/, '').toUpperCase()}`); } catch { /* exited */ } },
        kill: () => { try { proc.kill(); } catch { /* exited */ } },
      };
      channels.set(channelId, ch);
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
      try {
        const r = await cfg.files.operate(m.op, m.path, { offset: m.offset, length: m.length });
        return send(fileResult({ channelId, success: true, metadata: r.metadata ?? {}, entries: r.entries ?? [] }));
      } catch (e) {
        const message = e.wsh ? e.message : (e.code === 'ENOENT' ? 'no such file or directory' : `${m.op} failed`);
        if (!e.wsh && e.code !== 'ENOENT') log(`file ${m.op} ${m.path}: ${e.message}`);
        return send(fileResult({ channelId, success: false, errorMessage: message }));
      }
    }

    return {
      receive(bytes) { if (!state.closed) qmux.receiveBytes(bytes); },
      close() { shutdown('transport closed'); },
    };
  };
}
