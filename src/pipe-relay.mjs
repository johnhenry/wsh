/**
 * A pipe relay (wsh #118): rendezvous and byte copying, nothing else.
 *
 * Two parties that cannot reach each other directly both dial the relay with the same unguessable rendezvous id --
 * the host (`role: 'host'`) and the operator (`role: 'operator'`) -- and the relay joins them and copies WebSocket
 * messages in both directions. It does not parse wsh: it holds no keys, runs nothing, reads no files, and cannot
 * tell who either party is. The host serves its connection with the ordinary `createWshServer().accept(socket)` (or
 * `createMemoryHost().accept`), so it runs the ordinary handshake and verifies the OPERATOR'S OWN signature; the
 * operator connects with the ordinary `WshClient.connect(pipeUrl(...))` and can pin the host key. Compare relay
 * mode (`createWshServer({ relay })`), where the relay authenticates the operator and tells the peer who it is.
 * What a pipe relay can still do is in the README's Security model: it sees metadata and ciphertext-free traffic
 * volume, can drop or delay bytes, and can offer a host or operator to whoever holds the rendezvous id.
 *
 * THIS MODULE IMPORTS NOTHING STATICALLY, and its only dynamic imports are `ws`, `node:http` and `node:https` (in
 * `listen()`, for embedders that do not already run an HTTP server). test/pipe-relay.test.mjs asserts that the
 * module graph reaches nothing that can execute code or read files. That is the point of shipping it as its own
 * entry point (`@johnhenry/wsh/pipe-relay`) rather than a mode of the server.
 *
 * Bounds (every one has a default; 0 turns a limit off only where noted):
 *   maxWaiting          halves waiting for a partner, over all ids (default 1024); more are refused
 *   rendezvousTimeoutMs how long a half waits for its partner (default 120000)
 *   idleTimeoutMs       a pipe that carried no byte either way for this long is closed (default 300000; wsh clients ping)
 *   maxLifetimeMs       a pipe is closed this long after pairing (default 12 h)
 *   maxBytes            total bytes copied per pipe, both directions (default 1 GiB)
 *   maxMessageBytes     largest single message (default 4 MiB)
 *   earlyBytes          what a half may send before its partner arrives (default 64 KiB); more closes it
 *   highWaterBytes      a socket whose outgoing buffer exceeds this is not fed further until it drains (default 1 MiB)
 *
 * Backpressure: when the receiving socket's `bufferedAmount` passes `highWaterBytes`, the sending socket is
 * `pause()`d (the `ws` package's flow control, which stops reading its TCP socket) and resumed once the buffer is
 * below half of it. A socket that cannot pause (a browser's, say) is closed instead of buffered without bound.
 */

const OPEN = 1;
const ID_RE = /^[A-Za-z0-9_-]{22,128}$/;
const ROLES = new Set(['host', 'operator']);
const MIN_ID_LENGTH = 22; // 16 random bytes, base64url

/** A fresh rendezvous id: 128 bits from the platform CSPRNG, base64url (22 characters). */
export function newRendezvousId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

/**
 * The URL one side dials: `<relay>/r/<id>`, with `?role=host` for the host (the operator is the default).
 * @param {string} relayUrl - `ws://` / `wss://` (or `http(s)://`) base of the relay
 * @param {string} id
 * @param {'host' | 'operator'} [role='operator']
 */
export function pipeUrl(relayUrl, id, role = 'operator') {
  if (!ID_RE.test(id)) throw new TypeError(`pipeUrl: the rendezvous id must be ${MIN_ID_LENGTH}-128 base64url characters (use newRendezvousId())`);
  if (!ROLES.has(role)) throw new TypeError("pipeUrl: role must be 'host' or 'operator'");
  const u = new URL(relayUrl);
  u.pathname = `${u.pathname.replace(/\/+$/, '')}/r/${id}`;
  u.search = role === 'host' ? '?role=host' : '';
  return u.toString();
}

const sane = (code) => (Number.isInteger(code) && code >= 1000 && code <= 4999 && ![1004, 1005, 1006, 1015].includes(code) ? code : 1000);

/** Adapt a `ws`-style (`on`) or browser-style (`addEventListener`) socket to message/close callbacks. */
function listenOn(socket, onMessage, onClose) {
  if (typeof socket.addEventListener === 'function') {
    socket.addEventListener('message', (ev) => onMessage(ev?.data));
    socket.addEventListener('close', (ev) => onClose(ev?.code));
    socket.addEventListener('error', () => {});
  } else if (typeof socket.on === 'function') {
    socket.on('message', (data, isBinary) => onMessage(data, isBinary));
    socket.on('close', (code) => onClose(code));
    socket.on('error', () => {});
  } else {
    throw new TypeError('createPipeRelay: socket must support on() or addEventListener()');
  }
}

const sizeOf = (data) => (typeof data === 'string' ? -1
  : Array.isArray(data) ? data.reduce((n, d) => n + d.byteLength, 0)
    : data?.byteLength ?? data?.size ?? -1);

/**
 * @param {object} [options]
 * @param {number} [options.maxWaiting=1024]
 * @param {number} [options.rendezvousTimeoutMs=120000]
 * @param {number} [options.idleTimeoutMs=300000]
 * @param {number} [options.maxLifetimeMs=43200000]
 * @param {number} [options.maxBytes=1073741824]
 * @param {number} [options.maxMessageBytes=4194304]
 * @param {number} [options.earlyBytes=65536]
 * @param {number} [options.highWaterBytes=1048576]
 * @param {(who: { id: string, role: 'host' | 'operator', remote?: object }) => boolean | Promise<boolean>} [options.authorize]
 *   Optional gate, called before a half may wait or pair (rate limiting, an allow-list of ids you minted). Default:
 *   anyone holding a well-formed id; the id is the capability.
 * @param {(line: string) => void} [options.onLog]
 */
export function createPipeRelay({
  maxWaiting = 1024, rendezvousTimeoutMs = 120_000, idleTimeoutMs = 300_000, maxLifetimeMs = 12 * 3600_000,
  maxBytes = 1024 ** 3, maxMessageBytes = 4 * 1024 * 1024, earlyBytes = 64 * 1024, highWaterBytes = 1024 * 1024,
  authorize, onLog = () => {},
} = {}) {
  for (const [name, v] of Object.entries({ maxWaiting, rendezvousTimeoutMs, idleTimeoutMs, maxLifetimeMs, maxBytes, maxMessageBytes, earlyBytes, highWaterBytes })) {
    if (!Number.isFinite(v) || v < 1) throw new TypeError(`createPipeRelay: ${name} must be a positive number`);
  }
  if (authorize !== undefined && typeof authorize !== 'function') throw new TypeError('createPipeRelay: authorize must be a function');

  /** id -> the one half waiting for its partner. */
  const waiting = new Map();
  /** Live pipes. */
  const pipes = new Set();
  let closed = false;
  let server = null;

  const closeSocket = (socket, code = 1000, reason = '') => { try { socket.close(code, reason); } catch { /* gone */ } };

  function wait(half) {
    half.timer = setTimeout(() => { waiting.delete(half.id); closeSocket(half.socket, 1000, 'no partner arrived'); onLog(`pipe ${half.id.slice(0, 6)}: ${half.role} waited too long`); }, rendezvousTimeoutMs);
    half.timer.unref?.();
    waiting.set(half.id, half);
  }

  function pair(first, second) {
    clearTimeout(first.timer);
    waiting.delete(first.id);
    const pipe = { halves: [first, second], bytes: 0, last: Date.now(), timers: [], done: false };
    pipes.add(pipe);
    const end = (code, reason, from) => {
      if (pipe.done) return;
      pipe.done = true;
      pipes.delete(pipe);
      for (const t of pipe.timers) { clearInterval(t); clearTimeout(t); }
      for (const h of pipe.halves) { h.resume?.(); if (h !== from) closeSocket(h.socket, sane(code), reason); }
      onLog(`pipe ${first.id.slice(0, 6)} closed (${reason || code}) after ${pipe.bytes} bytes`);
    };
    pipe.end = end;
    const life = setTimeout(() => end(1000, 'maximum lifetime reached'), maxLifetimeMs);
    const idle = setInterval(() => { if (Date.now() - pipe.last > idleTimeoutMs) end(1000, 'idle'); }, Math.max(1000, Math.min(idleTimeoutMs / 4, 30_000)));
    for (const t of [life, idle]) t.unref?.();
    pipe.timers.push(life, idle);

    const [a, b] = pipe.halves;
    for (const [from, to] of [[a, b], [b, a]]) {
      from.forward = (data, isBinary) => {
        if (pipe.done) return;
        const n = sizeOf(data);
        if (n < 0 || isBinary === false) return end(1003, 'binary messages only', null);
        if (n > maxMessageBytes) return end(1009, 'message too large', null);
        pipe.bytes += n;
        pipe.last = Date.now();
        if (pipe.bytes > maxBytes) return end(1008, 'byte limit reached', null);
        if (to.socket.readyState !== OPEN) return;
        try { to.socket.send(data); } catch { return end(1011, 'send failed', null); }
        if ((to.socket.bufferedAmount ?? 0) > highWaterBytes) throttle(from, to, pipe);
      };
      // Whatever it said before its partner arrived.
      for (const m of from.early.splice(0)) from.forward(m.data, m.isBinary);
    }
  }

  function throttle(from, to, pipe) {
    if (from.paused) return;
    if (typeof from.socket.pause !== 'function' || typeof from.socket.resume !== 'function') return pipe.end(1013, 'receiver too slow', null);
    from.paused = true;
    from.socket.pause();
    from.resume = () => { if (from.paused) { from.paused = false; try { from.socket.resume(); } catch { /* gone */ } } };
    const poll = setInterval(() => {
      if (pipe.done) return clearInterval(poll);
      if ((to.socket.bufferedAmount ?? 0) < highWaterBytes / 2) { clearInterval(poll); from.resume(); }
    }, 10);
    poll.unref?.();
    pipe.timers.push(poll);
  }

  /**
   * Hand the relay one accepted connection.
   * @param {object} socket - a WebSocket-like duplex (`send`, `close`, `readyState`, `on` or `addEventListener`)
   * @param {{ id: string, role?: 'host' | 'operator', remote?: object }} who
   * @returns {Promise<boolean>} whether the connection is now waiting or paired (false: it was refused and closed)
   */
  async function accept(socket, { id, role = 'operator', remote } = {}) {
    if (!socket || typeof socket.send !== 'function' || typeof socket.close !== 'function') throw new TypeError('createPipeRelay.accept: socket must be a WebSocket-like duplex');
    const refuse = (code, reason) => { closeSocket(socket, code, reason); return false; };
    if (closed) return refuse(1001, 'relay is shutting down');
    if (typeof id !== 'string' || !ID_RE.test(id)) return refuse(1008, 'bad rendezvous id');
    if (!ROLES.has(role)) return refuse(1008, 'bad role');

    // Listeners first, so nothing the peer says while we decide is lost; it is held (bounded) until it can be passed on.
    const half = { id, role, socket, early: [], earlyBytes: 0, timer: null, forward: null, paused: false, resume: null };
    let pipeRef = null;
    listenOn(socket, (data, isBinary) => {
      if (half.forward) return half.forward(data, isBinary);
      const n = sizeOf(data);
      half.earlyBytes += Math.max(n, 0);
      if (n < 0 || isBinary === false || half.earlyBytes > earlyBytes) {
        waiting.get(id) === half && (clearTimeout(half.timer), waiting.delete(id));
        return closeSocket(socket, n < 0 || isBinary === false ? 1003 : 1009, 'too much before the partner arrived');
      }
      half.early.push({ data, isBinary });
    }, (code) => {
      if (waiting.get(id) === half) { clearTimeout(half.timer); waiting.delete(id); }
      for (const p of pipes) if (p.halves.includes(half)) { pipeRef = p; break; }
      pipeRef?.end(code, 'peer closed', half);
    });

    if (authorize) {
      let ok = false;
      try { ok = (await authorize({ id, role, remote })) === true; } catch (e) { onLog(`authorize threw: ${e.message}`); }
      if (!ok) return refuse(1008, 'not permitted');
      if (closed || socket.readyState !== OPEN) return false;
    }

    const other = waiting.get(id);
    if (!other) {
      if (waiting.size >= maxWaiting) return refuse(1013, 'too many waiting connections');
      wait(half);
      return true;
    }
    if (other.role === role) return refuse(1008, 'rendezvous id in use');
    pair(other, half);
    onLog(`pipe ${id.slice(0, 6)}: paired`);
    return true;
  }

  /**
   * Listen for WebSocket upgrades on `<path>/<id>` (default path `/r`), `?role=host` for the host side.
   * Convenience for embedders without an HTTP server; needs the `ws` package. `tls` is the options of `https.createServer`.
   * @returns {Promise<{ port: number, address: string, close(): Promise<void> }>}
   */
  async function listen({ host = '127.0.0.1', port = 0, path = '/r', tls } = {}) {
    if (server) throw new Error('createPipeRelay: already listening');
    const { WebSocketServer } = await import('ws');
    const http = tls ? await import('node:https') : await import('node:http');
    const wss = new WebSocketServer({ noServer: true, maxPayload: maxMessageBytes });
    const srv = tls ? http.createServer(tls) : http.createServer();
    srv.on('request', (_req, res) => { res.statusCode = 426; res.end('WebSocket only'); });
    srv.on('upgrade', (req, sock, head) => {
      let url;
      try { url = new URL(req.url, 'http://x'); } catch { sock.destroy(); return; }
      const m = url.pathname.startsWith(`${path}/`) ? url.pathname.slice(path.length + 1) : null;
      const role = url.searchParams.get('role') ?? 'operator';
      if (!m || !ID_RE.test(m) || !ROLES.has(role)) { sock.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n'); sock.destroy(); return; }
      wss.handleUpgrade(req, sock, head, (ws) => { accept(ws, { id: m, role, remote: { address: req.socket.remoteAddress, headers: req.headers } }).catch(() => closeSocket(ws, 1011, 'error')); });
    });
    await new Promise((resolve, reject) => { srv.once('error', reject); srv.listen(port, host, () => { srv.off('error', reject); resolve(); }); });
    server = { srv, wss };
    const addr = srv.address();
    return {
      port: addr.port, address: addr.address,
      close: () => close(),
    };
  }

  async function close() {
    closed = true;
    for (const h of waiting.values()) { clearTimeout(h.timer); closeSocket(h.socket, 1001, 'relay is shutting down'); }
    waiting.clear();
    for (const p of [...pipes]) p.end(1001, 'relay is shutting down', null);
    if (server) {
      const { srv, wss } = server;
      server = null;
      for (const c of wss.clients) c.terminate();
      await new Promise((r) => wss.close(r));
      await new Promise((r) => { srv.close(() => r()); srv.closeAllConnections?.(); });
    }
  }

  return {
    accept, listen, close,
    /** `{ waiting, pipes }` right now. */
    stats: () => ({ waiting: waiting.size, pipes: pipes.size }),
    newRendezvousId,
  };
}
