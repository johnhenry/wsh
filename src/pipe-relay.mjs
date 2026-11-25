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
 * THIS MODULE IMPORTS NOTHING, statically or by name: it is browser-safe (a page can bundle it for `pipeUrl`,
 * `newRendezvousId`, `watchPairing`, or to run `accept()` over sockets it holds). The one Node-only piece, `listen()`
 * (an HTTP server with `ws`, for embedders that do not already run one), lives in `./pipe-relay-node.mjs` and is
 * loaded only when `listen()` is called, through a specifier a bundler does not follow. test/pipe-relay.test.mjs
 * asserts that this module's graph is this one file and that the Node module reaches nothing that can execute code
 * or read files; test/browser-bundle.test.mjs bundles this entry for the browser. That is the point of shipping it
 * as its own entry point (`@johnhenry/wsh/pipe-relay`) rather than a mode of the server.
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
/** The Node-only half (`listen()`): a variable, not a literal, so a bundler does not follow it. */
const NODE_LISTENER = './pipe-relay-node.mjs';
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
 * The one text frame a relay sends a host that asked for it, when its partner arrives (before anything the partner said).
 * Everything else on a pipe is binary, so a text frame can never be wsh bytes.
 */
export const PAIRED_FRAME = 'wsh-pipe/1 paired';

/**
 * The URL one side dials: `<relay>/r/<id>`, with `?role=host` for the host (the operator is the default).
 * @param {string} relayUrl - `ws://` / `wss://` (or `http(s)://`) base of the relay
 * @param {string} id
 * @param {'host' | 'operator'} [role='operator']
 * @param {{ notifyPaired?: boolean }} [options] - `notifyPaired` (a host only) adds `&paired=1`: ask the relay to send
 *   `PAIRED_FRAME` when the operator arrives. A relay that predates it ignores the parameter and never sends it.
 */
export function pipeUrl(relayUrl, id, role = 'operator', { notifyPaired = false } = {}) {
  if (!ID_RE.test(id)) throw new TypeError(`pipeUrl: the rendezvous id must be ${MIN_ID_LENGTH}-128 base64url characters (use newRendezvousId())`);
  if (!ROLES.has(role)) throw new TypeError("pipeUrl: role must be 'host' or 'operator'");
  if (notifyPaired && role !== 'host') throw new TypeError('pipeUrl: notifyPaired is for the host side');
  const u = new URL(relayUrl);
  u.pathname = `${u.pathname.replace(/\/+$/, '')}/r/${id}`;
  u.search = role === 'host' ? (notifyPaired ? '?role=host&paired=1' : '?role=host') : '';
  return u.toString();
}

const textOf = (data) => {
  if (typeof data === 'string') return data;
  try {
    if (data instanceof ArrayBuffer) return new TextDecoder().decode(data);
    if (ArrayBuffer.isView(data)) return new TextDecoder().decode(data);
    if (Array.isArray(data)) return null;
    return typeof data?.toString === 'function' ? String(data) : null;
  } catch { return null; }
};

/**
 * Host side of the paired signal. Wrap the socket a host dialled with `notifyPaired` BEFORE anything is attached to it, hand
 * the returned `socket` to `server.accept()` / `host.accept()` (it is the same socket, with the one `PAIRED_FRAME` text frame
 * kept out of what the wsh host reads), and await `paired`: it resolves when the operator arrives, and rejects if the socket
 * closes first. Against a relay that does not know the flag it never resolves (the connection works as it always did): a
 * host that must know should also bound its wait with its own timer.
 * @param {object} socket  a WebSocket-like (`ws` or a browser's)
 * @returns {{ socket: object, paired: Promise<void> }}
 */
export function watchPairing(socket) {
  let resolve; let reject; let settled = false;
  const paired = new Promise((res, rej) => { resolve = res; reject = rej; });
  paired.catch(() => {}); // a host that ignores the promise must not crash on an unhandled rejection
  const isSignal = (data, isBinary) => isBinary !== true && textOf(data) === PAIRED_FRAME;
  const onSignal = (data, isBinary) => { if (!settled && isSignal(data, isBinary)) { settled = true; resolve(); } };
  const onClose = () => { if (!settled) { settled = true; reject(new Error('the pipe closed before a partner arrived')); } };
  if (typeof socket.addEventListener === 'function') {
    socket.addEventListener('message', (ev) => onSignal(ev?.data));
    socket.addEventListener('close', onClose);
  } else if (typeof socket.on === 'function') {
    socket.on('message', (data, isBinary) => onSignal(data, isBinary));
    socket.on('close', onClose);
  } else {
    throw new TypeError('watchPairing: socket must support on() or addEventListener()');
  }

  // The same socket for everything else, minus the signal frame for whoever listens for messages through it.
  const wrapped = new Map();
  const wrapFor = (style, fn) => {
    let w = wrapped.get(fn);
    if (!w) {
      w = style === 'event'
        ? (ev) => { if (!isSignal(ev?.data)) fn(ev); }
        : (data, isBinary) => { if (!isSignal(data, isBinary)) fn(data, isBinary); };
      wrapped.set(fn, w);
    }
    return w;
  };
  const proxy = new Proxy(socket, {
    get(target, prop) {
      if ((prop === 'addEventListener' || prop === 'on' || prop === 'addListener' || prop === 'once') && typeof target[prop] === 'function') {
        const style = prop === 'addEventListener' ? 'event' : 'node';
        return (type, fn, ...rest) => (type === 'message' && typeof fn === 'function' ? target[prop](type, wrapFor(style, fn), ...rest) : target[prop](type, fn, ...rest));
      }
      if ((prop === 'removeEventListener' || prop === 'off' || prop === 'removeListener') && typeof target[prop] === 'function') {
        return (type, fn, ...rest) => target[prop](type, (type === 'message' && wrapped.get(fn)) || fn, ...rest);
      }
      const v = Reflect.get(target, prop, target);
      return typeof v === 'function' ? v.bind(target) : v;
    },
    set(target, prop, value) { target[prop] = value; return true; },
  });
  return { socket: proxy, paired };
}

/**
 * The close reason texts a relay sends (#240), a stable list: a program may compare against these. Each limit closes BOTH halves of a
 * pipe with the same code and the same text, so the far side can tell a limit from the other person leaving (`peerClosed`, the only
 * text that means the partner's socket went away; the close code is then the partner's own). New texts may be added; none is renamed.
 *
 *   peerClosed       the partner's socket closed (code: the partner's)
 *   noPartner        1000  a half waited `rendezvousTimeoutMs` for a partner
 *   idle             1000  no byte either way for `idleTimeoutMs`
 *   lifetime         1000  `maxLifetimeMs` after pairing
 *   byteLimit        1008  `maxBytes` copied
 *   messageTooLarge  1009  one message over `maxMessageBytes` (also when the WebSocket server's own payload limit caught it first)
 *   binaryOnly       1003  a text frame (everything on a pipe is binary)
 *   earlyOverflow    1009 / 1003  a half sent more than `earlyBytes` (or a text frame) before its partner arrived (no partner exists yet)
 *   receiverTooSlow  1013  the receiver's buffer passed `highWaterBytes` and the sender cannot pause
 *   sendFailed       1011  writing to a socket threw
 *   shuttingDown     1001  `relay.close()`
 *   badId / badRole / notPermitted / idInUse / idRetired / tooManyWaiting   a refusal (1008; 1013 for tooManyWaiting) when the half arrived
 */
export const PIPE_CLOSE_REASONS = Object.freeze({
  peerClosed: 'peer closed',
  noPartner: 'no partner arrived',
  idle: 'idle',
  lifetime: 'maximum lifetime reached',
  byteLimit: 'byte limit reached',
  messageTooLarge: 'message too large',
  binaryOnly: 'binary messages only',
  earlyOverflow: 'too much before the partner arrived',
  receiverTooSlow: 'receiver too slow',
  sendFailed: 'send failed',
  shuttingDown: 'relay is shutting down',
  badId: 'bad rendezvous id',
  badRole: 'bad role',
  notPermitted: 'not permitted',
  idInUse: 'rendezvous id in use',
  idRetired: 'rendezvous id already used',
  tooManyWaiting: 'too many waiting connections',
});
const R = PIPE_CLOSE_REASONS;

const sane = (code) => (Number.isInteger(code) && code >= 1000 && code <= 4999 && ![1004, 1005, 1006, 1015].includes(code) ? code : 1000);

/** Adapt a `ws`-style (`on`) or browser-style (`addEventListener`) socket to message/close callbacks. */
function listenOn(socket, onMessage, onClose, onTooLarge) {
  if (typeof socket.addEventListener === 'function') {
    socket.addEventListener('message', (ev) => onMessage(ev?.data));
    socket.addEventListener('close', (ev) => onClose(ev?.code));
    socket.addEventListener('error', (ev) => { if ((ev?.error ?? ev)?.code === 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH') onTooLarge(); });
  } else if (typeof socket.on === 'function') {
    socket.on('message', (data, isBinary) => onMessage(data, isBinary));
    socket.on('close', (code) => onClose(code));
    // The `ws` package closes a socket itself when a frame passes its `maxPayload` (the relay's `maxMessageBytes`), and says so with this code.
    socket.on('error', (e) => { if (e?.code === 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH') onTooLarge(); });
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
  retirePaired = false, maxRetired = 10_000,
  authorize, onLog = () => {},
} = {}) {
  for (const [name, v] of Object.entries({ maxWaiting, rendezvousTimeoutMs, idleTimeoutMs, maxLifetimeMs, maxBytes, maxMessageBytes, earlyBytes, highWaterBytes })) {
    if (!Number.isFinite(v) || v < 1) throw new TypeError(`createPipeRelay: ${name} must be a positive number`);
  }
  if (typeof retirePaired !== 'boolean') throw new TypeError('createPipeRelay: retirePaired must be a boolean');
  if (!Number.isInteger(maxRetired) || maxRetired < 1) throw new TypeError('createPipeRelay: maxRetired must be a positive integer');
  if (authorize !== undefined && typeof authorize !== 'function') throw new TypeError('createPipeRelay: authorize must be a function');

  /** id -> the one half waiting for its partner. */
  const waiting = new Map();
  /** With `retirePaired`: the ids whose pipe paired, oldest first, at most `maxRetired` (a Set keeps insertion order). */
  const retired = new Set();
  const retire = (id) => {
    if (!retirePaired) return;
    retired.delete(id);
    retired.add(id);
    if (retired.size > maxRetired) retired.delete(retired.values().next().value);
  };
  /** Live pipes. */
  const pipes = new Set();
  let closed = false;
  let listening = false;
  /** What to run when the relay closes (the HTTP server of `listen()`). */
  const closers = [];

  const closeSocket = (socket, code = 1000, reason = '') => { try { socket.close(code, reason); } catch { /* gone */ } };

  function wait(half) {
    half.timer = setTimeout(() => { waiting.delete(half.id); closeSocket(half.socket, 1000, R.noPartner); onLog(`pipe ${half.id.slice(0, 6)}: ${half.role} waited too long`); }, rendezvousTimeoutMs);
    half.timer.unref?.();
    waiting.set(half.id, half);
  }

  function pair(first, second) {
    clearTimeout(first.timer);
    waiting.delete(first.id);
    retire(first.id);
    const pipe = { halves: [first, second], bytes: 0, last: Date.now(), timers: [], done: false };
    pipes.add(pipe);
    // A host that asked is told its partner is here, ahead of anything the partner said (not counted as pipe traffic).
    for (const h of pipe.halves) {
      if (h.notifyPaired && h.socket.readyState === OPEN) { try { h.socket.send(PAIRED_FRAME); } catch { /* it is gone; the pipe ends when its close arrives */ } }
    }
    const end = (code, reason, from) => {
      if (pipe.done) return;
      pipe.done = true;
      pipes.delete(pipe);
      for (const t of pipe.timers) { clearInterval(t); clearTimeout(t); }
      for (const h of pipe.halves) { h.resume?.(); if (h !== from) closeSocket(h.socket, sane(code), reason); }
      onLog(`pipe ${first.id.slice(0, 6)} closed (${reason || code}) after ${pipe.bytes} bytes`);
    };
    pipe.end = end;
    const life = setTimeout(() => end(1000, R.lifetime), maxLifetimeMs);
    const idle = setInterval(() => { if (Date.now() - pipe.last > idleTimeoutMs) end(1000, R.idle); }, Math.max(1000, Math.min(idleTimeoutMs / 4, 30_000)));
    for (const t of [life, idle]) t.unref?.();
    pipe.timers.push(life, idle);

    const [a, b] = pipe.halves;
    for (const [from, to] of [[a, b], [b, a]]) {
      from.forward = (data, isBinary) => {
        if (pipe.done) return;
        const n = sizeOf(data);
        if (n < 0 || isBinary === false) return end(1003, R.binaryOnly, null);
        if (n > maxMessageBytes) return end(1009, R.messageTooLarge, null);
        pipe.bytes += n;
        pipe.last = Date.now();
        if (pipe.bytes > maxBytes) return end(1008, R.byteLimit, null);
        if (to.socket.readyState !== OPEN) return;
        try { to.socket.send(data); } catch { return end(1011, R.sendFailed, null); }
        if ((to.socket.bufferedAmount ?? 0) > highWaterBytes) throttle(from, to, pipe);
      };
      // Whatever it said before its partner arrived.
      for (const m of from.early.splice(0)) from.forward(m.data, m.isBinary);
    }
  }

  function throttle(from, to, pipe) {
    if (from.paused) return;
    if (typeof from.socket.pause !== 'function' || typeof from.socket.resume !== 'function') return pipe.end(1013, R.receiverTooSlow, null);
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
   * @param {{ id: string, role?: 'host' | 'operator', remote?: object, notifyPaired?: boolean }} who  `notifyPaired` (a host
   *   that asked, `?paired=1`): send it `PAIRED_FRAME` once when the operator arrives. Only a host may ask.
   * @returns {Promise<boolean>} whether the connection is now waiting or paired (false: it was refused and closed)
   */
  async function accept(socket, { id, role = 'operator', remote, notifyPaired = false } = {}) {
    if (!socket || typeof socket.send !== 'function' || typeof socket.close !== 'function') throw new TypeError('createPipeRelay.accept: socket must be a WebSocket-like duplex');
    if (notifyPaired && role !== 'host') throw new TypeError('createPipeRelay.accept: notifyPaired is for the host side');
    const refuse = (code, reason) => { closeSocket(socket, code, reason); return false; };
    if (closed) return refuse(1001, R.shuttingDown);
    if (typeof id !== 'string' || !ID_RE.test(id)) return refuse(1008, R.badId);
    if (!ROLES.has(role)) return refuse(1008, R.badRole);

    // Listeners first, so nothing the peer says while we decide is lost; it is held (bounded) until it can be passed on.
    const half = { id, role, socket, early: [], earlyBytes: 0, timer: null, forward: null, paused: false, resume: null, notifyPaired: notifyPaired === true, tooLarge: false };
    let pipeRef = null;
    listenOn(socket, (data, isBinary) => {
      if (half.forward) return half.forward(data, isBinary);
      const n = sizeOf(data);
      half.earlyBytes += Math.max(n, 0);
      if (n < 0 || isBinary === false || half.earlyBytes > earlyBytes) {
        waiting.get(id) === half && (clearTimeout(half.timer), waiting.delete(id));
        return closeSocket(socket, n < 0 || isBinary === false ? 1003 : 1009, R.earlyOverflow);
      }
      half.early.push({ data, isBinary });
    }, (code) => {
      if (waiting.get(id) === half) { clearTimeout(half.timer); waiting.delete(id); }
      for (const p of pipes) if (p.halves.includes(half)) { pipeRef = p; break; }
      // A socket the WebSocket server closed itself for an oversize frame is a limit, not the person leaving: say so to the partner.
      if (half.tooLarge) pipeRef?.end(1009, R.messageTooLarge, half);
      else pipeRef?.end(code, R.peerClosed, half);
    }, () => { half.tooLarge = true; });

    if (authorize) {
      let ok = false;
      try { ok = (await authorize({ id, role, remote })) === true; } catch (e) { onLog(`authorize threw: ${e.message}`); }
      if (!ok) return refuse(1008, R.notPermitted);
      if (closed || socket.readyState !== OPEN) return false;
    }

    // After `authorize` (which still sees the attempt), so a caller it refuses learns nothing about whether an id was used.
    if (retired.has(id)) return refuse(1008, R.idRetired);
    const other = waiting.get(id);
    if (!other) {
      if (waiting.size >= maxWaiting) return refuse(1013, R.tooManyWaiting);
      wait(half);
      return true;
    }
    if (other.role === role) return refuse(1008, R.idInUse);
    pair(other, half);
    onLog(`pipe ${id.slice(0, 6)}: paired`);
    return true;
  }

  /**
   * Listen for WebSocket upgrades on `<path>/<id>` (default path `/r`), `?role=host` for the host side.
   * Convenience for embedders without an HTTP server; needs the `ws` package. `tls` is the options of `https.createServer`.
   * @returns {Promise<{ port: number, address: string, close(): Promise<void> }>}
   */
  async function listen(options = {}) {
    if (listening) throw new Error('createPipeRelay: already listening');
    listening = true;
    try {
      // The Node half lives in its own module and is named through a variable, so a bundler building this file for a
      // browser neither follows it nor needs `ws` or `node:http`.
      const { listenPipeRelay } = await import(NODE_LISTENER);
      return await listenPipeRelay({ accept, maxMessageBytes, onClose: (fn) => closers.push(fn), close: () => close() }, options);
    } catch (e) { listening = false; throw e; }
  }

  async function close() {
    closed = true;
    listening = false;
    for (const h of waiting.values()) { clearTimeout(h.timer); closeSocket(h.socket, 1001, R.shuttingDown); }
    waiting.clear();
    for (const p of [...pipes]) p.end(1001, R.shuttingDown, null);
    for (const fn of closers.splice(0)) await fn();
  }

  return {
    accept, listen, close,
    /** `{ waiting, pipes, retired }` right now (`retired`: ids remembered by `retirePaired`, 0 when it is off). */
    stats: () => ({ waiting: waiting.size, pipes: pipes.size, retired: retired.size }),
    newRendezvousId,
  };
}
