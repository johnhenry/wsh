/**
 * Serve a pre-upgraded transport: an already-accepted WebSocket-like duplex handed to a host by whoever did the
 * upgrade (an HTTP server of the embedder's, a Worker, a message port wrapper, a test). Browser-safe -- it touches
 * nothing but the object it is given -- and shared by `createWshServer().accept()` and `createMemoryHost()`.
 *
 * The duplex needs `send(bytes)`, `close(code?)`, `readyState` (1 = open) and either Node-style `on(event, fn)`
 * (`ws`) or `addEventListener(event, fn)` (browsers, Workers, undici). Incoming frames must be binary; a text frame
 * is ignored, as the QMux framing never carries one.
 */

const CONNECTING = 0;
const OPEN = 1;
/** Most bytes held for a socket that is still connecting (a handshake is a few hundred). */
const MAX_WAITING_BYTES = 256 * 1024;

/** @param {unknown} data - a message payload as `ws` (Buffer, ArrayBuffer, Buffer[]) or a browser (ArrayBuffer, view, Blob) delivers it */
async function toBytes(data) {
  if (data instanceof Uint8Array) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (Array.isArray(data)) {
    const parts = await Promise.all(data.map(toBytes));
    const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.byteLength; }
    return out;
  }
  if (data && typeof data.arrayBuffer === 'function') return new Uint8Array(await data.arrayBuffer());
  return null;
}

/**
 * @param {object} socket - the WebSocket-like duplex
 * @param {Promise<(opts: object) => { receive: Function, close: Function }>} ready - resolves to the connection factory's `attach`
 * @param {{ remote?: { address?: string, headers?: object }, dataStreams?: boolean }} [options] - what the host knows about the peer
 *   (`address` keys the password-failure throttle; the default key is shared by every socket without one).
 *   `dataStreams: false` serves this connection without client-opened data streams (exec output rides SessionData), for a
 *   client that cannot open them (the Rust client over WebSocket, #132). `sealSession: 'require'` makes THIS connection serve nothing
 *   until it is sealed, whatever the host's own setting (it can only strengthen it; a host with no host key, or with data streams, refuses to
 *   attach it: `ready` rejects). It is what `@johnhenry/wsh/duplex` asks of a transport it cannot vouch for.
 *   `waitForPeer` (#253): `true`, or a promise, says the far side is not there yet (the half a page dialled to a pipe relay, before any operator has): the login
 *   deadline (`loginTimeoutMs`) then starts when the far side arrives, not when this socket is handed over. The promise is the relay's paired signal
 *   (`watchPairing(socket).paired`); `true`, and a promise that does not settle, mean the first byte the far side sends. Default: the far side is here
 *   (a socket someone upgraded), and the deadline starts now.
 * @returns {Promise<{ close(): void }>} resolves once the connection is attached; `close()` drops it
 */
export function bindSocket(socket, ready, { remote = {}, dataStreams, sealSession, waitForPeer = false } = {}) {
  if (!socket || typeof socket.send !== 'function' || typeof socket.close !== 'function') {
    throw new TypeError('accept: socket must be a WebSocket-like duplex with send() and close()');
  }
  const peerSignal = waitForPeer !== null && typeof waitForPeer === 'object' && typeof waitForPeer.then === 'function' ? waitForPeer : null;
  if (waitForPeer !== true && waitForPeer !== false && !peerSignal) throw new TypeError('accept: waitForPeer must be true, false or a promise that resolves when the far side arrives');
  const listen = typeof socket.addEventListener === 'function'
    ? (event, fn) => socket.addEventListener(event, (ev) => fn(event === 'message' ? ev?.data : ev))
    : typeof socket.on === 'function'
      ? (event, fn) => socket.on(event, fn)
      : null;
  if (!listen) throw new TypeError('accept: socket must support addEventListener() or on()');
  try { socket.binaryType = 'arraybuffer'; } catch { /* read-only on some implementations; toBytes copes with any */ }

  // Listeners are attached now, before the host has finished starting, and the frames they see are
  // chained behind `ready`: a peer that speaks first (a client's QMux handshake) is not dropped.
  let conn = null;
  let closed = false;
  // A socket handed over while it is still connecting (`accept(new WebSocket(url))`) cannot be written to yet, but the host
  // speaks first (its QMux handshake): those bytes wait for `open`, in order, and are dropped if it never opens.
  let waiting = [];
  let waitingBytes = 0;
  const flush = () => {
    const out = waiting;
    waiting = []; waitingBytes = 0;
    if (socket.readyState !== OPEN) return;
    for (const b of out) socket.send(b);
  };
  const write = (bytes) => {
    if (socket.readyState === OPEN) { if (waiting.length) flush(); socket.send(bytes); return; }
    if (socket.readyState === CONNECTING && waitingBytes + bytes.byteLength <= MAX_WAITING_BYTES) { waiting.push(bytes); waitingBytes += bytes.byteLength; }
  };
  // The far side is there when the relay says so (a promise), before the connection exists or after: remembered, then applied.
  let peerArrived = false;
  if (peerSignal) {
    peerSignal.then(() => { peerArrived = true; conn?.startLoginClock?.(); }, () => { /* the pipe closed first: the close ends the connection */ });
  }
  let chain = ready.then((attach) => {
    if (closed) return;
    conn = attach({
      send: write,
      remote: { address: remote.address, headers: remote.headers ?? {} },
      dataStreams,
      ...(sealSession !== undefined ? { sealSession } : {}),
      ...(waitForPeer ? { waitForPeer: true } : {}),
      closeTransport: () => { try { socket.close(1000); } catch { /* already closed */ } },
    });
    if (peerArrived) conn.startLoginClock?.();
  });
  // The close joins the chain behind the messages that were received before it: each message is handled asynchronously, and
  // marking the connection closed at once would drop the peer's last messages (its final write, the end of its input).
  let closing = false;
  const drop = () => {
    if (closing) return;
    closing = true;
    chain = chain.then(() => { closed = true; return conn?.close(); }).catch(() => {});
  };
  listen('message', (data) => {
    if (closing) return;
    chain = chain.then(async () => {
      if (closed || !conn) return;
      const bytes = await toBytes(data);
      if (bytes && !closed) conn.receive(bytes);
    }).catch(() => {});
  });
  listen('open', flush);
  listen('close', drop);
  listen('error', () => {});
  return chain.then(() => ({
    close() { drop(); try { socket.close(1000); } catch { /* already closed */ } },
  }));
}
