/**
 * `client.forwardUnix({ local, remote })` for Node: the `ssh -L` / `ssh -R` shapes with unix sockets and TCP ports
 * mixed. Loaded on demand by `WshClient#forwardUnix` so the browser build never sees `node:*`.
 */

import net from 'node:net';
import fsp from 'node:fs/promises';
import { listenUnixSocket, removeIfIdentity } from './unix-listen.mjs';
import { watchHalfClosed, answeringKeepAliveMs, PEER_GONE_CODES } from './half-close-watch.mjs';
import { assertHalfCloseProbeMs } from './gateway-channel.mjs';

/** A named endpoint: the CLI's rule (`valid_endpoint_name`): letters, digits, ".", "_", "-", starting with a letter or digit, at most 64. */
export const ENDPOINT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
/** How many connections one forward to a named endpoint serves at once: the CLI's `MAX_FORWARDED_CONNECTIONS`. */
export const DEFAULT_MAX_ENDPOINT_CONNECTIONS = 128;

/**
 * `/path`, `./path`, `@abstract` are sockets; `endpoint=NAME` is a named endpoint of the host (the CLI's spelling; the `=`
 * cannot occur in a path or host name); anything else is `host:port` (also `[::1]:80`, or a bare port = 127.0.0.1).
 */
export function parseEndpoint(spec) {
  if (typeof spec !== 'string' || !spec) throw new TypeError('forwardUnix: an endpoint must be a non-empty string');
  if (spec.startsWith('endpoint=')) {
    const name = spec.slice('endpoint='.length);
    if (!ENDPOINT_NAME.test(name)) throw new TypeError(`forwardUnix: ${JSON.stringify(name)} is not a valid endpoint name (letters, digits, ".", "_", "-"; at most 64)`);
    return { kind: 'endpoint', name };
  }
  if (spec.startsWith('/') || spec.startsWith('./') || spec.startsWith('../') || spec.startsWith('@')) return { kind: 'unix', path: spec };
  if (/^\d{1,5}$/.test(spec)) return { kind: 'tcp', host: '127.0.0.1', port: Number(spec) };
  const m = /^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$/.exec(spec);
  if (!m) throw new TypeError(`forwardUnix: ${JSON.stringify(spec)} is neither a socket path nor host:port`);
  const port = Number(m[3]);
  if (port > 65535) throw new TypeError(`forwardUnix: bad port in ${JSON.stringify(spec)}`);
  return { kind: 'tcp', host: m[1] ?? m[2], port };
}

/** Resolves when `sock` can take more, or is gone (a bare `once(sock, 'drain')` never settles on a socket that closed meanwhile). */
function drained(sock) {
  return new Promise((resolve) => {
    const done = () => { sock.off('drain', done); sock.off('close', done); sock.off('error', done); resolve(); };
    sock.on('drain', done); sock.on('close', done); sock.on('error', done);
  });
}

/**
 * Pipe a net.Socket and a gateway duplex both ways with backpressure on each leg. The socket must have been created with
 * `allowHalfOpen: true`: a local EOF closes only the write side towards the host (the answer still comes back), and the
 * host ending its side ends the local write side. A socket error (EPIPE or a reset when the local peer closed first) is
 * the end of that connection, not a failure of the forward.
 *
 * A local peer that half-closed and then went away (killed, crashed) is noticed by `watchHalfClosed` (#282) when `probeMs` is
 * given: the socket is destroyed, which sends the host a second GatewayClose "discarded" (below), and `onGone` hears of it. Only
 * for a CONNECTOR (the program that dialled a `-L` listener, which reads the answer): when it is gone nobody reads what the host
 * still sends. Never for a service that answers (a reverse forward's local end): its complete close after its last byte is the
 * normal end of a response, and the discard would drop what the caller has not read yet.
 */
export function pipe(sock, duplex, { probeMs, onGone, answering = false, remoteMs } = {}) {
  const writer = duplex.writable.getWriter();
  const reader = duplex.readable.getReader();
  // An ANSWERING socket (a reverse forward's local service; only when `gateway-lossless-close` is negotiated, #286) that went away is not a failure
  // and not a discard: the connection is RELEASED, which makes the host deliver to its caller what the service sent and then end.
  let released = false;
  watchHalfClosed(sock, probeMs, answering ? () => { released = true; } : onGone, answering ? answeringKeepAliveMs(sock, probeMs, remoteMs) : probeMs);
  // The write of the chunk last read from the socket. The connection is destroyed only after it has settled: a chunk the socket
  // already handed over is part of what it said, and destroying the connection drops it while it waits for credit. A socket that
  // closes completely (or is reset, as one is when the caller's request reaches a service that has already closed) right after its
  // last bytes would otherwise cost the caller the tail of the answer.
  let tail = Promise.resolve();
  // The probe is not the only way the end of an answering socket is seen: a read or a write that fails (the caller's bytes, still arriving, into a service that
  // has been reset; the kernel can report a reset INSTEAD of the end of file) closes it too, and the probe is skipped while a write is queued, so any of them may
  // be first. A service that is gone (it reset the connection: `released` is set by the 'error' below) or that sent its WHOLE answer (its end of file was read)
  // is released whichever it is: a second close of "discarded" would make the host drop what its caller has not read yet. Any other failure stays a discard.
  const destroyAfterTail = () => { void tail.finally(() => ((released || (answering && sock.readableEnded)) && typeof duplex.release === 'function' ? duplex.release() : duplex.destroy())); };
  sock.on('data', (d) => {
    sock.pause();
    tail = writer.write(new Uint8Array(d.buffer, d.byteOffset, d.length)).then(() => { if (!sock.destroyed) sock.resume(); }, () => {
      // The peer RELEASED the connection (#286): it reads nothing more, so what the socket sends now (a request body still uploading after the
      // answer was complete) has nowhere to go and is dropped, with the socket left paused; what the peer sent is still being written to the
      // socket, and destroying it now would drop that. (Any other failed write is the end of the connection.)
      if (!duplex.peerReleased) sock.destroy();
    });
  });
  sock.on('end', () => { void writer.close().catch(() => {}); });
  sock.on('error', (e) => { if (answering && PEER_GONE_CODES.has(e?.code)) released = true; });
  sock.on('close', destroyAfterTail);
  (async () => {
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (sock.destroyed) break;
        if (!sock.write(value)) await drained(sock);
        if (sock.destroyed) break;
      }
      if (!sock.destroyed) {
        sock.end();
        // A released connection is over once its tail is out: the socket is not left half-open for a peer that may never read or close.
        if (duplex.peerReleased) sock.once('finish', () => sock.destroy());
      } else destroyAfterTail();
    } catch { sock.destroy(); }
  })();
  duplex.closed.then(() => { if (!sock.destroyed) sock.end(); });
}

async function listenLocal(spec, { replace }) {
  const server = net.createServer({ pauseOnConnect: true, allowHalfOpen: true });
  if (spec.kind === 'tcp') {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ host: spec.host, port: spec.port }, () => { server.off('error', reject); resolve(); }); });
    return { server, close: () => new Promise((res) => { server.close(() => res()); }) };
  }
  if (spec.path.startsWith('@')) throw new TypeError('forwardUnix: a local abstract socket is not supported; use a path');
  let existing = null;
  try { existing = await fsp.lstat(spec.path); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (existing) {
    if (!existing.isSocket()) throw new Error(`${spec.path} exists and is not a socket`);
    if (!replace) throw new Error(`${spec.path} already exists (pass replace: true to replace a stale socket)`);
    const live = await new Promise((resolve) => {
      const p = net.connect({ path: spec.path });
      p.once('connect', () => { p.destroy(); resolve(true); });
      p.once('error', (e) => resolve(e.code !== 'ECONNREFUSED' && e.code !== 'ENOENT'));
    });
    if (live) throw new Error(`${spec.path} is in use`);
    // The socket that was looked at, not whatever is at the name now.
    if (!(await removeIfIdentity(spec.path, { dev: existing.dev, ino: existing.ino }))) throw new Error(`${spec.path} changed while it was being checked; not replacing it`);
  }
  const listening = await listenUnixSocket(server, spec.path);
  return { server, close: () => listening.close() };
}

/**
 * `client.forwardEndpoint({ local, endpoint })`: sugar for `forward` with `remote: 'endpoint=NAME'`; the handle also names `endpoint`.
 * @param {import('./client.mjs').WshClient} client
 * @param {{ local: string, endpoint: string, replace?: boolean, maxConnections?: number, onError?: (err: Error) => void }} opts
 */
export async function forwardEndpoint(client, opts = {}) {
  const { endpoint, ...rest } = opts ?? {};
  if (typeof endpoint !== 'string') throw new TypeError('forwardEndpoint: endpoint must be the name of one of the host\'s endpoints');
  if ('remote' in rest || 'reverse' in rest) throw new TypeError('forwardEndpoint: takes { local, endpoint }; use forwardUnix for the other forwards');
  return forward(client, { ...rest, remote: `endpoint=${endpoint}` });
}

/**
 * @param {import('./client.mjs').WshClient} client
 * @param {{ local: string, remote: string, reverse?: boolean, replace?: boolean, maxConnections?: number, halfCloseProbeMs?: number, onError?: (err: Error) => void }} opts
 */
export async function forward(client, { local, remote, reverse = false, replace = false, maxConnections, halfCloseProbeMs, halfCloseProbeAnswers = true, halfCloseProbeRemoteMs, onError = () => {} } = {}) {
  if (typeof halfCloseProbeAnswers !== 'boolean') throw new TypeError('forwardUnix: halfCloseProbeAnswers must be a boolean');
  // #286: the keep-alive of a half-closed local service on another machine (default 30 s), as the host's `halfCloseProbeRemoteMs`
  const probeRemoteMs = halfCloseProbeRemoteMs === undefined ? 30_000 : assertHalfCloseProbeMs(halfCloseProbeRemoteMs, 'forwardUnix: halfCloseProbeRemoteMs');
  const probeAnswers = halfCloseProbeAnswers;
  const l = parseEndpoint(local);
  const r = parseEndpoint(remote);
  const probeMs = assertHalfCloseProbeMs(halfCloseProbeMs, 'forwardUnix: halfCloseProbeMs');
  if (l.kind === 'endpoint') throw new TypeError('forwardUnix: the local end cannot be a named endpoint (a host offers those; it is the remote end)');
  if (maxConnections !== undefined && !(Number.isInteger(maxConnections) && maxConnections > 0)) throw new TypeError('forwardUnix: maxConnections must be a positive integer');
  // A bound on concurrent connections: the CLI's 128 for a named endpoint; the other forwards stay unbounded unless asked.
  const limit = maxConnections ?? (r.kind === 'endpoint' ? DEFAULT_MAX_ENDPOINT_CONNECTIONS : Infinity);
  // An error callback must never take the forward down.
  const report = (e) => { try { onError(e); } catch { /* the caller's callback threw */ } };

  if (reverse) {
    if (r.kind === 'endpoint') throw new TypeError('forwardUnix: a named endpoint is something a host offers; the host cannot listen on one');
    if (r.kind !== 'unix') throw new TypeError('forwardUnix: with reverse: true the remote end must be a socket path (the host listens on it)');
    const rconns = new Set();
    const handle = await client.listenUnix(r.path, {
      replace,
      onConnection: (duplex) => {
        const sock = l.kind === 'unix' ? net.connect({ path: l.path, allowHalfOpen: true }) : net.connect({ host: l.host, port: l.port, allowHalfOpen: true });
        rconns.add(sock);
        sock.once('close', () => { rconns.delete(sock); });
        sock.pause();
        // The local end of a REVERSE forward is a service (it answers): one that finished and closed completely is the ordinary end
        // of a response, and the caller may still be reading it. A `discarded` close would drop what the caller has not read, so it is
        // watched only when the host and this client both stated `gateway-lossless-close` (#286): the close is then `released`, which loses
        // nothing. `halfCloseProbeAnswers: false` (or `halfCloseProbeMs: 0`) keeps it unwatched.
        const watchService = probeMs > 0 && probeAnswers && duplex.lossless === true;
        sock.once('connect', () => { pipe(sock, duplex, watchService ? { probeMs, answering: true, remoteMs: probeRemoteMs } : undefined); sock.resume(); });
        // Only a failure to reach the local service is reported; a socket that ends later (EPIPE, a reset) is just the end of that connection.
        const failed = (e) => { sock.off('connect', failed); duplex.destroy(); report(e); };
        sock.once('error', failed);
        sock.once('connect', () => sock.off('error', failed));
      },
    });
    return {
      local, remote,
      /** Connections open now (the host's callers that are being served by the local service). */
      get connections() { return rconns.size; },
      close: () => handle.close(),
    };
  }

  if (r.kind === 'endpoint' && !client.hasFeature('gateway-endpoints')) {
    throw new Error('forwardEndpoint: this host does not offer named endpoints (it did not advertise gateway-endpoints)');
  }
  const { server, close: closeListener } = await listenLocal(l, { replace });
  const open = r.kind === 'unix' ? () => client.openUnix(r.path) : r.kind === 'endpoint' ? () => client.openEndpoint(r.name) : () => client.openTcp(r.host, r.port);
  const conns = new Set(); // a net.Server has no closeAllConnections(): keep our own list, so close() can end them
  server.on('connection', async (sock) => {
    sock.on('error', () => {});
    if (conns.size >= limit) { sock.destroy(); report(new Error(`forward ${local} -> ${remote}: more than ${limit} connections are open; refusing another`)); return; }
    conns.add(sock);
    sock.once('close', () => { conns.delete(sock); });
    let duplex;
    try { duplex = await open(); } catch (e) { sock.destroy(); report(e); return; }
    if (sock.destroyed) { duplex.destroy(); return; }
    pipe(sock, duplex, { probeMs, onGone: report });
    sock.resume();
  });
  server.on('error', report);
  return {
    // A unix socket reports the path that was asked for: the server itself knows the private name it was bound to.
    local, remote, ...(r.kind === 'endpoint' ? { endpoint: r.name } : {}), address: l.kind === 'unix' ? l.path : server.address(),
    ...(limit === Infinity ? {} : { maxConnections: limit }),
    /** Connections open now (counted against `maxConnections`). */
    get connections() { return conns.size; },
    async close() {
      const closing = closeListener(); // stops accepting at once; resolves when the server is closed and what it made is removed
      for (const s of conns) s.destroy();
      await closing;
    },
  };
}
