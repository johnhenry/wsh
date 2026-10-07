/**
 * WebTransport listener for `@johnhenry/wsh/server` (`createWshServer({ webTransport })`).
 *
 * QUIC already multiplexes, so the QMux layer the WebSocket path needs is not
 * used. A session's FIRST bidirectional stream is the control stream (the
 * client's `WebTransportTransport` opens it first): length-prefixed CBOR
 * frames, exactly what `frameEncode` / `FrameDecoder` speak. Every later
 * bidirectional stream the client opens is a data stream, bound to the next
 * exec channel in `OpenOk` order like a QMux one.
 *
 * Streams a client creates are visible to the host the moment they are
 * created (HTTP/3 sends the stream's WebTransport header with it), so the
 * host's `stream-announce` feature holds here as it does over QMux: the
 * client writes no primer.
 *
 * A `selfSigned` certificate is rotated (see `startWebTransport`): the next one
 * is generated and published (`certificateHashes()`) ahead of time, and the
 * listener is switched to it shortly before the current one expires.
 *
 * `@fails-components/webtransport` (and its native HTTP/3 transport package)
 * are optional peers, imported only when `webTransport` is given.
 */

import { randomBytes } from 'node:crypto';
import { FrameDecoder, frameEncode } from '../cbor.mjs';
import { generateSelfSignedCertificate } from './self-signed.mjs';

const DEFAULT_PATH = '/wsh';
const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
/** setTimeout cannot wait longer than this (a 32-bit signed millisecond count). */
const MAX_TIMER_MS = 2 ** 31 - 1;

/** What a QMux stream looks like to the connection code, over a WebTransport bidirectional stream. */
function adaptStream({ readable, writable }, onGone) {
  const writer = writable.getWriter();
  const reader = readable.getReader();
  const stream = {
    onData: null,
    onEnd: null,
    onReset: null,
    write: (bytes) => writer.write(bytes),
    close: async () => { try { await writer.close(); } catch { /* peer gone or already closed */ } },
    /** Start delivering: after the consumer has had the chance to set its handlers. */
    start() {
      (async () => {
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) { stream.onEnd?.(); return; }
            stream.onData?.(value);
          }
        } catch {
          stream.onReset?.();
        } finally {
          onGone?.();
        }
      })();
    },
  };
  return stream;
}

/**
 * @param {object} opts
 * @param {object} opts.options - `createWshServer`'s `webTransport` option
 * @param {string} opts.host
 * @param {(opts: object) => { receiveMessage: Function, bindStream: Function, close: Function }} opts.attach
 * @param {(line: string) => void} opts.log
 * @returns {Promise<{ port: number, host: string, path: string, certificateHash: Uint8Array | null, certificateHashHex: string | null, notAfter: Date | null,
 *   certificateHashes(): object[], certificates(): object[], rotateCertificate(opts?: { activate?: boolean }): Promise<object>, close(): Promise<void> }>}
 */
export async function startWebTransport({ options, host, attach, log }) {
  const { port = 0, path = DEFAULT_PATH, selfSigned = false } = options;
  let { cert, privKey } = options;
  const certOpts = typeof selfSigned === 'object' ? selfSigned : {};
  const { rotate = true, prepareBeforeMs: prepareOpt, activateBeforeMs: activateOpt, ...generateOpts } = certOpts;
  /** The certificate being presented, and the next one once it has been generated (both only for `selfSigned`). */
  let current = null;
  let next = null;
  if (selfSigned) {
    if (cert || privKey) throw new TypeError('createWshServer: webTransport takes either selfSigned or cert/privKey, not both');
    current = generateSelfSignedCertificate(generateOpts);
    ({ cert, privKey } = current);
  }
  if (!cert || !privKey) throw new TypeError('createWshServer: webTransport needs cert and privKey (PEM), or selfSigned: true');
  if (typeof path !== 'string' || !path.startsWith('/')) throw new TypeError('createWshServer: webTransport.path must start with "/"');
  for (const [name, v] of [['prepareBeforeMs', prepareOpt], ['activateBeforeMs', activateOpt]]) {
    if (v !== undefined && !(Number.isFinite(v) && v >= 0)) throw new TypeError(`createWshServer: webTransport.selfSigned.${name} must be a non-negative number`);
  }

  let wtLib;
  try {
    wtLib = await import('@fails-components/webtransport');
    await wtLib.quicheLoaded;
  } catch (err) {
    throw new Error(
      'WebTransport needs the optional packages "@fails-components/webtransport" and '
      + '"@fails-components/webtransport-transport-http3-quiche": npm install @fails-components/webtransport @fails-components/webtransport-transport-http3-quiche',
      { cause: err },
    );
  }

  const secret = options.secret ?? randomBytes(16).toString('hex');
  const live = new Set();
  let closing = false;

  async function serve(session) {
    let conn = null;
    let closed = false;
    const end = () => { if (!closed) { closed = true; live.delete(session); conn?.close(); } };
    live.add(session);
    session.closed.then(end, end);
    try {
      await session.ready;
    } catch { end(); return; }

    let controlWriter = null;
    const decoder = new FrameDecoder();
    conn = attach({
      sendMessage: (msg) => (controlWriter ? controlWriter.write(frameEncode(msg)) : undefined),
      remote: { address: session.peerAddress, headers: session.header ?? {} },
      closeTransport: () => { try { session.close(); } catch { /* already closed */ } },
    });

    const incoming = session.incomingBidirectionalStreams.getReader();
    let first = true;
    try {
      for (;;) {
        const { done, value: bidi } = await incoming.read();
        if (done) break;
        if (first) {
          first = false;
          controlWriter = bidi.writable.getWriter();
          const reader = bidi.readable.getReader();
          (async () => {
            try {
              for (;;) {
                const { done: fin, value } = await reader.read();
                if (fin) break;
                let msgs;
                try { msgs = decoder.feed(value); } catch (e) { log(`webtransport frame decode error: ${e.message}`); break; }
                for (const m of msgs) conn.receiveMessage(m);
              }
            } catch { /* session went away */ }
            end();
          })();
        } else {
          const s = adaptStream(bidi);
          conn.bindStream(s);
          s.start();
        }
      }
    } catch { /* session closed under us */ }
    end();
  }

  /** Start an HTTP/3 listener presenting `pem` on `onPort` and feed its sessions to `serve`. */
  async function launch(pem, onPort) {
    const server = new wtLib.Http3Server({
      port: onPort, host: options.host ?? host, secret, cert: pem.cert, privKey: pem.privKey,
    });
    const sessions = server.sessionStream(path);
    server.startServer();
    try {
      await server.ready;
    } catch (err) {
      try { server.stopServer(); } catch { /* never started */ }
      throw err;
    }
    (async () => {
      const reader = sessions.getReader();
      try {
        for (;;) {
          const { done, value: session } = await reader.read();
          if (done || closing) break;
          serve(session).catch((e) => log(`webtransport session error: ${e.message}`));
        }
      } catch { /* server stopped */ }
    })();
    return { server, addr: server.address() };
  }

  /** End every live session, giving the close a moment to reach the peers. */
  async function closeLive() {
    const open = [...live];
    for (const s of open) { try { s.close(); } catch { /* gone */ } }
    // Bounded: a peer that never acks cannot hold shutdown.
    await Promise.race([
      Promise.allSettled(open.map((s) => s.closed)),
      new Promise((r) => { const t = setTimeout(r, 500); t.unref?.(); }),
    ]);
    live.clear();
  }

  let listener = await launch({ cert, privKey }, port);
  const boundPort = listener.addr.port;

  // ── Rotation (selfSigned only) ─────────────────────────────────────
  //
  // A pinned certificate cannot simply be renewed: clients pin its hash, and a
  // browser takes no certificate valid for more than 14 days, so a long-running
  // server would stop being reachable at `notAfter`. Instead the next
  // certificate is generated AHEAD of time and its hash is published next to the
  // current one (`certificateHashes()`), so a client that re-reads the list
  // during the overlap window pins both and survives the switch. The listener
  // presents one certificate at a time (the native transport cannot swap one in
  // place, so the switch restarts it on the same port: sessions end, clients
  // reconnect).
  let prepareTimer = null;
  let activateTimer = null;
  let chain = Promise.resolve();
  const serial = (fn) => { const run = chain.then(fn); chain = run.catch(() => {}); return run; };

  const validityOf = (c) => c.notAfter.getTime() - c.notBefore.getTime();
  const prepareBeforeMs = () => prepareOpt ?? Math.min(3 * DAY_MS, validityOf(current) / 3);
  const activateBeforeMs = () => activateOpt ?? Math.min(HOUR_MS, validityOf(current) / 6);
  const clearTimers = () => { clearTimeout(prepareTimer); clearTimeout(activateTimer); prepareTimer = activateTimer = null; };
  const later = (fn, at) => {
    // Long waits are re-armed: a timer cannot exceed ~24.8 days, and a sleeping machine fires late, so re-check on wake.
    const wait = Math.max(0, at - Date.now());
    const t = setTimeout(() => (wait > MAX_TIMER_MS ? later(fn, at) : fn()), Math.min(wait, MAX_TIMER_MS));
    t.unref?.();
    return t;
  };

  function schedule() {
    clearTimers();
    if (!current || !rotate || closing) return;
    if (!next) {
      prepareTimer = later(() => { rotateCertificate().catch((e) => log(`webtransport: preparing the next certificate failed: ${e.message}`)); }, current.notAfter.getTime() - prepareBeforeMs());
    } else {
      activateTimer = later(() => { rotateCertificate({ activate: true }).catch((e) => log(`webtransport: certificate rotation failed: ${e.message}`)); }, current.notAfter.getTime() - activateBeforeMs());
    }
  }

  function prepare() {
    if (next) return;
    next = generateSelfSignedCertificate(generateOpts);
    log(`webtransport: next certificate ready, sha-256 ${next.hashHex} (current ${current.hashHex} until ${current.notAfter.toISOString()})`);
  }

  async function activate() {
    prepare();
    const incoming = next;
    await closeLive();
    try { listener.server.stopServer(); } catch { /* already stopped */ }
    // The UDP port may take a moment to come free.
    let lastErr;
    for (let attempt = 0; attempt < 20; attempt++) {
      try {
        listener = await launch(incoming, boundPort);
        lastErr = null;
        break;
      } catch (err) {
        lastErr = err;
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    if (lastErr) throw new Error(`could not restart the WebTransport listener on port ${boundPort} with the new certificate: ${lastErr.message}`, { cause: lastErr });
    const old = current;
    current = incoming;
    next = null;
    log(`webtransport: now presenting certificate sha-256 ${current.hashHex} until ${current.notAfter.toISOString()} (replaced ${old.hashHex})`);
  }

  /**
   * Start a rotation: generate the next certificate if there is none yet and publish its hash
   * (`certificateHashes()` = [current, next]). With `activate`, also switch to it now (live sessions
   * end); otherwise it is switched to shortly before the current one expires.
   */
  function rotateCertificate({ activate: now = false } = {}) {
    if (!current) return Promise.reject(new Error('rotateCertificate: only a selfSigned certificate is rotated (supply a new cert by restarting the server)'));
    return serial(async () => {
      if (closing) throw new Error('rotateCertificate: the listener is closed');
      if (now) await activate(); else prepare();
      schedule();
      return { current: describe(current, true), next: next ? describe(next, false) : null };
    });
  }

  const describe = (c, active) => ({ hash: c.hash, hashHex: c.hashHex, notBefore: c.notBefore, notAfter: c.notAfter, active });
  schedule();

  const bound = {
    port: boundPort,
    host: listener.addr.host,
    path,
    get certificateHash() { return current?.hash ?? null; },
    get certificateHashHex() { return current?.hashHex ?? null; },
    get notAfter() { return current?.notAfter ?? null; },
    /** `serverCertificateHashes` for a client: the current certificate and, during an overlap, the next. */
    certificateHashes() { return [current, next].filter(Boolean).map((c) => ({ algorithm: 'sha-256', value: c.hash })); },
    /** The same, with validity and which one is being presented. */
    certificates() { return [current && describe(current, true), next && describe(next, false)].filter(Boolean); },
    rotateCertificate,
    async close() {
      closing = true;
      clearTimers();
      await chain.catch(() => {});
      await closeLive();
      try { listener.server.stopServer(); } catch { /* already stopped */ }
    },
  };
  log(`webtransport listening on https://${listener.addr.host}:${boundPort}${path}`
    + (current ? ` (self-signed, sha-256 ${current.hashHex}, until ${current.notAfter.toISOString()}${rotate ? '' : ', not rotated'})` : ''));
  return bound;
}
