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
 * `@fails-components/webtransport` (and its native HTTP/3 transport package)
 * are optional peers, imported only when `webTransport` is given.
 */

import { randomBytes } from 'node:crypto';
import { FrameDecoder, frameEncode } from '../cbor.mjs';
import { generateSelfSignedCertificate } from './self-signed.mjs';

const DEFAULT_PATH = '/wsh';

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
 * @returns {Promise<{ port: number, host: string, path: string, certificateHash: Uint8Array | null, certificateHashHex: string | null, notAfter: Date | null, close(): Promise<void> }>}
 */
export async function startWebTransport({ options, host, attach, log }) {
  const { port = 0, path = DEFAULT_PATH, selfSigned = false } = options;
  let { cert, privKey } = options;
  let generated = null;
  if (selfSigned) {
    if (cert || privKey) throw new TypeError('createWshServer: webTransport takes either selfSigned or cert/privKey, not both');
    generated = generateSelfSignedCertificate(typeof selfSigned === 'object' ? selfSigned : {});
    ({ cert, privKey } = generated);
  }
  if (!cert || !privKey) throw new TypeError('createWshServer: webTransport needs cert and privKey (PEM), or selfSigned: true');
  if (typeof path !== 'string' || !path.startsWith('/')) throw new TypeError('createWshServer: webTransport.path must start with "/"');

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

  const server = new wtLib.Http3Server({
    port, host: options.host ?? host, secret: options.secret ?? randomBytes(16).toString('hex'), cert, privKey,
  });
  const sessions = server.sessionStream(path);
  server.startServer();
  try {
    await server.ready;
  } catch (err) {
    try { server.stopServer(); } catch { /* never started */ }
    throw err;
  }
  const addr = server.address();

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

  const bound = {
    port: addr.port,
    host: addr.host,
    path,
    certificateHash: generated?.hash ?? null,
    certificateHashHex: generated?.hashHex ?? null,
    notAfter: generated?.notAfter ?? null,
    async close() {
      closing = true;
      const open = [...live];
      for (const s of open) { try { s.close(); } catch { /* gone */ } }
      // Let the close reach the peers before the socket is torn down (bounded: a peer that never acks cannot hold shutdown).
      await Promise.race([
        Promise.allSettled(open.map((s) => s.closed)),
        new Promise((r) => { const t = setTimeout(r, 500); t.unref?.(); }),
      ]);
      live.clear();
      try { server.stopServer(); } catch { /* already stopped */ }
    },
  };
  log(`webtransport listening on https://${addr.host}:${addr.port}${path}`
    + (generated ? ` (self-signed, sha-256 ${generated.hashHex}, until ${generated.notAfter.toISOString()})` : ''));
  return bound;
}
