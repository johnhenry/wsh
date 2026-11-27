/**
 * Noticing a half-closed local peer that has gone away (#282). Node only; imports nothing, it works on the socket it is given.
 *
 * A socket whose peer sent its FIN (half-closed: it will send no more and may still read) and was then killed gives Node no event:
 * libuv stops watching a socket for input once it has read the end of file, and the kernel reports a vanished peer only to a
 * writer. So the side holding the socket looks for it, while (and only while) the socket is half-closed:
 *
 *  - a zero-length write every `probeMs`. It delivers nothing to a live peer (the peer sees no byte, no wake-up), and fails with
 *    EPIPE or ECONNRESET once the peer is gone. On a unix socket that is the moment the peer died. It is skipped while a real write is
 *    queued or the socket is draining (that write finds out by itself, and the probe must not interleave with it).
 *  - on a TCP socket, the kernel is also told to run keep-alive on a short schedule (initial delay and interval of `probeMs`
 *    rounded up to whole seconds, three probes). A peer that half-closed and exited leaves a socket behind that answers everything
 *    except data, until its kernel drops it (60 s by default on Linux and macOS); the next keep-alive probe after that is answered
 *    with a reset, the socket is then in the error state, and the next zero-length write reports it. So TCP is bounded by that
 *    kernel timeout, not by the probe. A peer that died with data unread is reset at once, and noticed within one probe interval.
 *
 * The socket is untouched for a connection that is not half-closed: no timer, no keep-alive change.
 */

const LOOPBACK = /^(127\.|::1$|::ffff:127\.)/i;

/**
 * The keep-alive schedule for a half-closed ANSWERING socket (#286): a loopback socket (or a unix one, which has none) keeps the short one of `probeMs`, a
 * socket to another machine gets `remoteMs` (a live origin behind a short network partition must not be released and the rest of the client's upload
 * dropped, where TCP retransmission would have ridden it out). `0` for `remoteMs` means the same as `probeMs`.
 */
export function answeringKeepAliveMs(sock, probeMs, remoteMs) {
  const a = sock?.remoteAddress;
  if (typeof a !== 'string' || LOOPBACK.test(a)) return probeMs;
  return remoteMs > 0 ? remoteMs : probeMs;
}

/** Sockets being watched now, for tests: a probe exists exactly while its socket is half-closed and open. */
const watching = new Set();
export const halfCloseWatchCount = () => watching.size;

/** `error.code` of what is reported when a half-closed peer went away. */
export const LOCAL_PEER_GONE = 'WSH_LOCAL_PEER_GONE';

const EMPTY = new Uint8Array(0);

/** The error reported for a half-closed peer that went away: not a failure of whatever holds the socket. */
function goneError(cause) {
  const e = new Error(`the local peer went away after finishing its side${cause?.code ? ` (${cause.code})` : ''}`, { cause });
  e.code = LOCAL_PEER_GONE;
  return e;
}

/** A write error that says the peer is gone (not "the stream was already closed", which is somebody else's doing). */
const peerGone = (err) => err && typeof err.code === 'string' && !err.code.startsWith('ERR_');

/**
 * Start watching `sock` for a half-closed peer that goes away. The watch starts when the peer's end of file is seen (now, if it
 * has been) and ends when the socket closes.
 * @param {import('node:net').Socket} sock  the connection; the caller keeps handling its own 'close' and 'error'
 * @param {number} probeMs  milliseconds between probes; 0 or less = do nothing
 * @param {(err: Error) => void} [onGone]  called once, with `code` "WSH_LOCAL_PEER_GONE", just before the socket is destroyed
 */
export function watchHalfClosed(sock, probeMs, onGone, keepAliveMs = probeMs) {
  if (!(probeMs > 0) || typeof sock?.on !== 'function') return;
  const token = {};
  let timer = null;
  let over = false;

  const stop = () => {
    over = true;
    if (timer) { clearInterval(timer); timer = null; }
    watching.delete(token);
  };
  const gone = (cause) => {
    if (over) return;
    stop();
    // The caller's callback may throw, or be an async function that rejects: neither is the watch's to raise (a rejection nobody holds ends the process).
    try { const r = onGone?.(goneError(cause)); if (typeof r?.then === 'function') r.then(undefined, () => {}); } catch { /* the caller's callback threw */ }
    sock.destroy();
  };
  const probe = () => {
    if (over) return;
    if (sock.destroyed) return stop();
    // A write is in flight or queued, or the socket was ended by us: that is not ours to interleave with or to answer.
    if (sock.writableEnded || sock.connecting || sock.writableLength > 0 || sock.writableNeedDrain) return;
    try {
      sock.write(EMPTY, (err) => { if (peerGone(err)) gone(err); });
    } catch (e) { if (peerGone(e)) gone(e); }
  };
  const arm = () => {
    if (over || timer || sock.destroyed) return;
    watching.add(token);
    if (typeof sock.remoteAddress === 'string') {
      // TCP. Whole seconds (the kernel's unit), at least one.
      const secs = Math.max(1, Math.ceil((keepAliveMs > 0 ? keepAliveMs : probeMs) / 1000));
      try { sock.setKeepAlive(true, secs * 1000, secs * 1000, 3); } catch { /* the platform refused: the probe still runs */ }
    }
    timer = setInterval(probe, probeMs);
    timer.unref?.();
  };

  sock.once('close', stop);
  sock.on('end', arm);
  if (sock.readableEnded) arm();
}
