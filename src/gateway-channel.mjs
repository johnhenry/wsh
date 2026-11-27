/**
 * One gateway connection's data path with flow control, shared by both ends: the Node host (a TCP or unix socket is
 * attached to it), the host's named endpoints (the embedder gets its streams), and the client (`openUnix()` and
 * friends hand the application its streams). Browser-safe: no `node:*` import.
 *
 * Wire behaviour (spec: `GatewayCredit`, feature "gateway-credit"):
 *  - With `credit` on, each direction starts with `window` bytes of credit. `write()` sends only while it holds credit
 *    and waits for a `GatewayCredit` otherwise; the receiving side returns credit (`sendCredit`) as its application
 *    consumes data, so a slow reader stops the sender instead of growing a buffer. A peer that sends beyond the
 *    credit it was given has broken the protocol and the connection is closed.
 *  - With `credit` off (a peer that predates the feature), nothing is metered on the wire: `write()` still waits for
 *    the transport to accept each frame (the QMux window), and what the peer sends is bounded by `maxQueued` (this
 *    connection) and `budget` (all of this client's connections): exceeding either closes the connection.
 *
 * GatewayClose is a half-close, as it always was for the host: the side that sends it sends no more data, and goes on
 * receiving until the peer's own GatewayClose arrives. The connection is over when both have been sent (or on `destroy()`).
 * A half-closed connection stays open as long as anything moves: it is ended only when nothing has moved in EITHER
 * direction (data either way, credit either way) for `halfCloseIdleMs`, so a peer that half-closed and never reads is
 * reaped, and one that is merely slow to answer is not.
 *
 * Wire side: `receive(bytes)` for a GatewayData, `grant(n)` for a GatewayCredit, `remoteClosed(reason)` for a
 * GatewayClose. Application side: `write(bytes)`, `consumed(n)`, `end(reason)`, `destroy()`, or `streams()` for web streams.
 */

/** Credit each direction of a connection starts with when "gateway-credit" is negotiated (a protocol constant). */
export const GATEWAY_CREDIT_WINDOW = 262144;
/** Feature string: the client lists it in `Hello.features`, the host in `ServerHello.features`; both = credit is on. */
export const GATEWAY_CREDIT_FEATURE = 'gateway-credit';
/** A half-closed connection with nothing moving in either direction for this long is ended (`halfCloseIdleMs`; 0 turns it off). */
export const DEFAULT_HALF_CLOSE_IDLE_MS = 300_000;

/** `halfCloseIdleMs` as an option: a non-negative integer number of milliseconds (a timer cannot wait longer than 2^31 - 1). Undefined = the default. */
export function assertHalfCloseIdleMs(v, what = 'halfCloseIdleMs') {
  if (v === undefined) return DEFAULT_HALF_CLOSE_IDLE_MS;
  if (!Number.isInteger(v) || v < 0 || v > 0x7fffffff) throw new TypeError(`${what} must be an integer number of milliseconds from 0 (never) to 2147483647`);
  return v;
}

/**
 * How often a socket that this side holds, and whose peer has half-closed (sent its FIN), is checked for a peer that has gone
 * away (`halfCloseProbeMs`; 0 turns it off). The kernel tells a socket nothing about a peer that half-closed and then died
 * until something is written to it, so a Node socket is probed with a zero-length write (it delivers nothing to a live peer).
 */
export const DEFAULT_HALF_CLOSE_PROBE_MS = 2000;

/** `halfCloseProbeMs` as an option: a non-negative integer number of milliseconds (a timer cannot wait longer than 2^31 - 1). Undefined = the default. */
export function assertHalfCloseProbeMs(v, what = 'halfCloseProbeMs') {
  if (v === undefined) return DEFAULT_HALF_CLOSE_PROBE_MS;
  if (!Number.isInteger(v) || v < 0 || v > 0x7fffffff) throw new TypeError(`${what} must be an integer number of milliseconds from 0 (never) to 2147483647`);
  return v;
}

/**
 * The reason a side puts on its GatewayClose when it has DISCARDED the connection (`destroy()` with no reason of its own: a
 * local socket that closed or was reset, a stream that was dropped, an origin that is gone): it will read nothing more, so
 * the peer ends its own direction too instead of waiting for the idle bound. A GatewayClose without it is a half-close. A
 * peer that predates this just sees a reason string; one that sees it from an older peer is on the half-close rule.
 * A side that had ALREADY sent its close (half-closed) and is then destroyed sends it as a second GatewayClose, while the
 * peer has not closed; a peer that predates this ignores a repeated close.
 */
export const GATEWAY_DISCARDED = 'discarded';

/** The feature (#286) a side states in `Hello.features` / `ServerHello.features` (behind a relay: `ReverseConnect.features` / `ReverseAccept.features`) when it understands the reason `released`. */
export const GATEWAY_LOSSLESS_FEATURE = 'gateway-lossless-close';

/**
 * Behind a relay the statement of an operator travels in `ReverseConnect.features`, which a relay can drop or add. So a host answers it: it lists this in
 * `ReverseAccept.features` ONLY when it actually received the operator's `gateway-lossless-close`, and an operator treats the feature as negotiated for a
 * bridge only when it stated it AND got this back (the host: only when it received the statement). A relay that strips the statement therefore leaves
 * both sides on the earlier behaviour. (A relay that ADDS one an operator never made makes the host believe in it; the operator, which did not state it,
 * treats `released` as an ordinary reason. Nothing is lost either way; see COMPATIBILITY.md.)
 */
export const GATEWAY_LOSSLESS_ACK_FEATURE = 'gateway-lossless-close-ack';

/**
 * The reason on a GatewayClose that RELEASES the connection (#286, only to a peer that stated `gateway-lossless-close`): "I will read nothing more and
 * send nothing more; deliver what you already sent, in order, then finish." Where `discarded` makes the receiver drop what it has received and not yet
 * read (the sender is gone and nobody will read it), `released` loses nothing: it is what the side that holds an ANSWERING socket (an origin the host
 * dialled, the local service of a reverse forward) sends when that socket has half-closed and vanished, since a server that sent its whole answer and
 * closed completely looks exactly like that. Sent as the second close of a connection whose first close was already sent, or as the first close.
 * A peer that did not state the feature never receives it.
 */
export const GATEWAY_RELEASED = 'released';

/** Largest GatewayData payload this implementation sends. */
export const GATEWAY_MAX_FRAME = 65536;

/**
 * @typedef {object} GatewayChannelOptions
 * @property {number} id gateway_id
 * @property {boolean} [credit=false] metered by GatewayCredit
 * @property {number} [window=GATEWAY_CREDIT_WINDOW]
 * @property {number} [maxQueued=4194304] bytes received and not yet consumed before the connection is closed
 * @property {{ used: number, max: number }} [budget] shared by all of a client's connections (`used` is kept by the channel)
 * @property {boolean} [writeAfterRemoteClose=false] keep accepting `write()` after the peer's GatewayClose (the host's origin may still answer)
 * @property {number} [halfCloseIdleMs=0] a connection that is half-closed (one GatewayClose sent or received, not both) and has
 *   had no traffic in either direction for this long is destroyed with the reason "idle timeout" (0 = never)
 * @property {(bytes: Uint8Array) => Promise<unknown> | unknown} sendData
 * @property {(n: number) => unknown} sendCredit
 * @property {(reason?: string) => unknown} sendClose
 * @property {(bytes: Uint8Array) => void} [onData] sink mode: receive() calls this instead of queueing for `streams().readable`
 * @property {(reason?: string) => void} [onRemoteClose] the peer sent GatewayClose (it will send no more data)
 * @property {(reason?: string, graceful?: boolean) => void} [onClose] called once, when the connection is over; `graceful` is true when
 *   both sides finished by themselves (each sent its GatewayClose, no discard, no error, no idle bound, no destroy)
 */

export class GatewayChannel {
  #o;
  #sendCredit;
  #peerWindow;
  #unacked = 0;
  #queue = [];
  #queued = 0;
  #peakQueued = 0;
  #waiter = null;
  #creditWaiters = [];
  #sentClose = false;
  #gotClose = false;
  /** The peer's FIRST close was a discard: it reads nothing more, so nothing queued for it is worth delivering. */
  #discarded = false;
  /** The peer released the connection (#286): it reads nothing more, but what it already sent is still delivered. */
  #released = false;
  #finished = false;
  #idleTimer = null;
  #lastActive = 0;
  #streams = null;
  #closedPromise;
  #resolveClosed;

  /** @param {GatewayChannelOptions} o */
  constructor(o) {
    this.#o = { window: GATEWAY_CREDIT_WINDOW, maxQueued: 4 * 1024 * 1024, credit: false, writeAfterRemoteClose: false, halfCloseIdleMs: 0, lossless: false, ...o };
    this.#sendCredit = this.#o.credit ? this.#o.window : Infinity;
    this.#peerWindow = this.#o.credit ? this.#o.window : Infinity;
    this.#closedPromise = new Promise((r) => { this.#resolveClosed = r; });
  }

  get id() { return this.#o.id; }
  /** True once the connection is over. */
  get closed() { return this.#finished; }
  /** True once the peer's GatewayClose arrived. */
  get remoteEnded() { return this.#gotClose; }
  /** Resolves (with the close reason, if any) once the connection is over. */
  get closedPromise() { return this.#closedPromise; }
  /** Bytes received and not yet consumed. */
  get queuedBytes() { return this.#queued; }
  /** The most bytes this connection has ever held received and not yet consumed (what the credit window bounds). */
  get peakQueuedBytes() { return this.#peakQueued; }

  // ── wire side ──────────────────────────────────────────────────────

  /** A GatewayData arrived. */
  receive(bytes) {
    if (this.#finished || this.#gotClose) return;
    const n = bytes.byteLength;
    if (n === 0) return;
    if (this.#o.credit) {
      this.#peerWindow -= n;
      if (this.#peerWindow < 0) return this.#violate('peer exceeded its credit');
    }
    const budget = this.#o.budget;
    if (this.#queued + n > this.#o.maxQueued || (budget && budget.used + n > budget.max)) return this.#violate('buffer limit exceeded');
    this.#queued += n;
    if (this.#queued > this.#peakQueued) this.#peakQueued = this.#queued;
    if (budget) budget.used += n;
    this.#lastActive = Date.now();
    if (this.#o.onData) { this.#o.onData(bytes); return; }
    this.#queue.push(bytes);
    this.#waiter?.();
  }

  /** A GatewayCredit arrived. */
  grant(n) {
    if (!this.#o.credit || this.#finished || !Number.isFinite(n) || n <= 0) return;
    this.#sendCredit = Math.min(this.#sendCredit + n, Number.MAX_SAFE_INTEGER);
    this.#lastActive = Date.now();
    this.#wakeWriters();
  }

  /** A GatewayClose arrived: no more data comes (queued data can still be read). */
  remoteClosed(reason) {
    if (this.#finished) return;
    // `released` means something only between two sides that both stated `gateway-lossless-close`; to any other it is an ordinary reason text.
    const released = reason === GATEWAY_RELEASED && this.#o.lossless;
    if (this.#gotClose && released) {
      // (a connection the peer already DISCARDED stays a discard)
      if (!this.#released && !this.#discarded) this.#peerReleased();
      return;
    }
    if (this.#gotClose) {
      // A SECOND GatewayClose with "discarded": the peer had half-closed and has now lost its reader. It reads nothing
      // more, so the connection is over at once, as after a reset: what it sent and nothing here has read is dropped (an
      // application that never reads must not keep the slot). Anything else repeated is ignored, as it always was.
      if (reason === GATEWAY_DISCARDED && !this.#sentClose) { this.#sentClose = true; this.#finish(reason); }
      return;
    }
    this.#gotClose = true;
    // The peer discarded the connection (it reads nothing more): our direction is over too. Anything already received can
    // still be read; our writers fail; no GatewayClose goes back.
    if (reason === GATEWAY_DISCARDED && !this.#sentClose) { this.#sentClose = true; this.#discarded = true; this.#wakeWriters(); }
    this.#waiter?.();
    try { this.#o.onRemoteClose?.(reason); } catch { /* the application's problem */ }
    if (!this.#o.writeAfterRemoteClose) this.#wakeWriters();
    if (released) { this.#peerReleased(); return; }
    if (this.#sentClose) { if (this.#queue.length === 0) this.#finish(reason, !this.#discarded); return; }
    this.#watchIdle();
  }

  /**
   * The peer released the connection (#286): it reads nothing more and sends nothing more. Everything it sent before is already here (one ordered
   * stream), so it is delivered, in order; our writes fail and no close goes back; the connection ends once the application has taken the last of it
   * (at once if nothing is waiting). An application that never reads is bounded by the idle rule, as any half-closed connection is.
   */
  #peerReleased() {
    this.#released = true;
    this.#sentClose = true;
    this.#wakeWriters();
    this.#waiter?.();
    if (this.#queue.length === 0) this.#finish(GATEWAY_RELEASED, true);
    else this.#watchIdle();
  }

  /** The peer released the connection (#286): it reads nothing more, and what it sent is still being delivered. */
  get peerReleased() { return this.#released; }

  /** Does this connection use the lossless close (both ends stated `gateway-lossless-close`)? Only then may it be released. */
  get lossless() { return this.#o.lossless; }

  /**
   * The answering socket of this connection (an origin, a reverse forward's local service) has half-closed and vanished (#286): say so with `released`
   * and end the connection here. Against a peer that did not state the feature this is a discard, as it always was (a caller never releases).
   */
  release() {
    if (this.#finished) return;
    if (!this.#o.lossless) { this.destroy(); return; }
    if (!this.#sentClose || !this.#gotClose) {
      this.#sentClose = true;
      try { void this.#o.sendClose(GATEWAY_RELEASED); } catch { /* gone */ }
    }
    this.#finish(GATEWAY_RELEASED);
  }

  /**
   * Half-closed: arm the idle rule. One timer; traffic only stamps `#lastActive`, and the timer re-arms for what is left
   * of the bound when it fires, so a busy connection costs no timer churn.
   */
  #watchIdle() {
    const ms = this.#o.halfCloseIdleMs;
    this.#lastActive = Date.now();
    if (!(ms > 0) || this.#idleTimer || this.#finished) return;
    const check = () => {
      this.#idleTimer = null;
      if (this.#finished) return;
      const left = this.#lastActive + ms - Date.now();
      if (left > 0) { this.#idleTimer = setTimeout(check, left); this.#idleTimer.unref?.(); return; }
      this.destroy('idle timeout');
    };
    this.#idleTimer = setTimeout(check, ms);
    this.#idleTimer.unref?.();
  }

  // ── application side ───────────────────────────────────────────────

  /**
   * Send `bytes` to the peer: waits for credit (when metered) and for the transport to accept each frame. Resolves
   * when all of it has been handed over; rejects if the connection can no longer carry it.
   */
  async write(bytes) {
    let off = 0;
    while (off < bytes.byteLength) {
      this.#assertWritable();
      let n = Math.min(bytes.byteLength - off, GATEWAY_MAX_FRAME);
      if (this.#o.credit) {
        while (this.#sendCredit <= 0) {
          this.#assertWritable();
          await new Promise((resolve) => this.#creditWaiters.push(resolve));
        }
        this.#assertWritable();
        n = Math.min(n, this.#sendCredit);
        this.#sendCredit -= n;
      }
      await this.#o.sendData(bytes.subarray(off, off + n));
      this.#lastActive = Date.now();
      off += n;
    }
  }

  #assertWritable() {
    if (this.#finished || this.#sentClose || (this.#gotClose && !this.#o.writeAfterRemoteClose)) throw new Error('gateway connection closed');
  }

  /** The application has taken `n` received bytes: returns credit to the peer, and frees queue and budget. */
  consumed(n) {
    if (n <= 0) return;
    const taken = Math.min(n, this.#queued);
    this.#queued -= taken;
    this.#lastActive = Date.now();
    if (this.#o.budget) this.#o.budget.used -= taken;
    if (this.#o.credit && !this.#finished && !this.#gotClose) {
      this.#unacked += taken;
      if (this.#unacked >= this.#o.window / 2) {
        const give = this.#unacked;
        this.#unacked = 0;
        this.#peerWindow += give;
        try { void this.#o.sendCredit(give); } catch { /* transport gone */ }
      }
    }
  }

  /** We are done sending: GatewayClose goes out once. The connection is over when the peer's arrives too. */
  end(reason) {
    if (this.#finished || this.#sentClose) return;
    this.#sentClose = true;
    try { void this.#o.sendClose(reason); } catch { /* transport gone */ }
    this.#wakeWriters();
    if (this.#gotClose && this.#queue.length === 0) this.#finish(reason, true);
    else if (!this.#gotClose) this.#watchIdle(); // the peer owes us its own GatewayClose; it may take as long as it likes while bytes move
  }

  /**
   * Tear down at once; sends GatewayClose first if we had not. If we HAD half-closed and the peer has not, the peer is
   * still holding its direction open for us: a second GatewayClose with "discarded" tells it we read nothing more (as a
   * reset tells a sender its reader is gone). When the peer had closed too, the connection is over and nothing is sent.
   */
  destroy(reason) {
    if (this.#finished) return;
    if (!this.#sentClose) { this.#sentClose = true; try { void this.#o.sendClose(reason ?? GATEWAY_DISCARDED); } catch { /* gone */ } }
    else if (!this.#gotClose) { try { void this.#o.sendClose(GATEWAY_DISCARDED); } catch { /* gone */ } }
    this.#finish(reason);
  }

  /** The transport went away: finish without sending anything. */
  abandon(reason) {
    if (this.#finished) return;
    this.#sentClose = true;
    this.#finish(reason);
  }

  /**
   * Web streams over the connection: `readable` yields what the peer sends (credit is returned as it is read, so a
   * slow reader stops the peer), `writable` sends (its writes wait for credit). Closing `writable` half-closes;
   * cancelling `readable` or aborting `writable` destroys the connection.
   * @returns {{ readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array> }}
   */
  streams() {
    if (this.#streams) return this.#streams;
    const self = this;
    const readable = new ReadableStream({
      async pull(controller) {
        while (self.#queue.length === 0 && !self.#gotClose && !self.#finished) await new Promise((r) => { self.#waiter = r; });
        self.#waiter = null;
        if (self.#queue.length) {
          const chunk = self.#queue.shift();
          controller.enqueue(chunk);
          self.consumed(chunk.byteLength);
          return;
        }
        controller.close();
        if (self.#sentClose) self.#finish(self.#released ? GATEWAY_RELEASED : undefined, !self.#discarded);
      },
      cancel(reason) { self.destroy(typeof reason === 'string' ? reason : undefined); },
    }, { highWaterMark: 0 });
    const writable = new WritableStream({
      write(chunk) { return self.write(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)); },
      close() { self.end(); },
      abort(reason) { self.destroy(typeof reason === 'string' ? reason : undefined); },
    });
    this.#streams = { readable, writable };
    return this.#streams;
  }

  // ── internals ──────────────────────────────────────────────────────

  #violate(reason) { this.destroy(reason); }

  #wakeWriters() {
    for (const w of this.#creditWaiters.splice(0)) w(); // write() re-checks and throws or continues
  }

  /** @param {boolean} [graceful] both sides finished by themselves: nothing was discarded, so what was handed to a sink is still to be delivered */
  #finish(reason, graceful = false) {
    if (this.#finished) return;
    this.#finished = true;
    clearTimeout(this.#idleTimer);
    this.#idleTimer = null;
    if (this.#o.budget) this.#o.budget.used -= this.#queued;
    this.#queued = 0;
    this.#queue = [];
    this.#waiter?.();
    this.#wakeWriters();
    try { this.#o.onClose?.(reason, graceful); } catch { /* the application's problem */ }
    this.#resolveClosed(reason);
  }
}
