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
 *
 * Wire side: `receive(bytes)` for a GatewayData, `grant(n)` for a GatewayCredit, `remoteClosed(reason)` for a
 * GatewayClose. Application side: `write(bytes)`, `consumed(n)`, `end(reason)`, `destroy()`, or `streams()` for web streams.
 */

/** Credit each direction of a connection starts with when "gateway-credit" is negotiated (a protocol constant). */
export const GATEWAY_CREDIT_WINDOW = 262144;
/** Feature string: the client lists it in `Hello.features`, the host in `ServerHello.features`; both = credit is on. */
export const GATEWAY_CREDIT_FEATURE = 'gateway-credit';
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
 * @property {number} [graceMs=0] after the peer's GatewayClose, end our side too once this long has passed (0 = never)
 * @property {(bytes: Uint8Array) => Promise<unknown> | unknown} sendData
 * @property {(n: number) => unknown} sendCredit
 * @property {(reason?: string) => unknown} sendClose
 * @property {(bytes: Uint8Array) => void} [onData] sink mode: receive() calls this instead of queueing for `streams().readable`
 * @property {(reason?: string) => void} [onRemoteClose] the peer sent GatewayClose (it will send no more data)
 * @property {(reason?: string) => void} [onClose] called once, when the connection is over
 */

export class GatewayChannel {
  #o;
  #sendCredit;
  #peerWindow;
  #unacked = 0;
  #queue = [];
  #queued = 0;
  #waiter = null;
  #creditWaiters = [];
  #sentClose = false;
  #gotClose = false;
  #finished = false;
  #graceTimer = null;
  #streams = null;
  #closedPromise;
  #resolveClosed;

  /** @param {GatewayChannelOptions} o */
  constructor(o) {
    this.#o = { window: GATEWAY_CREDIT_WINDOW, maxQueued: 4 * 1024 * 1024, credit: false, writeAfterRemoteClose: false, graceMs: 0, ...o };
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
    if (budget) budget.used += n;
    if (this.#o.onData) { this.#o.onData(bytes); return; }
    this.#queue.push(bytes);
    this.#waiter?.();
  }

  /** A GatewayCredit arrived. */
  grant(n) {
    if (!this.#o.credit || this.#finished || !Number.isFinite(n) || n <= 0) return;
    this.#sendCredit = Math.min(this.#sendCredit + n, Number.MAX_SAFE_INTEGER);
    this.#wakeWriters();
  }

  /** A GatewayClose arrived: no more data comes (queued data can still be read). */
  remoteClosed(reason) {
    if (this.#finished || this.#gotClose) return;
    this.#gotClose = true;
    this.#waiter?.();
    try { this.#o.onRemoteClose?.(reason); } catch { /* the application's problem */ }
    if (!this.#o.writeAfterRemoteClose) this.#wakeWriters();
    if (this.#sentClose) { if (this.#queue.length === 0) this.#finish(reason); return; }
    if (this.#o.graceMs > 0) {
      clearTimeout(this.#graceTimer);
      this.#graceTimer = setTimeout(() => this.end('grace period over'), this.#o.graceMs);
      this.#graceTimer.unref?.();
    }
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
    if (this.#gotClose && this.#queue.length === 0) this.#finish(reason);
    else if (!this.#gotClose && this.#o.graceMs > 0) {
      // The peer owes us its own GatewayClose; a peer that never sends it must not hold the slot forever.
      this.#graceTimer = setTimeout(() => this.destroy('grace period over'), this.#o.graceMs);
      this.#graceTimer.unref?.();
    }
  }

  /** Tear down at once; sends GatewayClose first if we had not. */
  destroy(reason) {
    if (this.#finished) return;
    if (!this.#sentClose) { this.#sentClose = true; try { void this.#o.sendClose(reason); } catch { /* gone */ } }
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
        if (self.#sentClose) self.#finish();
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

  #finish(reason) {
    if (this.#finished) return;
    this.#finished = true;
    clearTimeout(this.#graceTimer);
    if (this.#o.budget) this.#o.budget.used -= this.#queued;
    this.#queued = 0;
    this.#queue = [];
    this.#waiter?.();
    this.#wakeWriters();
    try { this.#o.onClose?.(reason); } catch { /* the application's problem */ }
    this.#resolveClosed(reason);
  }
}
