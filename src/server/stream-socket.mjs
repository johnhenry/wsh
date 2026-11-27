/**
 * What a connection of an injected network looks like to the gateway session (#299): the few members of a Node `net.Socket` the
 * session uses, over a pair of web streams. With it the session pumps, half-closes, settles and bounds a connection of the embedder's
 * network with the very code it uses for the machine's sockets, instead of a second copy of it. Browser-safe: no `node:*`.
 *
 * Reading is one chunk at a time and only while the socket is not paused (the session pauses it until the gateway channel has taken
 * the chunk), so a client that stops reading stops the network's stream, which is the origin's own backpressure. Writing hands each
 * chunk to the stream's writer; the callback fires when the network's sink has taken it. `end()` closes the writer (a half-close);
 * `destroy()` cancels the reader, aborts the writer and calls `onDestroy` (which aborts the signal the network was given).
 */

/** The little of `EventEmitter` the session uses. */
class Emitter {
  #on = new Map();
  on(ev, fn) { (this.#on.get(ev) ?? this.#on.set(ev, []).get(ev)).push({ fn, once: false }); return this; }
  once(ev, fn) { (this.#on.get(ev) ?? this.#on.set(ev, []).get(ev)).push({ fn, once: true }); return this; }
  off(ev, fn) { const l = this.#on.get(ev); if (l) this.#on.set(ev, l.filter((e) => e.fn !== fn)); return this; }
  removeAllListeners(ev) { if (ev === undefined) this.#on.clear(); else this.#on.delete(ev); return this; }
  listenerCount(ev) { return this.#on.get(ev)?.length ?? 0; }
  emit(ev, ...args) {
    const l = this.#on.get(ev);
    if (!l?.length) return false;
    for (const e of [...l]) {
      if (e.once) this.off(ev, e.fn);
      try { e.fn(...args); } catch { /* a listener's own failure is not the stream's */ }
    }
    return true;
  }
}

/** A chunk of a network's stream as bytes, or null when it is not bytes. */
function toBytes(v) {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  return null;
}

export class StreamSocket extends Emitter {
  isStreamSocket = true;
  allowHalfOpen = true;
  destroyed = false;
  readableEnded = false;
  writableFinished = false;
  writableLength = 0;
  remoteAddress;
  remotePort;
  #reader;
  #writer;
  #paused = false;
  #flowing = false;
  #pumping = false;
  #wake = null;
  #ending = false;
  #idleMs = 0;
  #idleCb = null;
  #idleTimer = null;
  #lastActive = 0;
  #onDestroy;

  /**
   * @param {{ readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array> }} duplex  what the network handed over
   * @param {{ remoteAddress?: string, remotePort?: number, onDestroy?: () => void }} [o]
   */
  constructor(duplex, { remoteAddress = '', remotePort = 0, onDestroy } = {}) {
    super();
    if (!duplex || typeof duplex.readable?.getReader !== 'function' || typeof duplex.writable?.getWriter !== 'function') {
      throw new TypeError('the network must give { readable: ReadableStream, writable: WritableStream }');
    }
    this.#reader = duplex.readable.getReader();
    this.#writer = duplex.writable.getWriter();
    this.remoteAddress = remoteAddress;
    this.remotePort = remotePort;
    this.#onDestroy = onDestroy;
    // A stream the network errors or aborts is noticed even while nothing reads it (an inbound connection that waits to be accepted is paused): a connection the
    // network dropped is released, not held until the accept timeout.
    this.#reader.closed.catch((e) => this.#fail(e));
    this.#writer.closed.catch((e) => this.#fail(e));
  }

  setNoDelay() { return this; }

  on(ev, fn) {
    super.on(ev, fn);
    if (ev === 'data') { this.#flowing = true; void this.#pump(); }
    return this;
  }

  pause() { this.#paused = true; return this; }
  resume() { this.#paused = false; this.#wakeUp(); return this; }
  #wakeUp() { const w = this.#wake; this.#wake = null; w?.(); }

  /** Inactivity (a chunk either way) for `ms` calls `cb`; 0 turns it off. */
  setTimeout(ms, cb) {
    this.#idleMs = ms;
    this.#idleCb = cb ?? null;
    clearTimeout(this.#idleTimer);
    this.#idleTimer = null;
    if (ms > 0 && !this.destroyed) { this.#lastActive = Date.now(); this.#armIdle(ms); }
    return this;
  }

  #armIdle(ms) {
    this.#idleTimer = setTimeout(() => {
      this.#idleTimer = null;
      if (this.destroyed || !(this.#idleMs > 0)) return;
      const left = this.#lastActive + this.#idleMs - Date.now();
      if (left > 0) { this.#armIdle(left); return; }
      this.#idleCb?.();
    }, ms);
    this.#idleTimer.unref?.();
  }

  #touch() { this.#lastActive = Date.now(); }

  async #pump() {
    if (this.#pumping) return;
    this.#pumping = true;
    try {
      for (;;) {
        if (this.destroyed) return;
        if (this.#paused || !this.#flowing) { await new Promise((r) => { this.#wake = r; }); continue; }
        let r;
        try { r = await this.#reader.read(); } catch (e) { this.#fail(e); return; }
        if (this.destroyed) return;
        if (r.done) { this.readableEnded = true; this.emit('end'); this.#maybeClose(); return; }
        const bytes = toBytes(r.value);
        if (!bytes) { this.#fail(new TypeError('the network gave a chunk that is not bytes')); return; }
        if (bytes.byteLength === 0) continue;
        this.#touch();
        this.emit('data', bytes);
      }
    } finally { this.#pumping = false; }
  }

  /** @param {Uint8Array} chunk @param {(err?: Error) => void} [cb] called when the network's stream has taken the chunk */
  write(chunk, cb) {
    if (this.destroyed || this.#ending) { const e = new Error('the connection is closed'); queueMicrotask(() => cb?.(e)); return false; }
    const n = chunk.byteLength;
    this.writableLength += n;
    this.#touch();
    // A copy, as for a datagram: what the network's sink does with the buffer it is given (it may transfer or keep it) cannot reach the frame this came from.
    this.#writer.write(chunk.slice()).then(() => { this.writableLength -= n; cb?.(); }, (e) => { this.writableLength -= n; cb?.(e); this.#fail(e); });
    return true;
  }

  /** Nothing more will be written: the half-close. The reading side stays open. */
  end() {
    if (this.#ending || this.destroyed) return this;
    this.#ending = true;
    this.#writer.close().then(() => { this.writableFinished = true; this.emit('finish'); this.#maybeClose(); }, (e) => this.#fail(e));
    return this;
  }

  destroy(err) {
    if (this.destroyed) return this;
    this.destroyed = true;
    clearTimeout(this.#idleTimer);
    this.#idleTimer = null;
    this.#wakeUp();
    this.#reader.cancel(err).catch(() => {});
    this.#writer.abort(err).catch(() => {});
    try { this.#onDestroy?.(); } catch { /* the network's own */ }
    queueMicrotask(() => this.emit('close'));
    return this;
  }

  #fail(e) {
    if (this.destroyed) return;
    if (this.listenerCount('error')) this.emit('error', e);
    this.destroy(e);
  }

  /** Both directions are finished: the connection is over (a Node socket destroys itself the same way). */
  #maybeClose() { if (this.readableEnded && this.writableFinished) this.destroy(); }
}

/**
 * A UDP flow of an injected network as the session's datagram code sees a `dgram` socket: `send(bytes, cb)`, a `message` event per datagram,
 * `close()`. Each chunk of the network's streams is one datagram. What the client cannot take fast enough is dropped by the session, as
 * for a socket.
 */
export class DatagramFlow extends Emitter {
  closed = false;
  #reader;
  #writer;
  #onDestroy;
  #onDrop;

  constructor(flow, { onDestroy, onDrop } = {}) {
    super();
    this.#onDrop = onDrop;
    if (!flow || typeof flow.readable?.getReader !== 'function' || typeof flow.writable?.getWriter !== 'function') {
      throw new TypeError('the network must give { readable: ReadableStream, writable: WritableStream } for a UDP flow');
    }
    this.#reader = flow.readable.getReader();
    this.#writer = flow.writable.getWriter();
    this.#onDestroy = onDestroy;
    void this.#pump();
  }

  address() { return { port: 0, address: '', family: 'IPv4' }; }

  async #pump() {
    for (;;) {
      let r;
      try { r = await this.#reader.read(); } catch (e) { this.#fail(e); return; }
      if (this.closed) return;
      if (r.done) { this.#fail(null); return; }
      const bytes = toBytes(r.value);
      if (bytes && bytes.byteLength > 0) this.emit('message', bytes);
    }
  }

  /**
   * One datagram to the network. A network whose sink is not keeping up DROPS it (the sink's queue, `writable`'s own `highWaterMark`, is full), as a kernel
   * drops what a full socket buffer cannot hold: nothing queues without bound behind a sink that never drains, the flow stays open, and `onDrop` counts it.
   * `cb` is called either way (the datagram is "taken", so the credit that carried it is returned).
   */
  send(bytes, cb) {
    if (this.closed) { cb?.(new Error('the flow is closed')); return; }
    const room = this.#writer.desiredSize;
    if (room !== null && room <= 0) { try { this.#onDrop?.(); } catch { /* a counter */ } cb?.(); return; }
    this.#writer.write(bytes.slice()).then(() => cb?.(), (e) => { cb?.(e); this.#fail(e); });
  }

  #fail(e) {
    if (this.closed) return;
    if (e && this.listenerCount('error')) this.emit('error', e);
    // the network ended the flow: it is over, and the session's own idle rule reaps the channel
    this.close();
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.#reader.cancel().catch(() => {});
    this.#writer.abort().catch(() => {});
    try { this.#onDestroy?.(); } catch { /* the network's own */ }
    queueMicrotask(() => this.emit('close'));
  }
}
