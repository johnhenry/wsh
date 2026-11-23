/**
 * UDP flows as WebTransport datagrams (#124): the wire format, the rate limiter both ends use, and the client's flow
 * object. Browser-safe: no `node:*` import.
 *
 * Negotiation: the client lists `gateway-datagram` in `Hello.features` when its transport has datagrams (WebTransport
 * only), the host lists it in `ServerHello.features` when its transport has them AND its gateway serves UDP. Both =
 * every `OpenUdp` flow of that connection carries its payloads as datagrams instead of `GatewayData` on the control
 * stream. Open, close and errors (`OpenUdp`, `GatewayOk`/`GatewayFail`, `GatewayClose`) always stay on the control stream.
 *
 * Datagram layout (the whole QUIC datagram payload, one UDP payload per datagram):
 *
 *     0       1       2       3       4 ...
 *     +-------+-------+-------+-------+----------------------------+
 *     |        gateway_id (u32, big endian)  |  UDP payload (0..n bytes) |
 *     +-------+-------+-------+-------+----------------------------+
 *
 * `gateway_id` is the id the client chose in `OpenUdp`. A datagram naming a flow the receiver does not have is dropped.
 * Nothing is metered by `GatewayCredit` on a datagram flow (datagrams are never queued without bound: they are dropped).
 * A payload that does not fit `maxDatagramSize - 4` travels as `GatewayData` on the control stream instead, unless the
 * receiver is configured to drop it (see the host's `udp.oversize` and `openUdp`'s `oversize` option).
 */

/** Feature string: "UDP flows may use WebTransport datagrams". */
export const GATEWAY_DATAGRAM_FEATURE = 'gateway-datagram';
/** Bytes of the flow-id header in front of each UDP payload. */
export const DATAGRAM_HEADER_BYTES = 4;
/** The largest UDP payload a flow carries (an IPv4 datagram's limit). */
export const MAX_UDP_PAYLOAD = 65507;

/** @param {number} id @param {Uint8Array} payload */
export function encodeDatagram(id, payload) {
  const out = new Uint8Array(DATAGRAM_HEADER_BYTES + payload.byteLength);
  new DataView(out.buffer).setUint32(0, id, false);
  out.set(payload, DATAGRAM_HEADER_BYTES);
  return out;
}

/** @param {Uint8Array} bytes @returns {{ id: number, payload: Uint8Array } | null} null when it is too short to be one */
export function decodeDatagram(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < DATAGRAM_HEADER_BYTES) return null;
  const id = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
  return { id, payload: bytes.subarray(DATAGRAM_HEADER_BYTES) };
}

/**
 * A token bucket: `take(cost)` is true (and spends) when `cost` tokens are available. Refills continuously at
 * `ratePerSecond` up to `burst`. `ratePerSecond` of `Infinity` never refuses.
 */
export class TokenBucket {
  #rate;
  #burst;
  #tokens;
  #last;
  #now;
  /** @param {number} ratePerSecond @param {number} [burst] @param {() => number} [now] milliseconds */
  constructor(ratePerSecond, burst = ratePerSecond, now = () => Date.now()) {
    this.#rate = ratePerSecond;
    this.#burst = Math.max(burst, 1);
    this.#tokens = this.#burst;
    this.#now = now;
    this.#last = now();
  }

  take(cost = 1) {
    if (this.#rate === Infinity) return true;
    const t = this.#now();
    this.#tokens = Math.min(this.#burst, this.#tokens + ((t - this.#last) / 1000) * this.#rate);
    this.#last = t;
    if (this.#tokens < cost) return false;
    this.#tokens -= cost;
    return true;
  }
}

const DEFAULT_QUEUE_DATAGRAMS = 128;

/**
 * The client's end of a UDP flow: what `client.openUdp()` resolves with. Datagram semantics, explicitly: a datagram may
 * be dropped (by a rate limit, by transport back-pressure, by a full receive queue) and nothing tells you which.
 *
 * - `send(bytes)`: resolves `true` when handed to the transport, `false` when dropped locally (transport busy). Rejects
 *   with a `RangeError` for a payload over 65507 bytes, and (with `oversize: 'drop'` on a datagram flow) for one that does
 *   not fit `maxDatagramSize`; otherwise a payload too big for one datagram goes on the reliable control stream.
 * - `readable`: one chunk per datagram. When the reader is slower than the arrivals the NEWEST are dropped past a queue
 *   of `queueDatagrams` (counted in `stats.receiveDropped`).
 * - `writable`: the same as `send()` as a stream; it never fills up and never errors on a drop.
 * - `transport`: `'datagram'` or `'stream'` (the reliable fallback: WebSocket, no datagram support on either end).
 * - `maxDatagramSize`: the largest payload that travels as a datagram now (it can change; read it again).
 */
export class UdpFlow {
  #o;
  #queue = [];
  #waiter = null;
  #ended = false;
  #streams = null;
  stats = { sent: 0, received: 0, sentReliable: 0, receivedReliable: 0, sendDropped: 0, receiveDropped: 0 };

  /**
   * @param {object} o
   * @param {number} o.id
   * @param {import('./gateway-channel.mjs').GatewayChannel} o.channel
   * @param {{ send(bytes: Uint8Array): boolean, maxSize(): number } | null} o.datagrams  null = reliable path only
   * @param {'reliable' | 'drop'} [o.oversize]
   * @param {number} [o.queueDatagrams]
   */
  constructor(o) {
    this.#o = { oversize: 'reliable', queueDatagrams: DEFAULT_QUEUE_DATAGRAMS, ...o };
    this.channel = o.channel;
    this.closed = o.channel.closedPromise;
    this.closed.then(() => { this.#ended = true; this.#waiter?.(); });
  }

  get transport() { return this.#o.datagrams ? 'datagram' : 'stream'; }

  get maxDatagramSize() {
    if (!this.#o.datagrams) return MAX_UDP_PAYLOAD;
    return Math.max(0, this.#o.datagrams.maxSize() - DATAGRAM_HEADER_BYTES);
  }

  /** @param {Uint8Array} bytes @returns {Promise<boolean>} */
  async send(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new TypeError('send: bytes must be a Uint8Array');
    if (bytes.byteLength > MAX_UDP_PAYLOAD) throw new RangeError(`a UDP payload is at most ${MAX_UDP_PAYLOAD} bytes (got ${bytes.byteLength})`);
    if (this.channel.closed) throw new Error('the UDP flow is closed');
    const dg = this.#o.datagrams;
    if (dg && bytes.byteLength <= this.maxDatagramSize) {
      const ok = dg.send(encodeDatagram(this.channel.id, bytes));
      if (ok) this.stats.sent++; else this.stats.sendDropped++;
      return ok;
    }
    if (dg && this.#o.oversize === 'drop') {
      this.stats.sendDropped++;
      throw new RangeError(`this payload (${bytes.byteLength} bytes) does not fit one datagram (${this.maxDatagramSize} bytes) and this flow drops oversize payloads`);
    }
    await this.channel.write(bytes); // the reliable control stream: ordered, retransmitted, metered by credit
    this.stats.sentReliable++;
    return true;
  }

  /** A datagram for this flow arrived (the payload, header removed). */
  deliverDatagram(payload) { this.#push(payload, false); }

  /** A GatewayData for this flow arrived on the control stream (the reliable path, or an oversize payload). */
  deliverReliable(bytes) { this.#push(bytes, true); }

  #push(bytes, reliable) {
    if (this.#ended) return;
    if (this.#queue.length >= this.#o.queueDatagrams) {
      this.stats.receiveDropped++;
      if (reliable) this.channel.consumed(bytes.byteLength);
      return;
    }
    if (reliable) this.stats.receivedReliable++; else this.stats.received++;
    // Copy: a datagram is a view into a buffer the transport may reuse.
    this.#queue.push({ bytes: reliable ? bytes : bytes.slice(), reliable });
    this.#waiter?.();
  }

  get streams() {
    if (this.#streams) return this.#streams;
    const self = this;
    const readable = new ReadableStream({
      async pull(controller) {
        while (self.#queue.length === 0 && !self.#ended) await new Promise((r) => { self.#waiter = r; });
        self.#waiter = null;
        const next = self.#queue.shift();
        if (next) {
          controller.enqueue(next.bytes);
          if (next.reliable) self.channel.consumed(next.bytes.byteLength);
          return;
        }
        controller.close();
      },
      cancel() { self.destroy(); },
    }, { highWaterMark: 0 });
    const writable = new WritableStream({
      async write(chunk) { try { await self.send(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)); } catch (e) { if (!(e instanceof RangeError)) throw e; } },
      close() { self.close(); },
      abort() { self.destroy(); },
    });
    this.#streams = { readable, writable };
    return this.#streams;
  }

  get readable() { return this.streams.readable; }
  get writable() { return this.streams.writable; }

  /** A flow has no half-close: closing ends it (the host closes the socket). */
  close(reason) { this.channel.destroy(reason); }
  destroy(reason) { this.channel.destroy(reason); }
}
