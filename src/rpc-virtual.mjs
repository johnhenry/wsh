/**
 * rpc channels in virtual data mode (wsh #191): the CBOR sequence of an `rpc` channel (see `rpc.mjs`) carried as
 * `SessionData` on the control plane -- and so inside `EncryptedFrame` on a sealed session -- instead of on a
 * client-opened data stream. Transport-free and browser-safe: the host (`server/connection.mjs`) and the client
 * (`client.mjs`) each bind an `RpcCreditLink` to their end of the channel.
 *
 * A stream has the transport's own flow control; the control plane has none, so the link meters the bytes itself:
 *  - each direction starts with `RPC_CREDIT_WINDOW` bytes of credit; `write()` sends only while it holds credit and waits
 *    for a `GatewayCredit` otherwise, so a reader that does not read bounds the sender;
 *  - the receiver returns credit (`GatewayCredit`) as `RpcChannel` takes the bytes in, in bytes and not in messages, so a
 *    message larger than the window still arrives (credit is returned for the bytes of a partly received message);
 *  - a peer that sends more than the credit it was given has broken the protocol, and the channel is closed.
 *
 * `GatewayCredit` is reused rather than a new message, because it is already forwarded by every relay and ignored for an
 * id it does not know. Its `gateway_id` is a number space of its own beside the gateway's: an rpc channel's credit is
 * `RPC_CREDIT_FLAG | channel_id`, a flag no gateway id ever has (the gateway's ids count up from 1).
 */

/** Credit each direction of a virtual-mode rpc channel starts with, in bytes (a protocol constant). */
export const RPC_CREDIT_WINDOW = 262144;
/** `GatewayCredit.gateway_id` bit that marks credit for an rpc channel; the rest is the channel id. */
export const RPC_CREDIT_FLAG = 0x80000000;
/** Largest `SessionData` payload this layer sends. */
export const RPC_VIRTUAL_CHUNK_BYTES = 32 * 1024;

/** The `GatewayCredit.gateway_id` that grants credit on rpc channel `channelId`. @param {number} channelId */
export const rpcCreditId = (channelId) => (RPC_CREDIT_FLAG | channelId) >>> 0;
/** The rpc channel a `GatewayCredit.gateway_id` is for, or `undefined` if it is not rpc credit. @param {number} gatewayId */
export const rpcChannelOfCredit = (gatewayId) => (Number.isInteger(gatewayId) && gatewayId >= RPC_CREDIT_FLAG ? gatewayId - RPC_CREDIT_FLAG : undefined);

/**
 * One end of the byte pipe under a virtual-mode `RpcChannel`.
 *
 *   const link = new RpcCreditLink({ sendData, sendCredit, onViolation });
 *   const chan = new RpcChannel({ write: (b) => link.write(b), onConsumed: (n) => link.consumed(n), ... });
 *   // SessionData arrives:  if (link.receive(bytes.length)) chan.feed(bytes)
 *   // GatewayCredit arrives: link.grant(n)
 */
export class RpcCreditLink {
  #sendData; #sendCredit; #onViolation; #window; #chunk;
  /** Credit this end may still spend. */
  #credit;
  /** Credit this end has granted the peer and not yet seen spent. */
  #peerCredit;
  /** Bytes taken in and not yet returned as credit. */
  #owed = 0;
  #waiters = [];
  #closed = false;

  /**
   * @param {object} o
   * @param {(bytes: Uint8Array) => Promise<void> | void} o.sendData - one `SessionData` payload
   * @param {(bytes: number) => Promise<void> | void} o.sendCredit - one `GatewayCredit`
   * @param {(why: string) => void} [o.onViolation] - the peer overran its credit
   * @param {number} [o.window]
   * @param {number} [o.chunkBytes]
   */
  constructor({ sendData, sendCredit, onViolation = () => {}, window = RPC_CREDIT_WINDOW, chunkBytes = RPC_VIRTUAL_CHUNK_BYTES }) {
    this.#sendData = sendData;
    this.#sendCredit = sendCredit;
    this.#onViolation = onViolation;
    this.#window = window;
    this.#chunk = chunkBytes;
    this.#credit = window;
    this.#peerCredit = window;
  }

  /** Credit this end holds to send with. */
  get credit() { return this.#credit; }

  /** Send `bytes`: in chunks, each waiting for credit. Rejects if the link closes first. @param {Uint8Array} bytes */
  async write(bytes) {
    let off = 0;
    while (off < bytes.length) {
      while (this.#credit <= 0) {
        if (this.#closed) throw new Error('rpc channel closed');
        await new Promise((resolve) => this.#waiters.push(resolve));
      }
      if (this.#closed) throw new Error('rpc channel closed');
      const n = Math.min(bytes.length - off, this.#credit, this.#chunk);
      this.#credit -= n;
      const piece = bytes.subarray(off, off + n);
      off += n;
      await this.#sendData(piece);
    }
  }

  /** The peer granted `n` more bytes (a `GatewayCredit`). @param {number} n */
  grant(n) {
    if (this.#closed || !Number.isSafeInteger(n) || n <= 0) return;
    this.#credit = Math.min(this.#credit + n, Number.MAX_SAFE_INTEGER);
    for (const w of this.#waiters.splice(0)) w();
  }

  /**
   * Account for `n` bytes the peer sent (a `SessionData`). Returns false, and reports a violation, if that is more than the
   * credit this end granted: the caller must then not deliver them.
   * @param {number} n
   */
  receive(n) {
    if (this.#closed) return false;
    this.#peerCredit -= n;
    if (this.#peerCredit < 0) {
      this.#onViolation('the peer sent more rpc data than the credit it was given');
      return false;
    }
    return true;
  }

  /** The application took `n` received bytes in: hand the peer credit back, in batches of half a window. @param {number} n */
  consumed(n) {
    if (this.#closed) return;
    this.#owed += n;
    if (this.#owed >= this.#window / 2) {
      const give = this.#owed;
      this.#owed = 0;
      this.#peerCredit += give;
      try { void Promise.resolve(this.#sendCredit(give)).catch(() => {}); } catch { /* transport gone */ }
    }
  }

  /** The channel is over: writers waiting for credit are released with an error. */
  close() {
    this.#closed = true;
    for (const w of this.#waiters.splice(0)) w();
  }
}
