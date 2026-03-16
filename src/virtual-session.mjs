import { sessionData as sessionDataMsg } from './messages.mjs';

const textEncoder = new TextEncoder();

/**
 * Normalize user input into session bytes for a virtual terminal channel.
 *
 * @param {Uint8Array|string} data
 * @returns {Uint8Array}
 */
export function normalizeSessionData(data) {
  if (data instanceof Uint8Array) {
    return data;
  }
  return textEncoder.encode(String(data));
}

/**
 * Message-backed data plane for browser-hosted virtual sessions.
 */
export class WshVirtualSessionBackend {
  /** @type {function(object): Promise<void>} */
  #sendControl;

  /** @type {number} */
  #channelId;

  /** @type {object|null} */
  #lastEchoAck = null;

  /** @type {object|null} */
  #lastEchoState = null;

  /** @type {object|null} */
  #lastTermSync = null;

  /** @type {object|null} */
  #lastTermDiff = null;
  /** @type {Uint8Array[]} */
  #readQueue = [];
  /** @type {Array<{resolve: function({done:boolean,value?:Uint8Array}):void,reject:function(Error):void}>} */
  #readWaiters = [];
  /** @type {boolean} */
  #closed = false;

  /**
   * @param {function(object): Promise<void>} sendControl
   * @param {number} channelId
   */
  constructor(sendControl, channelId) {
    this.#sendControl = sendControl;
    this.#channelId = channelId;
  }

  /**
   * @param {Uint8Array|string} data
   * @returns {Promise<void>}
   */
  async write(data) {
    await this.#sendControl(
      sessionDataMsg({
        channelId: this.#channelId,
        data: normalizeSessionData(data),
      })
    );
  }

  async read() {
    if (this.#readQueue.length > 0) {
      return { done: false, value: this.#readQueue.shift() };
    }
    if (this.#closed) {
      return { done: true, value: undefined };
    }
    return await new Promise((resolve, reject) => {
      this.#readWaiters.push({ resolve, reject });
    });
  }

  pushData(data) {
    const bytes = data instanceof Uint8Array ? data : normalizeSessionData(data);
    const waiter = this.#readWaiters.shift();
    if (waiter) {
      waiter.resolve({ done: false, value: bytes });
      return;
    }
    this.#readQueue.push(bytes);
  }

  close() {
    if (this.#closed) return;
    this.#closed = true;
    while (this.#readWaiters.length > 0) {
      const waiter = this.#readWaiters.shift();
      waiter?.resolve({ done: true, value: undefined });
    }
  }

  get lastEchoAck() {
    return this.#lastEchoAck ? { ...this.#lastEchoAck } : null;
  }

  get lastEchoState() {
    return this.#lastEchoState ? { ...this.#lastEchoState } : null;
  }

  get lastTermSync() {
    if (!this.#lastTermSync) return null;
    return {
      ...this.#lastTermSync,
      state_hash: this.#lastTermSync.state_hash?.slice?.() || this.#lastTermSync.state_hash,
    };
  }

  get lastTermDiff() {
    if (!this.#lastTermDiff) return null;
    return {
      ...this.#lastTermDiff,
      patch: this.#lastTermDiff.patch?.slice?.() || this.#lastTermDiff.patch,
    };
  }

  recordEchoAck(msg) {
    this.#lastEchoAck = {
      channel_id: this.#channelId,
      echo_seq: msg.echo_seq ?? 0,
    };
    return this.lastEchoAck;
  }

  recordEchoState(msg) {
    this.#lastEchoState = {
      channel_id: this.#channelId,
      echo_seq: msg.echo_seq ?? 0,
      cursor_x: msg.cursor_x ?? 0,
      cursor_y: msg.cursor_y ?? 0,
      pending: msg.pending ?? 0,
    };
    return this.lastEchoState;
  }

  recordTermSync(msg) {
    this.#lastTermSync = {
      channel_id: this.#channelId,
      frame_seq: msg.frame_seq ?? 0,
      state_hash: msg.state_hash?.slice?.() || msg.state_hash || new Uint8Array(),
    };
    return this.lastTermSync;
  }

  recordTermDiff(msg) {
    this.#lastTermDiff = {
      channel_id: this.#channelId,
      frame_seq: msg.frame_seq ?? 0,
      base_seq: msg.base_seq ?? 0,
      patch: msg.patch?.slice?.() || msg.patch || new Uint8Array(),
    };
    return this.lastTermDiff;
  }
}
