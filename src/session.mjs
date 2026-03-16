/**
 * WshSession — shared facade for stream-backed and virtual-backed channels.
 *
 * Stream-backed sessions use raw transport streams for stdin/stdout.
 * Virtual-backed sessions use control messages (`SESSION_DATA`) for bytes.
 */

import {
  MSG, resize as resizeMsg, signal as signalMsg, close as closeMsg,
} from './messages.mjs';
import { WshVirtualSessionBackend } from './virtual-session.mjs';

// ── Session states ────────────────────────────────────────────────────

const STATE_OPENING = 'opening';
const STATE_ACTIVE  = 'active';
const STATE_CLOSED  = 'closed';

// ── Text encoding ─────────────────────────────────────────────────────

const textEncoder = new TextEncoder();

// ── Session class ─────────────────────────────────────────────────────

export class WshSession {
  /** @type {string} Unique session identifier (typically matches channelId). */
  id;

  /** @type {'pty'|'exec'} Channel kind. */
  kind;

  /** @type {number} Channel identifier assigned by the server. */
  channelId;

  /** @type {'opening'|'active'|'closed'} Current session state. */
  #state = STATE_OPENING;

  /** @type {import('./transport.mjs').WshTransport} Transport reference. */
  #transport;

  /** @type {'stream'|'virtual'} Session data plane. */
  #dataMode = 'stream';

  /** @type {string[]} Advertised session capabilities. */
  #capabilities = [];

  /**
   * Stream IDs returned by the server in OPEN_OK.
   * Typically { stdin: number, stdout: number } or a single bidirectional ID.
   * @type {object}
   */
  #streamIds;

  /**
   * The writable side of the stdin data stream.
   * @type {WritableStreamDefaultWriter|null}
   */
  #stdinWriter = null;

  /** @type {WshVirtualSessionBackend|null} */
  #virtualBackend = null;

  /**
   * The readable side of the stdout data stream.
   * @type {ReadableStream<Uint8Array>|null}
   */
  #stdoutReadable = null;

  /** @type {AbortController} Cancels the background data pump. */
  #abort = new AbortController();

  /** @type {Promise<void>|null} Resolves when the data pump finishes. */
  #pumpDone = null;

  /** @type {number|null} Exit code received from the server. */
  #exitCode = null;

  // ── Callbacks ───────────────────────────────────────────────────────

  /**
   * Called when stdout/stderr data arrives.
   * @type {function(Uint8Array): void|null}
   */
  onData = null;

  /**
   * Called when the remote process exits.
   * @type {function(number): void|null}
   */
  onExit = null;

  /**
   * Called when the session is fully closed.
   * @type {function(): void|null}
   */
  onClose = null;

  /**
   * Called when speculative local echo is acknowledged by the remote peer.
   * @type {function(object): void|null}
   */
  onEchoAck = null;

  /**
   * Called when the remote peer reports current cursor/echo state.
   * @type {function(object): void|null}
   */
  onEchoState = null;

  /**
   * Called when the remote peer emits a full terminal sync hash.
   * @type {function(object): void|null}
   */
  onTermSync = null;

  /**
   * Called when the remote peer emits an incremental terminal diff.
   * @type {function(object): void|null}
   */
  onTermDiff = null;

  /** @type {object|null} */
  #lastEchoAck = null;

  /** @type {object|null} */
  #lastEchoState = null;

  /** @type {object|null} */
  #lastTermSync = null;

  /** @type {object|null} */
  #lastTermDiff = null;

  // ── Constructor ─────────────────────────────────────────────────────

  /**
   * @param {import('./transport.mjs').WshTransport} transport
   * @param {number} channelId
   * @param {object} streamIds - Stream identifiers from OPEN_OK.
   * @param {'pty'|'exec'} kind
   * @param {object} [opts]
   * @param {'stream'|'virtual'} [opts.dataMode='stream']
   * @param {string[]} [opts.capabilities=[]]
   */
  constructor(transport, channelId, streamIds, kind, { dataMode = 'stream', capabilities = [] } = {}) {
    this.#transport = transport;
    this.channelId = channelId;
    this.#streamIds = streamIds;
    this.kind = kind;
    this.id = String(channelId);
    this.#dataMode = dataMode === 'virtual' ? 'virtual' : 'stream';
    this.#capabilities = Array.isArray(capabilities) ? [...capabilities] : [];
  }

  /** Current session state. */
  get state() {
    return this.#state;
  }

  /** Exit code, if the process has exited. */
  get exitCode() {
    return this.#exitCode;
  }

  /** Session data plane: stream-backed or control-message-backed. */
  get dataMode() {
    return this.#dataMode;
  }

  /** Advertised session capabilities. */
  get capabilities() {
    return [...this.#capabilities];
  }

  /** Last echo acknowledgment received for this session. */
  get lastEchoAck() {
    return this.#lastEchoAck ? { ...this.#lastEchoAck } : null;
  }

  /** Last echo-state update received for this session. */
  get lastEchoState() {
    return this.#lastEchoState ? { ...this.#lastEchoState } : null;
  }

  /** Last terminal sync hash received for this session. */
  get lastTermSync() {
    if (!this.#lastTermSync) return null;
    return {
      ...this.#lastTermSync,
      state_hash: this.#lastTermSync.state_hash?.slice?.() || this.#lastTermSync.state_hash,
    };
  }

  /** Last terminal diff received for this session. */
  get lastTermDiff() {
    if (!this.#lastTermDiff) return null;
    return {
      ...this.#lastTermDiff,
      patch: this.#lastTermDiff.patch?.slice?.() || this.#lastTermDiff.patch,
    };
  }

  // ── Stream binding ──────────────────────────────────────────────────

  /**
   * Bind the raw data streams to this session and start the read pump.
   * Called by WshClient after stream setup.
   *
   * @param {ReadableStream<Uint8Array>} readable - stdout/stderr bytes from server
   * @param {WritableStream<Uint8Array>} writable - stdin bytes to server
   */
  _bind(readable, writable) {
    if (this.#dataMode !== 'stream') {
      throw new Error('Cannot bind transport streams to a virtual session');
    }
    if (this.#state === STATE_CLOSED) {
      throw new Error('Cannot bind streams to a closed session');
    }
    this.#stdoutReadable = readable;
    this.#stdinWriter = writable.getWriter();
    this.#state = STATE_ACTIVE;
    this.#pumpDone = this._pumpDataStream();
  }

  /**
   * Activate a message-backed virtual session.
   *
   * @param {function(object): Promise<void>} sendControl
   */
  _activateVirtual(sendControl) {
    if (this.#dataMode !== 'virtual') {
      throw new Error('Cannot activate virtual backend for a stream session');
    }
    if (this.#state === STATE_CLOSED) {
      throw new Error('Cannot activate a closed session');
    }
    this.#virtualBackend = new WshVirtualSessionBackend(sendControl, this.channelId);
    this.#state = STATE_ACTIVE;
  }

  // ── Public API ──────────────────────────────────────────────────────

  /**
   * Write data to the session's stdin stream.
   * Accepts a Uint8Array for raw bytes or a string (UTF-8 encoded).
   *
   * @param {Uint8Array|string} data
   */
  async write(data) {
    if (this.#state === STATE_CLOSED) {
      throw new Error('Cannot write to a closed session');
    }
    if (this.#dataMode === 'virtual') {
      if (this.#virtualBackend === null) {
        throw new Error('Session not yet activated — virtual backend unavailable');
      }
      await this.#virtualBackend.write(data);
      return;
    }
    if (this.#stdinWriter === null) {
      throw new Error('Session not yet bound — stdin writer unavailable');
    }

    const bytes = typeof data === 'string' ? textEncoder.encode(data) : data;
    await this.#stdinWriter.write(bytes);
  }

  /**
   * Read one chunk from the session data plane.
   *
   * Returns `null` on EOF.
   *
   * @returns {Promise<Uint8Array|null>}
   */
  async read() {
    if (this.#dataMode === 'virtual') {
      if (this.#virtualBackend === null) {
        if (this.#state === STATE_CLOSED) {
          return null;
        }
        throw new Error('Session not yet activated — virtual backend unavailable');
      }
      const { done, value } = await this.#virtualBackend.read();
      return done ? null : value || new Uint8Array();
    }

    if (!this.#stdoutReadable) {
      throw new Error('Session not yet bound — stdout stream unavailable');
    }

    const reader = this.#stdoutReadable.getReader();
    try {
      const { done, value } = await reader.read();
      return done ? null : value || new Uint8Array();
    } finally {
      reader.releaseLock();
    }
  }

  /**
   * Request the remote PTY to resize.
   *
   * @param {number} cols - Terminal columns
   * @param {number} rows - Terminal rows
   */
  async resize(cols, rows) {
    this.#assertNotClosed('resize');
    await this.#transport.sendControl(
      resizeMsg({ channelId: this.channelId, cols, rows })
    );
  }

  /**
   * Send a signal to the remote process (e.g. 'SIGINT', 'SIGTERM').
   *
   * @param {string} sig - Signal name
   */
  async signal(sig) {
    this.#assertNotClosed('signal');
    await this.#transport.sendControl(
      signalMsg({ channelId: this.channelId, signal: sig })
    );
  }

  /**
   * Close this session. Sends a CLOSE control message and tears down
   * the data streams. Safe to call multiple times.
   */
  async close() {
    if (this.#state === STATE_CLOSED) return;

    // Optimistically mark closed so no further writes are accepted.
    this.#state = STATE_CLOSED;
    this.#abort.abort();

    // Send CLOSE to the server (best-effort).
    try {
      await this.#transport.sendControl(
        closeMsg({ channelId: this.channelId })
      );
    } catch {
      // Transport may already be closed; ignore.
    }

    if (this.#dataMode === 'stream') {
      // Release the stdin writer.
      try {
        await this.#stdinWriter?.close();
      } catch {
        // May already be closed or errored.
      }

      // Wait for the data pump to finish.
      if (this.#pumpDone) {
        await this.#pumpDone.catch(() => {});
      }
    }

    this.#stdinWriter = null;
    this.#stdoutReadable = null;
    this.#emitClose();
  }

  // ── Control message dispatch ────────────────────────────────────────

  /**
   * Handle a control message dispatched by WshClient for this channel.
   * @param {object} msg - Decoded CBOR control message
   * @internal
   */
  _handleControlMessage(msg) {
    switch (msg.type) {
      case MSG.SESSION_DATA: {
        if (msg.data && msg.data.byteLength > 0) {
          this.#virtualBackend?.pushData(msg.data);
          try {
            this.onData?.(msg.data);
          } catch (err) {
            console.error('[wsh:session] onData handler error:', err);
          }
        }
        break;
      }

      case MSG.EXIT: {
        this.#exitCode = msg.code ?? -1;
        try {
          this.onExit?.(this.#exitCode);
        } catch (err) {
          console.error('[wsh:session] onExit handler error:', err);
        }
        break;
      }

      case MSG.CLOSE: {
        // Server-initiated close.
        if (this.#state !== STATE_CLOSED) {
          this.#state = STATE_CLOSED;
          this.#abort.abort();
          this.#virtualBackend?.close();
          this.#releaseStreams();
          this.#emitClose();
        }
        break;
      }

      case MSG.RESIZE: {
        // Server acknowledgment of resize; currently a no-op on the client.
        break;
      }

      case MSG.ECHO_ACK:
        this.#lastEchoAck = this.#virtualBackend?.recordEchoAck(msg) || {
          channel_id: this.channelId,
          echo_seq: msg.echo_seq ?? 0,
        };
        try {
          this.onEchoAck?.(this.lastEchoAck);
        } catch (err) {
          console.error('[wsh:session] onEchoAck handler error:', err);
        }
        break;

      case MSG.ECHO_STATE:
        this.#lastEchoState = this.#virtualBackend?.recordEchoState(msg) || {
          channel_id: this.channelId,
          echo_seq: msg.echo_seq ?? 0,
          cursor_x: msg.cursor_x ?? 0,
          cursor_y: msg.cursor_y ?? 0,
          pending: msg.pending ?? 0,
        };
        try {
          this.onEchoState?.(this.lastEchoState);
        } catch (err) {
          console.error('[wsh:session] onEchoState handler error:', err);
        }
        break;

      case MSG.TERM_SYNC:
        this.#lastTermSync = this.#virtualBackend?.recordTermSync(msg) || {
          channel_id: this.channelId,
          frame_seq: msg.frame_seq ?? 0,
          state_hash: msg.state_hash?.slice?.() || msg.state_hash || new Uint8Array(),
        };
        try {
          this.onTermSync?.(this.lastTermSync);
        } catch (err) {
          console.error('[wsh:session] onTermSync handler error:', err);
        }
        break;

      case MSG.TERM_DIFF:
        this.#lastTermDiff = this.#virtualBackend?.recordTermDiff(msg) || {
          channel_id: this.channelId,
          frame_seq: msg.frame_seq ?? 0,
          base_seq: msg.base_seq ?? 0,
          patch: msg.patch?.slice?.() || msg.patch || new Uint8Array(),
        };
        try {
          this.onTermDiff?.(this.lastTermDiff);
        } catch (err) {
          console.error('[wsh:session] onTermDiff handler error:', err);
        }
        break;

      default:
        // Unknown control message for this channel — ignore gracefully.
        break;
    }
  }

  // ── Data stream pump ────────────────────────────────────────────────

  /**
   * Continuously read from the stdout data stream and invoke onData.
   * Runs until the stream ends, errors, or the session is aborted.
   * @private
   */
  async _pumpDataStream() {
    if (!this.#stdoutReadable) return;

    const reader = this.#stdoutReadable.getReader();
    try {
      while (true) {
        if (this.#abort.signal.aborted) break;

        const { done, value } = await reader.read();
        if (done) break;

        if (value && value.byteLength > 0) {
          try {
            this.onData?.(value);
          } catch (err) {
            console.error('[wsh:session] onData handler error:', err);
          }
        }
      }
    } catch (err) {
      // Only report errors if we haven't been intentionally aborted.
      if (!this.#abort.signal.aborted) {
        console.error('[wsh:session] data stream read error:', err);
      }
    } finally {
      reader.releaseLock();
    }

    // If the data stream ended but we haven't received a CLOSE message,
    // transition to closed state.
    if (this.#state !== STATE_CLOSED) {
      this.#state = STATE_CLOSED;
      this.#releaseStreams();
      this.#emitClose();
    }
  }

  // ── Private helpers ─────────────────────────────────────────────────

  /**
   * Release stream resources without sending a CLOSE message.
   * @private
   */
  #releaseStreams() {
    try {
      this.#stdinWriter?.close();
    } catch {
      // Ignore.
    }
    this.#stdinWriter = null;
    this.#stdoutReadable = null;
    this.#virtualBackend?.close();
  }

  /**
   * Emit the onClose callback exactly once.
   * @private
   */
  #emitClose() {
    try {
      this.onClose?.();
    } catch (err) {
      console.error('[wsh:session] onClose handler error:', err);
    }
    // Clear callbacks to prevent repeat invocations.
    this.onClose = null;
  }

  /**
   * Throw if the session is closed.
   * @param {string} action - Description of the attempted action.
   * @private
   */
  #assertNotClosed(action) {
    if (this.#state === STATE_CLOSED) {
      throw new Error(`Cannot ${action}: session is closed`);
    }
  }
}
