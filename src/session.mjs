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
import { sealFrame, openFrame, ROLE_TAGS } from './e2e-frame.mjs';
import {
  ChunkAccumulator, encodeChunk, resolveCoalesceOptions, WriteCoalescer, StreamAuthenticationError,
} from './stream-frame.mjs';

// ── Session states ────────────────────────────────────────────────────

const STATE_OPENING = 'opening';
const STATE_ACTIVE  = 'active';
const STATE_CLOSED  = 'closed';

/**
 * Stream-mode data and control streams are independently-multiplexed
 * transport streams (QUIC/QMux) with no guaranteed relative delivery
 * order (wsh #24). When the data stream reaches EOF, the server-sent
 * `CLOSE` control message -- not the data-stream FIN -- is the
 * authoritative close signal, so `_pumpDataStream()` waits up to this
 * long for `CLOSE` to arrive before falling back to closing on data-EOF
 * alone (a safety net for servers that never send `CLOSE`).
 */
const DATA_EOF_CLOSE_GRACE_MS = 300;

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
   * The server-assigned session_id this channel belongs to, from OPEN_OK
   * (clawser #48). `undefined` for channel kinds with no Attach/Resume-able
   * session (e.g. file channels).
   * @type {string|undefined}
   */
  #sessionId;

  /**
   * The session-scoped HMAC token minted by the server at Open time
   * (clawser #48), also from OPEN_OK. Pass it to `WshClient.resumeSession`
   * (or optionally `attachSession`) from a later connection to reclaim
   * this exact session. `undefined` alongside `#sessionId`.
   * @type {Uint8Array|undefined}
   */
  #resumeToken;

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
   * Non-extractable AES-256-GCM CryptoKey set by `enableE2E()`, or `null`
   * if E2E is not enabled for this session. Connection-scoped -- see
   * `enableE2E`'s doc comment for why this must never be reused across a
   * Resume/Attach.
   * @type {CryptoKey|null}
   */
  #e2eKey = null;

  /** @type {Uint8Array|null} This side's 4-byte nonce role tag, set by `enableE2E()`. */
  #e2eSendRoleTag = null;

  /** @type {Uint8Array|null} The peer's 4-byte nonce role tag, set by `enableE2E()`. */
  #e2eRecvRoleTag = null;

  /** @type {number} Next outgoing frame counter for this side. */
  #e2eSendCounter = 0;

  /** @type {number} Next expected incoming frame counter from the peer. */
  #e2eRecvCounter = 0;

  /**
   * Reassembles the raw stdout byte stream into complete sealed chunks
   * when E2E is enabled on a stream-mode session. `null` for virtual-mode
   * sessions or when E2E is not enabled.
   * @type {import('./stream-frame.mjs').ChunkAccumulator|null}
   */
  #streamAccumulator = null;

  /**
   * Batches outgoing stream-mode writes before sealing, per the
   * write-coalescing design (wsh #22). `null` means coalescing is
   * disabled (`coalesce: false`) -- every write() seals immediately.
   * @type {WriteCoalescer|null}
   */
  #streamCoalescer = null;

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

  /**
   * Pending fallback timer scheduled when the data stream hits EOF
   * before a `CLOSE` control message has arrived (wsh #24). Cleared
   * as soon as `CLOSE` arrives (or the session is otherwise closed) so
   * a prompt `CLOSE` short-circuits the wait instead of idling out the
   * full grace period.
   * @type {ReturnType<typeof setTimeout>|null}
   */
  #closeGraceTimer = null;

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

  /**
   * Queue of received FileChunk payloads not yet consumed by
   * _readFileChunk(). 'file'-kind sessions only.
   * @type {Array<object>}
   */
  #fileChunkQueue = [];

  /** @type {{resolve: function, reject: function}|null} */
  #fileChunkWaiter = null;

  // ── Constructor ─────────────────────────────────────────────────────

  /**
   * @param {import('./transport.mjs').WshTransport} transport
   * @param {number} channelId
   * @param {object} streamIds - Stream identifiers from OPEN_OK.
   * @param {'pty'|'exec'} kind
   * @param {object} [opts]
   * @param {'stream'|'virtual'} [opts.dataMode='stream']
   * @param {string[]} [opts.capabilities=[]]
   * @param {string} [opts.sessionId] - Server session_id from OPEN_OK (clawser #48; pty/exec only)
   * @param {Uint8Array} [opts.resumeToken] - Session-scoped resume token from OPEN_OK (clawser #48)
   */
  constructor(
    transport, channelId, streamIds, kind,
    { dataMode = 'stream', capabilities = [], sessionId, resumeToken } = {}
  ) {
    this.#transport = transport;
    this.channelId = channelId;
    this.#streamIds = streamIds;
    this.kind = kind;
    this.id = String(channelId);
    this.#dataMode = dataMode === 'virtual' ? 'virtual' : 'stream';
    this.#capabilities = Array.isArray(capabilities) ? [...capabilities] : [];
    this.#sessionId = sessionId;
    this.#resumeToken = resumeToken;
  }

  /**
   * The server-assigned session_id this channel belongs to, if any
   * (clawser #48; `undefined` for channel kinds with no Attach/Resume-able
   * session, e.g. file channels). Pass to `WshClient.attachSession`/
   * `resumeSession` from another connection.
   */
  get sessionId() {
    return this.#sessionId;
  }

  /**
   * The session-scoped resume token minted at Open time, if any (clawser
   * #48). Pass it to `WshClient.resumeSession` from a later connection to
   * reclaim this exact session, proving you're the same credentialed
   * opener rather than merely an authorized principal.
   */
  get resumeToken() {
    return this.#resumeToken;
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

  /** Whether `enableE2E()` has been called and E2E sealing is active for this session. */
  get e2eEnabled() {
    return this.#e2eKey !== null;
  }

  /**
   * Opt in to end-to-end encryption for this session's data plane.
   * Works for both virtual-mode and stream-mode sessions (wsh #22
   * generalized this from virtual-mode-only, #19).
   *
   * Virtual-mode: after this call, `write()` seals outgoing data into
   * `EncryptedFrame` control messages instead of plaintext
   * `SessionData`, and incoming `EncryptedFrame` messages are opened and
   * delivered via `onData` exactly like `SessionData` is today;
   * plaintext `SessionData` from a peer is no longer expected once this
   * side has opted in (it's simply passed through unchanged, as before
   * -- this method doesn't add any negotiation-failure handling; that's
   * a later PR).
   *
   * Stream-mode: outgoing bytes are sealed and framed inline in the raw
   * byte stream (`stream-frame.mjs`'s `[len][nonce][ciphertext]` chunk
   * format, reusing the same `sealFrame`/`openFrame` primitives) --
   * invisible to the control-message spec, no new CBOR message type.
   * Small writes are batched before sealing per `opts.coalesce` (see
   * below); incoming bytes are reassembled via a `ChunkAccumulator` and
   * opened per-chunk before reaching `onData`.
   *
   * IMPORTANT -- key lifetime: `sharedSecret` must come from a *fresh*
   * `WshClient.initiateE2E()` call on the *current* connection. E2E
   * state here is connection-scoped, not session-scoped: if this
   * session is later detached and Resumed/Attached on a new connection,
   * callers MUST run `initiateE2E()` again and call `enableE2E()` again
   * with the new key -- never persist or reuse a `sharedSecret` (or its
   * counters) across a resume. Calling `enableE2E()` again on an
   * already-enabled session is fine and resets counters cleanly (a
   * fresh key naturally means fresh counters), but the caller is
   * responsible for actually supplying a fresh key when doing so.
   *
   * @param {CryptoKey} sharedSecret - AES-256-GCM CryptoKey from `WshClient.initiateE2E()`
   * @param {object} opts
   * @param {'initiator'|'responder'} opts.role - which side of the KeyExchange this session was;
   *   determines this side's nonce role tag (see `e2e-frame.mjs`'s `ROLE_TAGS`). The two peers of
   *   one session MUST pick opposite roles, or their nonces can collide.
   * @param {false|{maxBytes?: number, maxDelayMs?: number}} [opts.coalesce] - stream-mode only:
   *   override the default write-coalescing profile derived from this session's `kind`
   *   ('pty'|'exec'), or pass `false` to seal every write() immediately with no batching.
   *   Ignored for virtual-mode sessions (each write() is already one EncryptedFrame).
   */
  enableE2E(sharedSecret, { role, coalesce } = {}) {
    if (!sharedSecret || typeof sharedSecret !== 'object') {
      throw new Error('enableE2E: sharedSecret must be a CryptoKey (see WshClient.initiateE2E)');
    }
    if (role !== 'initiator' && role !== 'responder') {
      throw new Error("enableE2E: opts.role must be 'initiator' or 'responder'");
    }
    if (!this.#sessionId) {
      throw new Error('enableE2E: session has no server-assigned session_id to bind as AAD -- was OPEN_OK missing session_id?');
    }
    this.#e2eKey = sharedSecret;
    this.#e2eSendRoleTag = ROLE_TAGS[role];
    this.#e2eRecvRoleTag = role === 'initiator' ? ROLE_TAGS.responder : ROLE_TAGS.initiator;
    this.#e2eSendCounter = 0;
    this.#e2eRecvCounter = 0;

    if (this.#dataMode === 'stream') {
      // Two-data-plane counter isolation note: send/recv counters above
      // are per-session (this instance), not shared with any other data
      // plane -- a session is always exactly one of stream/virtual today,
      // so there's nothing to cross-wire, but a future refactor that let
      // one session span both planes simultaneously would need separate
      // counters per plane.
      this.#streamAccumulator = new ChunkAccumulator();
      const profile = resolveCoalesceOptions(this.kind, coalesce);
      this.#streamCoalescer = profile
        ? new WriteCoalescer(profile, (bytes) => this.#sealAndWriteStreamChunk(bytes))
        : null;
    } else {
      this.#streamAccumulator = null;
      this.#streamCoalescer = null;
    }
  }

  /**
   * Seal one stream-mode chunk and write it to the stdin stream. Used
   * directly by write() when coalescing is disabled, and as the flush
   * callback for `#streamCoalescer` otherwise.
   * @private
   */
  async #sealAndWriteStreamChunk(bytes) {
    if (this.#stdinWriter === null) {
      throw new Error('Session not yet bound — stdin writer unavailable');
    }
    const counter = this.#e2eSendCounter++;
    const { nonce, ciphertext } = await sealFrame(
      this.#e2eKey, this.#sessionId, this.#e2eSendRoleTag, counter, bytes
    );
    await this.#stdinWriter.write(encodeChunk(nonce, ciphertext));
  }

  /**
   * Feed newly-read bytes through the stream E2E accumulator and open
   * every complete chunk it yields.
   *
   * @param {Uint8Array} bytes
   * @returns {Promise<Uint8Array[]|null>} the opened plaintext chunks, in order,
   *   or `null` if framing was corrupt or a chunk failed authentication
   *   (already logged; caller should tear the pump down).
   * @private
   */
  async #openStreamChunks(bytes) {
    let wireChunks;
    try {
      wireChunks = this.#streamAccumulator.feed(bytes);
    } catch (err) {
      console.error('[wsh:session] stream E2E framing error:', err);
      return null;
    }
    const plaintexts = [];
    for (const { nonce, ciphertext } of wireChunks) {
      const counter = this.#e2eRecvCounter++;
      try {
        const plaintext = await openFrame(this.#e2eKey, this.#sessionId, counter, { nonce, ciphertext });
        plaintexts.push(plaintext);
      } catch (err) {
        console.error(
          '[wsh:session] stream E2E chunk failed authentication:',
          new StreamAuthenticationError(err.message)
        );
        return null;
      }
    }
    return plaintexts;
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
      if (this.#e2eKey !== null) {
        const bytes = typeof data === 'string' ? textEncoder.encode(data) : data;
        const counter = this.#e2eSendCounter++;
        const { nonce, ciphertext } = await sealFrame(
          this.#e2eKey, this.#sessionId, this.#e2eSendRoleTag, counter, bytes
        );
        await this.#virtualBackend.writeEncrypted({ nonce, ciphertext, sessionId: this.#sessionId });
        return;
      }
      await this.#virtualBackend.write(data);
      return;
    }
    if (this.#stdinWriter === null) {
      throw new Error('Session not yet bound — stdin writer unavailable');
    }

    const bytes = typeof data === 'string' ? textEncoder.encode(data) : data;

    if (this.#e2eKey !== null) {
      if (this.#streamCoalescer) {
        await this.#streamCoalescer.write(bytes);
      } else {
        await this.#sealAndWriteStreamChunk(bytes);
      }
      return;
    }

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
    this.#clearCloseGraceTimer();

    // Send CLOSE to the server (best-effort).
    try {
      await this.#transport.sendControl(
        closeMsg({ channelId: this.channelId })
      );
    } catch {
      // Transport may already be closed; ignore.
    }

    if (this.#dataMode === 'stream') {
      // Flush any bytes still batched by write-coalescing before closing
      // the writer, so a pending buffer isn't silently dropped.
      if (this.#streamCoalescer) {
        try {
          await this.#streamCoalescer.flush();
        } catch (err) {
          console.error('[wsh:session] failed to flush coalesced stream E2E writes on close:', err);
        }
      }

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
    this.#resolvePendingFileChunk(null);
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

      case MSG.ENCRYPTED_FRAME: {
        if (this.#e2eKey === null) {
          console.error('[wsh:session] received EncryptedFrame but E2E is not enabled on this session — dropping');
          break;
        }
        if (msg.session_id !== this.#sessionId) {
          console.error('[wsh:session] EncryptedFrame session_id mismatch — dropping (possible splice attempt)');
          break;
        }
        // openFrame is async; _handleControlMessage is a synchronous
        // dispatch entry point (see the SESSION_DATA case above and its
        // callers), so this fires the decrypt-and-deliver as a
        // background task rather than awaiting it here. Per-channel
        // control messages are already dispatched serially by the
        // caller (see transport.mjs's dispatchSerially/SerialQueue), so
        // frames still arrive at openFrame() in wire order; only the
        // delivery of *this* frame's plaintext to onData is deferred by
        // one microtask/macrotask relative to synchronous cases.
        const counter = this.#e2eRecvCounter++;
        openFrame(this.#e2eKey, this.#sessionId, counter, { nonce: msg.nonce, ciphertext: msg.ciphertext })
          .then((plaintext) => {
            this.#virtualBackend?.pushData(plaintext);
            try {
              this.onData?.(plaintext);
            } catch (err) {
              console.error('[wsh:session] onData handler error:', err);
            }
          })
          .catch((err) => {
            console.error('[wsh:session] failed to open EncryptedFrame:', err);
          });
        break;
      }

      case MSG.FILE_CHUNK: {
        if (this.#fileChunkWaiter) {
          const { resolve } = this.#fileChunkWaiter;
          this.#fileChunkWaiter = null;
          resolve(msg);
        } else {
          this.#fileChunkQueue.push(msg);
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
        // Server-initiated close. This is the authoritative close signal
        // for stream-mode sessions (wsh #24) -- it always short-circuits
        // any pending data-EOF grace timer, regardless of which arrived
        // first.
        this.#clearCloseGraceTimer();
        if (this.#state !== STATE_CLOSED) {
          this.#state = STATE_CLOSED;
          this.#abort.abort();
          this.#virtualBackend?.close();
          this.#releaseStreams();
          this.#resolvePendingFileChunk(null);
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

  // ── File transfer ────────────────────────────────────────────────────

  /**
   * Wait for the next FileChunk control message on this channel.
   * Used by WshClient.upload/download for 'file'-kind sessions — file
   * transfer moves bytes as ordinary FileChunk control messages rather
   * than through write()/read(), so it works the same whether the
   * channel's data plane is stream- or virtual-backed.
   *
   * Returns `null` if the session closes before another chunk arrives
   * (a truncated transfer, distinct from a chunk with is_final=true).
   *
   * @returns {Promise<object|null>}
   * @internal
   */
  async _readFileChunk() {
    if (this.#fileChunkQueue.length > 0) {
      return this.#fileChunkQueue.shift();
    }
    if (this.#state === STATE_CLOSED) {
      return null;
    }
    return new Promise((resolve, reject) => {
      this.#fileChunkWaiter = { resolve, reject };
    });
  }

  /**
   * Resolve (or clear) any pending _readFileChunk() waiter.
   * @private
   */
  #resolvePendingFileChunk(value) {
    if (this.#fileChunkWaiter) {
      const { resolve } = this.#fileChunkWaiter;
      this.#fileChunkWaiter = null;
      resolve(value);
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
        if (done) {
          // Clean EOF: catch a torn (truncated) chunk left in the E2E
          // accumulator, if any -- per the design, no partial-chunk
          // plaintext is ever released, so this is purely a diagnostic
          // (the stream is ending either way).
          if (this.#e2eKey !== null && this.#streamAccumulator) {
            try {
              this.#streamAccumulator.finish();
            } catch (err) {
              console.error('[wsh:session] stream E2E torn chunk at stream end:', err);
            }
          }
          break;
        }

        if (value && value.byteLength > 0) {
          if (this.#e2eKey !== null && this.#streamAccumulator) {
            const deliverable = await this.#openStreamChunks(value);
            if (deliverable === null) {
              // Authentication failure (or corrupt framing) -- matches
              // the strict "no skip-and-continue" philosophy of
              // virtual-mode's counter check: tear the session down
              // rather than deliver anything from this point on.
              break;
            }
            for (const plaintext of deliverable) {
              try {
                this.onData?.(plaintext);
              } catch (err) {
                console.error('[wsh:session] onData handler error:', err);
              }
            }
          } else {
            try {
              this.onData?.(value);
            } catch (err) {
              console.error('[wsh:session] onData handler error:', err);
            }
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

    // The data stream ended, but its FIN carries no ordering guarantee
    // relative to the control stream (wsh #24): a server that closes the
    // data stream and sends EXIT/CLOSE around the same time can have
    // this EOF arrive before those control messages. Closing the session
    // here unconditionally would resolve onClose without onExit ever
    // having fired. Instead, give the (expected) CLOSE control message a
    // bounded grace period to arrive -- its handler clears this timer and
    // performs the real transition -- and only self-close on timeout as a
    // fallback for servers that never send CLOSE after ending the data
    // stream.
    if (this.#state !== STATE_CLOSED && this.#closeGraceTimer === null) {
      this.#closeGraceTimer = setTimeout(() => {
        this.#closeGraceTimer = null;
        if (this.#state !== STATE_CLOSED) {
          this.#state = STATE_CLOSED;
          this.#releaseStreams();
          this.#emitClose();
        }
      }, DATA_EOF_CLOSE_GRACE_MS);
      this.#closeGraceTimer?.unref?.();
    }
  }

  // ── Private helpers ─────────────────────────────────────────────────

  /**
   * Cancel any pending data-EOF close-grace timer (wsh #24). Safe to call
   * whether or not a timer is currently scheduled.
   * @private
   */
  #clearCloseGraceTimer() {
    if (this.#closeGraceTimer !== null) {
      clearTimeout(this.#closeGraceTimer);
      this.#closeGraceTimer = null;
    }
  }

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
