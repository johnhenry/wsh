/**
 * WshClient — manages a wsh connection, authentication, and multiple sessions.
 *
 * Handles the full lifecycle: transport selection, handshake, challenge-response
 * or password auth, channel multiplexing, ping/pong keepalive, and teardown.
 *
 * Supports forward connections (client opens sessions on a remote server) and
 * reverse mode (client registers as a peer for incoming connections).
 */

import { WebTransportTransport } from './transport.mjs';
import { WebSocketTransport } from './transport-ws.mjs';
import {
  MSG, AUTH_METHOD,
  hello, auth as authMsg, open as openMsg, close as closeMsg,
  attach as attachMsg, resume as resumeMsg, ping as pingMsg, pong as pongMsg,
  reverseRegister as reverseRegisterMsg, reverseList as reverseListMsg,
  reverseConnect as reverseConnectMsg,
  mcpDiscover as mcpDiscoverMsg, mcpCall as mcpCallMsg,
  suspendSession as suspendSessionMsg, restartPty as restartPtyMsg,
  metricsRequest as metricsRequestMsg,
  guestInvite as guestInviteMsg, guestJoin as guestJoinMsg, guestRevoke as guestRevokeMsg,
  shareSession as shareSessionMsg, shareRevoke as shareRevokeMsg,
  compressBegin as compressBeginMsg, compressAck as compressAckMsg,
  rateControl as rateControlMsg,
  sessionLink as sessionLinkMsg, sessionUnlink as sessionUnlinkMsg,
  copilotAttach as copilotAttachMsg, copilotSuggest as copilotSuggestMsg,
  copilotDetach as copilotDetachMsg,
  keyExchange as keyExchangeMsg,
  fileOp as fileOpMsg,
  policyEval as policyEvalMsg, policyUpdate as policyUpdateMsg,
} from './messages.mjs';
import { signChallenge, exportPublicKeyRaw } from './auth.mjs';
import { WshSession } from './session.mjs';

// ── Client states ─────────────────────────────────────────────────────

const STATE_DISCONNECTED  = 'disconnected';
const STATE_CONNECTING    = 'connecting';
const STATE_CONNECTED     = 'connected';
const STATE_AUTHENTICATED = 'authenticated';
const STATE_CLOSED        = 'closed';

// ── Defaults ──────────────────────────────────────────────────────────

const DEFAULT_AUTH_TIMEOUT   = 10_000;  // ms
const DEFAULT_OPEN_TIMEOUT   = 10_000;  // ms
const DEFAULT_PING_INTERVAL  = 30_000;  // ms
const DEFAULT_EXEC_TIMEOUT   = 60_000;  // ms
const FILE_CHUNK_SIZE        = 65_536;

const textEncoder = new TextEncoder();

function buildUploadHeader(path, totalSize) {
  const pathBytes = textEncoder.encode(path);
  const header = new Uint8Array(4 + pathBytes.length + 8);
  const view = new DataView(header.buffer);
  view.setUint32(0, pathBytes.length);
  header.set(pathBytes, 4);
  writeU64(header, 4 + pathBytes.length, totalSize);
  return header;
}

function buildDownloadHeader(path) {
  const pathBytes = textEncoder.encode(path);
  const header = new Uint8Array(4 + pathBytes.length);
  const view = new DataView(header.buffer);
  view.setUint32(0, pathBytes.length);
  header.set(pathBytes, 4);
  return header;
}

function writeU64(buffer, offset, value) {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const big = BigInt(value);
  view.setBigUint64(offset, big);
}

function decodeU64(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return Number(view.getBigUint64(0));
}

function createSessionReader(session) {
  let remainder = new Uint8Array();
  return {
    async readExact(totalBytes) {
      const output = new Uint8Array(totalBytes);
      let offset = 0;

      while (offset < totalBytes) {
        if (remainder.byteLength === 0) {
          const chunk = await session.read();
          if (chunk === null) {
            return null;
          }
          remainder = chunk;
        }

        const take = Math.min(totalBytes - offset, remainder.byteLength);
        output.set(remainder.subarray(0, take), offset);
        offset += take;
        remainder = remainder.subarray(take);
      }

      return output;
    },
    async readChunk() {
      if (remainder.byteLength > 0) {
        const chunk = remainder;
        remainder = new Uint8Array();
        return chunk;
      }
      return await session.read();
    },
  };
}

// ── Client class ──────────────────────────────────────────────────────

export class WshClient {

  /** @type {'disconnected'|'connecting'|'connected'|'authenticated'|'closed'} */
  #state = STATE_DISCONNECTED;

  /** @type {string|null} Session ID assigned by the server after authentication. */
  #sessionId = null;

  /** @type {string|null} Resume token from AUTH_OK. */
  #resumeToken = null;

  /** @type {import('./transport.mjs').WshTransport|null} Active transport. */
  #transport = null;

  /** @type {{ wt: () => import('./transport.mjs').WshTransport, ws: () => import('./transport.mjs').WshTransport }} */
  #transportFactories;

  /** @type {Map<number, WshSession>} Active sessions keyed by channel ID. */
  #sessions = new Map();

  /** @type {number} Monotonically increasing channel ID counter. */
  #channelCounter = 0;

  /**
   * Pending message waiters: Map<messageType, Array<{resolve, reject, timer}>>
   * Multiple waiters can exist for the same message type.
   */
  #waiters = new Map();

  /** @type {string[]} Server-advertised features from SERVER_HELLO. */
  #serverFeatures = [];

  /** @type {number|null} Ping interval handle. */
  #pingTimer = null;

  /** @type {number} Current ping ID for matching pongs. */
  #pingId = 0;

  /** @type {number|null} Timestamp of last pong received. */
  #lastPong = null;

  constructor({ transportFactories } = {}) {
    this.#transportFactories = transportFactories || {
      wt: () => new WebTransportTransport(),
      ws: () => new WebSocketTransport(),
    };
  }

  // ── Callbacks ───────────────────────────────────────────────────────

  /** Called when the connection is closed (intentionally or otherwise). */
  onClose = null;

  /** Called on connection-level errors. */
  onError = null;

  /**
   * Called when a reverse-connect request arrives (reverse mode only).
   * @type {function(object): void|null}
   */
  onReverseConnect = null;

  /**
   * Called when a clipboard sync message arrives (OSC 52).
   * The default handler writes to navigator.clipboard automatically.
   * @type {function(object): void|null}
   */
  onClipboard = null;

  /**
   * Called when a relay-forwarded message arrives from a remote peer.
   *
   * In reverse mode, the relay bridge forwards messages from the CLI peer
   * to this browser client.  Messages that the client would not normally
   * receive as a peer (Open, McpCall, McpDiscover, Close, Resize, Signal)
   * are routed here instead of being silently dropped.
   *
   * @type {function(object): void|null}
   */
  onRelayMessage = null;

  /**
   * Called when a rate warning message arrives from the server.
   * @type {function(object): void|null}
   */
  onRateWarning = null;

  /**
   * Called when a copilot suggestion arrives from an attached copilot.
   * @type {function(object): void|null}
   */
  onCopilotSuggest = null;

  /**
   * Called when a key exchange message arrives from a peer.
   * @type {function(object): void|null}
   */
  onKeyExchange = null;

  /**
   * Called when a gateway-subsystem control message arrives (opcodes 0x70-0x7f).
   *
   * The gateway subsystem proxies TCP/UDP connections and DNS lookups through
   * the server.  This callback receives every gateway message that is not
   * consumed by an active waiter (e.g. a pending GatewayOk/GatewayFail for
   * an in-flight request).
   *
   * Typical use: wire this to the netway GatewayBackend so it can route
   * GatewayOk, GatewayFail, GatewayClose, DnsResult, InboundOpen, ListenOk,
   * and ListenFail messages to the correct virtual sockets and listeners.
   *
   * @type {function(object): void|null}
   * @param {object} msg - Decoded control message with at least:
   *   - `type` {number}  — message opcode (0x70-0x7f)
   *   - `gateway_id` or `listener_id` {number} — correlator
   *   - Plus message-specific fields (see wsh-v1.yaml gateway section)
   */
  onGatewayMessage = null;

  // ── Public properties ───────────────────────────────────────────────

  /** Current client state. */
  get state() {
    return this.#state;
  }

  /** Server-assigned session ID. */
  get sessionId() {
    return this.#sessionId;
  }

  /** Read-only view of active sessions. */
  get sessions() {
    return new Map(this.#sessions);
  }

  /** Server-advertised features from SERVER_HELLO. */
  get features() {
    return [...this.#serverFeatures];
  }

  /**
   * Low-level transport reference.
   * Exposed for relay message replies (IncomingSession._sendReply).
   * Prefer higher-level methods (openSession, callTool, etc.) for normal use.
   * @returns {import('./transport.mjs').WshTransport|null}
   */
  get _transport() {
    return this.#transport;
  }

  /**
   * Check if the server advertised a specific feature.
   * @param {string} name - Feature name (e.g. 'gateway', 'reverse', 'mcp')
   * @returns {boolean}
   */
  hasFeature(name) {
    return this.#serverFeatures.includes(name);
  }

  // ── Connection ──────────────────────────────────────────────────────

  /**
   * Connect to a wsh server, authenticate, and return the session ID.
   *
   * @param {string} url - Server URL (https:// for WebTransport, wss:// or ws:// for WebSocket)
   * @param {object} opts
   * @param {string} opts.username - Username for authentication
   * @param {CryptoKeyPair} [opts.keyPair] - Ed25519 key pair for pubkey auth
   * @param {string} [opts.password] - Password for password auth
   * @param {'wt'|'ws'|'auto'} [opts.transport] - Force a specific transport
   * @param {number} [opts.timeout] - Auth handshake timeout in ms
   * @returns {Promise<string>} The server-assigned session ID
   */
  async connect(url, { username, keyPair, password, transport: transportHint, timeout = DEFAULT_AUTH_TIMEOUT } = {}) {
    if (this.#state !== STATE_DISCONNECTED && this.#state !== STATE_CLOSED) {
      throw new Error(`Client already ${this.#state}`);
    }
    if (!username) {
      throw new Error('username is required');
    }
    if (!keyPair && !password) {
      throw new Error('Either keyPair or password is required for authentication');
    }

    this.#state = STATE_CONNECTING;
    this.#sessions.clear();
    this.#channelCounter = 0;
    this.#waiters.clear();
    this.#sessionId = null;
    this.#resumeToken = null;

    try {
      // ── Select and connect transport ──────────────────────────────
      const transport = await this.#connectTransport(url, transportHint);
      this.#transport = transport;
      this.#state = STATE_CONNECTED;

      // ── Auth handshake ────────────────────────────────────────────
      const authMethod = keyPair ? AUTH_METHOD.PUBKEY : AUTH_METHOD.PASSWORD;
      await transport.sendControl(
        hello({ username, authMethod })
      );

      // Wait for SERVER_HELLO (which may include a session ID directly) or CHALLENGE.
      const firstResponse = await this.#waitForMessage(
        [MSG.SERVER_HELLO, MSG.CHALLENGE, MSG.AUTH_FAIL],
        timeout,
        'Auth handshake timed out waiting for server response'
      );

      if (firstResponse.type === MSG.AUTH_FAIL) {
        throw new Error(`Authentication failed: ${firstResponse.reason || 'unknown'}`);
      }

      let tempSessionId = null;

      if (firstResponse.type === MSG.SERVER_HELLO) {
        // Server may proceed directly to auth if it accepted the hello.
        tempSessionId = firstResponse.session_id;
        this.#serverFeatures = firstResponse.features || [];

        // If pubkey auth, we still need a challenge.
        if (authMethod === AUTH_METHOD.PUBKEY) {
          const challengeMsg = await this.#waitForMessage(
            [MSG.CHALLENGE, MSG.AUTH_OK],
            timeout,
            'Auth handshake timed out waiting for challenge'
          );

          if (challengeMsg.type === MSG.AUTH_OK) {
            // Server accepted without challenge (e.g. trusted key).
            this.#sessionId = challengeMsg.session_id || tempSessionId;
            this.#resumeToken = challengeMsg.token || null;
            this.#state = STATE_AUTHENTICATED;
            this.#startPing();
            return this.#sessionId;
          }

          // Sign the challenge.
          const { signature, publicKeyRaw } = await signChallenge(
            keyPair.privateKey,
            keyPair.publicKey,
            tempSessionId,
            challengeMsg.nonce
          );

          await transport.sendControl(
            authMsg({
              method: AUTH_METHOD.PUBKEY,
              signature,
              publicKey: publicKeyRaw,
            })
          );
        } else {
          // Password auth — send immediately after SERVER_HELLO.
          await transport.sendControl(
            authMsg({
              method: AUTH_METHOD.PASSWORD,
              password,
            })
          );
        }
      } else if (firstResponse.type === MSG.CHALLENGE) {
        // Some servers skip SERVER_HELLO and go straight to CHALLENGE.
        if (authMethod !== AUTH_METHOD.PUBKEY || !keyPair) {
          throw new Error('Server sent CHALLENGE but no key pair was provided');
        }

        // We need a session ID for the transcript. Use the nonce-derived ID
        // or a placeholder if the server hasn't provided one.
        tempSessionId = tempSessionId || 'pending';

        const { signature, publicKeyRaw } = await signChallenge(
          keyPair.privateKey,
          keyPair.publicKey,
          tempSessionId,
          firstResponse.nonce
        );

        await transport.sendControl(
          authMsg({
            method: AUTH_METHOD.PUBKEY,
            signature,
            publicKey: publicKeyRaw,
          })
        );
      }

      // Wait for AUTH_OK or AUTH_FAIL.
      const authResult = await this.#waitForMessage(
        [MSG.AUTH_OK, MSG.AUTH_FAIL],
        timeout,
        'Auth handshake timed out waiting for auth result'
      );

      if (authResult.type === MSG.AUTH_FAIL) {
        throw new Error(`Authentication failed: ${authResult.reason || 'rejected'}`);
      }

      this.#sessionId = authResult.session_id || tempSessionId;
      this.#resumeToken = authResult.token || null;
      this.#state = STATE_AUTHENTICATED;
      this.#startPing();

      return this.#sessionId;

    } catch (err) {
      // Clean up on failure.
      this.#state = STATE_CLOSED;
      await this.#transport?.close().catch(() => {});
      this.#transport = null;
      this.#rejectAllWaiters(err);
      throw err;
    }
  }

  // ── Session management ──────────────────────────────────────────────

  /**
   * Open a new PTY or exec session on the remote server.
   *
   * @param {object} opts
   * @param {'pty'|'exec'} opts.type - Channel kind
   * @param {string} [opts.command] - Command to execute (required for exec, optional for pty)
   * @param {number} [opts.cols=80] - Initial terminal columns
   * @param {number} [opts.rows=24] - Initial terminal rows
   * @param {object} [opts.env] - Environment variables
   * @param {number} [opts.timeout] - Timeout in ms
   * @returns {Promise<WshSession>}
   */
  async openSession({ type = 'pty', command, cols = 80, rows = 24, env, timeout = DEFAULT_OPEN_TIMEOUT } = {}) {
    this.#assertAuthenticated('openSession');
    const requestedChannelId = this._nextChannelId();

    await this.#transport.sendControl(
      openMsg({ kind: type, command, cols, rows, env })
    );

    // Wait for OPEN_OK or OPEN_FAIL.
    const response = await this.#waitForMessage(
      [MSG.OPEN_OK, MSG.OPEN_FAIL],
      timeout,
      'Timed out waiting for session open response'
    );

    if (response.type === MSG.OPEN_FAIL) {
      throw new Error(`Failed to open session: ${response.reason || 'rejected'}`);
    }

    const serverChannelId = response.channel_id ?? requestedChannelId;
    const streamIds = response.stream_ids ?? {};
    const dataMode = response.data_mode === 'virtual' ? 'virtual' : 'stream';
    const capabilities = Array.isArray(response.capabilities) ? response.capabilities : [];

    // Create the session object.
    const session = new WshSession(
      this.#transport,
      serverChannelId,
      streamIds,
      type,
      { dataMode, capabilities }
    );
    this.#sessions.set(serverChannelId, session);

    if (dataMode === 'virtual') {
      session._activateVirtual((msg) => this.sendRelayControl(msg));
      return session;
    }

    // Open the data stream and bind it to the session.
    const stream = await this.#transport.openStream();
    session._bind(stream.readable, stream.writable);

    return session;
  }

  /**
   * List locally tracked sessions with their current state.
   * @returns {Array<{channelId: number, kind: string, state: string}>}
   */
  listSessions() {
    const result = [];
    for (const [channelId, session] of this.#sessions) {
      result.push({
        channelId,
        kind: session.kind,
        state: session.state,
      });
    }
    return result;
  }

  /**
   * Attach to an existing remote session (collaborative or read-only).
   *
   * @param {string} targetSessionId - Remote session ID to attach to
   * @param {object} [opts]
   * @param {boolean} [opts.readOnly=false] - Attach in read-only mode
   * @param {number} [opts.timeout] - Timeout in ms
   * @returns {Promise<object>} Server's response
   */
  async attachSession(targetSessionId, { readOnly = false, timeout = DEFAULT_OPEN_TIMEOUT } = {}) {
    this.#assertAuthenticated('attachSession');

    const mode = readOnly ? 'readonly' : 'control';
    await this.#transport.sendControl(
      attachMsg({ sessionId: targetSessionId, token: this.#resumeToken, mode })
    );

    const response = await this.#waitForMessage(
      [MSG.OPEN_OK, MSG.OPEN_FAIL],
      timeout,
      'Timed out waiting for attach response'
    );

    if (response.type === MSG.OPEN_FAIL) {
      throw new Error(`Failed to attach: ${response.reason || 'rejected'}`);
    }

    return response;
  }

  /**
   * Resume a previously disconnected session.
   *
   * @param {string} targetSessionId - Session ID to resume
   * @param {string} token - Resume token from original AUTH_OK
   * @param {number} [opts.timeout] - Timeout in ms
   * @returns {Promise<object>} Server's response
   */
  async resumeSession(targetSessionId, token, { timeout = DEFAULT_OPEN_TIMEOUT } = {}) {
    this.#assertAuthenticated('resumeSession');

    await this.#transport.sendControl(
      resumeMsg({ sessionId: targetSessionId, token })
    );

    const response = await this.#waitForMessage(
      [MSG.AUTH_OK, MSG.AUTH_FAIL],
      timeout,
      'Timed out waiting for resume response'
    );

    if (response.type === MSG.AUTH_FAIL) {
      throw new Error(`Failed to resume: ${response.reason || 'rejected'}`);
    }

    return response;
  }

  // ── Disconnect ──────────────────────────────────────────────────────

  /**
   * Gracefully disconnect: close all sessions and the transport.
   */
  async disconnect() {
    if (this.#state === STATE_DISCONNECTED || this.#state === STATE_CLOSED) return;

    this.#stopPing();
    this.#state = STATE_CLOSED;

    // Close all sessions concurrently.
    const closePromises = [];
    for (const session of this.#sessions.values()) {
      closePromises.push(session.close().catch(() => {}));
    }
    await Promise.allSettled(closePromises);
    this.#sessions.clear();

    // Close the transport.
    if (this.#transport) {
      await this.#transport.close().catch(() => {});
      this.#transport = null;
    }

    this.#rejectAllWaiters(new Error('Client disconnected'));
  }

  // ── Static one-shot exec ────────────────────────────────────────────

  /**
   * One-shot command execution: connect, authenticate, run a command,
   * collect all output, disconnect, and return the result.
   *
   * @param {string} url - Server URL
   * @param {string} command - Command to execute
   * @param {object} opts
   * @param {string} opts.username
   * @param {CryptoKeyPair} [opts.keyPair]
   * @param {string} [opts.password]
   * @param {number} [opts.timeout=60000] - Overall timeout in ms
   * @returns {Promise<{stdout: Uint8Array, exitCode: number}>}
   */
  static async exec(url, command, { username, keyPair, password, timeout = DEFAULT_EXEC_TIMEOUT } = {}) {
    const client = new WshClient();
    const chunks = [];
    let exitCode = -1;

    try {
      await client.connect(url, { username, keyPair, password });

      const session = await client.openSession({ type: 'exec', command });

      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error(`exec timed out after ${timeout}ms`));
        }, timeout);

        session.onData = (data) => {
          chunks.push(data);
        };

        session.onExit = (code) => {
          exitCode = code;
        };

        session.onClose = () => {
          clearTimeout(timer);
          resolve();
        };
      });

    } finally {
      await client.disconnect().catch(() => {});
    }

    // Concatenate output chunks.
    const totalLength = chunks.reduce((sum, c) => sum + c.byteLength, 0);
    const stdout = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      stdout.set(chunk, offset);
      offset += chunk.byteLength;
    }

    return { stdout, exitCode };
  }

  // ── Reverse mode ────────────────────────────────────────────────────

  /**
   * Connect in reverse mode: register as a peer that can accept incoming
   * connections from other clients.
   *
   * @param {string} url - Server URL
   * @param {object} opts
   * @param {string} opts.username
   * @param {CryptoKeyPair} [opts.keyPair]
   * @param {string} [opts.password]
   * @param {object} [opts.expose] - Capabilities to expose { shell, exec, fs, tools }
   * @param {string} [opts.peerType]
   * @param {string} [opts.shellBackend]
   * @param {boolean} [opts.supportsAttach]
   * @param {boolean} [opts.supportsReplay]
   * @param {boolean} [opts.supportsEcho]
   * @param {boolean} [opts.supportsTermSync]
   * @returns {Promise<string>} Session ID
   */
  async connectReverse(url, {
    username,
    keyPair,
    password,
    expose = {},
    peerType = 'browser-shell',
    shellBackend,
    supportsAttach,
    supportsReplay,
    supportsEcho,
    supportsTermSync,
  } = {}) {
    // Authenticate normally first.
    const sessionId = await this.connect(url, { username, keyPair, password });

    // Build capabilities list from expose options.
    const capabilities = [];
    if (expose.shell) capabilities.push('shell');
    if (expose.exec) capabilities.push('exec');
    if (expose.fs) capabilities.push('fs');
    if (expose.tools) capabilities.push('tools');

    // Export public key for peer identification.
    let publicKey = null;
    if (keyPair) {
      publicKey = await exportPublicKeyRaw(keyPair.publicKey);
    }

    const effectiveShellBackend = shellBackend || (expose.shell ? 'virtual-shell' : 'exec-only');

    // Register as a reverse peer.
    await this.#transport.sendControl(
      reverseRegisterMsg({
        username,
        capabilities,
        peerType,
        shellBackend: effectiveShellBackend,
        supportsAttach: supportsAttach ?? effectiveShellBackend !== 'exec-only',
        supportsReplay: supportsReplay ?? effectiveShellBackend !== 'exec-only',
        supportsEcho: supportsEcho ?? effectiveShellBackend === 'virtual-shell',
        supportsTermSync: supportsTermSync ?? effectiveShellBackend === 'virtual-shell',
        publicKey,
      })
    );

    return sessionId;
  }

  /**
   * List peers registered on the relay server.
   *
   * @param {number} [timeout=10000] - Timeout in ms
   * @returns {Promise<Array<{fingerprint_short: string, username: string, capabilities: string[], last_seen: number|null}>>}
   */
  async listPeers(timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('listPeers');

    await this.#transport.sendControl(reverseListMsg());

    const response = await this.#waitForMessage(
      [MSG.REVERSE_PEERS],
      timeout,
      'Timed out waiting for peer list'
    );

    return response.peers || [];
  }

  /**
   * Initiate a reverse connection to a registered peer.
   *
   * @param {string} targetFingerprint - Fingerprint (or prefix) of the target peer
   * @param {number} [timeout=10000] - Timeout in ms
   * @returns {Promise<void>}
   */
  async reverseConnectTo(targetFingerprint, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('reverseConnectTo');

    const response = await this.reverseConnect(targetFingerprint, timeout);
    return response;
  }

  /**
   * Initiate a reverse connection and wait for accept/reject.
   *
   * @param {string} targetFingerprint
   * @param {number} [timeout=10000]
   * @returns {Promise<object>}
   */
  async reverseConnect(targetFingerprint, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('reverseConnect');

    await this.#transport.sendControl(
      reverseConnectMsg({ targetFingerprint, username: '' })
    );

    return this.#waitForMessage(
      [MSG.REVERSE_ACCEPT, MSG.REVERSE_REJECT],
      timeout,
      'Timed out waiting for reverse-connect response'
    );
  }

  /**
   * Send a control message over the authenticated relay connection.
   *
   * Browser reverse handlers use this for peer replies instead of touching
   * the transport internals directly.
   *
   * @param {object} msg
   * @returns {Promise<void>}
   */
  async sendRelayControl(msg) {
    this.#assertAuthenticated('sendRelayControl');
    await this.#transport.sendControl(msg);
  }

  // ── File transfer ───────────────────────────────────────────────────

  /**
   * Upload a blob to a remote path.
   *
   * Opens a file channel, writes the data, and waits for acknowledgment.
   *
   * @param {Blob|Uint8Array} blob - Data to upload
   * @param {string} remotePath - Destination path on the server
   * @param {object} [opts]
   * @param {function(number): void} [opts.onProgress] - Progress callback (bytes sent)
   */
  async upload(blob, remotePath, { onProgress } = {}) {
    this.#assertAuthenticated('upload');
    const session = await this.openSession({ type: 'file', command: `upload:${remotePath}` });
    const data = blob instanceof Blob
      ? new Uint8Array(await blob.arrayBuffer())
      : blob;
    const total = data.byteLength;
    const header = buildUploadHeader(remotePath, total);
    let sent = 0;

    try {
      await session.write(header);
      for (let i = 0; i < total; i += FILE_CHUNK_SIZE) {
        const end = Math.min(i + FILE_CHUNK_SIZE, total);
        await session.write(data.subarray(i, end));
        sent = end;
        onProgress?.(sent);
      }

      const ack = await session.read();
      if (ack === null) {
        throw new Error('Upload failed: unexpected EOF waiting for server acknowledgement');
      }
    } finally {
      await session.close().catch(() => {});
    }
  }

  /**
   * Download a file from a remote path.
   *
   * @param {string} remotePath - Source path on the server
   * @returns {Promise<Uint8Array>} File contents
   */
  async download(remotePath) {
    this.#assertAuthenticated('download');
    const session = await this.openSession({ type: 'file', command: `download:${remotePath}` });

    try {
      const reader = createSessionReader(session);
      await session.write(buildDownloadHeader(remotePath));

      const sizeChunk = await reader.readExact(8);
      if (sizeChunk === null) {
        throw new Error('Download failed: unexpected EOF reading file size');
      }
      const totalSize = decodeU64(sizeChunk);
      const data = new Uint8Array(totalSize);
      let offset = 0;

      while (offset < totalSize) {
        const chunk = await reader.readChunk();
        if (chunk === null) {
          throw new Error('Download failed: unexpected EOF reading file payload');
        }
        const remaining = totalSize - offset;
        data.set(chunk.subarray(0, remaining), offset);
        offset += Math.min(chunk.byteLength, remaining);
      }

      return data;
    } finally {
      await session.close().catch(() => {});
    }
  }

  // ── MCP integration ─────────────────────────────────────────────────

  /**
   * Discover MCP tools available on the remote server.
   *
   * @param {number} [timeout=10000]
   * @returns {Promise<Array>} Tool definitions
   */
  async discoverTools(timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('discoverTools');

    await this.#transport.sendControl(mcpDiscoverMsg());

    const response = await this.#waitForMessage(
      [MSG.MCP_TOOLS],
      timeout,
      'Timed out waiting for MCP tool discovery response'
    );

    return response.tools || [];
  }

  /**
   * Call an MCP tool on the remote server.
   *
   * @param {string} name - Tool name
   * @param {object} args - Tool arguments
   * @param {number} [timeout=30000]
   * @returns {Promise<*>} Tool result
   */
  async callTool(name, args, timeout = 30_000) {
    this.#assertAuthenticated('callTool');

    await this.#transport.sendControl(
      mcpCallMsg({ tool: name, arguments: args })
    );

    const response = await this.#waitForMessage(
      [MSG.MCP_RESULT],
      timeout,
      `Timed out waiting for MCP tool result (${name})`
    );

    return response.result;
  }

  // ── Suspend / Restart ───────────────────────────────────────────────

  /**
   * Suspend a session on the server.
   * @param {string} sessionId - Session to suspend
   * @param {string} [action='suspend'] - Action: 'suspend' or 'hibernate'
   */
  async suspendSession(sessionId, action = 'suspend') {
    this.#assertAuthenticated('suspendSession');
    await this.#transport.sendControl(suspendSessionMsg({ sessionId, action }));
  }

  /**
   * Restart the PTY process in a session.
   * @param {string} sessionId - Session whose PTY to restart
   * @param {string} [command] - Optional new command (defaults to original)
   */
  async restartPty(sessionId, command) {
    this.#assertAuthenticated('restartPty');
    await this.#transport.sendControl(restartPtyMsg({ sessionId, command }));
  }

  // ── Metrics ────────────────────────────────────────────────────────

  /**
   * Request server metrics (CPU, memory, sessions, RTT).
   * @param {number} [timeout=10000]
   * @returns {Promise<object>} Metrics response
   */
  async requestMetrics(timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('requestMetrics');
    await this.#transport.sendControl(metricsRequestMsg());
    return this.#waitForMessage(
      [MSG.METRICS],
      timeout,
      'Timed out waiting for metrics'
    );
  }

  // ── Guest Sessions ────────────────────────────────────────────────

  /**
   * Invite a guest to a session.
   * @param {string} sessionId - Session to share
   * @param {number} ttl - Invitation TTL in seconds
   * @param {string[]} [permissions=['read']] - Guest permissions
   * @param {number} [timeout=10000]
   * @returns {Promise<object>} Invite response with token
   */
  async inviteGuest(sessionId, ttl, permissions = ['read'], timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('inviteGuest');
    await this.#transport.sendControl(guestInviteMsg({ sessionId, ttl, permissions }));
    return this.#waitForMessage(
      [MSG.GUEST_INVITE],
      timeout,
      'Timed out waiting for guest invite confirmation'
    );
  }

  /**
   * Join a session as a guest.
   * @param {string} token - Invitation token
   * @param {string} [deviceLabel] - Device identifier
   * @param {number} [timeout=10000]
   * @returns {Promise<object>} Join response
   */
  async joinAsGuest(token, deviceLabel, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('joinAsGuest');
    await this.#transport.sendControl(guestJoinMsg({ token, deviceLabel }));
    return this.#waitForMessage(
      [MSG.PRESENCE, MSG.AUTH_FAIL],
      timeout,
      'Timed out waiting for guest join response'
    );
  }

  /**
   * Revoke a guest invitation.
   * @param {string} token - Token to revoke
   * @param {string} [reason] - Reason for revocation
   */
  async revokeGuest(token, reason) {
    this.#assertAuthenticated('revokeGuest');
    await this.#transport.sendControl(guestRevokeMsg({ token, reason }));
  }

  // ── Session Sharing ───────────────────────────────────────────────

  /**
   * Share a session for multi-attach.
   * @param {string} sessionId - Session to share
   * @param {string} [mode='read'] - Share mode
   * @param {number} [ttl] - Share TTL in seconds
   * @param {number} [timeout=10000]
   * @returns {Promise<object>} Share response with share_id
   */
  async shareSession(sessionId, mode = 'read', ttl, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('shareSession');
    await this.#transport.sendControl(shareSessionMsg({ sessionId, mode, ttl }));
    return this.#waitForMessage(
      [MSG.SHARE_SESSION],
      timeout,
      'Timed out waiting for share confirmation'
    );
  }

  /**
   * Revoke a session share.
   * @param {string} shareId - Share ID to revoke
   * @param {string} [reason] - Reason for revocation
   */
  async revokeShare(shareId, reason) {
    this.#assertAuthenticated('revokeShare');
    await this.#transport.sendControl(shareRevokeMsg({ shareId, reason }));
  }

  // ── Compression ───────────────────────────────────────────────────

  /**
   * Negotiate compression with the server.
   * @param {string} algorithm - Compression algorithm (e.g. 'zstd', 'lz4')
   * @param {number} [level=3] - Compression level
   * @param {number} [timeout=10000]
   * @returns {Promise<object>} CompressAck response
   */
  async negotiateCompression(algorithm, level = 3, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('negotiateCompression');
    await this.#transport.sendControl(compressBeginMsg({ algorithm, level }));
    return this.#waitForMessage(
      [MSG.COMPRESS_ACK],
      timeout,
      'Timed out waiting for compression acknowledgment'
    );
  }

  // ── Rate Control ──────────────────────────────────────────────────

  /**
   * Set rate control parameters for a session.
   * @param {string} sessionId - Session to rate-limit
   * @param {number} maxBytesPerSec - Maximum throughput
   * @param {string} [policy='pause'] - Rate limit policy
   */
  async setRateControl(sessionId, maxBytesPerSec, policy = 'pause') {
    this.#assertAuthenticated('setRateControl');
    await this.#transport.sendControl(rateControlMsg({ sessionId, maxBytesPerSec, policy }));
  }

  // ── Session Linking ───────────────────────────────────────────────

  /**
   * Link two sessions across hosts.
   * @param {string} sourceSession - Source session ID
   * @param {string} targetHost - Target host
   * @param {number} targetPort - Target port
   * @param {string} [targetUser] - Target username
   */
  async linkSession(sourceSession, targetHost, targetPort, targetUser) {
    this.#assertAuthenticated('linkSession');
    await this.#transport.sendControl(
      sessionLinkMsg({ sourceSession, targetHost, targetPort, targetUser })
    );
  }

  /**
   * Unlink a previously linked session.
   * @param {string} linkId - Link ID to remove
   * @param {string} [reason] - Reason for unlinking
   */
  async unlinkSession(linkId, reason) {
    this.#assertAuthenticated('unlinkSession');
    await this.#transport.sendControl(sessionUnlinkMsg({ linkId, reason }));
  }

  // ── Copilot ───────────────────────────────────────────────────────

  /**
   * Attach a copilot to a session.
   * @param {string} sessionId - Session to attach to
   * @param {string} model - Model name
   * @param {number} [contextWindow] - Context window size
   */
  async copilotAttach(sessionId, model, contextWindow) {
    this.#assertAuthenticated('copilotAttach');
    await this.#transport.sendControl(
      copilotAttachMsg({ sessionId, model, contextWindow })
    );
  }

  /**
   * Send a copilot suggestion.
   * @param {string} sessionId - Session ID
   * @param {string} suggestion - Suggestion text
   * @param {number} [confidence] - Confidence score 0-1
   */
  async copilotSuggest(sessionId, suggestion, confidence) {
    this.#assertAuthenticated('copilotSuggest');
    await this.#transport.sendControl(
      copilotSuggestMsg({ sessionId, suggestion, confidence })
    );
  }

  /**
   * Detach a copilot from a session.
   * @param {string} sessionId - Session ID
   * @param {string} [reason] - Reason for detaching
   */
  async copilotDetach(sessionId, reason) {
    this.#assertAuthenticated('copilotDetach');
    await this.#transport.sendControl(copilotDetachMsg({ sessionId, reason }));
  }

  // ── E2E Encryption ────────────────────────────────────────────────

  /**
   * Initiate end-to-end encryption for a session using X25519 key exchange.
   * @param {string} sessionId - Session ID
   * @param {string} [algorithm='X25519'] - Key exchange algorithm
   * @param {number} [timeout=10000]
   * @returns {Promise<{sharedSecret: CryptoKey, peerPublicKey: Uint8Array}>}
   */
  async initiateE2E(sessionId, algorithm = 'X25519', timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('initiateE2E');

    // Generate ephemeral X25519 key pair
    const ephemeral = await crypto.subtle.generateKey(
      { name: 'X25519' },
      false,
      ['deriveBits']
    );

    const localPub = new Uint8Array(
      await crypto.subtle.exportKey('raw', ephemeral.publicKey)
    );

    await this.#transport.sendControl(
      keyExchangeMsg({ algorithm, publicKey: localPub, sessionId })
    );

    const peerMsg = await this.#waitForMessage(
      [MSG.KEY_EXCHANGE],
      timeout,
      'Timed out waiting for peer key exchange'
    );

    // Import peer's public key and derive shared secret
    const peerKey = await crypto.subtle.importKey(
      'raw',
      peerMsg.public_key,
      { name: 'X25519' },
      false,
      []
    );

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'X25519', public: peerKey },
      ephemeral.privateKey,
      256
    );

    // Derive an AES-GCM key from the shared secret
    const sharedSecret = await crypto.subtle.importKey(
      'raw',
      sharedBits,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    return { sharedSecret, peerPublicKey: new Uint8Array(peerMsg.public_key) };
  }

  // ── Structured File Channel ───────────────────────────────────────

  /**
   * Perform a file operation on the remote host.
   * @param {string} op - Operation: 'stat', 'list', 'read', 'write', 'mkdir', 'remove', 'rename'
   * @param {string} path - File path
   * @param {object} [opts] - Optional: offset, length for read; data for write; newPath for rename
   * @param {number} [timeout=10000]
   * @returns {Promise<object>} FileResult response
   */
  async fileOperation(op, path, opts = {}, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('fileOperation');
    const channelId = this._nextChannelId();
    await this.#transport.sendControl(
      fileOpMsg({ channelId, op, path, offset: opts.offset, length: opts.length })
    );
    return this.#waitForMessage(
      [MSG.FILE_RESULT],
      timeout,
      `Timed out waiting for file ${op} result`
    );
  }

  /** Stat a remote file. */
  async fileStat(path, timeout) { return this.fileOperation('stat', path, {}, timeout); }
  /** List a remote directory. */
  async fileList(path, timeout) { return this.fileOperation('list', path, {}, timeout); }
  /** Read a remote file. */
  async fileRead(path, offset, length, timeout) { return this.fileOperation('read', path, { offset, length }, timeout); }
  /** Write to a remote file. */
  async fileWrite(path, data, offset, timeout) { return this.fileOperation('write', path, { offset }, timeout); }
  /** Create a remote directory. */
  async fileMkdir(path, timeout) { return this.fileOperation('mkdir', path, {}, timeout); }
  /** Remove a remote file or directory. */
  async fileRemove(path, timeout) { return this.fileOperation('remove', path, {}, timeout); }
  /** Rename a remote file or directory. */
  async fileRename(oldPath, newPath, timeout) { return this.fileOperation('rename', oldPath, {}, timeout); }

  // ── Policy Engine ─────────────────────────────────────────────────

  /**
   * Evaluate a policy on the server.
   * @param {string} action - Action to evaluate
   * @param {string} principal - Principal requesting the action
   * @param {object} [context={}] - Additional context
   * @param {number} [timeout=10000]
   * @returns {Promise<object>} PolicyResult response
   */
  async evaluatePolicy(action, principal, context = {}, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('evaluatePolicy');
    const requestId = `req_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await this.#transport.sendControl(
      policyEvalMsg({ requestId, action, principal, context })
    );
    return this.#waitForMessage(
      [MSG.POLICY_RESULT],
      timeout,
      'Timed out waiting for policy evaluation result'
    );
  }

  /**
   * Update a policy on the server.
   * @param {string} policyId - Policy to update
   * @param {object} rules - New policy rules
   * @param {number} version - Policy version
   */
  async updatePolicy(policyId, rules, version) {
    this.#assertAuthenticated('updatePolicy');
    await this.#transport.sendControl(
      policyUpdateMsg({ policyId, rules, version })
    );
  }

  // ── Internal: transport creation ────────────────────────────────────

  /**
   * Create the appropriate transport based on URL scheme and hint.
   *
   * @param {string} url
   * @param {'wt'|'ws'|'auto'} [hint]
   * @returns {Promise<import('./transport.mjs').WshTransport>}
   * @private
   */
  async #connectTransport(url, hint) {
    const attempts = this.#buildTransportAttempts(url, hint);
    const errors = [];

    for (const attempt of attempts) {
      const transport = this.#createTransport(attempt.kind);
      try {
        await transport.connect(attempt.url);
        this.#attachTransportHandlers(transport);
        return transport;
      } catch (err) {
        errors.push(`${attempt.kind}: ${err?.message || err}`);
        try {
          await transport.close();
        } catch {
          // Ignore cleanup errors after a failed connect attempt.
        }
      }
    }

    throw new Error(`Connection failed across transports (${errors.join('; ')})`);
  }

  /**
   * @param {'wt'|'ws'} kind
   * @returns {import('./transport.mjs').WshTransport}
   * @private
   */
  #createTransport(kind) {
    const factory = this.#transportFactories[kind];
    if (!factory) {
      throw new Error(`Unsupported transport: ${kind}`);
    }
    return factory();
  }

  /**
   * @param {string} url
   * @param {'wt'|'ws'|'auto'} [hint]
   * @returns {{ kind: 'wt'|'ws', url: string }[]}
   * @private
   */
  #buildTransportAttempts(url, hint) {
    if (hint === 'wt') {
      return [{ kind: 'wt', url }];
    }
    if (hint === 'ws') {
      return [{ kind: 'ws', url }];
    }
    if (/^wss?:\/\//i.test(url)) {
      return [{ kind: 'ws', url }];
    }
    return [
      { kind: 'wt', url },
      { kind: 'ws', url },
    ];
  }

  /**
   * @param {import('./transport.mjs').WshTransport} transport
   * @private
   */
  #attachTransportHandlers(transport) {
    transport.onControl = (msg) => this.#handleControl(msg);
    transport.onClose = () => this.#handleTransportClose();
    transport.onError = (err) => this.#handleTransportError(err);
  }

  /**
   * Create a client with a pre-configured transport instance.
   * Useful for WebSocket transport or custom transports.
   *
   * @param {import('./transport.mjs').WshTransport} transport
   * @returns {WshClient}
   */
  static withTransport(transport) {
    const client = new WshClient();
    client.#transport = transport;
    return client;
  }

  /**
   * Connect using an externally created transport.
   * Use this when you need WebSocket or a custom transport.
   *
   * @param {import('./transport.mjs').WshTransport} transport - An already-constructed transport
   * @param {string} url - Server URL to connect to
   * @param {object} opts - Same options as connect()
   * @returns {Promise<string>} Session ID
   */
  async connectWithTransport(transport, url, opts) {
    this.#state = STATE_CONNECTING;
    await transport.connect(url);
    this.#attachTransportHandlers(transport);
    this.#transport = transport;
    this.#state = STATE_CONNECTED;

    // Proceed with auth using the same logic.
    // We can't call this.connect() directly because it would create a new
    // transport, so we duplicate the auth portion.
    return this.#performAuth(opts);
  }

  // ── Internal: auth handshake ────────────────────────────────────────

  /**
   * Perform the authentication handshake after transport is connected.
   * Extracted so connectWithTransport can reuse it.
   *
   * @param {object} opts
   * @param {string} opts.username
   * @param {CryptoKeyPair} [opts.keyPair]
   * @param {string} [opts.password]
   * @param {number} [opts.timeout]
   * @returns {Promise<string>} Session ID
   * @private
   */
  async #performAuth({ username, keyPair, password, timeout = DEFAULT_AUTH_TIMEOUT } = {}) {
    if (!username) throw new Error('username is required');
    if (!keyPair && !password) throw new Error('Either keyPair or password is required');

    try {
      const authMethod = keyPair ? AUTH_METHOD.PUBKEY : AUTH_METHOD.PASSWORD;
      await this.#transport.sendControl(hello({ username, authMethod }));

      const firstResponse = await this.#waitForMessage(
        [MSG.SERVER_HELLO, MSG.CHALLENGE, MSG.AUTH_FAIL],
        timeout,
        'Auth handshake timed out'
      );

      if (firstResponse.type === MSG.AUTH_FAIL) {
        throw new Error(`Authentication failed: ${firstResponse.reason || 'unknown'}`);
      }

      let tempSessionId = null;

      if (firstResponse.type === MSG.SERVER_HELLO) {
        tempSessionId = firstResponse.session_id;
        this.#serverFeatures = firstResponse.features || [];

        if (authMethod === AUTH_METHOD.PUBKEY) {
          const challengeMsg = await this.#waitForMessage(
            [MSG.CHALLENGE, MSG.AUTH_OK],
            timeout,
            'Timed out waiting for challenge'
          );

          if (challengeMsg.type === MSG.AUTH_OK) {
            this.#sessionId = challengeMsg.session_id || tempSessionId;
            this.#resumeToken = challengeMsg.token || null;
            this.#state = STATE_AUTHENTICATED;
            this.#startPing();
            return this.#sessionId;
          }

          const { signature, publicKeyRaw } = await signChallenge(
            keyPair.privateKey, keyPair.publicKey, tempSessionId, challengeMsg.nonce
          );

          await this.#transport.sendControl(authMsg({
            method: AUTH_METHOD.PUBKEY, signature, publicKey: publicKeyRaw,
          }));
        } else {
          await this.#transport.sendControl(authMsg({
            method: AUTH_METHOD.PASSWORD, password,
          }));
        }
      } else if (firstResponse.type === MSG.CHALLENGE) {
        if (!keyPair) throw new Error('Server sent CHALLENGE but no key pair provided');

        tempSessionId = tempSessionId || 'pending';
        const { signature, publicKeyRaw } = await signChallenge(
          keyPair.privateKey, keyPair.publicKey, tempSessionId, firstResponse.nonce
        );

        await this.#transport.sendControl(authMsg({
          method: AUTH_METHOD.PUBKEY, signature, publicKey: publicKeyRaw,
        }));
      }

      const authResult = await this.#waitForMessage(
        [MSG.AUTH_OK, MSG.AUTH_FAIL],
        timeout,
        'Timed out waiting for auth result'
      );

      if (authResult.type === MSG.AUTH_FAIL) {
        throw new Error(`Authentication failed: ${authResult.reason || 'rejected'}`);
      }

      this.#sessionId = authResult.session_id || tempSessionId;
      this.#resumeToken = authResult.token || null;
      this.#state = STATE_AUTHENTICATED;
      this.#startPing();

      return this.#sessionId;
    } catch (err) {
      this.#state = STATE_CLOSED;
      await this.#transport?.close().catch(() => {});
      this.#transport = null;
      this.#rejectAllWaiters(err);
      throw err;
    }
  }

  // ── Internal: control message dispatch ──────────────────────────────

  /**
   * Route incoming control messages to the appropriate handler.
   * @param {object} msg
   * @private
   */
  #handleControl(msg) {
    const type = msg.type;

    // First, check if any waiters are listening for this message type.
    if (this.#waiters.has(type)) {
      const queue = this.#waiters.get(type);
      if (queue.length > 0) {
        const waiter = queue.shift();
        if (queue.length === 0) this.#waiters.delete(type);
        clearTimeout(waiter.timer);
        waiter.resolve(msg);
        return;
      }
    }

    // Also check multi-type waiters (stored under a synthetic key).
    for (const [key, queue] of this.#waiters) {
      if (typeof key === 'string' && key.startsWith('multi:')) {
        for (let i = 0; i < queue.length; i++) {
          if (queue[i].types?.includes(type)) {
            const waiter = queue.splice(i, 1)[0];
            if (queue.length === 0) this.#waiters.delete(key);
            clearTimeout(waiter.timer);
            waiter.resolve(msg);
            return;
          }
        }
      }
    }

    // Route gateway messages (0x70–0x7f) to the gateway handler.
    if (type >= 0x70 && type <= 0x7f) {
      try {
        this.onGatewayMessage?.(msg);
      } catch (err) {
        console.error('[wsh:client] onGatewayMessage handler error:', err);
      }
      return;
    }

    // Dispatch channel-specific messages to sessions.
    const channelId = msg.channel_id;
    if (channelId !== undefined && this.#sessions.has(channelId)) {
      const session = this.#sessions.get(channelId);
      session._handleControlMessage(msg);

      // Remove session from tracking if it's closed.
      if (type === MSG.CLOSE) {
        this.#sessions.delete(channelId);
      }
      return;
    }

    // Route relay-forwarded messages from remote CLI peers.
    // In reverse mode, the server's relay bridge forwards Open, McpCall,
    // McpDiscover, etc. from the CLI to this browser client. Channel-bound
    // traffic is given to active sessions first so stream and virtual
    // sessions share the same top-level API.
    if (this.onRelayMessage && this._isRelayForwardable(type)) {
      try {
        this.onRelayMessage(msg);
      } catch (err) {
        console.error('[wsh:client] onRelayMessage handler error:', err);
      }
      return;
    }

    // Handle transport-level messages.
    switch (type) {
      case MSG.PING:
        // Respond to server pings immediately.
        this.#transport?.sendControl(pongMsg({ id: msg.id })).catch(() => {});
        break;

      case MSG.PONG:
        this.#lastPong = Date.now();
        break;

      case MSG.ERROR:
        console.error('[wsh:client] Server error:', msg.code, msg.message);
        this.#emitError(new Error(`Server error ${msg.code}: ${msg.message}`));
        break;

      case MSG.SHUTDOWN:
        console.warn('[wsh:client] Server shutdown:', msg.reason);
        this.disconnect().catch(() => {});
        break;

      case MSG.IDLE_WARNING:
        // Respond with a ping to indicate we're still active.
        this.#transport?.sendControl(pingMsg({ id: ++this.#pingId })).catch(() => {});
        break;

      case MSG.REVERSE_CONNECT:
        try {
          this.onReverseConnect?.(msg);
        } catch (err) {
          console.error('[wsh:client] onReverseConnect handler error:', err);
        }
        break;

      case MSG.CLIPBOARD:
        // OSC 52 clipboard sync — write to navigator.clipboard if available.
        if (msg.direction === 'server_to_client' && msg.data) {
          try {
            const text = atob(msg.data);
            navigator.clipboard?.writeText(text).catch(() => {});
          } catch { /* ignore decode errors */ }
        }
        try {
          this.onClipboard?.(msg);
        } catch (err) {
          console.error('[wsh:client] onClipboard handler error:', err);
        }
        break;

      case MSG.PRESENCE:
      case MSG.CONTROL_CHANGED:
      case MSG.METRICS:
        // Informational messages — no default handling needed.
        break;

      case MSG.COMPRESS_BEGIN:
        // Server wants to negotiate compression.  Browser can't decompress
        // CBOR frames yet, so decline.
        this.#transport?.sendControl(
          compressAckMsg({ algorithm: msg.algorithm, accepted: false })
        ).catch(() => {});
        break;

      case MSG.RATE_WARNING:
        try {
          this.onRateWarning?.(msg);
        } catch (err) {
          console.error('[wsh:client] onRateWarning handler error:', err);
        }
        break;

      case MSG.COPILOT_SUGGEST:
        try {
          this.onCopilotSuggest?.(msg);
        } catch (err) {
          console.error('[wsh:client] onCopilotSuggest handler error:', err);
        }
        break;

      case MSG.KEY_EXCHANGE:
        try {
          this.onKeyExchange?.(msg);
        } catch (err) {
          console.error('[wsh:client] onKeyExchange handler error:', err);
        }
        break;

      default:
        // Unrecognized message — ignore gracefully.
        break;
    }
  }

  // ── Internal: transport events ──────────────────────────────────────

  /**
   * @private
   */
  #handleTransportClose() {
    if (this.#state === STATE_CLOSED) return;

    this.#state = STATE_CLOSED;
    this.#stopPing();
    this.#rejectAllWaiters(new Error('Transport closed'));

    // Close all sessions.
    for (const session of this.#sessions.values()) {
      session._handleControlMessage({ type: MSG.CLOSE });
    }
    this.#sessions.clear();

    try {
      this.onClose?.();
    } catch (err) {
      console.error('[wsh:client] onClose handler error:', err);
    }
  }

  /**
   * @private
   */
  #handleTransportError(err) {
    this.#emitError(err);
  }

  // ── Internal: message waiter system ─────────────────────────────────

  /**
   * Wait for the next control message matching one of the given types.
   *
   * @param {number|number[]} types - Message type(s) to wait for
   * @param {number} timeout - Timeout in ms
   * @param {string} timeoutMessage - Error message on timeout
   * @returns {Promise<object>}
   * @private
   */
  #waitForMessage(types, timeout, timeoutMessage) {
    const typeArr = Array.isArray(types) ? types : [types];

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        // Remove this waiter.
        this.#removeWaiter(key, waiter);
        reject(new Error(timeoutMessage));
      }, timeout);

      const waiter = { resolve, reject, timer, types: typeArr };

      // For multi-type waiting, use a synthetic key.
      const key = typeArr.length === 1
        ? typeArr[0]
        : `multi:${typeArr.join(',')}`;

      if (!this.#waiters.has(key)) {
        this.#waiters.set(key, []);
      }
      this.#waiters.get(key).push(waiter);
    });
  }

  /**
   * Remove a specific waiter from the queue.
   * @param {*} key
   * @param {object} waiter
   * @private
   */
  #removeWaiter(key, waiter) {
    const queue = this.#waiters.get(key);
    if (!queue) return;
    const idx = queue.indexOf(waiter);
    if (idx !== -1) queue.splice(idx, 1);
    if (queue.length === 0) this.#waiters.delete(key);
  }

  /**
   * Reject all pending waiters with the given error.
   * @param {Error} err
   * @private
   */
  #rejectAllWaiters(err) {
    for (const [, queue] of this.#waiters) {
      for (const waiter of queue) {
        clearTimeout(waiter.timer);
        waiter.reject(err);
      }
    }
    this.#waiters.clear();
  }

  // ── Internal: ping/pong keepalive ───────────────────────────────────

  /**
   * Start periodic ping messages.
   * @private
   */
  #startPing() {
    this.#stopPing();
    this.#lastPong = Date.now();

    this.#pingTimer = setInterval(() => {
      if (this.#state !== STATE_AUTHENTICATED) {
        this.#stopPing();
        return;
      }

      this.#transport?.sendControl(
        pingMsg({ id: ++this.#pingId })
      ).catch((err) => {
        console.warn('[wsh:client] Failed to send ping:', err.message);
      });
    }, DEFAULT_PING_INTERVAL);

    // Don't let the ping timer prevent Node.js/Deno from exiting.
    if (typeof this.#pingTimer === 'object' && this.#pingTimer.unref) {
      this.#pingTimer.unref();
    }
  }

  /**
   * Stop the ping interval.
   * @private
   */
  #stopPing() {
    if (this.#pingTimer !== null) {
      clearInterval(this.#pingTimer);
      this.#pingTimer = null;
    }
  }

  // ── Internal: helpers ───────────────────────────────────────────────

  /**
   * Check whether a message type is relay-forwardable — i.e. a message
   * that a client would not normally receive from the server, but that
   * arrives via the relay bridge from a remote CLI peer.
   *
   * @param {number} type - Message opcode
   * @returns {boolean}
   */
  _isRelayForwardable(type) {
    return [
      MSG.OPEN, MSG.MCP_DISCOVER, MSG.MCP_CALL,
      MSG.CLOSE, MSG.RESIZE, MSG.SIGNAL,
      MSG.SESSION_DATA,
      MSG.REVERSE_ACCEPT, MSG.REVERSE_REJECT,
      MSG.GUEST_JOIN, MSG.GUEST_REVOKE,         // Unit 4
      MSG.COPILOT_ATTACH, MSG.COPILOT_DETACH,   // Unit 9
      MSG.FILE_OP,                               // Unit 11
      MSG.POLICY_EVAL,                           // Unit 12
      MSG.ECHO_ACK, MSG.ECHO_STATE,
      MSG.TERM_SYNC, MSG.TERM_DIFF,
    ].includes(type);
  }

  /**
   * Get the next channel ID.
   * @returns {number}
   */
  _nextChannelId() {
    return ++this.#channelCounter;
  }

  /**
   * Assert that the client is authenticated.
   * @param {string} action
   * @private
   */
  #assertAuthenticated(action) {
    if (this.#state !== STATE_AUTHENTICATED) {
      throw new Error(`Cannot ${action}: client is ${this.#state} (expected authenticated)`);
    }
  }

  /**
   * Emit an error through the callback.
   * @param {Error} err
   * @private
   */
  #emitError(err) {
    try {
      this.onError?.(err);
    } catch (e) {
      console.error('[wsh:client] onError handler error:', e);
    }
  }
}
