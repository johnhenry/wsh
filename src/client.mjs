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
  fileChunk as fileChunkMsg,
  policyEval as policyEvalMsg, policyUpdate as policyUpdateMsg,
  detach as detachMsg,
  sessionListRequest as sessionListRequestMsg,
  sessionGrant as sessionGrantMsg, sessionRevoke as sessionRevokeMsg,
  isRelayForwardable,
} from './messages.mjs';
import { signChallenge, exportPublicKeyRaw, signPeerRecord, verifyPeerRecord, importPublicKeyRaw, fingerprint as computeFingerprint } from './auth.mjs';
import { generateMlKemKeyPair, mlKemEncapsulate, mlKemDecapsulate } from './mlkem.mjs';
import { WshSession } from './session.mjs';
import { cborDecode } from './cbor.mjs';

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

/**
 * Verify a `PeerInfo` entry's self-signed record (see `listPeers`).
 * Defensive by design: any missing field, malformed key, or fingerprint
 * mismatch resolves to `false` rather than throwing, so one bad entry
 * from an untrusted relay can't break the whole `listPeers()` call.
 * @param {object} peer - a raw `PeerInfo` wire entry
 * @returns {Promise<boolean>}
 */
async function verifyPeerInfoRecord(peer) {
  if (!peer.public_key || !peer.record_signature || peer.seq === undefined || peer.seq === null) return false;
  try {
    const claimedFingerprint = await computeFingerprint(peer.public_key);
    if (claimedFingerprint !== peer.fingerprint) return false;
    const publicKey = await importPublicKeyRaw(peer.public_key);
    return await verifyPeerRecord(publicKey, peer.record_signature, {
      username: peer.username,
      peerType: peer.peer_type,
      shellBackend: peer.shell_backend,
      capabilities: peer.capabilities,
      supportsAttach: peer.supports_attach,
      supportsReplay: peer.supports_replay,
      supportsEcho: peer.supports_echo,
      supportsTermSync: peer.supports_term_sync,
      seq: peer.seq,
    });
  } catch {
    return false;
  }
}

/**
 * Lexicographic byte comparison, used by `initiateE2E`'s hybrid mode to
 * deterministically assign the ML-KEM "encapsulator" role without an
 * extra round trip: both sides already have both ephemeral X25519
 * public keys after round 1, so whichever side's own key sorts lower
 * encapsulates.
 * @returns {number} <0 if a<b, >0 if a>b, 0 if equal
 */
function compareBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/**
 * Combine the classical (X25519 ECDH) and post-quantum (ML-KEM-768) key
 * exchange outputs into one AES-256-GCM key via HKDF-SHA256, so the
 * final key is only as weak as the *stronger* of the two if either
 * primitive is ever broken.
 * @param {Uint8Array} x25519Bits - 32-byte ECDH shared secret
 * @param {Uint8Array} kemSharedSecret - 32-byte ML-KEM-768 shared secret
 * @returns {Promise<Uint8Array>} 32 bytes of combined key material
 */
async function combineHybridSecret(x25519Bits, kemSharedSecret) {
  const ikm = new Uint8Array(x25519Bits.length + kemSharedSecret.length);
  ikm.set(x25519Bits, 0);
  ikm.set(kemSharedSecret, x25519Bits.length);
  const hkdfKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('wsh-hybrid-e2e-v1') },
    hkdfKey,
    256
  );
  return new Uint8Array(bits);
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

  /**
   * FIFO queue of in-flight openSession() calls awaiting the next
   * OPEN_OK/OPEN_FAIL. Handled as a dedicated synchronous case in
   * #handleControl (not the generic #waitForMessage machinery) so that
   * #sessions.set() happens in the same synchronous dispatch step as
   * OPEN_OK itself, with no microtask hop in between. That matters
   * because a server can legitimately push channel-scoped data (e.g. the
   * first FileChunk of a download) immediately after OPEN_OK, landing in
   * the same message batch -- dispatchSerially only guarantees one
   * microtask tick of separation between batch items, and registering the
   * session via a promise continuation takes more hops than that, so the
   * next item in the batch could still find #sessions.has(channelId)
   * false and be misrouted/dropped.
   * @type {Array<{kind: string, resolve: function, reject: function, timer: number}>}
   */
  #pendingOpens = [];

  /**
   * Fingerprints of reverse-connect peers this client has accepted a relay
   * bridge with. RelayForward-wrapped messages are only unwrapped and
   * delivered if their from_fingerprint is in this set — see trustRelayPeer.
   * @type {Set<string>}
   */
  #acceptedRelayPeers = new Set();

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

          // Sign the challenge. Challenge.session_id (not the one from
          // ServerHello) is authoritative for the transcript — see the
          // comment in the CHALLENGE-first branch below for why.
          const { signature, publicKeyRaw } = await signChallenge(
            keyPair.privateKey,
            keyPair.publicKey,
            challengeMsg.session_id,
            challengeMsg.nonce,
            { username }
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

        // Challenge carries session_id directly (protocol requirement as
        // of wsh-v1's Challenge.session_id field), so the transcript's
        // session-id component is always the server's real, authoritative
        // value regardless of whether ServerHello was sent, dropped, or
        // arrived out of order. No synthesizing a placeholder here. Keep
        // tempSessionId as a fallback for this.#sessionId below in case
        // AUTH_OK's own session_id is ever absent.
        tempSessionId = firstResponse.session_id;
        const { signature, publicKeyRaw } = await signChallenge(
          keyPair.privateKey,
          keyPair.publicKey,
          firstResponse.session_id,
          firstResponse.nonce,
          { username }
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

    // Registered as a dedicated pending-open (not the generic
    // #waitForMessage waiter) so #handleControl can construct and
    // register the WshSession synchronously the instant OPEN_OK arrives
    // — see #pendingOpens's doc comment for why that matters.
    return new Promise((resolve, reject) => {
      const entry = {
        mode: 'session',
        kind: type,
        requestedChannelId,
        resolve,
        reject,
      };
      entry.timer = setTimeout(() => {
        const idx = this.#pendingOpens.indexOf(entry);
        if (idx !== -1) this.#pendingOpens.splice(idx, 1);
        reject(new Error('Timed out waiting for session open response'));
      }, timeout);
      this.#pendingOpens.push(entry);
    });
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

    const attachMode = readOnly ? 'readonly' : 'control';
    await this.#transport.sendControl(
      attachMsg({ sessionId: targetSessionId, token: this.#resumeToken, mode: attachMode })
    );

    // Shares #pendingOpens with openSession() -- both wait on the same
    // OPEN_OK/OPEN_FAIL response stream, in the order their requests were
    // sent (see #pendingOpens's doc comment). Unlike openSession(),
    // attachSession() doesn't construct a WshSession, so it just wants
    // the raw response either way.
    const response = await new Promise((resolve, reject) => {
      const entry = { mode: 'raw', resolve, reject };
      entry.timer = setTimeout(() => {
        const idx = this.#pendingOpens.indexOf(entry);
        if (idx !== -1) this.#pendingOpens.splice(idx, 1);
        reject(new Error('Timed out waiting for attach response'));
      }, timeout);
      this.#pendingOpens.push(entry);
    });

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

  /**
   * Detach from a remote session: release control (stop receiving its
   * output) while leaving it running server-side, so it can be resumed
   * later via resumeSession(). Mirrors the Rust client/CLI's `wsh detach`.
   *
   * @param {string} sessionId - Remote session ID to detach from
   * @param {number} [timeout=10000]
   */
  async detach(sessionId, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('detach');

    await this.#transport.sendControl(detachMsg({ sessionId }));

    const response = await this.#waitForMessage(
      [MSG.DETACH_OK, MSG.DETACH_FAIL],
      timeout,
      'Timed out waiting for detach response'
    );

    if (response.type === MSG.DETACH_FAIL) {
      throw new Error(`Failed to detach: ${response.reason || 'rejected'}`);
    }
  }

  /**
   * List sessions on the server that this connection's key owns or has
   * been granted access to (a server round trip — distinct from the
   * purely local listSessions(), which only reports channels open on
   * this connection). Mirrors the Rust client's list_remote_sessions().
   *
   * @param {number} [timeout=10000]
   * @returns {Promise<Array<object>>} Server-reported session summaries
   */
  async listRemoteSessions(timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('listRemoteSessions');

    await this.#transport.sendControl(sessionListRequestMsg());

    const response = await this.#waitForMessage(
      [MSG.SESSION_LIST],
      timeout,
      'Timed out waiting for session list response'
    );

    return response.sessions || [];
  }

  /**
   * Grant another authenticated principal (username or fingerprint)
   * access to a session this connection owns. Server-enforced (only the
   * session owner may grant); fire-and-forget like updatePolicy() — the
   * server sends no response on success, only an Error envelope on
   * rejection (surfaced via onError, not this call).
   *
   * @param {string} sessionId
   * @param {string} principal - Username or fingerprint of the grantee
   * @param {string[]} [permissions=['read']]
   */
  async grantSessionAccess(sessionId, principal, permissions = ['read']) {
    this.#assertAuthenticated('grantSessionAccess');
    await this.#transport.sendControl(
      sessionGrantMsg({ sessionId, principal, permissions })
    );
  }

  /**
   * Revoke a previously granted principal's access to a session this
   * connection owns. Same fire-and-forget shape as grantSessionAccess().
   *
   * @param {string} sessionId
   * @param {string} principal
   * @param {string} [reason]
   */
  async revokeSessionAccess(sessionId, principal, reason) {
    this.#assertAuthenticated('revokeSessionAccess');
    await this.#transport.sendControl(
      sessionRevokeMsg({ sessionId, principal, reason })
    );
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
    const record = {
      username,
      capabilities,
      peerType,
      shellBackend: effectiveShellBackend,
      supportsAttach: supportsAttach ?? effectiveShellBackend !== 'exec-only',
      supportsReplay: supportsReplay ?? effectiveShellBackend !== 'exec-only',
      supportsEcho: supportsEcho ?? effectiveShellBackend === 'virtual-shell',
      supportsTermSync: supportsTermSync ?? effectiveShellBackend === 'virtual-shell',
      // The peer's own monotonic counter for this signed record --
      // current-time-millis in practice (see buildPeerRecordTranscript).
      // A server/operator must reject a record whose seq doesn't exceed
      // the last one accepted for this fingerprint.
      seq: Date.now(),
    };

    // Self-sign the registration so ReversePeers entries built from it
    // are verifiable by an operator independent of trusting the relay
    // (see auth.mjs's "Signed peer records" section). Only possible with
    // a real identity key, same precondition `publicKey` already had.
    let recordSignature;
    if (keyPair) {
      ({ signature: recordSignature } = await signPeerRecord(keyPair.privateKey, keyPair.publicKey, record));
    }

    // Register as a reverse peer.
    await this.#transport.sendControl(
      reverseRegisterMsg({
        ...record,
        publicKey,
        recordSignature,
      })
    );

    return sessionId;
  }

  /**
   * List peers registered on the relay server.
   *
   * Each entry's `verified` field is computed here, client-side, from
   * the peer's own signed record (`public_key`/`seq`/`record_signature`,
   * present when the relay honestly forwards what the peer sent) --
   * `true` only if the signature actually verifies against `public_key`
   * AND that key's fingerprint matches the claimed `fingerprint` field.
   * This is deliberately NOT trust-on-first-use of the relay's own
   * claims: a relay that omits or tampers with these fields, or that
   * substitutes a different key, produces `verified: false` rather than
   * silently passing. `verified` is additive to the wire response, not
   * a wire field itself.
   *
   * @param {number} [timeout=10000] - Timeout in ms
   * @returns {Promise<Array<{fingerprint_short: string, username: string, capabilities: string[], last_seen: number|null, verified: boolean}>>}
   */
  async listPeers(timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('listPeers');

    await this.#transport.sendControl(reverseListMsg());

    const response = await this.#waitForMessage(
      [MSG.REVERSE_PEERS],
      timeout,
      'Timed out waiting for peer list'
    );

    const peers = response.peers || [];
    return Promise.all(peers.map(async (peer) => ({ ...peer, verified: await verifyPeerInfoRecord(peer) })));
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
      // fromFingerprint is ignored by the server -- it overwrites it with
      // this connection's own authenticated fingerprint before forwarding.
      reverseConnectMsg({ targetFingerprint, username: '', fromFingerprint: '' })
    );

    const response = await this.#waitForMessage(
      [MSG.REVERSE_ACCEPT, MSG.REVERSE_REJECT],
      timeout,
      'Timed out waiting for reverse-connect response'
    );

    if (response.type === MSG.REVERSE_ACCEPT) {
      this.trustRelayPeer(response.target_fingerprint);
    }

    return response;
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

  /**
   * Mark a peer fingerprint as an accepted reverse-connect bridge partner.
   *
   * Call this once a ReverseConnect has been accepted (either side): the
   * target after sending ReverseAccept in response to an incoming request
   * (using the request's from_fingerprint), or the operator after receiving
   * ReverseAccept for a request it sent (handled automatically by
   * reverseConnect()). Only RelayForward-wrapped messages whose
   * from_fingerprint is trusted this way are unwrapped and delivered.
   *
   * @param {string} fingerprint
   */
  trustRelayPeer(fingerprint) {
    this.#acceptedRelayPeers.add(fingerprint);
  }

  /**
   * Stop trusting a peer as a relay-forward bridge partner (e.g. on session end).
   * @param {string} fingerprint
   */
  untrustRelayPeer(fingerprint) {
    this.#acceptedRelayPeers.delete(fingerprint);
  }

  // ── File transfer ───────────────────────────────────────────────────

  /**
   * Upload a blob to a remote path.
   *
   * Opens a file channel, then sends the data as a sequence of FileChunk
   * control messages (offset-addressed, the last one marked is_final) and
   * waits for the server to confirm completion. Works the same whether the
   * channel's data plane is stream- or virtual-backed, since FileChunk is
   * an ordinary control message rather than raw stream bytes.
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

    try {
      let sent = 0;
      do {
        const end = Math.min(sent + FILE_CHUNK_SIZE, total);
        await this.#transport.sendControl(fileChunkMsg({
          channelId: session.channelId,
          offset: sent,
          data: data.subarray(sent, end),
          isFinal: end >= total,
          totalSize: total,
        }));
        sent = end;
        onProgress?.(sent);
      } while (sent < total);

      // The server confirms completion the same way an exec session
      // signals it finished: Exit with a code, then Close. Resolve on
      // whichever arrives first.
      const code = await new Promise((resolve) => {
        session.onExit = (c) => { session.onExit = null; resolve(c); };
        session.onClose = () => resolve(null);
      });
      if (code !== 0) {
        throw new Error(`Upload failed with exit code ${code ?? 'unknown'}`);
      }
    } finally {
      await session.close().catch(() => {});
    }
  }

  /**
   * Download a file from a remote path.
   *
   * Opens a file channel and reads the file as a sequence of FileChunk
   * control messages until the final chunk arrives. offset/total_size are
   * checked so a truncated transfer (channel closes before is_final, or
   * the final chunk doesn't actually reach total_size) is detected rather
   * than silently returned as a short file.
   *
   * @param {string} remotePath - Source path on the server
   * @param {object} [opts]
   * @param {function({received: number, total: number}): void} [opts.onProgress]
   * @param {number} [opts.timeout=10000] - Timeout in ms waiting for the channel to open
   * @returns {Promise<Uint8Array>} File contents
   */
  async download(remotePath, { onProgress, timeout = DEFAULT_OPEN_TIMEOUT } = {}) {
    this.#assertAuthenticated('download');
    const session = await this.openSession({ type: 'file', command: `download:${remotePath}`, timeout });

    try {
      let data = null;
      let received = 0;

      while (true) {
        const chunk = await session._readFileChunk();
        if (chunk === null) {
          throw new Error('Download failed: connection closed before the transfer completed (truncated)');
        }
        if (data === null) {
          data = new Uint8Array(chunk.total_size ?? 0);
        }
        data.set(chunk.data, chunk.offset);
        received = chunk.offset + chunk.data.byteLength;
        onProgress?.({ received, total: data.byteLength });

        if (chunk.is_final) {
          if (received !== data.byteLength) {
            throw new Error(`Download failed: truncated transfer (received ${received} of ${data.byteLength} bytes)`);
          }
          return data;
        }
      }
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
   * Initiate end-to-end encryption for a session.
   *
   * `algorithm: 'X25519'` (default): classical ECDH only, one round trip
   * -- both sides send their ephemeral public key, derive the shared
   * secret directly.
   *
   * `algorithm: 'X25519+ML-KEM-768'`: hybrid classical+post-quantum. Round
   * 1 is the same as classical, plus both sides also send a fresh
   * ML-KEM-768 public key. Each side then deterministically derives the
   * same "encapsulator"/"decapsulator" role assignment by comparing the
   * two exchanged X25519 public keys byte-lexicographically (no extra
   * round trip needed, since both sides already have both values after
   * round 1) -- the encapsulator encapsulates against the decapsulator's
   * ML-KEM-768 key and sends the ciphertext in a second KeyExchange
   * message; the decapsulator decapsulates it. Both combine the X25519
   * and ML-KEM-768 outputs via HKDF-SHA256. Falls back to classical
   * automatically if the peer's round-1 message doesn't include a
   * kem_public_key (it doesn't support hybrid mode) -- algorithm
   * agility, not a hard cutover; check the returned `hybrid` flag to see
   * which actually happened.
   *
   * @param {string} sessionId - Session ID
   * @param {string} [algorithm='X25519'] - 'X25519' or 'X25519+ML-KEM-768'
   * @param {number} [timeout=10000]
   * @returns {Promise<{sharedSecret: CryptoKey, peerPublicKey: Uint8Array, hybrid: boolean}>}
   */
  async initiateE2E(sessionId, algorithm = 'X25519', timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('initiateE2E');
    const wantHybrid = algorithm === 'X25519+ML-KEM-768';

    // Generate ephemeral X25519 key pair (and, for hybrid, a fresh
    // ML-KEM-768 key pair too).
    const ephemeral = await crypto.subtle.generateKey(
      { name: 'X25519' },
      false,
      ['deriveBits']
    );
    const localPub = new Uint8Array(
      await crypto.subtle.exportKey('raw', ephemeral.publicKey)
    );
    const localKem = wantHybrid ? await generateMlKemKeyPair() : null;

    await this.#transport.sendControl(
      keyExchangeMsg({ algorithm, publicKey: localPub, sessionId, kemPublicKey: localKem?.publicKey })
    );

    const peerMsg = await this.#waitForMessage(
      [MSG.KEY_EXCHANGE],
      timeout,
      'Timed out waiting for peer key exchange'
    );

    // Import peer's public key and derive the classical shared secret.
    const peerKey = await crypto.subtle.importKey(
      'raw',
      peerMsg.public_key,
      { name: 'X25519' },
      false,
      []
    );
    const sharedBits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'X25519', public: peerKey },
      ephemeral.privateKey,
      256
    ));

    const hybridActive = wantHybrid && !!localKem && !!peerMsg.kem_public_key;
    let combinedBits = sharedBits;

    if (hybridActive) {
      const peerKemPublicKey = new Uint8Array(peerMsg.kem_public_key);
      const isEncapsulator = compareBytes(localPub, new Uint8Array(peerMsg.public_key)) < 0;

      let kemSharedSecret;
      if (isEncapsulator) {
        const { ciphertext, sharedSecret } = await mlKemEncapsulate(peerKemPublicKey);
        kemSharedSecret = sharedSecret;
        await this.#transport.sendControl(keyExchangeMsg({ algorithm, sessionId, kemCiphertext: ciphertext }));
      } else {
        const ctMsg = await this.#waitForMessage(
          [MSG.KEY_EXCHANGE],
          timeout,
          'Timed out waiting for peer ML-KEM-768 ciphertext'
        );
        kemSharedSecret = await mlKemDecapsulate(localKem.secretKeySeed, new Uint8Array(ctMsg.kem_ciphertext));
      }

      combinedBits = await combineHybridSecret(sharedBits, kemSharedSecret);
    }

    // Derive an AES-GCM key from the (possibly hybrid-combined) shared secret
    const sharedSecret = await crypto.subtle.importKey(
      'raw',
      combinedBits,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    return { sharedSecret, peerPublicKey: new Uint8Array(peerMsg.public_key), hybrid: hybridActive };
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
            keyPair.privateKey, keyPair.publicKey, challengeMsg.session_id, challengeMsg.nonce, { username }
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

        // Challenge carries session_id directly — see connect()'s
        // CHALLENGE branch for why. Keep tempSessionId as a fallback for
        // this.#sessionId below in case AUTH_OK's own session_id is ever
        // absent.
        tempSessionId = firstResponse.session_id;
        const { signature, publicKeyRaw } = await signChallenge(
          keyPair.privateKey, keyPair.publicKey, firstResponse.session_id, firstResponse.nonce, { username }
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

    // Unwrap RelayForward: only deliver the inner message if it came from a
    // peer this client has actually accepted a bridge with (see
    // trustRelayPeer), and only if the inner message's own type is on the
    // shared relay-forwardable allowlist (defense in depth against a
    // misbehaving or compromised relay server). from_fingerprint is set by
    // the server from the sender's authenticated identity -- never trust it
    // beyond checking membership in #acceptedRelayPeers.
    if (type === MSG.RELAY_FORWARD) {
      if (!this.#acceptedRelayPeers.has(msg.from_fingerprint)) {
        console.warn('[wsh:client] dropping RelayForward from untrusted/unaccepted peer:', msg.from_fingerprint);
        return;
      }
      let inner;
      try {
        inner = cborDecode(msg.inner);
      } catch (err) {
        console.error('[wsh:client] failed to decode RelayForward inner envelope:', err);
        return;
      }
      if (!isRelayForwardable(inner.type)) {
        console.warn('[wsh:client] dropping RelayForward wrapping a non-forwardable type:', inner.type);
        return;
      }
      this.#handleControl(inner);
      return;
    }

    // OPEN_OK/OPEN_FAIL: handled as a dedicated case (not the generic
    // waiter mechanism below) so the WshSession gets constructed and
    // registered in #sessions synchronously, in the same dispatch step as
    // OPEN_OK itself — see #pendingOpens's doc comment for why.
    if (type === MSG.OPEN_OK || type === MSG.OPEN_FAIL) {
      const pending = this.#pendingOpens.shift();
      if (!pending) return;
      clearTimeout(pending.timer);

      // attachSession() wants the raw response either way and never
      // constructs a session -- it has no #sessions-registration race to
      // protect against.
      if (pending.mode === 'raw') {
        pending.resolve(msg);
        return;
      }

      if (type === MSG.OPEN_FAIL) {
        pending.reject(new Error(`Failed to open session: ${msg.reason || 'rejected'}`));
        return;
      }

      const serverChannelId = msg.channel_id ?? pending.requestedChannelId;
      const streamIds = msg.stream_ids ?? {};
      const dataMode = msg.data_mode === 'virtual' ? 'virtual' : 'stream';
      const capabilities = Array.isArray(msg.capabilities) ? msg.capabilities : [];

      const session = new WshSession(
        this.#transport,
        serverChannelId,
        streamIds,
        pending.kind,
        { dataMode, capabilities }
      );
      this.#sessions.set(serverChannelId, session);

      if (dataMode === 'virtual') {
        session._activateVirtual((m) => this.sendRelayControl(m));
        pending.resolve(session);
        return;
      }

      // Stream mode needs a real transport stream, which is inherently
      // async — but #sessions.set() above already happened synchronously,
      // so channel-scoped control messages arriving before the stream
      // finishes binding still route correctly.
      this.#transport.openStream().then(
        (stream) => {
          session._bind(stream.readable, stream.writable);
          pending.resolve(session);
        },
        (err) => pending.reject(err)
      );
      return;
    }

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

    for (const pending of this.#pendingOpens) {
      clearTimeout(pending.timer);
      pending.reject(err);
    }
    this.#pendingOpens.length = 0;
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
   * Backed by the generated allowlist (single source of truth: the
   * `relay.forwardable` list in spec/wsh-v1.yaml) so this can no longer
   * drift out of sync with the server's own allowlist.
   *
   * @param {number} type - Message opcode
   * @returns {boolean}
   */
  _isRelayForwardable(type) {
    return isRelayForwardable(type);
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
