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
  reverseConnect as reverseConnectMsg, relayForward as relayForwardMsg,
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
  fileResult as fileResultMsg,
  authorizedKeyAdd as authorizedKeyAddMsg,
  policyEval as policyEvalMsg, policyUpdate as policyUpdateMsg,
  detach as detachMsg,
  sessionListRequest as sessionListRequestMsg,
  sessionGrant as sessionGrantMsg, sessionRevoke as sessionRevokeMsg,
  isRelayForwardable,
} from './messages.mjs';
import { signChallenge, exportPublicKeyRaw, signPeerRecord, verifyPeerRecord, importPublicKeyRaw, fingerprint as computeFingerprint } from './auth.mjs';
import { generateMlKemKeyPair, mlKemEncapsulate, mlKemDecapsulate } from './mlkem.mjs';
import { compareBytes, combineHybridSecret, verifyKeyExchangeSignature } from './e2e-exchange.mjs';
import { WshSession } from './session.mjs';
import { cborDecode, cborEncode } from './cbor.mjs';
import {
  RpcChannel, RpcError, RPC_ERROR, RPC_FEATURE, RPC_PROTOCOL_NAME_RE, RPC_DEFAULT_MAX_MESSAGE,
  rpcProtocolFeature, parseRpcFeatures,
} from './rpc.mjs';
import {
  HostKeyError, newHostKeyNonce, hostKeyProofMessage, findHostKeyAdvert,
  HOST_KEY_NONCE_PREFIX,
} from './host-key.mjs';
import { verify as verifySignature, exportPublicKeySSH, parseSSHPublicKey, extractRawFromSSHWire } from './auth.mjs';

// ── Client states ─────────────────────────────────────────────────────

const STATE_DISCONNECTED  = 'disconnected';
const STATE_CONNECTING    = 'connecting';
const STATE_CONNECTED     = 'connected';
const STATE_AUTHENTICATED = 'authenticated';
const STATE_CLOSED        = 'closed';

// ── Defaults ──────────────────────────────────────────────────────────

const DEFAULT_AUTH_TIMEOUT   = 10_000;  // ms
const DEFAULT_OPEN_TIMEOUT   = 10_000;  // ms
const FS_RPC_OPS = new Set(['stat', 'list', 'read', 'write', 'mkdir', 'remove', 'rename']);

/**
 * ServerHello feature advertising that McpResult echoes McpCall's call_id.
 *
 * Negotiated rather than assumed: McpCallPayload is `deny_unknown_fields` on
 * the Rust side, so sending call_id to a server predating it does not
 * degrade -- it makes the server reject the call.
 */
export const MCP_CALL_ID_FEATURE = 'mcp-call-id';

/**
 * ServerHello feature: the host discovers a client-opened exec data stream
 * on its own (the transport announces it), so the client must NOT write the
 * one-byte "primer" -- against such a host it would reach the process's stdin.
 */
export const STREAM_ANNOUNCE_FEATURE = 'stream-announce';

/**
 * Reject a missing argument that maps to a `required: true` wire field.
 *
 * JavaScript will happily let an omitted argument through, and
 * `cborEncode` turns the resulting `undefined` into CBOR null rather
 * than dropping the key -- so the message goes out looking well-formed,
 * gets rejected by a spec-conformant server for a reason that has
 * nothing to do with what the caller did wrong, and the local stack
 * trace is long gone by then. This is exactly how `resumeSession()`
 * shipped broken for two releases (CHANGELOG 0.14.0: `last_seq`
 * "previously always sent as `undefined`, which the wire's
 * `required: true` field never tolerated"). Failing here instead names
 * the argument at the call site.
 *
 * @param {string} method - Method name, for the message.
 * @param {Record<string, *>} args - Argument name -> value.
 */
function requireArgs(method, args) {
  for (const [name, value] of Object.entries(args)) {
    if (value === undefined || value === null) {
      throw new TypeError(
        `${method}: "${name}" is required -- the corresponding wire field is not optional, ` +
        'and omitting it produces a message a conformant server will reject'
      );
    }
  }
}
const DEFAULT_PING_INTERVAL  = 30_000;  // ms
/*
 * How long a peer may go without answering a ping before it is treated as
 * gone. A multiple of the interval, so an ordinary missed pong is tolerated
 * and a peer that has genuinely stopped answering is not.
 */
const DEFAULT_PONG_TIMEOUT   = 90_000;  // ms
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
 * `expectHostKey` accepts a hex fingerprint, a raw 32-byte key, or an
 * `ssh-ed25519 AAAA...` line; all normalize to the hex fingerprint.
 * @param {string|Uint8Array} v
 * @returns {Promise<string>}
 */
async function normalizeExpectedHostKey(v) {
  if (v instanceof Uint8Array) {
    if (v.byteLength !== 32) throw new TypeError('expectHostKey: a raw key must be 32 bytes');
    return computeFingerprint(v);
  }
  const text = String(v).trim();
  if (/^ssh-ed25519\s/.test(text)) {
    const parsed = parseSSHPublicKey(text);
    if (!parsed) throw new TypeError('expectHostKey: malformed ssh-ed25519 line');
    return computeFingerprint(extractRawFromSSHWire(parsed.data));
  }
  const hex = text.replace(/^sha256:/i, '').replace(/:/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new TypeError('expectHostKey: expected a 64-char hex fingerprint, a raw key, or an ssh-ed25519 line');
  return hex;
}

// ── Client class ──────────────────────────────────────────────────────

export class WshClient {

  /** @type {'disconnected'|'connecting'|'connected'|'authenticated'|'closed'} */
  #state = STATE_DISCONNECTED;

  /** @type {string|null} Session ID assigned by the server after authentication. */
  #sessionId = null;

  /**
   * @type {string|null} Connection-level token from AUTH_OK, bound to
   * this connection's own auth session_id (from CHALLENGE/SERVER_HELLO) --
   * NOT a PTY/exec session's token. Renamed from `#resumeToken` (clawser
   * #48): the old name invited exactly the bug this fix addresses --
   * attachSession() used to send this as if it were a valid token for the
   * *target* session_id, which it can never be (it's scoped to a
   * different session_id entirely). Not used for anything else currently;
   * kept and exposed via `authToken` for potential future connection-level
   * resume use, mirroring the Rust client's `WshClient::token()`.
   */
  #authToken = null;

  /** @type {import('./transport.mjs').WshTransport|null} Active transport. */
  #transport = null;

  /** @type {{fingerprint: string, publicKey: Uint8Array, openssh: string, status: string}|null} */
  #hostKey = null;

  /**
   * Called with the host's verified key before any credential is sent.
   * Return `false` (or throw) to refuse the host. See `connect({ onHostKey })`.
   * @type {((hostKey: object) => boolean|void|Promise<boolean|void>)|null}
   */
  onHostKey = null;

  /** @type {{ wt: () => import('./transport.mjs').WshTransport, ws: () => import('./transport.mjs').WshTransport }} */
  #transportFactories;

  /** @type {Map<number, WshSession>} Active sessions keyed by channel ID. */
  #sessions = new Map();

  /**
   * In-flight attachSession()/resumeSession() calls awaiting the Presence
   * that answers them. Like #pendingOpens, matched synchronously in
   * #handleControl so the WshSession exists before the replay (which the
   * host sends right behind the Presence) is dispatched.
   * @type {Array<{sessionId: string, token?: Uint8Array}>}
   */
  #pendingAttaches = [];

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

  /**
   * Observers registered through addControlListener() — see that method
   * and #dispatchControlListeners.
   * @type {Set<function(object): void>}
   */
  #controlListeners = new Set();

  /** @type {number} Monotonically increasing channel ID counter. */
  #channelCounter = 0;

  /** @type {number} Monotonically increasing MCP call counter for call_id. */
  #mcpCallCounter = 0;

  /**
   * Tail of the serialised MCP call chain, used only against servers that do
   * not advertise `mcp-call-id`. Never rejects: each link swallows so one
   * failed call does not poison the queue.
   * @type {Promise<void>}
   */
  #mcpQueue = Promise.resolve();

  /**
   * Pending message waiters: Map<messageType, Array<{resolve, reject, timer}>>
   * Multiple waiters can exist for the same message type.
   */
  #waiters = new Map();

  /** @type {string[]} Server-advertised features from SERVER_HELLO. */
  #serverFeatures = [];
  /**
   * @type {string[]|null} Features of the host behind an accepted relay bridge, from
   * `ReverseAccept.features`; `null` when no bridge is up or the peer stated none.
   */
  #bridgedFeatures = null;

  /** @type {number|null} Ping interval handle. */
  #pingTimer = null;

  /** @type {number} Current ping ID for matching pongs. */
  #pingId = 0;

  /** @type {number|null} Timestamp of last pong received. */
  #lastPong = null;
  #pingIntervalMs = DEFAULT_PING_INTERVAL;
  #pongTimeoutMs = DEFAULT_PONG_TIMEOUT;

  constructor({ transportFactories, pingIntervalMs, pongTimeoutMs } = {}) {
    this.#transportFactories = transportFactories || {
      wt: () => new WebTransportTransport(),
      ws: () => new WebSocketTransport(),
    };
    /*
     * Overridable so the keepalive is testable at all. Left as constants,
     * the only way to observe a 90s timeout is to wait 90s or fake the
     * clock -- which is why nothing observed it before.
     */
    this.#pingIntervalMs = pingIntervalMs ?? DEFAULT_PING_INTERVAL;
    this.#pongTimeoutMs = pongTimeoutMs ?? DEFAULT_PONG_TIMEOUT;
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

  /**
   * This connection's own AUTH-level token (from AUTH_OK), scoped to this
   * connection's auth session_id -- NOT a PTY/exec session token. See
   * `WshSession.resumeToken` for the per-session credential used by
   * `resumeSession`.
   */
  get authToken() {
    return this.#authToken;
  }

  /** Read-only view of active sessions. */
  get sessions() {
    return new Map(this.#sessions);
  }

  /**
   * The features this connection's operations can rely on: those of the host
   * behind an accepted relay bridge when it stated them (`ReverseAccept.features`,
   * see `reverseConnect()`), otherwise the server's `SERVER_HELLO` features.
   */
  get features() {
    return [...(this.#bridgedFeatures ?? this.#serverFeatures)];
  }

  /** The `SERVER_HELLO` features of the server this connection is to (the relay, over a bridge). */
  get serverFeatures() {
    return [...this.#serverFeatures];
  }

  /**
   * Features of the host behind an accepted relay bridge, as it stated them in
   * `ReverseAccept.features`; `null` when there is no bridge, or the peer did
   * not say (then `hasFeature()` falls back to the server's own).
   */
  get bridgedFeatures() {
    return this.#bridgedFeatures ? [...this.#bridgedFeatures] : null;
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
    return (this.#bridgedFeatures ?? this.#serverFeatures).includes(name);
  }

  /**
   * The host's Ed25519 identity, once the server has proven it holds the
   * key for this connection (`null` when the server advertised none, or
   * before `connect()` got that far). `{ fingerprint, publicKey, openssh,
   * status }` where `status` is `'pinned'` (matched `expectHostKey`),
   * `'known'` / `'unknown'` (per `knownHosts`), or `'unpinned'` (no policy
   * asked for one -- the key is surfaced but nothing was checked against it).
   */
  get hostKey() {
    return this.#hostKey;
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
   * @param {object} [opts.webTransport] - Options forwarded to the
   *   `WebTransport` constructor when the WebTransport rung of the ladder
   *   is tried. Most usefully `serverCertificateHashes`, which pins a
   *   specific self-signed certificate by SHA-256 digest -- the one way
   *   page JavaScript can reach a server whose certificate no certificate
   *   authority signed. Values may be raw bytes, hex (colon-separated is
   *   fine), or base64. Ignored by the WebSocket rung, which has no
   *   equivalent mechanism.
   * @param {number} [opts.timeout] - Auth handshake timeout in ms
   * @param {string|Uint8Array} [opts.expectHostKey] - Pin: the host's hex
   *   SHA-256 fingerprint, raw 32-byte Ed25519 key, or `ssh-ed25519 AAAA...`
   *   line. Refuses (`HostKeyError`) on mismatch OR when the host presents
   *   no verifiable key -- before any credential is sent.
   * @param {import('./known-hosts.mjs').WshKnownHosts} [opts.knownHosts] - TOFU
   *   store. A changed key is always refused; an unseen host is refused
   *   unless `trustOnFirstUse` (or an `onHostKey` that does not return
   *   `false`) accepts it, in which case it is pinned.
   * @param {boolean} [opts.trustOnFirstUse] - Pin an unseen host's key.
   * @param {string} [opts.hostLabel] - Key under which `knownHosts` records
   *   this host (default: the URL's `host:port`).
   * @param {Function} [opts.onHostKey] - Per-connect `onHostKey`.
   * @returns {Promise<string>} The server-assigned session ID
   */
  async connect(url, { username, keyPair, password, transport: transportHint, webTransport, timeout = DEFAULT_AUTH_TIMEOUT, ...hostKeyOpts } = {}) {
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
    this.#authToken = null;
    this.#hostKey = null;

    try {
      // ── Select and connect transport ──────────────────────────────
      const transport = await this.#connectTransport(url, transportHint, webTransport);
      this.#transport = transport;
      this.#state = STATE_CONNECTED;

      // ── Auth handshake ────────────────────────────────────────────
      const authMethod = keyPair ? AUTH_METHOD.PUBKEY : AUTH_METHOD.PASSWORD;
      const hostKeyNonce = newHostKeyNonce();
      await transport.sendControl(
        hello({ username, authMethod, features: [HOST_KEY_NONCE_PREFIX + hostKeyNonce] })
      );
      const hostCtx = { ...hostKeyOpts, url, username, nonce: hostKeyNonce };

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
        // If pubkey auth, we still need a challenge. Its waiter is registered
        // BEFORE the host key check awaits anything: the server sends the
        // Challenge right behind ServerHello, and a message nobody is waiting
        // for yet is dropped.
        const challengeWait = authMethod === AUTH_METHOD.PUBKEY
          ? this.#waitForMessage([MSG.CHALLENGE, MSG.AUTH_OK], timeout, 'Auth handshake timed out waiting for challenge')
          : null;
        challengeWait?.catch(() => {});
        await this.#verifyHostKey(firstResponse, hostCtx);

        if (authMethod === AUTH_METHOD.PUBKEY) {
          const challengeMsg = await challengeWait;

          if (challengeMsg.type === MSG.AUTH_OK) {
            // Server accepted without challenge (e.g. trusted key).
            this.#sessionId = challengeMsg.session_id || tempSessionId;
            this.#authToken = challengeMsg.token || null;
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
        await this.#verifyHostKey(null, hostCtx);
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
      this.#authToken = authResult.token || null;
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
   * @param {boolean} [opts.primer=true] - For stream-mode `exec` sessions: write
   *   the one-byte "primer" some hosts need to discover the client-opened data
   *   stream (without it they never bind the stream and drop all output).
   *   Skipped automatically against a host advertising `stream-announce`; pass
   *   `false` to never send it (e.g. a host that forwards stdin verbatim).
   * @param {string} [opts.protocol] - For `type: 'rpc'` (wsh #85): the protocol to speak (`mcp`, `wsh-fs`,
   *   `wsh-host`, or a host-defined name). Carried in `Open.command`. The session's data stream is a CBOR sequence
   *   of JSON-RPC 2.0 messages -- use {@link WshClient#openRpc} to get an `RpcChannel` over it.
   *   Throws `RpcError` (`UNSUPPORTED_PROTOCOL`) before sending anything if the host does not advertise it.
   * @param {(session: WshSession) => void} [opts.attach] - Advanced: called synchronously the moment the data
   *   stream is bound, before any received byte can be delivered (`openRpc` uses it to set `onData`).
   * @returns {Promise<WshSession>}
   */
  async openSession({ type = 'pty', command, protocol, cols = 80, rows = 24, env, timeout = DEFAULT_OPEN_TIMEOUT, primer = true, attach } = {}) {
    this.#assertAuthenticated('openSession');
    if (type === 'rpc') {
      this.#assertRpcProtocol(protocol);
      command = protocol;
    }
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
        primer,
        attach,
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

  /** Refuse an `rpc` open the host did not advertise, before any bytes are sent (wsh #85). */
  #assertRpcProtocol(protocol) {
    if (typeof protocol !== 'string' || !RPC_PROTOCOL_NAME_RE.test(protocol)) {
      throw new RpcError(RPC_ERROR.INVALID_PARAMS, 'openSession({ type: "rpc" }) needs a protocol name', undefined, 'INVALID_PROTOCOL');
    }
    if (!this.hasFeature(RPC_FEATURE)) {
      throw new RpcError(RPC_ERROR.UNSUPPORTED_PROTOCOL, `UNSUPPORTED_PROTOCOL: this host does not advertise "${RPC_FEATURE}" channels (cannot open "${protocol}")`, undefined, 'UNSUPPORTED_PROTOCOL');
    }
    if (!this.hasFeature(rpcProtocolFeature(protocol))) {
      throw new RpcError(RPC_ERROR.UNSUPPORTED_PROTOCOL, `UNSUPPORTED_PROTOCOL: this host does not advertise the "${protocol}" rpc protocol`, undefined, 'UNSUPPORTED_PROTOCOL');
    }
  }

  /**
   * Open a typed (object-mode) RPC channel (wsh #85): sugar over `openSession({ type: 'rpc', protocol })` that
   * returns an {@link RpcChannel} -- JSON-RPC 2.0 over a CBOR sequence on one QMux stream.
   *
   * @param {string} protocol - e.g. `'mcp'`, `'wsh-fs'`, `'wsh-host'`
   * @param {object} [opts]
   * @param {number} [opts.timeoutMs] - default timeout for every `request()` on the channel
   * @param {number} [opts.openTimeout] - how long to wait for the host to open the channel
   * @returns {Promise<RpcChannel>}
   */
  async openRpc(protocol, { timeoutMs, openTimeout = DEFAULT_OPEN_TIMEOUT } = {}) {
    this.#assertAuthenticated('openRpc');
    const { maxMessageBytes } = parseRpcFeatures(this.#serverFeatures);
    let channel = null;
    const session = await this.openSession({
      type: 'rpc', protocol, timeout: openTimeout,
      attach: (s) => {
        channel = new RpcChannel({
          maxMessageBytes: maxMessageBytes ?? RPC_DEFAULT_MAX_MESSAGE,
          timeoutMs,
          write: (bytes) => s.write(bytes),
          close: () => s.close(),
        });
        s.onData = (bytes) => channel.feed(bytes);
        s.onClose = (err) => channel.handleClose(err ? 'stream-error' : 'channel-closed');
      },
    });
    channel.session = session;
    return channel;
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
   * Authorization is satisfied by EITHER `token` OR the caller already
   * owning/being ACL-granted access to `targetSessionId` server-side (see
   * wsh-server's `check_session_access`) -- `token` is optional and, for
   * the common case of attaching via ownership or a `grantSessionAccess`
   * grant, should simply be omitted (a granted principal never receives
   * the session's token to begin with -- only the opener does, via
   * `WshSession.resumeToken`). Pass one explicitly only if you have it
   * (e.g. this same process opened the session earlier, or the owner
   * shared it with you out of band).
   *
   * Previously (clawser #48) this always sent this connection's own
   * AUTH-level token, which can never verify against a *different*
   * session_id -- making attachSession() unreachable for everyone,
   * including the session's own owner from a fresh connection. Also fixed
   * alongside that: the server actually replies with PRESENCE (success)
   * or ERROR (failure), not OPEN_OK/OPEN_FAIL -- this used to wait on the
   * wrong response stream entirely and would have hung even once the
   * token bug was fixed.
   *
   * @param {string} targetSessionId - Remote session ID to attach to
   * @param {object} [opts]
   * @param {boolean} [opts.readOnly=false] - Attach in read-only mode
   * @param {Uint8Array} [opts.token] - Session-scoped token (optional; see above)
   * @param {number} [opts.timeout] - Timeout in ms
   * @returns {Promise<object>} Server's PRESENCE response. Against a host that
   *   assigns the attachment a channel (`@johnhenry/wsh/server` with `sessions`)
   *   the response also has a non-enumerable `session`: a message-backed
   *   `WshSession` receiving the replay and live output (`onData`, `write()`,
   *   `resize()`, `onExit`), whose `seq` is the position to resume from next time.
   */
  async attachSession(targetSessionId, { readOnly = false, token, timeout = DEFAULT_OPEN_TIMEOUT } = {}) {
    this.#assertAuthenticated('attachSession');

    const attachMode = readOnly ? 'readonly' : 'control';
    return this.#attachOrResume(
      targetSessionId, token, attachMsg({ sessionId: targetSessionId, token, mode: attachMode }),
      timeout, 'attach', 'Failed to attach',
    );
  }

  /**
   * Send an Attach/Resume and wait for the Presence that answers it.
   * @private
   */
  async #attachOrResume(sessionId, token, msg, timeout, what, failure) {
    const pending = { sessionId, token };
    this.#pendingAttaches.push(pending);
    try {
      await this.#transport.sendControl(msg);

      const response = await this.#waitForMessage(
        [MSG.PRESENCE, MSG.ERROR],
        timeout,
        `Timed out waiting for ${what} response`,
        // A roster Presence about some other session this connection is in is not the answer.
        (m) => m.type === MSG.ERROR || !Array.isArray(m.attachments) || m.attachments.length === 0
          || m.attachments.some((a) => a?.session_id === sessionId),
      );

      if (response.type === MSG.ERROR) {
        throw new Error(`${failure}: ${response.message || 'rejected'}`);
      }

      return response;
    } finally {
      const i = this.#pendingAttaches.indexOf(pending);
      if (i !== -1) this.#pendingAttaches.splice(i, 1);
    }
  }

  /**
   * Resume a previously disconnected session.
   *
   * Unlike attachSession(), `token` is required and verified
   * unconditionally server-side -- Resume is specifically for the
   * connection that was handed this exact token (via
   * `WshSession.resumeToken`, when it originally opened the session)
   * coming back. A principal who only has ACL/ownership access but never
   * held the token should use attachSession() instead.
   *
   * @param {string} targetSessionId - Session ID to resume
   * @param {Uint8Array} token - Session-scoped resume token (see `WshSession.resumeToken`)
   * @param {object} [opts]
   * @param {number} [opts.lastSeq=0] - Cumulative session output bytes this
   *   client has already received (`WshSession.seq` of the session it lost).
   *   A host with a bounded history replays only what follows and refuses a
   *   position older than it still holds (use `attachSession()` then); the Rust
   *   `wsh-server` ignores it and replays its whole ring.
   * @param {number} [opts.timeout=10000] - Timeout in ms
   * @returns {Promise<object>} Server's PRESENCE response, with a non-enumerable
   *   `session` exactly as for `attachSession()`.
   */
  async resumeSession(targetSessionId, token, { lastSeq = 0, timeout = DEFAULT_OPEN_TIMEOUT } = {}) {
    this.#assertAuthenticated('resumeSession');

    return this.#attachOrResume(
      targetSessionId, token, resumeMsg({ sessionId: targetSessionId, token, lastSeq }),
      timeout, 'resume', 'Failed to resume',
    );
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
    this.#bridgedFeatures = null;

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
   * @param {boolean} [opts.primer=true] - See `openSession({ primer })`
   * @returns {Promise<{stdout: Uint8Array, exitCode: number}>}
   */
  static async exec(url, command, { username, keyPair, password, timeout = DEFAULT_EXEC_TIMEOUT, primer = true, ...hostKeyOpts } = {}) {
    const client = new WshClient();
    const chunks = [];
    let exitCode = -1;

    try {
      await client.connect(url, { username, keyPair, password, ...hostKeyOpts });

      const session = await client.openSession({ type: 'exec', command, primer });

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
    webTransport,
    expose = {},
    peerType = 'browser-shell',
    shellBackend,
    supportsAttach,
    supportsReplay,
    supportsEcho,
    supportsTermSync,
    ...hostKeyOpts
  } = {}) {
    // Authenticate normally first.
    const sessionId = await this.connect(url, { username, keyPair, password, webTransport, ...hostKeyOpts });

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
      // The relay's SERVER_HELLO describes the relay, not the host behind the
      // bridge: when that host says what it supports, feature gates
      // (file-write, file-rename, mcp-call-id) follow it instead.
      this.#bridgedFeatures = Array.isArray(response.features) && response.features.every((f) => typeof f === 'string')
        ? [...response.features]
        : null;
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
   * @param {{ to?: string }} [opts] - `to`: the operator this is for, when this peer serves several
   *   (`relay-multi-operator`, wsh #89): the message is sent as a `RelayForward` addressed to that
   *   fingerprint. Leave it out for a peer's only operator.
   * @returns {Promise<void>}
   */
  async sendRelayControl(msg, { to } = {}) {
    this.#assertAuthenticated('sendRelayControl');
    if (to !== undefined) {
      // A peer serving several operators addresses each message: the relay routes the wrapper to `to`
      // and re-wraps it with this peer's fingerprint (from_fingerprint here is overwritten, not trusted).
      if (typeof to !== 'string' || !to) throw new TypeError('sendRelayControl: to must be an operator fingerprint');
      msg = relayForwardMsg({ fromFingerprint: '', toFingerprint: to, inner: cborEncode(msg) });
    }
    await this.#transport.sendControl(msg);
  }

  // ── Raw control channel (used by WshMcpBridge / WshFileTransfer) ─────
  //
  // `WshMcpBridge` and `WshFileTransfer` both document their constructor
  // argument as "a WshClient", and both drive the connection through
  // `sendControl()` + `addControlListener()`/`removeControlListener()`
  // (`WshFileTransfer.list()` also needs `openStream()`). None of those
  // existed on this class, so every one of those code paths failed with
  // `TypeError: this.#client.sendControl is not a function` the moment a
  // real client was passed instead of a hand-written stand-in — the same
  // shape as the 0.14.0 `attachSession()`/`resumeSession()` bug, where a
  // whole method was unreachable while the suite stayed green because
  // every test spoke to a mock that answered whatever it was asked.
  //
  // These four members are thin, deliberate delegations rather than a new
  // subsystem: the transport already owns the socket and the framing, and
  // `#handleControl` already sees every inbound control message.

  /**
   * Send a raw control message on the authenticated connection.
   *
   * Prefer the typed methods (`openSession`, `callTool`, `upload`, …).
   * This exists for the helper classes that compose their own messages —
   * see `WshMcpBridge` and `WshFileTransfer`.
   *
   * @param {object} msg
   * @returns {Promise<void>}
   */
  async sendControl(msg) {
    this.#assertAuthenticated('sendControl');
    await this.#transport.sendControl(msg);
  }

  /**
   * Open a raw bidirectional stream on the underlying transport.
   *
   * @returns {Promise<{ readable: ReadableStream, writable: WritableStream }>}
   */
  async openStream() {
    this.#assertAuthenticated('openStream');
    return this.#transport.openStream();
  }

  /**
   * Observe every inbound control message this client handles.
   *
   * Listeners are called after the RelayForward trust gate, so a relayed
   * message from an untrusted peer is never handed to one, and a trusted
   * RelayForward is delivered as its unwrapped inner message. A listener
   * that throws is logged and does not stop the client's own dispatch.
   *
   * @param {function(object): void} fn
   */
  addControlListener(fn) {
    if (typeof fn !== 'function') throw new TypeError('addControlListener requires a function');
    this.#controlListeners.add(fn);
  }

  /**
   * Stop observing inbound control messages.
   * @param {function(object): void} fn
   */
  removeControlListener(fn) {
    this.#controlListeners.delete(fn);
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
   * Safe to call concurrently. Against a server advertising the
   * `mcp-call-id` feature each call carries a correlation id and takes only
   * its own reply. Against an older server there is no id on the wire and
   * replies are indistinguishable, so calls are queued one at a time on this
   * connection -- slower, but never the wrong tool's result.
   *
   * @param {string} name - Tool name
   * @param {object} [args={}] - Tool arguments. Defaults to `{}` rather
   *   than being omitted: `McpCall.arguments` is a required wire field,
   *   and a tool that takes no arguments is an ordinary thing to call.
   * @param {number} [timeout=30000]
   * @returns {Promise<*>} Tool result
   */
  async callTool(name, args = {}, timeout = 30_000) {
    this.#assertAuthenticated('callTool');
    requireArgs('callTool', { name });

    if (this.hasFeature(MCP_CALL_ID_FEATURE)) {
      return this.#callToolCorrelated(name, args, timeout);
    }
    // No correlation available: serialise so a concurrent caller cannot be
    // handed someone else's result.
    const run = this.#mcpQueue.then(
      () => this.#callToolCorrelated(name, args, timeout),
      () => this.#callToolCorrelated(name, args, timeout),
    );
    this.#mcpQueue = run.then(() => undefined, () => undefined);
    return run;
  }

  /**
   * Send one McpCall and wait for the McpResult that answers it.
   * @private
   */
  async #callToolCorrelated(name, args, timeout) {
    const correlate = this.hasFeature(MCP_CALL_ID_FEATURE);
    // Only sent when the peer understands it: McpCallPayload is
    // deny_unknown_fields on the Rust side, so an unsolicited call_id would
    // make an older server reject the call outright rather than ignore it.
    const callId = correlate ? `mcp-${++this.#mcpCallCounter}-${Date.now()}` : undefined;

    await this.#transport.sendControl(
      mcpCallMsg({ tool: name, arguments: args, callId })
    );

    const response = await this.#waitForMessage(
      [MSG.MCP_RESULT],
      timeout,
      `Timed out waiting for MCP tool result (${name})`,
      // A responder that echoes no call_id gets matched on type, which is
      // the pre-correlation behaviour and all an older peer can offer.
      callId === undefined
        ? undefined
        : (msg) => msg.call_id === undefined || msg.call_id === callId,
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
    requireArgs('inviteGuest', { sessionId, ttl });
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
   * @param {number} ttl - Share lifetime in seconds. Not optional,
   *   despite its position after a defaulted parameter:
   *   `ShareSession.ttl` is a required wire field, and there is no
   *   sensible default lifetime for a share link to invent on the
   *   caller's behalf.
   * @param {number} [timeout=10000]
   * @returns {Promise<object>} Share response with share_id
   */
  async shareSession(sessionId, mode = 'read', ttl, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('shareSession');
    requireArgs('shareSession', { sessionId, ttl });
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
    requireArgs('setRateControl', { sessionId, maxBytesPerSec });
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
    requireArgs('copilotAttach', { sessionId, model });
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
   * `KeyExchange` carries only ephemeral keys, so on its own it does not stop a relay that substitutes them.
   * Pass `verifyPeer` -- the peer's long-term Ed25519 public key, e.g. the `public_key` of the peer record you
   * listed -- to require that the peer signed its half (a reverse host does: `e2e-sign` in its features); the
   * exchange is refused with `code: 'E2E_PEER_UNAUTHENTICATED'` if the signature is missing or does not verify.
   *
   * @param {string} sessionId - Session ID
   * @param {string} [algorithm='X25519'] - 'X25519' or 'X25519+ML-KEM-768'
   * @param {number} [timeout=10000]
   * @param {object} [opts]
   * @param {Uint8Array | CryptoKey} [opts.verifyPeer] - the peer's Ed25519 public key (raw 32 bytes or imported)
   * @returns {Promise<{sharedSecret: CryptoKey, peerPublicKey: Uint8Array, hybrid: boolean, peerAuthenticated: boolean}>}
   */
  async initiateE2E(sessionId, algorithm = 'X25519', timeout = DEFAULT_OPEN_TIMEOUT, { verifyPeer } = {}) {
    this.#assertAuthenticated('initiateE2E');
    const wantHybrid = algorithm === 'X25519+ML-KEM-768';

    // Register the waiter before ANY await, key generation included.
    //
    // Two peers establishing E2E both call this at once, and #handleControl
    // DROPS a KEY_EXCHANGE that no waiter is listening for. Whichever side
    // finishes its local key generation first sends its round-1 message into
    // the other's blind window -- the other is still inside generateKey /
    // exportKey below and has nothing registered. That message is gone, and
    // the side that lost it then waits the full timeout for something the
    // peer has already sent and will not send again.
    //
    // Registering after the crypto, or merely before sendControl, leaves the
    // window open: measured at ~10% of runs before, and still ~5% with the
    // waiter registered after key generation. The only safe point is here,
    // before this function yields for the first time.
    const peerMsgPromise = this.#waitForMessage(
      [MSG.KEY_EXCHANGE],
      timeout,
      'Timed out waiting for peer key exchange'
    );
    // Mark it handled so a failure in the key generation or send below does
    // not surface as an unhandled rejection when this waiter later times
    // out. Awaiting the promise still throws normally.
    peerMsgPromise.catch(() => {});

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

    const peerMsg = await peerMsgPromise;

    let peerAuthenticated = false;
    if (verifyPeer !== undefined) {
      const ok = await verifyKeyExchangeSignature(verifyPeer, peerMsg.signature, {
        sessionId, algorithm, initiatorKey: localPub, responderKey: new Uint8Array(peerMsg.public_key ?? []),
      });
      if (!ok) {
        throw Object.assign(
          new Error(peerMsg.signature === undefined
            ? 'initiateE2E: the peer did not sign its key exchange (verifyPeer was given)'
            : 'initiateE2E: the peer\'s key exchange signature does not verify against verifyPeer'),
          { code: 'E2E_PEER_UNAUTHENTICATED' },
        );
      }
      peerAuthenticated = true;
    }

    // Round 2 has the same shape as round 1, so it needs the same treatment.
    // Whether we encapsulate or decapsulate is decided entirely by data
    // already in hand, so decide it now and register the ciphertext waiter
    // BEFORE the derive below. Registering it inside the `else` branch, after
    // importKey and deriveBits, let the peer's ciphertext arrive while this
    // side was still deriving -- dropped, then a full-timeout wait for a
    // message already sent. That surfaced as "Timed out waiting for peer
    // ML-KEM-768 ciphertext", which retryOnKnownFlake retries and the test
    // file attributes to a Node provider stall.
    const hybridActive = wantHybrid && !!localKem && !!peerMsg.kem_public_key;
    const isEncapsulator = hybridActive
      && compareBytes(localPub, new Uint8Array(peerMsg.public_key)) < 0;

    let ctMsgPromise = null;
    if (hybridActive && !isEncapsulator) {
      ctMsgPromise = this.#waitForMessage(
        [MSG.KEY_EXCHANGE],
        timeout,
        'Timed out waiting for peer ML-KEM-768 ciphertext'
      );
      ctMsgPromise.catch(() => {});
    }

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

    let combinedBits = sharedBits;

    if (hybridActive) {
      const peerKemPublicKey = new Uint8Array(peerMsg.kem_public_key);

      let kemSharedSecret;
      if (isEncapsulator) {
        const { ciphertext, sharedSecret } = await mlKemEncapsulate(peerKemPublicKey);
        kemSharedSecret = sharedSecret;
        await this.#transport.sendControl(keyExchangeMsg({ algorithm, sessionId, kemCiphertext: ciphertext }));
      } else {
        const ctMsg = await ctMsgPromise;
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

    return { sharedSecret, peerPublicKey: new Uint8Array(peerMsg.public_key), hybrid: hybridActive, peerAuthenticated };
  }

  // ── Structured File Channel ───────────────────────────────────────

  /**
   * Perform a file operation on the remote host.
   *
   * `write` and `rename` carry data the wsh-v1 `FileOp` frame has no field
   * for, so both send the payload as a `FileChunk` on the same channel id
   * (no frame or field outside the spec), and the host must advertise
   * `file-write` / `file-rename` in ServerHello; against a host that does
   * not, they throw instead of sending a request the host would misread:
   *  - `write`: `FileOp{ op: 'write', path, offset?, length }`, then the bytes
   *    as `FileChunk` frames (the last with `is_final`).
   *  - `rename`: `FileOp{ op: 'rename', path: <old> }`, then one final
   *    `FileChunk` whose data is the UTF-8 destination path.
   * Either way the single `FileResult` arrives after the final chunk.
   *
   * @param {string} op - Operation: 'stat', 'list', 'read', 'write', 'mkdir', 'remove', 'rename'
   * @param {string} path - File path
   * @param {object} [opts] - Optional: offset, length for read; `data` (+ `offset`) for write; `newPath` for rename
   * @param {number} [timeout=10000]
   * @returns {Promise<object>} FileResult response
   */
  async fileOperation(op, path, opts = {}, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('fileOperation');
    // wsh #85: a host that serves the `wsh-fs` rpc protocol is preferred over the FileOp/FileResult control path.
    if (this.preferRpcFiles && FS_RPC_OPS.has(op) && this.hasFeature(rpcProtocolFeature('wsh-fs'))) {
      let rpc = null;
      try { rpc = await this.#fsChannel(); } catch { /* fall back to FileOp */ }
      if (rpc) return this.#fileOperationRpc(rpc, op, path, opts, timeout);
    }
    const channelId = this._nextChannelId();
    // FileOp and FileResult both carry channel_id; each call claims only the
    // result for its own id, so overlapping operations cannot swap replies (#72).
    const byChannel = (m) => m.channel_id === channelId;

    if (op === 'write' || op === 'rename') {
      const feature = op === 'write' ? 'file-write' : 'file-rename';
      if (!this.hasFeature(feature)) throw new Error(`this host does not support file ${op} (no "${feature}" feature)`);
      let data;
      if (op === 'write') {
        data = typeof opts.data === 'string' ? new TextEncoder().encode(opts.data) : opts.data;
        if (!(data instanceof Uint8Array)) throw new TypeError('fileWrite: data must be a string or Uint8Array');
      } else {
        if (typeof opts.newPath !== 'string' || !opts.newPath) throw new TypeError('fileRename: newPath is required');
        data = new TextEncoder().encode(opts.newPath);
      }
      // Registered before sending: the host may fail fast (read-only, too big)
      // and answer before the last chunk goes out.
      const result = this.#waitForMessage([MSG.FILE_RESULT], timeout, `Timed out waiting for file ${op} result`, byChannel);
      result.catch(() => {});
      await this.#transport.sendControl(fileOpMsg({
        channelId, op, path, offset: op === 'write' ? opts.offset : undefined, length: data.byteLength,
      }));
      let off = 0;
      do {
        const end = Math.min(off + FILE_CHUNK_SIZE, data.byteLength);
        await this.#transport.sendControl(fileChunkMsg({
          channelId, offset: off, data: data.subarray(off, end), isFinal: end >= data.byteLength, totalSize: data.byteLength,
        }));
        off = end;
      } while (off < data.byteLength);
      return result;
    }

    await this.#transport.sendControl(
      fileOpMsg({ channelId, op, path, offset: opts.offset, length: opts.length })
    );
    return this.#waitForMessage(
      [MSG.FILE_RESULT],
      timeout,
      `Timed out waiting for file ${op} result`,
      byChannel
    );
  }

  /**
   * Use the `wsh-fs` rpc protocol for `fileStat`/`fileList`/`fileRead`/`fileWrite`/... when the host advertises it
   * (default `true`); set `false` to always use the FileOp control path. Results keep the FileResult shape either way.
   */
  preferRpcFiles = true;
  #fsRpc = null;

  async #fsChannel() {
    if (this.#fsRpc) {
      const existing = await this.#fsRpc.catch(() => null);
      if (existing && !existing.closed) return existing;
      this.#fsRpc = null;
    }
    const opening = this.openRpc('wsh-fs');
    this.#fsRpc = opening;
    try { return await opening; } catch (err) { if (this.#fsRpc === opening) this.#fsRpc = null; throw err; }
  }

  /** `fileOperation` over `wsh-fs`, mapped back onto the FileResult shape the FileOp path returns. */
  async #fileOperationRpc(rpc, op, path, opts, timeout) {
    const channelId = this._nextChannelId();
    const ok = (metadata = {}, entries = []) => fileResultMsg({ channelId, success: true, metadata, entries });
    const timeoutMs = timeout;
    try {
      switch (op) {
        case 'stat': return ok(await rpc.request('stat', { path }, { timeoutMs }));
        case 'list': {
          const r = await rpc.request('list', { path }, { timeoutMs });
          return ok({ path: r.path }, r.entries);
        }
        case 'read': {
          const parts = [];
          const r = await rpc.request('read', { path, offset: opts.offset, length: opts.length ?? FILE_CHUNK_SIZE }, { timeoutMs, onProgress: (c) => { if (c instanceof Uint8Array) parts.push(c); } });
          const data = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
          let at = 0;
          for (const p of parts) { data.set(p, at); at += p.byteLength; }
          return ok({ data, size: r.size });
        }
        case 'mkdir': case 'remove':
          return ok(await rpc.request(op, { path }, { timeoutMs }));
        case 'rename':
          if (typeof opts.newPath !== 'string' || !opts.newPath) throw new TypeError('fileRename: newPath is required');
          return ok(await rpc.request('rename', { path, newPath: opts.newPath }, { timeoutMs }));
        case 'write': {
          const data = typeof opts.data === 'string' ? new TextEncoder().encode(opts.data) : opts.data;
          if (!(data instanceof Uint8Array)) throw new TypeError('fileWrite: data must be a string or Uint8Array');
          const step = Math.max(256, Math.min(256 * 1024, rpc.maxMessageBytes - 1024));
          const base = opts.offset === undefined || opts.offset === null ? undefined : Number(opts.offset);
          let off = 0;
          do {
            const end = Math.min(off + step, data.byteLength);
            const chunk = data.subarray(off, end);
            // Whole-file replace streams as `upload` (offset 0 truncates, later offsets continue); an explicit
            // offset writes in place chunk by chunk, never truncating.
            if (base === undefined) await rpc.request('upload', { path, data: chunk, offset: off || undefined }, { timeoutMs });
            else await rpc.request('write', { path, data: chunk, offset: base + off }, { timeoutMs });
            off = end;
          } while (off < data.byteLength);
          return ok({ written: data.byteLength });
        }
        default: throw new Error(`unsupported file op ${op}`);
      }
    } catch (err) {
      // Host-reported failures keep the FileResult contract (success: false); transport trouble still throws.
      if (err instanceof RpcError && err.code !== RPC_ERROR.CANCELLED) {
        return fileResultMsg({ channelId, success: false, errorMessage: err.message });
      }
      throw err;
    }
  }

  /** Stat a remote file. */
  async fileStat(path, timeout) { return this.fileOperation('stat', path, {}, timeout); }
  /** List a remote directory. */
  async fileList(path, timeout) { return this.fileOperation('list', path, {}, timeout); }
  /** Read a remote file. */
  async fileRead(path, offset, length, timeout) { return this.fileOperation('read', path, { offset, length }, timeout); }
  /** Write to a remote file. */
  async fileWrite(path, data, offset, timeout) { return this.fileOperation('write', path, { data, offset }, timeout); }
  /** Create a remote directory. */
  async fileMkdir(path, timeout) { return this.fileOperation('mkdir', path, {}, timeout); }
  /** Remove a remote file or directory. */
  async fileRemove(path, timeout) { return this.fileOperation('remove', path, {}, timeout); }
  /** Rename a remote file or directory. */
  async fileRename(oldPath, newPath, timeout) { return this.fileOperation('rename', oldPath, { newPath }, timeout); }

  // ── Authorized-key management (wsh #59) ───────────────────────────

  /**
   * Install a raw 32-byte Ed25519 public key into the remote host's
   * ~/.wsh/authorized_keys via the AuthorizedKeyAdd protocol message.
   *
   * Replaces `wsh copy-id`'s CLI-only, shell-command-built approach
   * (`crates/wsh-cli/src/commands/copy_id.rs`) with a real protocol
   * message every implementation can call -- including this one, the
   * browser SDK, which previously had no way to install a key at all
   * (no shell channel to build a command string for). See copy_id.rs's
   * doc comment for the full security reasoning: an authenticated
   * connection already has unrestricted exec/file access to this exact
   * file, so this adds no new privilege boundary.
   *
   * Idempotent: installing an already-present key resolves
   * `{ added: false }` rather than duplicating the line or erroring.
   *
   * @param {Uint8Array} publicKeyRaw - Raw 32-byte Ed25519 public key
   * @param {string} [comment] - Trailing comment for the authorized_keys line
   * @param {number} [timeout=10000]
   * @returns {Promise<{ added: boolean }>}
   */
  async addAuthorizedKey(publicKeyRaw, comment, timeout = DEFAULT_OPEN_TIMEOUT) {
    this.#assertAuthenticated('addAuthorizedKey');
    await this.#transport.sendControl(
      authorizedKeyAddMsg({ publicKey: publicKeyRaw, comment })
    );
    const result = await this.#waitForMessage(
      [MSG.AUTHORIZED_KEY_RESULT],
      timeout,
      'Timed out waiting for authorized-key-add result'
    );
    if (!result.success) {
      throw new Error(result.error_message || 'key installation refused');
    }
    return { added: !!result.added };
  }

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
    requireArgs('updatePolicy', { policyId, rules, version });
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
   * @param {object} [webTransport] - Options for the `WebTransport`
   *   constructor, applied only to a `wt` attempt (see
   *   `WebTransportTransport`). The `ws` rung of the ladder ignores them:
   *   a `serverCertificateHashes` pin has no WebSocket equivalent, so a
   *   `wss:` fallback against that same self-signed certificate will
   *   still fail the usual certificate-authority check.
   * @returns {Promise<import('./transport.mjs').WshTransport>}
   * @private
   */
  async #connectTransport(url, hint, webTransport) {
    const attempts = this.#buildTransportAttempts(url, hint);
    const errors = [];

    for (const attempt of attempts) {
      const transport = this.#createTransport(attempt.kind);
      try {
        await transport.connect(attempt.url, attempt.kind === 'wt' ? webTransport : undefined);
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
    if (hint !== undefined && hint !== null && hint !== 'auto') {
      // Anything else is a typo, and silently treating it as 'auto' is
      // the worst available answer: `transport: 'webtransport'` would
      // quietly fall back to WebSocket, dropping any
      // `webTransport.serverCertificateHashes` pin along with it and
      // connecting over a transport the caller explicitly tried to avoid.
      throw new Error(
        `Unknown transport hint: ${JSON.stringify(hint)} (expected 'wt', 'ws', or 'auto')`
      );
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
    return this.#performAuth({ ...opts, url });
  }

  // ── Internal: host key (TOFU / pinning) ─────────────────────────────

  /**
   * Check the host's advertised key (see host-key.mjs) against the caller's
   * policy. Runs before any credential leaves this client. Throws a
   * `HostKeyError`; the surrounding handshake `catch` closes the transport.
   *
   * @param {object|null} serverHello - ServerHello, or null when the server went straight to CHALLENGE
   * @param {object} ctx - { url, username, nonce, expectHostKey, knownHosts, hostLabel, trustOnFirstUse, onHostKey }
   * @private
   */
  async #verifyHostKey(serverHello, ctx) {
    const { expectHostKey, knownHosts, trustOnFirstUse, nonce, username } = ctx;
    const wantsCheck = Boolean(expectHostKey || knownHosts);
    const advert = serverHello ? findHostKeyAdvert(serverHello.features) : null;

    if (!advert) {
      if (wantsCheck) {
        throw new HostKeyError('HOST_KEY_MISSING',
          'host key required (expectHostKey/knownHosts) but the server presented none; refusing before sending credentials');
      }
      return;
    }

    const { key, sig } = advert;
    if (!key || key.byteLength !== 32 || !sig) {
      throw new HostKeyError('HOST_KEY_INVALID', 'server advertised a malformed host key or no proof of possession');
    }
    let ok = false;
    let fp;
    try {
      fp = await computeFingerprint(key);
      ok = await verifySignature(
        await importPublicKeyRaw(key), sig,
        hostKeyProofMessage({ sessionId: serverHello.session_id, clientNonce: nonce, username }),
      );
    } catch { ok = false; }
    if (!ok) throw new HostKeyError('HOST_KEY_INVALID', 'host key proof does not verify (not signed over this connection)');
    if (serverHello.host_fingerprint && serverHello.host_fingerprint !== fp) {
      throw new HostKeyError('HOST_KEY_INVALID', 'ServerHello.host_fingerprint does not match the advertised host key');
    }

    let openssh = '';
    try { openssh = await exportPublicKeySSH(await importPublicKeyRaw(key)); } catch { /* informational only */ }
    const info = { fingerprint: fp, publicKey: key, openssh, status: 'unpinned' };
    this.#hostKey = info;

    if (expectHostKey) {
      const want = await normalizeExpectedHostKey(expectHostKey);
      if (want !== fp) {
        throw new HostKeyError('HOST_KEY_MISMATCH',
          `host key mismatch: expected ${want}, host presented ${fp}`, { expected: want, actual: fp });
      }
      info.status = 'pinned';
    }

    let label = ctx.hostLabel;
    if (knownHosts) {
      if (!label) {
        try { label = new URL(ctx.url).host; } catch { label = String(ctx.url); }
      }
      const v = knownHosts.verifyHost(label, fp);
      if (v.status === 'changed') {
        throw new HostKeyError('HOST_KEY_MISMATCH',
          `HOST KEY CHANGED for ${label}: pinned ${v.expected}, host presented ${fp} (possible impersonation)`,
          { expected: v.expected, actual: fp });
      }
      info.status = v.status; // 'known' | 'unknown'
    }

    const cb = ctx.onHostKey ?? this.onHostKey;
    if (typeof cb === 'function') {
      let verdict;
      try { verdict = await cb({ ...info }); } catch (e) {
        throw new HostKeyError('HOST_KEY_REJECTED', `onHostKey threw: ${e?.message ?? e}`);
      }
      if (verdict === false) throw new HostKeyError('HOST_KEY_REJECTED', 'host key rejected by onHostKey');
    }

    if (knownHosts && info.status === 'unknown') {
      if (!trustOnFirstUse && typeof cb !== 'function') {
        throw new HostKeyError('HOST_KEY_UNKNOWN',
          `${label} is not in knownHosts; pass trustOnFirstUse: true (or an onHostKey) to pin it`, { actual: fp });
      }
      knownHosts.addHost(label, fp);
    }
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
  async #performAuth({ username, keyPair, password, timeout = DEFAULT_AUTH_TIMEOUT, url, ...hostKeyOpts } = {}) {
    if (!username) throw new Error('username is required');
    if (!keyPair && !password) throw new Error('Either keyPair or password is required');

    this.#hostKey = null;
    try {
      const authMethod = keyPair ? AUTH_METHOD.PUBKEY : AUTH_METHOD.PASSWORD;
      const hostKeyNonce = newHostKeyNonce();
      await this.#transport.sendControl(hello({ username, authMethod, features: [HOST_KEY_NONCE_PREFIX + hostKeyNonce] }));
      const hostCtx = { ...hostKeyOpts, url, username, nonce: hostKeyNonce };

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
        // Waiter first, then the (async) host key check -- see connect().
        const challengeWait = authMethod === AUTH_METHOD.PUBKEY
          ? this.#waitForMessage([MSG.CHALLENGE, MSG.AUTH_OK], timeout, 'Timed out waiting for challenge')
          : null;
        challengeWait?.catch(() => {});
        await this.#verifyHostKey(firstResponse, hostCtx);

        if (authMethod === AUTH_METHOD.PUBKEY) {
          const challengeMsg = await challengeWait;

          if (challengeMsg.type === MSG.AUTH_OK) {
            this.#sessionId = challengeMsg.session_id || tempSessionId;
            this.#authToken = challengeMsg.token || null;
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
        await this.#verifyHostKey(null, hostCtx);

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
      this.#authToken = authResult.token || null;
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
  #handleControl(msg, from) {
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
      this.#handleControl(inner, msg.from_fingerprint);
      return;
    }

    // Observers registered via addControlListener() see the message here —
    // past the RelayForward trust gate above (so an untrusted peer's
    // message never reaches one, and a trusted one arrives unwrapped) and
    // before this client's own dispatch, so a helper waiting on a reply
    // cannot miss it to an ordering accident.
    this.#dispatchControlListeners(msg);

    // OPEN_OK/OPEN_FAIL: handled as a dedicated case (not the generic
    // waiter mechanism below) so the WshSession gets constructed and
    // registered in #sessions synchronously, in the same dispatch step as
    // OPEN_OK itself — see #pendingOpens's doc comment for why.
    if (type === MSG.OPEN_OK || type === MSG.OPEN_FAIL) {
      const pending = this.#pendingOpens.shift();
      if (!pending) return;
      clearTimeout(pending.timer);

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
        {
          dataMode,
          capabilities,
          // clawser #48: OpenOk now carries the session_id/token this
          // channel belongs to (pty/exec only -- undefined for e.g. file
          // channels, which have no Attach/Resume-able session). Exposed
          // via WshSession.sessionId/resumeToken for a later
          // attachSession()/resumeSession() call, possibly from a
          // different connection.
          sessionId: msg.session_id,
          resumeToken: msg.token,
        }
      );
      this.#sessions.set(serverChannelId, session);

      if (dataMode === 'virtual') {
        session._activateVirtual((m) => this.sendRelayControl(m));
        pending.attach?.(session);
        pending.resolve(session);
        return;
      }

      // Stream mode needs a real transport stream, which is inherently
      // async — but #sessions.set() above already happened synchronously,
      // so channel-scoped control messages arriving before the stream
      // finishes binding still route correctly.
      this.#transport.openStream().then(
        async (stream) => {
          session._bind(stream.readable, stream.writable);
          pending.attach?.(session);
          // The transport has already announced the stream, which is all a
          // current host needs. Older hosts only bind a stream on its first
          // byte, so exec (which has no stdin to send) writes a one-byte
          // primer they strip -- unless the host says it needs none.
          if (pending.kind === 'exec' && pending.primer && !this.hasFeature(STREAM_ANNOUNCE_FEATURE)) {
            try {
              await session.write(new Uint8Array([0]));
            } catch (err) {
              pending.reject(err);
              return;
            }
          }
          pending.resolve(session);
        },
        (err) => pending.reject(err)
      );
      return;
    }

    // The Presence answering this connection's own Attach/Resume names the
    // channel the host assigned (see AttachmentInfo.channel_id): build the
    // session now, synchronously, so the replay right behind it finds it.
    if (type === MSG.PRESENCE && this.#pendingAttaches.length > 0) {
      const own = Array.isArray(msg.attachments)
        ? msg.attachments.find((a) => a?.channel_id !== undefined && this.#pendingAttaches.some((p) => p.sessionId === a.session_id))
        : undefined;
      if (own) {
        const pending = this.#pendingAttaches.find((p) => p.sessionId === own.session_id);
        const session = new WshSession(this.#transport, own.channel_id, {}, 'pty', {
          dataMode: 'virtual',
          capabilities: ['resize', 'signal'],
          sessionId: own.session_id,
          resumeToken: pending.token,
        });
        session._setSeq(Number.isSafeInteger(own.seq) ? own.seq : 0);
        this.#sessions.set(own.channel_id, session);
        session._activateVirtual((m) => this.sendRelayControl(m));
        Object.defineProperty(msg, 'session', { value: session, enumerable: false });
      }
    }

    // First, check if any waiters are listening for this message type.
    // A waiter carrying a `match` predicate only takes messages it claims,
    // so the queue is scanned rather than shifted blindly.
    if (this.#waiters.has(type)) {
      const queue = this.#waiters.get(type);
      for (let i = 0; i < queue.length; i++) {
        if (queue[i].match && !queue[i].match(msg)) continue;
        const waiter = queue.splice(i, 1)[0];
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
          if (!queue[i].types?.includes(type)) continue;
          if (queue[i].match && !queue[i].match(msg)) continue;
          const waiter = queue.splice(i, 1)[0];
          if (queue.length === 0) this.#waiters.delete(key);
          clearTimeout(waiter.timer);
          waiter.resolve(msg);
          return;
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
        this.onRelayMessage(msg, from);
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

      case MSG.REVERSE_CLOSE:
        // The relay telling a peer that serves several operators that one of them left (wsh #89).
        try {
          this.onReverseClose?.(msg);
        } catch (err) {
          console.error('[wsh:client] onReverseClose handler error:', err);
        }
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
    this.#bridgedFeatures = null;
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
  #waitForMessage(types, timeout, timeoutMessage, match) {
    const typeArr = Array.isArray(types) ? types : [types];

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        // Remove this waiter.
        this.#removeWaiter(key, waiter);
        reject(new Error(timeoutMessage));
      }, timeout);

      // `match` lets a waiter claim only the reply that belongs to it --
      // correlation, rather than "first waiter of this type wins". Waiters
      // without one match on type alone, as before.
      const waiter = { resolve, reject, timer, types: typeArr, match };

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

      /*
       * Act on the pong, rather than merely recording it.
       *
       * `#lastPong` was written on every PONG and read nowhere -- `grep -arn
       * lastPong src/` returned the declaration and two assignments and no
       * third line. So the keepalive proved the connection was alive when it
       * was, and said nothing when it stopped being: pings went out forever
       * at every peer, dead or not, and a caller waiting for data waited
       * without a reason.
       *
       * Compared against a deadline rather than armed as a timer, which
       * matters: a timer re-armed on each tick is cleared before it can fire
       * whenever the interval is shorter than the timeout, and is then
       * incapable of firing at all. (browsermesh#32 shipped exactly that.) A
       * timestamp comparison has no such failure mode.
       */
      if (this.#lastPong !== null && Date.now() - this.#lastPong > this.#pongTimeoutMs) {
        const silentFor = Date.now() - this.#lastPong;
        this.#stopPing();
        this.#emitError(
          new Error(`wsh: peer stopped answering keepalive pings ${silentFor}ms ago`)
        );
        return;
      }

      this.#transport?.sendControl(
        pingMsg({ id: ++this.#pingId })
      ).catch((err) => {
        console.warn('[wsh:client] Failed to send ping:', err.message);
      });
    }, this.#pingIntervalMs);

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
   * Hand a control message to every addControlListener() observer.
   *
   * Iterates a copy, so a listener that deregisters itself (the normal
   * case — a one-shot reply waiter) does not perturb the iteration, and
   * isolates throws so one bad observer cannot break the client's own
   * dispatch of the same message.
   *
   * @param {object} msg
   * @private
   */
  #dispatchControlListeners(msg) {
    if (this.#controlListeners.size === 0) return;
    for (const fn of [...this.#controlListeners]) {
      try {
        fn(msg);
      } catch (err) {
        console.error('[wsh:client] control listener error:', err);
      }
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
