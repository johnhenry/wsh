/**
 * One wsh-v1 server connection, written against a byte pipe so it knows
 * nothing about WebSocket: `attach({ send })` returns `{ receive, close }`.
 * Speaks the same QMux-over-WebSocket framing the stock client's
 * `WebSocketTransport` does.
 *
 * Exec data plane: exec sessions use `data_mode: 'stream'` -- output flows on
 * the second, client-opened QMux stream. The client's transport announces that
 * stream the moment it opens it (an empty STREAM frame), so the host sees it
 * with no help; the host advertises `stream-announce` in ServerHello so the
 * client knows not to write a primer byte. A client that does write one anyway
 * (hosts that predate the announce required it) has the lone leading `0x00`
 * dropped rather than forwarded to the process's stdin.
 */

import { QMuxConnection } from '../qmux-connection.mjs';
import { FrameDecoder, frameEncode } from '../cbor.mjs';
import {
  MSG, serverHello, challenge, authOk, authFail, openOk, openFail, sessionData,
  exit as exitMsg, close as closeMsg, encryptedFrame as encryptedFrameMsg, pong, fileResult, fileChunk, mcpTools, mcpResult,
  presence as presenceMsg, error as errorMsg, sessionList, detachOk, detachFail, reversePeers, reverseReject,
  targetList as targetListMsg, gatewayFail, listenFail, gatewayCredit,
} from '../messages.gen.mjs';
import {
  generateNonce, verifyChallenge, fingerprint, importPublicKeyRaw,
} from '../auth.mjs';
import { FILE_CHUNK_BYTES, MAX_ATTACHMENTS } from './constants.mjs';
import { MCP_CALL_ID_FEATURE, MCP_CANCEL_FEATURE, RELAY_GATEWAY_FEATURE, SESSION_SEAL_FEATURE, SESSION_SEAL_REQUIRED_FEATURE, TARGETS_FEATURE } from '../features.mjs';
import { TARGET_NAME_RE } from '../host-backends.mjs';
import { RpcChannel, RPC_FEATURE, RPC_VIRTUAL_FEATURE, RPC_MAX_MESSAGE_PREFIX, rpcProtocolFeature } from '../rpc.mjs';
import { RpcCreditLink, rpcChannelOfCredit, rpcCreditId } from '../rpc-virtual.mjs';
import { sealFrame, openFrame, ROLE_TAGS } from '../e2e-frame.mjs';
import { E2EResponder, E2E_FEATURE, E2E_SIGN_FEATURE } from '../e2e-exchange.mjs';
import { MULTI_OPERATOR_FEATURE } from './relay.mjs';
import { gatewayFeatures, GATEWAY_FAIL } from './gateway-core.mjs';
import { GATEWAY_CREDIT_FEATURE } from '../gateway-channel.mjs';
import { GATEWAY_DATAGRAM_FEATURE } from '../gateway-datagram.mjs';
import { OPERATOR_PROOF_FEATURE } from '../operator-proof.mjs';
import { clientEnvFilter } from './client-env.mjs';
import { acceptableBindings, bindingFeatures } from '../channel-binding.mjs';
import { SealedBridge } from '../bridge-seal.mjs';
import { refusalNotifier, validateOnRefused } from '../refusal.mjs';
import { HOST_KEY_PREFIX, HOST_KEY_SIG_PREFIX, findClientNonce, hostKeyProofMessage, toHex } from '../host-key.mjs';
import { checkKeyRequest } from '../key-options.mjs';
import { resolveUsernamePattern, usernameAllowed } from './username.mjs';
import { SHARES_FEATURE, createShareSession } from '../shares.mjs';

export const STREAM_ANNOUNCE = 'stream-announce';
export { SESSION_SEAL_FEATURE, SESSION_SEAL_REQUIRED_FEATURE };

/**
 * The features a host built from `cfg` advertises (`ServerHello.features`, minus the host-key proof).
 * Over a relay bridge (`dataStreams: false`) there are no client-opened streams, so the
 * `stream-announce` is not offered and rpc is stated as `rpc-virtual` (#191) instead of `rpc`; a reverse host reports this
 * list to the operator in `ReverseAccept.features`.
 */
export function hostFeatures(cfg, { dataStreams = true } = {}) {
  const features = dataStreams ? [STREAM_ANNOUNCE] : [];
  if (cfg.mcp) features.push(MCP_CALL_ID_FEATURE, MCP_CANCEL_FEATURE);
  if (cfg.gateway) features.push(...gatewayFeatures(cfg.gateway));
  if (cfg.files) features.push('file-transfer', 'file-write', 'file-rename');
  // Execution targets (#121): `Open`, `FileOp` and `OpenEndpoint` take `target`, and `ListTargets` is answered. A target with files is
  // reached over FileOp, so the file features are stated for it too (the host's own may have none).
  if (cfg.targets) {
    features.push(TARGETS_FEATURE);
    if (!cfg.files && [...cfg.targets.values()].some((t) => t.files)) features.push('file-transfer', 'file-write', 'file-rename');
  }
  if (cfg.onShare) features.push(SHARES_FEATURE); // #159: this host can use folders the operator's client offers
  // End-to-end encryption (#90) is the virtual-mode EncryptedFrame layer, so it is offered where there are no
  // client-opened streams: over a relay bridge.
  // A relay carries a signed KeyExchange untouched, and (when configured) several operators per peer: peers read
  // these from its ServerHello before relying on either, since an older relay would drop the connection on them.
  if (cfg.relay) {
    // #289: this relay carries a reverse host's gateway requests for a bridge whose peer asked for it (`relay-gateway`); `relay.carryGateway: false` turns that off.
    features.push(E2E_SIGN_FEATURE, OPERATOR_PROOF_FEATURE);
    if (cfg.relay.carryGateway !== false) features.push(RELAY_GATEWAY_FEATURE);
    if (cfg.relay.maxOperatorsPerPeer > 1) features.push(MULTI_OPERATOR_FEATURE);
  }
  if (cfg.e2e && !dataStreams) features.push(E2E_FEATURE, ...(cfg.e2e.signKey ? [E2E_SIGN_FEATURE] : []));
  // A sealed session (#155) needs the host's identity to sign its half, and no client-opened streams (their bytes are not frames).
  if (cfg.sealSession && cfg.hostKey && !dataStreams) features.push(SESSION_SEAL_FEATURE, ...(cfg.sealSession === 'require' ? [SESSION_SEAL_REQUIRED_FEATURE] : []));
  // rpc (#85) rides a client-opened data stream; where there is none (a relay bridge, a sealed session) it rides the control
  // plane (#191). A host states one form per connection: a peer that only knows `rpc` never opens a channel it cannot carry.
  if (cfg.rpc && cfg.rpc.protocols.size) {
    features.push(dataStreams ? RPC_FEATURE : RPC_VIRTUAL_FEATURE, ...[...cfg.rpc.protocols.keys()].map(rpcProtocolFeature), RPC_MAX_MESSAGE_PREFIX + cfg.rpc.maxMessageBytes);
  }
  return features;
}
/**
 * The 50 ms the host has always let its last message drain before it closes the transport (a refusal, a deadline). Since #256 it is also how long the
 * host waits for that message to be written at all: a peer that granted no credit, or does not read, cannot hold the close back past 2 x this.
 */
const FINAL_MESSAGE_DRAIN_MS = 50;
/**
 * How long a connection that logged in under `sealSession: 'require'` may stay unsealed (#244): 30 s. The JS client's default for
 * each login step and for its own key exchange is 10 s, so a client on defaults gives up long before this and one on a slow link
 * (or with a longer `timeout`) is not cut off; the host had no bound at all before.
 */
export const DEFAULT_SEAL_TIMEOUT_MS = 30_000;

/** `sealTimeoutMs` must be a finite, non-negative number of milliseconds (0 = no deadline). */
export function assertSealTimeoutMs(v, where) {
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) throw new TypeError(`${where}: sealTimeoutMs must be a non-negative number of milliseconds (0 = no deadline)`);
}

/**
 * How long a connection may take, from the moment a host accepts it, to complete its login -- Hello and Auth (#248): 60 s. The JS client gives
 * each of the three steps (ServerHello, Challenge, AuthOk) 10 s by default, so a login on defaults is over within about 30 s whatever the link;
 * 60 s leaves a person's confirmation on the client (`onHostKey`, a signer on a device) inside the deadline when the client's own `timeout` is
 * raised to let it. The password a login sends is asked for before the connection is opened, not during it. The host had no bound at all before.
 */
export const DEFAULT_LOGIN_TIMEOUT_MS = 60_000;

/** `loginTimeoutMs` must be a finite, non-negative number of milliseconds (0 = no deadline). */
export function assertLoginTimeoutMs(v, where) {
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) throw new TypeError(`${where}: loginTimeoutMs must be a non-negative number of milliseconds (0 = no deadline)`);
}

const MAX_PENDING_WRITES = 8;
const MAX_RENAME_PATH_BYTES = 4096;
const WRITE_IDLE_MS = 30_000;

const MAX_CHANNELS = 64;
const REPLAY_CHUNK_BYTES = 32 * 1024;
const enc = new TextEncoder();

const randomUUID = () => crypto.randomUUID();
const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
const toBytes = (d) => (typeof d === 'string' ? enc.encode(d) : d);

/**
 * The connection handler every host runs -- `createWshServer`, `createMemoryHost`, `createReverseHost` -- exported
 * (as `@johnhenry/wsh/host`) for an embedder that wires its own transport: a WebSocket it opened itself, a
 * `MessagePort`, a byte pipe to another process. It returns `attach(...)`, called once per connection; see below.
 * Build the backends with `resolveBackends()` and the host key with `resolveHostKey()` (same entry point), and
 * answer `authorize` yourself; for the common cases `createMemoryHost()` does all of this and `bindSocket()` does the
 * socket side.
 *
 * Everything here is browser-safe: no `node:*` import and no `Buffer` is reachable from this module.
 *
 * @param {object} cfg
 * @param {(who: { username: string, fingerprint?: string, publicKey?: Uint8Array }) => Promise<boolean>} cfg.authorize - required;
 *   decides who is let in (`buildAuthorizer` in `server/auth.mjs` builds one from `authorizedKeys` / a callback)
 * @param {Function | null} [cfg.execRunner] - `run(command, io)`; null = exec is off
 * @param {object} [cfg.execOptions] - `{ timeoutMs, clientEnv }` (default `{}`)
 * @param {object | null} [cfg.pty] - normalized (see pty.mjs): `{ spawn, shell, cwd, env, term }`; null = pty is off
 * @param {object | null} [cfg.files] - a file backend (see `normalizeFileBackend` in `host-backends.mjs`); null = file access is off
 * @param {{ pubkey: boolean, password: Function | null }} [cfg.methods] - which auth methods are on (default pubkey only)
 * @param {object | null} [cfg.hostKey] - from `resolveHostKey` / `loadHostKey`
 * @param {object | null} cfg.mcp - from createMcpHost
 * @param {{ protocols: Map<string, Function>, maxMessageBytes: number, maxInflight: number } | null} cfg.rpc - from createRpcHost
 * @param {{ signKey: CryptoKey | null, hybrid?: boolean } | null} cfg.e2e - answer KeyExchange and seal virtual-mode traffic (bridged connections only)
 * @param {object | null} cfg.gateway - from normalizeGateway: TCP/DNS egress for the client (default deny)
 * @param {Record<string, Function> | undefined} cfg.extensions - handlers for application-defined (string-typed) messages
 * @param {object | null} cfg.relay - a RelayHub (see relay.mjs); null = not a relay
 * @param {object | null} cfg.sessions - a SessionRegistry (see sessions.mjs); null = sessions die with their connection
 * @param {{ limiter: object, key: Function, failureDelayMs: number } | null} cfg.rateLimit - password throttle
 * @param {number} [cfg.bindTimeoutMs=3000] - how long exec output waits for the data stream
 * @param {number} [cfg.sealTimeoutMs=30000] - with `sealSession: 'require'` (#244): how long after login the session may stay unsealed; at the deadline the
 *   connection is refused as `seal-timeout` and closed. 0 = no deadline. Nothing changes where sealing is not required.
 * @param {number} [cfg.loginTimeoutMs=60000] - #248: how long a connection may take from `attach()` to a completed login (Hello and Auth); at the deadline it is
 *   refused as `login-timeout` and closed. 0 = no deadline. A connection attached as `authenticated` has none.
 * @param {(line: string) => void} [cfg.log]
 */
export function createConnectionFactory(cfg) {
  if (!cfg || typeof cfg.authorize !== 'function') throw new TypeError('createConnectionFactory: authorize(who) is required (a host that lets everyone in is not a default)');
  cfg = {
    ...cfg,
    execOptions: cfg.execOptions ?? {},
    methods: cfg.methods ?? { pubkey: true, password: null },
    bindTimeoutMs: cfg.bindTimeoutMs ?? 3000,
    sealTimeoutMs: cfg.sealTimeoutMs ?? DEFAULT_SEAL_TIMEOUT_MS,
    loginTimeoutMs: cfg.loginTimeoutMs ?? DEFAULT_LOGIN_TIMEOUT_MS,
    log: cfg.log ?? (() => {}),
    usernamePattern: resolveUsernamePattern(cfg.usernamePattern, 'createConnectionFactory'),
  };
  validateOnRefused(cfg.onRefused, 'createConnectionFactory');
  assertSealTimeoutMs(cfg.sealTimeoutMs, 'createConnectionFactory');
  assertLoginTimeoutMs(cfg.loginTimeoutMs, 'createConnectionFactory');
  const notifyRefused = refusalNotifier(cfg.onRefused, cfg.log);
  let counter = 0;
  // What a client may put in `Open.env` (#126): an allow-list unless the host says otherwise.
  const execEnv = clientEnvFilter(cfg.execOptions?.clientEnv);
  const ptyEnv = clientEnvFilter(cfg.pty?.clientEnv);
  // Execution targets (#121): each has its own backends (and its own `clientEnv` rules). A request that names no target uses
  // the host's own, unless `requireTarget` says nothing may run on the host itself.
  /** @type {Map<string, object> | null} */
  const targetTable = cfg.targets && cfg.targets.size
    ? new Map([...cfg.targets].map(([name, spec]) => [name, { ...spec, execEnv: clientEnvFilter(spec.execOptions?.clientEnv), ptyEnv: clientEnvFilter(spec.pty?.clientEnv) }]))
    : null;
  const requireTarget = !!targetTable && !!cfg.requireTarget;
  const ownBackends = { execRunner: cfg.execRunner, execOptions: cfg.execOptions, execEnv, pty: cfg.pty, ptyEnv, files: cfg.files, ownHost: true };
  /** One answer for a target that does not exist and for one the caller may not use: the reply does not say which targets exist. */
  const NO_SUCH_TARGET = 'no such target';
  /** Every attached connection, for counting what a key holds open (`max-sessions`, #122). */
  const liveConnections = new Set();
  const targetCapabilities = (spec) =>[...(spec.execRunner ? ['exec'] : []), ...(spec.pty ? ['pty'] : []), ...(spec.files ? ['file'] : []), ...(spec.endpoints ? ['endpoint'] : [])];

  /**
   * Attach one connection. Two shapes:
   *  - bytes (the normal one): `{ send(bytes), remote, closeTransport() }` -> `{ receive(bytes), close() }`, speaking QMux.
   *  - messages: `{ sendMessage(msg), authenticated, dataStreams }` -> `{ receiveMessage(msg), bindStream(s), close() }`,
   *    for a transport that already frames messages itself (a relay bridge, WebTransport). `authenticated`
   *    (`{ username, fingerprint, grant? }`; `grant` is a `grantPermissions().permissions` object narrowing what the peer may do) skips the handshake for a peer something else has already authenticated;
   *    `dataStreams: false` means there are no client-opened streams to bind, so exec output rides SessionData.
   *    `e2e` overrides `cfg.e2e` for this connection.
   *
   * `waitForPeer: true` (#253) says the far side is not there yet (the half a page dialled to a pipe relay, before any operator has): the login clock
   * (`loginTimeoutMs`) does not start at `attach()` but at the first byte or message the far side sends, or at `startLoginClock()` (a pairing signal), whichever
   * comes first. Default `false`: the connection is the far side arriving, so the clock starts now. No effect on an `authenticated` connection.
   */
  return function attach({ send: sendBytes, sendMessage = null, remote = {}, authenticated = null, dataStreams = true, closeTransport = null, e2e: e2eOverride, channelBinding = null, datagrams = null, sealSession: sealOverride, waitForPeer = false }) {
    const cid = ++counter;
    const log = (m) => cfg.log(`[conn ${cid}] ${m}`);
    const state = {
      sessionId: randomUUID(), nonce: null, username: authenticated?.username ?? null, authed: !!authenticated,
      closed: false, nextChannel: 0, fingerprint: authenticated?.fingerprint ?? null,
      /** What `authorize()` granted, when it returned a capability set instead of `true` (#122). */
      grant: authenticated?.grant ?? null,
    };
    /** @type {Map<number, any>} */
    const channels = new Map();
    const live = { channels, fingerprint: () => state.fingerprint };
    liveConnections.add(live);

    // ── What the key's authorized_keys options allow (#122) ──────────
    // Looked up per request from the key this connection authenticated as (a bridged peer included); `null` = no options.
    const keyPermissions = () => (state.fingerprint ? cfg.authorize.permissionsFor?.(state.fingerprint) ?? null : null);
    /** pty/exec sessions this key holds open on this host: live unhosted channels of every connection, and hosted sessions. */
    function activeSessionsFor(fingerprint) {
      let n = 0;
      for (const c of liveConnections) {
        if (c.fingerprint() !== fingerprint) continue;
        for (const ch of c.channels.values()) if (ch.keyed) n++;
      }
      if (cfg.sessions) n += cfg.sessions.listFor(fingerprint).filter((s) => s.state !== 'exited').length;
      return n;
    }
    /** What this connection may do: its key's options, and what `authorize()` granted (#122, step two); each narrows the other. */
    const permissionSets = () => [keyPermissions(), state.grant].filter(Boolean);
    /** First refusal of `req` by any of the sets, or null; `silent` skips the log and `onRefused` (discovery filters). */
    function refusalOf(req, silent) {
      for (const perms of permissionSets()) {
        const counts = req.kind === 'open' && (req.channel === 'pty' || req.channel === 'exec') && perms.maxSessions !== null;
        const refusal = checkKeyRequest(perms, req, { activeSessions: counts ? activeSessionsFor(state.fingerprint) : 0 });
        if (!refusal) continue;
        if (!silent) {
          const what = `${req.kind}${req.channel ? ` ${req.channel}` : ''}${req.protocol ? ` ${req.protocol}` : ''}`;
          log(`key permissions refused ${what} for ${state.username ?? '?'} (${refusal.code}${refusal.capability ? `: ${refusal.capability}` : ''})`);
          // #122: the embedder hears of it with a stable reason (`not-permitted`; `key-expired` for a key past its `expires`).
          notifyRefused(refusal.code === 'key-expired' ? 'key-expired' : 'not-permitted', { username: state.username, fingerprint: state.fingerprint, address: remote.address }, `${refusal.code}: ${refusal.reason} (${what})`);
        }
        return refusal;
      }
      return null;
    }
    /**
     * `null` when the key's options and capabilities allow this request, else `{ code, reason, capability? }` (logged, and
     * reported through `onRefused`). Requests are described in `checkKeyRequest`.
     * @param {object} req
     */
    const keyRefusal = (req) => refusalOf(req, false);
    /** Whether this request would be allowed, without saying anything about it (what a discovery answer lists). */
    const keyAllows = (req) => refusalOf(req, true) === null;
    /**
     * What an rpc handler is told of the key it serves (additive): the capability list of the key (`null` for a key with none), and
     * `permits(request, { now })`, whether the key's options and capabilities allow a request such as `{ kind: 'mcp-tool', tool }`,
     * asked afresh each time (an expiry is honoured), without a refusal being reported. `permits` is the authority; the list is for display.
     */
    const keyCapabilities = () => { for (const p of permissionSets()) if (Array.isArray(p.capabilities)) return p.capabilities.slice(); return null; };
    const permits = (req, { now } = {}) => permissionSets().every((perms) => !checkKeyRequest(perms, req, { now }));
    /** The reply that refuses a gateway message the key's capabilities do not cover (`GatewayFail` / `ListenFail`), or null. */
    function gatewayRefusal(m) {
      let req; let listener = false;
      switch (m.type) {
        case MSG.OPEN_TCP: req = { kind: 'tcp', host: m.host, port: m.port }; break;
        case MSG.OPEN_UDP: req = { kind: 'udp', host: m.host, port: m.port }; break;
        case MSG.RESOLVE_DNS: req = { kind: 'dns', name: m.name }; break;
        case MSG.OPEN_UNIX: req = { kind: 'unix', path: m.path }; break;
        case MSG.OPEN_ENDPOINT: req = { kind: 'endpoint', name: m.name, target: m.target ?? undefined }; break;
        case MSG.LISTEN_REQUEST: req = { kind: 'listen-tcp', port: m.port }; listener = true; break;
        case MSG.LISTEN_UNIX: req = { kind: 'listen-unix', path: m.path }; listener = true; break;
        default: return null;
      }
      // A reverse host's gateway (#289) is used only by an operator that was GRANTED a capability list covering the request
      // (`accept()` returned `{ capabilities }`): the host's own `gateway` policy decides what is reachable, the grant who may ask.
      const refusal = cfg.gatewayNeedsGrant && !Array.isArray(state.grant?.capabilities)
        ? (() => {
          const reason = 'this host serves its gateway only to an operator it granted a gateway capability (accept() returned none)';
          log(`gateway refused for ${state.username ?? '?'}: no capability granted`);
          notifyRefused('not-permitted', { username: state.username, fingerprint: state.fingerprint, address: remote.address }, `capability-missing: ${reason}`);
          return { reason };
        })()
        : keyRefusal(req);
      if (!refusal) return null;
      return listener ? listenFail({ listenerId: m.listener_id, reason: refusal.reason }) : gatewayFail({ gatewayId: m.gateway_id, code: GATEWAY_FAIL.POLICY_DENIED, message: refusal.reason });
    }
    /** FileOp `write`/`rename`s awaiting their FileChunk frames, by client-chosen channel id. */
    const fileWrites = new Map();
    /** AbortControllers of in-flight MCP calls: aborted on disconnect, counted for the cap. */
    const mcpCalls = new Set();
    /** call_id -> AbortController, for McpCancel. */
    const mcpById = new Map();
    /** Channel ids awaiting their client-opened data stream, in OpenOk order. */
    const pendingStreams = [];
    const decoder = new FrameDecoder();
    const pendingSends = [];
    let control = null;
    let chain = Promise.resolve();
    /** This connection as the relay hub sees it (created on first need). */
    let relayHandle = null;
    /** Ends the connection at `connectionTtlMs` after authentication (#125). */
    let ttlTimer = null;
    /** Ends a connection that must seal and has not, `sealTimeoutMs` after login (#244). */
    let sealTimer = null;
    /** Ends a connection that has not completed its login `loginTimeoutMs` after it was attached (#248). */
    let loginTimer = null;
    /** Set when the login deadline has passed: nothing the peer sends after that is handled, and a login still in flight does not complete. */
    let loginExpired = false;

    // A sealed session (#155): after login, a signed KeyExchange for this connection's session id seals everything
    // that follows (control messages, gateway and endpoint data included) as EncryptedFrames on channel 0.
    // `sealSession: 'require'` in the options of this connection may only STRENGTHEN the host's setting (a transport that cannot vouch for itself,
    // a duplex someone else carries, asks for it); a host that cannot seal (no host key, or client-opened data streams) then cannot serve it at all.
    if (sealOverride !== undefined && sealOverride !== 'require') throw new TypeError("attach: sealSession can only be 'require' for one connection");
    if (sealOverride === 'require' && (!cfg.hostKey || dataStreams)) throw new Error('this connection must be sealed, and this host cannot seal it (it needs a host key and dataStreams: false)');
    const sealMode = sealOverride === 'require' ? 'require' : cfg.sealSession;
    const sealOn = !!sealMode && !!cfg.hostKey && !dataStreams;
    const sealRequired = sealOn && sealMode === 'require';
    /** @type {{ bridge: SealedBridge | null, responder: E2EResponder | null }} */
    const sealed = { bridge: null, responder: null };
    // A peer something else already authenticated (`authenticated`) has no login here to count from: its deadline runs from attach.
    // A connection whose far side is not there yet (`waitForPeer`, #253) starts the login clock when it is (`startLoginClock`).
    if (authenticated) armSealDeadline();
    else if (!waitForPeer) armLoginDeadline();

    // The gateway needs Node sockets, so `gateway.mjs` is not imported here (a browser host must not pull it in):
    // the embedder that has them (`createWshServer`) passes `cfg.createGatewaySession` along with `cfg.gateway`; a
    // host in a page passes the endpoints-only session of `gateway-core.mjs` (`createMemoryHost({ endpoints })`).
    if (cfg.gateway && typeof cfg.createGatewaySession !== 'function') throw new TypeError('createConnectionFactory: gateway needs createGatewaySession (only @johnhenry/wsh/server provides one)');
    const gateway = cfg.gateway
      ? cfg.createGatewaySession(cfg.gateway, (m) => send(m), log, {
        who: () => ({ username: state.username, fingerprint: state.fingerprint }),
        datagrams,
        // #121: a named target's own endpoints, once `authorize` has let the caller onto it
        target: async (name) => { const r = await resolveTarget(name, 'endpoint'); return r.refuse ? { refuse: r.refuse } : { endpoints: r.b.endpoints ?? null }; },
        requireTarget: () => requireTarget,
      })
      : null;
    // A reverse host's gateway (#289): connections opened through a relay bridge are always metered (`relay-gateway` implies `gateway-credit`),
    // whatever the operator listed: there is no Hello on a bridge to read it from.
    if (gateway && cfg.gatewayCredit && authenticated) gateway.setPeerFeatures([GATEWAY_CREDIT_FEATURE]);

    // Operator-side shared folders (#159): created with the connection, used only after the client's ShareOffer.
    const shares = cfg.onShare
      ? createShareSession({ send: (m) => send(m), onShare: cfg.onShare, who: () => ({ username: state.username, fingerprint: state.fingerprint }), log, timeoutMs: cfg.shareTimeoutMs })
      : null;

    const qmux = sendMessage ? null : new QMuxConnection({ isClient: false, send: (b) => { if (!state.closed) sendBytes(b); } });

    // ── End-to-end encryption (#90) ──────────────────────────────────
    // An operator that sent KeyExchange for one of this connection's sessions gets that session's output sealed
    // into EncryptedFrames and its input opened from them; plaintext input for it is ignored from then on (a relay
    // must not be able to inject stdin around the encryption).
    /** channel id -> the session id its OpenOk named (the AAD of its frames). */
    const sessionOfChannel = new Map();
    /** session id -> { key, sendCounter, recvCounter } for sessions with E2E on. */
    const e2eSessions = new Map();
    const MAX_E2E_SESSIONS = 64;
    const e2eConfig = e2eOverride === undefined ? cfg.e2e : e2eOverride;
    const responder = e2eConfig && !dataStreams ? new E2EResponder({ signKey: e2eConfig.signKey ?? null, hybrid: e2eConfig.hybrid !== false }) : null;
    /** Outgoing messages in order, once E2E is on (sealing is async; order on the wire must not change). */
    let outChain = Promise.resolve();
    const e2eFor = (channelId) => e2eSessions.get(sessionOfChannel.get(channelId));

    const send = (msg) => {
      if (state.closed) return Promise.resolve();
      if (msg.type === MSG.OPEN_OK && typeof msg.session_id === 'string') sessionOfChannel.set(msg.channel_id, msg.session_id);
      if (e2eSessions.size === 0) return deliver(msg);
      // E2E is on for something: everything goes through one chain, so a sealed frame cannot be overtaken
      // by (or overtake) the Exit that follows it.
      const done = outChain.then(async () => {
        const st = msg.type === MSG.SESSION_DATA ? e2eFor(msg.channel_id) : undefined;
        if (!st) return deliver(msg);
        const sessionId = sessionOfChannel.get(msg.channel_id);
        const { nonce, ciphertext } = await sealFrame(st.key, sessionId, ROLE_TAGS.responder, st.sendCounter++, msg.data);
        return deliver(encryptedFrameMsg({ channelId: msg.channel_id, nonce, ciphertext, sessionId }));
      });
      outChain = done.catch(() => {});
      return done.catch(() => {});
    };

    const deliver = (msg) => {
      // Sealed: everything but the keepalive leaves as a frame, in the order it was sent (the bridge seals in call order).
      if (sealed.bridge && msg.type !== MSG.PING && msg.type !== MSG.PONG) {
        return sealed.bridge.seal(msg).then((frame) => deliverRaw(frame), (e) => { log(`could not seal: ${e.message}`); });
      }
      return deliverRaw(msg);
    };

    const deliverRaw = (msg) => {
      if (state.closed) return Promise.resolve();
      if (sendMessage) {
        try { return Promise.resolve(sendMessage(msg)).catch(() => {}); } catch { return Promise.resolve(); }
      }
      const bytes = frameEncode(msg);
      if (control) return control.write(bytes).catch(() => {});
      pendingSends.push(bytes);
      return Promise.resolve();
    };

    /**
     * The last message before the host drops a connection (a refusal, a deadline) is a best effort (#256): a peer that granted no flow-control
     * credit, stopped reading, or whose transport never drains makes that write wait without end, and the close after it would never run.
     * This waits for the write for at most `FINAL_MESSAGE_DRAIN_MS`; the caller then closes whether or not it went.
     */
    function boundedFinal(sent) {
      let timer;
      return Promise.race([Promise.resolve(sent).catch(() => {}), new Promise((r) => { timer = setTimeout(r, FINAL_MESSAGE_DRAIN_MS); })]).finally(() => clearTimeout(timer));
    }

    function shutdown(why) {
      if (state.closed) return;
      state.closed = true;
      liveConnections.delete(live);
      clearTimeout(ttlTimer);
      clearTimeout(sealTimer);
      clearTimeout(loginTimer);
      // A hosted session survives its connection (it is detached, then expires or is resumed);
      // everything else dies with it.
      for (const ch of [...channels.values()]) (ch.detach ?? ch.kill)?.call(ch);
      channels.clear();
      responder?.close();
      gateway?.close();
      shares?.close();
      e2eSessions.clear();
      for (const c of mcpCalls) c.abort(new Error('connection closed'));
      mcpCalls.clear();
      mcpById.clear();
      for (const w of fileWrites.values()) clearTimeout(w.timer);
      fileWrites.clear();
      try { qmux?.destroy(new Error(why)); } catch { /* already gone */ }
      // The host ending the connection (a relay bridge ending, a refused login) must end the socket too.
      try { closeTransport?.(); } catch { /* already gone */ }
      relayHandle && cfg.relay?.drop(relayHandle);
      log(`closed (${why})`);
    }

    // A transport that closes right behind a message (a client's `disconnect()` sends Close for
    // every channel and then goes) must not make the host forget that message: it is processed
    // first, then the connection is torn down.
    const shutdownAfterQueue = (why) => { chain = chain.then(() => shutdown(why)); };

    if (qmux) {
    qmux.onError = (e) => log(`qmux error: ${e.message}`);
    qmux.onClose = () => shutdownAfterQueue('peer sent CONNECTION_CLOSE');
    qmux.onStreamOpen = (s) => {
      if (s.id !== 0) { bindDataStream(s); return; }
      control = s;
      s.onData = (d) => {
        let msgs;
        try { msgs = decoder.feed(d); } catch (e) { log(`frame decode error: ${e.message}`); return; }
        for (const m of msgs) chain = chain.then(() => handle(m)).catch((e) => log(`handler error: ${e.message}`));
      };
      s.onEnd = () => shutdownAfterQueue('control stream FIN');
      s.onReset = () => shutdownAfterQueue('control stream reset');
      for (const b of pendingSends.splice(0)) s.write(b).catch(() => {});
    };
    qmux.sendHandshake();
    }

    function bindDataStream(s) {
      const channelId = pendingStreams.shift();
      const ch = channelId !== undefined ? channels.get(channelId) : undefined;
      if (!ch?.bind) { s.close().catch(() => {}); return; }
      ch.bind(s);
    }

    // ── Auth ──────────────────────────────────────────────────────────

    async function handle(m) {
      if (state.closed || loginExpired) return;
      if (!state.authed) return handleAuth(m);
      if (sealOn) {
        const inner = await sealedInput(m);
        if (inner === undefined) return;
        m = inner;
      }
      if (await handleRelay(m)) return;
      // Credit for a virtual-mode rpc channel (#191) is a GatewayCredit in a number space of its own; it is never the gateway's.
      if (m.type === MSG.GATEWAY_CREDIT && rpcChannelOfCredit(m.gateway_id) !== undefined) {
        channels.get(rpcChannelOfCredit(m.gateway_id))?.credit?.(m.bytes);
        return;
      }
      if (gateway) {
        // What the key's capabilities allow of the gateway (#122), before the gateway's own policy is asked.
        const refusal = gatewayRefusal(m);
        if (refusal) return send(refusal);
        if (await gateway.handle(m)) return;
      }
      if (shares && shares.handle(m)) return;
      switch (m.type) {
        case MSG.PING: return send(pong({ id: m.id }));
        case MSG.OPEN: return handleOpen(m);
        case MSG.SESSION_DATA:
          if (e2eFor(m.channel_id)) { log(`ignored plaintext SessionData on E2E channel ${m.channel_id}`); return; }
          channels.get(m.channel_id)?.input?.(m.data);
          return;
        case MSG.KEY_EXCHANGE: return handleKeyExchange(m);
        case MSG.ENCRYPTED_FRAME: return handleEncryptedFrame(m);
        case MSG.RESIZE: channels.get(m.channel_id)?.resize?.(m.cols, m.rows); return;
        case MSG.SIGNAL: channels.get(m.channel_id)?.signal?.(String(m.signal ?? '')); return;
        case MSG.CLOSE: { const ch = channels.get(m.channel_id); if (ch) { ch.kill?.(); } return; }
        case MSG.FILE_OP: return handleFileOp(m);
        case MSG.FILE_CHUNK: return (fileWrites.has(m.channel_id) ? handleWriteChunk(m) : channels.get(m.channel_id)?.chunk?.(m));
        case MSG.ATTACH: return handleAttach(m, false);
        case MSG.RESUME: return handleAttach(m, true);
        case MSG.DETACH: return handleDetach(m);
        case MSG.SESSION_LIST_REQUEST: return handleSessionList();
        case MSG.LIST_TARGETS: return handleListTargets();
        case MSG.MCP_DISCOVER: return handleMcpDiscover();
        // Not awaited: the handler chain is serial, and a slow tool must not hold up
        // the next call (or a Close) behind it.
        case MSG.MCP_CALL: handleMcpCall(m); return;
        case MSG.MCP_CANCEL: if (typeof m.call_id === 'string') mcpById.get(m.call_id)?.abort(new Error('cancelled by the caller')); return;
        default:
          if (typeof m.type === 'string' && Object.hasOwn(cfg.extensions ?? {}, m.type) && typeof cfg.extensions[m.type] === 'function') {
            try { await cfg.extensions[m.type](m, { username: state.username, fingerprint: state.fingerprint, send }); } catch (e) { log(`extension "${m.type}" threw: ${e.message}`); }
            return;
          }
          log(`ignored message type ${typeof m.type === 'number' ? `0x${m.type.toString(16)}` : JSON.stringify(String(m.type)).slice(0, 80)}`);
      }
    }

    async function handleKeyExchange(m) {
      if (!responder) { log('ignored KeyExchange (end-to-end encryption is not enabled here)'); return; }
      // Only for a session this connection actually has: the id is the AAD of every frame, and it bounds the state kept.
      const known = typeof m.session_id === 'string' && [...sessionOfChannel.values()].includes(m.session_id);
      if (!known) { log('ignored KeyExchange for a session this connection does not have'); return; }
      if (!e2eSessions.has(m.session_id) && e2eSessions.size >= MAX_E2E_SESSIONS) { log('ignored KeyExchange (too many encrypted sessions)'); return; }
      let result;
      try { result = await responder.respond(m, send); } catch (e) { log(`KeyExchange refused: ${e.message}`); return; }
      // Sealing starts after the reply is on its way, so the operator never gets a frame before it has the key.
      if (result.key) {
        e2eSessions.set(result.sessionId, { key: result.key, sendCounter: 0, recvCounter: 0 });
        log(`end-to-end encryption on for session ${result.sessionId.slice(0, 8)}${result.hybrid ? ' (hybrid)' : ''}`);
      }
    }

    async function handleEncryptedFrame(m) {
      const st = e2eSessions.get(m.session_id);
      // The frame must name the session its channel belongs to, or it could be spliced onto another channel.
      if (!st || sessionOfChannel.get(m.channel_id) !== m.session_id) { log('dropped an EncryptedFrame for a session without E2E'); return; }
      let plain;
      try {
        plain = await openFrame(st.key, m.session_id, st.recvCounter, { nonce: m.nonce, ciphertext: m.ciphertext, expectedRoleTag: ROLE_TAGS.initiator });
      } catch (e) {
        // Garbage (a replay, a tampered or foreign frame) neither reaches the process nor consumes a counter.
        log(`dropped an EncryptedFrame: ${e.message}`);
        return;
      }
      st.recvCounter += 1;
      channels.get(m.channel_id)?.input?.(plain);
    }

    /**
     * `AuthOk` (#125). `ttl` is the lifetime this host enforces on the connection, in seconds (0 = unlimited, the
     * default); `token` is an opaque per-connection value that carries no authority -- the spec requires the field
     * and released peers parse it, but nothing on this host accepts it back.
     */
    async function grantAuth() {
      clearTimeout(loginTimer);
      armSealDeadline();
      const ttlMs = cfg.connectionTtlMs ?? 0;
      if (ttlMs > 0) {
        ttlTimer = setTimeout(() => { log('connection ttl reached'); shutdownAfterQueue('connection ttl reached'); }, ttlMs);
        ttlTimer.unref?.();
      }
      await send(authOk({ sessionId: state.sessionId, token: randomBytes(16), ttl: Math.ceil(ttlMs / 1000) }));
    }

    /** Tell the embedder (`onRefused`, #163) once per connection that this peer was turned away. */
    let refusalReported = false;
    function reportRefused(code, detail, extra = {}) {
      if (refusalReported) return;
      refusalReported = true;
      notifyRefused(code, { username: state.username, fingerprint: state.fingerprint, address: remote.address, ...extra }, detail);
    }

    /**
     * With `sealSession: 'require'` the key exchange follows the login and nothing is served before it; this bounds how long it may
     * take (#244). At the deadline the peer is told why (an `Error`, as for a plain message), the embedder hears `seal-timeout`, and
     * the connection ends. A sealed session, a closed connection, `sealTimeoutMs: 0` and a host that does not require sealing never reach it.
     */
    function armSealDeadline() {
      if (!sealRequired || !(cfg.sealTimeoutMs > 0) || sealTimer) return;
      sealTimer = setTimeout(async () => {
        if (state.closed || sealed.bridge) return;
        log('sealed session not established in time');
        reportRefused('seal-timeout', `the session was not sealed within ${cfg.sealTimeoutMs} ms of login`);
        await boundedFinal(deliverRaw(errorMsg({ code: 1, message: 'the sealed session was not established in time (seal-timeout)' })));
        setTimeout(() => { if (!sealed.bridge) shutdown('sealed session not established in time'); }, FINAL_MESSAGE_DRAIN_MS);
      }, cfg.sealTimeoutMs);
      sealTimer.unref?.();
    }

    /**
     * Bounds the time from the connection being attached to a completed login (Hello and Auth) (#248): a peer that connects and never
     * logs in, or stops half way, otherwise holds the connection (and, on a relay, its pipe) for as long as it likes. At the deadline the
     * peer is told why (an `AuthFail`, as for any refused login), the embedder hears `login-timeout`, and the connection ends. A connection
     * that completed its login, a closed one and `loginTimeoutMs: 0` never reach it.
     */
    function armLoginDeadline() {
      if (!(cfg.loginTimeoutMs > 0) || loginTimer || state.closed || state.authed) return;
      loginTimer = setTimeout(async () => {
        if (state.closed || state.authed) return;
        loginExpired = true;
        log('login not completed in time');
        reportRefused('login-timeout', `the login was not completed within ${cfg.loginTimeoutMs} ms of the connection`);
        await boundedFinal(deliverRaw(authFail({ reason: 'the login was not completed in time (login-timeout)' })));
        setTimeout(() => shutdown('login not completed in time'), FINAL_MESSAGE_DRAIN_MS);
      }, cfg.loginTimeoutMs);
      loginTimer.unref?.();
    }

    async function refuse(reason, code = 'bad-request', who) {
      log(`AUTH_FAIL: ${reason}`);
      reportRefused(code, reason, who);
      await boundedFinal(send(authFail({ reason })));
      setTimeout(() => shutdown('auth failed'), FINAL_MESSAGE_DRAIN_MS);
    }

    async function handleAuth(m) {
      if (m.type === MSG.HELLO) {
        const user = String(m.username ?? '');
        if (!usernameAllowed(cfg.usernamePattern, user)) return refuse(`bad username ${JSON.stringify(user)}`);
        const method = m.auth_method || 'pubkey';
        if (method === 'password') {
          if (!cfg.methods.password) return refuse('password auth is not enabled on this host', 'method-disabled', { username: user });
        } else if (method === 'pubkey') {
          if (!cfg.methods.pubkey) return refuse('pubkey auth is not enabled on this host', 'method-disabled', { username: user });
        } else {
          return refuse(`unsupported auth method ${JSON.stringify(method)}`, 'bad-request', { username: user });
        }
        if (sealRequired && method !== 'pubkey') return refuse('this host requires a sealed session, which needs a key login', 'not-sealed', { username: user });
        state.username = user;
        state.method = method;
        gateway?.setPeerFeatures(m.features);
        const features = hostFeatures(sealMode === cfg.sealSession ? cfg : { ...cfg, sealSession: sealMode }, { dataStreams });
        // UDP over datagrams only where this transport has them and the gateway serves (and allows) UDP.
        if (datagrams && cfg.gateway?.tcp && cfg.gateway.udpOn !== false && cfg.gateway.udp?.datagrams) features.push(GATEWAY_DATAGRAM_FEATURE);
        let hostFingerprint;
        if (cfg.hostKey) {
          hostFingerprint = cfg.hostKey.fingerprint;
          const clientNonce = findClientNonce(m.features);
          if (clientNonce) {
            const sig = await cfg.hostKey.sign(hostKeyProofMessage({ sessionId: state.sessionId, clientNonce, username: user }));
            features.push(HOST_KEY_PREFIX + toHex(cfg.hostKey.publicKey), HOST_KEY_SIG_PREFIX + toHex(sig));
          }
        }
        // Channel binding (#119): what this host can tie the client's signature to on this connection.
        if (method === 'pubkey') {
          state.bindingHeld = { ...(channelBinding ?? {}) };
          if (cfg.hostKey) state.bindingHeld.host = [cfg.hostKey.publicKey];
          const kinds = Object.keys(state.bindingHeld).filter((k) => state.bindingHeld[k]?.length);
          features.push(...bindingFeatures(kinds, { required: !!cfg.requireChannelBinding }));
        }
        state.features = features;
        state.hostFingerprint = hostFingerprint ?? null;
        await send(serverHello({ sessionId: state.sessionId, features, hostFingerprint }));
        if (method === 'pubkey') {
          state.nonce = generateNonce();
          await send(challenge({ nonce: state.nonce, sessionId: state.sessionId }));
        } else {
          state.awaitingPassword = true;
        }
        return;
      }
      if (m.type === MSG.AUTH && state.awaitingPassword) return handlePasswordAuth(m);
      if (m.type === MSG.AUTH) {
        if (!state.nonce) return;
        if (m.method !== 'pubkey' || !(m.public_key instanceof Uint8Array) || !(m.signature instanceof Uint8Array)) {
          return refuse('expected a pubkey AUTH with public_key and signature');
        }
        let fp;
        let key;
        try {
          fp = await fingerprint(m.public_key);
          key = await importPublicKeyRaw(m.public_key);
        } catch { return refuse('malformed public key'); }
        const claimed = { fingerprint: fp };
        // Verify the signature first: nothing about who is on the allowlist
        // is revealed to a caller who cannot even prove they hold a key.
        // The signature may be over the empty binding (a client that knows nothing of #119, or a browser that can
        // bind nothing) or over any combination of the kinds this host offered; a host that requires a binding
        // accepts only the latter.
        const required = cfg.requireChannelBinding ?? false;
        const acceptable = await acceptableBindings(state.bindingHeld ?? {}, { required });
        let ok = false;
        let boundKinds = [];
        try {
          for (const cand of acceptable) {
            if (await verifyChallenge(key, m.signature, state.sessionId, state.nonce, { username: state.username, channelBinding: cand.binding })) { ok = true; boundKinds = cand.kinds; break; }
          }
        } catch { ok = false; }
        if (!ok) {
          if (required) {
            let unbound = false;
            try { unbound = await verifyChallenge(key, m.signature, state.sessionId, state.nonce, { username: state.username }); } catch { /* not that either */ }
            if (unbound) return refuse('channel binding required: the signature is not bound to this connection', 'binding-required', claimed);
          }
          return refuse('signature does not verify over the transcript', 'bad-signature', claimed);
        }
        state.channelBinding = boundKinds;
        let allowed = false;
        try {
          // `sealRequired`: this host serves nothing until the session is sealed (after login), so a login here is not yet a session
          // that can do anything; `cfg.onSealed` says when it is.
          allowed = await cfg.authorize({ username: state.username, fingerprint: fp, publicKey: m.public_key, ...(sealRequired ? { sealRequired: true } : {}) });
        } catch (e) { log(`authorize threw: ${e.message}`); }
        if (!allowed) return refuse('key not authorized', 'unauthorized', claimed);
        // `authorize` may answer with a capability set (`{ permissions }` from `buildAuthorizer`): it narrows what the key's own options allow.
        const grant = typeof allowed === 'object' ? allowed.permissions ?? null : null;
        // A key past its `expires` does not log in (#122).
        for (const perms of [cfg.authorize.permissionsFor?.(fp) ?? null, grant]) {
          if (perms && checkKeyRequest(perms, { kind: 'login' })) return refuse('key has expired', 'key-expired', claimed);
        }
        if (loginExpired) return; // the deadline passed while `authorize` was thinking: the peer has been told
        state.grant = grant;
        state.authed = true;
        state.fingerprint = fp;
        state.publicKey = m.public_key;
        state.nonce = null;
        await grantAuth();
        log(`authenticated ${state.username} (${fp.slice(0, 12)}...)`);
      }
    }

    /**
     * The sealed-session gate (#155) for a message from an authenticated peer: the message to handle, or undefined
     * when it was consumed (the key exchange) or refused. A plain message is not heard once the session is sealed
     * (a relay in the middle can inject any), and with `sealSession: 'require'` not before either.
     */
    async function sealedInput(m) {
      if (sealed.bridge) {
        if (m.type === MSG.PING) return m;
        if (!sealed.bridge.isFrame(m)) { log(`dropped a plaintext message (type ${m.type}) on a sealed session`); return undefined; }
        try { return await sealed.bridge.open(m); } catch (e) {
          log(`a sealed frame did not open (${e.message}): closing the session`);
          reportRefused('seal-failed', `a sealed frame did not open: ${e.message}`);
          shutdown('sealed frame did not open');
          return undefined;
        }
      }
      if (m.type === MSG.KEY_EXCHANGE && m.session_id === state.sessionId) {
        if (!state.publicKey) { log('sealed session refused: no login key to authenticate the initiator with'); reportRefused('seal-failed', 'no login key to authenticate the initiator with'); shutdown('sealed session needs a key login'); return undefined; }
        sealed.responder ??= new E2EResponder({
          signKey: cfg.hostKey, hybrid: true, identity: cfg.hostKey.publicKey,
          initiator: { publicKey: state.publicKey, require: true },
        });
        try {
          const result = await sealed.responder.respond(m, (reply) => deliverRaw(reply));
          if (result.key) {
            sealed.bridge = new SealedBridge({ key: result.key, sessionId: state.sessionId, role: 'responder', scope: 'session' });
            clearTimeout(sealTimer);
            log(`session sealed${result.hybrid ? ' (hybrid)' : ''}`);
            try { cfg.onSealed?.({ username: state.username, fingerprint: state.fingerprint }); } catch (e) { log(`onSealed threw: ${e.message}`); }
          }
        } catch (e) { log(`sealed session refused: ${e.message}`); reportRefused('seal-failed', `key exchange failed: ${e.message}`); shutdown('sealed session key exchange failed'); }
        return undefined;
      }
      if (m.type === MSG.PING) return m;
      if (sealRequired) {
        log(`refused a plaintext message (type ${m.type}): this host requires a sealed session`);
        reportRefused('not-sealed', `a plaintext message (type ${m.type}) on a host that requires a sealed session`);
        await boundedFinal(deliverRaw(errorMsg({ code: 1, message: 'this host requires a sealed session (e2e-session-required)' })));
        setTimeout(() => shutdown('sealed session required'), FINAL_MESSAGE_DRAIN_MS);
        return undefined;
      }
      return m;
    }

    async function handlePasswordAuth(m) {
      state.awaitingPassword = false; // one guess per connection
      if (m.method !== 'password' || typeof m.password !== 'string') return refuse('expected a password AUTH', 'bad-request');
      const rl = cfg.rateLimit;
      const key = rl.key({ address: remote.address, headers: remote.headers, username: state.username });
      const locked = rl.limiter.lockedFor(key);
      if (locked > 0) {
        // Not even evaluated: a locked-out caller learns nothing and costs nothing.
        return refuse(`too many failed attempts; try again in ${Math.ceil(locked / 1000)}s`, 'rate-limited');
      }
      let ok = false;
      try { ok = (await cfg.methods.password(state.username, m.password)) === true; } catch (e) { log(`password check threw: ${e.message}`); }
      if (!ok) {
        rl.limiter.fail(key);
        if (rl.failureDelayMs > 0) await new Promise((r) => setTimeout(r, rl.failureDelayMs));
        return refuse('authentication failed', 'unauthorized');
      }
      rl.limiter.succeed(key);
      if (loginExpired) return;
      state.authed = true;
      await grantAuth();
      log(`authenticated ${state.username} (password)`);
    }

    // ── Relay (createWshServer({ relay })) ────────────────────────────

    const RELAY_TYPES = new Set([MSG.REVERSE_REGISTER, MSG.REVERSE_LIST, MSG.REVERSE_CONNECT, MSG.REVERSE_ACCEPT, MSG.REVERSE_REJECT, MSG.RELAY_FORWARD, MSG.REVERSE_CHALLENGE, MSG.REVERSE_PROOF]);

    function hubHandle() {
      relayHandle ??= {
        send, fingerprint: state.fingerprint, username: state.username,
        close: () => shutdownAfterQueue('relay bridge ended'),
      };
      return relayHandle;
    }

    /** @returns {Promise<boolean>} true when the message was the relay's and has been dealt with */
    async function handleRelay(m) {
      const hub = cfg.relay;
      if (!hub) {
        // Not a relay: answer instead of leaving the client to time out.
        if (m.type === MSG.REVERSE_LIST) { await send(reversePeers({ peers: [] })); return true; }
        if (m.type === MSG.REVERSE_CONNECT) { await send(reverseReject({ targetFingerprint: String(m.target_fingerprint ?? ''), username: '', reason: 'relay is not enabled on this server' })); return true; }
        if (m.type === MSG.REVERSE_REGISTER) { await send(errorMsg({ code: 3, message: 'relay is not enabled on this server' })); return true; }
        return false;
      }
      if (!RELAY_TYPES.has(m.type)) {
        // Anything else a bridged connection sends that may cross a bridge, does.
        if (!relayHandle) return false;
        hub.touch(relayHandle);
        return hub.forward(relayHandle, m);
      }
      // Relay roles are keyed by an authenticated key: from_fingerprint means nothing for a password login.
      if (!state.fingerprint) {
        await send(errorMsg({ code: 2, message: 'relay operations need a key login' }));
        return true;
      }
      // The entry points to the relay (#122): a key without `permit-relay` cannot register, list or connect.
      if (m.type === MSG.REVERSE_REGISTER || m.type === MSG.REVERSE_LIST || m.type === MSG.REVERSE_CONNECT) {
        const refusal = keyRefusal({ kind: 'relay' });
        if (refusal) {
          if (m.type === MSG.REVERSE_CONNECT) await send(reverseReject({ targetFingerprint: String(m.target_fingerprint ?? ''), username: '', reason: refusal.reason }));
          else await send(errorMsg({ code: 2, message: refusal.reason }));
          return true;
        }
      }
      const h = hubHandle();
      switch (m.type) {
        case MSG.REVERSE_REGISTER: {
          const reason = await hub.register(h, m, { username: state.username, fingerprint: state.fingerprint });
          if (reason) {
            log(`ReverseRegister refused: ${reason}`);
            await send(errorMsg({ code: 2, message: `registration refused: ${reason}` }));
          }
          return true;
        }
        case MSG.REVERSE_LIST: await send(await hub.list({ username: state.username, fingerprint: state.fingerprint })); return true;
        case MSG.REVERSE_CONNECT: await hub.connect(h, m); return true;
        case MSG.REVERSE_ACCEPT: case MSG.REVERSE_REJECT: hub.answer(h, m); return true;
        case MSG.REVERSE_CHALLENGE: hub.challenge(h, m); return true;
        case MSG.REVERSE_PROOF: hub.proof(h, m); return true;
        default: hub.forward(h, m); return true; // a RelayForward the client wrote itself
      }
    }

    // ── MCP ───────────────────────────────────────────────────────────

    const principal = () => ({ username: state.username, fingerprint: state.fingerprint });

    async function handleMcpDiscover() {
      let tools = [];
      // A key without MCP (#122) sees no tools, as it would on a host that has none.
      if (cfg.mcp && keyAllows({ kind: 'mcp' })) {
        try { tools = await cfg.mcp.list(state.username, principal()); } catch (e) { log(`mcp discover failed: ${e.message}`); }
        // A key with `mcp:<tool>` capabilities is told only of those tools.
        tools = tools.filter((t) => keyAllows({ kind: 'mcp-tool', tool: t.name }));
      }
      return send(mcpTools({ tools }));
    }

    function handleMcpCall(m) {
      const callId = typeof m.call_id === 'string' ? m.call_id : undefined;
      const reply = (result) => {
        try { return send(mcpResult({ result, callId })); } catch (e) {
          log(`mcp result for ${m.tool} not encodable: ${e.message}`);
          return send(mcpResult({ result: { success: false, error: 'tool result could not be encoded' }, callId }));
        }
      };
      const fail = (error) => reply({ success: false, error });
      if (!cfg.mcp) { fail('mcp is not enabled on this server'); return; }
      { const refusal = keyRefusal({ kind: 'mcp-call', tool: typeof m.tool === 'string' ? m.tool : '' }); if (refusal) { fail(refusal.reason); return; } }
      if (mcpCalls.size >= cfg.mcp.maxConcurrent) { fail('too many concurrent MCP calls'); return; }

      const abort = new AbortController();
      mcpCalls.add(abort);
      if (callId !== undefined) mcpById.set(callId, abort);
      (async () => {
        const name = typeof m.tool === 'string' ? m.tool : '';
        const tool = name ? await cfg.mcp.find(name, state.username, principal()) : null;
        if (!tool) return fail(`unknown tool: ${name || String(m.tool)}`);
        const args = m.arguments ?? {};
        const problem = cfg.mcp.validate(tool, args);
        if (problem) return fail(`invalid arguments: ${problem}`);

        let timer = null;
        const aborted = new Promise((_, reject) => {
          abort.signal.addEventListener('abort', () => reject(abort.signal.reason ?? new Error('aborted')), { once: true });
        });
        aborted.catch(() => {});
        if (cfg.mcp.timeoutMs > 0) {
          timer = setTimeout(() => abort.abort(new Error(`tool ${name} timed out after ${cfg.mcp.timeoutMs}ms`)), cfg.mcp.timeoutMs);
        }
        try {
          const ctx = { user: state.username, fingerprint: state.fingerprint, signal: abort.signal };
          const out = await Promise.race([Promise.resolve().then(() => tool.call(args, ctx)), aborted]);
          return reply(out === undefined ? null : out);
        } catch (e) {
          if (!state.closed) log(`mcp tool ${name} failed: ${e?.message ?? e}`);
          return fail(String(e?.message ?? e));
        } finally {
          clearTimeout(timer);
        }
      })()
        .catch((e) => log(`mcp call ${m.tool}: ${e.message}`))
        .finally(() => { mcpCalls.delete(abort); if (callId !== undefined && mcpById.get(callId) === abort) mcpById.delete(callId); });
    }

    // ── Open ──────────────────────────────────────────────────────────

    /**
     * The backends a request is served by (#121): the host's own when it names no target (and `requireTarget` is off), else the
     * target's, once the host knows the name and its `authorize(who, { target, kind })` lets this caller on. `{ refuse }`
     * otherwise, never a fallback to the host's own: a request for somewhere else is not run here.
     * @returns {Promise<{ b: object } | { refuse: string }>}
     */
    async function resolveTarget(target, kind) {
      if (target === undefined || target === null) return requireTarget ? { refuse: 'a target is required' } : { b: ownBackends };
      if (!targetTable) return { refuse: 'this host has no targets' };
      const spec = typeof target === 'string' && TARGET_NAME_RE.test(target) ? targetTable.get(target) : undefined;
      if (!spec) return { refuse: NO_SUCH_TARGET };
      if (spec.authorize) {
        let allowed = false;
        try { allowed = (await spec.authorize({ username: state.username, fingerprint: state.fingerprint }, { target, kind })) === true; } catch (e) { log(`target ${target} authorize threw: ${e.message}`); }
        if (!allowed) {
          log(`target ${target} refused for ${state.username ?? '?'} (${kind})`);
          return { refuse: NO_SUCH_TARGET };
        }
      }
      return { b: spec };
    }

    /** `ListTargets`: the targets this caller may use, as the host shows them. */
    async function handleListTargets() {
      if (!targetTable) return send(errorMsg({ code: 3, message: 'this host has no targets' }));
      const out = [];
      for (const [name, spec] of targetTable) {
        // A key with capabilities is told only of the targets it holds (`target:NAME`).
        if (!keyAllows({ kind: 'target', name })) continue;
        const r = await resolveTarget(name, 'list');
        if (r.refuse) continue;
        out.push({ name, ...(spec.description !== undefined ? { description: spec.description } : {}), capabilities: targetCapabilities(spec) });
      }
      return send(targetListMsg({ targets: out }));
    }

    async function handleOpen(m) {
      if (channels.size >= MAX_CHANNELS) return send(openFail({ reason: 'too many open channels' }));
      const target = m.target ?? undefined;
      switch (m.kind) {
        case 'exec': case 'pty': case 'file': {
          // The key's options and capabilities (#122): asked before the target is looked up (a key without `target:NAME` learns
          // nothing about whether it exists), and again once it is, because no await may separate the `max-sessions` check from
          // the channel being registered (two opens must not both pass when one slot is left).
          const req = { kind: 'open', channel: m.kind, target, direction: m.kind === 'file' ? (String(m.command ?? '').startsWith('download:') ? 'download' : 'upload') : undefined };
          const early = keyRefusal(req);
          if (early) return send(openFail({ reason: early.reason }));
          const r = await resolveTarget(target, m.kind);
          if (r.refuse) return send(openFail({ reason: r.refuse }));
          const refusal = keyAllows(req) ? null : keyRefusal(req);
          if (refusal) return send(openFail({ reason: refusal.reason }));
          if (m.kind === 'exec') return openExec(m, r.b, target);
          return m.kind === 'pty' ? openPty(m, r.b, target) : openFile(m, r.b);
        }
        case 'rpc':
          // rpc channels (`wsh-fs`, `wsh-host`, `mcp`) are the host's own, not per target.
          if (target !== undefined) return send(openFail({ reason: 'rpc channels do not take a target' }));
          if (requireTarget) return send(openFail({ reason: 'a target is required' }));
          {
            const protocol = typeof m.command === 'string' ? m.command : '';
            const refusal = keyRefusal({ kind: 'open', channel: 'rpc', protocol, scoped: cfg.rpc?.protocols.get(protocol)?.capabilityScoped === true, authorizesItself: cfg.rpc?.protocols.get(protocol)?.authorizesItself === true });
            if (refusal) return send(openFail({ reason: refusal.reason }));
          }
          return openRpc(m);
        default: return send(openFail({ reason: `kind "${m.kind}" is not supported by this server` }));
      }
    }

    function finishChannel(channelId, code) {
      if (!channels.has(channelId) || state.closed) return Promise.resolve();
      channels.delete(channelId);
      return send(exitMsg({ channelId, code })).then(() => send(closeMsg({ channelId })));
    }

    // ── Hosted sessions (createWshServer({ sessions })) ───────────────

    /** Who this connection authenticated as: its key, or its username for a password login. */
    const principalKey = () => state.fingerprint ?? `password:${state.username}`;
    const ownerRecord = () => ({ username: state.username, fingerprint: state.fingerprint, principal: principalKey() });

    /**
     * This connection's message-backed attachment to a hosted session: output, Presence and the
     * final Exit/Close all go through one ordered chain, so a replay is never overtaken by live output.
     */
    function virtualAttachment(hosted, channelId, mode) {
      let out = Promise.resolve();
      const enqueue = (fn) => { out = out.then(fn).catch(() => {}); return out; };
      return {
        connId: cid, channelId, mode, username: state.username, principal: principalKey(),
        write: (bytes) => enqueue(() => send(sessionData({ channelId, data: bytes }))),
        notify: (msg) => enqueue(() => send(presenceMsg(msg))),
        exit: (code) => enqueue(async () => {
          channels.delete(channelId);
          await send(exitMsg({ channelId, code }));
          await send(closeMsg({ channelId }));
        }),
        flush: () => out,
      };
    }

    /** The `channels` entry for a virtual attachment (an Attach/Resume, or a pty's own channel). */
    function attachedChannel(hosted, att) {
      const control = () => att.mode === 'control';
      const ch = {
        session: hosted, attachment: att,
        input: (d) => { if (control()) hosted.handlers.input?.(d); },
        resize: (c, r) => { if (control()) hosted.handlers.resize?.(c, r); },
        signal: (name) => { if (control()) hosted.handlers.signal?.(name); },
        // The client closed the channel: the session's owner ends it, anyone else just leaves it.
        kill: () => {
          if (att.principal === hosted.owner.principal && control()) hosted.kill();
          else ch.detach();
        },
        detach: () => { channels.delete(att.channelId); hosted.detach(att); },
      };
      channels.set(att.channelId, ch);
      return ch;
    }

    async function handleAttach(m, isResume) {
      const reg = cfg.sessions;
      const fail = (code, message) => send(errorMsg({ code, message }));
      if (!reg) return fail(3, `${isResume ? 'resume' : 'attach'} is not enabled on this server (no "sessions" option)`);
      const s = reg.get(m.session_id);
      const mine = !!s && s.owner.principal === principalKey();
      const tokenOk = !!s && m.token !== undefined && reg.checkToken(s, m.token);
      // Attach: the token OR ownership. Resume: the token AND ownership (the credentialed connection coming back).
      if (!s || !(isResume ? tokenOk && mine : tokenOk || mine)) {
        log(`${isResume ? 'resume' : 'attach'} refused for ${String(m.session_id).slice(0, 8)}`);
        return fail(2, 'unknown session or not authorized');
      }
      if ([...channels.values()].some((c) => c.session === s)) return fail(3, 'already attached to this session on this connection');
      if (s.attachments.size >= MAX_ATTACHMENTS) return fail(3, 'too many attachments to this session');
      if (channels.size >= MAX_CHANNELS) return fail(3, 'too many open channels');

      let from = s.ring.start;
      if (isResume) {
        const last = m.last_seq;
        if (!Number.isSafeInteger(last) || last < 0) return fail(3, 'last_seq must be a non-negative integer');
        if (last > s.ring.end) return fail(4, `last_seq ${last} is ahead of the session (it has produced ${s.ring.end} bytes)`);
        if (last < s.ring.start) {
          return fail(4, `output gap: this session's retained output starts at seq ${s.ring.start} but last_seq is ${last}; attach for the retained output instead`);
        }
        from = last;
      }
      const mode = !isResume && /^(readonly|read|view|ro)$/i.test(String(m.mode ?? '')) ? 'readonly' : 'control';
      const channelId = ++state.nextChannel;
      const att = virtualAttachment(s, channelId, mode);
      attachedChannel(s, att);

      // Reply, replay, then (if the process is already over) its exit -- all before any live output,
      // which only reaches `att` once `s.attach(att)` registers it, after these are queued.
      const self = { session_id: s.id, mode, username: state.username, channel_id: channelId, seq: from };
      att.notify({ attachments: [self, ...s.roster()] });
      const replay = s.ring.read(from);
      for (let off = 0; off < replay.byteLength; off += REPLAY_CHUNK_BYTES) att.write(replay.subarray(off, off + REPLAY_CHUNK_BYTES));
      if (s.state === 'exited') att.exit(s.exitCode ?? 0);
      else s.attach(att);
      log(`${isResume ? 'resumed' : `attached (${mode})`} session ${s.id.slice(0, 8)} on channel ${channelId} from seq ${from}`);
    }

    async function handleDetach(m) {
      const s = cfg.sessions?.get(m.session_id);
      const entry = s && [...channels.entries()].find(([, c]) => c.session === s);
      if (!entry) return send(detachFail({ reason: 'not attached to this session on this connection' }));
      const [channelId, ch] = entry;
      const flushed = ch.attachment.flush();
      ch.detach();
      await flushed;
      await send(closeMsg({ channelId }));
      return send(detachOk({ sessionId: s.id }));
    }

    function handleSessionList() {
      const now = Date.now();
      const sessions = (cfg.sessions?.listFor(principalKey()) ?? []).map((s) => ({
        session_id: s.id,
        username: s.owner.username,
        fingerprint_short: (s.owner.fingerprint ?? '').slice(0, 8),
        created_at_secs: Math.floor(s.createdAt / 1000),
        idle_secs: Math.max(0, Math.floor((now - s.lastActivity) / 1000)),
        attached_count: s.attachments.size,
      }));
      return send(sessionList({ sessions }));
    }

    async function openExec(m, b, target) {
      if (!b.execRunner) return send(openFail({ reason: `exec is not enabled ${b.ownHost ? 'on this server' : 'for this target'}` }));
      // A key tied to one command (`command="..."`, #122) runs that, whatever the client asked for.
      const command = keyPermissions()?.forcedCommand ?? String(m.command ?? '').trim();
      if (!command) return send(openFail({ reason: 'command is required for kind "exec"' }));

      const channelId = ++state.nextChannel;
      const abort = new AbortController();
      const hosted = cfg.sessions ? cfg.sessions.create({ owner: ownerRecord(), kind: 'exec', command }) : null;
      let stream = null;
      let primerChecked = false;
      let wq = Promise.resolve();
      const buffered = [];
      const boundWaiters = [];
      const inputCbs = [];
      const endCbs = [];
      const signalCbs = [];

      const signalTo = (name) => {
        const n = name.replace(/^SIG/, '').toUpperCase();
        for (const cb of signalCbs) cb(n);
        if (/^(INT|TERM|KILL|HUP)$/.test(n) && signalCbs.length === 0) abort.abort();
      };
      const ch = {
        keyed: !hosted, // counts toward the key's `max-sessions` (a hosted session is counted by the registry)
        kill: () => abort.abort(),
        signal: signalTo,
        bind(s) {
          stream = s;
          s.onData = (d) => {
            // A client that primes (see header) sends one lone 0x00 first.
            if (!primerChecked) {
              primerChecked = true;
              if (d.byteLength === 1 && d[0] === 0) return;
            }
            if (d.byteLength) for (const cb of inputCbs) cb(d);
          };
          s.onEnd = () => { for (const cb of endCbs) cb(); };
          // A hosted session outlives its stream; an unhosted one dies with it.
          s.onReset = () => { if (!hosted) abort.abort(); };
          const pending = buffered.splice(0);
          wq = wq.then(async () => { for (const b of pending) await s.write(b).catch(() => {}); });
          for (const r of boundWaiters.splice(0)) r();
        },
      };
      channels.set(channelId, ch);
      if (dataStreams) pendingStreams.push(channelId);
      // No client-opened streams on this connection (a relay bridge): stdin arrives as SessionData.
      else ch.input = (d) => { for (const cb of inputCbs) cb(d); };

      let timer = null;
      if (b.execOptions.timeoutMs > 0) timer = setTimeout(() => abort.abort(), b.execOptions.timeoutMs);

      // Output to the opening connection's data stream (held until the client has opened it).
      const toStream = (bytes) => {
        if (!dataStreams) {
          wq = wq.then(() => send(sessionData({ channelId, data: bytes })));
          return wq;
        }
        if (!stream) { buffered.push(bytes); return Promise.resolve(); }
        const s = stream;
        wq = wq.then(() => s.write(bytes).catch(() => {}));
        return wq;
      };
      // Output is ready but the client's stream may not have been bound yet (a host without
      // announce support waits for the first byte): give it a bounded chance rather than
      // dropping the output or hanging forever.
      const closeStream = async (code) => {
        if (dataStreams && !stream) await Promise.race([new Promise((r) => boundWaiters.push(r)), new Promise((r) => setTimeout(r, cfg.bindTimeoutMs))]);
        if (dataStreams && !stream) log(`exec channel ${channelId}: data stream never appeared; output dropped`);
        await wq;
        try { await stream?.close(); } catch { /* peer gone */ }
        await finishChannel(channelId, Number.isInteger(code) ? code : 0);
      };

      if (hosted) {
        const att = {
          connId: cid, channelId, mode: 'control', username: state.username, principal: principalKey(),
          write: toStream,
          notify: (msg) => send(presenceMsg(msg)),
          exit: (code) => closeStream(code),
          flush: () => wq,
        };
        hosted.handlers = {
          input: (d) => { for (const cb of inputCbs) cb(d); },
          inputEnd: () => { for (const cb of endCbs) cb(); },
          signal: signalTo,
          resize: () => {},
          kill: () => abort.abort(),
        };
        ch.session = hosted;
        ch.attachment = att;
        ch.detach = () => {
          channels.delete(channelId);
          hosted.detach(att);
          try { stream?.close().catch(() => {}); } catch { /* gone */ }
        };
        hosted.attach(att);
      }

      const io = {
        user: state.username,
        // Which execution target this command runs on (#121); undefined on the host's own.
        target,
        env: b.execEnv(m.env),
        cols: m.cols || 80,
        rows: m.rows || 24,
        signal: abort.signal,
        write(data) {
          const bytes = toBytes(data);
          if (!hosted) return toStream(bytes);
          hosted.push(bytes);
          return wq;
        },
        onInput: (cb) => inputCbs.push(cb),
        onInputEnd: (cb) => endCbs.push(cb),
        onSignal: (cb) => signalCbs.push(cb),
      };

      await send(openOk({
        channelId, dataMode: dataStreams ? 'stream' : 'virtual', capabilities: ['signal'],
        sessionId: hosted?.id ?? randomUUID(), token: hosted?.token ?? randomBytes(16),
      }));
      log(`exec channel ${channelId}: ${command}`);

      // Detached: the message chain must stay free to deliver this
      // session's Signal/Close/SessionData while the command runs.
      runExec().catch((e) => log(`exec channel ${channelId}: ${e.message}`));

      async function runExec() {
        let code;
        try { code = await b.execRunner(command, io); } catch (e) {
          await io.write(`wsh: ${e.message}\n`);
          code = 1;
        }
        if (timer) clearTimeout(timer);
        // Hosted: everyone attached (this connection's stream included, if it is still there) hears the exit.
        if (hosted) { hosted.finish(Number.isInteger(code) ? code : 0); return; }
        await closeStream(code);
      }
    }

    // A typed RPC channel (wsh #85): `Open { kind: 'rpc', command: <protocol> }` is answered like an exec channel's -- OpenOk,
    // then the client's data stream binds in OpenOk order -- but the stream carries a CBOR sequence of JSON-RPC messages
    // handled by the protocol's handler, not process I/O.
    async function openRpc(m) {
      const rpc = cfg.rpc;
      const protocol = typeof m.command === 'string' ? m.command : '';
      const handler = rpc?.protocols.get(protocol);
      if (!rpc || !handler) {
        const why = !rpc ? 'rpc is not enabled on this server' : `protocol "${protocol}" is not supported by this server`;
        return send(openFail({ reason: `UNSUPPORTED_PROTOCOL: ${why}` }));
      }
      if (!dataStreams) return openRpcVirtual(m, protocol, handler, rpc);
      const channelId = ++state.nextChannel;
      let chan = null;
      let stream = null;
      const ch = {
        // The peer closed the channel (or the connection is going away).
        kill: () => {
          channels.delete(channelId);
          chan?.handleClose('peer-closed');
          try { stream?.close().catch(() => {}); } catch { /* gone */ }
        },
        bind(s) {
          stream = s;
          chan = new RpcChannel({
            maxMessageBytes: rpc.maxMessageBytes,
            maxInflight: rpc.maxInflight,
            write: (bytes) => s.write(bytes),
            // The host ended it: close our end of the stream, then tell the client the channel is over.
            close: async () => { try { await s.close(); } catch { /* peer gone */ } await finishChannel(channelId, 0); },
          });
          s.onData = (d) => chan.feed(d);
          s.onEnd = () => { void chan.close('stream-end'); };
          s.onReset = () => chan.handleClose('stream-reset');
          const ctx = {
            protocol, channelId, user: state.username, fingerprint: state.fingerprint, remote,
            features: state.features ?? [], hostFingerprint: state.hostFingerprint,
            capabilities: keyCapabilities(), permits,
            log: (line) => log(`rpc ${protocol} channel ${channelId}: ${line}`),
          };
          // Inbound messages wait until the handler (possibly async) has registered its methods.
          chan.hold();
          let ready;
          try { ready = Promise.resolve(handler(chan, ctx)); } catch (e) { ready = Promise.reject(e); }
          ready.then(() => chan.release(), (e) => {
            log(`rpc ${protocol} channel ${channelId}: handler failed: ${e?.message ?? e}`);
            void chan.close('handler-error');
          });
        },
      };
      channels.set(channelId, ch);
      pendingStreams.push(channelId);
      await send(openOk({ channelId, dataMode: 'stream', capabilities: [] }));
      log(`rpc channel ${channelId}: ${protocol}`);
    }

    // An rpc channel in virtual data mode (#191): the same CBOR sequence of JSON-RPC messages, carried as SessionData (and so
    // inside EncryptedFrame on a sealed session) and metered by credit, because the control plane has no flow control of its own.
    async function openRpcVirtual(m, protocol, handler, rpc) {
      const channelId = ++state.nextChannel;
      let chan = null;
      const link = new RpcCreditLink({
        sendData: (bytes) => send(sessionData({ channelId, data: bytes })),
        sendCredit: (n) => send(gatewayCredit({ gatewayId: rpcCreditId(channelId), bytes: n })),
        onViolation: (why) => { log(`rpc ${protocol} channel ${channelId}: ${why}; closing it`); void chan?.close('credit-violation'); },
      });
      chan = new RpcChannel({
        maxMessageBytes: rpc.maxMessageBytes,
        maxInflight: rpc.maxInflight,
        write: (bytes) => link.write(bytes),
        onConsumed: (n) => link.consumed(n),
        close: async () => { link.close(); await finishChannel(channelId, 0); },
      });
      channels.set(channelId, {
        kill: () => { channels.delete(channelId); link.close(); chan.handleClose('peer-closed'); },
        input: (d) => { if (d?.length && link.receive(d.length)) chan.feed(d); },
        credit: (n) => link.grant(n),
      });
      const ctx = {
        protocol, channelId, user: state.username, fingerprint: state.fingerprint, remote,
        features: state.features ?? [], hostFingerprint: state.hostFingerprint,
        capabilities: keyCapabilities(), permits,
        log: (line) => log(`rpc ${protocol} channel ${channelId}: ${line}`),
      };
      // Inbound messages wait until the handler (possibly async) has registered its methods; the handler starts only after
      // OpenOk is on its way, so nothing it sends can reach a client that does not have the channel yet.
      chan.hold();
      await send(openOk({ channelId, dataMode: 'virtual', capabilities: [] }));
      log(`rpc channel ${channelId}: ${protocol} (virtual)`);
      let ready;
      try { ready = Promise.resolve(handler(chan, ctx)); } catch (e) { ready = Promise.reject(e); }
      ready.then(() => chan.release(), (e) => {
        log(`rpc ${protocol} channel ${channelId}: handler failed: ${e?.message ?? e}`);
        void chan.close('handler-error');
      });
    }

    async function openPty(m, b, target) {
      if (!b.pty) return send(openFail({ reason: `pty is not enabled ${b.ownHost ? 'on this server' : 'for this target'}` }));
      const channelId = ++state.nextChannel;
      const cols = m.cols || 80;
      const rows = m.rows || 24;
      const p = b.pty;
      let proc;
      try {
        const args = m.command ? ['-c', String(m.command)] : [];
        proc = p.spawn(p.shell, args, {
          name: p.term, cols, rows, cwd: p.cwd,
          env: { ...(p.env ?? globalThis.process?.env), TERM: p.term, ...b.ptyEnv(m.env) },
          // Which execution target this shell is for (#121); absent on the host's own.
          ...(target !== undefined ? { target } : {}),
        });
      } catch (e) {
        return send(openFail({ reason: `pty spawn failed: ${e.message}` }));
      }
      const ctl = {
        keyed: !cfg.sessions, // counts toward the key's `max-sessions` (a hosted session is counted by the registry)
        // Bytes, not a `Buffer`: there is none in a browser (#133), and node-pty's streams take a Uint8Array as is.
        // A write to a process that has exited throws; that is expected and dropped, anything else is logged.
        input: (data) => {
          try { proc.write(Uint8Array.from(data)); } catch (e) { log(`pty channel ${channelId}: input not written: ${e?.message ?? e}`); }
        },
        resize: (c, r) => { try { proc.resize(c || cols, r || rows); } catch { /* exited */ } },
        signal: (name) => { try { proc.kill(`SIG${name.replace(/^SIG/, '').toUpperCase()}`); } catch { /* exited */ } },
        kill: () => { try { proc.kill(); } catch { /* exited */ } },
      };

      if (cfg.sessions) {
        const hosted = cfg.sessions.create({ owner: ownerRecord(), kind: 'pty', command: m.command });
        hosted.handlers = ctl;
        const att = virtualAttachment(hosted, channelId, 'control');
        attachedChannel(hosted, att);
        proc.onData((d) => hosted.push(Uint8Array.from(toBytes(d))));
        proc.onExit(({ exitCode }) => hosted.finish(exitCode ?? 0));
        const opened = send(openOk({
          channelId, dataMode: 'virtual', capabilities: ['resize', 'signal'],
          sessionId: hosted.id, token: hosted.token,
        }));
        hosted.attach(att);
        await opened;
        log(`pty channel ${channelId} opened (${cols}x${rows}), session ${hosted.id.slice(0, 8)}`);
        return;
      }

      channels.set(channelId, ctl);
      let out = Promise.resolve();
      proc.onData((d) => { out = out.then(() => send(sessionData({ channelId, data: toBytes(d) }))); });
      proc.onExit(({ exitCode }) => { out.then(() => finishChannel(channelId, exitCode ?? 0)); });
      await send(openOk({
        channelId, dataMode: 'virtual', capabilities: ['resize', 'signal'],
        sessionId: randomUUID(), token: randomBytes(16),
      }));
      log(`pty channel ${channelId} opened (${cols}x${rows})`);
    }

    async function openFile(m, b) {
      const files = b.files;
      if (!files) return send(openFail({ reason: `file access is not enabled ${b.ownHost ? 'on this server' : 'for this target'}` }));
      const spec = String(m.command ?? '');
      const mm = spec.match(/^(upload|download):(.*)$/s);
      if (!mm) return send(openFail({ reason: 'file channel expects upload:<path> or download:<path>' }));
      const [, direction, filePath] = mm;
      const channelId = ++state.nextChannel;

      if (direction === 'download') {
        let data;
        try { data = await files.readWhole(filePath); } catch (e) { return send(openFail({ reason: e.message })); }
        let cancelled = false;
        channels.set(channelId, { kill: () => { if (channels.delete(channelId)) { cancelled = true; log(`download ${filePath}: closed before completion`); } } });
        await send(openOk({ channelId, dataMode: 'virtual', capabilities: [] }));
        let off = 0;
        do {
          if (cancelled) return;
          const end = Math.min(off + FILE_CHUNK_BYTES, data.byteLength);
          await send(fileChunk({ channelId, offset: off, data: data.subarray(off, end), isFinal: end >= data.byteLength, totalSize: data.byteLength }));
          off = end;
        } while (off < data.byteLength);
        log(`download ${filePath} (${data.byteLength} B)`);
        return;
      }

      // Closed before the final chunk: the buffered bytes are dropped and nothing is written, so an
      // aborted upload leaves the destination exactly as it was (the write itself is whole-file, see writeWhole).
      const ch = { buf: null, kill: () => { if (channels.delete(channelId)) log(`upload ${filePath}: closed before completion, nothing written`); } };
      channels.set(channelId, ch);
      const done = async (code, why) => {
        if (why) log(`upload ${filePath}: ${why}`);
        await finishChannel(channelId, code);
      };
      ch.chunk = async (c) => {
        if (ch.failed) return;
        const total = Number(c.total_size ?? 0);
        if (total > files.maxFileBytes) { ch.failed = true; return done(1, `refused: ${total} B exceeds ${files.maxFileBytes} B`); }
        ch.buf ??= new Uint8Array(total);
        const data = c.data instanceof Uint8Array ? c.data : new Uint8Array(0);
        if (c.offset + data.byteLength > ch.buf.byteLength) { ch.failed = true; return done(1, 'chunk past total_size'); }
        ch.buf.set(data, c.offset);
        if (c.is_final) {
          try { await files.writeWhole(filePath, ch.buf); } catch (e) { ch.failed = true; return done(1, e.message); }
          return done(0, `stored ${ch.buf.byteLength} B`);
        }
      };
      await send(openOk({ channelId, dataMode: 'virtual', capabilities: [] }));
    }

    async function handleFileOp(m) {
      const channelId = m.channel_id;
      const target = m.target ?? undefined;
      const refusal = keyRefusal({ kind: 'file-op', op: m.op, target });
      if (refusal) return send(fileResult({ channelId, success: false, errorMessage: refusal.reason }));
      const r0 = await resolveTarget(target, 'file');
      if (r0.refuse) return send(fileResult({ channelId, success: false, errorMessage: r0.refuse }));
      const files = r0.b.files;
      if (!files) return send(fileResult({ channelId, success: false, errorMessage: `file access is not enabled ${r0.b.ownHost ? 'on this server' : 'for this target'}` }));
      if (m.op === 'write' || m.op === 'rename') return startPayloadOp(m, files);
      try {
        const r = await files.operate(m.op, m.path, { offset: m.offset, length: m.length });
        return send(fileResult({ channelId, success: true, metadata: r.metadata ?? {}, entries: r.entries ?? [] }));
      } catch (e) {
        const message = e.wsh ? e.message : (e.code === 'ENOENT' ? 'no such file or directory' : `${m.op} failed`);
        if (!e.wsh && e.code !== 'ENOENT') log(`file ${m.op} ${m.path}: ${e.message}`);
        return send(fileResult({ channelId, success: false, errorMessage: message }));
      }
    }

    // write / rename = FileOp then FileChunk frame(s) on the same channel id
    // (rename's payload is the UTF-8 destination path); one FileResult once
    // the last chunk lands (see WshClient.fileOperation).
    async function startPayloadOp(m, files) {
      const channelId = m.channel_id;
      const failWrite = (errorMessage) => send(fileResult({ channelId, success: false, errorMessage }));
      const rename = m.op === 'rename';
      const length = Number(m.length);
      if (!Number.isSafeInteger(length) || length < 0) return failWrite(`${m.op} needs a length`);
      const limit = rename ? MAX_RENAME_PATH_BYTES : files.maxFileBytes;
      if (length > limit) return failWrite(`${m.op} payload of ${length} bytes exceeds the ${limit} byte limit`);
      if (channels.has(channelId) || fileWrites.has(channelId)) return failWrite('channel id already in use');
      if (fileWrites.size >= MAX_PENDING_WRITES) return failWrite('too many writes in flight');
      const w = { rename, files, path: m.path, offset: m.offset, length, buf: new Uint8Array(length), next: 0, timer: null };
      const arm = () => {
        clearTimeout(w.timer);
        w.timer = setTimeout(() => {
          if (fileWrites.delete(channelId)) failWrite('write timed out waiting for data');
        }, WRITE_IDLE_MS);
        w.timer.unref?.();
      };
      arm();
      w.arm = arm;
      fileWrites.set(channelId, w);
    }

    async function handleWriteChunk(m) {
      const channelId = m.channel_id;
      const w = fileWrites.get(channelId);
      const abort = (errorMessage) => {
        clearTimeout(w.timer);
        fileWrites.delete(channelId);
        return send(fileResult({ channelId, success: false, errorMessage }));
      };
      const data = m.data instanceof Uint8Array ? m.data : new Uint8Array(0);
      if (m.offset !== w.next) return abort('chunks must arrive in order');
      if (w.next + data.byteLength > w.length) return abort('chunk past the declared length');
      w.buf.set(data, w.next);
      w.next += data.byteLength;
      if (!m.is_final) { w.arm(); return; }
      clearTimeout(w.timer);
      fileWrites.delete(channelId);
      if (w.next !== w.length) return send(fileResult({ channelId, success: false, errorMessage: 'payload ended short of the declared length' }));
      try {
        const r = w.rename
          ? await w.files.operate('rename', w.path, { newPath: new TextDecoder('utf-8', { fatal: true }).decode(w.buf) })
          : await w.files.operate('write', w.path, { offset: w.offset, data: w.buf });
        return send(fileResult({ channelId, success: true, metadata: r.metadata ?? {} }));
      } catch (e) {
        const message = e.wsh ? e.message : (e.code === 'ENOENT' ? 'no such file or directory' : `${w.rename ? 'rename' : 'write'} failed`);
        if (!e.wsh && e.code !== 'ENOENT') log(`file write ${w.path}: ${e.message}`);
        return send(fileResult({ channelId, success: false, errorMessage: message }));
      }
    }

    return {
      receive(bytes) {
        if (state.closed) return;
        if (waitForPeer && bytes?.length) armLoginDeadline(); // the far side is there: the first byte starts its login clock (#253)
        qmux?.receiveBytes(bytes);
      },
      /** The far side of a `waitForPeer` connection is there (a relay said its partner arrived): start the login clock, once. Nothing otherwise. */
      startLoginClock() { if (waitForPeer) armLoginDeadline(); },
      /** A transport datagram (WebTransport) arrived: only the gateway's UDP flows use them. */
      receiveDatagram(bytes) { if (!state.closed && state.authed) gateway?.handleDatagram?.(bytes); },
      receiveMessage(msg) { if (!state.closed && waitForPeer) armLoginDeadline(); if (!state.closed) chain = chain.then(() => handle(msg)).catch((e) => log(`handler error: ${e.message}`)); },
      bindStream: bindDataStream,
      close() { shutdownAfterQueue('transport closed'); },
    };
  };
}
