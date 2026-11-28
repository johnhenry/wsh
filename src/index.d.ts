/**
 * wsh -- Web Shell client library
 *
 * Browser-native remote command execution over WebTransport/WebSocket
 * with Ed25519 authentication.
 */

// ============================================================================
// cbor.mjs -- CBOR codec + length-prefixed framing
// ============================================================================

/**
 * Encode a JS value into CBOR bytes.
 * Supports: maps, arrays, strings, integers, bytes (Uint8Array),
 * booleans, null, and floats.
 */
export function cborEncode(value: unknown): Uint8Array;

/**
 * Decode CBOR bytes into a JS value. Strict (#317): the whole buffer must be exactly one item, every declared length must fit the
 * buffer, and there are no tags, no indefinite lengths (but see `legacyIndefiniteMap`), no duplicate or non-text map keys, no invalid UTF-8,
 * at most CBOR_MAX_CONTAINERS arrays and maps. Throws a {@link CborError}.
 *
 * The encoder writes the canonical form (RFC 8949 4.2.1); the decoder reads what released peers wrote too, until the compatibility window closes
 * (COMPATIBILITY.md rule 7). `strict: true` turns every legacy option off.
 */
export function cborDecode(data: Uint8Array, options?: CborDecodeOptions): unknown;

/** Every option is checked: a wrong type or value (`strict: 1`, `maxContainers: 0`) throws a TypeError; `undefined` takes the default. */
export interface CborDecodeOptions {
  /** Every legacy option off (the default of a later minor). An explicit option below wins. */
  strict?: boolean;
  /** Accept an indefinite-length map as the TOP-LEVEL item (at offset 0), which every released wsh Rust encoder wrote. Default true. */
  legacyIndefiniteMap?: boolean;
  /** Accept the map key order, float widths and NaN forms the released encoders wrote (not sorted length-first, not shortest, any NaN). Default true. */
  legacyNonCanonical?: boolean;
  /** An integer beyond +-(2^53-1): 'round' (the nearest double; default), 'bigint' (exact), 'refuse' (a CborError `unsafe-integer`; what `strict` selects). */
  unsafeIntegers?: 'round' | 'bigint' | 'refuse';
  /** The most arrays and maps one item may hold. Default CBOR_MAX_CONTAINERS. */
  maxContainers?: number;
}

/**
 * Decode ONE item starting at `offset` and return where it ended; whatever follows is left to the caller. As strict as `cborDecode` about the item.
 */
export function cborDecodePrefix(data: Uint8Array, options?: CborDecodeOptions & { offset?: number }): { value: unknown; end: number };

/** A malformed CBOR input. `code` is the rule that was broken. */
export class CborError extends Error {
  constructor(code: CborErrorCode, message: string, offset?: number);
  readonly code: CborErrorCode;
  readonly offset?: number;
}

export type CborErrorCode =
  | 'truncated' | 'length-exceeds-buffer' | 'trailing-bytes' | 'non-shortest' | 'indefinite-length' | 'unexpected-break'
  | 'reserved-additional-info' | 'duplicate-key' | 'non-text-key' | 'tag' | 'simple-value' | 'invalid-utf8' | 'too-deep'
  | 'too-many-containers' | 'non-canonical-key-order' | 'non-canonical-float' | 'unsafe-integer';

/** The deepest nesting a decoded item may have. */
export const CBOR_MAX_DEPTH: number;

/** The most arrays and maps one decoded item may hold (1,000,000). */
export const CBOR_MAX_CONTAINERS: number;

/**
 * Frame a CBOR-encoded message with a 4-byte big-endian length prefix.
 * @returns [4-byte length][CBOR payload]
 */
export function frameEncode(value: unknown): Uint8Array;

/**
 * Default cap on a single frame's claimed payload length (16 MiB).
 */
export const DEFAULT_MAX_FRAME_SIZE: number;

/**
 * Thrown by FrameDecoder#feed when a frame's claimed length exceeds the
 * decoder's configured maximum.
 */
export class FrameSizeError extends Error {
  constructor(len: number, maxFrameSize: number);
  readonly len: number;
  readonly maxFrameSize: number;
}

/**
 * Streaming frame decoder. Feed it chunks and it yields complete messages.
 */
export class FrameDecoder {
  /**
   * @param opts.maxFrameSize Maximum allowed claimed frame length in bytes.
   *   Defaults to DEFAULT_MAX_FRAME_SIZE.
   * @param opts The other options are {@link CborDecodeOptions}, applied to every frame (default: the compatibility window).
   */
  constructor(opts?: { maxFrameSize?: number } & CborDecodeOptions);

  /**
   * Feed bytes and return decoded messages.
   * @throws {FrameSizeError} if a frame's claimed length exceeds the
   *   configured maximum.
   */
  feed(chunk: Uint8Array): unknown[];

  /** Reset internal buffer. */
  reset(): void;

  /** Bytes remaining in buffer. */
  readonly pending: number;
}

// ============================================================================
// messages.gen.mjs / messages.mjs -- Protocol messages
// ============================================================================

/** Wire message type constants (frozen object of hex opcodes). */
export const MSG: {
  // Handshake
  readonly HELLO: 0x01;
  readonly SERVER_HELLO: 0x02;
  readonly CHALLENGE: 0x03;
  readonly AUTH_METHODS: 0x04;
  readonly AUTH: 0x05;
  readonly AUTH_OK: 0x06;
  readonly AUTH_FAIL: 0x07;

  // Channel
  readonly OPEN: 0x10;
  readonly OPEN_OK: 0x11;
  readonly OPEN_FAIL: 0x12;
  readonly RESIZE: 0x13;
  readonly SIGNAL: 0x14;
  readonly EXIT: 0x15;
  readonly CLOSE: 0x16;
  readonly SESSION_DATA: 0x17;

  // Transport
  readonly ERROR: 0x20;
  readonly PING: 0x21;
  readonly PONG: 0x22;

  // Session
  readonly ATTACH: 0x30;
  readonly RESUME: 0x31;
  readonly RENAME: 0x32;
  readonly IDLE_WARNING: 0x33;
  readonly SHUTDOWN: 0x34;
  readonly SNAPSHOT: 0x35;
  readonly PRESENCE: 0x36;
  readonly CONTROL_CHANGED: 0x37;
  readonly METRICS: 0x38;
  readonly CLIPBOARD: 0x39;
  readonly RECORDING_EXPORT: 0x3a;
  readonly COMMAND_JOURNAL: 0x3b;
  readonly METRICS_REQUEST: 0x3c;
  readonly SUSPEND_SESSION: 0x3d;
  readonly RESTART_PTY: 0x3e;

  // Mcp
  readonly MCP_DISCOVER: 0x40;
  readonly MCP_TOOLS: 0x41;
  readonly MCP_CALL: 0x42;
  readonly MCP_RESULT: 0x43;

  // Reverse
  readonly REVERSE_REGISTER: 0x50;
  readonly REVERSE_LIST: 0x51;
  readonly REVERSE_PEERS: 0x52;
  readonly REVERSE_CONNECT: 0x53;
  readonly REVERSE_ACCEPT: 0x54;
  readonly REVERSE_REJECT: 0x55;
  readonly RELAY_FORWARD: 0x56;

  // Gateway
  readonly OPEN_TCP: 0x70;
  readonly OPEN_UDP: 0x71;
  readonly RESOLVE_DNS: 0x72;
  readonly GATEWAY_OK: 0x73;
  readonly GATEWAY_FAIL: 0x74;
  readonly GATEWAY_CLOSE: 0x75;
  readonly INBOUND_OPEN: 0x76;
  readonly INBOUND_ACCEPT: 0x77;
  readonly INBOUND_REJECT: 0x78;
  readonly DNS_RESULT: 0x79;
  readonly LISTEN_REQUEST: 0x7a;
  readonly LISTEN_OK: 0x7b;
  readonly LISTEN_FAIL: 0x7c;
  readonly LISTEN_CLOSE: 0x7d;
  readonly GATEWAY_DATA: 0x7e;

  // Guest
  readonly GUEST_INVITE: 0x80;
  readonly GUEST_JOIN: 0x81;
  readonly GUEST_REVOKE: 0x82;

  // Sharing
  readonly SHARE_SESSION: 0x83;
  readonly SHARE_REVOKE: 0x84;

  // Compression
  readonly COMPRESS_BEGIN: 0x85;
  readonly COMPRESS_ACK: 0x86;

  // Ratecontrol
  readonly RATE_CONTROL: 0x87;
  readonly RATE_WARNING: 0x88;

  // Linking
  readonly SESSION_LINK: 0x89;
  readonly SESSION_UNLINK: 0x8a;

  // Copilot
  readonly COPILOT_ATTACH: 0x8b;
  readonly COPILOT_SUGGEST: 0x8c;
  readonly COPILOT_DETACH: 0x8d;

  // E2e
  readonly KEY_EXCHANGE: 0x8e;
  readonly ENCRYPTED_FRAME: 0x8f;

  // Echo
  readonly ECHO_ACK: 0x90;
  readonly ECHO_STATE: 0x91;

  // Termsync
  readonly TERM_SYNC: 0x92;
  readonly TERM_DIFF: 0x93;

  // Scaling
  readonly NODE_ANNOUNCE: 0x94;
  readonly NODE_REDIRECT: 0x95;

  // Principals
  readonly SESSION_GRANT: 0x96;
  readonly SESSION_REVOKE: 0x97;

  // Filechannel
  readonly FILE_OP: 0x98;
  readonly FILE_RESULT: 0x99;
  readonly FILE_CHUNK: 0x9a;

  // Policy
  readonly POLICY_EVAL: 0x9b;
  readonly POLICY_RESULT: 0x9c;
  readonly POLICY_UPDATE: 0x9d;

  // Terminal
  readonly TERMINAL_CONFIG: 0x9e;
};

/** Reverse lookup: message type number to name string. */
export const MSG_NAMES: Readonly<Record<number, string>>;

/** Channel kind constants. */
export const CHANNEL_KIND: {
  readonly PTY: 'pty';
  readonly EXEC: 'exec';
  readonly META: 'meta';
  readonly FILE: 'file';
  readonly TCP: 'tcp';
  readonly UDP: 'udp';
  readonly JOB: 'job';
  /** A typed object-mode channel (#85): `Open.command` names the protocol. `client.openRpc()` sends it. */
  readonly RPC: 'rpc';
};

/** Authentication method constants. */
export const AUTH_METHOD: {
  readonly PUBKEY: 'pubkey';
  readonly PASSWORD: 'password';
};

/** Protocol version string. */
export const PROTOCOL_VERSION: 'wsh-v1';

/**
 * ServerHello feature advertising that McpResult echoes McpCall's call_id.
 *
 * Compare against `WshClient.hasFeature()` before setting `callId`:
 * McpCallPayload is `deny_unknown_fields` server-side, so sending the field
 * to a server predating it makes the server reject the call rather than
 * ignore the field.
 */
export const MCP_CALL_ID_FEATURE: 'mcp-call-id';

/** ServerHello feature: the host understands `McpCancel` (stop an in-flight `McpCall`). Implies `mcp-call-id`. */
export const MCP_CANCEL_FEATURE: 'mcp-cancel';

/**
 * ServerHello feature: the host discovers a client-opened exec data stream
 * without help (the transport announces it), so the client writes no
 * one-byte primer against it.
 */
export const STREAM_ANNOUNCE_FEATURE: 'stream-announce';
/** ServerHello feature: the host runs `exec` on plain pipes (stderr apart, stdin EOF) when asked with `stdio: 'pipes'`. */
export const EXEC_PIPES_FEATURE: 'exec-pipes';
/** ServerHello feature (#121): the host has execution targets; `Open`, `FileOp` and `OpenEndpoint` take `target`. */
export const TARGETS_FEATURE: 'targets';

/**
 * Relay and reverse-host feature: the gateway's requests (`OpenTcp`, `OpenUdp`, `ResolveDns`, `ListenRequest` and their answers) cross
 * the relay bridge. A relay lists it in `ServerHello.features`; a reverse host whose owner turned its gateway on lists it in
 * `ReverseAccept.features`. Implies `gateway-credit`.
 */
export const RELAY_GATEWAY_FEATURE: 'relay-gateway';

// ── Typed (object-mode) RPC channels -- wsh #85 ────────────────────────

/** ServerHello feature: the host serves `rpc` sessions (`openSession({ type: 'rpc', protocol })`). */
export const RPC_FEATURE: 'rpc';
/**
 * ServerHello (or `ReverseAccept`) feature (#191): the host serves rpc channels in virtual data mode (the CBOR sequence rides
 * `SessionData`, inside `EncryptedFrame` on a sealed session, metered by credit). A host states this INSTEAD of `rpc` on a
 * connection with no client-opened data streams. `openRpc` picks the form from what the host states.
 */
export const RPC_VIRTUAL_FEATURE: 'rpc-virtual';
/** Does this feature list offer rpc in virtual data mode? */
export function rpcVirtualOffered(features?: string[]): boolean;
/** Credit, in bytes, each direction of a virtual-mode rpc channel starts with (a protocol constant). */
export const RPC_CREDIT_WINDOW: 262144;
/** ServerHello feature prefix: one `rpc-protocol:<name>` per protocol the host serves. */
export const RPC_PROTOCOL_PREFIX: 'rpc-protocol:';
/** ServerHello feature prefix: `rpc-max-message:<bytes>`. */
export const RPC_MAX_MESSAGE_PREFIX: 'rpc-max-message:';
/** Largest single rpc message when the host does not say (1 MiB). */
export const RPC_DEFAULT_MAX_MESSAGE: 1048576;
/** Allowed protocol names. */
export const RPC_PROTOCOL_NAME_RE: RegExp;
/** `'rpc-protocol:' + name`. */
export function rpcProtocolFeature(name: string): string;
/** Read the rpc advertisement out of `ServerHello.features` (`client.features`). */
export function parseRpcFeatures(features?: string[]): { enabled: boolean; protocols: string[]; maxMessageBytes: number };

/** JSON-RPC's reserved error codes plus wsh's. */
export const RPC_ERROR: Readonly<{
  PARSE: -32700;
  INVALID_REQUEST: -32600;
  METHOD_NOT_FOUND: -32601;
  INVALID_PARAMS: -32602;
  INTERNAL: -32603;
  /** The host does not serve the requested protocol. */
  UNSUPPORTED_PROTOCOL: -32000;
  /** Cancelled (`$/cancel`, a timeout, or the channel closing: see `RpcError.reason`). */
  CANCELLED: -32001;
  /** Too many requests in flight on the channel. */
  STREAM_LIMIT: -32002;
  /** Refused on policy grounds (confinement, read-only, a handler's own authorization). */
  UNAUTHORIZED: -32003;
}>;

/** A JSON-RPC error: what `request()` rejects with, and what a handler throws to answer with one. */
export class RpcError extends Error {
  constructor(code: number, message: string, data?: unknown, reason?: string);
  readonly code: number;
  readonly data?: unknown;
  /** A short machine-readable cause: `channel-closed`, `timeout`, `cancelled`, `aborted`, `message-too-large`, `UNSUPPORTED_PROTOCOL`. */
  readonly reason?: string;
  toJSON(): { code: number; message: string; data?: unknown };
}

/** Incremental decoder for a CBOR sequence (RFC 8742); feed bytes, get completed items. */
export class CborSequenceDecoder {
  constructor(opts?: { maxItemBytes?: number });
  feed(chunk: Uint8Array): unknown[];
  /** Bytes buffered towards an incomplete item. */
  readonly pending: number;
}

/** What a request handler receives beside the params. */
export interface RpcContext {
  readonly id: string | number;
  readonly method: string;
  /** Aborts on `$/cancel` or channel close. */
  readonly signal: AbortSignal;
  readonly channel: RpcChannel;
  /** Send a `$/progress` chunk for this request (resolves once written; no-op after cancel). */
  progress(chunk: unknown): Promise<void>;
}

export interface RpcRequestOptions {
  onProgress?: (chunk: any) => void;
  signal?: AbortSignal;
  /** Overrides the channel's default timeout; on expiry the request rejects with `-32001` / `timeout` and the callee is told. */
  timeoutMs?: number;
  /** Use this JSON-RPC id instead of the channel's counter (it must not be in flight). */
  id?: string | number;
}

/** A pending request: a promise that also knows its id and can be cancelled. */
export interface RpcRequestPromise<T = any> extends Promise<T> {
  readonly id: string | number;
  cancel(reason?: string): boolean;
}

export interface RpcChannelOptions {
  write(bytes: Uint8Array): Promise<void> | void;
  close?(): Promise<void> | void;
  maxMessageBytes?: number;
  timeoutMs?: number;
  maxInflight?: number;
  /** For a metered transport (virtual-mode rpc): called with the received bytes taken in and dispatched, so credit can be returned. */
  onConsumed?: (bytes: number) => void;
}

/**
 * One end of a typed RPC channel: JSON-RPC 2.0 over a CBOR sequence on one QMux stream. Symmetric -- either side may
 * request, notify and answer. Binary values are `Uint8Array`.
 */
export class RpcChannel {
  constructor(opts: RpcChannelOptions);
  /** The `WshSession` carrying this channel (client side, from `openRpc`). */
  session?: WshSession;
  readonly closed: boolean;
  readonly closeReason: string | null;
  readonly maxMessageBytes: number;
  readonly pendingCount: number;
  readonly inflightCount: number;
  /** Called once when the channel ends. */
  onClose: ((reason: string) => void) | null;

  request<T = any>(method: string, params?: unknown, opts?: RpcRequestOptions): RpcRequestPromise<T>;
  notify(method: string, params?: unknown): Promise<void>;
  /** Cancel an outbound request: `$/cancel` to the callee, `-32001` locally, late responses dropped. */
  cancel(id: string | number, reason?: string): boolean;
  onRequest(method: string, handler: (params: any, ctx: RpcContext) => unknown): () => void;
  onNotification(method: string, handler: (params: any) => void): () => void;
  onProgress(id: string | number, fn: (chunk: any) => void): void;
  setFallbackRequestHandler(fn: ((method: string, params: any, ctx: RpcContext) => unknown) | null): void;
  setFallbackNotificationHandler(fn: ((method: string, params: any) => void) | null): void;
  /** Pending requests reject with `-32001` / `channel-closed`; the stream is closed. */
  close(reason?: string): Promise<void>;
  /** Transport hooks. */
  feed(bytes: Uint8Array): void;
  handleClose(reason?: string): void;
  hold(): void;
  release(): void;
}

/**
 * An MCP SDK `Transport` (structural -- the SDK is not imported) over an {@link RpcChannel}.
 * `await mcpClient.connect(mcpClientTransport(await client.openRpc('mcp')))`.
 */
export class RpcMcpTransport {
  constructor(channel: RpcChannel);
  readonly channel: RpcChannel;
  sessionId?: string;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: any, extra?: any) => void;
  start(): Promise<void>;
  send(message: any, options?: any): Promise<void>;
  close(): Promise<void>;
}
/** A transport for an MCP `Client` over a channel from `openRpc('mcp')`. */
export function mcpClientTransport(channel: RpcChannel): RpcMcpTransport;
/** A transport for an MCP `Server` over a server-side channel (`mcpServerAdapter` wraps this). */
export function mcpServerTransport(channel: RpcChannel): RpcMcpTransport;

/** A wsh protocol control message (all messages have a numeric `type`). */
export interface WshMessage {
  type: number;
  [key: string]: unknown;
}

// -- Message constructors (handshake) --

export function hello(opts?: {
  username?: string;
  features?: string[];
  authMethod?: string;
}): WshMessage;

export function serverHello(opts?: {
  sessionId?: string;
  features?: string[];
  fingerprints?: string[];
}): WshMessage;

export function challenge(opts?: {
  nonce?: Uint8Array;
  sessionId?: string;
}): WshMessage;

export function authMethods(opts?: {
  methods?: string[];
}): WshMessage;

export function auth(opts?: {
  method?: string;
  signature?: Uint8Array;
  publicKey?: Uint8Array;
  password?: string;
}): WshMessage;

export function authOk(opts?: {
  sessionId?: string;
  token?: Uint8Array;
  ttl?: number;
}): WshMessage;

export function authFail(opts?: {
  reason?: string;
}): WshMessage;

// -- Message constructors (channel) --

export function open(opts?: {
  kind?: string;
  command?: string;
  cols?: number;
  rows?: number;
  env?: Record<string, string>;
  stdio?: string;
  /** #121: the host's execution target (only to a host that advertises `targets`). */
  target?: string;
}): WshMessage;

export function openOk(opts?: {
  channelId?: number;
  streamIds?: number[];
  dataMode?: string;
  capabilities?: string[];
  sessionId?: string;
  token?: Uint8Array;
}): WshMessage;

export function openFail(opts?: {
  reason?: string;
}): WshMessage;

export function resize(opts?: {
  channelId?: number;
  cols?: number;
  rows?: number;
}): WshMessage;

export function signal(opts?: {
  channelId?: number;
  signal?: string;
}): WshMessage;

export function exit(opts?: {
  channelId?: number;
  code?: number;
}): WshMessage;

export function close(opts?: {
  channelId?: number;
}): WshMessage;

export function sessionData(opts?: {
  channelId?: number;
  data?: Uint8Array;
}): WshMessage;

// -- Message constructors (transport) --

export function error(opts?: {
  code?: number | string;
  message?: string;
}): WshMessage;

export function ping(opts?: {
  id?: number;
}): WshMessage;

export function pong(opts?: {
  id?: number;
}): WshMessage;

// -- Message constructors (session) --

export function attach(opts?: {
  sessionId?: string;
  token?: Uint8Array;
  mode?: string;
  deviceLabel?: string;
}): WshMessage;

export function resume(opts?: {
  sessionId?: string;
  token?: Uint8Array;
  lastSeq?: number;
}): WshMessage;

export function rename(opts?: {
  sessionId?: string;
  name?: string;
}): WshMessage;

export function idleWarning(opts?: {
  expiresIn?: number;
}): WshMessage;

export function shutdown(opts?: {
  reason?: string;
  retryAfter?: number;
}): WshMessage;

export function snapshot(opts?: {
  label?: string;
}): WshMessage;

export function presence(opts?: {
  attachments?: unknown;
}): WshMessage;

export function controlChanged(opts?: {
  newController?: string;
}): WshMessage;

export function metrics(opts?: {
  cpu?: number;
  memory?: number;
  sessions?: number;
  rtt?: number;
}): WshMessage;

// -- Message constructors (MCP) --

export function mcpDiscover(): WshMessage;

export function mcpTools(opts?: {
  tools?: unknown[];
}): WshMessage;

export function mcpCall(opts?: {
  tool?: string;
  arguments?: Record<string, unknown>;
  /** Correlates this call with its McpResult. Omitted from the message entirely when undefined. */
  callId?: string;
}): WshMessage;

export function mcpCancel(opts?: {
  /** The `call_id` of the McpCall to stop. */
  callId?: string;
}): WshMessage;

export function mcpResult(opts?: {
  result?: unknown;
  /** Echoed verbatim from the McpCall this answers. */
  callId?: string;
}): WshMessage;

// -- Message constructors (reverse) --

export function reverseRegister(opts?: {
  username?: string;
  capabilities?: string[];
  peerType?: string;
  shellBackend?: string;
  supportsAttach?: boolean;
  supportsReplay?: boolean;
  supportsEcho?: boolean;
  supportsTermSync?: boolean;
  publicKey?: Uint8Array | null;
  /** The signing peer's own monotonic counter for its signed peer record. */
  seq?: number;
  /** Ed25519 signature over the peer record transcript (see signPeerRecord). */
  recordSignature?: Uint8Array;
}): WshMessage;

export function reverseList(): WshMessage;

export function reversePeers(opts?: {
  peers?: unknown[];
}): WshMessage;

export function reverseConnect(opts?: {
  targetFingerprint?: string;
  username?: string;
  fromFingerprint?: string;
}): WshMessage;

export function reverseAccept(opts?: {
  targetFingerprint?: string;
  username?: string;
  capabilities?: string[];
  peerType?: string;
  shellBackend?: string;
  supportsAttach?: boolean;
  supportsReplay?: boolean;
  supportsEcho?: boolean;
  supportsTermSync?: boolean;
  /** Features of this (bridged) host, in the vocabulary of `ServerHello.features`; omit rather than send `[]`. */
  features?: string[];
}): WshMessage;

export function reverseReject(opts?: {
  targetFingerprint?: string;
  username?: string;
  reason?: string;
}): WshMessage;

export function relayForward(opts?: {
  fromFingerprint?: string;
  inner?: Uint8Array;
  /** Peer -> relay: the operator this is for, when the peer serves several (wsh #89). */
  toFingerprint?: string;
}): WshMessage;

/** Relay -> peer: one operator of a multi-operator peer left (wsh #89). */
export function reverseClose(opts?: {
  targetFingerprint?: string;
  reason?: string;
}): WshMessage;

/** Message types a relay may forward inside a RelayForward wrapper. */
export const RELAY_FORWARDABLE: ReadonlySet<number>;

export function isRelayForwardable(typeNum: number): boolean;

/**
 * Message types a relay carries only for a bridge whose peer stated `relay-gateway` (and only on a relay that lists it): the gateway's
 * requests and their answers. Not part of `RELAY_FORWARDABLE`.
 */
export const RELAY_GATEWAY_FORWARDABLE: ReadonlySet<number>;

export function isRelayGatewayForwardable(typeNum: number): boolean;

// -- Message constructors (gateway) --

export function openTcp(opts?: {
  gatewayId?: number;
  host?: string;
  port?: number;
}): WshMessage;

export function openUdp(opts?: {
  gatewayId?: number;
  host?: string;
  port?: number;
}): WshMessage;

export function resolveDns(opts?: {
  gatewayId?: number;
  name?: string;
  recordType?: string;
}): WshMessage;

export function gatewayOk(opts?: {
  gatewayId?: number;
  resolvedAddr?: string;
}): WshMessage;

export function gatewayFail(opts?: {
  gatewayId?: number;
  code?: number | string;
  message?: string;
}): WshMessage;

export function gatewayClose(opts?: {
  gatewayId?: number;
  reason?: string;
}): WshMessage;

export function inboundOpen(opts?: {
  listenerId?: number;
  channelId?: number;
  peerAddr?: string;
  peerPort?: number;
}): WshMessage;

export function inboundAccept(opts?: {
  channelId?: number;
  gatewayId?: number;
}): WshMessage;

export function inboundReject(opts?: {
  channelId?: number;
  reason?: string;
}): WshMessage;

export function dnsResult(opts?: {
  gatewayId?: number;
  addresses?: string[];
  ttl?: number;
}): WshMessage;

export function listenRequest(opts?: {
  listenerId?: number;
  port?: number;
  bindAddr?: string;
}): WshMessage;

export function listenOk(opts?: {
  listenerId?: number;
  actualPort?: number;
}): WshMessage;

export function listenFail(opts?: {
  listenerId?: number;
  reason?: string;
}): WshMessage;

export function listenClose(opts?: {
  listenerId?: number;
}): WshMessage;

export function gatewayData(opts?: {
  gatewayId?: number;
  data?: Uint8Array;
}): WshMessage;

// -- Message constructors (session extras) --

export function clipboard(opts?: {
  direction?: string;
  data?: string;
}): WshMessage;

export function recordingExport(opts?: {
  sessionId?: string;
  format?: string;
  data?: string;
}): WshMessage;

export function commandJournal(opts?: {
  sessionId?: string;
  command?: string;
  exitCode?: number;
  durationMs?: number;
  cwd?: string;
  timestamp?: number;
}): WshMessage;

export function metricsRequest(): WshMessage;

export function suspendSession(opts?: {
  sessionId?: string;
  action?: string;
}): WshMessage;

export function restartPty(opts?: {
  sessionId?: string;
  command?: string;
}): WshMessage;

export function sessionListRequest(): WshMessage;

export function listTargets(): WshMessage;

export function targetList(opts?: {
  targets?: WshTargetInfo[];
}): WshMessage;

export function sessionList(opts?: {
  sessions?: unknown[];
}): WshMessage;

export function detach(opts?: {
  sessionId?: string;
}): WshMessage;

export function detachOk(opts?: {
  sessionId?: string;
}): WshMessage;

export function detachFail(opts?: {
  reason?: string;
}): WshMessage;

// -- Message constructors (guest sharing) --

export function guestInvite(opts?: {
  sessionId?: string;
  ttl?: number;
  permissions?: string[];
}): WshMessage;

export function guestJoin(opts?: {
  token?: string;
  deviceLabel?: string;
}): WshMessage;

export function guestRevoke(opts?: {
  token?: string;
  reason?: string;
}): WshMessage;

export function shareSession(opts?: {
  sessionId?: string;
  mode?: string;
  ttl?: number;
}): WshMessage;

export function shareRevoke(opts?: {
  shareId?: string;
  reason?: string;
}): WshMessage;

// -- Message constructors (compression / rate control / linking) --

export function compressBegin(opts?: {
  algorithm?: string;
  level?: number;
}): WshMessage;

export function compressAck(opts?: {
  algorithm?: string;
  accepted?: boolean;
}): WshMessage;

export function rateControl(opts?: {
  sessionId?: string;
  maxBytesPerSec?: number;
  policy?: string;
}): WshMessage;

export function rateWarning(opts?: {
  sessionId?: string;
  queuedBytes?: number;
  action?: string;
}): WshMessage;

export function sessionLink(opts?: {
  sourceSession?: string;
  targetHost?: string;
  targetPort?: number;
  targetUser?: string;
}): WshMessage;

export function sessionUnlink(opts?: {
  linkId?: string;
  reason?: string;
}): WshMessage;

// -- Message constructors (copilot) --

export function copilotAttach(opts?: {
  sessionId?: string;
  model?: string;
  contextWindow?: number;
}): WshMessage;

export function copilotSuggest(opts?: {
  sessionId?: string;
  suggestion?: string;
  confidence?: number;
}): WshMessage;

export function copilotDetach(opts?: {
  sessionId?: string;
  reason?: string;
}): WshMessage;

// -- Message constructors (e2e / echo / termsync) --

export function keyExchange(opts?: {
  algorithm?: string;
  publicKey?: Uint8Array;
  sessionId?: string;
  kemPublicKey?: Uint8Array;
  kemCiphertext?: Uint8Array;
  /** Round 1 only: the sender's Ed25519 signature over the exchange (see the spec's KeyExchange). */
  signature?: Uint8Array;
}): WshMessage;

export function encryptedFrame(opts?: {
  nonce?: Uint8Array;
  ciphertext?: Uint8Array;
  sessionId?: string;
}): WshMessage;

export function echoAck(opts?: {
  channelId?: number;
  echoSeq?: number;
}): WshMessage;

export function echoState(opts?: {
  channelId?: number;
  echoSeq?: number;
  cursorX?: number;
  cursorY?: number;
  pending?: number;
}): WshMessage;

export function termSync(opts?: {
  channelId?: number;
  frameSeq?: number;
  stateHash?: Uint8Array;
}): WshMessage;

export function termDiff(opts?: {
  channelId?: number;
  frameSeq?: number;
  baseSeq?: number;
  patch?: Uint8Array;
}): WshMessage;

// -- Message constructors (scaling / principals) --

export function nodeAnnounce(opts?: {
  nodeId?: string;
  endpoint?: string;
  load?: number;
  capacity?: number;
}): WshMessage;

export function nodeRedirect(opts?: {
  targetNode?: string;
  targetEndpoint?: string;
  sessionId?: string;
  reason?: string;
}): WshMessage;

export function sessionGrant(opts?: {
  sessionId?: string;
  principal?: string;
  permissions?: string[];
}): WshMessage;

export function sessionRevoke(opts?: {
  sessionId?: string;
  principal?: string;
  reason?: string;
}): WshMessage;

// -- Message constructors (file channel / policy / terminal) --

export function fileOp(opts?: {
  channelId?: number;
  op?: string;
  path?: string;
  offset?: number;
  length?: number;
  /** #121: the host's execution target (only to a host that advertises `targets`). */
  target?: string;
}): WshMessage;

export function fileResult(opts?: {
  channelId?: number;
  success?: boolean;
  metadata?: Record<string, unknown>;
  /** wsh #59: typed directory entries for a "list" op (see WshFileListEntry-shaped wire fields). */
  entries?: Array<{
    name: string;
    size: number;
    modified: number;
    type: 'file' | 'directory' | 'symlink' | 'device' | 'pipe' | 'socket';
    symlink_target?: string;
  }>;
  errorMessage?: string;
}): WshMessage;

export function fileChunk(opts?: {
  channelId?: number;
  offset?: number;
  data?: Uint8Array;
  isFinal?: boolean;
  totalSize?: number;
}): WshMessage;

/** wsh #59: install a public key into the remote's authorized_keys (see WshClient.addAuthorizedKey). */
export function authorizedKeyAdd(opts?: {
  publicKey?: Uint8Array;
  comment?: string;
}): WshMessage;

export function authorizedKeyResult(opts?: {
  success?: boolean;
  added?: boolean;
  errorMessage?: string;
}): WshMessage;

export function policyEval(opts?: {
  requestId?: string;
  action?: string;
  principal?: string;
  context?: Record<string, unknown>;
}): WshMessage;

export function policyResult(opts?: {
  requestId?: string;
  allowed?: boolean;
  reason?: string;
}): WshMessage;

export function policyUpdate(opts?: {
  policyId?: string;
  rules?: Record<string, unknown>;
  version?: number;
}): WshMessage;

export function terminalConfig(opts?: {
  channelId?: number;
  frontend?: string;
  options?: Record<string, unknown>;
}): WshMessage;

// -- Utility --

/**
 * Get the human-readable name for a message type number.
 */
export function msgName(typeNum: number): string;

/**
 * Validate that a message has a recognized type field.
 */
export function isValidMessage(msg: unknown): boolean;

// ============================================================================
// auth.mjs -- Ed25519 crypto
// ============================================================================

/**
 * Whether this runtime's WebCrypto implements Ed25519, measured by
 * generating a key rather than sniffed from a version string.
 *
 * There is no pure-JS fallback: one would need the private scalar as
 * ordinary bytes, giving up the non-extractable `CryptoKey` property
 * `WshKeyStore` is built around. Check this before committing to pubkey
 * auth and fall back to password auth where it returns false.
 */
export function isEd25519Supported(): Promise<boolean>;

/**
 * Generate a new Ed25519 key pair. Throws with an actionable message
 * where WebCrypto has no Ed25519 -- see `isEd25519Supported()`.
 * @param extractable - Whether private key can be exported (default false)
 */
export function generateKeyPair(extractable?: boolean): Promise<CryptoKeyPair>;

/**
 * Export public key as raw 32-byte Ed25519 point.
 */
export function exportPublicKeyRaw(publicKey: CryptoKey): Promise<Uint8Array>;

/**
 * Export public key in SSH wire format: ssh-ed25519 AAAA...
 */
export function exportPublicKeySSH(publicKey: CryptoKey): Promise<string>;

/**
 * Import a raw 32-byte Ed25519 public key.
 */
export function importPublicKeyRaw(raw: Uint8Array): Promise<CryptoKey>;

/**
 * Export private key as PKCS8 bytes.
 * @param privateKey - Must have been created with extractable=true
 */
export function exportPrivateKeyPKCS8(privateKey: CryptoKey): Promise<Uint8Array>;

/**
 * Import a PKCS8-encoded Ed25519 private key.
 */
export function importPrivateKeyPKCS8(pkcs8: Uint8Array, extractable?: boolean): Promise<CryptoKey>;

/**
 * Sign data with an Ed25519 private key. Positional order mirrors WebCrypto
 * (`sign(privateKey, message)`) and is the canonical form across wsh, raijin
 * and browsermesh.
 * @returns 64-byte signature
 */
export function sign(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array>;

/**
 * Verify an Ed25519 signature. Positional order mirrors WebCrypto
 * (`verify(publicKey, signature, message)`) and is the canonical form across
 * wsh, raijin and browsermesh.
 */
export function verify(publicKey: CryptoKey, signature: Uint8Array, message: Uint8Array): Promise<boolean>;

/** Options binding extra context into the auth transcript. */
export interface WshTranscriptOptions {
  /** Username this transcript is bound to (default ''). */
  username?: string;
  /** Reserved for a transport-layer identity binding; no caller populates it yet. */
  channelBinding?: Uint8Array;
}

/**
 * Build the authentication transcript hash for challenge-response signing.
 *
 * transcript = SHA-256(
 *   "wsh-v1\0" || lp(username) || lp(session_id) || nonce || channel_binding
 * )
 *
 * where lp() is a 4-byte big-endian length prefix on the variable-length
 * string fields.
 *
 * @returns 32-byte SHA-256 hash
 */
export function buildTranscript(
  sessionId: string,
  nonce: Uint8Array,
  opts?: WshTranscriptOptions,
): Promise<Uint8Array>;

/**
 * Perform the full client-side auth signing:
 * 1. Build transcript hash
 * 2. Sign with private key
 * 3. Export public key for sending to server
 */
export function signChallenge(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  sessionId: string,
  nonce: Uint8Array,
  opts?: WshTranscriptOptions,
): Promise<{ signature: Uint8Array; publicKeyRaw: Uint8Array }>;

/**
 * A signer that need not expose a private key: a wallet, a hardware token, a Worker.
 * `publicKey` is the raw 32-byte Ed25519 key or a public `CryptoKey`; `sign` returns the 64-byte signature.
 */
export interface WshSigner {
  publicKey: Uint8Array | CryptoKey;
  sign(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** A `keyPair` or `signer` normalized to a raw public key and an async `sign`; `null` when neither is given. */
export interface WshResolvedSigner {
  publicKeyRaw: Uint8Array;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/** Normalize `{ keyPair }` or `{ signer }`. Throws a TypeError for both together or a malformed signer. */
export function resolveSigner(credentials?: { keyPair?: CryptoKeyPair; signer?: WshSigner }): Promise<WshResolvedSigner | null>;

/** `signChallenge` for a signer resolved by `resolveSigner`. */
export function signChallengeWith(
  signer: WshResolvedSigner,
  sessionId: string,
  nonce: Uint8Array,
  opts?: WshTranscriptOptions,
): Promise<{ signature: Uint8Array; publicKeyRaw: Uint8Array }>;

/** `signPeerRecord` for a signer resolved by `resolveSigner`. */
export function signPeerRecordWith(
  signer: WshResolvedSigner,
  record: WshPeerRecord,
): Promise<{ signature: Uint8Array; publicKeyRaw: Uint8Array }>;

/**
 * Server-side: verify a client's challenge response.
 */
export function verifyChallenge(
  publicKey: CryptoKey,
  signature: Uint8Array,
  sessionId: string,
  nonce: Uint8Array,
  opts?: WshTranscriptOptions,
): Promise<boolean>;

/** Fields of a signed peer record (reverse-mode registration). See `signPeerRecord`. */
export interface WshPeerRecord {
  username: string;
  peerType?: string;
  shellBackend?: string;
  capabilities?: string[];
  supportsAttach?: boolean;
  supportsReplay?: boolean;
  supportsEcho?: boolean;
  supportsTermSync?: boolean;
  /** The signing peer's own monotonic counter (current-time-millis in practice). */
  seq: number;
}

/**
 * Build the signed transcript for a peer record -- domain-separated from
 * `buildTranscript`'s auth-challenge transcript even under the same key.
 * @returns 32-byte SHA-256 hash
 */
export function buildPeerRecordTranscript(record: WshPeerRecord): Promise<Uint8Array>;

/** Client-side: sign a peer record with the identity key pair. */
export function signPeerRecord(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  record: WshPeerRecord,
): Promise<{ signature: Uint8Array; publicKeyRaw: Uint8Array }>;

/** Verify a peer record's signature against the claimed record fields. */
export function verifyPeerRecord(publicKey: CryptoKey, signature: Uint8Array, record: WshPeerRecord): Promise<boolean>;

/**
 * Compute the SHA-256 fingerprint of a raw public key.
 * @returns hex-encoded fingerprint
 */
export function fingerprint(publicKeyRaw: Uint8Array): Promise<string>;

/**
 * The BrowserMesh pod ID of a raw public key: base64url (no padding, 43
 * characters) of the SHA-256 of the 32 raw key bytes. For the same key this
 * equals `@johnhenry/browsermesh-primitives`' `derivePodId(cryptoKey)` /
 * `PodIdentity.podId`, and is the same hash as `fingerprint()` in a different
 * encoding (hex there, base64url here).
 */
export function podId(publicKeyRaw: Uint8Array): Promise<string>;

/**
 * Re-encode a hex `fingerprint()` as a pod ID (pure; no hashing).
 * @throws TypeError if the argument is not an even-length hex string
 */
export function fingerprintToPodId(hexFingerprint: string): string;

/**
 * Re-encode a pod ID as the hex `fingerprint()` of the same key (pure; no hashing).
 */
export function podIdToFingerprint(podId: string): string;

/**
 * Get the shortest unique prefix of a fingerprint within a set.
 */
export function shortFingerprint(
  fp: string,
  allFingerprints?: string[],
  minLen?: number,
): string;

/**
 * Generate a random 32-byte nonce.
 */
export function generateNonce(): Uint8Array;

/**
 * Parse an SSH public key string ("ssh-ed25519 AAAA... comment").
 */
export function parseSSHPublicKey(line: string): {
  type: string;
  data: Uint8Array;
  comment: string;
} | null;

/**
 * Extract the raw 32-byte Ed25519 public key from SSH wire format.
 */
export function extractRawFromSSHWire(wireData: Uint8Array): Uint8Array;

/**
 * Decode a base64-encoded string into bytes.
 */
export function base64Decode(str: string): Uint8Array;

// ============================================================================
// transport.mjs -- Abstract transport + WebTransport implementation
// ============================================================================

/** A bidirectional data stream handle. */
export interface WshStream {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  id: number;
}

/**
 * Abstract transport for the wsh protocol.
 *
 * Subclasses must implement:
 *   - _doConnect(url)
 *   - _doClose()
 *   - _doSendControl(msg)
 *   - _doOpenStream()
 */
export class WshTransport {
  /** Callback for incoming control messages. */
  onControl: ((msg: WshMessage) => void) | null;

  /** Callback for server-initiated streams. */
  onStreamOpen: ((stream: WshStream) => void) | null;

  /** Callback when transport closes; the argument, when the transport knows why, is the close info (#240). */
  onClose: ((info?: WshCloseInfo) => void) | null;

  /** Why the connection closed, when the peer or the network ended it; `null` before a close and after a close this side made. */
  readonly closeInfo: WshCloseInfo | null;

  /** Callback on transport error. */
  onError: ((err: Error) => void) | null;

  /** Callback for an unreliable datagram (WebTransport only). */
  onDatagram: ((bytes: Uint8Array) => void) | null;
  /** True where the transport can carry unreliable datagrams (WebTransport). */
  readonly supportsDatagrams: boolean;
  /** The largest datagram the connection can carry now, in bytes (0 = none). Read it again before sending. */
  readonly maxDatagramSize: number;
  /** Send one datagram without waiting or queueing; false = dropped. */
  sendDatagram(bytes: Uint8Array): boolean;

  /** Current transport state. */
  readonly state: 'disconnected' | 'connecting' | 'connected' | 'closed';

  /** Connect to a wsh server. */
  connect(url: string, options?: object): Promise<void>;

  /** Gracefully close the transport. */
  close(): Promise<void>;

  /** Send a control message (CBOR-framed). */
  sendControl(msg: object): Promise<void>;

  /** Open a new bidirectional data stream. */
  openStream(): Promise<WshStream>;

  /** @protected Update internal state. */
  protected _setState(s: string): void;

  /** @protected Emit a control message to the callback. */
  protected _emitControl(msg: WshMessage): void;

  /** @protected Emit a new server-initiated stream. */
  protected _emitStreamOpen(stream: WshStream): void;

  /** @protected Emit close event. */
  protected _emitClose(): void;

  /** @protected Emit error event. */
  protected _emitError(err: Error): void;

  /** @protected Must be overridden by subclasses. */
  protected _doConnect(url: string, options?: object): Promise<void>;

  /** @protected Must be overridden by subclasses. */
  protected _doClose(): Promise<void>;

  /** @protected Must be overridden by subclasses. */
  protected _doSendControl(msg: object): Promise<void>;

  /** @protected Must be overridden by subclasses. */
  protected _doOpenStream(): Promise<WshStream>;
}

/**
 * wsh transport over the WebTransport API.
 *
 * - The first bidirectional stream becomes the control stream.
 * - Control messages use length-prefixed CBOR (frameEncode / FrameDecoder).
 * - Subsequent streams carry raw byte data (no framing).
 * - Server-initiated streams are surfaced via onStreamOpen.
 */
export class WebTransportTransport extends WshTransport {
  /**
   * @param options Forwarded to the `WebTransport` constructor. Options
   *   passed to `connect()` override these per call.
   */
  constructor(options?: WshWebTransportOptions);

  connect(url: string, options?: WshWebTransportOptions): Promise<void>;
}

/**
 * One entry of `serverCertificateHashes`. The digest may be given as raw
 * bytes, as hex (with or without `:` separators -- what
 * `openssl x509 -fingerprint -sha256` prints), or as base64/base64url.
 */
export interface WshCertificateHash {
  /** Defaults to `'sha-256'`, the only algorithm the platform accepts today. */
  algorithm?: string;
  value: BufferSource | string;
}

/**
 * Options forwarded to the `WebTransport` constructor.
 *
 * `serverCertificateHashes` is the interesting one: it pins a specific
 * self-signed certificate by digest, which is the only mechanism in the
 * web platform that lets page JavaScript reach a server whose certificate
 * no certificate authority signed. The platform's own constraints apply --
 * `https:` URL, HTTP/3 only, ECDSA P-256 key, at most 14 days validity,
 * no connection pooling.
 *
 * Every other key is forwarded verbatim, so platform options not listed
 * here still work.
 */
export interface WshWebTransportOptions {
  serverCertificateHashes?: Array<WshCertificateHash | BufferSource | string>;
  allowPooling?: boolean;
  requireUnreliable?: boolean;
  congestionControl?: 'default' | 'throughput' | 'low-latency';
  anticipatedConcurrentIncomingUnidirectionalStreams?: number | null;
  anticipatedConcurrentIncomingBidirectionalStreams?: number | null;
  protocols?: string[];
  [key: string]: unknown;
}

/**
 * Decode one `serverCertificateHashes` digest into bytes. Accepts a
 * `BufferSource`, hex (separators and an `... Fingerprint=` prefix are
 * stripped), or base64/base64url. Throws a `TypeError` on an
 * unrecognised shape and a `RangeError` on a digest of the wrong length
 * for the algorithm.
 */
export function parseCertificateHash(value: BufferSource | string, algorithm?: string): Uint8Array;

/**
 * Normalise a caller-supplied options bag into a `WebTransportOptions`
 * dictionary, or `undefined` when there is nothing to pass.
 */
export function normalizeWebTransportOptions(options?: WshWebTransportOptions): object | undefined;

/**
 * Dispatch a fixed, already-available batch of items one at a time,
 * fully awaiting each handler call before dispatching the next. Use
 * SerialQueue instead for items arriving incrementally via a push
 * callback.
 */
export function dispatchSerially<T>(
  items: Iterable<T>,
  handler: (item: T) => void | Promise<void>,
): Promise<void>;

/**
 * A queue drained one item at a time, awaiting each dispatch before
 * starting the next. Use where items arrive incrementally over time via
 * a push callback (e.g. a transport's raw `message` event).
 */
export class SerialQueue<T = unknown> {
  constructor(handler: (item: T) => void | Promise<void>);
  push(item: T): void;
}

// ============================================================================
// transport-ws.mjs -- WebSocket transport
// ============================================================================

/**
 * wsh transport over a single WebSocket, multiplexed with QMux
 * (draft-ietf-quic-qmux-02). The control channel is QMux stream 0.
 *
 * Provides the same interface as WebTransportTransport so that upper
 * layers (session, client) work identically over either transport.
 */
export class WebSocketTransport extends WshTransport {
  /** `WebSocket`: a constructor to dial with instead of the global one (a test double, `createMemoryHost().WebSocket`). */
  constructor(options?: { WebSocket?: new (url: string) => any });
}

/**
 * @deprecated The old hand-rolled 5-byte mux's frame-type byte values.
 * wsh now speaks QMux instead; this export is kept only for source
 * compatibility and is no longer produced or consumed anywhere.
 */
export const WS_FRAME_TYPE: {
  readonly CONTROL: 0x01;
  readonly DATA: 0x02;
  readonly OPEN_STREAM: 0x03;
  readonly CLOSE_STREAM: 0x04;
};

// ============================================================================
// qmux.mjs / qmux-connection.mjs -- QMux multiplexing layer
// ============================================================================

/** Default QMux flow-control parameters. */
export const QMUX_DEFAULTS: {
  /** Connection-wide receive window in bytes (8 MiB). */
  readonly initialMaxData: number;
  /** Per-stream receive window in bytes (1 MiB). */
  readonly initialMaxStreamData: number;
  /** Initial bidirectional stream credit. */
  readonly initialMaxStreamsBidi: number;
};

/** QUIC transport error codes used by wsh (RFC 9000 Section 20.1 subset). */
export const QMUX_ERROR_CODE: {
  readonly NO_ERROR: 0x00;
  readonly INTERNAL_ERROR: 0x01;
  readonly FLOW_CONTROL_ERROR: 0x03;
  readonly STREAM_LIMIT_ERROR: 0x04;
  readonly STREAM_STATE_ERROR: 0x05;
  readonly FINAL_SIZE_ERROR: 0x06;
  readonly FRAME_ENCODING_ERROR: 0x07;
  readonly TRANSPORT_PARAMETER_ERROR: 0x08;
  readonly PROTOCOL_VIOLATION: 0x0a;
  readonly APPLICATION_ERROR: 0x0c;
};

/** Stream-initiator bit values (QUIC stream-id low bit). */
export const QMUX_STREAM_INITIATOR: {
  readonly CLIENT: 0;
  readonly SERVER: 1;
};

/** First bidirectional stream ID for the given initiator (0 or 1). */
export function firstBidiStreamId(initiator: 0 | 1): number;

/** Next bidirectional stream ID after `id` for the same initiator (+4). */
export function nextBidiStreamId(id: number): number;

/** Whether a stream ID was opened by the client side. */
export function isClientInitiated(streamId: number): boolean;

/** Whether a stream ID is bidirectional (wsh only uses bidi streams). */
export function isBidirectional(streamId: number): boolean;

/**
 * One multiplexed QMux stream: a minimal push/pull data API (not DOM
 * Streams -- WebSocketTransport wraps these in ReadableStream/
 * WritableStream for the rest of wsh).
 */
export interface QMuxStream {
  /** Stream ID. */
  id: number;

  /** In-order data delivery. */
  onData: ((data: Uint8Array) => void) | null;

  /** Clean FIN: all data delivered. */
  onEnd: (() => void) | null;

  /** Peer aborted (after any reliable prefix was delivered). */
  onReset: ((errorCode: number) => void) | null;

  /** The whole connection died (transport closed/errored). */
  onDestroy: ((err: Error) => void) | null;

  /** Send state: 'ready' | 'send' | 'reset_sent' | 'data_sent'. */
  readonly sendState: string;

  /** Receive state: 'recv' | 'size_known' | 'data_recvd' | 'reset_recvd'. */
  readonly recvState: string;

  /** Write bytes, awaiting flow-control window as needed. */
  write(bytes: Uint8Array): Promise<void>;

  /** Half-close the send side (send FIN). */
  close(): Promise<void>;

  /**
   * Abort the send side. A non-zero `reliableSize` uses RESET_STREAM_AT
   * (draft-ietf-quic-reliable-stream-reset) to guarantee that prefix is
   * still delivered.
   */
  reset(errorCode?: number, reliableSize?: number): void;

  /** Tell the peer to stop sending. */
  stopSending(errorCode?: number): void;
}

/**
 * QMux connection: stream state machine + windowed flow control over an
 * ordered, reliable byte stream. Transport-agnostic -- it takes a
 * `send(bytes)` callback for outbound record bytes and is fed inbound
 * bytes via `receiveBytes()`. Exported so alternate server
 * implementations can speak the same framing as WebSocketTransport.
 */
export class QMuxConnection {
  constructor(opts: {
    /** Whether this endpoint is the client (determines stream-id parity). */
    isClient: boolean;
    /** Callback receiving encoded QMux record bytes to transmit. */
    send: (bytes: Uint8Array) => void;
    initialMaxData?: number;
    initialMaxStreamData?: number;
    initialMaxStreamsBidi?: number;
  });

  /** Called for peer-initiated streams. */
  onStreamOpen: ((stream: QMuxStream) => void) | null;

  /** Called for DATAGRAM frames. */
  onDatagram: ((data: Uint8Array) => void) | null;

  /** Called on peer CONNECTION_CLOSE. */
  onClose: ((errorCode: number, reason: string) => void) | null;

  /** Called on protocol errors. */
  onError: ((err: Error) => void) | null;

  /** Send the QX_TRANSPORT_PARAMETERS handshake frame -- must be the first frame sent. */
  sendHandshake(): void;

  /** Open a new locally-initiated bidirectional stream. */
  openStream(): Promise<QMuxStream>;

  /** Look up an existing stream by ID. */
  getStream(id: number): QMuxStream | undefined;

  /** Send a DATAGRAM frame. */
  sendDatagram(bytes: Uint8Array): void;

  /** Feed inbound bytes from the underlying transport. */
  receiveBytes(chunk: Uint8Array): void;

  /** Send CONNECTION_CLOSE and shut down. */
  close(errorCode?: number, reason?: string): void;

  /** Forcibly tear down every stream (transport died; nothing is sent). */
  destroy(err: Error): void;
}

// ============================================================================
// session.mjs -- WshSession
// ============================================================================

/**
 * Manages a single PTY or exec channel over a wsh transport.
 *
 * Each session owns a pair of data streams (stdin/stdout) and receives
 * control messages (EXIT, CLOSE, RESIZE) dispatched by the parent WshClient.
 */
export class WshSession {
  /** Unique session identifier (typically matches channelId). */
  id: string;

  /** Channel kind. */
  kind: 'pty' | 'exec';

  /** Channel identifier assigned by the server. */
  channelId: number;

  /** Current session state. */
  readonly state: 'opening' | 'active' | 'closed';

  /** Exit code, if the process has exited. */
  readonly exitCode: number | null;

  /** Session data plane. */
  readonly dataMode: 'stream' | 'virtual';

  /** Session capabilities advertised by OPEN_OK. */
  readonly capabilities: string[];

  /**
   * The server-assigned session_id this channel belongs to, from OPEN_OK
   * (clawser #48). `undefined` for channel kinds with no Attach/Resume-able
   * session (e.g. file channels). Pass to `WshClient.attachSession`/
   * `resumeSession` from another connection.
   */
  readonly sessionId: string | undefined;

  /**
   * The session-scoped resume token minted at Open time, if any (clawser
   * #48). Pass to `WshClient.resumeSession` from a later connection to
   * reclaim this exact session.
   */
  readonly resumeToken: Uint8Array | undefined;

  /**
   * Cumulative session output bytes received so far -- the host's `seq` for
   * the next byte. Pass it as `lastSeq` to `WshClient.resumeSession()`.
   * Absolute for a session obtained from `attachSession()`/`resumeSession()`.
   */
  readonly seq: number;

  /** Called when stdout/stderr data arrives. */
  onData: ((data: Uint8Array) => void) | null;

  /** stderr of a `stdio: 'pipes'` exec session (the host keeps it apart from stdout). */
  onStderr: ((data: Uint8Array) => void) | null;

  /** Channel id carrying stderr for a `stdio: 'pipes'` session, else undefined. */
  readonly stderrChannelId: number | undefined;

  /** Called when the remote process exits. */
  onExit: ((code: number) => void) | null;

  /**
   * Called when the session is fully closed.
   *
   * Receives the same value as `closeReason`: an Error for a torn-down
   * session, null for an ordinary close.
   */
  onClose: ((reason: Error | null) => void) | null;

  /**
   * Why the session closed, or null for an ordinary close.
   *
   * A torn-down session and a clean exit are otherwise indistinguishable
   * from the outside.
   */
  readonly closeReason: Error | null;

  /** Called when the remote peer acknowledges speculative local echo. */
  onEchoAck: ((payload: Record<string, unknown>) => void) | null;

  /** Called when the remote peer reports current echo/cursor state. */
  onEchoState: ((payload: Record<string, unknown>) => void) | null;

  /** Called when the remote peer emits a terminal sync hash. */
  onTermSync: ((payload: Record<string, unknown>) => void) | null;

  /** Called when the remote peer emits an incremental terminal diff. */
  onTermDiff: ((payload: Record<string, unknown>) => void) | null;

  /** Last echo acknowledgement received for the session. */
  readonly lastEchoAck: Record<string, unknown> | null;

  /** Last echo state received for the session. */
  readonly lastEchoState: Record<string, unknown> | null;

  /** Last terminal sync received for the session. */
  readonly lastTermSync: Record<string, unknown> | null;

  /** Last terminal diff received for the session. */
  readonly lastTermDiff: Record<string, unknown> | null;

  /** Whether `enableE2E()` has been called and E2E sealing is active for this session. */
  readonly e2eEnabled: boolean;

  constructor(
    transport: WshTransport,
    channelId: number,
    streamIds: object,
    kind: 'pty' | 'exec',
    opts?: {
      dataMode?: 'stream' | 'virtual';
      capabilities?: string[];
      sessionId?: string;
      resumeToken?: Uint8Array;
    },
  );

  /**
   * Write data to the session's stdin stream.
   * Accepts a Uint8Array for raw bytes or a string (UTF-8 encoded).
   * Sealed into an EncryptedFrame instead of plaintext SessionData when
   * `enableE2E()` has been called (virtual-mode sessions only).
   */
  write(data: Uint8Array | string): Promise<void>;

  /**
   * Send EOF on stdin without closing the session: output keeps arriving and
   * `onExit`/`onClose` fire as usual. Idempotent; `write()` rejects afterwards.
   * Stream-mode sessions only (throws on a virtual-mode session).
   */
  closeStdin(): Promise<void>;

  /**
   * Opt in to end-to-end encryption for this session's data plane
   * (virtual-mode sessions only). `sharedSecret` must come from a fresh
   * `WshClient.initiateE2E()` call on the *current* connection --
   * E2E state is connection-scoped, not session-scoped, so a session
   * Resumed/Attached on a new connection must run `initiateE2E()` and
   * `enableE2E()` again rather than reusing a prior key.
   */
  enableE2E(sharedSecret: CryptoKey, opts: { role: 'initiator' | 'responder' }): void;

  /**
   * Request the remote PTY to resize.
   */
  resize(cols: number, rows: number): Promise<void>;

  /**
   * Send a signal to the remote process (e.g. 'SIGINT', 'SIGTERM').
   */
  signal(sig: string): Promise<void>;

  /**
   * Close this session. Sends a CLOSE control message and tears down
   * the data streams. Safe to call multiple times.
   */
  close(): Promise<void>;

  /**
   * Bind the raw data streams to this session and start the read pump.
   * Called by WshClient after stream setup.
   * @internal
   */
  _bind(readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>): void;

  /**
   * Activate the message-backed data plane for a virtual session.
   * @internal
   */
  _activateVirtual(sendControl: (msg: WshMessage) => Promise<void>): void;

  /**
   * Handle a control message dispatched by WshClient for this channel.
   * @internal
   */
  _handleControlMessage(msg: WshMessage): void;

  /**
   * Continuously read from the stdout data stream and invoke onData.
   * @internal
   */
  _pumpDataStream(): Promise<void>;
}

export function normalizeSessionData(data: Uint8Array | string): Uint8Array;

export class WshVirtualSessionBackend {
  constructor(sendControl: (msg: WshMessage) => Promise<void>, channelId: number);
  write(data: Uint8Array | string): Promise<void>;
}

// ============================================================================
// client.mjs -- WshClient
// ============================================================================

/** The host identity a server proved it holds (see `WshClient.hostKey`). */
export interface WshHostKey {
  /** Hex SHA-256 of the raw key (same as `fingerprint()` / `ServerHello.host_fingerprint`). */
  fingerprint: string;
  /** Raw 32-byte Ed25519 host public key. */
  publicKey: Uint8Array;
  /** `ssh-ed25519 AAAA...` form, for display or `expectHostKey`. */
  openssh: string;
  /** `pinned` matched `expectHostKey`; `known`/`unknown` per `knownHosts`; `unpinned` = surfaced, nothing checked. */
  status: 'pinned' | 'known' | 'unknown' | 'unpinned';
}

/** Why a host key was refused. */
export type WshHostKeyErrorCode =
  | 'HOST_KEY_MISSING' | 'HOST_KEY_INVALID' | 'HOST_KEY_MISMATCH' | 'HOST_KEY_UNKNOWN' | 'HOST_KEY_REJECTED';

/** Stable `code` values of `WshAuthError` and `WshConnectionError`. */
export const WSH_ERROR_CODES: Readonly<{
  AUTH_FAILED: 'AUTH_FAILED';
  AUTH_UNAUTHORIZED: 'AUTH_UNAUTHORIZED';
  AUTH_BAD_SIGNATURE: 'AUTH_BAD_SIGNATURE';
  AUTH_METHOD_DISABLED: 'AUTH_METHOD_DISABLED';
  AUTH_RATE_LIMITED: 'AUTH_RATE_LIMITED';
  AUTH_KEY_EXPIRED: 'AUTH_KEY_EXPIRED';
  AUTH_BINDING_REQUIRED: 'AUTH_BINDING_REQUIRED';
  AUTH_NOT_SEALED: 'AUTH_NOT_SEALED';
  AUTH_BAD_REQUEST: 'AUTH_BAD_REQUEST';
  CONNECTION_FAILED: 'CONNECTION_FAILED';
  HANDSHAKE_TIMEOUT: 'HANDSHAKE_TIMEOUT';
}>;
export type WshAuthErrorCode = Exclude<keyof typeof WSH_ERROR_CODES, 'CONNECTION_FAILED' | 'HANDSHAKE_TIMEOUT'>;

/**
 * Thrown by `connect()` when the host refuses the login. The message is `Authentication failed: <reason>`, as it always was.
 * `refusal` is the reason the host reports to its own `onRefused` (`REFUSAL_REASONS` of `@johnhenry/wsh/host`), recognised from the
 * wording of the hosts this package ships (the wire carries the text only); `null` for a host that words it otherwise.
 */
export class WshAuthError extends Error {
  constructor(reason: string, message?: string);
  readonly code: WshAuthErrorCode;
  /** What the host said, verbatim. */
  readonly reason: string;
  readonly refusal: 'unauthorized' | 'bad-signature' | 'method-disabled' | 'rate-limited' | 'key-expired' | 'binding-required' | 'not-sealed' | 'bad-request' | null;
}

/** Thrown by `connect()` when no transport could be opened (`CONNECTION_FAILED`, with `attempts`) or the host did not answer a login step in time (`HANDSHAKE_TIMEOUT`). */
export class WshConnectionError extends Error {
  constructor(code: 'CONNECTION_FAILED' | 'HANDSHAKE_TIMEOUT', message: string, details?: { attempts?: string[]; cause?: unknown });
  readonly code: 'CONNECTION_FAILED' | 'HANDSHAKE_TIMEOUT';
  /** One line per transport tried. */
  readonly attempts?: string[];
}

/** Map an `AuthFail` reason to the stable code and `onRefused` reason (`AUTH_FAILED` / `null` when it is not recognised). */
export function classifyAuthRefusal(reason: unknown): { code: WshAuthErrorCode; refusal: WshAuthError['refusal'] };

/** Thrown by `connect()` when the host key fails the caller's policy. No credential has been sent. */
export class HostKeyError extends Error {
  constructor(code: WshHostKeyErrorCode, message: string, details?: { expected?: string; actual?: string });
  readonly code: WshHostKeyErrorCode;
  /** MISMATCH: the pinned / expected fingerprint. */
  readonly expected?: string;
  /** MISMATCH / UNKNOWN: the fingerprint the host presented. */
  readonly actual?: string;
}

/** Host-key policy shared by `connect()`, `exec()` and `connectReverse()`. */
export interface WshHostKeyOptions {
  /** Pin: hex fingerprint (optionally `sha256:`-prefixed), raw 32-byte key, or `ssh-ed25519 AAAA...` line. Refuses on mismatch or when the host presents no key. */
  expectHostKey?: string | Uint8Array;
  /** TOFU store. A changed key is always refused; an unseen host is refused unless `trustOnFirstUse` / `onHostKey` accepts it. */
  knownHosts?: WshKnownHosts;
  /** Pin an unseen host's key into `knownHosts`. */
  trustOnFirstUse?: boolean;
  /** Key `knownHosts` records this host under (default: the URL's `host:port`). */
  hostLabel?: string;
  /** Sees the verified key before any credential is sent; return `false` (or throw) to refuse. */
  onHostKey?: (hostKey: WshHostKey) => boolean | void | Promise<boolean | void>;
  /**
   * Refuse to sign the login unless the signature can be bound to this connection (#119): `true` needs at least one
   * binding kind the host offers and this client can supply (`host`, `cert-hash`, `tls-exporter`), an array names
   * kinds that must all be bound. Nothing is signed otherwise. Key logins only.
   */
  requireChannelBinding?: boolean | WshChannelBindingKind[];
  /**
   * Seal the WHOLE session end to end (#155): after login a signed key exchange with the host (bound to its proven host
   * key and this login key), then every message but the keepalive -- gateway and endpoint data included -- is an
   * authenticated encrypted frame a relay that copies bytes can neither read nor alter; a frame that does not open
   * closes the connection. Default `'auto'`: seal only against a host that says `e2e-session-required`. `true` seals or
   * fails, BEFORE a credential is sent (a host that does not offer `e2e-session`, one that proved no host key, a password
   * login). `false` never seals. Only `true` is a guarantee (a relay can strip the ServerHello feature `'auto'` rests
   * on); pin the host (`expectHostKey` / `knownHosts`) as well, since the exchange authenticates the key the host proved.
   */
  sealSession?: false | 'auto' | true;
}

/** What a login signature can be bound to (wsh #119). */
export type WshChannelBindingKind = 'cert-hash' | 'host' | 'tls-exporter';

/** Options for WshClient.connect(). */
export interface WshConnectOptions extends WshHostKeyOptions {
  username: string;
  keyPair?: CryptoKeyPair;
  /** A page-held signer instead of `keyPair` (not both). */
  signer?: WshSigner;
  password?: string;
  transport?: 'wt' | 'ws';
  /**
   * Forwarded to the `WebTransport` constructor when the WebTransport
   * rung of the transport ladder is tried; ignored by the WebSocket rung,
   * which has no `serverCertificateHashes` equivalent.
   */
  webTransport?: WshWebTransportOptions;
  timeout?: number;
  /**
   * A gateway connection (`openTcp`, `openUnix`, `openEndpoint`, a listener's connections) that is half-closed -- one side
   * sent GatewayClose and the other has not -- stays open while anything moves in either direction, and is ended after
   * this many milliseconds with nothing moving in either. Default 300000 (five minutes); `0` never.
   */
  gatewayHalfCloseIdleMs?: number;
  /**
   * State `gateway-lossless-close` (#286, default `true`): this client understands the `GatewayClose` reason `released` and, with a host
   * that states it too (directly, or behind a relay that carries the gateway), the host watches the ANSWERING socket of a connection
   * (an origin it dialled) and releases the connection when it vanished, losing nothing the client has received. `false` does not
   * state it: connections behave as they did before the feature (and a pairing with an older host is simulated this way in tests).
   */
  gatewayLosslessClose?: boolean;
}

/** Options for WshClient.openSession(). */
export interface WshOpenSessionOptions {
  type?: 'pty' | 'exec' | 'file' | 'rpc';
  command?: string;
  /**
   * `type: 'rpc'` only: the protocol to speak (`mcp`, `wsh-fs`, `wsh-host`, or a host-defined name). Throws
   * `RpcError` (`UNSUPPORTED_PROTOCOL`) before sending anything if the host does not advertise it.
   */
  protocol?: string;
  /** Advanced: called synchronously when the data stream binds, before any received byte is delivered. */
  attach?: (session: WshSession) => void;
  cols?: number;
  rows?: number;
  env?: Record<string, string>;
  timeout?: number;
  /**
   * Stream-mode `exec` only (default `true`): write the one-byte "primer"
   * that older hosts need to discover the client-opened data stream. Skipped
   * automatically against a host advertising `stream-announce`; `false`
   * never sends it.
   */
  primer?: boolean;
  /**
   * `exec` only: `'pipes'` runs the command on plain pipes (no echo, stderr on
   * `session.onStderr`, `closeStdin()` works) and throws unless the host
   * advertises `exec-pipes`. `'pty'` or omitted: the host's native mode.
   */
  stdio?: 'pty' | 'pipes';
  /**
   * #121: which of the host's execution targets this channel runs on (see {@link WshClient.listTargets}). Throws before sending
   * anything unless the host advertises `targets`. Omitted: the host's own default, as before.
   */
  target?: string;
}

/**
 * The Presence answering `attachSession()` / `resumeSession()`. Against a host
 * that assigns the attachment a channel (`@johnhenry/wsh/server` with `sessions`),
 * `session` -- non-enumerable -- is the message-backed `WshSession` receiving
 * the replay and live output.
 */
export type WshAttachResponse = WshMessage & { readonly session?: WshSession };

/** Options for WshClient.attachSession(). */
export interface WshAttachSessionOptions {
  readOnly?: boolean;
  /**
   * Session-scoped token (clawser #48; optional). Omit for the common
   * case of attaching via ownership or a `grantSessionAccess` grant --
   * the server accepts EITHER a valid token OR the caller already
   * owning/being ACL-granted access. Pass one (e.g. from
   * `WshSession.resumeToken`) only if you have it.
   */
  token?: Uint8Array;
  timeout?: number;
}

/** Options for WshClient.resumeSession(). */
export interface WshResumeSessionOptions {
  /**
   * Cumulative session output bytes this client already has (`WshSession.seq`
   * of the session it lost). A host with a bounded history replays only what
   * follows and refuses a position older than it still holds; the Rust
   * `wsh-server` ignores it and replays its whole ring. Default 0.
   */
  lastSeq?: number;
  timeout?: number;
}

/** Options for WshClient.connectReverse(). */
export interface WshConnectReverseOptions {
  username: string;
  keyPair?: CryptoKeyPair;
  /** A page-held signer instead of `keyPair` (not both). */
  signer?: WshSigner;
  password?: string;
  /** Forwarded to the underlying `connect()` -- see `WshConnectOptions`. */
  webTransport?: WshWebTransportOptions;
  expectHostKey?: WshHostKeyOptions['expectHostKey'];
  knownHosts?: WshKnownHosts;
  trustOnFirstUse?: boolean;
  hostLabel?: string;
  onHostKey?: WshHostKeyOptions['onHostKey'];
  requireChannelBinding?: WshHostKeyOptions['requireChannelBinding'];
  expose?: {
    shell?: boolean;
    exec?: boolean;
    fs?: boolean;
    tools?: boolean;
    /**
     * This peer's owner turned its gateway on for operators behind the relay (#289): lists the `gateway` capability in the record and
     * delivers the gateway's requests of each operator to `onRelayMessage(msg, from)`, on a relay that lists `relay-gateway`.
     * `createReverseHost` of `@johnhenry/wsh/server` sets it from its `gateway` option; a custom reverse handler answers them itself.
     */
    gateway?: boolean;
  };
  /** List `operator-proof` in the registered capabilities (key logins only; default true): this peer can answer an operator's challenge. */
  operatorProof?: boolean;
  /** List `gateway-lossless-close-signed` (#318): this peer reads a signed `gateway-lossless-close` in an operator's proof. Needs `operatorProof` and the `gateway` capability. Default false; `createReverseHost` sets it. */
  gatewayLosslessSigned?: boolean;
  peerType?: string;
  shellBackend?: string;
  supportsAttach?: boolean;
  supportsReplay?: boolean;
  supportsEcho?: boolean;
  supportsTermSync?: boolean;
}

/** Options for WshClient.exec(). */
export interface WshExecOptions extends WshHostKeyOptions {
  username: string;
  keyPair?: CryptoKeyPair;
  /** A page-held signer instead of `keyPair` (not both). */
  signer?: WshSigner;
  password?: string;
  timeout?: number;
  /** See {@link WshOpenSessionOptions.primer}. */
  primer?: boolean;
  /**
   * Input for the command: written, then stdin is closed (EOF), so `cat`,
   * `wc -c` and `sh -s` finish. Omitted: stdin is not touched. Needs a
   * stream-mode host (`@johnhenry/wsh/server`).
   */
  stdin?: string | Uint8Array | ReadableStream<Uint8Array | string> | AsyncIterable<Uint8Array | string> | Iterable<Uint8Array | string>;
  /**
   * Default: with `stdin`, plain pipes when the host advertises `exec-pipes`,
   * else the host's native mode; without `stdin`, the host's native mode.
   * `'pipes'` throws if the host lacks `exec-pipes`; `'pty'` never asks for pipes.
   */
  stdio?: 'pty' | 'pipes';
  /** See {@link WshOpenSessionOptions.target}. */
  target?: string;
}

/** Result from WshClient.exec(). */
export interface WshExecResult {
  stdout: Uint8Array;
  exitCode: number;
  /** Present only when the command ran on plain pipes (`exec-pipes`). */
  stderr?: Uint8Array;
}

/** Session list entry. */
export interface WshSessionInfo {
  channelId: number;
  kind: string;
  state: string;
  /** The server's session id, when the host assigned one (pty / exec). */
  sessionId?: string;
}

/** Peer information from reverse list. */
export interface WshPeerInfo {
  fingerprint: string;
  fingerprint_short: string;
  username: string;
  capabilities: string[];
  peer_type: string;
  shell_backend: string;
  source: string;
  supports_attach: boolean;
  supports_replay: boolean;
  supports_echo: boolean;
  supports_term_sync: boolean;
  last_seen: number | null;
  /** Raw 32-byte Ed25519 public key from the peer's signed record, if present. */
  public_key?: Uint8Array;
  /** The signing peer's own monotonic counter, from the signed record. */
  seq?: number;
  /** Raw Ed25519 signature over the peer record's transcript, if present. */
  record_signature?: Uint8Array;
  /**
   * Not a wire field -- computed client-side by `listPeers()` from
   * `public_key`/`seq`/`record_signature` via `verifyPeerRecord`. `true`
   * only if the signature verifies AND the key's fingerprint matches
   * `fingerprint`; `false` for missing/tampered/mismatched records.
   */
  verified: boolean;
}

/** Host feature: it answers `KeyExchange` and seals/opens `EncryptedFrame`s (a reverse host with `e2e` on). */
export const E2E_FEATURE: 'e2e';
/** Host feature: it signs its `KeyExchange` reply, so `initiateE2E(..., { verifyPeer })` can authenticate it. */
export const E2E_SIGN_FEATURE: 'e2e-sign';

/** Relay feature / operator feature: a `ReverseChallenge` / `ReverseProof` crosses the relay (#117). */
export const OPERATOR_PROOF_FEATURE: 'operator-proof';
/** #318: what a host lists in its registered capabilities when it reads a signed `gateway-lossless-close` in an operator's proof (`wsh-operator-proof-v2`). */
export const GATEWAY_LOSSLESS_SIGNED_FEATURE: 'gateway-lossless-close-signed';
/** Host feature (`ReverseAccept.features`): it takes a signed initiator half and a sealed bridge (#117). */
export const E2E_SEALED_FEATURE: 'e2e-sealed';
export function challengeTranscript(t: { peerPublicKey: Uint8Array; operatorFingerprint: string; nonce: Uint8Array; sessionId: string }): Uint8Array;
export function proofTranscript(t: { peerPublicKey: Uint8Array; operatorPublicKey: Uint8Array; username: string; nonce: Uint8Array; sessionId: string }): Uint8Array;
/** `EncryptedFrame.channel_id` of a bridge-level frame (real channels start at 1). */
export const BRIDGE_CHANNEL_ID: 0;
/** A sealed reverse bridge (#117): seals every message that would cross it into an `EncryptedFrame` and opens them. */
export class SealedBridge {
  constructor(p: { key: CryptoKey; sessionId: string; role: 'initiator' | 'responder' });
  readonly sessionId: string;
  isFrame(msg: WshMessage): boolean;
  seal(msg: WshMessage): Promise<WshMessage>;
  open(frame: WshMessage): Promise<WshMessage>;
}
/** Operator proof (#117): the peer's signed `ReverseChallenge` fields, and the checks on each side. */
export function createReverseChallenge(identity: { keyPair?: CryptoKeyPair; signer?: WshSigner }, operatorFingerprint: string): Promise<{ fields: object; nonce: Uint8Array; sessionId: string; peerPublicKey: Uint8Array }>;
export function verifyReverseChallenge(msg: WshMessage, expect: { target: string; ownFingerprint: string }): Promise<{ peerPublicKey: Uint8Array; peerFingerprint: string; nonce: Uint8Array; sessionId: string }>;
export function createOperatorProof(signer: { publicKeyRaw: Uint8Array; sign(data: Uint8Array): Promise<Uint8Array> }, challenge: { peerPublicKey: Uint8Array; nonce: Uint8Array; sessionId: string }, username: string): Promise<object>;
export function verifyOperatorProof(msg: WshMessage, issued: { nonce: Uint8Array; sessionId: string; peerPublicKey: Uint8Array }): Promise<{ publicKey: Uint8Array; fingerprint: string; username: string } | null>;
/** The binding a login signature carries (#119): SHA-256 over the kinds present, or empty when there are none. */
export function computeChannelBinding(values: Partial<Record<WshChannelBindingKind, Uint8Array>>): Promise<Uint8Array>;
export const CHANNEL_BINDING_KINDS: readonly WshChannelBindingKind[];

/** The bytes a responder signs in `KeyExchange.signature`. */
export function keyExchangeTranscript(t: {
  sessionId: string;
  /** The initiator's `algorithm` string. */
  algorithm: string;
  initiatorKey: Uint8Array;
  responderKey: Uint8Array;
}): Uint8Array;

/** Verify a responder's `KeyExchange.signature` against its long-term Ed25519 public key. */
export function verifyKeyExchangeSignature(
  peerIdentity: Uint8Array | CryptoKey,
  signature: Uint8Array | undefined,
  transcript: Parameters<typeof keyExchangeTranscript>[0],
): Promise<boolean>;

/** Result from WshClient.initiateE2E(). */
export interface WshE2EResult {
  /** Non-extractable AES-256-GCM key derived from the exchange. */
  sharedSecret: CryptoKey;
  /** The peer's ephemeral X25519 public key. */
  peerPublicKey: Uint8Array;
  /**
   * Whether hybrid X25519+ML-KEM-768 mode actually took effect --
   * `false` if `algorithm: 'X25519'` was requested, or if hybrid was
   * requested but the peer didn't support it (automatic fallback).
   */
  hybrid: boolean;
  /** True when `verifyPeer` was given and the peer's signature over the exchange verified. */
  peerAuthenticated: boolean;
}

/**
 * Raw `FileResult` response to a structured file-channel operation
 * (`WshClient.fileList`/`fileRemove`/etc.), as received off the wire --
 * wire field names (snake_case), not the camelCase shape the `fileResult()`
 * message constructor takes as input. `entries` is only populated for a
 * `"list"` op; `error_message` is only present on failure.
 */
export interface WshFileOperationResult {
  type: number;
  channel_id: number;
  success: boolean;
  metadata: Record<string, unknown>;
  entries: Array<{
    name: string;
    size: number;
    modified: number;
    type: 'file' | 'directory' | 'symlink' | 'device' | 'pipe' | 'socket';
    symlink_target?: string;
  }>;
  error_message?: string;
}

/**
 * WshClient -- manages a wsh connection, authentication, and multiple sessions.
 *
 * Handles the full lifecycle: transport selection, handshake, challenge-response
 * or password auth, channel multiplexing, ping/pong keepalive, and teardown.
 *
 * Supports forward connections (client opens sessions on a remote server) and
 * reverse mode (client registers as a peer for incoming connections).
 */
/** Options for `openUnix` / `openEndpoint` / `openTcp`. */
export interface WshGatewayOpenOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  /** The half-close idle bound (#271) for this one connection, instead of the client's `gatewayHalfCloseIdleMs`: a non-negative integer of milliseconds, `0` = never. */
  halfCloseIdleMs?: number;
  /** `openEndpoint` only (#121): the host's execution target whose endpoint this is. Needs the `targets` feature. */
  target?: string;
}

/** Options for `forwardEndpoint` (Node only). */
export interface WshForwardEndpointOptions {
  /** Where to listen: a socket path (`/tmp/d.sock`, `./d.sock`), `host:port`, or a bare port (loopback). Give an address (`0.0.0.0:8080`) to listen elsewhere. */
  local: string;
  /** The host's endpoint name: letters, digits, `.`, `_`, `-`, at most 64 (the CLI's rule). */
  endpoint: string;
  /** Replace a STALE socket at `local` (never a live one, never another kind of file). Default: an existing path is refused. */
  replace?: boolean;
  /** Connections open at once; one more is closed and reported to `onError`. Default 128 (the CLI's). */
  maxConnections?: number;
  /** How often a local connection whose program has half-closed (sent its end of file) is checked for the program having gone away; see {@link WshForwardOptions.halfCloseProbeMs}. */
  halfCloseProbeMs?: number;
  /**
   * `halfCloseProbeAnswers` (#286): see {@link WshForwardOptions.halfCloseProbeAnswers}. (A named endpoint's forward connects, so this only matters for a reverse forward.)
   */
  halfCloseProbeAnswers?: boolean;
  /**
   * Called for a connection that could not be served (no such endpoint, refused, over the bound), with the reason. The listener stays up.
   * Also called, with `error.code === 'WSH_LOCAL_PEER_GONE'`, when a local program half-closed and then went away (killed, crashed)
   * and the connection was ended because of it: informational, not a failure of the forward.
   */
  onError?: (err: Error) => void;
}

/** Options for `forwardUnix` (Node only); `forwardEndpoint` takes the same, with `endpoint` instead of `remote`. */
export interface WshForwardOptions {
  local: string;
  remote: string;
  reverse?: boolean;
  replace?: boolean;
  maxConnections?: number;
  /**
   * (Not for `reverse: true`: the local end of a reverse forward is a service that answers, and one that finished and closed
   * completely is the normal end of a response; it is watched only with `gateway-lossless-close`, see `halfCloseProbeAnswers`.)
   * A local program that connected, half-closed (sent its end of file, still reading) and was then killed gives Node no event; the
   * kernel reports it to a writer only. While (and only while) a local connection is half-closed the forward writes ZERO bytes to
   * it every this many milliseconds: a live program is not touched (no byte, no wake-up), a dead one fails the write, and the
   * connection is ended as a destroyed one (the host is sent `GatewayClose` with the reason `discarded`) and reported to `onError`
   * with `code` `'WSH_LOCAL_PEER_GONE'`. A TCP socket is also given keep-alive on this schedule (rounded up to whole seconds,
   * three probes): a TCP program that exited with nothing unread is noticed when ITS kernel drops the socket (about a minute by
   * default), one killed with data unread at once. Default 2000; `0` turns it off. A whole number of milliseconds from 0 to
   * 2147483647, else a `TypeError`.
   */
  halfCloseProbeMs?: number;
  /**
   * For `reverse: true` (#286): the local service of a reverse forward is watched (once it has half-closed, at `halfCloseProbeMs`) when the
   * host and this client both stated `gateway-lossless-close`. A service that went away releases the connection (the host delivers what
   * it has received to its caller, then ends it, with no `onError`); one that sent its whole answer and closed completely loses nothing.
   * `false` keeps the local service unwatched, as before the feature. Default `true`; a non-boolean is a `TypeError`.
   */
  halfCloseProbeAnswers?: boolean;
  /** For `reverse: true` (#286): the keep-alive schedule of a half-closed local service on another machine, in milliseconds (default 30000; loopback and unix keep `halfCloseProbeMs`; `0` = the same). */
  halfCloseProbeRemoteMs?: number;
  onError?: (err: Error) => void;
}

/** What the Node forwards (`forwardUnix`, `forwardEndpoint`) return. */
export interface WshForwardHandle {
  local: string;
  /** What the other end is: the `remote` given, or `endpoint=NAME`. */
  remote: string;
  /** Where it listens (not for a reverse forward). */
  address?: { address: string; family: string; port: number } | string | null;
  /** Set when a bound on concurrent connections applies. */
  maxConnections?: number;
  /** Local connections open now (what `maxConnections` counts; for a reverse forward, the host's callers being served by the local service). */
  readonly connections?: number;
  /** Stop listening, end every live connection and remove the socket file this forward created. Safe to call twice. */
  close(): Promise<void>;
}

/** One execution target a host shows this key (`ListTargets` / `TargetList`, #121). */
export interface WshTargetInfo {
  /** What to pass as `target`. */
  name: string;
  /** A human line about the target; not for parsing. */
  description?: string;
  /** What the caller can do there: any of `exec`, `pty`, `file`, `endpoint` (a hint; the host decides on each request). */
  capabilities: string[];
}

/** One gateway connection as web streams with backpressure (credit-based flow control when both ends offer `gateway-credit`). */
export interface WshGatewayDuplex {
  /** What the peer sends. Read it to keep credit flowing: a reader that stops reading stops the peer. */
  readable: ReadableStream<Uint8Array>;
  /** What you send. Each write waits for credit; closing it half-closes (the peer finishes and closes its side). */
  writable: WritableStream<Uint8Array>;
  /** Half-close: nothing more will be written. */
  close(reason?: string): void;
  /** Tear the connection down now. */
  destroy(reason?: string): void;
  /** Settles once the connection is over. Resolves with `'released'` when the peer released it (see {@link WshGatewayDuplex.lossless}). */
  closed: Promise<string | undefined>;
  /**
   * Both ends stated `gateway-lossless-close` (#286): this connection may be RELEASED, and a close with the reason `released` ("I will read
   * nothing more and send nothing more; deliver what you already sent, in order, then finish") is understood. What a peer released is still
   * delivered to `readable` before it ends; writes fail from then on.
   *
   * #318: `true` only where no relay can forge or strip the release: a direct connection, or a SEALED bridge (`reverseConnect(fp, t, { sealed: true })`)
   * on which the operator signed the statement for a host whose verified record lists `gateway-lossless-close-signed`. On an unsealed bridge it is
   * `false`: the release is best-effort (see `releasable`), a `released` the operator did not negotiate ends the connection promptly, and none of it is a
   * guarantee.
   */
  lossless?: boolean;
  /** #318: the release is negotiated with the peer (so this side may send one), whether or not it is a guarantee (`lossless`). */
  releasable?: boolean;
  /** The answering socket of this connection went away after finishing its side (a reverse forward's local service): end it with `released`, which loses nothing the peer has received. A discard where `lossless` is false. */
  release?(): void;
  /** Bytes received from the peer and not yet read from `readable`: what this end is holding for you. With credit it never exceeds the credit window (256 KiB). */
  readonly queuedBytes?: number;
  /** The most bytes this connection has ever held, received and not yet read, at once (a byte count kept by the connection, not a heap measurement). */
  readonly peakQueuedBytes?: number;
}

/** A UDP flow (`client.openUdp()`): one chunk = one datagram, and a datagram may be dropped without notice. */
export interface WshUdpFlow extends WshGatewayDuplex {
  /** 'datagram': WebTransport datagrams. 'stream': the reliable control stream (WebSocket, or a host without `gateway-datagram`). */
  readonly transport: 'datagram' | 'stream';
  /** The largest payload that travels as one datagram right now (it can change; read it again). */
  readonly maxDatagramSize: number;
  /** Resolves true when handed to the transport, false when dropped locally. Rejects with RangeError for a payload over 65507 bytes (or over the datagram size with `oversize: 'drop'`). */
  send(bytes: Uint8Array): Promise<boolean>;
  stats: { sent: number; received: number; sentReliable: number; receivedReliable: number; sendDropped: number; receiveDropped: number };
}
/** Feature string for UDP over WebTransport datagrams. */
export const GATEWAY_DATAGRAM_FEATURE: 'gateway-datagram';

/**
 * A GatewayFail / ListenFail as an Error: `code` 4 = refused by the host's policy, 7 = too many connections, 1 = refused by the target,
 * 8 = timed out. A `5` is "the gateway is disabled, or a timeout from an older Node gateway", and the message says so.
 */
export class GatewayError extends Error { code: number }

/**
 * The codes of `GatewayFail` by name (the one table the Node gateway, the page host and netway share). Frozen. `5` is `GATEWAY_DISABLED` (the
 * spec, the Rust server); `TIMEOUT` is `8`. A Node gateway older than the one that sends `8` sent `5` for a timeout, so keep reading a `5` as
 * "disabled, or a timeout from an older Node gateway".
 */
export const GATEWAY_FAIL: Readonly<{
  CONNECTION_REFUSED: 1; HOST_UNREACHABLE: 2; DNS_FAILED: 3; POLICY_DENIED: 4; GATEWAY_DISABLED: 5; CLOSED: 6; QUEUE_FULL: 7; TIMEOUT: 8;
}>;
/** The same codes with their meaning; `alsoSentAs` is a second name another (or an older) implementation gives the number (`5` is also what an older Node gateway sent for a timeout). */
export const GATEWAY_FAIL_TABLE: ReadonlyArray<Readonly<{ name: keyof typeof GATEWAY_FAIL; code: number; meaning: string; alsoSentAs?: readonly string[] }>>;
/** Codes a client gives its own `GatewayError` when it never asked the host (not on the wire): `UNSUPPORTED` is `0`, a feature the host did not advertise. */
export const GATEWAY_FAIL_LOCAL: Readonly<{ UNSUPPORTED: 0 }>;
/** The name of a wire or client-local code, or `null`. */
export function gatewayFailName(code: number): string | null;

/** The feature a client lists in `Hello.features` and a host in `ServerHello.features` to meter gateway data with `GatewayCredit`. */
export const GATEWAY_CREDIT_FEATURE: 'gateway-credit';
/** The feature a side states when it understands the `GatewayClose` reason `released` (#286). */
export const GATEWAY_LOSSLESS_FEATURE: 'gateway-lossless-close';
/** What a reverse host lists in `ReverseAccept.features` when the operator's `gateway-lossless-close` really reached it (a relay can drop the statement); an operator relies on the feature behind a relay only with this (#286). */
export const GATEWAY_LOSSLESS_ACK_FEATURE: 'gateway-lossless-close-ack';
/** The `GatewayClose` reason of a connection one side releases: it reads and sends nothing more, and what it already sent is still delivered (#286). */
export const GATEWAY_RELEASED: 'released';
/** Credit, in bytes, each direction of a gateway connection starts with. */
export const GATEWAY_CREDIT_WINDOW: 262144;

/**
 * Why a connection closed (#240), as `WshClient.onClose` is given it and `WshClient.closeInfo` keeps it. `source`: `'websocket'` (the socket's
 * close code and reason, such as a pipe relay's limit text), `'qmux'` (the peer's CONNECTION_CLOSE frame and its error code),
 * `'webtransport'` (the session's close code and reason, or the error text when it failed), or `'transport'` (a custom transport that did not
 * say; `code` is `null`). `reason` is at most 256 characters. `wasClean`: the peer ended it with a close handshake.
 */
export interface WshCloseInfo {
  readonly source: 'websocket' | 'qmux' | 'webtransport' | 'transport' | (string & {});
  readonly code: number | null;
  readonly reason: string;
  readonly wasClean: boolean;
}

/** Options of `new WshClient()`. */
export interface WshClientOptions {
  /**
   * Build the transport for each rung of the ladder: `ws` for WebSocket URLs, `wt` for WebTransport. Giving the object REPLACES the
   * defaults, so a kind you leave out is unsupported (`connect()` with that transport fails). Use it for a custom `WebSocket`
   * (`new WebSocketTransport({ WebSocket })`), a test double, or a transport of your own.
   */
  transportFactories?: { ws?: () => WshTransport; wt?: () => WshTransport };
  /** How often the client pings the host, in milliseconds. */
  pingIntervalMs?: number;
  /** How long it waits for a pong before it treats the connection as dead, in milliseconds. */
  pongTimeoutMs?: number;
}

export class WshClient {
  constructor(options?: WshClientOptions);

  /** Current client state. */
  readonly state: 'disconnected' | 'connecting' | 'connected' | 'authenticated' | 'closed';

  /** Server-assigned session ID. */
  readonly sessionId: string | null;

  /**
   * This connection's own AUTH-level token (from AUTH_OK), scoped to this
   * connection's auth session_id -- NOT a PTY/exec session token. See
   * `WshSession.resumeToken` for the per-session credential used by
   * `resumeSession`.
   */
  readonly authToken: Uint8Array | null;

  /** Seconds the host said it will keep this connection (`AuthOk.ttl`); 0 = no limit promised. Hosts older than 0.36 sent an unenforced 3600. */
  readonly authTtl: number;

  /** Read-only view of active sessions. */
  readonly sessions: Map<number, WshSession>;

  /**
   * The features this connection can rely on: those of the host behind an accepted relay bridge when it
   * stated them (`ReverseAccept.features`), otherwise the server's `SERVER_HELLO` features.
   */
  readonly features: string[];
  /** The `SERVER_HELLO` features of the server connected to (the relay, over a bridge). */
  readonly serverFeatures: string[];
  /** Features of the host behind an accepted relay bridge as it stated them; `null` when there is no bridge or it did not say. */
  readonly bridgedFeatures: string[] | null;

  /**
   * Low-level transport reference.
   * Prefer higher-level methods for normal use.
   */
  readonly _transport: WshTransport | null;

  /**
   * Called when the peer or the network closes the connection (not for a `disconnect()` / `close()` this side made). The argument says
   * why (#240) and is also kept as `closeInfo`; a handler that takes none works as before.
   */
  onClose: ((info: WshCloseInfo) => void) | null;

  /** Why the last connection closed (the object `onClose` got); `null` before a close, after a close this side made, and at the next `connect()`. */
  readonly closeInfo: WshCloseInfo | null;

  /** Called on connection-level errors. */
  onError: ((err: Error) => void) | null;

  /**
   * Called when a sealed session or bridge drops a message it does not accept (a plain message where only sealed frames are
   * heard, or a bridge frame that does not open). The connection carries on, so this is not `onError`; the drops are also
   * counted in `droppedMessages`. Nothing is written to the console.
   */
  onDrop: ((drop: {
    reason: 'plaintext-on-sealed-session' | 'plaintext-before-seal' | 'plaintext-on-sealed-bridge' | 'unopenable-bridge-frame';
    messageType?: number;
    detail?: string;
  }) => void) | null;

  /** How many messages a sealed session or bridge has dropped: plain ones, and bridge frames that did not open. */
  readonly droppedMessages: { plaintext: number; unopened: number };

  /** Called when a reverse-connect request arrives (reverse mode only). */
  onReverseConnect: ((msg: WshMessage) => void) | null;

  /** Called when a clipboard sync message arrives (OSC 52). */
  onClipboard: ((msg: WshMessage) => void) | null;

  /**
   * Called when a relay-forwarded message arrives from a remote peer.
   * In reverse mode, the relay bridge forwards messages from the CLI peer
   * to this browser client.
   */
  onRelayMessage: ((msg: WshMessage, fromFingerprint?: string) => void) | null;

  /**
   * Called on a peer that serves several operators when the relay reports that one left (`ReverseClose`,
   * wsh #89): end that operator's bridge and clean up what belongs to it.
   */
  onReverseClose: ((msg: WshMessage) => void) | null;

  /**
   * Called when a gateway-subsystem control message arrives (opcodes 0x70-0x7f).
   */
  onGatewayMessage: ((msg: WshMessage) => void) | null;

  /**
   * Check if a feature is available: advertised by the server, or by the bridged host (see `features`).
   */
  hasFeature(name: string): boolean;

  /**
   * The host's Ed25519 identity once it has proven it holds the key for this
   * connection; `null` if the server advertised none (e.g. the Rust server).
   */
  readonly hostKey: WshHostKey | null;

  /** Is this whole session sealed end to end (`connect(url, { sealSession })`, #155)? */
  readonly sessionSealed: boolean;

  /** Default `onHostKey` for `connect()` (a per-call option wins). */
  onHostKey: ((hostKey: WshHostKey) => boolean | void | Promise<boolean | void>) | null;

  /**
   * Connect to a wsh server, authenticate, and return the session ID.
   */
  connect(url: string, opts?: WshConnectOptions): Promise<string>;

  /**
   * Open a new PTY or exec session on the remote server.
   */
  openSession(opts?: WshOpenSessionOptions): Promise<WshSession>;

  // ── Gateway: unix sockets, named endpoints, TCP egress (#120, #123) ──

  /** Connect to a unix-domain socket on the HOST (needs the host feature `gateway-unix`; refused unless its policy lists the path). */
  openUnix(path: string, opts?: WshGatewayOpenOptions): Promise<WshGatewayDuplex>;
  /** Open the host's named virtual endpoint (needs the host feature `gateway-endpoints`). */
  openEndpoint(name: string, opts?: WshGatewayOpenOptions): Promise<WshGatewayDuplex>;
  /** Connect to host:port FROM THE HOST (needs the host feature `gateway`; refused unless its `gateway.allow` lists it). */
  openTcp(host: string, port: number, opts?: WshGatewayOpenOptions): Promise<WshGatewayDuplex>;
  /**
   * A UDP flow to ONE destination, host:port, FROM THE HOST. Datagram semantics: any payload may be dropped. Over WebTransport, when the
   * host lists `gateway-datagram`, payloads are WebTransport datagrams (unordered, no retransmission, no head-of-line blocking between
   * flows); otherwise they ride the reliable control stream. A payload too big for one datagram goes on the control stream unless `oversize: 'drop'`.
   */
  openUdp(host: string, port: number, opts?: WshGatewayOpenOptions & { oversize?: 'reliable' | 'drop' }): Promise<WshUdpFlow>;
  /** Ask the host to listen on a TCP port (a reverse tunnel); needs `gateway` and the host's `gateway.reverse`. `bindAddr` is a request the host may ignore. */
  listenTcp(port: number, opts: { bindAddr?: string; timeoutMs?: number; onConnection: (duplex: WshGatewayDuplex, info: { peer: string; peerPort: number }) => void }): Promise<{ port: number; close(): Promise<void> }>;
  /** Ask the host to listen on a unix-domain socket and hand each connection to `onConnection` (OpenSSH `-R`). */
  listenUnix(path: string, opts: { replace?: boolean; timeoutMs?: number; onConnection: (duplex: WshGatewayDuplex, info: { peer: string }) => void }): Promise<{ path: string; close(): Promise<void> }>;
  /**
   * Node only: forward between a local endpoint and a remote one (`ssh -L` / `-R` with unix sockets and TCP ports mixed).
   * Each of `local` and `remote` is a socket path (starts with `/`, `./` or `@`) or `host:port`. With `reverse: true` the
   * HOST listens on `remote` (a unix path) and connections are made to `local` from here. `remote` may also be
   * `endpoint=NAME` (the CLI's spelling), a named endpoint of the host: see `forwardEndpoint`. `maxConnections` bounds the
   * connections open at once (default 128 for a named endpoint, unbounded otherwise).
   */
  forwardUnix(opts: WshForwardOptions): Promise<WshForwardHandle>;
  /**
   * Node only: listen on a local unix socket or TCP port and join every connection to the host's NAMED endpoint; the
   * JavaScript equivalent of the CLI's `wsh -L /tmp/d.sock:endpoint=NAME` (needs the host feature `gateway-endpoints`).
   * A missing or refused endpoint closes that one connection and reports the reason to `onError`; the listener stays up.
   * Half-close and backpressure work in both directions; a client that closes first is not an error.
   */
  forwardEndpoint(opts: WshForwardEndpointOptions): Promise<WshForwardHandle & { endpoint: string }>;

  /**
   * Open a typed (object-mode) RPC channel (wsh #85): JSON-RPC 2.0 over a CBOR sequence on one stream. Sugar over
   * `openSession({ type: 'rpc', protocol })`. Throws `RpcError` (`UNSUPPORTED_PROTOCOL`) before sending any bytes
   * if the host does not advertise `rpc` and `rpc-protocol:<protocol>`.
   */
  openRpc(protocol: string, opts?: { timeoutMs?: number; openTimeout?: number }): Promise<RpcChannel>;

  /**
   * Use the `wsh-fs` rpc protocol for `fileStat`/`fileList`/`fileRead`/`fileWrite`/... when the host advertises it
   * (default `true`); `false` always uses the FileOp control path. Results keep the `FileResult` shape.
   */
  preferRpcFiles: boolean;

  /**
   * List locally tracked sessions with their current state.
   */
  listSessions(): WshSessionInfo[];

  /**
   * The live session this client opened, by `channelId` or server `sessionId` -- one that can `write()`,
   * `resize()`, `closeStdin()` and `close()`. `undefined` when there is none.
   */
  getSession(id: number | string): WshSession | undefined;

  /**
   * Attach to an existing remote session (collaborative or read-only).
   * Authorization is satisfied by EITHER `opts.token` OR the caller
   * already owning/being ACL-granted access to `targetSessionId`
   * server-side -- see `WshAttachSessionOptions.token`.
   */
  attachSession(targetSessionId: string, opts?: WshAttachSessionOptions): Promise<WshAttachResponse>;

  /**
   * Resume a previously disconnected session. Unlike `attachSession()`,
   * `token` is required and verified unconditionally server-side.
   */
  resumeSession(targetSessionId: string, token: Uint8Array, opts?: WshResumeSessionOptions): Promise<WshAttachResponse>;

  /**
   * Detach from a remote session, leaving it running server-side.
   */
  detach(sessionId: string, timeout?: number): Promise<void>;

  /**
   * List sessions on the server this connection's key can see (a server
   * round trip — distinct from the purely local listSessions()).
   */
  listRemoteSessions(timeout?: number): Promise<object[]>;

  /**
   * Grant another principal access to a session this connection owns.
   */
  grantSessionAccess(sessionId: string, principal: string, permissions?: string[]): Promise<void>;

  /**
   * Revoke a previously granted principal's access to a session.
   */
  revokeSessionAccess(sessionId: string, principal: string, reason?: string): Promise<void>;

  /**
   * List a remote directory over the structured file channel (`FileOp`
   * op `"list"`). Prefer `WshFileTransfer.list()` for a typed
   * `WshFileListEntry[]` result (with `modified` as a `Date`) -- this is
   * the raw wire-shaped `FileResult` response `fileOperation()` waits on.
   */
  fileList(path: string, timeout?: number): Promise<WshFileOperationResult>;

  /**
   * Write bytes to a remote file. `offset` omitted replaces the file; given,
   * writes in place at that offset. Needs the host feature `file-write`
   * (`@johnhenry/wsh/server` with `fs` has it); throws against a host without
   * it. Failure is reported as `success: false` in the result.
   */
  fileWrite(path: string, data: Uint8Array | string, offset?: number, timeout?: number): Promise<WshFileOperationResult>;

  /**
   * Rename/move a remote file or directory. Needs the host feature
   * `file-rename`; throws against a host without it. Refuses to overwrite.
   */
  fileRename(oldPath: string, newPath: string, timeout?: number): Promise<WshFileOperationResult>;

  /**
   * Remove a remote file or directory (`FileOp` op `"remove"`). Refused
   * today by every `wsh-server` release ("not yet implemented" -- see
   * README's file-op parity table); wired here so clients built against
   * this SDK don't need to wait on the server to type-check against it.
   */
  fileRemove(path: string, timeout?: number): Promise<WshFileOperationResult>;

  /**
   * Install a raw 32-byte Ed25519 public key into the remote host's
   * `~/.wsh/authorized_keys` (wsh #59's `AuthorizedKeyAdd` protocol
   * message -- replaces `wsh copy-id`'s previous CLI-only shell-command
   * approach with something every implementation, including this one,
   * can call directly). Idempotent: installing an already-present key
   * resolves `added: false` rather than duplicating the line or erroring.
   */
  addAuthorizedKey(
    publicKeyRaw: Uint8Array,
    comment?: string,
    timeout?: number,
  ): Promise<{ added: boolean }>;

  /**
   * Gracefully disconnect: close all sessions and the transport.
   */
  disconnect(): Promise<void>;

  /** The same as `disconnect()` (#240). */
  close(): Promise<void>;

  /**
   * One-shot command execution: connect, authenticate, run a command,
   * collect all output, disconnect, and return the result.
   */
  static exec(url: string, command: string, opts?: WshExecOptions): Promise<WshExecResult>;

  /**
   * Create a client with a pre-configured transport instance.
   * Useful for WebSocket transport or custom transports.
   */
  static withTransport(transport: WshTransport): WshClient;

  /**
   * Connect in reverse mode: register as a peer that can accept incoming
   * connections from other clients.
   */
  connectReverse(url: string, opts?: WshConnectReverseOptions): Promise<string>;

  /**
   * List peers registered on the relay server.
   */
  listPeers(timeout?: number): Promise<WshPeerInfo[]>;

  /**
   * The execution targets this connection may use (#121): what the host decides to show THIS key. Pass a `name` as `target` to
   * `openSession`, `exec`, `fileOperation` or `openEndpoint`. Throws if the host does not advertise `targets`.
   */
  listTargets(timeout?: number): Promise<WshTargetInfo[]>;

  /**
   * One structured file operation (`FileOp`), the raw wire-shaped result. `opts.target` (#121) names the execution target whose
   * files these are (needs `targets`; such a request is never sent over the `wsh-fs` rpc, which is not per target).
   */
  fileOperation(op: string, path: string, opts?: { offset?: number; length?: number; data?: Uint8Array | string; newPath?: string; target?: string }, timeout?: number): Promise<WshFileOperationResult>;

  /**
   * Initiate a reverse connection to a registered peer.
   */
  reverseConnectTo(targetFingerprint: string, timeout?: number): Promise<void>;

  /**
   * Connect to a registered peer and wait for its accept or reject. Against a relay that lists `operator-proof` and a
   * peer that asks, this operator PROVES its identity to the peer (a signature over the peer's key, a nonce the peer
   * chose and the bridge's session) instead of leaving the peer to trust the relay's `from_fingerprint` (#117).
   */
  reverseConnect(
    targetFingerprint: string,
    timeout?: number,
    opts?: {
      /** `'auto'` (default): offer proof when the relay carries it and the peer's registered record lists `operator-proof`; `false`: never; `true`: offer regardless of the record (the relay still strips it for a peer that did not advertise it) and refuse if the relay cannot carry it. */
      proof?: 'auto' | boolean;
      /** The peer's capability list, when the caller already holds it (skips the `listPeers()` lookup `'auto'` makes). */
      peerCapabilities?: string[];
      /** Refuse the bridge unless the peer signed its challenge (so it proved its key to this operator). */
      requirePeerProof?: boolean;
      /**
       * Seal the bridge: a key exchange both sides sign comes first, and everything after crosses the relay as
       * `EncryptedFrame`s. Nothing that names a command, a path or a session is sent before the key exists.
       * The peer must state `e2e-sealed`. `{ hybrid: false }` skips ML-KEM.
       */
      sealed?: boolean | { hybrid?: boolean };
    },
  ): Promise<WshMessage>;

  /** The binding kinds the last login's signature covered (`[]` = unbound). */
  readonly channelBinding: WshChannelBindingKind[];

  /** Called with the operator's `ReverseProof` when this peer sent a `ReverseChallenge` (reverse mode). */
  onReverseProof: ((msg: WshMessage) => void) | null;

  /**
   * Send a control message over the authenticated relay connection.
   */
  sendRelayControl(msg: WshMessage, opts?: { to?: string }): Promise<void>;

  /**
   * Send a raw control message on the authenticated connection.
   *
   * Prefer the typed methods. This is the hook `WshMcpBridge` and
   * `WshFileTransfer` compose their own messages through.
   */
  sendControl(msg: WshMessage): Promise<void>;

  /**
   * Open a raw bidirectional stream on the underlying transport.
   */
  openStream(): Promise<WshStream>;

  /**
   * Observe every inbound control message this client handles. Listeners
   * are called past the RelayForward trust gate, so a message from an
   * unaccepted peer never reaches one.
   */
  addControlListener(fn: (msg: WshMessage) => void): void;

  /**
   * Stop observing inbound control messages.
   */
  removeControlListener(fn: (msg: WshMessage) => void): void;

  /**
   * Initiate end-to-end encryption for a session: `'X25519'` (default,
   * classical ECDH) or `'X25519+ML-KEM-768'` (hybrid, with automatic
   * fallback to classical if the peer doesn't support it). Experimental
   * -- the derived key is not yet wired to any actual encryption.
   */
  initiateE2E(
    sessionId: string,
    algorithm?: 'X25519' | 'X25519+ML-KEM-768',
    timeout?: number,
    opts?: {
      /** The peer's long-term Ed25519 public key; the exchange is refused (`E2E_PEER_UNAUTHENTICATED`) unless it signed its half. */
      verifyPeer?: Uint8Array | CryptoKey;
      /** Sign this (initiator) half with the operator's key; send only to a peer that stated `e2e-sealed`. */
      signAs?: { sign(data: Uint8Array): Promise<Uint8Array> };
      /** The responder's raw identity key, bound into the initiator signature (default: `verifyPeer` when raw). */
      responderIdentity?: Uint8Array;
    },
  ): Promise<WshE2EResult>;

  /**
   * Mark a peer fingerprint as an accepted reverse-connect bridge partner.
   * Only RelayForward-wrapped messages whose from_fingerprint is trusted
   * this way are unwrapped and delivered via onRelayMessage.
   */
  trustRelayPeer(fingerprint: string): void;

  /**
   * Stop trusting a peer as a relay-forward bridge partner.
   */
  untrustRelayPeer(fingerprint: string): void;

  /**
   * Upload a blob to a remote path.
   */
  upload(blob: Blob | Uint8Array, remotePath: string, opts?: {
    onProgress?: (bytesSent: number) => void;
    /** Rejects with an `AbortError` and closes the file channel; an already-aborted signal opens nothing. */
    signal?: AbortSignal;
  }): Promise<void>;

  /**
   * Download a file from a remote path.
   */
  download(
    remotePath: string,
    opts?: {
      onProgress?: (progress: { received: number; total: number }) => void;
      timeout?: number;
      /** Rejects with an `AbortError` and closes the file channel; an already-aborted signal opens nothing. */
      signal?: AbortSignal;
    },
  ): Promise<Uint8Array>;

  /**
   * Discover MCP tools available on the remote server.
   */
  discoverTools(timeout?: number): Promise<unknown[]>;

  /**
   * Call an MCP tool on the remote server.
   */
  callTool(
    name: string,
    args?: Record<string, unknown>,
    /** A timeout in ms, or `{ timeout, signal }`. An aborted call rejects with an `AbortError`; against a host advertising `mcp-cancel` the tool handler's signal fires too. */
    options?: number | { timeout?: number; signal?: AbortSignal },
  ): Promise<unknown>;

  /**
   * Connect using an externally created transport.
   * Use this when you need WebSocket or a custom transport.
   */
  connectWithTransport(transport: WshTransport, url: string, opts: WshConnectOptions): Promise<string>;

  /**
   * Check whether a message type is relay-forwardable.
   * @internal
   */
  _isRelayForwardable(type: number): boolean;

  /**
   * Get the next channel ID.
   * @internal
   */
  _nextChannelId(): number;
}

// ============================================================================
// keystore.mjs -- WshKeyStore
// ============================================================================

/** Key entry from the key store. */
export interface WshKeyEntry {
  name: string;
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  createdAt: number;
  fingerprint: string;
}

/** Key listing entry (without CryptoKey objects). */
export interface WshKeyListEntry {
  name: string;
  fingerprint: string;
  createdAt: number;
}

/** Result of key generation. */
export interface WshKeyGenerateResult {
  name: string;
  fingerprint: string;
  publicKeySSH: string;
}

/** Result of backup operation. */
export interface WshBackupResult {
  backedUp: number;
  skipped: number;
}

/** Result of restore operation. */
export interface WshRestoreResult {
  restored: number;
  skipped: number;
}

/**
 * WshKeyStore -- Ed25519 key management via IndexedDB with OPFS encrypted backup.
 *
 * Keys are stored as non-extractable CryptoKey objects in IndexedDB for
 * day-to-day use. An optional passphrase-encrypted backup can be written
 * to OPFS (requires extractable keys at generation time).
 */
export class WshKeyStore {
  /** @internal */
  _db: IDBDatabase | null;

  /** Open or create the IndexedDB database. */
  open(): Promise<void>;

  /** Close the database connection. */
  close(): void;

  /**
   * Generate a new Ed25519 key pair and store it in IndexedDB.
   * @param name - Key name / identifier (default 'default')
   * @param opts.extractable - Whether the private key can be exported (default false)
   */
  generateKey(name?: string, opts?: { extractable?: boolean }): Promise<WshKeyGenerateResult>;

  /**
   * Get a stored key entry by name.
   */
  getKey(name: string): Promise<WshKeyEntry | null>;

  /**
   * List all stored key names and fingerprints.
   */
  listKeys(): Promise<WshKeyListEntry[]>;

  /**
   * Delete a key by name.
   * @returns true if the key existed and was deleted
   */
  deleteKey(name: string): Promise<boolean>;

  /**
   * Export a public key as an SSH-formatted string.
   * @returns ssh-ed25519 AAAA... format
   */
  exportPublicKey(name: string): Promise<string>;

  /**
   * Get the CryptoKey pair for a named key.
   */
  getKeyPair(name: string): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }>;

  /**
   * Export all extractable keys, encrypt with a passphrase, and store in OPFS.
   */
  backup(passphrase: string): Promise<WshBackupResult>;

  /**
   * Restore keys from an OPFS encrypted backup.
   */
  restore(passphrase: string): Promise<WshRestoreResult>;
}

// ============================================================================
// known-hosts.mjs -- WshKnownHosts (wsh #59)
// ============================================================================

/** Minimal storage interface `WshKnownHosts` needs -- `localStorage` already satisfies it. */
export interface WshKnownHostsStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** Result of verifying a host's fingerprint against the stored record. */
export interface WshHostVerifyResult {
  status: 'known' | 'unknown' | 'changed';
  /** Previously stored fingerprint, present only when status === 'changed'. */
  expected?: string;
}

/**
 * WshKnownHosts -- trust-on-first-use (TOFU) host-identity store, mirroring
 * Rust's `KnownHosts`/`HostStatus` (`crates/wsh-client/src/known_hosts.rs`).
 * Pins `ServerHello.host_fingerprint` (spec/wsh-v1.yaml, wsh #59) -- no
 * `wsh-server` release populates that field yet, so this has nothing
 * authoritative to verify against for any real server today. See the
 * class doc comment in `known-hosts.mjs` for the full reasoning.
 */
export class WshKnownHosts {
  constructor(opts?: { storage?: WshKnownHostsStorage; storageKey?: string });

  /** Verify a host's fingerprint against the stored record. */
  verifyHost(host: string, fingerprint: string): WshHostVerifyResult;

  /** Add or update a host's fingerprint. */
  addHost(host: string, fingerprint: string): void;

  /** Remove a host entry. Returns true if an entry was removed. */
  removeHost(host: string): boolean;

  /** List all known hosts and their fingerprints. */
  list(): Array<{ host: string; fingerprint: string }>;
}

// ============================================================================
// file-transfer.mjs -- WshFileTransfer
// ============================================================================

/** Upload progress callback payload. */
export interface WshFileUploadProgress {
  sent: number;
  total: number;
}

/** Download progress callback payload. */
export interface WshFileDownloadProgress {
  received: number;
  total?: number;
}

/** Upload result. */
export interface WshFileUploadResult {
  success: boolean;
  bytesTransferred: number;
}

/**
 * File listing entry (wsh #59: generated from spec/wsh-v1.yaml's
 * `FileEntry` nested type -- the same shape `crates/wsh-core`'s Rust
 * `FileEntry` struct is generated from, so a directory entry can no longer
 * describe a symlink as a plain file in one implementation and not the
 * other). `modified` is converted from the wire's Unix epoch seconds into
 * a `Date` for JS ergonomics. `symlinkTarget` is only present when
 * `type === 'symlink'`.
 */
export interface WshFileListEntry {
  name: string;
  size: number;
  modified: Date;
  type: 'file' | 'directory' | 'symlink' | 'device' | 'pipe' | 'socket';
  symlinkTarget?: string;
}

/**
 * WshFileTransfer -- dedicated stream file transfer (scp-like) over a wsh connection.
 *
 * Uploads and downloads files using the wsh channel protocol with 'file' kind
 * channels. Data flows over a dedicated bidirectional stream in 64KB chunks.
 */
export class WshFileTransfer {
  constructor(client: object);

  /**
   * Upload data to a remote path.
   */
  upload(
    data: Uint8Array | ArrayBuffer,
    remotePath: string,
    opts?: {
      onProgress?: (progress: WshFileUploadProgress) => void;
      timeout?: number;
      signal?: AbortSignal;
    },
  ): Promise<WshFileUploadResult>;

  /**
   * Download a file from a remote path.
   */
  download(
    remotePath: string,
    opts?: {
      onProgress?: (progress: WshFileDownloadProgress) => void;
      timeout?: number;
      signal?: AbortSignal;
    },
  ): Promise<Uint8Array>;

  /**
   * List files at a remote path.
   */
  list(remotePath: string): Promise<WshFileListEntry[]>;
}

// ============================================================================
// recording.mjs -- SessionRecorder + SessionPlayer
// ============================================================================

/** Event type for session recording. */
export type SessionRecordingEventType = 'input' | 'output' | 'resize' | 'open' | 'exit';

/** A single recorded event entry. */
export interface SessionRecordingEntry {
  t: number;
  type: string;
  data: unknown;
}

/** The `toJSON()` export: asciicast-v2-shaped (not a playable asciicast file -- one JSON document, plus `sessionId` and `open`/`exit` events). */
export interface SessionRecordingJSON {
  version: 2;
  width: number;
  height: number;
  timestamp: number;
  env: Record<string, string>;
  sessionId: string;
  events: Array<[number, string, string]>;
}

/**
 * Records PTY I/O events with relative timestamps for session replay.
 */
export class SessionRecorder {
  /** Unique session identifier. */
  sessionId: string;

  /** Unix epoch ms when recording started. */
  startTime: number;

  /** Recorded event entries. */
  entries: SessionRecordingEntry[];

  /** Total duration in milliseconds. */
  readonly duration: number;

  /** Number of recorded events. */
  readonly length: number;

  constructor(sessionId: string, opts?: { width?: number; height?: number });

  /**
   * Record an event.
   */
  record(type: SessionRecordingEventType | string, data: unknown): void;

  /**
   * Export the recording as a JSON-serializable object (asciicast-v2-shaped; see the README for converting it to a `.cast` file).
   */
  toJSON(): SessionRecordingJSON;

  /**
   * Import a recording from JSON.
   */
  static fromJSON(json: SessionRecordingJSON | string): SessionRecorder;
}

/** Playback controller interface. */
export interface SessionPlaybackController {
  /** Pause playback. */
  pause(): void;

  /** Resume playback after pause. */
  resume(): void;

  /** Stop playback entirely. */
  stop(): void;

  /**
   * Seek to a specific time in the recording.
   * Immediately replays all output events up to the target time,
   * then resumes normal timed playback from that point.
   * @param timeMs - Target time in milliseconds from start
   */
  seek(timeMs: number): void;
}

/** Recording metadata. */
export interface SessionPlayerMetadata {
  width: number;
  height: number;
  duration: number;
  eventCount: number;
}

/**
 * Replays a recorded session with original timing.
 */
export class SessionPlayer {
  constructor(recording: SessionRecorder | SessionRecordingJSON);

  /** Get the recording metadata. */
  readonly metadata: SessionPlayerMetadata;

  /**
   * Replay the recording with original timing.
   */
  play(
    onData: (data: string) => void,
    opts?: {
      speed?: number;
      onEvent?: (type: string, data: unknown) => void;
    },
  ): SessionPlaybackController;
}

// ============================================================================
// mcp-bridge.mjs -- WshMcpBridge
// ============================================================================

/** MCP tool specification. */
export interface WshMcpToolSpec {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

/** MCP call result. */
export interface WshMcpCallResult {
  success: boolean;
  output: unknown;
  error?: string;
}

/**
 * WshMcpBridge -- bridges remote MCP tools over the wsh meta channel.
 *
 * Sends MCP_DISCOVER and MCP_CALL messages through the wsh control channel,
 * enabling a wsh client to discover and invoke MCP tools hosted on the
 * remote server.
 */
export class WshMcpBridge {
  constructor(client: object);

  /**
   * Discover available MCP tools on the remote server.
   */
  discover(opts?: { timeout?: number }): Promise<WshMcpToolSpec[]>;

  /**
   * Call a remote MCP tool by name.
   */
  call(
    toolName: string,
    args?: Record<string, unknown>,
    opts?: { timeout?: number; signal?: AbortSignal },
  ): Promise<WshMcpCallResult>;

  /**
   * Get cached tool specs (after discover() has been called).
   */
  getToolSpecs(): WshMcpToolSpec[];

  /**
   * Check whether a specific tool is available (based on cached discovery).
   */
  hasTool(toolName: string): boolean;

  /** Get the number of cached tools. */
  readonly toolCount: number;

  /** Clear the cached tool specs. Call discover() again to refresh. */
  clearCache(): void;
}
