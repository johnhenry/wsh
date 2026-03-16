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
 * Decode CBOR bytes into a JS value.
 */
export function cborDecode(data: Uint8Array): unknown;

/**
 * Frame a CBOR-encoded message with a 4-byte big-endian length prefix.
 * @returns [4-byte length][CBOR payload]
 */
export function frameEncode(value: unknown): Uint8Array;

/**
 * Streaming frame decoder. Feed it chunks and it yields complete messages.
 */
export class FrameDecoder {
  /**
   * Feed bytes and return decoded messages.
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

  // Framing
  readonly WS_DATA: 0x60;

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
};

/** Authentication method constants. */
export const AUTH_METHOD: {
  readonly PUBKEY: 'pubkey';
  readonly PASSWORD: 'password';
};

/** Protocol version string. */
export const PROTOCOL_VERSION: 'wsh-v1';

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
  token?: string;
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
}): WshMessage;

export function openOk(opts?: {
  channelId?: number;
  streamIds?: number[];
  dataMode?: string;
  capabilities?: string[];
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
  token?: string;
  mode?: string;
  deviceLabel?: string;
}): WshMessage;

export function resume(opts?: {
  sessionId?: string;
  token?: string;
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
}): WshMessage;

export function mcpResult(opts?: {
  result?: unknown;
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
}): WshMessage;

export function reverseList(): WshMessage;

export function reversePeers(opts?: {
  peers?: unknown[];
}): WshMessage;

export function reverseConnect(opts?: {
  targetFingerprint?: string;
  username?: string;
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
}): WshMessage;

export function reverseReject(opts?: {
  targetFingerprint?: string;
  username?: string;
  reason?: string;
}): WshMessage;

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
 * Generate a new Ed25519 key pair.
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
 * Sign data with an Ed25519 private key.
 * @returns 64-byte signature
 */
export function sign(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array>;

/**
 * Verify an Ed25519 signature.
 */
export function verify(publicKey: CryptoKey, signature: Uint8Array, data: Uint8Array): Promise<boolean>;

/**
 * Build the authentication transcript hash for challenge-response signing.
 *
 * transcript = SHA-256("wsh-v1\0" || session_id || nonce || channel_binding)
 *
 * @returns 32-byte SHA-256 hash
 */
export function buildTranscript(
  sessionId: string,
  nonce: Uint8Array,
  channelBinding?: Uint8Array,
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
  channelBinding?: Uint8Array,
): Promise<{ signature: Uint8Array; publicKeyRaw: Uint8Array }>;

/**
 * Server-side: verify a client's challenge response.
 */
export function verifyChallenge(
  publicKey: CryptoKey,
  signature: Uint8Array,
  sessionId: string,
  nonce: Uint8Array,
  channelBinding?: Uint8Array,
): Promise<boolean>;

/**
 * Compute the SHA-256 fingerprint of a raw public key.
 * @returns hex-encoded fingerprint
 */
export function fingerprint(publicKeyRaw: Uint8Array): Promise<string>;

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

  /** Callback when transport closes. */
  onClose: (() => void) | null;

  /** Callback on transport error. */
  onError: ((err: Error) => void) | null;

  /** Current transport state. */
  readonly state: 'disconnected' | 'connecting' | 'connected' | 'closed';

  /** Connect to a wsh server. */
  connect(url: string): Promise<void>;

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
  protected _doConnect(url: string): Promise<void>;

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
export class WebTransportTransport extends WshTransport {}

// ============================================================================
// transport-ws.mjs -- WebSocket transport
// ============================================================================

/**
 * wsh transport over a single WebSocket with multiplexed virtual streams.
 *
 * Provides the same interface as WebTransportTransport so that upper
 * layers (session, client) work identically over either transport.
 */
export class WebSocketTransport extends WshTransport {}

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

  /** Called when stdout/stderr data arrives. */
  onData: ((data: Uint8Array) => void) | null;

  /** Called when the remote process exits. */
  onExit: ((code: number) => void) | null;

  /** Called when the session is fully closed. */
  onClose: (() => void) | null;

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

  constructor(
    transport: WshTransport,
    channelId: number,
    streamIds: object,
    kind: 'pty' | 'exec',
    opts?: {
      dataMode?: 'stream' | 'virtual';
      capabilities?: string[];
    },
  );

  /**
   * Write data to the session's stdin stream.
   * Accepts a Uint8Array for raw bytes or a string (UTF-8 encoded).
   */
  write(data: Uint8Array | string): Promise<void>;

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

/** Options for WshClient.connect(). */
export interface WshConnectOptions {
  username: string;
  keyPair?: CryptoKeyPair;
  password?: string;
  transport?: 'wt' | 'ws';
  timeout?: number;
}

/** Options for WshClient.openSession(). */
export interface WshOpenSessionOptions {
  type?: 'pty' | 'exec';
  command?: string;
  cols?: number;
  rows?: number;
  env?: Record<string, string>;
  timeout?: number;
}

/** Options for WshClient.attachSession(). */
export interface WshAttachSessionOptions {
  readOnly?: boolean;
  timeout?: number;
}

/** Options for WshClient.connectReverse(). */
export interface WshConnectReverseOptions {
  username: string;
  keyPair?: CryptoKeyPair;
  password?: string;
  expose?: {
    shell?: boolean;
    exec?: boolean;
    fs?: boolean;
    tools?: boolean;
  };
  peerType?: string;
  shellBackend?: string;
  supportsAttach?: boolean;
  supportsReplay?: boolean;
  supportsEcho?: boolean;
  supportsTermSync?: boolean;
}

/** Options for WshClient.exec(). */
export interface WshExecOptions {
  username: string;
  keyPair?: CryptoKeyPair;
  password?: string;
  timeout?: number;
}

/** Result from WshClient.exec(). */
export interface WshExecResult {
  stdout: Uint8Array;
  exitCode: number;
}

/** Session list entry. */
export interface WshSessionInfo {
  channelId: number;
  kind: string;
  state: string;
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
export class WshClient {
  /** Current client state. */
  readonly state: 'disconnected' | 'connecting' | 'connected' | 'authenticated' | 'closed';

  /** Server-assigned session ID. */
  readonly sessionId: string | null;

  /** Read-only view of active sessions. */
  readonly sessions: Map<number, WshSession>;

  /** Server-advertised features from SERVER_HELLO. */
  readonly features: string[];

  /**
   * Low-level transport reference.
   * Prefer higher-level methods for normal use.
   */
  readonly _transport: WshTransport | null;

  /** Called when the connection is closed (intentionally or otherwise). */
  onClose: (() => void) | null;

  /** Called on connection-level errors. */
  onError: ((err: Error) => void) | null;

  /** Called when a reverse-connect request arrives (reverse mode only). */
  onReverseConnect: ((msg: WshMessage) => void) | null;

  /** Called when a clipboard sync message arrives (OSC 52). */
  onClipboard: ((msg: WshMessage) => void) | null;

  /**
   * Called when a relay-forwarded message arrives from a remote peer.
   * In reverse mode, the relay bridge forwards messages from the CLI peer
   * to this browser client.
   */
  onRelayMessage: ((msg: WshMessage) => void) | null;

  /**
   * Called when a gateway-subsystem control message arrives (opcodes 0x70-0x7f).
   */
  onGatewayMessage: ((msg: WshMessage) => void) | null;

  /**
   * Check if the server advertised a specific feature.
   */
  hasFeature(name: string): boolean;

  /**
   * Connect to a wsh server, authenticate, and return the session ID.
   */
  connect(url: string, opts?: WshConnectOptions): Promise<string>;

  /**
   * Open a new PTY or exec session on the remote server.
   */
  openSession(opts?: WshOpenSessionOptions): Promise<WshSession>;

  /**
   * List locally tracked sessions with their current state.
   */
  listSessions(): WshSessionInfo[];

  /**
   * Attach to an existing remote session (collaborative or read-only).
   */
  attachSession(targetSessionId: string, opts?: WshAttachSessionOptions): Promise<WshMessage>;

  /**
   * Resume a previously disconnected session.
   */
  resumeSession(targetSessionId: string, token: string, opts?: { timeout?: number }): Promise<WshMessage>;

  /**
   * Gracefully disconnect: close all sessions and the transport.
   */
  disconnect(): Promise<void>;

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
   * Initiate a reverse connection to a registered peer.
   */
  reverseConnectTo(targetFingerprint: string, timeout?: number): Promise<void>;

  /**
   * Send a control message over the authenticated relay connection.
   */
  sendRelayControl(msg: WshMessage): Promise<void>;

  /**
   * Upload a blob to a remote path.
   */
  upload(blob: Blob | Uint8Array, remotePath: string, opts?: { onProgress?: (bytesSent: number) => void }): Promise<void>;

  /**
   * Download a file from a remote path.
   */
  download(remotePath: string): Promise<Uint8Array>;

  /**
   * Discover MCP tools available on the remote server.
   */
  discoverTools(timeout?: number): Promise<unknown[]>;

  /**
   * Call an MCP tool on the remote server.
   */
  callTool(name: string, args: Record<string, unknown>, timeout?: number): Promise<unknown>;

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

/** File listing entry. */
export interface WshFileListEntry {
  name: string;
  size: number;
  modified: string;
  type: 'file' | 'directory' | 'symlink' | 'device' | 'pipe' | 'socket';
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

/** Asciicast v2 export format. */
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
   * Export the recording as a JSON-serializable object (asciicast v2 format).
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
    opts?: { timeout?: number },
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
