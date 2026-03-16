/**
 * wsh protocol control message types and constructors.
 * AUTO-GENERATED from wsh-v1.yaml — do not edit.
 * Run: node web/packages/wsh/spec/codegen.mjs
 */

// ── Message type constants ────────────────────────────────────────────

export const MSG = Object.freeze({
  // Handshake
  HELLO:             0x01,
  SERVER_HELLO:      0x02,
  CHALLENGE:         0x03,
  AUTH_METHODS:      0x04,
  AUTH:              0x05,
  AUTH_OK:           0x06,
  AUTH_FAIL:         0x07,

  // Channel
  OPEN:              0x10,
  OPEN_OK:           0x11,
  OPEN_FAIL:         0x12,
  RESIZE:            0x13,
  SIGNAL:            0x14,
  EXIT:              0x15,
  CLOSE:             0x16,
  SESSION_DATA:      0x17,

  // Transport
  ERROR:             0x20,
  PING:              0x21,
  PONG:              0x22,

  // Session
  ATTACH:            0x30,
  RESUME:            0x31,
  RENAME:            0x32,
  IDLE_WARNING:      0x33,
  SHUTDOWN:          0x34,
  SNAPSHOT:          0x35,
  PRESENCE:          0x36,
  CONTROL_CHANGED:   0x37,
  METRICS:           0x38,
  CLIPBOARD:         0x39,
  RECORDING_EXPORT:  0x3a,
  COMMAND_JOURNAL:   0x3b,
  METRICS_REQUEST:   0x3c,
  SUSPEND_SESSION:   0x3d,
  RESTART_PTY:       0x3e,
  SESSION_LIST_REQUEST: 0x3f,

  // Mcp
  MCP_DISCOVER:      0x40,
  MCP_TOOLS:         0x41,
  MCP_CALL:          0x42,
  MCP_RESULT:        0x43,

  // Reverse
  REVERSE_REGISTER:  0x50,
  REVERSE_LIST:      0x51,
  REVERSE_PEERS:     0x52,
  REVERSE_CONNECT:   0x53,
  REVERSE_ACCEPT:    0x54,
  REVERSE_REJECT:    0x55,

  // Session
  SESSION_LIST:      0x5f,
  DETACH:            0x60,

  // Framing
  WS_DATA:           0x60,

  // Session
  DETACH_OK:         0x61,
  DETACH_FAIL:       0x62,

  // Gateway
  OPEN_TCP:          0x70,
  OPEN_UDP:          0x71,
  RESOLVE_DNS:       0x72,
  GATEWAY_OK:        0x73,
  GATEWAY_FAIL:      0x74,
  GATEWAY_CLOSE:     0x75,
  INBOUND_OPEN:      0x76,
  INBOUND_ACCEPT:    0x77,
  INBOUND_REJECT:    0x78,
  DNS_RESULT:        0x79,
  LISTEN_REQUEST:    0x7a,
  LISTEN_OK:         0x7b,
  LISTEN_FAIL:       0x7c,
  LISTEN_CLOSE:      0x7d,
  GATEWAY_DATA:      0x7e,

  // Guest
  GUEST_INVITE:      0x80,
  GUEST_JOIN:        0x81,
  GUEST_REVOKE:      0x82,

  // Sharing
  SHARE_SESSION:     0x83,
  SHARE_REVOKE:      0x84,

  // Compression
  COMPRESS_BEGIN:    0x85,
  COMPRESS_ACK:      0x86,

  // Ratecontrol
  RATE_CONTROL:      0x87,
  RATE_WARNING:      0x88,

  // Linking
  SESSION_LINK:      0x89,
  SESSION_UNLINK:    0x8a,

  // Copilot
  COPILOT_ATTACH:    0x8b,
  COPILOT_SUGGEST:   0x8c,
  COPILOT_DETACH:    0x8d,

  // E2e
  KEY_EXCHANGE:      0x8e,
  ENCRYPTED_FRAME:   0x8f,

  // Echo
  ECHO_ACK:          0x90,
  ECHO_STATE:        0x91,

  // Termsync
  TERM_SYNC:         0x92,
  TERM_DIFF:         0x93,

  // Scaling
  NODE_ANNOUNCE:     0x94,
  NODE_REDIRECT:     0x95,

  // Principals
  SESSION_GRANT:     0x96,
  SESSION_REVOKE:    0x97,

  // Filechannel
  FILE_OP:           0x98,
  FILE_RESULT:       0x99,
  FILE_CHUNK:        0x9a,

  // Policy
  POLICY_EVAL:       0x9b,
  POLICY_RESULT:     0x9c,
  POLICY_UPDATE:     0x9d,

  // Terminal
  TERMINAL_CONFIG:   0x9e,
});

// Reverse lookup: number → name
export const MSG_NAMES = Object.freeze(
  Object.fromEntries(Object.entries(MSG).map(([k, v]) => [v, k]))
);

// ── Channel kinds ─────────────────────────────────────────────────────

export const CHANNEL_KIND = Object.freeze({
  PTY:   'pty',
  EXEC:  'exec',
  META:  'meta',
  FILE:  'file',
  TCP:   'tcp',
  UDP:   'udp',
  JOB:   'job',
});

// ── Auth methods ──────────────────────────────────────────────────────

export const AUTH_METHOD = Object.freeze({
  PUBKEY:    'pubkey',
  PASSWORD:  'password',
});

// ── Protocol version ──────────────────────────────────────────────────

export const PROTOCOL_VERSION = 'wsh-v1';

// ── Message constructors ──────────────────────────────────────────────

export function hello({ username, features = [], authMethod = AUTH_METHOD.PUBKEY } = {}) {
  return {
    type: MSG.HELLO,
    version: PROTOCOL_VERSION,
    username,
    features,
    auth_method: authMethod,
  };
}

export function serverHello({ sessionId, features = [], fingerprints = [] } = {}) {
  return {
    type: MSG.SERVER_HELLO,
    session_id: sessionId,
    features,
    fingerprints,
  };
}

export function challenge({ nonce } = {}) {
  return {
    type: MSG.CHALLENGE,
    nonce,
  };
}

export function authMethods({ methods = [AUTH_METHOD.PUBKEY] } = {}) {
  return {
    type: MSG.AUTH_METHODS,
    methods,
  };
}

export function auth({ method, signature, publicKey, password } = {}) {
  const msg = { type: MSG.AUTH, method };
  if (method === AUTH_METHOD.PUBKEY) {
    msg.signature = signature;
    msg.public_key = publicKey;
  } else if (method === AUTH_METHOD.PASSWORD) {
    msg.password = password;
  }
  return msg;
}

export function authOk({ sessionId, token, ttl } = {}) {
  return {
    type: MSG.AUTH_OK,
    session_id: sessionId,
    token,
    ttl,
  };
}

export function authFail({ reason } = {}) {
  return {
    type: MSG.AUTH_FAIL,
    reason,
  };
}

export function open({ kind, command, cols, rows, env } = {}) {
  const msg = { type: MSG.OPEN, kind };
  if (command !== undefined) msg.command = command;
  if (cols !== undefined) msg.cols = cols;
  if (rows !== undefined) msg.rows = rows;
  if (env !== undefined) msg.env = env;
  return msg;
}

export function openOk({ channelId, streamIds = [], dataMode = "stream", capabilities = [] } = {}) {
  return {
    type: MSG.OPEN_OK,
    channel_id: channelId,
    stream_ids: streamIds,
    data_mode: dataMode,
    capabilities,
  };
}

export function openFail({ reason } = {}) {
  return {
    type: MSG.OPEN_FAIL,
    reason,
  };
}

export function resize({ channelId, cols, rows } = {}) {
  return {
    type: MSG.RESIZE,
    channel_id: channelId,
    cols,
    rows,
  };
}

export function signal({ channelId, signal } = {}) {
  return {
    type: MSG.SIGNAL,
    channel_id: channelId,
    signal,
  };
}

export function exit({ channelId, code } = {}) {
  return {
    type: MSG.EXIT,
    channel_id: channelId,
    code,
  };
}

export function close({ channelId } = {}) {
  return {
    type: MSG.CLOSE,
    channel_id: channelId,
  };
}

export function sessionData({ channelId, data } = {}) {
  return {
    type: MSG.SESSION_DATA,
    channel_id: channelId,
    data,
  };
}

export function error({ code, message } = {}) {
  return {
    type: MSG.ERROR,
    code,
    message,
  };
}

export function ping({ id } = {}) {
  return {
    type: MSG.PING,
    id,
  };
}

export function pong({ id } = {}) {
  return {
    type: MSG.PONG,
    id,
  };
}

export function attach({ sessionId, token, mode = "control", deviceLabel } = {}) {
  const msg = { type: MSG.ATTACH, session_id: sessionId, token, mode };
  if (deviceLabel !== undefined) msg.device_label = deviceLabel;
  return msg;
}

export function resume({ sessionId, token, lastSeq } = {}) {
  return {
    type: MSG.RESUME,
    session_id: sessionId,
    token,
    last_seq: lastSeq,
  };
}

export function rename({ sessionId, name } = {}) {
  return {
    type: MSG.RENAME,
    session_id: sessionId,
    name,
  };
}

export function idleWarning({ expiresIn } = {}) {
  return {
    type: MSG.IDLE_WARNING,
    expires_in: expiresIn,
  };
}

export function shutdown({ reason, retryAfter } = {}) {
  const msg = { type: MSG.SHUTDOWN, reason };
  if (retryAfter !== undefined) msg.retry_after = retryAfter;
  return msg;
}

export function snapshot({ label } = {}) {
  return {
    type: MSG.SNAPSHOT,
    label,
  };
}

export function presence({ attachments } = {}) {
  return {
    type: MSG.PRESENCE,
    attachments,
  };
}

export function controlChanged({ newController } = {}) {
  return {
    type: MSG.CONTROL_CHANGED,
    new_controller: newController,
  };
}

export function metrics({ cpu, memory, sessions, rtt } = {}) {
  const msg = { type: MSG.METRICS,  };
  if (cpu !== undefined) msg.cpu = cpu;
  if (memory !== undefined) msg.memory = memory;
  if (sessions !== undefined) msg.sessions = sessions;
  if (rtt !== undefined) msg.rtt = rtt;
  return msg;
}

export function clipboard({ direction, data } = {}) {
  return {
    type: MSG.CLIPBOARD,
    direction,
    data,
  };
}

export function recordingExport({ sessionId, format = "jsonl", data } = {}) {
  const msg = { type: MSG.RECORDING_EXPORT, session_id: sessionId, format };
  if (data !== undefined) msg.data = data;
  return msg;
}

export function commandJournal({ sessionId, command, exitCode, durationMs, cwd, timestamp } = {}) {
  const msg = { type: MSG.COMMAND_JOURNAL, session_id: sessionId, command, timestamp };
  if (exitCode !== undefined) msg.exit_code = exitCode;
  if (durationMs !== undefined) msg.duration_ms = durationMs;
  if (cwd !== undefined) msg.cwd = cwd;
  return msg;
}

export function metricsRequest() {
  return { type: MSG.METRICS_REQUEST };
}

export function suspendSession({ sessionId, action } = {}) {
  return {
    type: MSG.SUSPEND_SESSION,
    session_id: sessionId,
    action,
  };
}

export function restartPty({ sessionId, command } = {}) {
  const msg = { type: MSG.RESTART_PTY, session_id: sessionId };
  if (command !== undefined) msg.command = command;
  return msg;
}

export function sessionListRequest() {
  return { type: MSG.SESSION_LIST_REQUEST };
}

export function mcpDiscover() {
  return { type: MSG.MCP_DISCOVER };
}

export function mcpTools({ tools } = {}) {
  return {
    type: MSG.MCP_TOOLS,
    tools,
  };
}

export function mcpCall({ tool, arguments: args } = {}) {
  return { type: MSG.MCP_CALL, tool, arguments: args };
}

export function mcpResult({ result } = {}) {
  return {
    type: MSG.MCP_RESULT,
    result,
  };
}

export function reverseRegister({ username, capabilities = [], peerType = "host", shellBackend = "pty", supportsAttach = false, supportsReplay = false, supportsEcho = false, supportsTermSync = false, publicKey } = {}) {
  return {
    type: MSG.REVERSE_REGISTER,
    username,
    capabilities,
    peer_type: peerType,
    shell_backend: shellBackend,
    supports_attach: supportsAttach,
    supports_replay: supportsReplay,
    supports_echo: supportsEcho,
    supports_term_sync: supportsTermSync,
    public_key: publicKey,
  };
}

export function reverseList() {
  return { type: MSG.REVERSE_LIST };
}

export function reversePeers({ peers } = {}) {
  return {
    type: MSG.REVERSE_PEERS,
    peers,
  };
}

export function reverseConnect({ targetFingerprint, username } = {}) {
  return {
    type: MSG.REVERSE_CONNECT,
    target_fingerprint: targetFingerprint,
    username,
  };
}

export function reverseAccept({ targetFingerprint, username, capabilities = [], peerType = "host", shellBackend = "pty", supportsAttach = false, supportsReplay = false, supportsEcho = false, supportsTermSync = false } = {}) {
  return {
    type: MSG.REVERSE_ACCEPT,
    target_fingerprint: targetFingerprint,
    username,
    capabilities,
    peer_type: peerType,
    shell_backend: shellBackend,
    supports_attach: supportsAttach,
    supports_replay: supportsReplay,
    supports_echo: supportsEcho,
    supports_term_sync: supportsTermSync,
  };
}

export function reverseReject({ targetFingerprint, username, reason } = {}) {
  return {
    type: MSG.REVERSE_REJECT,
    target_fingerprint: targetFingerprint,
    username,
    reason,
  };
}

export function sessionList({ sessions } = {}) {
  return {
    type: MSG.SESSION_LIST,
    sessions,
  };
}

export function detach({ sessionId } = {}) {
  return {
    type: MSG.DETACH,
    session_id: sessionId,
  };
}

export function detachOk({ sessionId } = {}) {
  return {
    type: MSG.DETACH_OK,
    session_id: sessionId,
  };
}

export function detachFail({ reason } = {}) {
  return {
    type: MSG.DETACH_FAIL,
    reason,
  };
}

export function openTcp({ gatewayId, host, port } = {}) {
  return {
    type: MSG.OPEN_TCP,
    gateway_id: gatewayId,
    host,
    port,
  };
}

export function openUdp({ gatewayId, host, port } = {}) {
  return {
    type: MSG.OPEN_UDP,
    gateway_id: gatewayId,
    host,
    port,
  };
}

export function resolveDns({ gatewayId, name, recordType = "A" } = {}) {
  return {
    type: MSG.RESOLVE_DNS,
    gateway_id: gatewayId,
    name,
    record_type: recordType,
  };
}

export function gatewayOk({ gatewayId, resolvedAddr } = {}) {
  const msg = { type: MSG.GATEWAY_OK, gateway_id: gatewayId };
  if (resolvedAddr !== undefined) msg.resolved_addr = resolvedAddr;
  return msg;
}

export function gatewayFail({ gatewayId, code, message } = {}) {
  return {
    type: MSG.GATEWAY_FAIL,
    gateway_id: gatewayId,
    code,
    message,
  };
}

export function gatewayClose({ gatewayId, reason } = {}) {
  const msg = { type: MSG.GATEWAY_CLOSE, gateway_id: gatewayId };
  if (reason !== undefined) msg.reason = reason;
  return msg;
}

export function inboundOpen({ listenerId, channelId, peerAddr, peerPort } = {}) {
  return {
    type: MSG.INBOUND_OPEN,
    listener_id: listenerId,
    channel_id: channelId,
    peer_addr: peerAddr,
    peer_port: peerPort,
  };
}

export function inboundAccept({ channelId, gatewayId } = {}) {
  const msg = { type: MSG.INBOUND_ACCEPT, channel_id: channelId };
  if (gatewayId !== undefined) msg.gateway_id = gatewayId;
  return msg;
}

export function inboundReject({ channelId, reason } = {}) {
  const msg = { type: MSG.INBOUND_REJECT, channel_id: channelId };
  if (reason !== undefined) msg.reason = reason;
  return msg;
}

export function dnsResult({ gatewayId, addresses, ttl } = {}) {
  const msg = { type: MSG.DNS_RESULT, gateway_id: gatewayId, addresses };
  if (ttl !== undefined) msg.ttl = ttl;
  return msg;
}

export function listenRequest({ listenerId, port, bindAddr = "0.0.0.0" } = {}) {
  return {
    type: MSG.LISTEN_REQUEST,
    listener_id: listenerId,
    port,
    bind_addr: bindAddr,
  };
}

export function listenOk({ listenerId, actualPort } = {}) {
  return {
    type: MSG.LISTEN_OK,
    listener_id: listenerId,
    actual_port: actualPort,
  };
}

export function listenFail({ listenerId, reason } = {}) {
  return {
    type: MSG.LISTEN_FAIL,
    listener_id: listenerId,
    reason,
  };
}

export function listenClose({ listenerId } = {}) {
  return {
    type: MSG.LISTEN_CLOSE,
    listener_id: listenerId,
  };
}

export function gatewayData({ gatewayId, data } = {}) {
  return {
    type: MSG.GATEWAY_DATA,
    gateway_id: gatewayId,
    data,
  };
}

export function guestInvite({ sessionId, ttl, permissions = ["read"] } = {}) {
  return {
    type: MSG.GUEST_INVITE,
    session_id: sessionId,
    ttl,
    permissions,
  };
}

export function guestJoin({ token, deviceLabel } = {}) {
  const msg = { type: MSG.GUEST_JOIN, token };
  if (deviceLabel !== undefined) msg.device_label = deviceLabel;
  return msg;
}

export function guestRevoke({ token, reason } = {}) {
  const msg = { type: MSG.GUEST_REVOKE, token };
  if (reason !== undefined) msg.reason = reason;
  return msg;
}

export function shareSession({ sessionId, mode = "read", ttl } = {}) {
  return {
    type: MSG.SHARE_SESSION,
    session_id: sessionId,
    mode,
    ttl,
  };
}

export function shareRevoke({ shareId, reason } = {}) {
  const msg = { type: MSG.SHARE_REVOKE, share_id: shareId };
  if (reason !== undefined) msg.reason = reason;
  return msg;
}

export function compressBegin({ algorithm, level = 3 } = {}) {
  return {
    type: MSG.COMPRESS_BEGIN,
    algorithm,
    level,
  };
}

export function compressAck({ algorithm, accepted } = {}) {
  return {
    type: MSG.COMPRESS_ACK,
    algorithm,
    accepted,
  };
}

export function rateControl({ sessionId, maxBytesPerSec, policy = "pause" } = {}) {
  return {
    type: MSG.RATE_CONTROL,
    session_id: sessionId,
    max_bytes_per_sec: maxBytesPerSec,
    policy,
  };
}

export function rateWarning({ sessionId, queuedBytes, action } = {}) {
  return {
    type: MSG.RATE_WARNING,
    session_id: sessionId,
    queued_bytes: queuedBytes,
    action,
  };
}

export function sessionLink({ sourceSession, targetHost, targetPort, targetUser } = {}) {
  const msg = { type: MSG.SESSION_LINK, source_session: sourceSession, target_host: targetHost, target_port: targetPort };
  if (targetUser !== undefined) msg.target_user = targetUser;
  return msg;
}

export function sessionUnlink({ linkId, reason } = {}) {
  const msg = { type: MSG.SESSION_UNLINK, link_id: linkId };
  if (reason !== undefined) msg.reason = reason;
  return msg;
}

export function copilotAttach({ sessionId, model, contextWindow } = {}) {
  const msg = { type: MSG.COPILOT_ATTACH, session_id: sessionId, model };
  if (contextWindow !== undefined) msg.context_window = contextWindow;
  return msg;
}

export function copilotSuggest({ sessionId, suggestion, confidence } = {}) {
  const msg = { type: MSG.COPILOT_SUGGEST, session_id: sessionId, suggestion };
  if (confidence !== undefined) msg.confidence = confidence;
  return msg;
}

export function copilotDetach({ sessionId, reason } = {}) {
  const msg = { type: MSG.COPILOT_DETACH, session_id: sessionId };
  if (reason !== undefined) msg.reason = reason;
  return msg;
}

export function keyExchange({ algorithm, publicKey, sessionId } = {}) {
  return {
    type: MSG.KEY_EXCHANGE,
    algorithm,
    public_key: publicKey,
    session_id: sessionId,
  };
}

export function encryptedFrame({ nonce, ciphertext, sessionId } = {}) {
  return {
    type: MSG.ENCRYPTED_FRAME,
    nonce,
    ciphertext,
    session_id: sessionId,
  };
}

export function echoAck({ channelId, echoSeq } = {}) {
  return {
    type: MSG.ECHO_ACK,
    channel_id: channelId,
    echo_seq: echoSeq,
  };
}

export function echoState({ channelId, echoSeq, cursorX, cursorY, pending } = {}) {
  return {
    type: MSG.ECHO_STATE,
    channel_id: channelId,
    echo_seq: echoSeq,
    cursor_x: cursorX,
    cursor_y: cursorY,
    pending,
  };
}

export function termSync({ channelId, frameSeq, stateHash } = {}) {
  return {
    type: MSG.TERM_SYNC,
    channel_id: channelId,
    frame_seq: frameSeq,
    state_hash: stateHash,
  };
}

export function termDiff({ channelId, frameSeq, baseSeq, patch } = {}) {
  return {
    type: MSG.TERM_DIFF,
    channel_id: channelId,
    frame_seq: frameSeq,
    base_seq: baseSeq,
    patch,
  };
}

export function nodeAnnounce({ nodeId, endpoint, load, capacity } = {}) {
  return {
    type: MSG.NODE_ANNOUNCE,
    node_id: nodeId,
    endpoint,
    load,
    capacity,
  };
}

export function nodeRedirect({ targetNode, targetEndpoint, sessionId, reason } = {}) {
  const msg = { type: MSG.NODE_REDIRECT, target_node: targetNode, target_endpoint: targetEndpoint, session_id: sessionId };
  if (reason !== undefined) msg.reason = reason;
  return msg;
}

export function sessionGrant({ sessionId, principal, permissions = ["read"] } = {}) {
  return {
    type: MSG.SESSION_GRANT,
    session_id: sessionId,
    principal,
    permissions,
  };
}

export function sessionRevoke({ sessionId, principal, reason } = {}) {
  const msg = { type: MSG.SESSION_REVOKE, session_id: sessionId, principal };
  if (reason !== undefined) msg.reason = reason;
  return msg;
}

export function fileOp({ channelId, op, path, offset, length } = {}) {
  const msg = { type: MSG.FILE_OP, channel_id: channelId, op, path };
  if (offset !== undefined) msg.offset = offset;
  if (length !== undefined) msg.length = length;
  return msg;
}

export function fileResult({ channelId, success, metadata = {}, errorMessage } = {}) {
  const msg = { type: MSG.FILE_RESULT, channel_id: channelId, success, metadata };
  if (errorMessage !== undefined) msg.error_message = errorMessage;
  return msg;
}

export function fileChunk({ channelId, offset, data, isFinal } = {}) {
  return {
    type: MSG.FILE_CHUNK,
    channel_id: channelId,
    offset,
    data,
    is_final: isFinal,
  };
}

export function policyEval({ requestId, action, principal, context = {} } = {}) {
  return {
    type: MSG.POLICY_EVAL,
    request_id: requestId,
    action,
    principal,
    context,
  };
}

export function policyResult({ requestId, allowed, reason } = {}) {
  const msg = { type: MSG.POLICY_RESULT, request_id: requestId, allowed };
  if (reason !== undefined) msg.reason = reason;
  return msg;
}

export function policyUpdate({ policyId, rules, version } = {}) {
  return {
    type: MSG.POLICY_UPDATE,
    policy_id: policyId,
    rules,
    version,
  };
}

export function terminalConfig({ channelId, frontend, options = {} } = {}) {
  return {
    type: MSG.TERMINAL_CONFIG,
    channel_id: channelId,
    frontend,
    options,
  };
}

// ── Utility ───────────────────────────────────────────────────────────

/**
 * Get the human-readable name for a message type number.
 * @param {number} typeNum
 * @returns {string}
 */
export function msgName(typeNum) {
  return MSG_NAMES[typeNum] || `UNKNOWN(0x${typeNum.toString(16)})`;
}

/**
 * Validate that a message has a recognized type field.
 * @param {object} msg
 * @returns {boolean}
 */
export function isValidMessage(msg) {
  return msg != null && typeof msg === 'object' && typeof msg.type === 'number' && msg.type in MSG_NAMES;
}
