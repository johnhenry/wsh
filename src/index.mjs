/**
 * wsh — Web Shell client library
 *
 * Browser-native remote command execution over WebTransport/WebSocket
 * with Ed25519 authentication.
 */

// CBOR codec + framing
export { cborEncode, cborDecode, frameEncode, FrameDecoder, FrameSizeError, DEFAULT_MAX_FRAME_SIZE } from './cbor.mjs';

// Protocol messages
export {
  MSG, MSG_NAMES, CHANNEL_KIND, AUTH_METHOD, PROTOCOL_VERSION,
  hello, serverHello, challenge, authMethods, auth, authOk, authFail,
  open, openOk, openFail, resize, signal, exit, close, sessionData, error, ping, pong,
  attach, resume, rename, idleWarning, shutdown, snapshot,
  presence, controlChanged, metrics,
  mcpDiscover, mcpTools, mcpCall, mcpResult,
  reverseRegister, reverseList, reversePeers, reverseConnect, reverseAccept, reverseReject,
  relayForward, RELAY_FORWARDABLE, isRelayForwardable,
  openTcp, openUdp, resolveDns, gatewayOk, gatewayFail, gatewayClose,
  inboundOpen, inboundAccept, inboundReject, dnsResult,
  listenRequest, listenOk, listenFail, listenClose, gatewayData,
  clipboard, recordingExport, commandJournal, metricsRequest,
  suspendSession, restartPty, sessionListRequest, sessionList,
  detach, detachOk, detachFail,
  guestInvite, guestJoin, guestRevoke,
  shareSession, shareRevoke,
  compressBegin, compressAck,
  rateControl, rateWarning,
  sessionLink, sessionUnlink,
  copilotAttach, copilotSuggest, copilotDetach,
  keyExchange, encryptedFrame,
  echoAck, echoState, termSync, termDiff,
  nodeAnnounce, nodeRedirect,
  sessionGrant, sessionRevoke,
  fileOp, fileResult, fileChunk,
  policyEval, policyResult, policyUpdate,
  terminalConfig,
  msgName, isValidMessage,
} from './messages.mjs';

// Auth + crypto
export {
  isEd25519Supported,
  generateKeyPair, exportPublicKeyRaw, exportPublicKeySSH,
  importPublicKeyRaw, exportPrivateKeyPKCS8, importPrivateKeyPKCS8,
  sign, verify, buildTranscript, signChallenge, verifyChallenge,
  buildPeerRecordTranscript, signPeerRecord, verifyPeerRecord,
  fingerprint, shortFingerprint, generateNonce,
  parseSSHPublicKey, extractRawFromSSHWire, base64Decode,
} from './auth.mjs';

// Transport
export {
  WshTransport, WebTransportTransport, dispatchSerially, SerialQueue,
  parseCertificateHash, normalizeWebTransportOptions,
} from './transport.mjs';
export { WebSocketTransport, WS_FRAME_TYPE } from './transport-ws.mjs';

// QMux (QUIC-v1 frames over an ordered byte stream, draft-ietf-quic-qmux-02)
// -- the wire multiplexing layer WebSocketTransport speaks. Exposed so an
// alternate server implementation (not just the Rust wsh-server, which
// vendors its own port) can speak the same framing without reimplementing
// it -- see clawser's tools/wsh-server.mjs for exactly this use case.
export { QMuxConnection, DEFAULTS as QMUX_DEFAULTS } from './qmux-connection.mjs';
export {
  ERROR_CODE as QMUX_ERROR_CODE, STREAM_INITIATOR as QMUX_STREAM_INITIATOR,
  firstBidiStreamId, nextBidiStreamId, isClientInitiated, isBidirectional,
} from './qmux.mjs';

// Session + Client
export { WshSession } from './session.mjs';
export { WshVirtualSessionBackend, normalizeSessionData } from './virtual-session.mjs';
export { WshClient } from './client.mjs';

// Key storage
export { WshKeyStore } from './keystore.mjs';

// File transfer
export { WshFileTransfer } from './file-transfer.mjs';

// Session recording
export { SessionRecorder, SessionPlayer } from './recording.mjs';

// MCP bridge
export { WshMcpBridge } from './mcp-bridge.mjs';
