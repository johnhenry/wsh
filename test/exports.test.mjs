import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// All message constructors that should be exported from the package barrel
const EXPECTED_CONSTRUCTORS = [
  // Handshake
  'hello', 'serverHello', 'challenge', 'authMethods', 'auth', 'authOk', 'authFail',
  // Channel
  'open', 'openOk', 'openFail', 'resize', 'signal', 'exit', 'close', 'error', 'ping', 'pong',
  // Session
  'attach', 'resume', 'rename', 'idleWarning', 'shutdown', 'snapshot',
  'presence', 'controlChanged', 'metrics',
  // MCP
  'mcpDiscover', 'mcpTools', 'mcpCall', 'mcpResult',
  // Reverse
  'reverseRegister', 'reverseList', 'reversePeers', 'reverseConnect',
  // Gateway
  'openTcp', 'openUdp', 'resolveDns', 'gatewayOk', 'gatewayFail', 'gatewayClose',
  'inboundOpen', 'inboundAccept', 'inboundReject', 'dnsResult',
  'listenRequest', 'listenOk', 'listenFail', 'listenClose', 'gatewayData',
  // Session extended
  'clipboard', 'recordingExport', 'commandJournal', 'metricsRequest',
  'suspendSession', 'restartPty', 'sessionListRequest', 'sessionList',
  'detach', 'detachOk', 'detachFail',
  // Guest
  'guestInvite', 'guestJoin', 'guestRevoke',
  // Sharing
  'shareSession', 'shareRevoke',
  // Compression
  'compressBegin', 'compressAck',
  // Rate control
  'rateControl', 'rateWarning',
  // Linking
  'sessionLink', 'sessionUnlink',
  // Copilot
  'copilotAttach', 'copilotSuggest', 'copilotDetach',
  // E2E
  'keyExchange', 'encryptedFrame',
  // Echo
  'echoAck', 'echoState',
  // TermSync
  'termSync', 'termDiff',
  // Scaling
  'nodeAnnounce', 'nodeRedirect',
  // Principals
  'sessionGrant', 'sessionRevoke',
  // File channel
  'fileOp', 'fileResult', 'fileChunk',
  // Policy
  'policyEval', 'policyResult', 'policyUpdate',
  // Terminal
  'terminalConfig',
  // Utilities
  'msgName', 'isValidMessage',
];

describe('wsh exports', () => {
  it('all message constructors are exported from index.mjs', async () => {
    const mod = await import('../src/index.mjs');
    for (const name of EXPECTED_CONSTRUCTORS) {
      assert.equal(typeof mod[name], 'function', `Missing export: ${name}`);
    }
  });

  it('MSG constant has all expected opcodes', async () => {
    const { MSG } = await import('../src/index.mjs');
    const expected = [
      'HELLO', 'SERVER_HELLO', 'CHALLENGE', 'AUTH_METHODS', 'AUTH', 'AUTH_OK', 'AUTH_FAIL',
      'OPEN', 'OPEN_OK', 'OPEN_FAIL', 'RESIZE', 'SIGNAL', 'EXIT', 'CLOSE',
      'ERROR', 'PING', 'PONG',
      'ATTACH', 'RESUME', 'RENAME', 'IDLE_WARNING', 'SHUTDOWN', 'SNAPSHOT',
      'PRESENCE', 'CONTROL_CHANGED', 'METRICS',
      'CLIPBOARD', 'RECORDING_EXPORT', 'COMMAND_JOURNAL', 'METRICS_REQUEST',
      'SUSPEND_SESSION', 'RESTART_PTY', 'SESSION_LIST_REQUEST',
      'MCP_DISCOVER', 'MCP_TOOLS', 'MCP_CALL', 'MCP_RESULT',
      'REVERSE_REGISTER', 'REVERSE_LIST', 'REVERSE_PEERS', 'REVERSE_CONNECT',
      'SESSION_LIST', 'DETACH', 'DETACH_OK', 'DETACH_FAIL',
      'GUEST_INVITE', 'GUEST_JOIN', 'GUEST_REVOKE',
      'SHARE_SESSION', 'SHARE_REVOKE',
      'COMPRESS_BEGIN', 'COMPRESS_ACK',
      'RATE_CONTROL', 'RATE_WARNING',
      'SESSION_LINK', 'SESSION_UNLINK',
      'COPILOT_ATTACH', 'COPILOT_SUGGEST', 'COPILOT_DETACH',
      'KEY_EXCHANGE', 'ENCRYPTED_FRAME',
      'ECHO_ACK', 'ECHO_STATE', 'TERM_SYNC', 'TERM_DIFF',
      'NODE_ANNOUNCE', 'NODE_REDIRECT',
      'SESSION_GRANT', 'SESSION_REVOKE',
      'FILE_OP', 'FILE_RESULT', 'FILE_CHUNK',
      'POLICY_EVAL', 'POLICY_RESULT', 'POLICY_UPDATE',
      'TERMINAL_CONFIG',
    ];
    for (const name of expected) {
      assert.equal(typeof MSG[name], 'number', `MSG.${name} should be a number`);
    }
  });

  it('each constructor returns an object with the correct type field', async () => {
    const mod = await import('../src/index.mjs');
    const { MSG } = mod;

    // Spot-check a selection of constructors
    assert.equal(mod.suspendSession({ sessionId: 'x', action: 'suspend' }).type, MSG.SUSPEND_SESSION);
    assert.equal(mod.restartPty({ sessionId: 'x' }).type, MSG.RESTART_PTY);
    assert.equal(mod.metricsRequest().type, MSG.METRICS_REQUEST);
    assert.equal(mod.guestInvite({ sessionId: 'x', ttl: 300 }).type, MSG.GUEST_INVITE);
    assert.equal(mod.guestJoin({ token: 'abc' }).type, MSG.GUEST_JOIN);
    assert.equal(mod.shareSession({ sessionId: 'x' }).type, MSG.SHARE_SESSION);
    assert.equal(mod.compressBegin({ algorithm: 'zstd' }).type, MSG.COMPRESS_BEGIN);
    assert.equal(mod.rateControl({ sessionId: 'x', maxBytesPerSec: 1024 }).type, MSG.RATE_CONTROL);
    assert.equal(mod.sessionLink({ sourceSession: 'a', targetHost: 'b', targetPort: 22 }).type, MSG.SESSION_LINK);
    assert.equal(mod.copilotAttach({ sessionId: 'x', model: 'gpt-4' }).type, MSG.COPILOT_ATTACH);
    assert.equal(mod.keyExchange({ algorithm: 'x25519', publicKey: new Uint8Array(32), sessionId: 'x' }).type, MSG.KEY_EXCHANGE);
    assert.equal(mod.fileOp({ channelId: 1, op: 'stat', path: '/tmp' }).type, MSG.FILE_OP);
    assert.equal(mod.policyEval({ requestId: '1', action: 'exec', principal: 'user' }).type, MSG.POLICY_EVAL);
    assert.equal(mod.terminalConfig({ channelId: 1, frontend: 'xterm' }).type, MSG.TERMINAL_CONFIG);
  });

  it('exports WS_FRAME_TYPE with the correct mux frame-type values', async () => {
    const { WS_FRAME_TYPE } = await import('../src/index.mjs');
    assert.deepEqual(WS_FRAME_TYPE, {
      CONTROL: 0x01,
      DATA: 0x02,
      OPEN_STREAM: 0x03,
      CLOSE_STREAM: 0x04,
    });
    assert.ok(Object.isFrozen(WS_FRAME_TYPE));
  });

  it('exports dispatchSerially and SerialQueue', async () => {
    const { dispatchSerially, SerialQueue } = await import('../src/index.mjs');
    assert.equal(typeof dispatchSerially, 'function');
    assert.equal(typeof SerialQueue, 'function');
  });
});
