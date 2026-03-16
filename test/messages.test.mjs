import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  MSG, MSG_NAMES, PROTOCOL_VERSION,
  hello, serverHello, challenge, authMethods, auth, authOk, authFail,
  open, openOk, openFail, resize, signal, exit, close, error, ping, pong,
  attach, resume, rename, idleWarning, shutdown, snapshot,
  presence, controlChanged, metrics,
  clipboard, recordingExport, commandJournal, metricsRequest, suspendSession, restartPty,
  mcpDiscover, mcpTools, mcpCall, mcpResult,
  reverseRegister, reverseList, reversePeers, reverseConnect,
  openTcp, openUdp, resolveDns, gatewayOk, gatewayFail, gatewayClose,
  inboundOpen, inboundAccept, inboundReject, dnsResult,
  listenRequest, listenOk, listenFail, listenClose, gatewayData,
  guestInvite, guestJoin, guestRevoke,
  shareSession, shareRevoke,
  compressBegin, compressAck,
  rateControl, rateWarning,
  sessionLink, sessionUnlink,
  copilotAttach, copilotSuggest, copilotDetach,
  keyExchange, encryptedFrame,
  echoAck, echoState,
  termSync, termDiff,
  nodeAnnounce, nodeRedirect,
  sessionGrant, sessionRevoke,
  fileOp, fileResult, fileChunk,
  policyEval, policyResult, policyUpdate,
  terminalConfig,
  msgName, isValidMessage,
  AUTH_METHOD, CHANNEL_KIND,
} from '../src/messages.mjs';

describe('MSG constants', () => {
  // DETACH (0x60) and WS_DATA (0x60) intentionally share the same opcode:
  // WS_DATA is a framing-layer marker, DETACH is a session-layer message.
  const KNOWN_ALIASES = new Set([0x60]);

  it('has unique values (except known aliases)', () => {
    const values = Object.values(MSG);
    const seen = new Map();
    for (const [name, value] of Object.entries(MSG)) {
      if (seen.has(value) && !KNOWN_ALIASES.has(value)) {
        assert.fail(`Duplicate MSG value 0x${value.toString(16)}: ${seen.get(value)} and ${name}`);
      }
      seen.set(value, name);
    }
    // Verify we have the expected count (total entries minus known aliases)
    const aliasCount = [...KNOWN_ALIASES].reduce((n, v) => {
      const names = Object.entries(MSG).filter(([, val]) => val === v);
      return n + names.length - 1;
    }, 0);
    const unique = new Set(values);
    assert.equal(values.length - aliasCount, unique.size, 'MSG values must be unique (excluding known aliases)');
  });

  it('MSG_NAMES maps back correctly (last-wins for aliases)', () => {
    for (const [name, value] of Object.entries(MSG)) {
      // For aliased opcodes, MSG_NAMES maps to whichever name was last in Object.entries
      if (KNOWN_ALIASES.has(value)) continue;
      assert.equal(MSG_NAMES[value], name);
    }
  });
});

describe('msgName', () => {
  it('returns name for known types', () => {
    assert.equal(msgName(MSG.HELLO), 'HELLO');
    assert.equal(msgName(MSG.AUTH_OK), 'AUTH_OK');
    assert.equal(msgName(MSG.MCP_CALL), 'MCP_CALL');
  });

  it('returns UNKNOWN for unrecognized types', () => {
    assert.ok(msgName(0xff).startsWith('UNKNOWN'));
  });
});

describe('isValidMessage', () => {
  it('validates known message objects', () => {
    assert.ok(isValidMessage(hello({ username: 'test' })));
    assert.ok(isValidMessage(ping({ id: 1 })));
  });

  it('rejects invalid inputs', () => {
    assert.ok(!isValidMessage(null));
    assert.ok(!isValidMessage({}));
    assert.ok(!isValidMessage({ type: 'string' }));
    assert.ok(!isValidMessage({ type: 0xff }));
  });
});

describe('message constructors', () => {
  it('hello', () => {
    const msg = hello({ username: 'john', features: ['pty'] });
    assert.equal(msg.type, MSG.HELLO);
    assert.equal(msg.version, PROTOCOL_VERSION);
    assert.equal(msg.username, 'john');
    assert.deepEqual(msg.features, ['pty']);
    assert.equal(msg.auth_method, AUTH_METHOD.PUBKEY);
  });

  it('serverHello', () => {
    const msg = serverHello({ sessionId: 'abc', fingerprints: ['a3f8'] });
    assert.equal(msg.type, MSG.SERVER_HELLO);
    assert.equal(msg.session_id, 'abc');
    assert.deepEqual(msg.fingerprints, ['a3f8']);
  });

  it('challenge', () => {
    const nonce = new Uint8Array(32);
    const msg = challenge({ nonce });
    assert.equal(msg.type, MSG.CHALLENGE);
    assert.equal(msg.nonce, nonce);
  });

  it('auth (pubkey)', () => {
    const sig = new Uint8Array(64);
    const pk = new Uint8Array(32);
    const msg = auth({ method: AUTH_METHOD.PUBKEY, signature: sig, publicKey: pk });
    assert.equal(msg.type, MSG.AUTH);
    assert.equal(msg.method, 'pubkey');
    assert.equal(msg.signature, sig);
    assert.equal(msg.public_key, pk);
    assert.equal(msg.password, undefined);
  });

  it('auth (password)', () => {
    const msg = auth({ method: AUTH_METHOD.PASSWORD, password: 'secret' });
    assert.equal(msg.type, MSG.AUTH);
    assert.equal(msg.method, 'password');
    assert.equal(msg.password, 'secret');
  });

  it('authOk', () => {
    const token = new Uint8Array(40);
    const msg = authOk({ sessionId: 's1', token, ttl: 3600 });
    assert.equal(msg.type, MSG.AUTH_OK);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.ttl, 3600);
  });

  it('authFail', () => {
    const msg = authFail({ reason: 'bad key' });
    assert.equal(msg.type, MSG.AUTH_FAIL);
    assert.equal(msg.reason, 'bad key');
  });

  it('open', () => {
    const msg = open({ kind: CHANNEL_KIND.PTY, cols: 80, rows: 24 });
    assert.equal(msg.type, MSG.OPEN);
    assert.equal(msg.kind, 'pty');
    assert.equal(msg.cols, 80);
    assert.equal(msg.rows, 24);
  });

  it('open (exec with command)', () => {
    const msg = open({ kind: CHANNEL_KIND.EXEC, command: 'ls -la' });
    assert.equal(msg.kind, 'exec');
    assert.equal(msg.command, 'ls -la');
  });

  it('openOk', () => {
    const msg = openOk({ channelId: 1, streamIds: [2, 3] });
    assert.equal(msg.type, MSG.OPEN_OK);
    assert.equal(msg.channel_id, 1);
    assert.deepEqual(msg.stream_ids, [2, 3]);
  });

  it('resize', () => {
    const msg = resize({ channelId: 1, cols: 120, rows: 40 });
    assert.equal(msg.type, MSG.RESIZE);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.cols, 120);
  });

  it('signal', () => {
    const msg = signal({ channelId: 1, signal: 'SIGINT' });
    assert.equal(msg.type, MSG.SIGNAL);
    assert.equal(msg.signal, 'SIGINT');
  });

  it('exit', () => {
    const msg = exit({ channelId: 1, code: 0 });
    assert.equal(msg.type, MSG.EXIT);
    assert.equal(msg.code, 0);
  });

  it('close', () => {
    const msg = close({ channelId: 1 });
    assert.equal(msg.type, MSG.CLOSE);
    assert.equal(msg.channel_id, 1);
  });

  it('ping/pong', () => {
    assert.equal(ping({ id: 42 }).type, MSG.PING);
    assert.equal(pong({ id: 42 }).type, MSG.PONG);
    assert.equal(pong({ id: 42 }).id, 42);
  });

  it('attach', () => {
    const msg = attach({ sessionId: 's1', token: new Uint8Array(40), mode: 'read' });
    assert.equal(msg.type, MSG.ATTACH);
    assert.equal(msg.mode, 'read');
  });

  it('mcpDiscover', () => {
    assert.equal(mcpDiscover().type, MSG.MCP_DISCOVER);
  });

  it('mcpTools', () => {
    const msg = mcpTools({ tools: [{ name: 'git', description: 'Git tool' }] });
    assert.equal(msg.type, MSG.MCP_TOOLS);
    assert.equal(msg.tools.length, 1);
  });

  it('reverseRegister', () => {
    const msg = reverseRegister({
      username: 'john',
      capabilities: ['shell', 'fs'],
      publicKey: new Uint8Array(32),
    });
    assert.equal(msg.type, MSG.REVERSE_REGISTER);
    assert.deepEqual(msg.capabilities, ['shell', 'fs']);
  });

  it('metrics', () => {
    const msg = metrics({ cpu: 0.5, memory: 1024, sessions: 3, rtt: 50 });
    assert.equal(msg.type, MSG.METRICS);
    assert.equal(msg.cpu, 0.5);
  });

  // ── Gateway messages ─────────────────────────────────────────────

  it('openTcp', () => {
    const msg = openTcp({ gatewayId: 1, host: 'example.com', port: 80 });
    assert.equal(msg.type, MSG.OPEN_TCP);
    assert.equal(msg.gateway_id, 1);
    assert.equal(msg.host, 'example.com');
    assert.equal(msg.port, 80);
  });

  it('openUdp', () => {
    const msg = openUdp({ gatewayId: 2, host: '10.0.0.1', port: 53 });
    assert.equal(msg.type, MSG.OPEN_UDP);
    assert.equal(msg.gateway_id, 2);
    assert.equal(msg.host, '10.0.0.1');
    assert.equal(msg.port, 53);
  });

  it('resolveDns', () => {
    const msg = resolveDns({ gatewayId: 3, name: 'example.com' });
    assert.equal(msg.type, MSG.RESOLVE_DNS);
    assert.equal(msg.gateway_id, 3);
    assert.equal(msg.name, 'example.com');
    assert.equal(msg.record_type, 'A');
  });

  it('resolveDns with custom record type', () => {
    const msg = resolveDns({ gatewayId: 4, name: 'example.com', recordType: 'AAAA' });
    assert.equal(msg.record_type, 'AAAA');
  });

  it('gatewayOk', () => {
    const msg = gatewayOk({ gatewayId: 1, resolvedAddr: '93.184.216.34' });
    assert.equal(msg.type, MSG.GATEWAY_OK);
    assert.equal(msg.gateway_id, 1);
    assert.equal(msg.resolved_addr, '93.184.216.34');
  });

  it('gatewayOk without resolved addr', () => {
    const msg = gatewayOk({ gatewayId: 1 });
    assert.equal(msg.type, MSG.GATEWAY_OK);
    assert.equal(msg.resolved_addr, undefined);
  });

  it('gatewayFail', () => {
    const msg = gatewayFail({ gatewayId: 1, code: 111, message: 'Connection refused' });
    assert.equal(msg.type, MSG.GATEWAY_FAIL);
    assert.equal(msg.gateway_id, 1);
    assert.equal(msg.code, 111);
    assert.equal(msg.message, 'Connection refused');
  });

  it('gatewayClose', () => {
    const msg = gatewayClose({ gatewayId: 1, reason: 'peer reset' });
    assert.equal(msg.type, MSG.GATEWAY_CLOSE);
    assert.equal(msg.gateway_id, 1);
    assert.equal(msg.reason, 'peer reset');
  });

  it('gatewayClose without reason', () => {
    const msg = gatewayClose({ gatewayId: 1 });
    assert.equal(msg.reason, undefined);
  });

  it('inboundOpen', () => {
    const msg = inboundOpen({ listenerId: 1, channelId: 5, peerAddr: '10.0.0.2', peerPort: 54321 });
    assert.equal(msg.type, MSG.INBOUND_OPEN);
    assert.equal(msg.listener_id, 1);
    assert.equal(msg.channel_id, 5);
    assert.equal(msg.peer_addr, '10.0.0.2');
    assert.equal(msg.peer_port, 54321);
  });

  it('inboundAccept', () => {
    const msg = inboundAccept({ channelId: 5 });
    assert.equal(msg.type, MSG.INBOUND_ACCEPT);
    assert.equal(msg.channel_id, 5);
    assert.equal(msg.gateway_id, undefined);
  });

  it('inboundAccept with gateway_id', () => {
    const msg = inboundAccept({ channelId: 5, gatewayId: 42 });
    assert.equal(msg.type, MSG.INBOUND_ACCEPT);
    assert.equal(msg.channel_id, 5);
    assert.equal(msg.gateway_id, 42);
  });

  it('inboundReject', () => {
    const msg = inboundReject({ channelId: 5, reason: 'policy denied' });
    assert.equal(msg.type, MSG.INBOUND_REJECT);
    assert.equal(msg.channel_id, 5);
    assert.equal(msg.reason, 'policy denied');
  });

  it('inboundReject without reason', () => {
    const msg = inboundReject({ channelId: 5 });
    assert.equal(msg.reason, undefined);
  });

  it('dnsResult', () => {
    const msg = dnsResult({ gatewayId: 3, addresses: ['93.184.216.34', '2606:2800:220:1::'], ttl: 300 });
    assert.equal(msg.type, MSG.DNS_RESULT);
    assert.equal(msg.gateway_id, 3);
    assert.deepEqual(msg.addresses, ['93.184.216.34', '2606:2800:220:1::']);
    assert.equal(msg.ttl, 300);
  });

  it('dnsResult without ttl', () => {
    const msg = dnsResult({ gatewayId: 3, addresses: ['127.0.0.1'] });
    assert.equal(msg.ttl, undefined);
  });

  it('listenRequest', () => {
    const msg = listenRequest({ listenerId: 1, port: 8080 });
    assert.equal(msg.type, MSG.LISTEN_REQUEST);
    assert.equal(msg.listener_id, 1);
    assert.equal(msg.port, 8080);
    assert.equal(msg.bind_addr, '0.0.0.0');
  });

  it('listenRequest with custom bind addr', () => {
    const msg = listenRequest({ listenerId: 1, port: 8080, bindAddr: '127.0.0.1' });
    assert.equal(msg.bind_addr, '127.0.0.1');
  });

  it('listenOk', () => {
    const msg = listenOk({ listenerId: 1, actualPort: 8080 });
    assert.equal(msg.type, MSG.LISTEN_OK);
    assert.equal(msg.listener_id, 1);
    assert.equal(msg.actual_port, 8080);
  });

  it('listenFail', () => {
    const msg = listenFail({ listenerId: 1, reason: 'address in use' });
    assert.equal(msg.type, MSG.LISTEN_FAIL);
    assert.equal(msg.listener_id, 1);
    assert.equal(msg.reason, 'address in use');
  });

  it('listenClose', () => {
    const msg = listenClose({ listenerId: 1 });
    assert.equal(msg.type, MSG.LISTEN_CLOSE);
    assert.equal(msg.listener_id, 1);
  });

  it('gatewayData', () => {
    const payload = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
    const msg = gatewayData({ gatewayId: 7, data: payload });
    assert.equal(msg.type, MSG.GATEWAY_DATA);
    assert.equal(msg.gateway_id, 7);
    assert.equal(msg.data, payload);
  });
});

describe('CHANNEL_KIND extensions', () => {
  it('has tcp and udp kinds', () => {
    assert.equal(CHANNEL_KIND.TCP, 'tcp');
    assert.equal(CHANNEL_KIND.UDP, 'udp');
  });

  it('still has original kinds', () => {
    assert.equal(CHANNEL_KIND.PTY, 'pty');
    assert.equal(CHANNEL_KIND.EXEC, 'exec');
    assert.equal(CHANNEL_KIND.META, 'meta');
    assert.equal(CHANNEL_KIND.FILE, 'file');
  });

  it('has exactly 7 kinds', () => {
    assert.equal(Object.keys(CHANNEL_KIND).length, 7);
  });
});

describe('ephemeral guest sessions', () => {
  it('guestInvite', () => {
    const msg = guestInvite({ sessionId: 's1', ttl: 600, permissions: ['read'] });
    assert.equal(msg.type, MSG.GUEST_INVITE);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.ttl, 600);
    assert.deepEqual(msg.permissions, ['read']);
  });

  it('guestInvite with default permissions', () => {
    const msg = guestInvite({ sessionId: 's1', ttl: 300 });
    assert.deepEqual(msg.permissions, ['read']);
  });

  it('guestJoin', () => {
    const msg = guestJoin({ token: 'abc123', deviceLabel: 'Guest/Chrome' });
    assert.equal(msg.type, MSG.GUEST_JOIN);
    assert.equal(msg.token, 'abc123');
    assert.equal(msg.device_label, 'Guest/Chrome');
  });

  it('guestJoin without device label', () => {
    const msg = guestJoin({ token: 'abc123' });
    assert.equal(msg.device_label, undefined);
  });

  it('guestRevoke', () => {
    const msg = guestRevoke({ token: 'abc123', reason: 'expired' });
    assert.equal(msg.type, MSG.GUEST_REVOKE);
    assert.equal(msg.token, 'abc123');
    assert.equal(msg.reason, 'expired');
  });

  it('guestRevoke without reason', () => {
    const msg = guestRevoke({ token: 'abc123' });
    assert.equal(msg.reason, undefined);
  });

  it('guest message codes in 0x80-0x82 range', () => {
    assert.equal(MSG.GUEST_INVITE, 0x80);
    assert.equal(MSG.GUEST_JOIN, 0x81);
    assert.equal(MSG.GUEST_REVOKE, 0x82);
  });

  it('guest messages validate correctly', () => {
    assert.ok(isValidMessage(guestInvite({ sessionId: 's1', ttl: 300 })));
    assert.ok(isValidMessage(guestJoin({ token: 'x' })));
    assert.ok(isValidMessage(guestRevoke({ token: 'x' })));
  });
});

describe('multi-attach read-only URL sharing', () => {
  it('shareSession', () => {
    const msg = shareSession({ sessionId: 's1', mode: 'read', ttl: 3600 });
    assert.equal(msg.type, MSG.SHARE_SESSION);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.mode, 'read');
    assert.equal(msg.ttl, 3600);
  });

  it('shareSession with default mode', () => {
    const msg = shareSession({ sessionId: 's1', ttl: 600 });
    assert.equal(msg.mode, 'read');
  });

  it('shareRevoke', () => {
    const msg = shareRevoke({ shareId: 'share-abc', reason: 'no longer needed' });
    assert.equal(msg.type, MSG.SHARE_REVOKE);
    assert.equal(msg.share_id, 'share-abc');
    assert.equal(msg.reason, 'no longer needed');
  });

  it('shareRevoke without reason', () => {
    const msg = shareRevoke({ shareId: 'share-abc' });
    assert.equal(msg.reason, undefined);
  });

  it('share message codes', () => {
    assert.equal(MSG.SHARE_SESSION, 0x83);
    assert.equal(MSG.SHARE_REVOKE, 0x84);
  });

  it('share messages validate correctly', () => {
    assert.ok(isValidMessage(shareSession({ sessionId: 's1', ttl: 60 })));
    assert.ok(isValidMessage(shareRevoke({ shareId: 'x' })));
  });
});

describe('stream compression negotiation', () => {
  it('compressBegin', () => {
    const msg = compressBegin({ algorithm: 'zstd', level: 3 });
    assert.equal(msg.type, MSG.COMPRESS_BEGIN);
    assert.equal(msg.algorithm, 'zstd');
    assert.equal(msg.level, 3);
  });

  it('compressBegin with default level', () => {
    const msg = compressBegin({ algorithm: 'zstd' });
    assert.equal(msg.level, 3);
  });

  it('compressAck', () => {
    const msg = compressAck({ algorithm: 'zstd', accepted: true });
    assert.equal(msg.type, MSG.COMPRESS_ACK);
    assert.equal(msg.algorithm, 'zstd');
    assert.equal(msg.accepted, true);
  });

  it('compressAck rejected', () => {
    const msg = compressAck({ algorithm: 'zstd', accepted: false });
    assert.equal(msg.accepted, false);
  });

  it('compress message codes', () => {
    assert.equal(MSG.COMPRESS_BEGIN, 0x85);
    assert.equal(MSG.COMPRESS_ACK, 0x86);
  });

  it('compress messages validate correctly', () => {
    assert.ok(isValidMessage(compressBegin({ algorithm: 'zstd' })));
    assert.ok(isValidMessage(compressAck({ algorithm: 'zstd', accepted: true })));
  });
});

describe('per-attachment rate control', () => {
  it('rateControl', () => {
    const msg = rateControl({ sessionId: 's1', maxBytesPerSec: 1048576, policy: 'drop' });
    assert.equal(msg.type, MSG.RATE_CONTROL);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.max_bytes_per_sec, 1048576);
    assert.equal(msg.policy, 'drop');
  });

  it('rateControl with default policy', () => {
    const msg = rateControl({ sessionId: 's1', maxBytesPerSec: 0 });
    assert.equal(msg.policy, 'pause');
  });

  it('rateWarning', () => {
    const msg = rateWarning({ sessionId: 's1', queuedBytes: 4096, action: 'dropping' });
    assert.equal(msg.type, MSG.RATE_WARNING);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.queued_bytes, 4096);
    assert.equal(msg.action, 'dropping');
  });

  it('rate control codes', () => {
    assert.equal(MSG.RATE_CONTROL, 0x87);
    assert.equal(MSG.RATE_WARNING, 0x88);
  });

  it('rate control messages validate correctly', () => {
    assert.ok(isValidMessage(rateControl({ sessionId: 's1', maxBytesPerSec: 0 })));
    assert.ok(isValidMessage(rateWarning({ sessionId: 's1', queuedBytes: 0, action: 'ok' })));
  });
});

describe('cross-session linking (jump host)', () => {
  it('sessionLink', () => {
    const msg = sessionLink({ sourceSession: 's1', targetHost: 'jump.example.com', targetPort: 22, targetUser: 'admin' });
    assert.equal(msg.type, MSG.SESSION_LINK);
    assert.equal(msg.source_session, 's1');
    assert.equal(msg.target_host, 'jump.example.com');
    assert.equal(msg.target_port, 22);
    assert.equal(msg.target_user, 'admin');
  });

  it('sessionLink with optional target user', () => {
    const msg = sessionLink({ sourceSession: 's1', targetHost: 'host', targetPort: 22 });
    assert.equal(msg.target_user, undefined);
  });

  it('sessionUnlink', () => {
    const msg = sessionUnlink({ linkId: 'link-42', reason: 'user requested' });
    assert.equal(msg.type, MSG.SESSION_UNLINK);
    assert.equal(msg.link_id, 'link-42');
    assert.equal(msg.reason, 'user requested');
  });

  it('sessionUnlink without reason', () => {
    const msg = sessionUnlink({ linkId: 'link-42' });
    assert.equal(msg.reason, undefined);
  });

  it('session link codes', () => {
    assert.equal(MSG.SESSION_LINK, 0x89);
    assert.equal(MSG.SESSION_UNLINK, 0x8a);
  });

  it('session link messages validate correctly', () => {
    assert.ok(isValidMessage(sessionLink({ sourceSession: 's1', targetHost: 'h', targetPort: 22 })));
    assert.ok(isValidMessage(sessionUnlink({ linkId: 'x' })));
  });
});

describe('AI co-pilot attachment mode', () => {
  it('copilotAttach', () => {
    const msg = copilotAttach({ sessionId: 's1', model: 'claude-sonnet', contextWindow: 200000 });
    assert.equal(msg.type, MSG.COPILOT_ATTACH);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.model, 'claude-sonnet');
    assert.equal(msg.context_window, 200000);
  });

  it('copilotAttach with optional context window', () => {
    const msg = copilotAttach({ sessionId: 's1', model: 'gpt-4' });
    assert.equal(msg.context_window, undefined);
  });

  it('copilotSuggest', () => {
    const msg = copilotSuggest({ sessionId: 's1', suggestion: 'try: git stash', confidence: 0.95 });
    assert.equal(msg.type, MSG.COPILOT_SUGGEST);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.suggestion, 'try: git stash');
    assert.equal(msg.confidence, 0.95);
  });

  it('copilotSuggest with optional confidence', () => {
    const msg = copilotSuggest({ sessionId: 's1', suggestion: 'hello' });
    assert.equal(msg.confidence, undefined);
  });

  it('copilotDetach', () => {
    const msg = copilotDetach({ sessionId: 's1', reason: 'user dismissed' });
    assert.equal(msg.type, MSG.COPILOT_DETACH);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.reason, 'user dismissed');
  });

  it('copilotDetach without reason', () => {
    const msg = copilotDetach({ sessionId: 's1' });
    assert.equal(msg.reason, undefined);
  });

  it('copilot codes', () => {
    assert.equal(MSG.COPILOT_ATTACH, 0x8b);
    assert.equal(MSG.COPILOT_SUGGEST, 0x8c);
    assert.equal(MSG.COPILOT_DETACH, 0x8d);
  });

  it('copilot messages validate correctly', () => {
    assert.ok(isValidMessage(copilotAttach({ sessionId: 's1', model: 'm' })));
    assert.ok(isValidMessage(copilotSuggest({ sessionId: 's1', suggestion: 's' })));
    assert.ok(isValidMessage(copilotDetach({ sessionId: 's1' })));
  });
});

describe('E2E encrypted session mode', () => {
  it('keyExchange', () => {
    const pk = new Uint8Array(32);
    const msg = keyExchange({ algorithm: 'x25519', publicKey: pk, sessionId: 's1' });
    assert.equal(msg.type, MSG.KEY_EXCHANGE);
    assert.equal(msg.algorithm, 'x25519');
    assert.equal(msg.public_key, pk);
    assert.equal(msg.session_id, 's1');
  });

  it('encryptedFrame', () => {
    const nonce = new Uint8Array(12);
    const ciphertext = new Uint8Array([0xde, 0xad]);
    const msg = encryptedFrame({ nonce, ciphertext, sessionId: 's1' });
    assert.equal(msg.type, MSG.ENCRYPTED_FRAME);
    assert.equal(msg.nonce, nonce);
    assert.equal(msg.ciphertext, ciphertext);
    assert.equal(msg.session_id, 's1');
  });

  it('E2E codes', () => {
    assert.equal(MSG.KEY_EXCHANGE, 0x8e);
    assert.equal(MSG.ENCRYPTED_FRAME, 0x8f);
  });

  it('E2E messages validate correctly', () => {
    assert.ok(isValidMessage(keyExchange({ algorithm: 'x25519', publicKey: new Uint8Array(32), sessionId: 's1' })));
    assert.ok(isValidMessage(encryptedFrame({ nonce: new Uint8Array(12), ciphertext: new Uint8Array(0), sessionId: 's1' })));
  });
});

describe('predictive local echo (mosh-style)', () => {
  it('echoAck', () => {
    const msg = echoAck({ channelId: 1, echoSeq: 42 });
    assert.equal(msg.type, MSG.ECHO_ACK);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.echo_seq, 42);
  });

  it('echoState', () => {
    const msg = echoState({ channelId: 1, echoSeq: 42, cursorX: 10, cursorY: 5, pending: 3 });
    assert.equal(msg.type, MSG.ECHO_STATE);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.echo_seq, 42);
    assert.equal(msg.cursor_x, 10);
    assert.equal(msg.cursor_y, 5);
    assert.equal(msg.pending, 3);
  });

  it('echoState with defaults', () => {
    const msg = echoState({ channelId: 1, echoSeq: 0, cursorX: 0, cursorY: 0, pending: 0 });
    assert.equal(msg.pending, 0);
  });

  it('echo codes', () => {
    assert.equal(MSG.ECHO_ACK, 0x90);
    assert.equal(MSG.ECHO_STATE, 0x91);
  });

  it('echo messages validate correctly', () => {
    assert.ok(isValidMessage(echoAck({ channelId: 1, echoSeq: 0 })));
    assert.ok(isValidMessage(echoState({ channelId: 1, echoSeq: 0, cursorX: 0, cursorY: 0, pending: 0 })));
  });
});

describe('terminal diff-based sync', () => {
  it('termSync', () => {
    const hash = new Uint8Array(32);
    const msg = termSync({ channelId: 1, frameSeq: 100, stateHash: hash });
    assert.equal(msg.type, MSG.TERM_SYNC);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.frame_seq, 100);
    assert.equal(msg.state_hash, hash);
  });

  it('termDiff', () => {
    const patch = new Uint8Array([0x01, 0x02, 0x03]);
    const msg = termDiff({ channelId: 1, frameSeq: 100, baseSeq: 95, patch });
    assert.equal(msg.type, MSG.TERM_DIFF);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.frame_seq, 100);
    assert.equal(msg.base_seq, 95);
    assert.equal(msg.patch, patch);
  });

  it('term sync codes', () => {
    assert.equal(MSG.TERM_SYNC, 0x92);
    assert.equal(MSG.TERM_DIFF, 0x93);
  });

  it('term sync messages validate correctly', () => {
    assert.ok(isValidMessage(termSync({ channelId: 1, frameSeq: 0, stateHash: new Uint8Array(0) })));
    assert.ok(isValidMessage(termDiff({ channelId: 1, frameSeq: 0, baseSeq: 0, patch: new Uint8Array(0) })));
  });
});

describe('horizontal scaling', () => {
  it('nodeAnnounce', () => {
    const msg = nodeAnnounce({ nodeId: 'node-1', endpoint: 'wss://n1.example.com', load: 0.42, capacity: 100 });
    assert.equal(msg.type, MSG.NODE_ANNOUNCE);
    assert.equal(msg.node_id, 'node-1');
    assert.equal(msg.endpoint, 'wss://n1.example.com');
    assert.equal(msg.load, 0.42);
    assert.equal(msg.capacity, 100);
  });

  it('nodeRedirect', () => {
    const msg = nodeRedirect({ targetNode: 'node-2', targetEndpoint: 'wss://n2.example.com', sessionId: 's1', reason: 'rebalance' });
    assert.equal(msg.type, MSG.NODE_REDIRECT);
    assert.equal(msg.target_node, 'node-2');
    assert.equal(msg.target_endpoint, 'wss://n2.example.com');
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.reason, 'rebalance');
  });

  it('nodeRedirect with optional reason', () => {
    const msg = nodeRedirect({ targetNode: 'n', targetEndpoint: 'e', sessionId: 's' });
    assert.equal(msg.reason, undefined);
  });

  it('scaling codes', () => {
    assert.equal(MSG.NODE_ANNOUNCE, 0x94);
    assert.equal(MSG.NODE_REDIRECT, 0x95);
  });

  it('scaling messages validate correctly', () => {
    assert.ok(isValidMessage(nodeAnnounce({ nodeId: 'n', endpoint: 'e', load: 0, capacity: 1 })));
    assert.ok(isValidMessage(nodeRedirect({ targetNode: 'n', targetEndpoint: 'e', sessionId: 's' })));
  });
});

describe('shared sessions across principals', () => {
  it('sessionGrant', () => {
    const msg = sessionGrant({ sessionId: 's1', principal: 'alice', permissions: ['read', 'write'] });
    assert.equal(msg.type, MSG.SESSION_GRANT);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.principal, 'alice');
    assert.deepEqual(msg.permissions, ['read', 'write']);
  });

  it('sessionGrant default permissions', () => {
    const msg = sessionGrant({ sessionId: 's1', principal: 'bob' });
    assert.deepEqual(msg.permissions, ['read']);
  });

  it('sessionRevoke', () => {
    const msg = sessionRevoke({ sessionId: 's1', principal: 'alice', reason: 'access removed' });
    assert.equal(msg.type, MSG.SESSION_REVOKE);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.principal, 'alice');
    assert.equal(msg.reason, 'access removed');
  });

  it('sessionRevoke without reason', () => {
    const msg = sessionRevoke({ sessionId: 's1', principal: 'bob' });
    assert.equal(msg.reason, undefined);
  });

  it('session sharing codes', () => {
    assert.equal(MSG.SESSION_GRANT, 0x96);
    assert.equal(MSG.SESSION_REVOKE, 0x97);
  });

  it('session sharing messages validate correctly', () => {
    assert.ok(isValidMessage(sessionGrant({ sessionId: 's', principal: 'p' })));
    assert.ok(isValidMessage(sessionRevoke({ sessionId: 's', principal: 'p' })));
  });
});

describe('structured file channel (SFTP replacement)', () => {
  it('fileOp', () => {
    const msg = fileOp({ channelId: 1, op: 'stat', path: '/etc/hosts' });
    assert.equal(msg.type, MSG.FILE_OP);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.op, 'stat');
    assert.equal(msg.path, '/etc/hosts');
  });

  it('fileOp with optional fields', () => {
    const msg = fileOp({ channelId: 1, op: 'read', path: '/tmp/file', offset: 100, length: 512 });
    assert.equal(msg.offset, 100);
    assert.equal(msg.length, 512);
  });

  it('fileOp optional fields absent', () => {
    const msg = fileOp({ channelId: 1, op: 'list', path: '/' });
    assert.equal(msg.offset, undefined);
    assert.equal(msg.length, undefined);
  });

  it('fileResult', () => {
    const msg = fileResult({ channelId: 1, success: true, metadata: { size: 1024, mode: '0644' } });
    assert.equal(msg.type, MSG.FILE_RESULT);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.success, true);
    assert.deepEqual(msg.metadata, { size: 1024, mode: '0644' });
  });

  it('fileResult failure', () => {
    const msg = fileResult({ channelId: 1, success: false, errorMessage: 'not found' });
    assert.equal(msg.success, false);
    assert.equal(msg.error_message, 'not found');
  });

  it('fileChunk', () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    const msg = fileChunk({ channelId: 1, offset: 0, data, isFinal: true });
    assert.equal(msg.type, MSG.FILE_CHUNK);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.offset, 0);
    assert.equal(msg.data, data);
    assert.equal(msg.is_final, true);
  });

  it('file channel codes', () => {
    assert.equal(MSG.FILE_OP, 0x98);
    assert.equal(MSG.FILE_RESULT, 0x99);
    assert.equal(MSG.FILE_CHUNK, 0x9a);
  });

  it('file channel messages validate correctly', () => {
    assert.ok(isValidMessage(fileOp({ channelId: 1, op: 'stat', path: '/' })));
    assert.ok(isValidMessage(fileResult({ channelId: 1, success: true })));
    assert.ok(isValidMessage(fileChunk({ channelId: 1, offset: 0, data: new Uint8Array(0), isFinal: false })));
  });
});

describe('policy engine (OPA-like)', () => {
  it('policyEval', () => {
    const msg = policyEval({ requestId: 'r1', action: 'open_pty', principal: 'alice', context: { ip: '10.0.0.1' } });
    assert.equal(msg.type, MSG.POLICY_EVAL);
    assert.equal(msg.request_id, 'r1');
    assert.equal(msg.action, 'open_pty');
    assert.equal(msg.principal, 'alice');
    assert.deepEqual(msg.context, { ip: '10.0.0.1' });
  });

  it('policyEval default context', () => {
    const msg = policyEval({ requestId: 'r1', action: 'exec', principal: 'bob' });
    assert.deepEqual(msg.context, {});
  });

  it('policyResult', () => {
    const msg = policyResult({ requestId: 'r1', allowed: true, reason: 'policy matched' });
    assert.equal(msg.type, MSG.POLICY_RESULT);
    assert.equal(msg.request_id, 'r1');
    assert.equal(msg.allowed, true);
    assert.equal(msg.reason, 'policy matched');
  });

  it('policyResult denied without reason', () => {
    const msg = policyResult({ requestId: 'r1', allowed: false });
    assert.equal(msg.allowed, false);
    assert.equal(msg.reason, undefined);
  });

  it('policyUpdate', () => {
    const msg = policyUpdate({ policyId: 'p1', rules: { deny: ['exec'] }, version: 2 });
    assert.equal(msg.type, MSG.POLICY_UPDATE);
    assert.equal(msg.policy_id, 'p1');
    assert.deepEqual(msg.rules, { deny: ['exec'] });
    assert.equal(msg.version, 2);
  });

  it('policy engine codes', () => {
    assert.equal(MSG.POLICY_EVAL, 0x9b);
    assert.equal(MSG.POLICY_RESULT, 0x9c);
    assert.equal(MSG.POLICY_UPDATE, 0x9d);
  });

  it('policy messages validate correctly', () => {
    assert.ok(isValidMessage(policyEval({ requestId: 'r', action: 'a', principal: 'p' })));
    assert.ok(isValidMessage(policyResult({ requestId: 'r', allowed: true })));
    assert.ok(isValidMessage(policyUpdate({ policyId: 'p', rules: {}, version: 1 })));
  });
});

describe('ghostty-web terminal frontend integration', () => {
  it('terminalConfig', () => {
    const msg = terminalConfig({
      channelId: 1,
      frontend: 'ghostty-web',
      options: { fontFamily: 'JetBrains Mono', fontSize: 14, theme: 'dracula' },
    });
    assert.equal(msg.type, MSG.TERMINAL_CONFIG);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.frontend, 'ghostty-web');
    assert.deepEqual(msg.options, { fontFamily: 'JetBrains Mono', fontSize: 14, theme: 'dracula' });
  });

  it('terminalConfig default options', () => {
    const msg = terminalConfig({ channelId: 1, frontend: 'xterm.js' });
    assert.deepEqual(msg.options, {});
  });

  it('terminal config code', () => {
    assert.equal(MSG.TERMINAL_CONFIG, 0x9e);
  });

  it('terminal config validates correctly', () => {
    assert.ok(isValidMessage(terminalConfig({ channelId: 1, frontend: 'ghostty-web' })));
  });
});

// ── Tests for previously untested constructors ──────────────────────

describe('authMethods', () => {
  it('constructs with methods list', () => {
    const msg = authMethods({ methods: [AUTH_METHOD.PUBKEY, AUTH_METHOD.PASSWORD] });
    assert.equal(msg.type, MSG.AUTH_METHODS);
    assert.deepEqual(msg.methods, ['pubkey', 'password']);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(authMethods({ methods: ['pubkey'] })));
  });
});

describe('openFail', () => {
  it('constructs with reason', () => {
    const msg = openFail({ reason: 'permission denied' });
    assert.equal(msg.type, MSG.OPEN_FAIL);
    assert.equal(msg.reason, 'permission denied');
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(openFail({ reason: 'test' })));
  });
});

describe('error', () => {
  it('constructs with code and message', () => {
    const msg = error({ code: 42, message: 'something broke' });
    assert.equal(msg.type, MSG.ERROR);
    assert.equal(msg.code, 42);
    assert.equal(msg.message, 'something broke');
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(error({ code: 1, message: 'x' })));
  });
});

describe('resume', () => {
  it('constructs with session, token, and last_seq', () => {
    const token = new Uint8Array(40);
    const msg = resume({ sessionId: 's1', token, lastSeq: 100 });
    assert.equal(msg.type, MSG.RESUME);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.token, token);
    assert.equal(msg.last_seq, 100);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(resume({ sessionId: 's1', token: new Uint8Array(40), lastSeq: 0 })));
  });
});

describe('rename', () => {
  it('constructs with session and name', () => {
    const msg = rename({ sessionId: 's1', name: 'my-session' });
    assert.equal(msg.type, MSG.RENAME);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.name, 'my-session');
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(rename({ sessionId: 's1', name: 'test' })));
  });
});

describe('idleWarning', () => {
  it('constructs with expires_in', () => {
    const msg = idleWarning({ expiresIn: 300 });
    assert.equal(msg.type, MSG.IDLE_WARNING);
    assert.equal(msg.expires_in, 300);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(idleWarning({ expiresIn: 60 })));
  });
});

describe('shutdown', () => {
  it('constructs with reason', () => {
    const msg = shutdown({ reason: 'server maintenance' });
    assert.equal(msg.type, MSG.SHUTDOWN);
    assert.equal(msg.reason, 'server maintenance');
    assert.equal(msg.retry_after, undefined);
  });

  it('constructs with retry_after', () => {
    const msg = shutdown({ reason: 'restart', retryAfter: 30 });
    assert.equal(msg.retry_after, 30);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(shutdown({ reason: 'test' })));
  });
});

describe('snapshot', () => {
  it('constructs with label', () => {
    const msg = snapshot({ label: 'before-deploy' });
    assert.equal(msg.type, MSG.SNAPSHOT);
    assert.equal(msg.label, 'before-deploy');
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(snapshot({ label: 'test' })));
  });
});

describe('presence', () => {
  it('constructs with attachments', () => {
    const msg = presence({ attachments: [{ sessionId: 's1', mode: 'control', username: 'alice' }] });
    assert.equal(msg.type, MSG.PRESENCE);
    assert.equal(msg.attachments.length, 1);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(presence({ attachments: [] })));
  });
});

describe('controlChanged', () => {
  it('constructs with new controller', () => {
    const msg = controlChanged({ newController: 'alice' });
    assert.equal(msg.type, MSG.CONTROL_CHANGED);
    assert.equal(msg.new_controller, 'alice');
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(controlChanged({ newController: 'x' })));
  });
});

describe('clipboard', () => {
  it('constructs with direction and data', () => {
    const msg = clipboard({ direction: 'server_to_client', data: 'aGVsbG8=' });
    assert.equal(msg.type, MSG.CLIPBOARD);
    assert.equal(msg.direction, 'server_to_client');
    assert.equal(msg.data, 'aGVsbG8=');
  });

  it('clipboard code', () => {
    assert.equal(MSG.CLIPBOARD, 0x39);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(clipboard({ direction: 'server_to_client', data: 'x' })));
  });
});

describe('recordingExport', () => {
  it('constructs with session and format', () => {
    const msg = recordingExport({ sessionId: 's1', format: 'asciicast' });
    assert.equal(msg.type, MSG.RECORDING_EXPORT);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.format, 'asciicast');
    assert.equal(msg.data, undefined);
  });

  it('constructs with default format', () => {
    const msg = recordingExport({ sessionId: 's1' });
    assert.equal(msg.format, 'jsonl');
  });

  it('constructs with data', () => {
    const msg = recordingExport({ sessionId: 's1', data: '{"type":"output"}' });
    assert.equal(msg.data, '{"type":"output"}');
  });

  it('recording export code', () => {
    assert.equal(MSG.RECORDING_EXPORT, 0x3a);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(recordingExport({ sessionId: 's1' })));
  });
});

describe('commandJournal', () => {
  it('constructs with all fields', () => {
    const msg = commandJournal({
      sessionId: 's1', command: 'ls -la', exitCode: 0,
      durationMs: 150, cwd: '/home/user', timestamp: 1234567890,
    });
    assert.equal(msg.type, MSG.COMMAND_JOURNAL);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.command, 'ls -la');
    assert.equal(msg.exit_code, 0);
    assert.equal(msg.duration_ms, 150);
    assert.equal(msg.cwd, '/home/user');
    assert.equal(msg.timestamp, 1234567890);
  });

  it('constructs with optional fields absent', () => {
    const msg = commandJournal({ sessionId: 's1', command: 'pwd', timestamp: 1 });
    assert.equal(msg.exit_code, undefined);
    assert.equal(msg.duration_ms, undefined);
    assert.equal(msg.cwd, undefined);
  });

  it('command journal code', () => {
    assert.equal(MSG.COMMAND_JOURNAL, 0x3b);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(commandJournal({ sessionId: 's1', command: 'x', timestamp: 1 })));
  });
});

describe('metricsRequest', () => {
  it('constructs with no fields', () => {
    const msg = metricsRequest();
    assert.equal(msg.type, MSG.METRICS_REQUEST);
  });

  it('metrics request code', () => {
    assert.equal(MSG.METRICS_REQUEST, 0x3c);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(metricsRequest()));
  });
});

describe('suspendSession', () => {
  it('constructs with session and action', () => {
    const msg = suspendSession({ sessionId: 's1', action: 'suspend' });
    assert.equal(msg.type, MSG.SUSPEND_SESSION);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.action, 'suspend');
  });

  it('suspend session code', () => {
    assert.equal(MSG.SUSPEND_SESSION, 0x3d);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(suspendSession({ sessionId: 's1', action: 'resume' })));
  });
});

describe('restartPty', () => {
  it('constructs with session', () => {
    const msg = restartPty({ sessionId: 's1' });
    assert.equal(msg.type, MSG.RESTART_PTY);
    assert.equal(msg.session_id, 's1');
    assert.equal(msg.command, undefined);
  });

  it('constructs with command', () => {
    const msg = restartPty({ sessionId: 's1', command: '/bin/zsh' });
    assert.equal(msg.command, '/bin/zsh');
  });

  it('restart PTY code', () => {
    assert.equal(MSG.RESTART_PTY, 0x3e);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(restartPty({ sessionId: 's1' })));
  });
});

describe('mcpCall', () => {
  it('constructs with tool and arguments', () => {
    const msg = mcpCall({ tool: 'git.status', arguments: { path: '.' } });
    assert.equal(msg.type, MSG.MCP_CALL);
    assert.equal(msg.tool, 'git.status');
    assert.deepEqual(msg.arguments, { path: '.' });
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(mcpCall({ tool: 'test', arguments: {} })));
  });
});

describe('mcpResult', () => {
  it('constructs with result', () => {
    const msg = mcpResult({ result: { output: 'clean' } });
    assert.equal(msg.type, MSG.MCP_RESULT);
    assert.deepEqual(msg.result, { output: 'clean' });
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(mcpResult({ result: {} })));
  });
});

describe('reverseList', () => {
  it('constructs with no fields', () => {
    const msg = reverseList();
    assert.equal(msg.type, MSG.REVERSE_LIST);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(reverseList()));
  });
});

describe('reversePeers', () => {
  it('constructs with peers', () => {
    const msg = reversePeers({
      peers: [{
        fingerprintShort: 'a1b2c3d4',
        username: 'alice',
        capabilities: ['shell'],
        lastSeen: 60,
      }],
    });
    assert.equal(msg.type, MSG.REVERSE_PEERS);
    assert.equal(msg.peers.length, 1);
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(reversePeers({ peers: [] })));
  });
});

describe('reverseConnect', () => {
  it('constructs with target and username', () => {
    const msg = reverseConnect({ targetFingerprint: 'a1b2c3d4e5f6', username: 'bob' });
    assert.equal(msg.type, MSG.REVERSE_CONNECT);
    assert.equal(msg.target_fingerprint, 'a1b2c3d4e5f6');
    assert.equal(msg.username, 'bob');
  });

  it('validates correctly', () => {
    assert.ok(isValidMessage(reverseConnect({ targetFingerprint: 'x', username: 'y' })));
  });
});

describe('gateway MSG constants', () => {
  it('gateway codes are in 0x70-0x7e range', () => {
    assert.equal(MSG.OPEN_TCP, 0x70);
    assert.equal(MSG.OPEN_UDP, 0x71);
    assert.equal(MSG.RESOLVE_DNS, 0x72);
    assert.equal(MSG.GATEWAY_OK, 0x73);
    assert.equal(MSG.GATEWAY_FAIL, 0x74);
    assert.equal(MSG.GATEWAY_CLOSE, 0x75);
    assert.equal(MSG.INBOUND_OPEN, 0x76);
    assert.equal(MSG.INBOUND_ACCEPT, 0x77);
    assert.equal(MSG.INBOUND_REJECT, 0x78);
    assert.equal(MSG.DNS_RESULT, 0x79);
    assert.equal(MSG.LISTEN_REQUEST, 0x7a);
    assert.equal(MSG.LISTEN_OK, 0x7b);
    assert.equal(MSG.LISTEN_FAIL, 0x7c);
    assert.equal(MSG.LISTEN_CLOSE, 0x7d);
    assert.equal(MSG.GATEWAY_DATA, 0x7e);
  });

  it('gateway messages validate correctly', () => {
    assert.ok(isValidMessage(openTcp({ gatewayId: 1, host: 'x', port: 80 })));
    assert.ok(isValidMessage(gatewayOk({ gatewayId: 1 })));
    assert.ok(isValidMessage(listenClose({ listenerId: 1 })));
    assert.ok(isValidMessage(gatewayData({ gatewayId: 1, data: new Uint8Array(0) })));
  });
});

// ── Explicit opcode assertions for handshake/channel/transport/session/MCP/reverse ──

describe('MSG opcode values — handshake', () => {
  it('has correct hex values', () => {
    assert.equal(MSG.HELLO, 0x01);
    assert.equal(MSG.SERVER_HELLO, 0x02);
    assert.equal(MSG.CHALLENGE, 0x03);
    assert.equal(MSG.AUTH_METHODS, 0x04);
    assert.equal(MSG.AUTH, 0x05);
    assert.equal(MSG.AUTH_OK, 0x06);
    assert.equal(MSG.AUTH_FAIL, 0x07);
  });
});

describe('MSG opcode values — channel', () => {
  it('has correct hex values', () => {
    assert.equal(MSG.OPEN, 0x10);
    assert.equal(MSG.OPEN_OK, 0x11);
    assert.equal(MSG.OPEN_FAIL, 0x12);
    assert.equal(MSG.RESIZE, 0x13);
    assert.equal(MSG.SIGNAL, 0x14);
    assert.equal(MSG.EXIT, 0x15);
    assert.equal(MSG.CLOSE, 0x16);
  });
});

describe('MSG opcode values — transport', () => {
  it('has correct hex values', () => {
    assert.equal(MSG.ERROR, 0x20);
    assert.equal(MSG.PING, 0x21);
    assert.equal(MSG.PONG, 0x22);
  });
});

describe('MSG opcode values — session', () => {
  it('has correct hex values', () => {
    assert.equal(MSG.ATTACH, 0x30);
    assert.equal(MSG.RESUME, 0x31);
    assert.equal(MSG.RENAME, 0x32);
    assert.equal(MSG.IDLE_WARNING, 0x33);
    assert.equal(MSG.SHUTDOWN, 0x34);
    assert.equal(MSG.SNAPSHOT, 0x35);
    assert.equal(MSG.PRESENCE, 0x36);
    assert.equal(MSG.CONTROL_CHANGED, 0x37);
    assert.equal(MSG.METRICS, 0x38);
  });
});

describe('MSG opcode values — MCP', () => {
  it('has correct hex values', () => {
    assert.equal(MSG.MCP_DISCOVER, 0x40);
    assert.equal(MSG.MCP_TOOLS, 0x41);
    assert.equal(MSG.MCP_CALL, 0x42);
    assert.equal(MSG.MCP_RESULT, 0x43);
  });
});

describe('MSG opcode values — reverse', () => {
  it('has correct hex values', () => {
    assert.equal(MSG.REVERSE_REGISTER, 0x50);
    assert.equal(MSG.REVERSE_LIST, 0x51);
    assert.equal(MSG.REVERSE_PEERS, 0x52);
    assert.equal(MSG.REVERSE_CONNECT, 0x53);
  });
});

describe('MSG opcode values — framing', () => {
  it('WS_DATA has correct hex value', () => {
    assert.equal(MSG.WS_DATA, 0x60);
  });
});

// ── Untested defaults ───────────────────────────────────────────────

describe('constructor defaults', () => {
  it('hello.features defaults to []', () => {
    const msg = hello({ username: 'test' });
    assert.deepEqual(msg.features, []);
  });

  it('serverHello.features defaults to []', () => {
    const msg = serverHello({ sessionId: 'abc' });
    assert.deepEqual(msg.features, []);
  });

  it('serverHello.fingerprints defaults to []', () => {
    const msg = serverHello({ sessionId: 'abc' });
    assert.deepEqual(msg.fingerprints, []);
  });

  it('authMethods.methods defaults to [AUTH_METHOD.PUBKEY]', () => {
    const msg = authMethods();
    assert.deepEqual(msg.methods, [AUTH_METHOD.PUBKEY]);
  });

  it('openOk.streamIds defaults to []', () => {
    const msg = openOk({ channelId: 1 });
    assert.deepEqual(msg.stream_ids, []);
  });

  it('attach.mode defaults to "control"', () => {
    const msg = attach({ sessionId: 'sess1', token: 'tok1' });
    assert.equal(msg.mode, 'control');
  });

  it('reverseRegister.capabilities defaults to []', () => {
    const msg = reverseRegister({ publicKey: new Uint8Array(32), username: 'u' });
    assert.deepEqual(msg.capabilities, []);
  });

  it('fileResult.metadata defaults to {}', () => {
    const msg = fileResult({ channelId: 1, success: true });
    assert.deepEqual(msg.metadata, {});
  });
});

// ── Untested optional fields ────────────────────────────────────────

describe('optional field coverage', () => {
  it('open.env present', () => {
    const msg = open({ kind: 'pty', cols: 80, rows: 24, env: { TERM: 'xterm' } });
    assert.deepEqual(msg.env, { TERM: 'xterm' });
  });

  it('open.env absent', () => {
    const msg = open({ kind: 'pty', cols: 80, rows: 24 });
    assert.equal(msg.env, undefined);
  });

  it('open.cols absent', () => {
    const msg = open({ kind: 'pty' });
    assert.equal(msg.cols, undefined);
  });

  it('open.rows absent', () => {
    const msg = open({ kind: 'pty' });
    assert.equal(msg.rows, undefined);
  });

  it('metrics.memory present', () => {
    const msg = metrics({ memory: 1024 });
    assert.equal(msg.memory, 1024);
  });

  it('metrics.memory absent', () => {
    const msg = metrics({});
    assert.equal(msg.memory, undefined);
  });

  it('metrics.sessions present', () => {
    const msg = metrics({ sessions: 5 });
    assert.equal(msg.sessions, 5);
  });

  it('metrics.sessions absent', () => {
    const msg = metrics({});
    assert.equal(msg.sessions, undefined);
  });

  it('metrics.rtt present', () => {
    const msg = metrics({ rtt: 42.5 });
    assert.equal(msg.rtt, 42.5);
  });

  it('metrics.rtt absent', () => {
    const msg = metrics({});
    assert.equal(msg.rtt, undefined);
  });

  it('metrics all fields omitted', () => {
    const msg = metrics();
    assert.equal(msg.type, MSG.METRICS);
    assert.equal(msg.cpu, undefined);
    assert.equal(msg.memory, undefined);
    assert.equal(msg.sessions, undefined);
    assert.equal(msg.rtt, undefined);
  });

  it('attach.device_label present', () => {
    const msg = attach({ sessionId: 's1', token: 't1', mode: 'read', deviceLabel: 'Chrome/Mac' });
    assert.equal(msg.device_label, 'Chrome/Mac');
  });

  it('attach.device_label absent', () => {
    const msg = attach({ sessionId: 's1', token: 't1' });
    assert.equal(msg.device_label, undefined);
  });

  it('fileResult.error_message absent', () => {
    const msg = fileResult({ channelId: 1, success: true });
    assert.equal(msg.error_message, undefined);
  });
});
