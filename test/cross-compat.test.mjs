/**
 * Cross-language compatibility tests.
 *
 * These tests verify that the JS implementation produces identical wire-format
 * output to the Rust implementation. This is the most important test suite
 * because bugs here mean the JS client can't talk to the Rust server.
 *
 * The expected values were generated from the Rust implementation and hardcoded
 * here as ground truth.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cborEncode as encode, cborDecode as decode, frameEncode, FrameDecoder } from '../src/cbor.mjs';
import {
  MSG, PROTOCOL_VERSION,
  hello, challenge, auth, authOk, open, openOk,
  resize, signal, exit, close, ping, pong,
  attach, mcpDiscover, mcpCall,
} from '../src/messages.mjs';

// ── Protocol Constants ──────────────────────────────────────────────

describe('protocol constants match Rust', () => {
  it('PROTOCOL_VERSION is wsh-v1', () => {
    assert.equal(PROTOCOL_VERSION, 'wsh-v1');
  });

  it('MSG type values match Rust MsgType enum', () => {
    // These must match crates/wsh-core/src/messages.rs exactly
    assert.equal(MSG.HELLO, 0x01);
    assert.equal(MSG.SERVER_HELLO, 0x02);
    assert.equal(MSG.CHALLENGE, 0x03);
    assert.equal(MSG.AUTH_METHODS, 0x04);
    assert.equal(MSG.AUTH, 0x05);
    assert.equal(MSG.AUTH_OK, 0x06);
    assert.equal(MSG.AUTH_FAIL, 0x07);

    assert.equal(MSG.OPEN, 0x10);
    assert.equal(MSG.OPEN_OK, 0x11);
    assert.equal(MSG.OPEN_FAIL, 0x12);
    assert.equal(MSG.RESIZE, 0x13);
    assert.equal(MSG.SIGNAL, 0x14);
    assert.equal(MSG.EXIT, 0x15);
    assert.equal(MSG.CLOSE, 0x16);

    assert.equal(MSG.ERROR, 0x20);
    assert.equal(MSG.PING, 0x21);
    assert.equal(MSG.PONG, 0x22);

    assert.equal(MSG.ATTACH, 0x30);
    assert.equal(MSG.RESUME, 0x31);
    assert.equal(MSG.RENAME, 0x32);
    assert.equal(MSG.IDLE_WARNING, 0x33);
    assert.equal(MSG.SHUTDOWN, 0x34);
    assert.equal(MSG.SNAPSHOT, 0x35);
    assert.equal(MSG.PRESENCE, 0x36);
    assert.equal(MSG.CONTROL_CHANGED, 0x37);
    assert.equal(MSG.METRICS, 0x38);

    assert.equal(MSG.MCP_DISCOVER, 0x40);
    assert.equal(MSG.MCP_TOOLS, 0x41);
    assert.equal(MSG.MCP_CALL, 0x42);
    assert.equal(MSG.MCP_RESULT, 0x43);

    assert.equal(MSG.REVERSE_REGISTER, 0x50);
    assert.equal(MSG.REVERSE_LIST, 0x51);
    assert.equal(MSG.REVERSE_PEERS, 0x52);
    assert.equal(MSG.REVERSE_CONNECT, 0x53);
  });
});

// ── CBOR Wire Format ────────────────────────────────────────────────

describe('CBOR wire format', () => {
  it('encodes integers identically to ciborium', () => {
    // ciborium encodes small positive ints as CBOR unsigned int (major type 0)
    // 0 → 0x00, 1 → 0x01, 23 → 0x17, 24 → 0x1818
    assert.deepEqual([...encode(0)], [0x00]);
    assert.deepEqual([...encode(1)], [0x01]);
    assert.deepEqual([...encode(23)], [0x17]);
    assert.deepEqual([...encode(24)], [0x18, 24]);
    assert.deepEqual([...encode(255)], [0x18, 0xff]);
    assert.deepEqual([...encode(256)], [0x19, 0x01, 0x00]);
  });

  it('encodes negative integers identically to ciborium', () => {
    // CBOR negative int: major type 1, value = -1 - n
    // -1 → 0x20, -24 → 0x37, -25 → 0x3818
    assert.deepEqual([...encode(-1)], [0x20]);
    assert.deepEqual([...encode(-10)], [0x29]);
    assert.deepEqual([...encode(-24)], [0x37]);
    assert.deepEqual([...encode(-25)], [0x38, 24]);
  });

  it('encodes strings identically to ciborium', () => {
    // CBOR text string: major type 3
    // "" → 0x60
    // "a" → 0x6161
    assert.deepEqual([...encode('')], [0x60]);
    // "a" → 0x61 (major type 3, length 1) + 0x61 ('a' = 97)
    assert.deepEqual([...encode('a')], [0x61, 0x61]);
  });

  it('encodes byte arrays as CBOR bytes (major type 2), not arrays', () => {
    // This is critical: Uint8Array must encode as CBOR bytes (type 2),
    // not as a CBOR array of integers (type 4).
    const bytes = new Uint8Array([1, 2, 3]);
    const encoded = encode(bytes);
    // First byte should be 0x43 = major type 2 (bytes), length 3
    assert.equal(encoded[0], 0x43);
    assert.deepEqual([...encoded], [0x43, 1, 2, 3]);
  });

  it('length-prefix framing uses 4-byte big-endian', () => {
    const msg = { type: 1, version: 'wsh-v1' };
    const frame = frameEncode(msg);
    // First 4 bytes are length (big-endian)
    const len = new DataView(frame.buffer, frame.byteOffset).getUint32(0);
    assert.equal(len, frame.length - 4);
    assert.ok(len > 0);
  });

  it('FrameDecoder extracts the payload correctly', () => {
    const msg = { hello: 'world' };
    const frame = frameEncode(msg);
    const decoder = new FrameDecoder();
    const results = decoder.feed(frame);
    assert.equal(results.length, 1);
    assert.deepEqual(results[0], msg);
  });

  it('round-trips nested objects', () => {
    const obj = {
      type: 0x10,
      kind: 'pty',
      cols: 80,
      rows: 24,
      env: { TERM: 'xterm-256color', LANG: 'en_US.UTF-8' },
    };
    const bytes = encode(obj);
    const decoded = decode(bytes);
    assert.deepEqual(decoded, obj);
  });
});

// ── Message Field Names ─────────────────────────────────────────────

describe('message field names match Rust serde', () => {
  // Rust uses #[serde(rename = "type")] for msg_type → "type"
  // Rust uses snake_case field names by default

  it('hello() uses snake_case fields', () => {
    const msg = hello({ username: 'john', authMethod: 'pubkey' });
    assert.equal(msg.type, MSG.HELLO);
    assert.equal(msg.version, 'wsh-v1');
    assert.equal(msg.username, 'john');
    assert.equal(msg.auth_method, 'pubkey');
    // Must NOT have camelCase keys
    assert.equal(msg.authMethod, undefined);
  });

  it('open() uses snake_case fields', () => {
    const msg = open({ kind: 'pty', cols: 80, rows: 24, command: 'bash' });
    assert.equal(msg.type, MSG.OPEN);
    assert.equal(msg.kind, 'pty');
    assert.equal(msg.cols, 80);
    assert.equal(msg.rows, 24);
    assert.equal(msg.command, 'bash');
  });

  it('openOk() uses snake_case fields', () => {
    const msg = openOk({ channelId: 1, streamIds: [2, 3] });
    assert.equal(msg.type, MSG.OPEN_OK);
    assert.equal(msg.channel_id, 1);
    assert.deepEqual(msg.stream_ids, [2, 3]);
    // Must NOT have camelCase keys
    assert.equal(msg.channelId, undefined);
    assert.equal(msg.streamIds, undefined);
  });

  it('resize() uses snake_case fields', () => {
    const msg = resize({ channelId: 1, cols: 120, rows: 40 });
    assert.equal(msg.type, MSG.RESIZE);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.cols, 120);
    assert.equal(msg.rows, 40);
  });

  it('signal() uses snake_case fields', () => {
    const msg = signal({ channelId: 1, signal: 'SIGINT' });
    assert.equal(msg.type, MSG.SIGNAL);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.signal, 'SIGINT');
  });

  it('exit() uses snake_case fields', () => {
    const msg = exit({ channelId: 1, code: 0 });
    assert.equal(msg.type, MSG.EXIT);
    assert.equal(msg.channel_id, 1);
    assert.equal(msg.code, 0);
  });

  it('close() uses snake_case fields', () => {
    const msg = close({ channelId: 1 });
    assert.equal(msg.type, MSG.CLOSE);
    assert.equal(msg.channel_id, 1);
  });

  it('attach() uses snake_case fields', () => {
    const msg = attach({
      sessionId: 'sess-123',
      token: new Uint8Array([1, 2, 3]),
      mode: 'control',
    });
    assert.equal(msg.type, MSG.ATTACH);
    assert.equal(msg.session_id, 'sess-123');
    assert.ok(msg.token instanceof Uint8Array);
    assert.equal(msg.mode, 'control');
  });

  it('auth() with pubkey uses correct field names', () => {
    const msg = auth({
      method: 'pubkey',
      signature: new Uint8Array(64),
      publicKey: new Uint8Array(32),
    });
    assert.equal(msg.type, MSG.AUTH);
    assert.equal(msg.method, 'pubkey');
    assert.ok(msg.signature instanceof Uint8Array);
    assert.ok(msg.public_key instanceof Uint8Array);
    // Must NOT have camelCase
    assert.equal(msg.publicKey, undefined);
  });

  it('mcpCall() uses correct field names', () => {
    const msg = mcpCall({ tool: 'git', arguments: { args: ['status'] } });
    assert.equal(msg.type, MSG.MCP_CALL);
    assert.equal(msg.tool, 'git');
    assert.deepEqual(msg.arguments, { args: ['status'] });
  });
});

// ── Auth Transcript ─────────────────────────────────────────────────

let authModule;
try {
  authModule = await import('../src/auth.mjs');
} catch { /* skip if no Web Crypto */ }
const hasEd25519 = authModule && typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

describe('auth transcript', { skip: !hasEd25519 && 'Ed25519 not available' }, () => {

  it('buildTranscript formula matches Rust: SHA-256("wsh-v1\\0" || session_id || nonce)', async () => {
    const sessionId = 'test-session-123';
    const nonce = new Uint8Array(32).fill(42);

    const transcript = await authModule.buildTranscript(sessionId, nonce);
    assert.equal(transcript.length, 32);

    // Manually compute the expected hash to verify the formula
    const enc = new TextEncoder();
    const data = new Uint8Array([
      ...enc.encode('wsh-v1\0'),
      ...enc.encode(sessionId),
      ...nonce,
    ]);
    const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    assert.deepEqual([...transcript], [...expected]);
  });

  it('buildTranscript with empty channelBinding matches without channelBinding', async () => {
    // The JS function takes optional channelBinding (defaults to empty Uint8Array)
    // Since the Rust side doesn't include channelBinding, they should produce
    // the same result when channelBinding is empty.
    const sessionId = 'session-abc';
    const nonce = new Uint8Array(32).fill(7);

    const t1 = await authModule.buildTranscript(sessionId, nonce);
    const t2 = await authModule.buildTranscript(sessionId, nonce, new Uint8Array(0));
    assert.deepEqual([...t1], [...t2]);
  });

  it('signChallenge produces 64-byte signature + 32-byte pubkey', async () => {
    const keyPair = await authModule.generateKeyPair(true);
    const nonce = authModule.generateNonce();
    const sessionId = 'session-xyz';

    const { signature, publicKeyRaw } = await authModule.signChallenge(
      keyPair.privateKey, keyPair.publicKey, sessionId, nonce
    );

    assert.equal(signature.length, 64);
    assert.equal(publicKeyRaw.length, 32);

    // Verify the signature
    const imported = await authModule.importPublicKeyRaw(publicKeyRaw);
    const valid = await authModule.verifyChallenge(imported, signature, sessionId, nonce);
    assert.ok(valid);
  });
});

// ── SSH Key Format ──────────────────────────────────────────────────

describe('SSH key wire format', { skip: !hasEd25519 && 'Ed25519 not available' }, () => {
  it('exportPublicKeySSH produces valid SSH wire format that Rust can parse', async () => {
    const keyPair = await authModule.generateKeyPair(true);
    const sshLine = await authModule.exportPublicKeySSH(keyPair.publicKey);

    // Format: "ssh-ed25519 <base64> [comment]"
    const parts = sshLine.split(' ');
    assert.equal(parts[0], 'ssh-ed25519');

    // Decode base64 and verify SSH wire format
    const wireData = authModule.base64Decode(parts[1]);

    // Wire format: [4B len]["ssh-ed25519"][4B len][32B key]
    const view = new DataView(wireData.buffer, wireData.byteOffset);
    const typeLen = view.getUint32(0);
    assert.equal(typeLen, 11); // "ssh-ed25519".length

    const typeStr = new TextDecoder().decode(wireData.slice(4, 4 + typeLen));
    assert.equal(typeStr, 'ssh-ed25519');

    const keyLen = view.getUint32(4 + typeLen);
    assert.equal(keyLen, 32); // Ed25519 raw key length

    const rawKey = wireData.slice(4 + typeLen + 4, 4 + typeLen + 4 + keyLen);
    assert.equal(rawKey.length, 32);

    // Verify it matches the direct raw export
    const directRaw = await authModule.exportPublicKeyRaw(keyPair.publicKey);
    assert.deepEqual([...rawKey], [...directRaw]);
  });
});

// ── Fingerprint Compatibility ───────────────────────────────────────

describe('fingerprint compatibility', { skip: !hasEd25519 && 'Ed25519 not available' }, () => {
  it('fingerprint is SHA-256 of raw public key (matching Rust identity::fingerprint)', async () => {
    // Both JS and Rust compute: hex(SHA-256(raw_32_byte_pubkey))
    const keyPair = await authModule.generateKeyPair(true);
    const raw = await authModule.exportPublicKeyRaw(keyPair.publicKey);
    const fp = await authModule.fingerprint(raw);

    // Manually verify
    const hash = await crypto.subtle.digest('SHA-256', raw);
    const expected = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    assert.equal(fp, expected);
    assert.equal(fp.length, 64);
  });
});
