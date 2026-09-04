import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { WshTransport } from '../src/transport.mjs';
import { MSG } from '../src/messages.gen.mjs';
import { cborEncode, cborDecode } from '../src/cbor.mjs';
import { WshClient } from '../src/client.mjs';
import { generateKeyPair } from '../src/auth.mjs';

// Every other test in this repo checks the client against a stand-in
// that answers whatever the client asked for. This one checks it against
// spec/wsh-v1.yaml, which is the only party in the room that cannot be
// talked around.
//
// The failure it exists to catch has already happened once. From
// CHANGELOG 0.14.0, on `resumeSession()`: `lastSeq` was "previously
// always sent as `undefined`, which the wire's `required: true` field
// never tolerated -- so `resumeSession()` could never have produced a
// valid `Resume` message before this fix either." 443 tests passed
// throughout, because the message went out looking structurally fine and
// the mock on the other end had no opinion about `required`.
//
// So: drive the public API, capture what actually goes on the wire, and
// hold it against the field requirements the spec declares.

const SPEC_PATH = fileURLToPath(new URL('../spec/wsh-v1.yaml', import.meta.url));

/**
 * Extract `{ code, required[] }` per message from the spec YAML.
 *
 * A hand-rolled reader rather than a YAML dependency: this package has
 * no runtime dependencies and the spec is a fixed-indentation subset.
 * `parseSpecSanity` below fails loudly if the extraction ever stops
 * matching the document, so a parser that quietly reads nothing cannot
 * turn this file into a suite of vacuous passes.
 */
function loadSpecRequirements(path) {
  const lines = readFileSync(path, 'utf8').split('\n');
  const byName = {};
  let inMessages = false;
  let msg = null;
  let inFields = false;
  let field = null;

  for (const raw of lines) {
    if (raw.trim() === '' || /^\s*#/.test(raw)) continue;
    const indent = raw.match(/^ */)[0].length;
    const text = raw.trim();

    if (indent === 0) {                       // top-level key
      inMessages = text === 'messages:';
      msg = field = null;
      inFields = false;
    } else if (!inMessages) {
      continue;
    } else if (indent === 2 && text.endsWith(':')) {   // category
      msg = field = null;
      inFields = false;
    } else if (indent === 4 && text.endsWith(':')) {   // message name
      msg = text.slice(0, -1);
      byName[msg] = { name: msg, code: null, required: [] };
      inFields = false;
      field = null;
    } else if (indent === 6) {                          // message attribute
      inFields = text === 'fields:';
      const code = text.match(/^code:\s*(\S+)/);
      if (code && msg) byName[msg].code = Number(code[1]);
      field = null;
    } else if (indent === 8 && inFields && text.endsWith(':')) {  // field name
      field = text.slice(0, -1);
    } else if (indent >= 10 && field && /^required:\s*true\b/.test(text)) {
      byName[msg].required.push(field);
    }
  }

  const byCode = new Map();
  for (const m of Object.values(byName)) {
    if (m.code !== null) byCode.set(m.code, m);
  }
  return { byName, byCode };
}

let spec;
before(() => { spec = loadSpecRequirements(SPEC_PATH); });

describe('the spec reader actually read the spec', () => {
  // Without these, a parser bug would make every assertion below pass by
  // finding nothing to check.
  it('finds the full set of message types the README advertises', () => {
    assert.equal(Object.keys(spec.byName).length, 95);
    assert.equal(spec.byCode.size, 95);
  });

  it('agrees with messages.gen.mjs about opcodes', () => {
    assert.equal(spec.byName.Hello.code, MSG.HELLO);
    assert.equal(spec.byName.Resume.code, MSG.RESUME);
    assert.equal(spec.byName.RateControl.code, MSG.RATE_CONTROL);
    assert.equal(spec.byName.PolicyUpdate.code, MSG.POLICY_UPDATE);
  });

  it('reads required-field sets, including the one that shipped broken', () => {
    assert.deepEqual(spec.byName.Resume.required, ['session_id', 'token', 'last_seq']);
    assert.deepEqual(spec.byName.Attach.required, ['session_id']);
    assert.deepEqual(spec.byName.Hello.required, ['version', 'username']);
    assert.deepEqual(spec.byName.PolicyUpdate.required, ['policy_id', 'rules', 'version']);
  });

  it('distinguishes required from optional and defaulted fields', () => {
    // Attach.token is optional (clawser #48) and Attach.mode is defaulted;
    // neither may show up as required.
    assert.ok(!spec.byName.Attach.required.includes('token'));
    assert.ok(!spec.byName.Attach.required.includes('mode'));
    assert.ok(!spec.byName.RateControl.required.includes('policy'));
  });
});

describe('an omitted required field does not vanish -- it becomes CBOR null', () => {
  it('encodes as a present key with a null value, not as an absent key', () => {
    const encoded = cborEncode({ type: MSG.RATE_CONTROL, session_id: 's', max_bytes_per_sec: undefined });
    const decoded = cborDecode(encoded);
    assert.ok('max_bytes_per_sec' in decoded, 'the key survives the round trip');
    assert.equal(decoded.max_bytes_per_sec, null);
  });
});

const hasEd25519 = typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

/** Records outbound control messages; answers only what the handshake needs. */
class RecordingTransport extends WshTransport {
  sent = [];

  async _doConnect() {}
  async _doClose() {}
  async _doOpenStream() { throw new Error('not needed'); }

  async _doSendControl(msg) {
    this.sent.push(msg);
    const reply = (m) => setTimeout(() => this._emitControl(m), 0);
    switch (msg.type) {
      case MSG.HELLO:
        reply({ type: MSG.CHALLENGE, nonce: new Uint8Array(32).fill(7), session_id: 'sid' });
        break;
      case MSG.AUTH:
        reply({ type: MSG.AUTH_OK, session_id: 'sid' });
        break;
      // Deliberately nothing else: these tests care about what the client
      // *sends*, and a reply this transport invents would only be an
      // opinion about what the client wanted to hear.
      default:
        break;
    }
  }
}

describe('outbound messages satisfy the spec', { skip: !hasEd25519 && 'Ed25519 not available' }, () => {
  /** @returns {Promise<{ client: WshClient, transport: RecordingTransport }>} */
  async function connected() {
    const keyPair = await generateKeyPair(true);
    const transport = new RecordingTransport();
    const client = new WshClient();
    await client.connectWithTransport(transport, 'wsh://example.test/wsh', {
      username: 'alice',
      keyPair,
    });
    return { client, transport };
  }

  /** Assert every captured message carries every field the spec requires. */
  function assertConformant(transport, label) {
    assert.ok(transport.sent.length > 0, `${label}: nothing was sent`);
    for (const msg of transport.sent) {
      const definition = spec.byCode.get(msg.type);
      assert.ok(definition, `${label}: opcode 0x${msg.type.toString(16)} is not in the spec`);
      const missing = definition.required.filter((f) => msg[f] === undefined || msg[f] === null);
      assert.deepEqual(
        missing,
        [],
        `${label}: ${definition.name} is missing required field(s) ${missing.join(', ')}`
      );
    }
  }

  it('the handshake itself is conformant', async () => {
    const { transport } = await connected();
    assertConformant(transport, 'handshake');
  });

  // Every method below is called with only the arguments its own JSDoc
  // marks as required. That is the shape the resumeSession() bug took:
  // the library, calling its own message constructor, left a required
  // wire field undefined.
  const minimalCalls = [
    ['attachSession', (c) => c.attachSession('sess-1')],
    ['resumeSession', (c) => c.resumeSession('sess-1', new Uint8Array(32))],
    ['detach', (c) => c.detach('sess-1')],
    ['listRemoteSessions', (c) => c.listRemoteSessions()],
    ['discoverTools', (c) => c.discoverTools()],
    ['callTool', (c) => c.callTool('some-tool')],
    ['requestMetrics', (c) => c.requestMetrics()],
    ['listPeers', (c) => c.listPeers()],
    ['joinAsGuest', (c) => c.joinAsGuest(new Uint8Array(16))],
    ['negotiateCompression', (c) => c.negotiateCompression('zstd')],
    ['evaluatePolicy', (c) => c.evaluatePolicy('exec', 'alice')],
    ['fileStat', (c) => c.fileStat('/tmp/x')],
    ['fileRead', (c) => c.fileRead('/tmp/x')],
    ['fileWrite', (c) => c.fileWrite('/tmp/x', new Uint8Array(4))],
    ['fileRename', (c) => c.fileRename('/a', '/b')],
    ['grantSessionAccess', (c) => c.grantSessionAccess('sess-1', 'bob')],
    ['revokeSessionAccess', (c) => c.revokeSessionAccess('sess-1', 'bob')],
    ['suspendSession', (c) => c.suspendSession('sess-1')],
    ['restartPty', (c) => c.restartPty('sess-1')],
    ['revokeGuest', (c) => c.revokeGuest(new Uint8Array(16))],
    ['revokeShare', (c) => c.revokeShare('share-1')],
    ['linkSession', (c) => c.linkSession('sess-1', 'host', 22)],
    ['unlinkSession', (c) => c.unlinkSession('link-1')],
    ['copilotSuggest', (c) => c.copilotSuggest('sess-1', 'try ls')],
    ['copilotDetach', (c) => c.copilotDetach('sess-1')],
    ['inviteGuest', (c) => c.inviteGuest('sess-1', 300)],
    ['shareSession', (c) => c.shareSession('sess-1', 'read', 300)],
    ['setRateControl', (c) => c.setRateControl('sess-1', 1_000_000)],
    ['copilotAttach', (c) => c.copilotAttach('sess-1', 'claude-sonnet')],
    ['updatePolicy', (c) => c.updatePolicy('policy-1', { allow: [] }, 2)],
  ];

  for (const [name, call] of minimalCalls) {
    it(`${name}() sends only spec-conformant messages`, async () => {
      const { client, transport } = await connected();
      transport.sent.length = 0;

      // Request/reply calls never resolve here on purpose -- this
      // transport answers nothing after the handshake. What was sent is
      // already captured by the time the waiter is registered.
      const pending = call(client);
      if (pending && typeof pending.then === 'function') {
        pending.catch(() => {});     // a timeout later is fine and expected
        await Promise.resolve();
      }
      await new Promise((r) => setTimeout(r, 0));

      assertConformant(transport, name);
      await client.disconnect().catch(() => {});
    });
  }
});

describe('a missing required argument is refused at the call site', { skip: !hasEd25519 && 'Ed25519 not available' }, () => {
  async function connected() {
    const keyPair = await generateKeyPair(true);
    const transport = new RecordingTransport();
    const client = new WshClient();
    await client.connectWithTransport(transport, 'wsh://example.test/wsh', {
      username: 'alice',
      keyPair,
    });
    return { client, transport };
  }

  const omissions = [
    ['inviteGuest', (c) => c.inviteGuest('sess-1'), /"ttl" is required/],
    ['shareSession', (c) => c.shareSession('sess-1'), /"ttl" is required/],
    ['setRateControl', (c) => c.setRateControl('sess-1'), /"maxBytesPerSec" is required/],
    ['copilotAttach', (c) => c.copilotAttach('sess-1'), /"model" is required/],
    ['updatePolicy', (c) => c.updatePolicy('policy-1'), /"rules" is required/],
  ];

  for (const [name, call, expected] of omissions) {
    it(`${name}() throws by argument name instead of sending CBOR null`, async () => {
      const { client, transport } = await connected();
      transport.sent.length = 0;

      await assert.rejects(() => call(client), expected);
      assert.deepEqual(transport.sent, [], 'nothing may go on the wire');
      await client.disconnect().catch(() => {});
    });
  }

  it('callTool() defaults its arguments to {} rather than refusing -- a no-argument tool is normal', async () => {
    const { client, transport } = await connected();
    transport.sent.length = 0;

    client.callTool('some-tool').catch(() => {});
    await new Promise((r) => setTimeout(r, 0));

    const call = transport.sent.find((m) => m.type === MSG.MCP_CALL);
    assert.ok(call, 'the call must still be sent');
    assert.deepEqual(call.arguments, {});
    await client.disconnect().catch(() => {});
  });
});
