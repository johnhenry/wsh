import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { WshTransport } from '../src/transport.mjs';
import { MSG } from '../src/messages.gen.mjs';
import { WshClient } from '../src/client.mjs';
import { generateKeyPair } from '../src/auth.mjs';

// `WshClient#buildTransportAttempts` decides which transport is tried,
// in what order, and against which URL. It is the behaviour a caller
// depends on most and, until this file, had no test of any kind -- both
// existing transport suites construct a transport directly and never
// exercise the choice between them.
//
// These tests drive the ladder through the public API, via the
// documented `transportFactories` injection point. The factories are not
// a mock server: they record which kind was asked for and which URL it
// was handed, and can be told to fail. Nothing here answers a protocol
// question, so nothing here can agree with the client about something
// they are both wrong about.

const hasEd25519 = typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';

/**
 * A transport that records its connect URL, optionally fails, and
 * otherwise completes the auth handshake so `connect()` resolves.
 */
class SpyTransport extends WshTransport {
  constructor(kind, log, { failWith } = {}) {
    super();
    this.kind = kind;
    this.log = log;
    this.failWith = failWith;
  }

  async _doConnect(url, options) {
    this.log.push({ kind: this.kind, url, options });
    if (this.failWith) throw new Error(this.failWith);
  }

  async _doClose() {
    this.log.push({ kind: this.kind, closed: true });
  }

  async _doSendControl(msg) {
    if (msg.type === MSG.HELLO) {
      setTimeout(() => this._emitControl({
        type: MSG.CHALLENGE,
        nonce: new Uint8Array(32).fill(3),
        session_id: `sid-${this.kind}`,
      }), 0);
    } else if (msg.type === MSG.AUTH) {
      setTimeout(() => this._emitControl({ type: MSG.AUTH_OK }), 0);
    }
  }

  async _doOpenStream() {
    throw new Error('not needed');
  }
}

/**
 * @param {{ wtFails?: string, wsFails?: string }} [opts]
 * @returns {{ client: WshClient, log: Array }}
 */
function makeClient({ wtFails, wsFails } = {}) {
  const log = [];
  const client = new WshClient({
    transportFactories: {
      wt: () => new SpyTransport('wt', log, { failWith: wtFails }),
      ws: () => new SpyTransport('ws', log, { failWith: wsFails }),
    },
  });
  return { client, log };
}

/** Which transport kinds were *connect-attempted*, in order. */
const attempted = (log) => log.filter((e) => !e.closed).map((e) => e.kind);

describe('WshClient transport ladder', { skip: !hasEd25519 && 'Ed25519 not available' }, () => {
  let keyPair;

  const connect = async (client, url, extra = {}) => {
    keyPair ||= await generateKeyPair(true);
    return client.connect(url, { username: 'u', keyPair, ...extra });
  };

  it('a bare host URL tries WebTransport first, then falls back to WebSocket', async () => {
    const { client, log } = makeClient({ wtFails: 'no WebTransport here' });
    await connect(client, 'https://example.test:4433/wsh');

    assert.deepEqual(attempted(log), ['wt', 'ws']);
    // Both rungs get the *same* URL -- the WebSocket transport does its
    // own https:// -> wss:// rewrite internally, and the ladder must not
    // pre-empt it.
    assert.equal(log[0].url, 'https://example.test:4433/wsh');
    assert.equal(attempted(log).length, 2);
    assert.equal(log.find((e) => e.kind === 'ws' && !e.closed).url, 'https://example.test:4433/wsh');
  });

  it('stops at WebTransport when it succeeds -- WebSocket is never constructed', async () => {
    const { client, log } = makeClient();
    await connect(client, 'https://example.test:4433/wsh');

    assert.deepEqual(attempted(log), ['wt']);
  });

  it('a wss:// URL is WebSocket-only and never attempts WebTransport', async () => {
    const { client, log } = makeClient();
    await connect(client, 'wss://example.test:4433/wsh');

    assert.deepEqual(attempted(log), ['ws']);
  });

  it('a ws:// URL is WebSocket-only too', async () => {
    const { client, log } = makeClient();
    await connect(client, 'ws://example.test:4433/wsh');

    assert.deepEqual(attempted(log), ['ws']);
  });

  it('scheme matching is case-insensitive (WSS:// is still WebSocket-only)', async () => {
    const { client, log } = makeClient();
    await connect(client, 'WSS://example.test:4433/wsh');

    assert.deepEqual(attempted(log), ['ws']);
  });

  it("transport: 'wt' forces WebTransport and does NOT fall back", async () => {
    const { client, log } = makeClient({ wtFails: 'nope' });
    await assert.rejects(
      () => connect(client, 'https://example.test:4433/wsh', { transport: 'wt' }),
      /Connection failed across transports.*wt: nope/s
    );
    assert.deepEqual(attempted(log), ['wt']);
  });

  it("transport: 'ws' forces WebSocket even for an https:// URL that would otherwise try wt first", async () => {
    const { client, log } = makeClient();
    await connect(client, 'https://example.test:4433/wsh', { transport: 'ws' });

    assert.deepEqual(attempted(log), ['ws']);
  });

  it("transport: 'ws' overrides the wss:// rule's outcome identically (still ws-only)", async () => {
    const { client, log } = makeClient();
    await connect(client, 'wss://example.test:4433/wsh', { transport: 'ws' });

    assert.deepEqual(attempted(log), ['ws']);
  });

  it('when every rung fails, the error names each rung and its reason', async () => {
    const { client, log } = makeClient({ wtFails: 'h3 unreachable', wsFails: 'handshake refused' });
    await assert.rejects(
      () => connect(client, 'https://example.test:4433/wsh'),
      (err) => {
        assert.match(err.message, /wt: h3 unreachable/);
        assert.match(err.message, /ws: handshake refused/);
        return true;
      }
    );
    assert.deepEqual(attempted(log), ['wt', 'ws']);
  });

  it('a failed rung is closed before the next one is tried, so nothing is left dangling', async () => {
    const { client, log } = makeClient({ wtFails: 'nope' });
    await connect(client, 'https://example.test:4433/wsh');

    const wtClosed = log.findIndex((e) => e.kind === 'wt' && e.closed);
    const wsAttempt = log.findIndex((e) => e.kind === 'ws' && !e.closed);
    assert.ok(wtClosed !== -1, 'the failed wt transport must be closed');
    assert.ok(wtClosed < wsAttempt, 'it must be closed before ws is attempted');
  });

  it('webTransport options reach the wt rung and are withheld from the ws rung', async () => {
    const hashes = [{ algorithm: 'sha-256', value: new Uint8Array(32).fill(9) }];
    const { client, log } = makeClient({ wtFails: 'nope' });
    await connect(client, 'https://example.test:4433/wsh', {
      webTransport: { serverCertificateHashes: hashes },
    });

    const wt = log.find((e) => e.kind === 'wt' && !e.closed);
    const ws = log.find((e) => e.kind === 'ws' && !e.closed);
    assert.deepEqual(wt.options, { serverCertificateHashes: hashes });
    // A pinned certificate digest has no WebSocket equivalent; handing it
    // to the fallback rung would imply a guarantee that rung cannot make.
    assert.equal(ws.options, undefined);
  });

  it("transport: 'auto' is the explicit spelling of the default ladder", async () => {
    const { client, log } = makeClient({ wtFails: 'nope' });
    await connect(client, 'https://example.test:4433/wsh', { transport: 'auto' });

    assert.deepEqual(attempted(log), ['wt', 'ws']);
  });

  it('a typo in the transport hint is rejected rather than silently downgrading to the ladder', async () => {
    const { client, log } = makeClient();
    await assert.rejects(
      () => connect(client, 'https://example.test:4433/wsh', { transport: 'webtransport' }),
      /Unknown transport hint: "webtransport"/
    );
    // The point is not the message: silently treating it as 'auto' would
    // have connected over WebSocket, dropping any certificate pin the
    // caller passed alongside it.
    assert.deepEqual(attempted(log), []);
  });
});
