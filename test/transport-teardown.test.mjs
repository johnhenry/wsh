import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { WshTransport } from '../src/transport.mjs';
import { WebSocketTransport } from '../src/transport-ws.mjs';

// Two failure modes on the teardown path, both of which leave a live
// connection behind. Neither is reachable through a mock server: what
// goes wrong is between the transport and the socket underneath it.

describe('WshTransport cleans up after a failed connect', () => {
  /** Fails partway through _doConnect, after "acquiring" a resource. */
  class HalfOpenTransport extends WshTransport {
    acquired = false;
    released = false;

    async _doConnect() {
      this.acquired = true;      // e.g. the WebSocket is now open
      throw new Error('handshake failed after the socket opened');
    }

    async _doClose() {
      this.released = true;
    }

    async _doSendControl() {}
    async _doOpenStream() { throw new Error('unused'); }
  }

  it('_doClose() runs when _doConnect() throws, so a half-open resource is released', async () => {
    const t = new HalfOpenTransport();
    await assert.rejects(() => t.connect('wss://example.test/wsh'));

    assert.equal(t.acquired, true);
    assert.equal(t.released, true, 'the half-open transport must be torn down');
    assert.equal(t.state, 'closed');
  });

  it('a later close() is still a safe no-op and does not tear down twice', async () => {
    const t = new HalfOpenTransport();
    await assert.rejects(() => t.connect('wss://example.test/wsh'));
    t.released = false;

    await t.close();
    assert.equal(t.released, false, 'close() after a failed connect must not re-enter _doClose()');
  });

  it('does not emit onClose for a connection that never opened', async () => {
    const t = new HalfOpenTransport();
    let closeEvents = 0;
    t.onClose = () => { closeEvents++; };

    await assert.rejects(() => t.connect('wss://example.test/wsh'));
    assert.equal(closeEvents, 0);
  });

  it('a _doClose() that throws does not mask the connect error', async () => {
    class Nasty extends HalfOpenTransport {
      async _doClose() { throw new Error('teardown also exploded'); }
    }
    const t = new Nasty();
    await assert.rejects(
      () => t.connect('wss://example.test/wsh'),
      /handshake failed after the socket opened/
    );
  });
});

describe('WebSocketTransport teardown survives a broken socket', () => {
  /**
   * A socket that opens and then throws on every send. That is not an
   * exotic case: a socket you cannot write to is the single most likely
   * reason you are closing in the first place, and the graceful QMux
   * CONNECTION_CLOSE that `_doClose()` sends is a write.
   */
  class UnwritableWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    static instances = [];

    readyState = UnwritableWebSocket.CONNECTING;
    binaryType = '';
    closeCalls = [];
    #listeners = new Map();

    constructor(url) {
      this.url = url;
      UnwritableWebSocket.instances.push(this);
      setTimeout(() => {
        this.readyState = UnwritableWebSocket.OPEN;
        for (const h of this.#listeners.get('open') || []) h();
      }, 0);
    }

    addEventListener(type, handler) {
      if (!this.#listeners.has(type)) this.#listeners.set(type, []);
      this.#listeners.get(type).push(handler);
    }

    send() {
      throw new Error('socket is broken');
    }

    close(code, reason) {
      this.closeCalls.push([code, reason]);
      this.readyState = UnwritableWebSocket.CLOSED;
    }
  }

  let savedWebSocket;

  beforeEach(() => {
    savedWebSocket = globalThis.WebSocket;
    globalThis.WebSocket = UnwritableWebSocket;
    UnwritableWebSocket.instances = [];
  });

  afterEach(() => {
    if (savedWebSocket === undefined) delete globalThis.WebSocket;
    else globalThis.WebSocket = savedWebSocket;
  });

  it('closes the underlying socket even though the graceful CONNECTION_CLOSE write throws', async () => {
    const t = new WebSocketTransport();
    await assert.rejects(() => t.connect('wss://example.test/wsh'));

    const socket = UnwritableWebSocket.instances[0];
    assert.deepEqual(
      socket.closeCalls,
      [[1000, 'client close']],
      'the socket must be closed, not leaked, when the courtesy close frame fails to send'
    );
    assert.equal(socket.readyState, UnwritableWebSocket.CLOSED);
  });

  it('close() on a connected-then-broken transport still closes the socket', async () => {
    // Reach `connected` with a socket that only breaks afterwards.
    let broken = false;
    class BreaksLater extends UnwritableWebSocket {
      send(data) {
        if (broken) throw new Error('socket is broken');
        // Swallow: the peer is not modelled here, only the socket.
        void data;
      }
    }
    globalThis.WebSocket = BreaksLater;

    const t = new WebSocketTransport();
    await t.connect('wss://example.test/wsh');
    assert.equal(t.state, 'connected');

    broken = true;
    await t.close();

    const socket = UnwritableWebSocket.instances[0];
    assert.deepEqual(socket.closeCalls, [[1000, 'client close']]);
  });
});
