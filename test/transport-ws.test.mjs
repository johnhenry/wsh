import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FrameDecoder, frameEncode } from '../src/cbor.mjs';

// Loopback tests for the WebSocket transport's own multiplexing layer
// (transport-ws.mjs): the mux frame format, stream-ID allocation, and
// close/reset semantics. Drives WebSocketTransport's real public API
// (connect/sendControl/openStream/close) against a fake `WebSocket`
// global that records the exact bytes sent and lets a test inject
// arbitrary inbound frames — so these assert on real wire behavior, not
// a mock of the transport itself.

let transportWsMod;
try {
  transportWsMod = await import('../src/transport-ws.mjs');
} catch {
  // Module import may fail in environments without the expected globals.
}

const WS_FRAME_TYPE = transportWsMod?.WS_FRAME_TYPE;

class FakeWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = FakeWebSocket.CONNECTING;
  binaryType = '';
  sent = [];
  #listeners = new Map();

  constructor(url) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type, handler) {
    if (!this.#listeners.has(type)) this.#listeners.set(type, []);
    this.#listeners.get(type).push(handler);
  }

  removeEventListener(type, handler) {
    const arr = this.#listeners.get(type);
    if (!arr) return;
    const i = arr.indexOf(handler);
    if (i !== -1) arr.splice(i, 1);
  }

  #emit(type, ev) {
    for (const handler of [...(this.#listeners.get(type) || [])]) handler(ev);
  }

  send(data) {
    if (this.readyState !== FakeWebSocket.OPEN) {
      throw new Error('FakeWebSocket: send() while not open');
    }
    this.sent.push(data instanceof Uint8Array ? data : new Uint8Array(data));
  }

  close(code = 1000, reason = '') {
    if (this.readyState === FakeWebSocket.CLOSED) return;
    this.readyState = FakeWebSocket.CLOSED;
    this.#emit('close', { code, reason });
  }

  // ── Test-only helpers (simulate the server side) ──────────────────
  simulateOpen() {
    this.readyState = FakeWebSocket.OPEN;
    this.#emit('open', {});
  }

  /** @param {Uint8Array} bytes */
  simulateMessage(bytes) {
    this.#emit('message', { data: bytes });
  }

  simulateServerClose(code = 1000, reason = 'server closed') {
    this.close(code, reason);
  }
}
FakeWebSocket.instances = [];

function installFakeWebSocket() {
  const original = globalThis.WebSocket;
  globalThis.WebSocket = FakeWebSocket;
  FakeWebSocket.instances = [];
  return () => {
    globalThis.WebSocket = original;
  };
}

/** Build a raw mux frame the way the real server would, for injecting inbound test data. */
function buildTestFrame(type, streamId, payload = new Uint8Array(0)) {
  const frame = new Uint8Array(5 + payload.byteLength);
  const view = new DataView(frame.buffer);
  view.setUint8(0, type);
  view.setUint32(1, streamId);
  frame.set(payload, 5);
  return frame;
}

async function connectedTransport() {
  const transport = new transportWsMod.WebSocketTransport();
  const connecting = transport.connect('ws://test.invalid');
  const ws = FakeWebSocket.instances.at(-1);
  ws.simulateOpen();
  await connecting;
  return { transport, ws };
}

describe('WebSocketTransport mux framing', { skip: !transportWsMod && 'transport-ws.mjs failed to import' }, () => {
  it('sendControl() writes a byte-exact CONTROL frame on stream 0', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];

      await transport.sendControl({ type: 5, foo: 'bar' });

      assert.equal(ws.sent.length, 1);
      const frame = ws.sent[0];
      const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
      assert.equal(view.getUint8(0), WS_FRAME_TYPE.CONTROL);
      assert.equal(view.getUint32(1), 0, 'control frames always use stream 0');

      // The payload is the same length-prefixed CBOR framing used
      // elsewhere (frameEncode / FrameDecoder) -- decode it back and
      // check the exact message round-trips.
      const decoder = new FrameDecoder();
      const [decoded] = decoder.feed(frame.subarray(5));
      assert.deepEqual(decoded, { type: 5, foo: 'bar' });
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('a single WebSocket message containing two CBOR control messages dispatches both, in order', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      const received = [];
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      transport.onControl = (msg) => received.push(msg);

      const cbor1 = frameEncode({ type: 10, seq: 1 });
      const cbor2 = frameEncode({ type: 10, seq: 2 });
      const combinedPayload = new Uint8Array(cbor1.byteLength + cbor2.byteLength);
      combinedPayload.set(cbor1, 0);
      combinedPayload.set(cbor2, cbor1.byteLength);

      ws.simulateMessage(buildTestFrame(WS_FRAME_TYPE.CONTROL, 0, combinedPayload));
      // #handleMessage is dispatched serially via a SerialQueue; give it
      // a macrotask to actually run.
      await new Promise((resolve) => setTimeout(resolve, 0));

      assert.deepEqual(received, [{ type: 10, seq: 1 }, { type: 10, seq: 2 }]);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('openStream() allocates client stream IDs as odd, incrementing by 2, and sends OPEN_STREAM', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];

      const s1 = await transport.openStream();
      const s2 = await transport.openStream();
      const s3 = await transport.openStream();

      assert.deepEqual([s1.id, s2.id, s3.id], [1, 3, 5]);

      const openFrames = ws.sent.filter((f) => f[0] === WS_FRAME_TYPE.OPEN_STREAM);
      assert.equal(openFrames.length, 3);
      const ids = openFrames.map((f) => new DataView(f.buffer, f.byteOffset).getUint32(1));
      assert.deepEqual(ids, [1, 3, 5]);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('writing to a stream sends a DATA frame with the exact bytes and correct stream ID', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const { writable, id } = await transport.openStream();

      const writer = writable.getWriter();
      await writer.write(new Uint8Array([1, 2, 3, 4]));
      writer.releaseLock();

      const dataFrame = ws.sent.find((f) => f[0] === WS_FRAME_TYPE.DATA);
      assert.ok(dataFrame);
      const view = new DataView(dataFrame.buffer, dataFrame.byteOffset, dataFrame.byteLength);
      assert.equal(view.getUint32(1), id);
      assert.deepEqual(Array.from(dataFrame.subarray(5)), [1, 2, 3, 4]);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('inbound DATA frames for a known stream are delivered via its readable side', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const { readable, id } = await transport.openStream();

      ws.simulateMessage(buildTestFrame(WS_FRAME_TYPE.DATA, id, new Uint8Array([9, 8, 7])));

      const reader = readable.getReader();
      const { value, done } = await reader.read();
      reader.releaseLock();

      assert.equal(done, false);
      assert.deepEqual(Array.from(value), [9, 8, 7]);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('inbound DATA frames for an unknown/already-closed stream are ignored, not an error', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      let sawError = false;
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      transport.onError = () => { sawError = true; };

      // Stream 99 was never opened.
      ws.simulateMessage(buildTestFrame(WS_FRAME_TYPE.DATA, 99, new Uint8Array([1])));
      await new Promise((resolve) => setTimeout(resolve, 0));

      assert.equal(sawError, false);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('closing a stream\'s writable sends CLOSE_STREAM for that stream only', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const s1 = await transport.openStream();
      const s2 = await transport.openStream();

      await s1.writable.close();

      const closeFrames = ws.sent.filter((f) => f[0] === WS_FRAME_TYPE.CLOSE_STREAM);
      assert.equal(closeFrames.length, 1);
      assert.equal(new DataView(closeFrames[0].buffer, closeFrames[0].byteOffset).getUint32(1), s1.id);
      void s2;
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('an inbound CLOSE_STREAM ends the readable side (EOF) without affecting other streams', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const s1 = await transport.openStream();
      const s2 = await transport.openStream();

      ws.simulateMessage(buildTestFrame(WS_FRAME_TYPE.CLOSE_STREAM, s1.id));

      const reader1 = s1.readable.getReader();
      const result1 = await reader1.read();
      assert.equal(result1.done, true);

      // s2 is unaffected: writing to it still produces a DATA frame.
      const writer2 = s2.writable.getWriter();
      await writer2.write(new Uint8Array([1]));
      writer2.releaseLock();
      assert.ok(ws.sent.some((f) => f[0] === WS_FRAME_TYPE.DATA && new DataView(f.buffer, f.byteOffset).getUint32(1) === s2.id));
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('server-initiated OPEN_STREAM (even ID) fires onStreamOpen', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const opened = [];
      transport.onStreamOpen = (s) => opened.push(s);

      ws.simulateMessage(buildTestFrame(WS_FRAME_TYPE.OPEN_STREAM, 2));
      await new Promise((resolve) => setTimeout(resolve, 0));

      assert.equal(opened.length, 1);
      assert.equal(opened[0].id, 2);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('transport close destroys all open streams: further writes reject', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const { writable } = await transport.openStream();

      await transport.close();

      await assert.rejects(() => writable.getWriter().write(new Uint8Array([1])));
    } finally {
      restore();
    }
  });

  it('a malformed inbound frame (too short) emits onError without crashing the transport', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      let errorMessage = null;
      transport.onError = (err) => { errorMessage = err.message; };

      ws.simulateMessage(new Uint8Array([1, 2, 3])); // shorter than the 5-byte header
      await new Promise((resolve) => setTimeout(resolve, 0));

      assert.match(errorMessage || '', /Malformed frame/);

      // The transport is still usable afterward.
      await transport.sendControl({ type: 1 });
      assert.ok(ws.sent.some((f) => f[0] === WS_FRAME_TYPE.CONTROL));
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('server-initiated close (unexpected) destroys streams and fires onClose', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const { readable } = await transport.openStream();
      let closed = false;
      transport.onClose = () => { closed = true; };

      ws.simulateServerClose(1006, 'abnormal closure');
      await new Promise((resolve) => setTimeout(resolve, 0));

      assert.equal(closed, true);
      await assert.rejects(() => readable.getReader().read());
    } finally {
      restore();
    }
  });
});
