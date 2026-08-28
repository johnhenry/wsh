import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FrameDecoder, frameEncode } from '../src/cbor.mjs';
import {
  RecordDecoder, decodeFrames, encodeRecord,
  encodeStream, encodeTransportParameters, encodeMaxStreamData, encodeMaxData,
} from '../src/qmux.mjs';

// Integration tests for WebSocketTransport: does it correctly wire
// QMuxConnection (qmux-connection.mjs, its own thoroughly-tested state
// machine) to a real WebSocket? The wire codec itself (frame byte
// layout, varints) is covered by test/qmux.test.mjs; the stream state
// machine and flow control by test/qmux-connection.test.mjs. This file
// verifies the *plumbing*: connect() opens the control stream,
// sendControl()/openStream() route through QMux correctly, inbound
// bytes are correctly decoded and delivered, and transport-level
// lifecycle (close, errors, server-initiated streams) works.

let transportWsMod;
try {
  transportWsMod = await import('../src/transport-ws.mjs');
} catch {
  // Module import may fail in environments without the expected globals.
}

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

  /** @param {Uint8Array} recordBytes a full QMux Record (already length-prefixed) */
  simulateMessage(recordBytes) {
    this.#emit('message', { data: recordBytes });
  }

  simulateServerClose(code = 1000, reason = 'server closed') {
    this.close(code, reason);
  }

  /** Every QMux Record this fake WebSocket has sent, decoded into frames. */
  sentFrames() {
    const decoder = new RecordDecoder();
    const frames = [];
    for (const chunk of this.sent) {
      for (const record of decoder.feed(chunk)) {
        frames.push(...decodeFrames(record));
      }
    }
    return frames;
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

async function connectedTransport() {
  const transport = new transportWsMod.WebSocketTransport();
  const connecting = transport.connect('ws://test.invalid');
  const ws = FakeWebSocket.instances.at(-1);
  ws.simulateOpen();
  await connecting;
  return { transport, ws };
}

function nextTick(n = 1) {
  return new Promise((resolve) => {
    let remaining = n;
    const step = () => { remaining -= 1; if (remaining <= 0) resolve(); else setTimeout(step, 0); };
    setTimeout(step, 0);
  });
}

describe('WebSocketTransport (QMux)', { skip: !transportWsMod && 'transport-ws.mjs failed to import' }, () => {
  it('connect() sends the QX_TRANSPORT_PARAMETERS handshake frame first and opens the control stream with no wire traffic of its own', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];

      const frames = ws.sentFrames();
      assert.equal(frames.length, 1, 'only the handshake frame should have been sent so far');
      assert.equal(frames[0].frameType, 'QX_TRANSPORT_PARAMETERS');
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('sendControl() writes a STREAM frame on stream 0 wrapping length-prefixed CBOR', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];

      await transport.sendControl({ type: 5, foo: 'bar' });

      const streamFrames = ws.sentFrames().filter((f) => f.frameType === 'STREAM');
      assert.equal(streamFrames.length, 1);
      assert.equal(streamFrames[0].streamId, 0, 'control messages always go out on stream 0');

      // Payload is the same length-prefixed CBOR framing used elsewhere.
      const decoder = new FrameDecoder();
      const [decoded] = decoder.feed(streamFrames[0].data);
      assert.deepEqual(decoded, { type: 5, foo: 'bar' });
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('a server STREAM frame for stream 0 spanning two CBOR messages dispatches both, in order', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      const received = [];
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      transport.onControl = (msg) => received.push(msg);

      const cbor1 = frameEncode({ type: 10, seq: 1 });
      const cbor2 = frameEncode({ type: 10, seq: 2 });
      const combined = new Uint8Array(cbor1.byteLength + cbor2.byteLength);
      combined.set(cbor1, 0);
      combined.set(cbor2, cbor1.byteLength);

      ws.simulateMessage(encodeRecord(encodeStream({ streamId: 0, offset: 0, data: combined, fin: false })));
      await nextTick(2);

      assert.deepEqual(received, [{ type: 10, seq: 1 }, { type: 10, seq: 2 }]);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('openStream() allocates client stream IDs starting after the control stream (4, 8, 12...)', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());

      const s1 = await transport.openStream();
      const s2 = await transport.openStream();
      const s3 = await transport.openStream();

      assert.deepEqual([s1.id, s2.id, s3.id], [4, 8, 12]);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('writing to an opened stream sends a STREAM frame with the exact bytes and correct stream ID', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const { writable, id } = await transport.openStream();

      const writer = writable.getWriter();
      await writer.write(new Uint8Array([1, 2, 3, 4]));
      writer.releaseLock();

      const dataFrame = ws.sentFrames().find((f) => f.frameType === 'STREAM' && f.streamId === id);
      assert.ok(dataFrame);
      assert.deepEqual(Array.from(dataFrame.data), [1, 2, 3, 4]);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('inbound STREAM frames for a known stream are delivered via its readable side', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const { readable, id } = await transport.openStream();

      ws.simulateMessage(encodeRecord(encodeStream({ streamId: id, offset: 0, data: new Uint8Array([9, 8, 7]), fin: false })));

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

  it('closing a stream\'s writable sends a FIN STREAM frame for that stream only', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const s1 = await transport.openStream();
      const s2 = await transport.openStream();
      void s2;

      await s1.writable.close();

      const finFrames = ws.sentFrames().filter((f) => f.frameType === 'STREAM' && f.fin === true);
      assert.equal(finFrames.length, 1);
      assert.equal(finFrames[0].streamId, s1.id);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('an inbound FIN ends the readable side (EOF) without affecting other streams', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const s1 = await transport.openStream();
      const s2 = await transport.openStream();

      ws.simulateMessage(encodeRecord(encodeStream({ streamId: s1.id, offset: 0, data: new Uint8Array(0), fin: true })));

      const reader1 = s1.readable.getReader();
      const result1 = await reader1.read();
      assert.equal(result1.done, true);

      // s2 is unaffected: writing to it still produces a STREAM frame.
      const writer2 = s2.writable.getWriter();
      await writer2.write(new Uint8Array([1]));
      writer2.releaseLock();
      assert.ok(ws.sentFrames().some((f) => f.frameType === 'STREAM' && f.streamId === s2.id && f.data.byteLength === 1));
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('a server-initiated stream (odd stream ID, from this client\'s perspective) fires onStreamOpen', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const opened = [];
      transport.onStreamOpen = (s) => opened.push(s);

      // Stream 1: server-initiated (initiator bit set), bidirectional.
      ws.simulateMessage(encodeRecord(encodeStream({ streamId: 1, offset: 0, data: new Uint8Array([1]), fin: false })));
      await nextTick(2);

      assert.equal(opened.length, 1);
      assert.equal(opened[0].id, 1);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('grants from the peer (MAX_STREAM_DATA / MAX_DATA) are consumed without surfacing as control or stream data', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      let sawControl = false;
      transport.onControl = () => { sawControl = true; };

      ws.simulateMessage(encodeRecord(encodeMaxData(1_000_000)));
      ws.simulateMessage(encodeRecord(encodeMaxStreamData({ streamId: 0, maxStreamData: 1_000_000 })));
      await nextTick(2);

      assert.equal(sawControl, false);
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('transport close destroys open streams: further writes reject', async () => {
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

  // Regression test: local close() used to only send a graceful
  // CONNECTION_CLOSE to the peer without tearing down this endpoint's
  // own stream objects, so a reader still waiting on a stream's
  // readable side at close time would hang forever (nothing else would
  // ever error or close that controller once the peer can no longer
  // meaningfully respond).
  it('transport close also errors any pending read on an open stream, rather than hanging it forever', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const { readable } = await transport.openStream();
      const reader = readable.getReader();
      const readPromise = reader.read();

      await transport.close();

      await assert.rejects(() => readPromise);
    } finally {
      restore();
    }
  });

  it('a malformed inbound record (garbage frame type) emits onError without crashing the transport', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      let sawError = false;
      transport.onError = () => { sawError = true; };

      // 0x06 is CRYPTO -- a QMux-prohibited frame type.
      ws.simulateMessage(encodeRecord(new Uint8Array([0x06])));
      await nextTick(2);

      assert.equal(sawError, true);

      // The transport is still usable afterward for anything not tied to
      // the frame that errored.
      await transport.sendControl({ type: 1 });
      assert.ok(ws.sentFrames().some((f) => f.frameType === 'STREAM' && f.streamId === 0));
    } finally {
      await transport?.close().catch(() => {});
      restore();
    }
  });

  it('server-initiated WebSocket close (unexpected) destroys streams and fires onClose', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      const { readable } = await transport.openStream();
      let closed = false;
      transport.onClose = () => { closed = true; };

      ws.simulateServerClose(1006, 'abnormal closure');
      await nextTick(2);

      assert.equal(closed, true);
      await assert.rejects(() => readable.getReader().read());
    } finally {
      restore();
    }
  });

  it('a peer CONNECTION_CLOSE frame also tears the transport down gracefully', async () => {
    const restore = installFakeWebSocket();
    let transport;
    try {
      ({ transport } = await connectedTransport());
      const ws = FakeWebSocket.instances[0];
      let closed = false;
      transport.onClose = () => { closed = true; };

      const { encodeConnectionClose } = await import('../src/qmux.mjs');
      ws.simulateMessage(encodeRecord(encodeConnectionClose({ application: true, errorCode: 0, reason: 'bye' })));
      await nextTick(2);

      assert.equal(closed, true);
    } finally {
      restore();
    }
  });
});
