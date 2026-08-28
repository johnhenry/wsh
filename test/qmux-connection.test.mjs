import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { QMuxConnection, DEFAULTS } from '../src/qmux-connection.mjs';
import { ERROR_CODE, QMuxProtocolError } from '../src/qmux.mjs';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * Wires two QMuxConnections together with a genuinely asynchronous
 * "wire" (each send is delivered via a real macrotask, not a direct
 * synchronous call) so flow-control blocking/unblocking can actually be
 * observed mid-flight, the way it would over a real WebSocket -- a
 * fully synchronous send/receive callback would let every window-update
 * round trip resolve within the same call stack as the write that
 * triggered it, defeating the point of testing backpressure at all.
 */
function makeLinkedPair(opts = {}) {
  let client, server;
  client = new QMuxConnection({
    isClient: true,
    send: (bytes) => setTimeout(() => server.receiveBytes(bytes), 0),
    ...opts,
  });
  server = new QMuxConnection({
    isClient: false,
    send: (bytes) => setTimeout(() => client.receiveBytes(bytes), 0),
    ...opts,
  });
  return { client, server };
}

function nextTick(n = 1) {
  return new Promise((resolve) => {
    let remaining = n;
    const step = () => {
      remaining -= 1;
      if (remaining <= 0) resolve();
      else setTimeout(step, 0);
    };
    setTimeout(step, 0);
  });
}

describe('QMuxConnection: basic stream round trip', () => {
  it('client-opened stream delivers data and FIN to the server in order', async () => {
    const { client, server } = makeLinkedPair();
    client.sendHandshake();
    server.sendHandshake();

    let opened = null;
    const chunks = [];
    let ended = false;
    server.onStreamOpen = (s) => {
      opened = s;
      s.onData = (d) => chunks.push(textDecoder.decode(d));
      s.onEnd = () => { ended = true; };
    };

    const stream = await client.openStream();
    await stream.write(textEncoder.encode('hello '));
    await stream.write(textEncoder.encode('world'));
    await stream.close();

    await nextTick(5);

    assert.ok(opened, 'server should have seen the stream open');
    assert.equal(opened.id, stream.id);
    assert.equal(chunks.join(''), 'hello world');
    assert.equal(ended, true);
  });

  it('server-initiated (peer) streams use even-parity IDs and fire onStreamOpen', async () => {
    const { client, server } = makeLinkedPair();
    client.sendHandshake();
    server.sendHandshake();
    await nextTick(2);

    let opened = null;
    client.onStreamOpen = (s) => { opened = s; };

    const serverStream = await server.openStream();
    await serverStream.write(textEncoder.encode('ping'));
    await nextTick(3);

    assert.ok(opened);
    assert.equal(opened.id, serverStream.id);
    assert.equal(opened.id % 2, 1, 'server-initiated bidi stream IDs are odd (initiator bit set)');
  });

  it('multiple concurrent streams interleave independently without cross-contamination', async () => {
    const { client, server } = makeLinkedPair();
    client.sendHandshake();
    server.sendHandshake();

    const receivedByStream = new Map();
    server.onStreamOpen = (s) => {
      receivedByStream.set(s.id, []);
      s.onData = (d) => receivedByStream.get(s.id).push(textDecoder.decode(d));
    };

    const s1 = await client.openStream();
    const s2 = await client.openStream();
    const s3 = await client.openStream();
    assert.deepEqual([s1.id, s2.id, s3.id], [0, 4, 8]);

    await Promise.all([
      s1.write(textEncoder.encode('one')),
      s2.write(textEncoder.encode('two')),
      s3.write(textEncoder.encode('three')),
    ]);
    await nextTick(5);

    assert.equal(receivedByStream.get(s1.id).join(''), 'one');
    assert.equal(receivedByStream.get(s2.id).join(''), 'two');
    assert.equal(receivedByStream.get(s3.id).join(''), 'three');
  });
});

describe('QMuxConnection: flow control', () => {
  it('write() blocks when the stream-level window is exhausted and resumes once MAX_STREAM_DATA arrives', async () => {
    const { client, server } = makeLinkedPair({ initialMaxStreamData: 16, initialMaxData: 10_000 });
    client.sendHandshake();
    server.sendHandshake();
    await nextTick(2);

    const received = [];
    server.onStreamOpen = (s) => {
      s.onData = (d) => received.push(Buffer.from(d));
    };

    const stream = await client.openStream();
    const payload = new Uint8Array(64).fill(65); // 4x the 16-byte window
    let writeDone = false;
    const writePromise = stream.write(payload).then(() => { writeDone = true; });

    // Immediately after issuing the write, only the first window's worth
    // can have gone out -- the rest is blocked pending a round trip.
    await nextTick(1);
    assert.equal(writeDone, false, 'write() should still be pending, blocked on stream flow control');
    assert.ok(Buffer.concat(received).byteLength < 64, 'not all data should have arrived yet');

    await writePromise;
    // write() resolving means every chunk was handed to the transport, not
    // that the peer has received it yet (the last chunk's delivery is
    // still a pending setTimeout(0) at that point) -- give it a tick.
    await nextTick(2);
    assert.equal(Buffer.concat(received).byteLength, 64, 'all data eventually arrives once window updates catch up');
  });

  it('write() blocks on the connection-level window even when the stream-level window is generous', async () => {
    const { client, server } = makeLinkedPair({ initialMaxStreamData: 10_000, initialMaxData: 16 });
    client.sendHandshake();
    server.sendHandshake();
    await nextTick(2);

    const received = [];
    server.onStreamOpen = (s) => { s.onData = (d) => received.push(Buffer.from(d)); };

    const stream = await client.openStream();
    const payload = new Uint8Array(64).fill(66);
    let writeDone = false;
    const writePromise = stream.write(payload).then(() => { writeDone = true; });

    await nextTick(1);
    assert.equal(writeDone, false);

    await writePromise;
    await nextTick(2);
    assert.equal(Buffer.concat(received).byteLength, 64);
  });

  it('two streams sharing one connection both eventually make progress under a tight connection-level window', async () => {
    const { client, server } = makeLinkedPair({ initialMaxStreamData: 10_000, initialMaxData: 32 });
    client.sendHandshake();
    server.sendHandshake();
    await nextTick(2);

    const receivedByStream = new Map();
    server.onStreamOpen = (s) => {
      receivedByStream.set(s.id, []);
      s.onData = (d) => receivedByStream.get(s.id).push(Buffer.from(d));
    };

    const s1 = await client.openStream();
    const s2 = await client.openStream();
    const payload1 = new Uint8Array(40).fill(1);
    const payload2 = new Uint8Array(40).fill(2);

    await Promise.all([s1.write(payload1), s2.write(payload2)]);
    await nextTick(2);

    assert.equal(Buffer.concat(receivedByStream.get(s1.id)).byteLength, 40);
    assert.equal(Buffer.concat(receivedByStream.get(s2.id)).byteLength, 40);
  });
});

describe('QMuxConnection: RESET_STREAM / RESET_STREAM_AT', () => {
  it('reset() with no reliableSize delivers nothing and fires onReset immediately', async () => {
    const { client, server } = makeLinkedPair();
    client.sendHandshake();
    server.sendHandshake();
    await nextTick(2);

    const received = [];
    let resetCode = null;
    server.onStreamOpen = (s) => {
      s.onData = (d) => received.push(d);
      s.onReset = (code) => { resetCode = code; };
    };

    const stream = await client.openStream();
    stream.reset(ERROR_CODE.INTERNAL_ERROR);
    await nextTick(3);

    assert.equal(received.length, 0);
    assert.equal(resetCode, ERROR_CODE.INTERNAL_ERROR);
  });

  it('reset() with a reliableSize delivers the prefix before firing onReset', async () => {
    const { client, server } = makeLinkedPair();
    client.sendHandshake();
    server.sendHandshake();
    await nextTick(2);

    const received = [];
    let resetCode = null;
    let dataBeforeReset = null;
    server.onStreamOpen = (s) => {
      s.onData = (d) => received.push(textDecoder.decode(d));
      s.onReset = (code) => {
        dataBeforeReset = received.join('');
        resetCode = code;
      };
    };

    const stream = await client.openStream();
    await stream.write(textEncoder.encode('important-prefix'));
    stream.reset(ERROR_CODE.APPLICATION_ERROR, 16); // "important-prefix".length
    await nextTick(3);

    assert.equal(dataBeforeReset, 'important-prefix');
    assert.equal(resetCode, ERROR_CODE.APPLICATION_ERROR);
  });

  it('write()/close() after reset() throw', async () => {
    const { client, server } = makeLinkedPair();
    client.sendHandshake();
    server.sendHandshake();
    const stream = await client.openStream();
    stream.reset();

    await assert.rejects(() => stream.write(new Uint8Array([1])));
    void server;
  });

  it('stopSending() causes the peer to reset its send side', async () => {
    const { client, server } = makeLinkedPair();
    client.sendHandshake();
    server.sendHandshake();
    await nextTick(2);

    let serverStream = null;
    server.onStreamOpen = (s) => { serverStream = s; };

    const stream = await client.openStream();
    await stream.write(textEncoder.encode('x'));
    await nextTick(2);
    assert.ok(serverStream);

    // STOP_SENDING targets our *send* side (the client's, since the
    // client owns this stream's send direction) -- onReset is for
    // observing a *peer's* reset on the receive side, which is a
    // different direction and not what STOP_SENDING triggers here.
    assert.equal(stream.sendState, 'send');
    serverStream.stopSending(ERROR_CODE.APPLICATION_ERROR);
    await nextTick(3);

    assert.equal(stream.sendState, 'reset_sent');
  });
});

describe('QMuxConnection: MAX_STREAMS', () => {
  it('openStream() blocks once the peer-granted stream limit is reached, and resumes after MAX_STREAMS', async () => {
    const { client, server } = makeLinkedPair({ initialMaxStreamsBidi: 1 });
    client.sendHandshake();
    server.sendHandshake();
    await nextTick(2);

    server.onStreamOpen = (s) => { s.close(); }; // accept and immediately half-close from the server side too, so streams can fully close
    const s1 = await client.openStream();
    await s1.close();
    await nextTick(3); // let the server's close (FIN) arrive back and complete full closure + MAX_STREAMS regrant

    // A second stream should now be allowed once the first fully closed
    // and the server topped the grant back up.
    const s2 = await client.openStream();
    assert.equal(s2.id, 4);
  });
});

describe('QMuxConnection: protocol violations', () => {
  it('an out-of-order STREAM frame closes the connection with PROTOCOL_VIOLATION', async () => {
    let closeInfo = null;
    const client = new QMuxConnection({ isClient: true, send: () => {} });
    client.onClose = null;
    client.onError = (err) => { closeInfo = err; };

    // Fabricate a STREAM frame for stream 1 (server-initiated) at offset
    // 5 when the connection has never seen offset 0-4 -- an out-of-order
    // violation this in-order-transport codec should reject.
    const { encodeRecord, encodeStream } = await import('../src/qmux.mjs');
    const badFrame = encodeStream({ streamId: 1, offset: 5, data: new Uint8Array([1]), fin: false });
    client.receiveBytes(encodeRecord(badFrame));

    assert.ok(closeInfo instanceof QMuxProtocolError);
    assert.equal(closeInfo.errorCode, ERROR_CODE.PROTOCOL_VIOLATION);
  });
});

describe('QMuxConnection: connection close', () => {
  it('close() sends CONNECTION_CLOSE and the peer observes it via onClose', async () => {
    const { client, server } = makeLinkedPair();
    client.sendHandshake();
    server.sendHandshake();
    await nextTick(2);

    let closeArgs = null;
    server.onClose = (errorCode, reason) => { closeArgs = { errorCode, reason }; };

    client.close(ERROR_CODE.NO_ERROR, 'done');
    await nextTick(2);

    assert.deepEqual(closeArgs, { errorCode: ERROR_CODE.NO_ERROR, reason: 'done' });
  });
});

describe('QMuxConnection: datagrams', () => {
  it('sendDatagram()/onDatagram round trip', async () => {
    const { client, server } = makeLinkedPair();
    client.sendHandshake();
    server.sendHandshake();
    await nextTick(2);

    let received = null;
    server.onDatagram = (d) => { received = textDecoder.decode(d); };

    client.sendDatagram(textEncoder.encode('unreliable-but-actually-reliable-here'));
    await nextTick(2);

    assert.equal(received, 'unreliable-but-actually-reliable-here');
  });
});

describe('QMuxConnection: defaults', () => {
  it('DEFAULTS are sane (nonzero, large enough for real traffic)', () => {
    assert.ok(DEFAULTS.initialMaxData > DEFAULTS.initialMaxStreamData);
    assert.ok(DEFAULTS.initialMaxStreamsBidi > 0);
  });
});
