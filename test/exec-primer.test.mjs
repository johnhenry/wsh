// test/exec-primer.test.mjs
//
// Stream-mode exec sessions used to lose ALL output unless the client wrote
// a one-byte "primer" to the data stream right after openSession().
//
// Root cause: a QMux (and QUIC/WebTransport) stream is created lazily --
// opening one allocates an id locally and puts NOTHING on the wire until the
// first byte (or FIN) is sent. An exec client never has stdin to send, so the
// server never learned the data stream existed; a host that binds the stream
// on first sight (FIFO against its pending OpenOk) waited, gave up and
// dropped the buffered output.
//
// Fix, two layers:
//   1. the QMux transport announces a stream the moment it is opened (an empty
//      STREAM frame -- legal QUIC, carries no payload to strip);
//   2. a server that advertises the `stream-announce` feature promises it
//      needs no primer; against any other host the stock client still writes
//      the primer itself (opt out with `primer: false`).
//
// The host below is deliberately minimal and "legacy": it binds the data
// stream on first sight, strips one leading byte if told to, and gives up
// after a short wait -- the behaviour of the vendored hosts that motivated this.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocketServer } from 'ws';
import { WshClient } from '../src/client.mjs';
import { QMuxConnection } from '../src/qmux-connection.mjs';
import { FrameDecoder, frameEncode } from '../src/cbor.mjs';
import {
  MSG, serverHello, challenge, authOk, openOk, exit as exitMsg, close as closeMsg,
} from '../src/messages.gen.mjs';
import { generateKeyPair } from '../src/auth.mjs';

const BIND_WAIT_MS = 400;
const enc = new TextEncoder();
const dec = new TextDecoder();

/** @returns {Promise<{url: string, log: object[], close: () => Promise<void>}>} */
async function legacyHost({ features = [], stripPrimer = true } = {}) {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await new Promise((r) => wss.once('listening', r));
  const log = [];
  wss.on('connection', (ws) => {
    const qmux = new QMuxConnection({ isClient: false, send: (b) => ws.send(b) });
    const decoder = new FrameDecoder();
    let control = null;
    let dataStream = null;
    let boundResolve;
    const bound = new Promise((r) => { boundResolve = r; });
    const send = (m) => control.write(frameEncode(m));

    qmux.onStreamOpen = (s) => {
      if (s.id === 0) {
        control = s;
        s.onData = (d) => { for (const m of decoder.feed(d)) onMessage(m); };
        return;
      }
      dataStream = s;
      s.onData = (d) => {
        log.push({ inbound: [...d] });
        if (stripPrimer) d = d.subarray(1);
      };
      log.push({ streamOpened: true });
      boundResolve();
    };

    async function onMessage(m) {
      if (m.type === MSG.HELLO) {
        await send(serverHello({ sessionId: 's1', features }));
        await send(challenge({ nonce: new Uint8Array(32).fill(1), sessionId: 's1' }));
      } else if (m.type === MSG.AUTH) {
        await send(authOk({ sessionId: 's1', token: new Uint8Array(16), ttl: 60 }));
      } else if (m.type === MSG.OPEN) {
        await send(openOk({ channelId: 1, dataMode: 'stream', sessionId: 'x' }));
        // The "process": its output is ready immediately.
        const got = await Promise.race([bound.then(() => true), new Promise((r) => setTimeout(r, BIND_WAIT_MS, false))]);
        if (got) await dataStream.write(enc.encode('hello\n'));
        else log.push({ gaveUp: true });
        if (dataStream) await dataStream.close();
        await send(exitMsg({ channelId: 1, code: 0 }));
        await send(closeMsg({ channelId: 1 }));
      }
    }
    qmux.sendHandshake();
    ws.on('message', (d) => qmux.receiveBytes(new Uint8Array(d)));
  });
  return {
    url: `ws://127.0.0.1:${wss.address().port}`,
    log,
    close: () => new Promise((r) => { for (const c of wss.clients) c.terminate(); wss.close(r); }),
  };
}

describe('exec output without a hand-written primer', () => {
  let keyPair;
  before(async () => { keyPair = await generateKeyPair(true); });

  it('WshClient.exec() receives output from a legacy host (no consumer-side primer)', async () => {
    const host = await legacyHost();
    try {
      const { stdout, exitCode } = await WshClient.exec(host.url, 'echo hello', { username: 'u', keyPair, timeout: 5000 });
      assert.equal(dec.decode(stdout), 'hello\n');
      assert.equal(exitCode, 0);
      assert.ok(!host.log.some((e) => e.gaveUp), 'host gave up waiting for the data stream');
    } finally { await host.close(); }
  });

  it('the data stream is announced before any payload byte is written', async () => {
    const host = await legacyHost();
    try {
      await WshClient.exec(host.url, 'echo hello', { username: 'u', keyPair, timeout: 5000 });
      assert.deepEqual(host.log[0], { streamOpened: true });
    } finally { await host.close(); }
  });

  it('writes exactly one primer byte to a host that does not advertise stream-announce', async () => {
    const host = await legacyHost();
    try {
      await WshClient.exec(host.url, 'echo hello', { username: 'u', keyPair, timeout: 5000 });
      assert.deepEqual(host.log.filter((e) => e.inbound).map((e) => e.inbound), [[0]]);
    } finally { await host.close(); }
  });

  it('writes NO primer to a host that advertises stream-announce', async () => {
    const host = await legacyHost({ features: ['stream-announce'] });
    try {
      const { stdout } = await WshClient.exec(host.url, 'echo hello', { username: 'u', keyPair, timeout: 5000 });
      assert.equal(dec.decode(stdout), 'hello\n');
      assert.deepEqual(host.log.filter((e) => e.inbound), []);
    } finally { await host.close(); }
  });

  it('primer: false opts out, and output still arrives (the announce alone binds the stream)', async () => {
    const host = await legacyHost();
    try {
      const { stdout } = await WshClient.exec(host.url, 'echo hello', { username: 'u', keyPair, primer: false, timeout: 5000 });
      assert.equal(dec.decode(stdout), 'hello\n');
      assert.deepEqual(host.log.filter((e) => e.inbound), []);
    } finally { await host.close(); }
  });

  it('openSession({ type: "exec" }) primes by default and honours primer: false', async () => {
    for (const [primer, expected] of [[undefined, [[0]]], [false, []]]) {
      const host = await legacyHost();
      const client = new WshClient();
      try {
        await client.connect(host.url, { username: 'u', keyPair });
        const session = await client.openSession({ type: 'exec', command: 'echo hello', primer });
        await new Promise((r) => { session.onClose = r; });
        assert.deepEqual(host.log.filter((e) => e.inbound).map((e) => e.inbound), expected);
      } finally { await client.disconnect().catch(() => {}); await host.close(); }
    }
  });
});
