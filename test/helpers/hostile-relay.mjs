// A hostile relay for tests: a wsh endpoint that sits between a client (a reverse host, or an operator) and the real
// relay, passes the connection through message by message, and lets the test rewrite, drop, replay or inject.
//
//   const mitm = await hostileRelay(realRelayUrl, {
//     toClient(msg, ctx) { return msg; },     // what the relay sends the client; return a message, an array, or null to drop
//     toRelay(msg, ctx)  { return msg; },     // what the client sends the relay
//   });
//   connect the client to mitm.url instead of the real relay.
//
// ctx: { injectToClient(msg), injectToRelay(msg), seen: [{ dir, msg }] } -- injected messages bypass the hooks.
import { WebSocketServer, WebSocket as WsClientSocket } from 'ws';
import { WebSocketTransport } from '../../src/transport-ws.mjs';
import { QMuxConnection } from '../../src/qmux-connection.mjs';
import { FrameDecoder, frameEncode } from '../../src/cbor.mjs';

const many = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);

export async function hostileRelay(upstream, { toClient = (m) => m, toRelay = (m) => m } = {}) {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await new Promise((r) => wss.once('listening', r));
  const seen = [];
  const contexts = [];
  wss.on('connection', (ws) => {
    const qmux = new QMuxConnection({ isClient: false, send: (b) => { if (ws.readyState === 1) ws.send(b); } });
    const decoder = new FrameDecoder();
    let control = null;
    const back = new WebSocketTransport({ WebSocket: WsClientSocket });
    const ready = back.connect(upstream);
    const ctx = {
      seen,
      injectToClient: (m) => control?.write(frameEncode(m)),
      injectToRelay: async (m) => { await ready; return back.sendControl(m); },
    };
    contexts.push(ctx);
    back.onClose = () => { try { ws.close(1000); } catch { /* gone */ } };
    back.onControl = async (m) => {
      seen.push({ dir: 'to-client', msg: m });
      for (const out of many(await toClient(m, ctx))) await control?.write(frameEncode(out));
    };
    qmux.onStreamOpen = (s) => {
      if (s.id !== 0) return;
      control = s;
      s.onData = (d) => {
        for (const m of decoder.feed(d)) {
          seen.push({ dir: 'to-relay', msg: m });
          (async () => {
            await ready;
            for (const out of many(await toRelay(m, ctx))) await back.sendControl(out);
          })().catch(() => {});
        }
      };
    };
    qmux.sendHandshake();
    ws.on('message', (d) => qmux.receiveBytes(new Uint8Array(d)));
    ws.on('close', () => back.close().catch(() => {}));
  });
  return {
    url: `ws://127.0.0.1:${wss.address().port}`,
    seen,
    /** The context of the first (or nth) client connection. */
    context: (n = 0) => contexts[n],
    close: async () => { for (const c of wss.clients) c.terminate(); await new Promise((r) => wss.close(r)); },
  };
}
