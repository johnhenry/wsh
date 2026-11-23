// Node-side pieces of the browser tests: a wsh server for the page to connect to, and the byte pipe that joins an
// in-page host to an operator (the JS client or the Rust CLI) that cannot reach into the page.
import { WebSocketServer } from 'ws';
import https from 'node:https';
import { createWshServer, generateSelfSignedCertificate } from '@johnhenry/wsh/server';

/** Start a Node wsh server on a free loopback port. */
export async function startServer(options) {
  const server = createWshServer({ host: '127.0.0.1', port: 0, ...options });
  const { port } = await server.listen();
  return { server, port, url: `ws://127.0.0.1:${port}`, close: () => server.close() };
}

/**
 * A byte pipe: the page opens a WebSocket to `hostUrl` (its host serves that socket), an operator connects to `operatorUrl`
 * (`ws://`) or `operatorTlsPort` (`wss://`, for the released Rust CLI, which only speaks `wss://`), and every binary
 * message is passed through unchanged, in order, in both directions. An operator is paired with the oldest host socket
 * still waiting; one that arrives first waits for it. The pipe knows nothing of wsh.
 */
export async function startPipe() {
  const hostSide = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  const operatorSide = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  const cert = generateSelfSignedCertificate();
  const tls = https.createServer({ cert: cert.cert, key: cert.privKey });
  const operatorTls = new WebSocketServer({ server: tls });
  await Promise.all([
    new Promise((r) => hostSide.on('listening', r)),
    new Promise((r) => operatorSide.on('listening', r)),
    new Promise((r) => tls.listen(0, '127.0.0.1', r)),
  ]);
  const waitingHosts = [];
  const waitingOperators = [];
  const traffic = { toHost: 0, toOperator: 0 };
  const recorded = []; // every byte the relay copied, both ways (what a recording relay would keep)
  const join = (host, operator) => {
    host.on('message', (d, isBinary) => { traffic.toOperator += d.length; recorded.push(Buffer.from(d)); if (operator.readyState === 1) operator.send(d, { binary: isBinary }); });
    operator.on('message', (d, isBinary) => { traffic.toHost += d.length; recorded.push(Buffer.from(d)); if (host.readyState === 1) host.send(d, { binary: isBinary }); });
    host.on('close', () => operator.close());
    operator.on('close', () => host.close());
  };
  const pair = () => { while (waitingHosts.length && waitingOperators.length) join(waitingHosts.shift(), waitingOperators.shift()); };
  hostSide.on('connection', (s) => { waitingHosts.push(s); pair(); });
  for (const wss of [operatorSide, operatorTls]) wss.on('connection', (s) => { waitingOperators.push(s); pair(); });
  return {
    hostUrl: `ws://127.0.0.1:${hostSide.address().port}`,
    operatorUrl: `ws://127.0.0.1:${operatorSide.address().port}`,
    operatorTlsPort: tls.address().port,
    traffic,
    /** Everything the relay copied so far, as one buffer. */
    recording: () => Buffer.concat(recorded),
    async close() {
      for (const w of [hostSide, operatorSide, operatorTls]) { for (const c of w.clients) c.terminate(); w.close(); }
      tls.closeAllConnections?.();
      await new Promise((r) => tls.close(r));
    },
  };
}
