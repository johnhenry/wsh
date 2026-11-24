/**
 * The Node-only half of the pipe relay: an HTTP(S) server that accepts WebSocket upgrades on `<path>/<id>` and hands each to
 * `relay.accept()`. `createPipeRelay().listen()` loads this module on demand; the relay itself (`./pipe-relay.mjs`) is
 * browser-safe and imports nothing. Needs the optional `ws` package. Its only imports are `ws`, `node:http` and `node:https`,
 * all dynamic, so it reaches nothing that can execute code or read files (test/pipe-relay.test.mjs walks its graph too).
 */

const ID_RE = /^[A-Za-z0-9_-]{22,128}$/;
const ROLES = new Set(['host', 'operator']);

/**
 * @param {{ accept: Function, maxMessageBytes: number, onClose: (fn: () => Promise<void> | void) => void, close: () => Promise<void> }} relay
 * @param {{ host?: string, port?: number, path?: string, tls?: object }} [options]
 * @returns {Promise<{ port: number, address: string, close(): Promise<void> }>}
 */
export async function listenPipeRelay(relay, { host = '127.0.0.1', port = 0, path = '/r', tls } = {}) {
  const { WebSocketServer } = await import('ws');
  const http = tls ? await import('node:https') : await import('node:http');
  const wss = new WebSocketServer({ noServer: true, maxPayload: relay.maxMessageBytes });
  const srv = tls ? http.createServer(tls) : http.createServer();
  srv.on('request', (_req, res) => { res.statusCode = 426; res.end('WebSocket only'); });
  srv.on('upgrade', (req, sock, head) => {
    let url;
    try { url = new URL(req.url, 'http://x'); } catch { sock.destroy(); return; }
    const m = url.pathname.startsWith(`${path}/`) ? url.pathname.slice(path.length + 1) : null;
    const role = url.searchParams.get('role') ?? 'operator';
    if (!m || !ID_RE.test(m) || !ROLES.has(role)) { sock.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n'); sock.destroy(); return; }
    // `paired=1` is the host asking to be told when its partner arrives; an operator that sends it is not a host, so it is ignored.
    const notifyPaired = role === 'host' && url.searchParams.get('paired') === '1';
    wss.handleUpgrade(req, sock, head, (ws) => {
      relay.accept(ws, { id: m, role, notifyPaired, remote: { address: req.socket.remoteAddress, headers: req.headers } })
        .catch(() => { try { ws.close(1011, 'error'); } catch { /* gone */ } });
    });
  });
  await new Promise((resolve, reject) => { srv.once('error', reject); srv.listen(port, host, () => { srv.off('error', reject); resolve(); }); });
  relay.onClose(async () => {
    for (const c of wss.clients) c.terminate();
    await new Promise((r) => wss.close(r));
    await new Promise((r) => { srv.close(() => r()); srv.closeAllConnections?.(); });
  });
  const addr = srv.address();
  return { port: addr.port, address: addr.address, close: () => relay.close() };
}
