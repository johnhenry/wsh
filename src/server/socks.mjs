/**
 * SOCKS5 client for the Node gateway (`gateway.socks`). Node only (`node:net`, `Buffer`), loaded on first use by the gateway session so
 * that the session itself (`gateway-session.mjs`) bundles for a browser.
 */

import net from 'node:net';
import { GATEWAY_FAIL } from './gateway-core.mjs';

const DEFAULT_CONNECT_TIMEOUT_MS = 15_000;

/**
 * SOCKS5 CONNECT (RFC 1928) with no authentication, destination as a domain name.
 * Resolves with the connected socket, or rejects with an Error carrying `.code`
 * (a GATEWAY_FAIL value).
 */
export async function socksConnect(proxy, host, port, { timeoutMs = DEFAULT_CONNECT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const name = Buffer.from(host, 'utf8');
    const fail = (code, message, sock) => { sock?.destroy(); const e = new Error(message); e.code = code; reject(e); };
    if (name.length === 0 || name.length > 255) return fail(GATEWAY_FAIL.DNS_FAILED, 'invalid host name');
    const sock = net.connect({ host: proxy.host, port: proxy.port });
    sock.setNoDelay(true);
    const timer = setTimeout(() => fail(GATEWAY_FAIL.TIMEOUT, 'SOCKS5 connect timed out', sock), timeoutMs);
    let stage = 'method';
    let buf = Buffer.alloc(0);
    sock.once('error', (e) => { clearTimeout(timer); fail(GATEWAY_FAIL.HOST_UNREACHABLE, `SOCKS5 proxy: ${e.message}`, sock); });
    sock.once('connect', () => sock.write(Buffer.from([0x05, 0x01, 0x00])));
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 'method') {
        if (buf.length < 2) return;
        if (buf[0] !== 0x05 || buf[1] !== 0x00) { clearTimeout(timer); return fail(GATEWAY_FAIL.POLICY_DENIED, 'SOCKS5 proxy requires authentication', sock); }
        buf = buf.subarray(2);
        stage = 'reply';
        const req = Buffer.alloc(7 + name.length);
        req.set([0x05, 0x01, 0x00, 0x03, name.length], 0);
        name.copy(req, 5);
        req.writeUInt16BE(port, 5 + name.length);
        sock.write(req);
      }
      if (stage === 'reply') {
        if (buf.length < 5) return;
        const atyp = buf[3];
        const need = 4 + (atyp === 0x01 ? 4 : atyp === 0x04 ? 16 : 1 + buf[4]) + 2;
        if (buf.length < need) return;
        clearTimeout(timer);
        sock.off('data', onData);
        sock.removeAllListeners('error');
        const rest = buf.subarray(need);
        if (buf[1] !== 0x00) {
          const code = buf[1] === 0x05 ? GATEWAY_FAIL.CONNECTION_REFUSED : buf[1] === 0x04 || buf[1] === 0x03 ? GATEWAY_FAIL.HOST_UNREACHABLE : buf[1] === 0x02 ? GATEWAY_FAIL.POLICY_DENIED : GATEWAY_FAIL.HOST_UNREACHABLE;
          return fail(code, `SOCKS5 proxy refused (reply 0x${buf[1].toString(16)})`, sock);
        }
        if (rest.length) sock.unshift(rest);
        resolve(sock);
      }
    };
    sock.on('data', onData);
  });
}
