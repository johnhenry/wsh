/**
 * Gateway for the Node server: the TCP and DNS half of the wire protocol's
 * gateway opcodes (0x70-0x7e), which until now only the Rust `wsh-server`
 * answered. It lets an authenticated client (typically a browser tab running
 * `GatewayBackend` from `@johnhenry/browsermesh-netway`) open TCP connections
 * and resolve names FROM THE HOST, so a page can reach a plain-TCP service
 * (an MQTT broker, a database) that a browser cannot.
 *
 * Off unless `createWshServer({ gateway })` is given, and then default-deny:
 * a destination must match `allow`. Pattern forms (the same as the Rust policy):
 * `"*"` any host and port, `"host"` that name on any port, `"host:port"`.
 * Matching is on the NAME the client asked for, case-insensitively; with `socks`
 * set the name is handed to the proxy unresolved, so the host never looks it up.
 *
 * Not implemented, and answered with a clean GatewayFail / ListenFail rather than
 * silence: UDP (`OpenUdp`) and reverse tunnels (`ListenRequest`).
 *
 * `socks`: dial through a SOCKS5 proxy (`'host:port'`, `socks5://host:port` or
 * `{ host, port }`), e.g. a local Tor client (`127.0.0.1:9050`). Commands carry the
 * destination as a domain name (ATYP 3), so name resolution happens at the proxy
 * (no DNS leak) and `.onion` names work. In that mode `ResolveDns` is refused:
 * the host would have to resolve the name itself.
 */

import net from 'node:net';
import dns from 'node:dns/promises';
import { MSG, gatewayOk, gatewayFail, gatewayClose, gatewayData, dnsResult, listenFail } from '../messages.gen.mjs';

/** Numeric codes of GatewayFail (the same table `@johnhenry/browsermesh-netway` decodes). */
export const GATEWAY_FAIL = Object.freeze({
  CONNECTION_REFUSED: 1, HOST_UNREACHABLE: 2, DNS_FAILED: 3, POLICY_DENIED: 4, TIMEOUT: 5, CLOSED: 6, QUEUE_FULL: 7,
});

const DEFAULT_MAX_CONNECTIONS = 32;
const DEFAULT_CONNECT_TIMEOUT_MS = 15_000;
const MAX_DATA_BYTES = 1024 * 1024;

/** @param {string|{host:string,port:number}} socks */
export function parseSocks(socks) {
  if (socks === undefined || socks === null || socks === false) return null;
  if (typeof socks === 'object') {
    if (!socks.host || !Number.isInteger(socks.port)) throw new TypeError('gateway.socks must be "host:port" or { host, port }');
    return { host: String(socks.host), port: socks.port };
  }
  const m = /^(?:socks5h?:\/\/)?(\[[^\]]+\]|[^:/]+):(\d{1,5})$/.exec(String(socks));
  if (!m) throw new TypeError('gateway.socks must be "host:port" or { host, port }');
  return { host: m[1].replace(/^\[|\]$/g, ''), port: Number(m[2]) };
}

/** Does `host:port` match one of the allow patterns? */
export function destinationAllowed(allow, host, port) {
  const h = String(host).toLowerCase();
  for (const raw of allow) {
    const p = String(raw).toLowerCase();
    if (p === '*' || p === h || p === `${h}:${port}`) return true;
  }
  return false;
}

/**
 * SOCKS5 CONNECT (RFC 1928) with no authentication, destination as a domain name.
 * Resolves with the connected socket, or rejects with an Error carrying `.code`
 * (a GATEWAY_FAIL value).
 */
export function socksConnect(proxy, host, port, { timeoutMs = DEFAULT_CONNECT_TIMEOUT_MS } = {}) {
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

/**
 * @param {object} opts
 * @param {string[]} [opts.allow=[]]  destination patterns; empty = nothing is reachable
 * @param {number} [opts.maxConnections=32]  concurrent gateway sockets per client connection
 * @param {number} [opts.connectTimeoutMs=15000]
 * @param {string|{host:string,port:number}} [opts.socks]  dial through this SOCKS5 proxy (Tor)
 * @param {(line: string) => void} [opts.log]
 */
export function normalizeGateway(opts) {
  if (opts === true) throw new TypeError('createWshServer: gateway needs an explicit allow list (default deny): { allow: ["host:port", ...] }');
  if (!opts || typeof opts !== 'object') return null;
  const allow = opts.allow ?? [];
  if (!Array.isArray(allow) || allow.some((a) => typeof a !== 'string' || !a)) throw new TypeError('gateway.allow must be an array of non-empty strings');
  const maxConnections = opts.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
  if (!Number.isInteger(maxConnections) || maxConnections < 1) throw new TypeError('gateway.maxConnections must be a positive integer');
  return {
    allow: [...allow],
    maxConnections,
    connectTimeoutMs: opts.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
    socks: parseSocks(opts.socks),
  };
}

/**
 * The per-connection half: one instance per client connection, torn down with it.
 * @param {ReturnType<typeof normalizeGateway>} cfg
 * @param {(msg: object) => unknown} send
 * @param {(line: string) => void} log
 */
export function createGatewaySession(cfg, send, log = () => {}) {
  /** @type {Map<number, net.Socket>} */
  const sockets = new Map();
  /** gateway_ids whose connect is still in flight (they count against the cap). */
  const pending = new Set();

  const reply = (m) => { try { return send(m); } catch { return undefined; } };
  const fail = (gatewayId, code, message) => reply(gatewayFail({ gatewayId, code, message }));
  const active = () => sockets.size + pending.size;

  async function openTcp(m) {
    const id = m.gateway_id;
    if (!Number.isInteger(id) || typeof m.host !== 'string' || !Number.isInteger(m.port) || m.port < 1 || m.port > 65535) {
      return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'malformed OpenTcp');
    }
    if (sockets.has(id) || pending.has(id)) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'gateway_id already in use');
    if (!destinationAllowed(cfg.allow, m.host, m.port)) {
      log(`gateway: refused ${m.host}:${m.port} (not on the allow list)`);
      return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'destination not allowed by the gateway policy');
    }
    if (active() >= cfg.maxConnections) return fail(id, GATEWAY_FAIL.QUEUE_FULL, 'too many gateway connections');
    pending.add(id);
    let sock;
    try {
      if (cfg.socks) sock = await socksConnect(cfg.socks, m.host, m.port, { timeoutMs: cfg.connectTimeoutMs });
      else {
        sock = await new Promise((resolve, reject) => {
          const s = net.connect({ host: m.host, port: m.port });
          const t = setTimeout(() => { s.destroy(); const e = new Error('connect timed out'); e.code = GATEWAY_FAIL.TIMEOUT; reject(e); }, cfg.connectTimeoutMs);
          s.once('connect', () => { clearTimeout(t); s.removeAllListeners('error'); resolve(s); });
          s.once('error', (e) => {
            clearTimeout(t);
            const code = e.code === 'ECONNREFUSED' ? GATEWAY_FAIL.CONNECTION_REFUSED : e.code === 'ENOTFOUND' || e.code === 'EAI_AGAIN' ? GATEWAY_FAIL.DNS_FAILED : GATEWAY_FAIL.HOST_UNREACHABLE;
            const err = new Error(e.code === 'ENOTFOUND' ? 'name not found' : e.message);
            err.code = code;
            reject(err);
          });
        });
      }
    } catch (e) {
      pending.delete(id);
      return fail(id, typeof e.code === 'number' ? e.code : GATEWAY_FAIL.HOST_UNREACHABLE, String(e.message).slice(0, 200));
    }
    pending.delete(id);
    sockets.set(id, sock);
    sock.setNoDelay(true);
    sock.on('data', (d) => { void reply(gatewayData({ gatewayId: id, data: new Uint8Array(d.buffer, d.byteOffset, d.length) })); });
    sock.on('error', (e) => log(`gateway ${id}: ${e.message}`));
    sock.on('close', () => {
      if (sockets.get(id) === sock) { sockets.delete(id); void reply(gatewayClose({ gatewayId: id })); }
    });
    log(`gateway: ${id} -> ${m.host}:${m.port}${cfg.socks ? ' (via SOCKS5)' : ''}`);
    return reply(gatewayOk({ gatewayId: id }));
  }

  async function resolveDns(m) {
    const id = m.gateway_id;
    if (cfg.socks) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'names are resolved by the SOCKS proxy; this gateway does not look them up');
    if (typeof m.name !== 'string' || !m.name) return fail(id, GATEWAY_FAIL.DNS_FAILED, 'malformed ResolveDns');
    // Only names the client could also connect to: the allow list is about hosts, not ports, here.
    const hostAllowed = cfg.allow.some((a) => { const p = a.toLowerCase(); return p === '*' || p === m.name.toLowerCase() || p.startsWith(`${m.name.toLowerCase()}:`); });
    if (!hostAllowed) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'destination not allowed by the gateway policy');
    try {
      const family = m.record_type === 'AAAA' ? 6 : m.record_type === 'A' || m.record_type === undefined ? 4 : 0;
      if (!family) return fail(id, GATEWAY_FAIL.DNS_FAILED, `unsupported record type ${String(m.record_type).slice(0, 8)}`);
      const addresses = (await dns.lookup(m.name, { family, all: true })).map((a) => a.address);
      return reply(dnsResult({ gatewayId: id, addresses }));
    } catch (e) {
      return fail(id, GATEWAY_FAIL.DNS_FAILED, String(e.code === 'ENOTFOUND' ? 'name not found' : e.message).slice(0, 200));
    }
  }

  return {
    /** @returns {Promise<boolean>} true when the message was a gateway message this session consumed */
    async handle(m) {
      switch (m.type) {
        case MSG.OPEN_TCP: await openTcp(m); return true;
        case MSG.OPEN_UDP: fail(m.gateway_id, GATEWAY_FAIL.POLICY_DENIED, 'UDP is not supported by this gateway'); return true;
        case MSG.RESOLVE_DNS: await resolveDns(m); return true;
        case MSG.GATEWAY_DATA: {
          const s = sockets.get(m.gateway_id);
          const d = m.data;
          if (s && d && d.length <= MAX_DATA_BYTES) s.write(Buffer.from(d.buffer, d.byteOffset, d.length));
          return true;
        }
        case MSG.GATEWAY_CLOSE: {
          const s = sockets.get(m.gateway_id);
          if (s) { s.end(); setTimeout(() => s.destroy(), 1000).unref(); } // its 'close' event deletes it and acknowledges
          return true;
        }
        case MSG.LISTEN_REQUEST: reply(listenFail({ listenerId: m.listener_id, reason: 'reverse tunnels are not supported by this gateway' })); return true;
        case MSG.LISTEN_CLOSE: return true;
        default: return false;
      }
    },
    close() {
      for (const s of sockets.values()) s.destroy();
      sockets.clear();
    },
    get size() { return sockets.size; },
  };
}
