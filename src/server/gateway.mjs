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
 * The pattern is matched against the NAME the client asked for, case-insensitively, and then the ADDRESS it resolves
 * to is checked as well: the host resolves the name once, refuses every address that is not globally routable
 * (loopback, private, link-local, CGNAT, ULA, multicast, reserved, and IPv4 wrapped in IPv6 as mapped, NAT64 or 6to4
 * forms) unless a rule says otherwise, and connects to that same address. Rules that say otherwise: `allowPrivate`
 * (CIDR blocks or addresses the host may dial although they are not public) and an allow entry that is itself an IP
 * literal (`"127.0.0.1:1883"`), which permits exactly that address. `ResolveDns` answers are filtered the same way.
 * With `socks` set the name is handed to the proxy unresolved, so the host never looks it up (and cannot check what it
 * resolves to; IP literals are still checked).
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

import { MSG, gatewayOk, gatewayFail, gatewayClose, gatewayData, dnsResult, listenFail } from '../messages.gen.mjs';
import { isPublicAddress, parseCidr, addressInCidr, parseIp, sameAddress } from './address-guard.mjs';

// Loaded on first use so that importing the connection handler (which serves the gateway opcodes)
// does not pull `node:net` into a browser bundle (see `src/memory-host.mjs`).
let netModule = null;
let dnsModule = null;
const loadNet = async () => (netModule ??= (await import('node:net')).default);
const loadDns = async () => (dnsModule ??= (await import('node:dns/promises')).default);

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
 * The name rule: does any allow entry match, and does a matching entry name the requested host as an IP literal
 * (`explicit`: that entry is then allowed to reach exactly that address even if it is not public)?
 */
function nameDecision(allow, host, port) {
  const h = String(host).toLowerCase();
  let allowed = false;
  let explicit = false;
  for (const raw of allow) {
    const p = String(raw).toLowerCase();
    if (p === '*') allowed = true;
    else if (p === h || p === `${h}:${port}`) { allowed = true; if (parseIp(h)) explicit = true; }
  }
  return { allowed, explicit };
}

/**
 * May the host dial this resolved address? Public addresses, addresses in `allowPrivate`, and the literal address of
 * an explicit IP rule.
 * @param {{ allowPrivate: Array<object> }} cfg
 */
export function addressPermitted(cfg, address, { explicitLiteral = null } = {}) {
  if (explicitLiteral && sameAddress(address, explicitLiteral)) return true;
  if (isPublicAddress(address)) return true;
  return cfg.allowPrivate.some((c) => addressInCidr(address, c));
}

/**
 * SOCKS5 CONNECT (RFC 1928) with no authentication, destination as a domain name.
 * Resolves with the connected socket, or rejects with an Error carrying `.code`
 * (a GATEWAY_FAIL value).
 */
export async function socksConnect(proxy, host, port, { timeoutMs = DEFAULT_CONNECT_TIMEOUT_MS } = {}) {
  const net = await loadNet();
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

const connectError = (e) => {
  const code = e.code === 'ECONNREFUSED' ? GATEWAY_FAIL.CONNECTION_REFUSED : e.code === 'ENOTFOUND' || e.code === 'EAI_AGAIN' ? GATEWAY_FAIL.DNS_FAILED : GATEWAY_FAIL.HOST_UNREACHABLE;
  const err = new Error(e.code === 'ENOTFOUND' ? 'name not found' : e.message);
  err.code = code;
  return err;
};

/**
 * Connect to ONE address (no name lookup happens: the caller already resolved and checked it).
 * @returns {Promise<import('node:net').Socket>}
 */
async function connectAddress(address, port, timeoutMs) {
  const net = await loadNet();
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: address, port });
    const t = setTimeout(() => { s.destroy(); const e = new Error('connect timed out'); e.code = GATEWAY_FAIL.TIMEOUT; reject(e); }, timeoutMs);
    s.once('connect', () => { clearTimeout(t); s.removeAllListeners('error'); resolve(s); });
    s.once('error', (e) => { clearTimeout(t); reject(connectError(e)); });
  });
}

/**
 * Resolve `host` ONCE and return only the addresses `cfg` permits (an empty answer after filtering is POLICY_DENIED).
 * Everything that then connects does so to one of these addresses, never to the name.
 * @returns {Promise<string[]>}
 */
export async function resolveChecked(cfg, host, explicitLiteral, timeoutMs = cfg.connectTimeoutMs) {
  const dns = await loadDns();
  let found;
  try {
    found = await Promise.race([
      dns.lookup(host, { all: true, verbatim: true }),
      new Promise((_, rej) => { const t = setTimeout(() => { const e = new Error('name lookup timed out'); e.code = GATEWAY_FAIL.TIMEOUT; rej(e); }, timeoutMs); t.unref?.(); }),
    ]);
  } catch (e) { throw typeof e.code === 'number' ? e : connectError(e); }
  const addresses = found.map((a) => a.address);
  const usable = addresses.filter((a) => addressPermitted(cfg, a, { explicitLiteral }));
  if (usable.length === 0) {
    const e = new Error('the address this name resolves to is not permitted by the gateway policy');
    e.code = GATEWAY_FAIL.POLICY_DENIED;
    e.refusedAddresses = addresses;
    throw e;
  }
  return usable;
}

/**
 * Resolve `host` once, keep only the addresses `cfg` permits, and connect to the first that answers. A refusal of
 * every address is POLICY_DENIED; the connect uses the address that was checked, never the name.
 * @returns {Promise<{ sock: import('node:net').Socket, address: string }>}
 */
export async function dialChecked(cfg, host, port, explicitLiteral, timeoutMs = cfg.connectTimeoutMs) {
  const deadline = Date.now() + timeoutMs;
  const usable = await resolveChecked(cfg, host, explicitLiteral, timeoutMs);
  let last;
  for (const address of usable) {
    const left = deadline - Date.now();
    if (left <= 0) break;
    try { return { sock: await connectAddress(address, port, left), address }; } catch (e) { last = e; }
  }
  throw last ?? Object.assign(new Error('connect timed out'), { code: GATEWAY_FAIL.TIMEOUT });
}

/**
 * @param {object} opts
 * @param {string[]} [opts.allow=[]]  destination patterns; empty = nothing is reachable
 * @param {string[]} [opts.allowPrivate=[]]  CIDR blocks or addresses (`"10.0.0.0/8"`, `"127.0.0.1"`, `"fd00::/8"`) the host may dial even though they are not globally routable
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
  const privateRules = opts.allowPrivate ?? [];
  if (!Array.isArray(privateRules)) throw new TypeError('gateway.allowPrivate must be an array of CIDR blocks or addresses');
  const allowPrivate = privateRules.map((r) => {
    const c = parseCidr(r);
    if (!c) throw new TypeError(`gateway.allowPrivate: ${JSON.stringify(r)} is not an address or CIDR block`);
    return c;
  });
  const maxConnections = opts.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
  if (!Number.isInteger(maxConnections) || maxConnections < 1) throw new TypeError('gateway.maxConnections must be a positive integer');
  return {
    allow: [...allow],
    allowPrivate,
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
    const decision = nameDecision(cfg.allow, m.host, m.port);
    if (!decision.allowed) {
      log(`gateway: refused ${m.host}:${m.port} (not on the allow list)`);
      return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'destination not allowed by the gateway policy');
    }
    if (active() >= cfg.maxConnections) return fail(id, GATEWAY_FAIL.QUEUE_FULL, 'too many gateway connections');
    pending.add(id);
    let sock;
    let resolvedAddr;
    try {
      if (cfg.socks) {
        // The proxy resolves the name, so only an IP literal can be checked here.
        if (parseIp(m.host) && !addressPermitted(cfg, m.host, { explicitLiteral: decision.explicit ? m.host : null })) {
          const e = new Error('the address is not permitted by the gateway policy');
          e.code = GATEWAY_FAIL.POLICY_DENIED;
          throw e;
        }
        sock = await socksConnect(cfg.socks, m.host, m.port, { timeoutMs: cfg.connectTimeoutMs });
      } else {
        ({ sock, address: resolvedAddr } = await dialChecked(cfg, m.host, m.port, decision.explicit ? m.host : null));
      }
    } catch (e) {
      pending.delete(id);
      if (e.code === GATEWAY_FAIL.POLICY_DENIED) log(`gateway: refused ${m.host}:${m.port} (${e.message})`);
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
    log(`gateway: ${id} -> ${m.host}:${m.port}${resolvedAddr && resolvedAddr !== m.host ? ` (${resolvedAddr})` : ''}${cfg.socks ? ' (via SOCKS5)' : ''}`);
    return reply(gatewayOk({ gatewayId: id, resolvedAddr }));
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
      const all = (await (await loadDns()).lookup(m.name, { family, all: true, verbatim: true })).map((a) => a.address);
      // An answer a client could not connect to is not handed out either: it would only be a way to learn the
      // host's internal addresses, and a later OpenTcp to it has to pass the same check.
      const lit = parseIp(m.name) ? m.name : null;
      const addresses = all.filter((a) => addressPermitted(cfg, a, { explicitLiteral: lit }));
      if (all.length && !addresses.length) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'the addresses this name resolves to are not permitted by the gateway policy');
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
