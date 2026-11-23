/**
 * Gateway for the Node server: the TCP and DNS half of the wire protocol's gateway opcodes (0x70-0x7f), which until
 * now only the Rust `wsh-server` answered, plus unix-domain socket forwarding (`OpenUnix`, `ListenUnix`) and named
 * virtual endpoints (`OpenEndpoint`). It lets an authenticated client (typically a browser tab running
 * `GatewayBackend` from `@johnhenry/browsermesh-netway`) open TCP connections and resolve names FROM THE HOST, so a
 * page can reach a plain-TCP service (an MQTT broker, a database) that a browser cannot.
 *
 * Off unless `createWshServer({ gateway })` is given, and then default-deny: a destination must match `allow`.
 * Pattern forms (the same as the Rust policy): `"*"` any host and port, `"host"` that name on any port,
 * `"host:port"`. The pattern is matched against the NAME the client asked for, case-insensitively, and then the
 * ADDRESS it resolves to is checked as well: the host resolves the name once, refuses every address that is not
 * globally routable (loopback, private, link-local, CGNAT, ULA, multicast, reserved, and IPv4 wrapped in IPv6 as
 * mapped, NAT64 or 6to4 forms) unless a rule says otherwise, and connects to that same address, so a name that
 * resolves differently a moment later cannot redirect the connection. Rules that say otherwise: `allowPrivate`
 * (CIDR blocks or addresses the host may dial even though they are not public), and an allow entry that is itself
 * an IP literal (`"127.0.0.1:1883"`), which permits exactly that address. `ResolveDns` answers are filtered with
 * the same rule. With `socks` set the name is handed to the proxy unresolved, so the host never looks it up and
 * cannot check what it resolves to (the proxy's network is then the egress); IP literals are still checked.
 *
 * Flow control: with "gateway-credit" negotiated each direction of each connection is metered (see
 * `src/gateway-channel.mjs`); with an older peer the host bounds its buffering by `maxBufferedBytes` per connection
 * and `maxClientBufferedBytes` per client and closes a connection that exceeds them.
 *
 * `OpenUdp` flows go to ONE destination chosen at open (same destination policy as TCP, resolved-address check
 * included; replies are accepted only from that address and port, the socket is `connect()`ed to it). Over a
 * WebSocket (or any peer without "gateway-datagram") one GatewayData is one datagram on the reliable control stream; over
 * WebTransport, when both ends list "gateway-datagram", the payloads are WebTransport datagrams with a 4-byte flow-id
 * header (`src/gateway-datagram.mjs`), so loss on one flow delays no other and nothing is retransmitted. Bounds
 * (`udp: {...}`): flows per client, packets per second per flow and per client, bytes per second per client, idle flows
 * closed after `udpIdleMs`; a payload bigger than the datagram limit goes on the reliable stream (or is dropped, by `udp.oversize`).
 *
 * `reverse: {...}` (off unless given): TCP reverse tunnels (`ListenRequest`), see `reverse-policy.mjs`.
 *
 * `socks`: dial through a SOCKS5 proxy (`'host:port'`, `socks5://host:port` or `{ host, port }`), e.g. a local Tor
 * client (`127.0.0.1:9050`). Commands carry the destination as a domain name (ATYP 3), so name resolution happens at
 * the proxy (no DNS leak) and `.onion` names work. In that mode `ResolveDns` is refused.
 *
 * `unix: { connect, listen, replaceStale }` (Node only): sockets in the host's file system a client may connect to
 * or create. Off unless given. See `unix-policy.mjs`. `endpoints: { name: handler }`: named virtual endpoints.
 */

import { MSG, gatewayOk, dnsResult, listenOk, listenFail, inboundOpen } from '../messages.gen.mjs';
import {
  GATEWAY_FAIL, HALF_CLOSE_GRACE_MS, gatewayFeatures, createGatewayCore, normalizeGatewayLimits, normalizeEndpoints,
} from './gateway-core.mjs';
import { isPublicAddress, parseCidr, addressInCidr, parseIp, sameAddress } from './address-guard.mjs';
import { normalizeReverse, reversePortAllowed, reversePortRefusal, reverseBindAddress } from './reverse-policy.mjs';
import { normalizeUdp, newGatewayStats } from './udp-policy.mjs';
import { TokenBucket, encodeDatagram, decodeDatagram, MAX_UDP_PAYLOAD, GATEWAY_DATAGRAM_FEATURE } from '../gateway-datagram.mjs';

export { normalizeReverse, reversePortAllowed } from './reverse-policy.mjs';
export { normalizeUdp } from './udp-policy.mjs';

// Loaded on first use so that importing the connection handler (which serves the gateway opcodes)
// does not pull `node:net` into a browser bundle (see `src/memory-host.mjs`).
let netModule = null;
let dnsModule = null;
let unixModule = null;
const loadNet = async () => (netModule ??= (await import('node:net')).default);
const loadDns = async () => (dnsModule ??= (await import('node:dns/promises')).default);
const loadUnix = async () => (unixModule ??= await import('./unix-policy.mjs'));

export { GATEWAY_FAIL, gatewayFeatures };

const DEFAULT_CONNECT_TIMEOUT_MS = 15_000;
const MAX_PENDING_INBOUND = 16;
const INBOUND_ACCEPT_TIMEOUT_MS = 30_000;
const DEFAULT_UDP_IDLE_MS = 60_000;
const MAX_DATAGRAM = MAX_UDP_PAYLOAD;
const UDP_OUTBOX_BYTES = 256 * 1024;

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

/** Does `host:port` match one of the allow patterns? (The NAME check only; see `addressPermitted` for the address.) */
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
 * @param {number} [opts.maxBufferedBytes=4194304]  bytes received from a client for one connection and not yet taken by its origin
 * @param {number} [opts.maxClientBufferedBytes=33554432]  the same, summed over one client's connections
 * @param {string|{host:string,port:number}} [opts.socks]  dial through this SOCKS5 proxy (Tor)
 * @param {{ connect?: string[], listen?: string[], replaceStale?: boolean, maxListeners?: number }} [opts.unix]  unix-domain sockets (see unix-policy.mjs)
 * @param {boolean | object} [opts.reverse]  TCP reverse tunnels, off unless given (see reverse-policy.mjs)
 * @param {object} [opts.udp]  UDP bounds (see udp-policy.mjs)
 * @param {Record<string, Function | { open: Function, authorize?: Function }>} [opts.endpoints]  named virtual endpoints
 * @param {boolean} [opts.tcp=true]  false: no TCP or DNS at all (an endpoints-only host such as the memory host)
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
  const { maxConnections, maxBufferedBytes, maxClientBufferedBytes } = normalizeGatewayLimits(opts);
  let unix = null;
  if (opts.unix !== undefined && opts.unix !== null && opts.unix !== false) {
    if (opts.unix === true || typeof opts.unix !== 'object') throw new TypeError('gateway.unix needs explicit paths (default deny): { connect: [...], listen: [...] }');
    // The policy module touches the file system; validate its shape here without loading `node:fs`.
    unix = normalizeUnixShape(opts.unix);
  }
  const endpoints = normalizeEndpoints(opts.endpoints);
  return {
    allow: [...allow],
    allowPrivate,
    maxConnections,
    maxBufferedBytes,
    maxClientBufferedBytes,
    connectTimeoutMs: opts.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
    udpIdleMs: opts.udpIdleMs ?? DEFAULT_UDP_IDLE_MS,
    udp: normalizeUdp(opts.udp),
    reverse: normalizeReverse(opts.reverse),
    stats: newGatewayStats(),
    socks: parseSocks(opts.socks),
    tcp: opts.tcp !== false,
    unix,
    endpoints,
  };
}

/** The shape check of `normalizeUnixPolicy`, without importing it (it needs `node:fs`). */
function normalizeUnixShape(u) {
  const list = (v, what) => {
    if (v === undefined) return [];
    if (!Array.isArray(v) || v.some((p) => typeof p !== 'string' || !p)) throw new TypeError(`gateway.unix.${what} must be an array of non-empty strings`);
    for (const p of v) {
      if (p.includes('\0') || p.length > 4096) throw new TypeError(`gateway.unix.${what}: bad pattern ${JSON.stringify(p.slice(0, 80))}`);
      if (!p.startsWith('/') && !p.startsWith('@')) throw new TypeError(`gateway.unix.${what}: ${JSON.stringify(p)} must be an absolute path or an abstract name starting with "@"`);
      if (p === '/' || p === '@' || p === '@/') throw new TypeError(`gateway.unix.${what}: ${JSON.stringify(p)} would allow everything; list a specific path or directory`);
      if (p.split('/').includes('..')) throw new TypeError(`gateway.unix.${what}: ${JSON.stringify(p)} must not contain ".."`);
    }
    return [...v];
  };
  const maxListeners = u.maxListeners ?? 4;
  if (!Number.isInteger(maxListeners) || maxListeners < 0) throw new TypeError('gateway.unix.maxListeners must be a non-negative integer');
  return { connect: list(u.connect, 'connect'), listen: list(u.listen, 'listen'), replaceStale: u.replaceStale === true, maxListeners };
}

/**
 * The per-connection half: one instance per client connection, torn down with it.
 * @param {ReturnType<typeof normalizeGateway>} cfg
 * @param {(msg: object) => unknown} send
 * @param {(line: string) => void} log
 * @param {{ who?: () => { username: string | null, fingerprint: string | null } }} [ctx]
 */
export function createGatewaySession(cfg, send, log = () => {}, ctx = {}) {
  // The connection table, credit negotiation, the per-client budget and the endpoint opcodes are the browser-safe core.
  const core = createGatewayCore(cfg, send, log, ctx);
  const { conns, pending, reply, fail, active, idInUse, makeChannel } = core;
  /** @type {Map<number, { server: import('node:net').Server, path: string, abstract: boolean, stat: any, pendingChannels: Set<number> }>} */
  const listeners = new Map();
  const pendingListeners = new Set();
  /** Accepted inbound sockets waiting for InboundAccept: channel_id -> { sock, listenerId, timer }. */
  const inbound = new Map();
  let nextInbound = 0;
  let closed = false;
  const failListen = (listenerId, reason) => reply(listenFail({ listenerId, reason }));

  /** Attach a connected socket (TCP or unix) as gateway connection `id`. */
  function attachSocket(id, sock) {
    sock.setNoDelay?.(true);
    let tail = Promise.resolve();
    let graceTimer = null;
    const channel = makeChannel(id, {
      writeAfterRemoteClose: true,
      graceMs: HALF_CLOSE_GRACE_MS,
      onData: (bytes) => { sock.write(bytes, () => channel.consumed(bytes.byteLength)); },
      onRemoteClose: () => { sock.end(); graceTimer = setTimeout(() => sock.destroy(), HALF_CLOSE_GRACE_MS); graceTimer.unref?.(); },
      onClose: () => { clearTimeout(graceTimer); sock.destroy(); },
    });
    conns.set(id, { channel, sock });
    // Origin -> client: one chunk at a time. The socket is paused until the channel has taken the chunk (it waits for
    // credit and for the transport), so a client that stops reading stops the origin instead of filling memory here.
    sock.on('data', (d) => {
      sock.pause();
      tail = channel.write(new Uint8Array(d.buffer, d.byteOffset, d.length)).then(() => { if (!sock.destroyed) sock.resume(); }, () => { sock.destroy(); });
    });
    sock.on('error', (e) => log(`gateway ${id}: ${e.message}`));
    // The origin is gone: say so once everything it sent has gone out, and forget the connection (the client's own
    // GatewayClose, if it sends one, then finds nothing and is ignored).
    sock.on('close', () => { void tail.finally(() => channel.destroy()); });
    return channel;
  }

  async function openTcp(m) {
    const id = m.gateway_id;
    if (!Number.isInteger(id) || typeof m.host !== 'string' || !Number.isInteger(m.port) || m.port < 1 || m.port > 65535) {
      return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'malformed OpenTcp');
    }
    if (idInUse(id)) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'gateway_id already in use');
    if (!cfg.tcp) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'TCP is not enabled on this gateway');
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
        const lit = parseIp(m.host);
        if (lit && !addressPermitted(cfg, m.host, { explicitLiteral: decision.explicit ? m.host : null })) {
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
    if (closed) { sock.destroy(); return undefined; }
    attachSocket(id, sock);
    log(`gateway: ${id} -> ${m.host}:${m.port}${resolvedAddr && resolvedAddr !== m.host ? ` (${resolvedAddr})` : ''}${cfg.socks ? ' (via SOCKS5)' : ''}`);
    return reply(gatewayOk({ gatewayId: id, resolvedAddr }));
  }

  async function resolveDns(m) {
    const id = m.gateway_id;
    if (!cfg.tcp) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'DNS is not enabled on this gateway');
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

  // ── UDP ──────────────────────────────────────────────────────────
  // A flow is one connect()ed UDP socket: one destination, fixed at OpenUdp, whose address passed the resolved-address
  // policy; the kernel delivers nothing to it from any other address or port, so the host is no relay to arbitrary peers.
  // Payloads travel as WebTransport datagrams when both ends negotiated "gateway-datagram" (no retransmission, no
  // head-of-line blocking between flows), else one GatewayData per datagram on the reliable control stream. Both
  // directions are rate-limited (token buckets: per flow, per client, and bytes per client) and a datagram over a limit
  // is dropped and counted, as a congested network would. What a client cannot take fast enough is dropped, never buffered.

  const udpCfg = cfg.udp;
  const stats = cfg.stats.udp;
  const clientPackets = new TokenBucket(udpCfg.packetsPerSecondPerClient, Math.max(udpCfg.packetsPerSecondPerClient / 4, 32));
  const clientBytes = new TokenBucket(udpCfg.bytesPerSecondPerClient, Math.max(udpCfg.bytesPerSecondPerClient / 4, 65536));
  /** gateway_id -> handler for a datagram that arrived for the flow. */
  const udpFlows = new Map();
  const udpPending = new Set();
  let peerDatagrams = false;
  const datagramsOn = () => peerDatagrams && udpCfg.datagrams && !!ctx.datagrams;

  async function openUdp(m) {
    const id = m.gateway_id;
    if (!Number.isInteger(id) || typeof m.host !== 'string' || !Number.isInteger(m.port) || m.port < 1 || m.port > 65535) {
      return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'malformed OpenUdp');
    }
    if (idInUse(id)) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'gateway_id already in use');
    if (!cfg.tcp) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'UDP is not enabled on this gateway');
    if (cfg.socks) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'UDP is not available through a SOCKS proxy');
    const decision = nameDecision(cfg.allow, m.host, m.port);
    if (!decision.allowed) {
      log(`gateway: refused udp ${m.host}:${m.port} (not on the allow list)`);
      return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'destination not allowed by the gateway policy');
    }
    if (udpFlows.size + udpPending.size >= udpCfg.maxFlows) return fail(id, GATEWAY_FAIL.QUEUE_FULL, `too many UDP flows (limit ${udpCfg.maxFlows})`);
    if (active() >= cfg.maxConnections) return fail(id, GATEWAY_FAIL.QUEUE_FULL, 'too many gateway connections');
    udpPending.add(id);
    pending.add(id);
    let sock;
    let address;
    try {
      address = (await resolveChecked(cfg, m.host, decision.explicit ? m.host : null))[0];
      const dgram = (await import('node:dgram')).default;
      sock = dgram.createSocket(address.includes(':') ? 'udp6' : 'udp4');
      await new Promise((resolve, reject) => { sock.once('error', reject); sock.connect(m.port, address, () => { sock.off('error', reject); resolve(); }); });
    } catch (e) {
      pending.delete(id); udpPending.delete(id);
      try { sock?.close(); } catch { /* not open */ }
      if (e.code === GATEWAY_FAIL.POLICY_DENIED) log(`gateway: refused udp ${m.host}:${m.port} (${e.message})`);
      return fail(id, typeof e.code === 'number' ? e.code : GATEWAY_FAIL.HOST_UNREACHABLE, String(e.message).slice(0, 200));
    }
    pending.delete(id); udpPending.delete(id);
    if (closed) { sock.close(); return undefined; }
    attachDatagrams(id, sock);
    stats.flowsOpened++;
    log(`gateway: ${id} -> udp ${m.host}:${m.port}${address !== m.host ? ` (${address})` : ''}${datagramsOn() ? ' (datagrams)' : ''} (local port ${sock.address().port})`);
    return reply(gatewayOk({ gatewayId: id, resolvedAddr: address }));
  }

  function attachDatagrams(id, sock) {
    let idle = null;
    const touch = () => { clearTimeout(idle); idle = setTimeout(() => channel.destroy('idle timeout'), cfg.udpIdleMs); idle.unref?.(); };
    const flowPackets = new TokenBucket(udpCfg.packetsPerSecondPerFlow, Math.max(udpCfg.packetsPerSecondPerFlow / 4, 16));
    const useDatagrams = datagramsOn();
    /** All three buckets must have room; a datagram over any limit is dropped. */
    const admit = (n) => {
      if (flowPackets.take(1) && clientPackets.take(1) && clientBytes.take(n)) return true;
      stats.rateDropped++;
      return false;
    };
    const outbox = [];
    let outboxBytes = 0;
    let pumping = false;
    const channel = makeChannel(id, {
      onData: (bytes) => { // a payload on the reliable stream (the only path without datagrams; the oversize path with them)
        touch();
        if (bytes.byteLength > MAX_DATAGRAM || !admit(bytes.byteLength)) { channel.consumed(bytes.byteLength); return; }
        stats.reliableFromClient++;
        sock.send(bytes, () => channel.consumed(bytes.byteLength));
      },
      onRemoteClose: () => channel.destroy(), // UDP has no half-close
      onClose: () => { clearTimeout(idle); udpFlows.delete(id); try { sock.close(); } catch { /* closed */ } },
    });
    conns.set(id, { channel, sock: null });
    udpFlows.set(id, (payload) => { // a datagram from the client
      touch();
      if (payload.byteLength > MAX_DATAGRAM || !admit(payload.byteLength)) return;
      stats.datagramsFromClient++;
      sock.send(payload);
    });
    async function pump() {
      if (pumping) return;
      pumping = true;
      try {
        while (outbox.length && !channel.closed) {
          const d = outbox.shift();
          outboxBytes -= d.length;
          await channel.write(new Uint8Array(d.buffer, d.byteOffset, d.length));
        }
      } catch { /* closed while writing */ } finally { pumping = false; }
    }
    sock.on('message', (d) => {
      touch();
      if (!admit(d.length)) return;
      if (useDatagrams) {
        const frame = encodeDatagram(id, d);
        if (frame.length <= ctx.datagrams.maxSize()) {
          if (ctx.datagrams.send(frame)) stats.datagramsToClient++; else stats.backpressureDropped++;
          return;
        }
        if (udpCfg.oversize === 'drop') { stats.oversizeDropped++; log(`gateway ${id}: dropped a ${d.length}-byte reply that does not fit a datagram (${ctx.datagrams.maxSize() - 4} bytes)`); return; }
        stats.oversizeReliable++;
      }
      if (outboxBytes + d.length > UDP_OUTBOX_BYTES) return; // the client is not keeping up: drop, as a network would
      stats.reliableToClient++;
      outbox.push(d); outboxBytes += d.length;
      void pump();
    });
    sock.on('error', (e) => log(`gateway ${id}: ${e.message}`));
    touch();
  }

  // ── unix sockets ─────────────────────────────────────────────────

  async function openUnix(m) {
    const id = m.gateway_id;
    if (!Number.isInteger(id) || typeof m.path !== 'string') return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'malformed OpenUnix');
    if (idInUse(id)) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'gateway_id already in use');
    if (!cfg.unix || cfg.unix.connect.length === 0) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'unix sockets are not enabled on this gateway');
    if (active() >= cfg.maxConnections) return fail(id, GATEWAY_FAIL.QUEUE_FULL, 'too many gateway connections');
    pending.add(id);
    let sock;
    try {
      const unix = await loadUnix();
      const chk = await unix.checkUnixPath(m.path, cfg.unix.connect);
      if (!chk.ok) {
        log(`gateway: refused unix ${JSON.stringify(m.path.slice(0, 200))} (${chk.reason})`);
        pending.delete(id);
        return fail(id, GATEWAY_FAIL.POLICY_DENIED, chk.reason);
      }
      if (!chk.abstract) {
        const st = await unix.statSocket(chk.path);
        if (!st) { pending.delete(id); return fail(id, GATEWAY_FAIL.CONNECTION_REFUSED, 'no such socket'); }
        if (!st.socket) { pending.delete(id); log(`gateway: refused unix ${chk.path} (not a socket)`); return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'not a socket'); }
      }
      sock = await new Promise((resolve, reject) => {
        loadNet().then((net) => {
          const s = net.connect({ path: chk.path });
          const t = setTimeout(() => { s.destroy(); const e = new Error('connect timed out'); e.code = GATEWAY_FAIL.TIMEOUT; reject(e); }, cfg.connectTimeoutMs);
          s.once('connect', () => { clearTimeout(t); s.removeAllListeners('error'); resolve(s); });
          s.once('error', (e) => { clearTimeout(t); reject(connectError(e)); });
        }, reject);
      });
    } catch (e) {
      pending.delete(id);
      return fail(id, typeof e.code === 'number' ? e.code : GATEWAY_FAIL.HOST_UNREACHABLE, String(e.message).slice(0, 200));
    }
    pending.delete(id);
    if (closed) { sock.destroy(); return undefined; }
    attachSocket(id, sock);
    log(`gateway: ${id} -> unix ${m.path.slice(0, 200)}`);
    return reply(gatewayOk({ gatewayId: id }));
  }

  async function listenUnix(m) {
    const id = m.listener_id;
    if (!Number.isInteger(id) || typeof m.path !== 'string') return failListen(id, 'malformed ListenUnix');
    if (listeners.has(id) || pendingListeners.has(id)) return failListen(id, 'listener_id already in use');
    if (!cfg.unix || cfg.unix.listen.length === 0) return failListen(id, 'unix listeners are not enabled on this gateway');
    if (listeners.size + pendingListeners.size >= cfg.unix.maxListeners) return failListen(id, 'too many unix listeners');
    pendingListeners.add(id);
    let server;
    try {
      const unix = await loadUnix();
      const net = await loadNet();
      const chk = await unix.checkUnixPath(m.path, cfg.unix.listen);
      if (!chk.ok) { log(`gateway: refused unix listen ${JSON.stringify(m.path.slice(0, 200))} (${chk.reason})`); return await failListen(id, chk.reason); }
      if (!chk.abstract) {
        const st = await unix.statSocket(chk.path);
        if (st) {
          if (!st.socket) return await failListen(id, 'a file that is not a socket is in the way');
          if (m.replace !== true) return await failListen(id, 'address in use (a socket file exists; ask to replace it)');
          if (!cfg.unix.replaceStale) return await failListen(id, 'replacing an existing socket is not allowed by the gateway policy');
          // Only a stale socket: one nothing accepts connections on.
          const live = await new Promise((resolve) => {
            const probe = net.connect({ path: chk.path });
            probe.once('connect', () => { probe.destroy(); resolve(true); });
            probe.once('error', (e) => resolve(e.code !== 'ECONNREFUSED' && e.code !== 'ENOENT'));
          });
          if (live) return await failListen(id, 'address in use (the existing socket is live)');
          await unix.unlinkIfSocket(chk.path, st);
        }
      }
      if (closed) return undefined;
      server = net.createServer();
      // Created private from the first instant: the mode of a socket is its umask at bind time.
      const oldMask = (() => { try { return process.umask(0o177); } catch { return null; } })();
      try {
        await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ path: chk.path }, () => { server.off('error', reject); resolve(); }); });
      } finally { if (oldMask !== null) { try { process.umask(oldMask); } catch { /* gone */ } } }
      let stat = null;
      if (!chk.abstract) {
        const fsp = (await import('node:fs/promises')).default;
        await fsp.chmod(chk.path, 0o600);
        stat = await unix.statSocket(chk.path);
      }
      if (closed) { server.close(); if (stat) await unix.unlinkIfSocket(chk.path, stat); return undefined; }
      const entry = { server, kind: 'unix', path: chk.path, abstract: chk.abstract, stat, pendingChannels: new Set(), open: 0 };
      listeners.set(id, entry);
      server.on('connection', (sock) => onInbound(id, entry, sock));
      server.on('error', (e) => log(`gateway listener ${id}: ${e.message}`));
      log(`gateway: listening on unix ${m.path.slice(0, 200)} (listener ${id})`);
      return await reply(listenOk({ listenerId: id, actualPort: 0 }));
    } catch (e) {
      try { server?.close(); } catch { /* not listening */ }
      return failListen(id, e.code === 'EADDRINUSE' ? 'address in use' : String(e.message).slice(0, 200));
    } finally {
      pendingListeners.delete(id);
    }
  }

  // ── TCP reverse tunnels ──────────────────────────────────────────

  async function listenTcp(m) {
    const id = m.listener_id;
    if (!Number.isInteger(id) || !Number.isInteger(m.port) || m.port < 0 || m.port > 65535) return failListen(id, 'malformed ListenRequest');
    if (!cfg.reverse) return failListen(id, 'reverse tunnels are not enabled on this gateway');
    if (listeners.has(id) || pendingListeners.has(id)) return failListen(id, 'listener_id already in use');
    const rev = cfg.reverse;
    if (!reversePortAllowed(rev, m.port)) { log(`gateway: refused reverse listen on port ${m.port} (port policy)`); return failListen(id, reversePortRefusal(rev, m.port)); }
    let tcpCount = pendingListeners.size;
    for (const l of listeners.values()) if (l.kind === 'tcp') tcpCount++;
    if (tcpCount >= rev.maxListeners) return failListen(id, `too many reverse listeners (limit ${rev.maxListeners})`);
    pendingListeners.add(id);
    let server;
    try {
      const net = await loadNet();
      const host = reverseBindAddress(rev, m.bind_addr);
      if (host !== m.bind_addr) log(`gateway: reverse listen: ignoring the client's bind address ${JSON.stringify(String(m.bind_addr).slice(0, 64))}, binding ${host}`);
      server = net.createServer();
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ port: m.port, host, backlog: rev.backlog }, () => { server.off('error', reject); resolve(); }); });
      if (closed) { server.close(); return undefined; }
      const addr = server.address();
      const entry = { server, kind: 'tcp', path: '', abstract: false, stat: null, pendingChannels: new Set(), open: 0 };
      listeners.set(id, entry);
      server.on('connection', (sock) => onInbound(id, entry, sock));
      server.on('error', (e) => log(`gateway listener ${id}: ${e.message}`));
      cfg.stats.reverse.listeners++;
      log(`gateway: listening on ${host}:${addr.port} (reverse listener ${id})`);
      return await reply(listenOk({ listenerId: id, actualPort: addr.port }));
    } catch (e) {
      try { server?.close(); } catch { /* not listening */ }
      return failListen(id, e.code === 'EADDRINUSE' ? 'address in use' : e.code === 'EACCES' ? 'permission denied binding that port' : String(e.message).slice(0, 200));
    } finally {
      pendingListeners.delete(id);
    }
  }

  function onInbound(listenerId, entry, sock) {
    const tcp = entry.kind === 'tcp';
    const refuse = (why) => { if (tcp) cfg.stats.reverse.refusedConnections++; log(`gateway: reverse listener ${listenerId}: dropped a connection (${why})`); sock.destroy(); };
    if (closed || inbound.size >= MAX_PENDING_INBOUND || active() + inbound.size >= cfg.maxConnections) return refuse('too many gateway connections');
    if (tcp && entry.open >= cfg.reverse.maxConnectionsPerListener) return refuse(`listener is at its limit of ${cfg.reverse.maxConnectionsPerListener} connections`);
    sock.pause();
    sock.on('error', () => {});
    const channelId = ++nextInbound;
    const timer = setTimeout(() => { inbound.delete(channelId); entry.pendingChannels.delete(channelId); sock.destroy(); }, INBOUND_ACCEPT_TIMEOUT_MS);
    timer.unref?.();
    if (tcp) { entry.open++; cfg.stats.reverse.accepted++; sock.once('close', () => { entry.open--; }); }
    sock.once('close', () => { if (inbound.get(channelId)?.sock === sock) { clearTimeout(timer); inbound.delete(channelId); entry.pendingChannels.delete(channelId); } });
    inbound.set(channelId, { sock, listenerId, timer });
    entry.pendingChannels.add(channelId);
    void reply(inboundOpen({ listenerId, channelId, peerAddr: tcp ? (sock.remoteAddress ?? '') : 'unix', peerPort: tcp ? (sock.remotePort ?? 0) : 0 }));
  }

  function inboundAccept(m) {
    const p = inbound.get(m.channel_id);
    if (!p) return;
    clearTimeout(p.timer);
    inbound.delete(m.channel_id);
    listeners.get(p.listenerId)?.pendingChannels.delete(m.channel_id);
    const id = m.gateway_id;
    if (!Number.isInteger(id) || idInUse(id) || p.sock.destroyed || active() >= cfg.maxConnections) { p.sock.destroy(); return; }
    attachSocket(id, p.sock);
    const rev = listeners.get(p.listenerId)?.kind === 'tcp' ? cfg.reverse : null;
    if (rev && rev.idleMs > 0) {
      // Inactivity in either direction ends the connection (the socket's own timeout counts reads and writes).
      p.sock.setTimeout(rev.idleMs, () => { cfg.stats.reverse.idleClosed++; log(`gateway: reverse connection ${id} idle for ${rev.idleMs} ms, closing`); p.sock.destroy(); });
    }
    p.sock.resume();
  }

  function inboundReject(m) {
    const p = inbound.get(m.channel_id);
    if (!p) return;
    clearTimeout(p.timer);
    inbound.delete(m.channel_id);
    p.sock.destroy();
  }

  async function closeListener(id) {
    const l = listeners.get(id);
    if (!l) return;
    listeners.delete(id);
    for (const ch of l.pendingChannels) { const p = inbound.get(ch); if (p) { clearTimeout(p.timer); inbound.delete(ch); p.sock.destroy(); } }
    await new Promise((r) => { l.server.close(() => r()); });
    if (l.stat) await (await loadUnix()).unlinkIfSocket(l.path, l.stat);
  }

  return {
    setPeerFeatures: (features) => { core.setPeerFeatures(features); peerDatagrams = Array.isArray(features) && features.includes(GATEWAY_DATAGRAM_FEATURE); },
    /** A WebTransport datagram arrived from the client: [flow id][payload]. */
    handleDatagram(bytes) {
      if (closed) return;
      const d = decodeDatagram(bytes);
      if (!d) { stats.malformed++; return; }
      const flow = datagramsOn() ? udpFlows.get(d.id) : undefined;
      if (!flow) { stats.unknownFlow++; return; }
      flow(d.payload);
    },
    /** @returns {Promise<boolean>} true when the message was a gateway message this session consumed */
    async handle(m) {
      if (closed) return true;
      switch (m.type) {
        case MSG.OPEN_TCP: await openTcp(m); return true;
        case MSG.OPEN_UDP: await openUdp(m); return true;
        case MSG.OPEN_UNIX: await openUnix(m); return true;
        case MSG.RESOLVE_DNS: await resolveDns(m); return true;
        case MSG.LISTEN_REQUEST: await listenTcp(m); return true;
        case MSG.LISTEN_UNIX: await listenUnix(m); return true;
        case MSG.LISTEN_CLOSE: await closeListener(m.listener_id); return true;
        case MSG.INBOUND_ACCEPT: inboundAccept(m); return true;
        case MSG.INBOUND_REJECT: inboundReject(m); return true;
        // OpenEndpoint, GatewayData, GatewayCredit, GatewayClose: the core.
        default: return core.handle(m);
      }
    },
    close() {
      closed = true;
      core.close();
      for (const { sock, timer } of inbound.values()) { clearTimeout(timer); sock.destroy(); }
      inbound.clear();
      for (const id of [...listeners.keys()]) void closeListener(id).catch(() => {});
    },
    get size() { return conns.size; },
    /** Bytes received from the client for its origins and not yet taken by them (what the caps bound). */
    get bufferedBytes() { return core.bufferedBytes; },
    get listenerCount() { return listeners.size; },
  };
}
