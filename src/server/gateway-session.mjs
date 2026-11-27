/**
 * The gateway session: the TCP and DNS half of the wire protocol's gateway opcodes (0x70-0x7f), plus UDP, reverse
 * tunnels, unix-domain socket forwarding (`OpenUnix`, `ListenUnix`) and named virtual endpoints (`OpenEndpoint`). It lets an
 * authenticated client (typically a browser tab running `GatewayBackend` from `@johnhenry/browsermesh-netway`) open TCP
 * connections and resolve names FROM THE HOST, so a page can reach a plain-TCP service (an MQTT broker, a database) that a
 * browser cannot.
 *
 * Which network the host dials is a choice of the embedder (#299). By default it is the machine's: `node:net`, `node:dgram` and
 * `node:dns` through `@johnhenry/wsh/address-guard`, loaded when first needed. `gateway.network` replaces it with a network the
 * embedder supplies (`{ connectTcp, resolve, openUdp, listenTcp }`, web streams for the bytes), and this same session then runs
 * anywhere JavaScript does: nothing in this file imports a Node built-in (the SOCKS5 client and the unix-socket code are loaded by
 * name when used), so a host in a page serves the gateway through `createMemoryHost({ gateway: { network, ... } })`. The destination
 * policy, the connection cap, the credit window, the half-close rules and the UDP bounds are the same code for both: only the way a
 * connection is dialled, and what a connected socket is, differ (see `stream-socket.mjs`).
 *
 * With an injected network the policy is applied by this session BEFORE the network is called, and to the address that is dialled:
 * the network's own `resolve` answers are what is classified, and the address that passes is what `connectTcp` / `openUdp` receive
 * (the name is never handed on, so there is no second lookup); a name the network cannot resolve is refused. The network may have
 * address space of its own (private ranges are normal in a virtual network): they are refused like any non-public address until the
 * embedder names them (`allowPrivate`, or an IP literal in `allow`). wsh cannot vouch for what an injected network reaches.
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
 *
 * `network: { connectTcp, resolve, openUdp, listenTcp }` (#299): the network the host dials instead of the machine's. See `normalizeGateway`.
 */

import { MSG, gatewayOk, dnsResult, listenOk, listenFail, inboundOpen } from '../messages.gen.mjs';
import {
  GATEWAY_FAIL, gatewayFeatures, createGatewayCore, normalizeGatewayLimits, normalizeEndpoints,
} from './gateway-core.mjs';
import { DEFAULT_HALF_CLOSE_PROBE_MS } from '../gateway-channel.mjs';
import { watchHalfClosed } from '../half-close-watch.mjs';
import { parseCidr, parseIp } from './address-guard.mjs';
import { checkAddress, resolveChecked, dialChecked, dialUdpChecked, AddressGuardError } from '../address-guard.mjs';
import { normalizeReverse, reversePortAllowed, reversePortRefusal, reverseBindAddress } from './reverse-policy.mjs';
import { normalizeUdp, newGatewayStats } from './udp-policy.mjs';
import { TokenBucket, encodeDatagram, decodeDatagram, MAX_UDP_PAYLOAD, GATEWAY_DATAGRAM_FEATURE } from '../gateway-datagram.mjs';
import { StreamSocket, DatagramFlow } from './stream-socket.mjs';
import { checkGatewayOptions } from '../gateway-shape.mjs';

export { normalizeReverse, reversePortAllowed } from './reverse-policy.mjs';
export { normalizeUdp } from './udp-policy.mjs';

// Loaded on first use so that importing the connection handler (which serves the gateway opcodes)
// does not pull `node:net` into a browser bundle (see `src/memory-host.mjs`). The specifiers are held in variables so that a bundler
// for a browser, which follows every literal `import('...')`, does not: these modules are used only on the machine's own network.
const NET = 'node:net';
const UNIX_POLICY = './unix-policy.mjs';
const SOCKS = './socks.mjs';
// A Node entry (`server/gateway.mjs`) hands the session LITERAL dynamic imports through `cfg.nodeLoaders`, so that a bundled Node server still includes them
// (a variable specifier is invisible to a bundler); the variable ones below are the fallback of an unbundled run, and are never reached from a browser.
let netModule = null;
let unixModule = null;
let socksModule = null;
const loadNet = async (cfg) => (netModule ??= cfg?.nodeLoaders?.net ? await cfg.nodeLoaders.net() : (await import(NET)).default);
const loadUnix = async (cfg) => (unixModule ??= cfg?.nodeLoaders?.unix ? await cfg.nodeLoaders.unix() : await import(UNIX_POLICY));
const loadSocks = async (cfg) => (socksModule ??= cfg?.nodeLoaders?.socks ? await cfg.nodeLoaders.socks() : await import(SOCKS));

/** The SOCKS5 client (Node only), here so that this module can be imported where there is no `node:net`. */
export async function socksConnect(proxy, host, port, opts) { return (await loadSocks(opts?.cfg)).socksConnect(proxy, host, port, opts); }

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
  return checkAddress(address, gatewayPolicy(cfg, explicitLiteral)).permitted;
}

/**
 * The gateway's destination policy in the terms of `@johnhenry/wsh/address-guard`: `allowPrivate` blocks, plus the literal
 * address of an explicit IP rule, are permitted whatever their class. The resolving, checking and dialling is the guard's.
 */
export function gatewayPolicy(cfg, explicitLiteral = null) {
  return { allow: explicitLiteral ? [...cfg.allowPrivate, explicitLiteral] : cfg.allowPrivate };
}

/** The guard's options for one gateway destination. */
const guardOptions = (cfg, explicitLiteral, extra = {}) => ({ ...gatewayPolicy(cfg, explicitLiteral), timeoutMs: cfg.connectTimeoutMs, ...extra });

/** An error of the guard as the gateway reports it: `.code` is a GATEWAY_FAIL value, the text is what a client has always been told. */
function gatewayError(e) {
  if (!(e instanceof AddressGuardError)) return e;
  const code = {
    ADDRESS_REFUSED: GATEWAY_FAIL.POLICY_DENIED,
    NAME_NOT_FOUND: GATEWAY_FAIL.DNS_FAILED,
    CONNECTION_REFUSED: GATEWAY_FAIL.CONNECTION_REFUSED,
    TIMEOUT: GATEWAY_FAIL.TIMEOUT,
    LOOKUP_FAILED: e.cause?.code === 'EAI_AGAIN' ? GATEWAY_FAIL.DNS_FAILED : GATEWAY_FAIL.HOST_UNREACHABLE,
  }[e.code] ?? GATEWAY_FAIL.HOST_UNREACHABLE;
  const err = new Error(e.code === 'ADDRESS_REFUSED' ? 'the address this name resolves to is not permitted by the gateway policy' : e.message);
  err.code = code;
  if (e.refusedAddresses) err.refusedAddresses = e.refusedAddresses;
  return err;
}

/** An error of an injected network as the gateway reports it: `.code` becomes a GATEWAY_FAIL value, whatever the network used (a number of the table, or a name like Node's). */
function networkError(e) {
  if (e instanceof AddressGuardError) return e;
  const known = Object.values(GATEWAY_FAIL);
  const c = e?.code;
  const code = known.includes(c) ? c
    : c === 'ECONNREFUSED' ? GATEWAY_FAIL.CONNECTION_REFUSED
      : c === 'ENOTFOUND' || c === 'EAI_AGAIN' || c === 'ENODATA' ? GATEWAY_FAIL.DNS_FAILED
        : c === 'ETIMEDOUT' || c === 'TIMEOUT' ? GATEWAY_FAIL.TIMEOUT
          : GATEWAY_FAIL.HOST_UNREACHABLE;
  const err = new Error(String(e?.message ?? e ?? 'the network failed').slice(0, 200));
  err.code = code;
  return err;
}

/** An error with a GATEWAY_FAIL code, for what this session itself refuses. */
const refusal = (message, code = GATEWAY_FAIL.POLICY_DENIED) => Object.assign(new Error(message), { code });

/** Best-effort release of whatever a network handed over that is not (or no longer) wanted: cancel what can be read, abort what can be written. Never throws. */
function releaseDuplex(d) {
  try { const p = d?.readable?.cancel?.(); p?.catch?.(() => {}); } catch { /* not a stream, or locked */ }
  try { const p = d?.writable?.abort?.(); p?.catch?.(() => {}); } catch { /* not a stream, or locked */ }
}

/** A listener handle the network gave too late (or that we cannot use): stop it. Never throws. */
function releaseListener(h) {
  try { const p = h?.close?.(); p?.catch?.(() => {}); } catch { /* the network's own */ }
}

/**
 * Await `promise`, but no longer than `ms`, and not past the abort of `ac` (the session ended): then the result is a TIMEOUT (and `ac` is aborted, so the
 * network is told) or CLOSED. A result that arrives after that is passed to `release` (a connection is cancelled, a listener closed), never kept.
 */
function withTimeout(promise, ms, ac, what, release = releaseDuplex) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, v) => { if (settled) return false; settled = true; clearTimeout(timer); ac.signal.removeEventListener('abort', onAbort); fn(v); return true; };
    const timer = setTimeout(() => { if (finish(reject, refusal(what, GATEWAY_FAIL.TIMEOUT))) ac.abort(); }, Math.max(ms, 0));
    timer.unref?.();
    const onAbort = () => { finish(reject, refusal('aborted', GATEWAY_FAIL.CLOSED)); };
    if (ac.signal.aborted) onAbort(); else ac.signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then((v) => { if (!finish(resolve, v)) release(v); }, (e) => { finish(reject, e); });
  });
}

/** Wait for `promise` for at most `ms` and ignore how it ends (the network's own `close()`: it must not hold the session's message loop). */
function settleWithin(promise, ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, Math.max(ms, 0));
    timer.unref?.();
    Promise.resolve(promise).then(() => { clearTimeout(timer); resolve(); }, () => { clearTimeout(timer); resolve(); });
  });
}

/** Most addresses taken from one answer of a network's `resolve` (dialled, or handed to a caller in a `DnsResult`), and most entries looked at to find them. */
const MAX_ANSWER_ADDRESSES = 64;
const MAX_ANSWER_SCAN = 1024;

const connectError = (e) => {
  const code = e.code === 'ECONNREFUSED' ? GATEWAY_FAIL.CONNECTION_REFUSED : e.code === 'ENOTFOUND' || e.code === 'EAI_AGAIN' ? GATEWAY_FAIL.DNS_FAILED : GATEWAY_FAIL.HOST_UNREACHABLE;
  const err = new Error(e.code === 'ENOTFOUND' ? 'name not found' : e.message);
  err.code = code;
  return err;
};

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
  const network = normalizeNetwork(opts.network);
  if (network) {
    // The machine's own ways of reaching out are not the network's to give or take, and the allow list is never implied.
    if (opts.socks !== undefined && opts.socks !== null && opts.socks !== false) throw new TypeError('gateway.socks dials from this machine and cannot be combined with gateway.network');
    if (opts.unix !== undefined && opts.unix !== null && opts.unix !== false) throw new TypeError('gateway.unix serves this machine\'s sockets and cannot be combined with gateway.network');
    if (opts.tcp === false) throw new TypeError('gateway.tcp: false cannot be combined with gateway.network (leave the method out of the network instead)');
    if (!Array.isArray(opts.allow)) throw new TypeError('gateway.allow is required with gateway.network (default deny): { allow: ["host:port", ...] }, an empty list reaches nothing');
    // A new surface is strict: a typo (`allowPrivte`) is a mistake, not an option that silently does nothing. (The machine's gateway keeps accepting what it always did.)
    checkGatewayOptions(opts, 'gateway');
  }
  const allow = opts.allow ?? [];
  if (!Array.isArray(allow) || allow.some((a) => typeof a !== 'string' || !a)) throw new TypeError('gateway.allow must be an array of non-empty strings');
  const privateRules = opts.allowPrivate ?? [];
  if (!Array.isArray(privateRules)) throw new TypeError('gateway.allowPrivate must be an array of CIDR blocks or addresses');
  const allowPrivate = privateRules.map((r) => {
    const c = parseCidr(r);
    if (!c) throw new TypeError(`gateway.allowPrivate: ${JSON.stringify(r)} is not an address or CIDR block`);
    return c;
  });
  const { maxConnections, maxBufferedBytes, maxClientBufferedBytes, halfCloseIdleMs, halfCloseProbeMs } = normalizeGatewayLimits(opts);
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
    halfCloseIdleMs,
    halfCloseProbeMs,
    connectTimeoutMs: opts.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
    udpIdleMs: opts.udpIdleMs ?? DEFAULT_UDP_IDLE_MS,
    // `udp: false` turns UDP OFF (on the Node path too: it used to throw "must be an options object"); `true` or the bounds turn it on with them.
    udp: normalizeUdp(opts.udp === false ? undefined : opts.udp),
    reverse: normalizeReverse(opts.reverse),
    stats: newGatewayStats(),
    socks: parseSocks(opts.socks),
    tcp: opts.tcp !== false,
    unix,
    endpoints,
    network,
    // On the machine's network UDP and DNS are on with the gateway (as they always were) unless given as `false`; on an injected one each is a switch
    // the embedder turns on, and needs the network method as well.
    udpOn: network ? (opts.udp !== undefined && opts.udp !== null && opts.udp !== false) : opts.udp !== false,
    dnsOn: network ? opts.dns === true : opts.dns !== false,
  };
}

const NETWORK_METHODS = ['connectTcp', 'resolve', 'openUdp', 'listenTcp'];

/**
 * `gateway.network` (#299): the network the host dials instead of the machine's. Methods, each optional (one is required), none called
 * until a client asks and the destination policy has passed:
 *  - `connectTcp({ host, port, signal }) -> Promise<{ readable, writable }>`: `host` is an IP address (the one `resolve` answered with, or the
 *    literal the client gave); the result is web streams of bytes (half-close = closing `writable`). `signal` aborts when wsh is done with the
 *    connection for any reason (the client left, the host closed, a timeout): release it.
 *  - `resolve({ name, family, signal }) -> Promise<string[]>`: the IP addresses of a name (`family` 4, 6 or 0); answers that are not IP addresses are ignored.
 *  - `openUdp({ host, port, signal }) -> Promise<{ readable, writable }>`: a flow to one destination; each chunk is one datagram.
 *  - `listenTcp({ port, bindAddr, signal, onConnection }) -> Promise<{ port, close() }>`: `onConnection({ readable, writable }, { peerAddr, peerPort })`.
 * @param {unknown} network
 * @returns {object | null}
 */
export function normalizeNetwork(network) {
  if (network === undefined || network === null) return null;
  if (typeof network !== 'object' || Array.isArray(network)) throw new TypeError('gateway.network must be an object: { connectTcp, resolve, openUdp, listenTcp }');
  for (const k of Object.keys(network)) if (!NETWORK_METHODS.includes(k)) throw new TypeError(`gateway.network.${k} is not a network method (${NETWORK_METHODS.join(', ')})`);
  for (const k of NETWORK_METHODS) if (network[k] !== undefined && typeof network[k] !== 'function') throw new TypeError(`gateway.network.${k} must be a function`);
  if (!NETWORK_METHODS.some((k) => typeof network[k] === 'function')) throw new TypeError(`gateway.network needs at least one of ${NETWORK_METHODS.join(', ')}`);
  return network;
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
 * A connection both sides have finished (nothing discarded): end the socket's write side and close it once everything handed to it
 * has been taken by its peer, instead of destroying it with that still queued. A peer that stops taking what is queued (it
 * reads nothing, or too slowly to matter) is not waited for beyond `idleMs` without a single byte accepted (the half-close idle
 * bound; 0 = never), after which the socket is destroyed as it always was.
 */
export function settleSocket(sock, idleMs) {
  if (sock.destroyed) return;
  sock.end();
  if (sock.writableFinished) { sock.destroy(); return; }
  sock.once('finish', () => { sock.destroy(); });
  if (!(idleMs > 0)) return;
  // Progress is what the socket has let go of: the bytes still queued on this side, in the stream and in the handle (the stream
  // hands a batch of writes to libuv as one request, so its own count moves only when the whole batch is out). `bytesWritten` counts
  // what is queued as written, so it shows nothing.
  const queued = () => sock.writableLength + (sock._handle?.writeQueueSize ?? 0);
  let seen = queued();
  let timer = null;
  const check = () => {
    timer = null;
    if (sock.destroyed) return;
    if (queued() !== seen) { seen = queued(); timer = setTimeout(check, idleMs); timer.unref?.(); return; }
    sock.destroy();
  };
  timer = setTimeout(check, idleMs);
  timer.unref?.();
  sock.once('close', () => { clearTimeout(timer); });
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
  const network = cfg.network ?? null;
  /** Controllers of the connects and listens in flight on an injected network: aborted when the session ends, so the network is told. */
  const aborts = new Set();
  const newAbort = () => { const ac = new AbortController(); aborts.add(ac); return ac; };

  /**
   * An injected network: resolve `name` ONCE through the network and keep the addresses the policy permits. The answers of the network
   * are what is classified and what is then dialled; an IP literal is its own answer (the network is not asked). A name the network
   * cannot resolve is refused. Rejects with an `AddressGuardError` (as the machine's own path does) or a coded error.
   */
  async function resolveInjected(name, { explicit, family = 0, signal }) {
    if (!parseIp(name) && typeof network.resolve !== 'function') throw refusal('this network cannot resolve names');
    const lookup = async (n, o) => {
      let answers;
      try { answers = await network.resolve({ name: n, family: o.family, signal }); } catch (e) { throw (e instanceof AddressGuardError ? e : Object.assign(new Error(String(e?.message ?? e).slice(0, 200)), { code: e?.code })); }
      if (!Array.isArray(answers)) throw new AddressGuardError('LOOKUP_FAILED', 'the network returned no list of addresses');
      // What is an address: text that is an IP literal exactly as written (no space around it, no zone id, no trailing dot). At most 64 are taken, from
      // at most the first 1024 entries: a network that answers with ten thousand addresses cannot make the host classify, dial or report them all.
      const taken = [];
      for (const a of answers.slice(0, MAX_ANSWER_SCAN)) {
        const text = typeof a === 'string' ? a : a?.address;
        if (typeof text === 'string' && text === text.trim() && parseIp(text)) { taken.push(text); if (taken.length >= MAX_ANSWER_ADDRESSES) break; }
      }
      return taken;
    };
    return resolveChecked(name, guardOptions(cfg, explicit, { family, signal, lookup }));
  }
  /** @type {Map<number, { server: import('node:net').Server, path: string, abstract: boolean, bound?: { close: () => Promise<void> }, pendingChannels: Set<number> }>} */
  const listeners = new Map();
  const pendingListeners = new Set();
  /** Accepted inbound sockets waiting for InboundAccept: channel_id -> { sock, listenerId, timer }. */
  const inbound = new Map();
  let nextInbound = 0;
  let closed = false;
  const failListen = (listenerId, reason) => reply(listenFail({ listenerId, reason }));

  /** Attach a connected socket (TCP or unix) as gateway connection `id`. */
  function attachSocket(id, sock, { watchPeer = false } = {}) {
    sock.setNoDelay?.(true);
    // Whoever made the socket (the dialer, the SOCKS client, a listener) did not ask for half-open behaviour; the gateway
    // does: an EOF from the origin is a half-close, and what the client sends after it must still reach the origin.
    sock.allowHalfOpen = true;
    let tail = Promise.resolve();
    const channel = makeChannel(id, {
      writeAfterRemoteClose: true,
      onData: (bytes) => { sock.write(bytes, () => channel.consumed(bytes.byteLength)); },
      // The client will send no more: pass the EOF on to the origin and keep reading its answer for as long as it takes
      // (the channel's idle rule, not a timer here, reaps a connection nothing moves on).
      onRemoteClose: () => { sock.end(); },
      // Both sides finished by themselves: what this side already handed to the socket still has to reach its peer (a caller that
      // half-closed first and reads slowly), so the socket is ended and closed once it has taken it. Anything else (an error, a
      // discard, the idle bound) is the end of the connection, as it was.
      onClose: (_reason, graceful) => { if (graceful) settleSocket(sock, cfg.halfCloseIdleMs); else sock.destroy(); },
    });
    conns.set(id, { channel, sock });
    // Origin -> client: one chunk at a time. The socket is paused until the channel has taken the chunk (it waits for
    // credit and for the transport), so a client that stops reading stops the origin instead of filling memory here.
    sock.on('data', (d) => {
      sock.pause();
      tail = channel.write(new Uint8Array(d.buffer, d.byteOffset, d.length)).then(() => { if (!sock.destroyed) sock.resume(); }, () => { sock.destroy(); });
    });
    sock.on('error', (e) => log(`gateway ${id}: ${e.message}`));
    // The origin finished sending (its FIN): half-close towards the client once everything it sent has gone out, and keep
    // the other direction open (the socket is half-open, so Node does not end our side for us).
    const originEnded = () => { void tail.finally(() => channel.end()); };
    sock.on('end', originEnded);
    if (sock.readableEnded) originEnded(); // an accepted connection whose peer half-closed before it was taken
    // A CALLER of a reverse listener that finished sending (its FIN) and then went away is not noticed by the kernel until
    // something is written to it (#282): while it is half-closed, probe it. Gone = destroyed, which is the 'close' below (a second
    // GatewayClose "discarded": the caller reads nothing more, so what the client's service still sends is wanted by nobody).
    // An ORIGIN of the host is deliberately not watched: one that finished sending and then closed completely is the ordinary end
    // of a response, and the client may still be reading what it sent; the discard drops what the client has received and not
    // yet read, so it would cut the tail of the answer off.
    // (A socket of an injected network has no kernel to ask: its owner closes the stream when its peer is gone.)
    if (watchPeer && !sock.isStreamSocket) watchHalfClosed(sock, cfg.halfCloseProbeMs ?? DEFAULT_HALF_CLOSE_PROBE_MS, (e) => log(`gateway ${id}: ${e.message}`));
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
    if (network && typeof network.connectTcp !== 'function') return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'this network cannot open TCP connections');
    pending.add(id);
    let sock;
    let resolvedAddr;
    const ac = network ? newAbort() : null;
    try {
      if (network) {
        ({ sock, address: resolvedAddr } = await dialNetwork(m, decision, ac));
      } else if (cfg.socks) {
        const lit = parseIp(m.host);
        if (lit && !addressPermitted(cfg, m.host, { explicitLiteral: decision.explicit ? m.host : null })) {
          const e = new Error('the address is not permitted by the gateway policy');
          e.code = GATEWAY_FAIL.POLICY_DENIED;
          throw e;
        }
        sock = await socksConnect(cfg.socks, m.host, m.port, { timeoutMs: cfg.connectTimeoutMs, cfg });
      } else {
        ({ socket: sock, address: resolvedAddr } = await dialChecked(m.host, m.port, guardOptions(cfg, decision.explicit ? m.host : null)));
      }
    } catch (err) {
      const e = gatewayError(network ? networkError(err) : err);
      pending.delete(id);
      if (ac) { aborts.delete(ac); ac.abort(); }
      if (e.code === GATEWAY_FAIL.POLICY_DENIED) log(`gateway: refused ${m.host}:${m.port} (${e.message})`);
      return fail(id, typeof e.code === 'number' ? e.code : GATEWAY_FAIL.HOST_UNREACHABLE, String(e.message).slice(0, 200));
    }
    pending.delete(id);
    if (ac) aborts.delete(ac); // from here the socket owns it: destroying the socket aborts it
    if (closed) { sock.destroy(); return undefined; }
    attachSocket(id, sock);
    log(`gateway: ${id} -> ${m.host}:${m.port}${resolvedAddr && resolvedAddr !== m.host ? ` (${resolvedAddr})` : ''}${cfg.socks ? ' (via SOCKS5)' : ''}`);
    return reply(gatewayOk({ gatewayId: id, resolvedAddr }));
  }

  /**
   * Dial through the injected network: resolve (once, policy-checked), then hand the network the address that passed; the first address
   * that connects wins. The network is never given the name.
   */
  async function dialNetwork(m, decision, ac) {
    const { made, address } = await dialInjected(m, decision, ac, 'connectTcp', (duplex, a) => new StreamSocket(duplex, { remoteAddress: a, remotePort: m.port, onDestroy: () => ac.abort() }));
    return { sock: made, address };
  }

  /**
   * The injected dial shared by TCP and UDP: ONE deadline (`connectTimeoutMs`) for the lookup and every candidate together, as the machine's `dialChecked`
   * has; at most 64 candidates; each is a permitted address from the network's own answer, tried in its order, and the first that connects wins. A
   * duplex the network hands over that is not one is released at once.
   */
  async function dialInjected(m, decision, ac, method, wrap) {
    const deadline = Date.now() + cfg.connectTimeoutMs;
    const candidates = await resolveInjected(m.host, { explicit: decision.explicit ? m.host : null, signal: ac.signal });
    let last;
    for (const c of candidates) {
      if (ac.signal.aborted) throw refusal('aborted', GATEWAY_FAIL.CLOSED);
      const left = deadline - Date.now();
      if (left <= 0) { ac.abort(); throw refusal('connect timed out', GATEWAY_FAIL.TIMEOUT); }
      try {
        const duplex = await withTimeout(network[method]({ host: c.address, port: m.port, signal: ac.signal }), left, ac, 'connect timed out');
        try { return { made: wrap(duplex, c.address), address: c.address }; } catch (e) { releaseDuplex(duplex); throw e; }
      } catch (e) {
        if (ac.signal.aborted) throw e;
        last = e;
      }
    }
    throw last ?? refusal('connect failed', GATEWAY_FAIL.HOST_UNREACHABLE);
  }

  async function resolveDns(m) {
    const id = m.gateway_id;
    if (!cfg.tcp) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'DNS is not enabled on this gateway');
    if (!cfg.dnsOn) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'name resolution is not enabled on this gateway');
    if (network && typeof network.resolve !== 'function') return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'this network cannot resolve names');
    if (cfg.socks) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'names are resolved by the SOCKS proxy; this gateway does not look them up');
    if (typeof m.name !== 'string' || !m.name) return fail(id, GATEWAY_FAIL.DNS_FAILED, 'malformed ResolveDns');
    // Only names the client could also connect to: the allow list is about hosts, not ports, here.
    const hostAllowed = cfg.allow.some((a) => { const p = a.toLowerCase(); return p === '*' || p === m.name.toLowerCase() || p.startsWith(`${m.name.toLowerCase()}:`); });
    if (!hostAllowed) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'destination not allowed by the gateway policy');
    try {
      const family = m.record_type === 'AAAA' ? 6 : m.record_type === 'A' || m.record_type === undefined ? 4 : 0;
      if (!family) return fail(id, GATEWAY_FAIL.DNS_FAILED, `unsupported record type ${String(m.record_type).slice(0, 8)}`);
      // An answer a client could not connect to is not handed out either: it would only be a way to learn the
      // host's internal addresses, and a later OpenTcp to it has to pass the same check.
      const lit = parseIp(m.name) ? m.name : null;
      let addresses;
      if (network) {
        const ac = newAbort();
        try { addresses = (await resolveInjected(m.name, { explicit: lit, family, signal: ac.signal })).map((a) => a.address); } finally { aborts.delete(ac); ac.abort(); }
      } else {
        addresses = (await resolveChecked(m.name, guardOptions(cfg, lit, { family }))).map((a) => a.address);
      }
      return reply(dnsResult({ gatewayId: id, addresses }));
    } catch (err) {
      if (err instanceof AddressGuardError && err.code === 'ADDRESS_REFUSED') return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'the addresses this name resolves to are not permitted by the gateway policy');
      return fail(id, GATEWAY_FAIL.DNS_FAILED, String(err instanceof AddressGuardError && err.code === 'NAME_NOT_FOUND' ? 'name not found' : err.message).slice(0, 200));
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
    if (!cfg.udpOn) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'UDP is not enabled on this gateway');
    if (network && typeof network.openUdp !== 'function') return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'this network cannot open UDP flows');
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
    const ac = network ? newAbort() : null;
    try {
      if (network) {
        // As for TCP: the network's own answers are classified, and the address that passes is what it is given.
        ({ made: sock, address } = await dialInjected(m, decision, ac, 'openUdp', (flow) => new DatagramFlow(flow, { onDestroy: () => ac.abort(), onDrop: () => { stats.backpressureDropped++; } })));
      } else {
        ({ socket: sock, address } = await dialUdpChecked(m.host, m.port, guardOptions(cfg, decision.explicit ? m.host : null)));
      }
    } catch (err) {
      const e = gatewayError(network ? networkError(err) : err);
      pending.delete(id); udpPending.delete(id);
      if (ac) { aborts.delete(ac); ac.abort(); }
      try { sock?.close(); } catch { /* not open */ }
      if (e.code === GATEWAY_FAIL.POLICY_DENIED) log(`gateway: refused udp ${m.host}:${m.port} (${e.message})`);
      return fail(id, typeof e.code === 'number' ? e.code : GATEWAY_FAIL.HOST_UNREACHABLE, String(e.message).slice(0, 200));
    }
    pending.delete(id); udpPending.delete(id);
    if (ac) aborts.delete(ac);
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
    // A flow of an injected network that the network ended is over (a dgram socket closes only when this side closes it, so for it this is a no-op).
    sock.once('close', () => channel.destroy());
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
      const unix = await loadUnix(cfg);
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
        loadNet(cfg).then((net) => {
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
      const unix = await loadUnix(cfg);
      const net = await loadNet(cfg);
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
      server = net.createServer({ allowHalfOpen: true }); // a connector that half-closes before it is accepted still gets its answer
      // Private from the first instant, and closing removes only the socket this listener made (never a file put at the
      // name since): see src/unix-listen.mjs.
      const bound = await unix.listenUnixSocket(server, chk.path);
      if (closed) { await bound.close(); return undefined; }
      const entry = { server, kind: 'unix', path: chk.path, abstract: chk.abstract, bound, pendingChannels: new Set(), open: 0 };
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
    if (network && typeof network.listenTcp !== 'function') return failListen(id, 'this network cannot listen for connections');
    if (listeners.has(id) || pendingListeners.has(id)) return failListen(id, 'listener_id already in use');
    const rev = cfg.reverse;
    if (!reversePortAllowed(rev, m.port)) { log(`gateway: refused reverse listen on port ${m.port} (port policy)`); return failListen(id, reversePortRefusal(rev, m.port)); }
    let tcpCount = pendingListeners.size;
    for (const l of listeners.values()) if (l.kind === 'tcp') tcpCount++;
    if (tcpCount >= rev.maxListeners) return failListen(id, `too many reverse listeners (limit ${rev.maxListeners})`);
    pendingListeners.add(id);
    let server;
    try {
      const host = reverseBindAddress(rev, m.bind_addr);
      if (host !== m.bind_addr) log(`gateway: reverse listen: ignoring the client's bind address ${JSON.stringify(String(m.bind_addr).slice(0, 64))}, binding ${host}`);
      if (network) return await listenInjected(id, m, host);
      const net = await loadNet(cfg);
      server = net.createServer({ allowHalfOpen: true }); // as above
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ port: m.port, host, backlog: rev.backlog }, () => { server.off('error', reject); resolve(); }); });
      if (closed) { server.close(); return undefined; }
      const addr = server.address();
      const entry = { server, kind: 'tcp', path: '', abstract: false, pendingChannels: new Set(), open: 0 };
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

  /** A reverse tunnel on an injected network: the network listens (on the bind address and port the policy chose) and hands over each connection. */
  async function listenInjected(id, m, host) {
    // Registered with the session, so that a session that ends while the network is still binding tells it; and bounded, so a network that never answers
    // cannot hold this client's message loop (and a listener slot) for ever: the same `connectTimeoutMs` as a connect.
    const ac = newAbort();
    const entry = { server: null, kind: 'tcp', path: '', abstract: false, bound: null, pendingChannels: new Set(), open: 0, ready: false };
    let handle;
    try {
      handle = await withTimeout(network.listenTcp({
        port: m.port, bindAddr: host, signal: ac.signal,
        onConnection: (duplex, info) => {
          // Not announced before the client has been told the listener exists, nor after it was closed (its InboundOpen would have nothing to belong to):
          // such a connection is released at once. What the network says about the peer is text on the wire: an IP literal and a port, or nothing.
          if (!entry.ready || closed) { releaseDuplex(duplex); return; }
          let sock;
          try {
            const peer = typeof info?.peerAddr === 'string' && info.peerAddr === info.peerAddr.trim() && parseIp(info.peerAddr) ? info.peerAddr : '';
            sock = new StreamSocket(duplex, { remoteAddress: peer, remotePort: Number.isInteger(info?.peerPort) && info.peerPort >= 0 && info.peerPort <= 65535 ? info.peerPort : 0 });
          } catch (e) { releaseDuplex(duplex); log(`gateway listener ${id}: ${String(e?.message ?? e).slice(0, 200)}`); return; }
          onInbound(id, entry, sock);
        },
      }), cfg.connectTimeoutMs, ac, 'the network did not start listening in time', releaseListener);
    } catch (e) {
      aborts.delete(ac);
      ac.abort();
      return failListen(id, String(e?.message ?? e).slice(0, 200));
    }
    aborts.delete(ac);
    // The port is what the network says it listens on: a port, or the listen failed (a number that is not one is not reported as the one asked for).
    if (!Number.isInteger(handle?.port) || handle.port < 1 || handle.port > 65535) {
      ac.abort(); releaseListener(handle);
      return failListen(id, 'the network did not report a port it listens on');
    }
    const port = handle.port;
    entry.bound = {
      close: async () => {
        entry.ready = false; // a connection the network delivers from now on is released, not announced
        ac.abort();
        let closing;
        try { closing = handle.close?.(); } catch { /* the network's own failure: it is closed as far as we are concerned */ }
        await settleWithin(closing, cfg.connectTimeoutMs); // bounded: a close that never settles must not hold the message loop
      },
    };
    if (closed) { await entry.bound.close(); return undefined; }
    listeners.set(id, entry);
    entry.ready = true;
    cfg.stats.reverse.listeners++;
    log(`gateway: listening on ${host}:${port} (reverse listener ${id}, injected network)`);
    return reply(listenOk({ listenerId: id, actualPort: port }));
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
    entry.open++;
    sock.once('close', () => { entry.open--; });
    if (tcp) cfg.stats.reverse.accepted++;
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
    attachSocket(id, p.sock, { watchPeer: true });
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
    l.ready = false;
    for (const ch of l.pendingChannels) { const p = inbound.get(ch); if (p) { clearTimeout(p.timer); inbound.delete(ch); p.sock.destroy(); } }
    const closing = l.bound ? l.bound.close() : new Promise((r) => { l.server.close(() => r()); });
    // A server finishes closing only when its connections have ended, and with half-closed connections that can need
    // messages that arrive behind this one (the client's GatewayClose): do not hold the message loop for them.
    if (l.open > 0) void closing.catch(() => {});
    else await closing;
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
      for (const ac of aborts) ac.abort(); // a connect or lookup still in flight on an injected network
      aborts.clear();
      for (const { sock, timer } of inbound.values()) { clearTimeout(timer); sock.destroy(); }
      inbound.clear();
      for (const id of [...listeners.keys()]) void closeListener(id).catch(() => {});
    },
    /** The peer is going away but its queued messages are still to be served: tell the injected network what it is still working on (a connect, a lookup, a listen). */
    abortPending() { for (const ac of aborts) ac.abort(); aborts.clear(); },
    get size() { return conns.size; },
    /** Bytes received from the client for its origins and not yet taken by them (what the caps bound). */
    get bufferedBytes() { return core.bufferedBytes; },
    get listenerCount() { return listeners.size; },
  };
}
