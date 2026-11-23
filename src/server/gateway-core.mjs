/**
 * The browser-safe half of the gateway: configuration of the parts that need no Node API (limits, named endpoints,
 * the features a host advertises), and the per-connection core that serves `OpenEndpoint`, `GatewayData`,
 * `GatewayCredit` and `GatewayClose` with flow control (`src/gateway-channel.mjs`). A host in a page
 * (`createMemoryHost({ endpoints })`) is built from this alone; `gateway.mjs` (Node: TCP, DNS, UDP, unix sockets)
 * extends it. Nothing here imports a Node built-in.
 */

import { MSG, gatewayOk, gatewayFail, gatewayClose, gatewayData, gatewayCredit, listenFail } from '../messages.gen.mjs';
import { GatewayChannel, GATEWAY_CREDIT_FEATURE, GATEWAY_CREDIT_WINDOW } from '../gateway-channel.mjs';

/** Numeric codes of GatewayFail (the same table `@johnhenry/browsermesh-netway` decodes). */
export const GATEWAY_FAIL = Object.freeze({
  CONNECTION_REFUSED: 1, HOST_UNREACHABLE: 2, DNS_FAILED: 3, POLICY_DENIED: 4, TIMEOUT: 5, CLOSED: 6, QUEUE_FULL: 7,
});

export const DEFAULT_MAX_CONNECTIONS = 32;
export const DEFAULT_MAX_BUFFERED = 4 * 1024 * 1024;
export const DEFAULT_MAX_CLIENT_BUFFERED = 32 * 1024 * 1024;
export const MAX_DATA_BYTES = 1024 * 1024;
export const HALF_CLOSE_GRACE_MS = 1000;
export const ENDPOINT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** The limits shared by every gateway (validated here so the Node and the in-page host agree). */
export function normalizeGatewayLimits(opts) {
  const maxConnections = opts.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
  if (!Number.isInteger(maxConnections) || maxConnections < 1) throw new TypeError('gateway.maxConnections must be a positive integer');
  const maxBufferedBytes = opts.maxBufferedBytes ?? DEFAULT_MAX_BUFFERED;
  const maxClientBufferedBytes = opts.maxClientBufferedBytes ?? DEFAULT_MAX_CLIENT_BUFFERED;
  if (!Number.isInteger(maxBufferedBytes) || maxBufferedBytes < GATEWAY_CREDIT_WINDOW) throw new TypeError(`gateway.maxBufferedBytes must be an integer of at least ${GATEWAY_CREDIT_WINDOW}`);
  if (!Number.isInteger(maxClientBufferedBytes) || maxClientBufferedBytes < maxBufferedBytes) throw new TypeError('gateway.maxClientBufferedBytes must be an integer of at least maxBufferedBytes');
  return { maxConnections, maxBufferedBytes, maxClientBufferedBytes };
}

/** `{ name: handler | { open, authorize } }` -> a Map, or null when there are none. */
export function normalizeEndpoints(endpoints) {
  if (endpoints === undefined || endpoints === null) return null;
  if (typeof endpoints !== 'object' || Array.isArray(endpoints)) throw new TypeError('gateway.endpoints must be an object of { name: handler }');
  const map = new Map();
  for (const [name, h] of Object.entries(endpoints)) {
    if (!ENDPOINT_NAME_RE.test(name)) throw new TypeError(`gateway.endpoints: ${JSON.stringify(name)} is not a valid endpoint name (letters, digits, ".", "_", "-"; at most 64)`);
    const open = typeof h === 'function' ? h : h?.open;
    if (typeof open !== 'function') throw new TypeError(`gateway.endpoints[${JSON.stringify(name)}] needs a handler function (duplex, who) => void, or { open, authorize }`);
    if (h?.authorize !== undefined && typeof h.authorize !== 'function') throw new TypeError(`gateway.endpoints[${JSON.stringify(name)}].authorize must be a function (who) => boolean`);
    map.set(name, { open, authorize: h?.authorize ?? null });
  }
  return map.size === 0 ? null : map;
}

/**
 * The configuration of a gateway that serves named endpoints only (no TCP, DNS or unix sockets): what
 * `createMemoryHost({ endpoints })` passes as `gateway`, with `createEndpointGatewaySession` as the session factory.
 */
export function normalizeEndpointGateway(opts = {}) {
  return { ...normalizeGatewayLimits(opts), tcp: false, unix: null, endpoints: normalizeEndpoints(opts.endpoints) };
}

/** Which gateway-related features a host with this config advertises (besides what the connection adds). */
export function gatewayFeatures(cfg) {
  const f = [];
  // "gateway" also covers reverse tunnels (the Rust server lists nothing more specific for ListenRequest).
  if (cfg.tcp || cfg.reverse) f.push('gateway');
  f.push(GATEWAY_CREDIT_FEATURE);
  if (cfg.unix) f.push('gateway-unix');
  if (cfg.endpoints) f.push('gateway-endpoints');
  return f;
}

/**
 * The per-connection core: the table of open gateway connections, the per-client byte budget, credit negotiation and
 * the opcodes that need no Node API. `gateway.mjs` builds its socket-backed session on the same object.
 * @param {{ maxConnections: number, maxBufferedBytes: number, maxClientBufferedBytes: number, endpoints: Map<string, object> | null }} cfg
 * @param {(msg: object) => unknown} send
 * @param {(line: string) => void} log
 * @param {{ who?: () => { username: string | null, fingerprint: string | null } }} [ctx]
 */
export function createGatewayCore(cfg, send, log = () => {}, ctx = {}) {
  /** @type {Map<number, { channel: GatewayChannel, sock: any }>} */
  const conns = new Map();
  /** gateway_ids whose connect is still in flight (they count against the cap). */
  const pending = new Set();
  let credit = false;
  let closed = false;
  const budget = { used: 0, max: cfg.maxClientBufferedBytes };

  const reply = (m) => { try { return Promise.resolve(send(m)).catch(() => {}); } catch { return Promise.resolve(); } };
  const fail = (gatewayId, code, message) => reply(gatewayFail({ gatewayId, code, message }));
  const active = () => conns.size + pending.size;
  const idInUse = (id) => conns.has(id) || pending.has(id);

  /** A channel wired to the wire; `extra` adds the sink (a socket's writer) and the close hooks. */
  function makeChannel(id, extra) {
    return new GatewayChannel({
      id, credit, maxQueued: cfg.maxBufferedBytes, budget,
      sendData: (data) => reply(gatewayData({ gatewayId: id, data })),
      sendCredit: (n) => reply(gatewayCredit({ gatewayId: id, bytes: n })),
      sendClose: (reason) => reply(gatewayClose({ gatewayId: id, reason })),
      ...extra,
      onClose: (reason) => { conns.delete(id); extra?.onClose?.(reason); },
    });
  }

  async function openEndpoint(m) {
    const id = m.gateway_id;
    if (!Number.isInteger(id) || typeof m.name !== 'string') return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'malformed OpenEndpoint');
    if (idInUse(id)) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'gateway_id already in use');
    const ep = cfg.endpoints && ENDPOINT_NAME_RE.test(m.name) ? cfg.endpoints.get(m.name) : undefined;
    if (!ep) return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'no such endpoint');
    if (active() >= cfg.maxConnections) return fail(id, GATEWAY_FAIL.QUEUE_FULL, 'too many gateway connections');
    const who = ctx.who?.() ?? { username: null, fingerprint: null };
    pending.add(id);
    try {
      if (ep.authorize && !(await ep.authorize(who))) { pending.delete(id); return await fail(id, GATEWAY_FAIL.POLICY_DENIED, 'endpoint refused this caller'); }
    } catch (e) { pending.delete(id); log(`gateway endpoint ${m.name} authorize threw: ${e.message}`); return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'endpoint refused this caller'); }
    pending.delete(id);
    if (closed) return undefined;
    const channel = makeChannel(id, { writeAfterRemoteClose: true, graceMs: HALF_CLOSE_GRACE_MS });
    conns.set(id, { channel, sock: null });
    const { readable, writable } = channel.streams();
    const duplex = {
      readable, writable, who,
      /** Half-close: nothing more will be sent. */
      close: (reason) => channel.end(reason),
      /** Tear the connection down now. */
      destroy: (reason) => channel.destroy(reason),
      closed: channel.closedPromise,
    };
    try {
      const out = ep.open(duplex, who);
      if (out && typeof out.then === 'function') out.then(undefined, (e) => { log(`gateway endpoint ${m.name} failed: ${e?.message}`); channel.destroy('endpoint error'); });
    } catch (e) {
      log(`gateway endpoint ${m.name} threw: ${e.message}`);
      channel.abandon();
      return fail(id, GATEWAY_FAIL.POLICY_DENIED, 'endpoint refused the connection');
    }
    log(`gateway: ${id} -> endpoint ${m.name}`);
    return reply(gatewayOk({ gatewayId: id }));
  }

  return {
    conns, pending, budget, reply, fail, active, idInUse, makeChannel,
    get closed() { return closed; },
    /** Credit is used on this connection only when the client listed "gateway-credit" in its Hello. */
    setPeerFeatures(features) { credit = Array.isArray(features) && features.includes(GATEWAY_CREDIT_FEATURE); },
    /** @returns {Promise<boolean>} true when the message was a gateway message this session consumed */
    async handle(m) {
      if (closed) return true;
      switch (m.type) {
        case MSG.OPEN_ENDPOINT: await openEndpoint(m); return true;
        case MSG.GATEWAY_DATA: {
          const c = conns.get(m.gateway_id)?.channel;
          const d = m.data;
          if (c && d && d.length <= MAX_DATA_BYTES) c.receive(d);
          return true;
        }
        case MSG.GATEWAY_CREDIT: {
          if (credit && Number.isInteger(m.bytes)) conns.get(m.gateway_id)?.channel.grant(m.bytes);
          return true;
        }
        case MSG.GATEWAY_CLOSE: {
          conns.get(m.gateway_id)?.channel.remoteClosed(m.reason);
          return true;
        }
        // What this host does not serve is refused, not ignored, so the client does not wait for an answer.
        case MSG.OPEN_TCP: case MSG.OPEN_UDP: case MSG.RESOLVE_DNS:
          await fail(m.gateway_id, GATEWAY_FAIL.POLICY_DENIED, 'only named endpoints are available on this host'); return true;
        case MSG.OPEN_UNIX:
          await fail(m.gateway_id, GATEWAY_FAIL.POLICY_DENIED, 'unix sockets are not available on this host'); return true;
        case MSG.LISTEN_REQUEST: case MSG.LISTEN_UNIX:
          await reply(listenFail({ listenerId: m.listener_id, reason: 'listening is not available on this host' })); return true;
        default: return false;
      }
    },
    close() {
      closed = true;
      for (const { channel } of [...conns.values()]) channel.abandon('connection closed');
      conns.clear();
    },
    get size() { return conns.size; },
    /** Bytes received from the client for its origins and not yet taken by them (what the caps bound). */
    get bufferedBytes() { return budget.used; },
    get listenerCount() { return 0; },
  };
}

/** The session factory of an endpoints-only host (`cfg.createGatewaySession`). */
export function createEndpointGatewaySession(cfg, send, log, ctx) {
  return createGatewayCore(cfg, send, log, ctx);
}
